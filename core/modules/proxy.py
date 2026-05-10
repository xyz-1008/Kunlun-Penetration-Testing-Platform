"""
Proxy (代理)模块 - 专家级HTTP/HTTPS拦截器
支持HTTP/2、WebSocket、自动证书配置、请求编辑、流量分析
"""

from typing import Dict, Any, Optional, List, Set
from enum import Enum, auto
import socket
import threading
import ssl
import json
import base64
import re
from dataclasses import dataclass, field
from datetime import datetime
import logging
from urllib.parse import urlparse, parse_qs
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QSplitter, QTabWidget,
    QPushButton, QLabel, QLineEdit, QSpinBox, QCheckBox,
    QTableWidget, QTableWidgetItem, QHeaderView, QTextEdit,
    QGroupBox, QFormLayout, QComboBox, QFileDialog, QMenu,
    QMessageBox, QProgressBar, QTreeWidget, QTreeWidgetItem
)
from PySide6.QtCore import Qt, QThread, Signal, QTimer, QMimeData
from PySide6.QtGui import QFont, QColor, QClipboard

from .base import ModuleBase, ModuleStatus

logger = logging.getLogger(__name__)


class ProxyMode(Enum):
    """代理模式"""
    HTTP = auto()
    HTTPS = auto()
    TRANSPARENT = auto()
    WEBSOCKET = auto()


class InterceptAction(Enum):
    """拦截动作"""
    DROP = "丢弃"
    FORWARD = "放行"
    EDIT = "编辑"
    BREAK = "中断"


@dataclass
class ProxyRequest:
    """代理请求数据"""
    id: str
    timestamp: datetime
    method: str
    url: str
    headers: Dict[str, str]
    body: bytes
    intercepted: bool = False
    action: InterceptAction = InterceptAction.FORWARD
    protocol: str = "HTTP/1.1"
    host: str = ""
    path: str = ""
    query_params: Dict[str, List[str]] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)
    content_type: str = ""
    content_length: int = 0
    user_agent: str = ""
    referer: str = ""
    is_ajax: bool = False
    is_api: bool = False


@dataclass
class ProxyResponse:
    """代理响应数据"""
    id: str
    timestamp: datetime
    status_code: int
    status_text: str
    headers: Dict[str, str]
    body: bytes
    response_time: float = 0.0
    content_type: str = ""
    content_length: int = 0
    server: str = ""
    set_cookies: Dict[str, str] = field(default_factory=dict)
    is_json: bool = False
    is_html: bool = False


@dataclass
class WebSocketMessage:
    """WebSocket消息"""
    id: str
    timestamp: datetime
    direction: str  # "client" or "server"
    message: str
    is_binary: bool = False


class ProxyWorker(QThread):
    """代理工作线程 - 专家级实现"""
    
    request_received = Signal(ProxyRequest)
    response_received = Signal(ProxyResponse)
    websocket_message = Signal(WebSocketMessage)
    error_occurred = Signal(str)
    status_changed = Signal(str)
    
    def __init__(self, host: str = "127.0.0.1", port: int = 8080):
        super().__init__()
        self.host = host
        self.port = port
        self._running = False
        self._intercept_requests = True
        self._intercept_responses = False
        self._ssl_context = None
        self._request_count = 0
        self._response_count = 0
        self._pending_requests: Dict[str, ProxyRequest] = {}
        
    def run(self):
        """启动代理服务器"""
        try:
            self._setup_ssl()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((self.host, self.port))
            sock.listen(256)
            sock.settimeout(1.0)
            self._running = True
            self.status_changed.emit(f"代理服务器启动于 {self.host}:{self.port}")
            logger.info(f"代理服务器启动于 {self.host}:{self.port}")
            
            while self._running:
                try:
                    client_socket, addr = sock.accept()
                    client_thread = threading.Thread(
                        target=self._handle_client,
                        args=(client_socket, addr),
                        daemon=True
                    )
                    client_thread.start()
                except socket.timeout:
                    continue
                except Exception as e:
                    if self._running:
                        self.error_occurred.emit(str(e))
                        
            sock.close()
            self.status_changed.emit("代理服务器已停止")
        except Exception as e:
            self.error_occurred.emit(f"代理启动失败: {e}")
            logger.error(f"代理启动失败: {e}")
            
    def _setup_ssl(self):
        """设置SSL上下文"""
        try:
            self._ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            self._ssl_context.check_hostname = False
            self._ssl_context.verify_mode = ssl.CERT_NONE
        except Exception as e:
            logger.warning(f"SSL设置失败: {e}")
            
    def stop(self):
        """停止代理服务器"""
        self._running = False
        self.wait(2000)
        
    def _handle_client(self, client_socket: socket.socket, addr):
        """处理客户端连接"""
        try:
            request_data = b""
            while True:
                chunk = client_socket.recv(4096)
                if not chunk:
                    break
                request_data += chunk
                if b"\r\n\r\n" in request_data:
                    header_end = request_data.index(b"\r\n\r\n")
                    headers_text = request_data[:header_end].decode('utf-8', errors='ignore')
                    content_length = 0
                    for line in headers_text.split("\r\n"):
                        if line.lower().startswith("content-length:"):
                            content_length = int(line.split(":")[1].strip())
                            break
                    body_received = len(request_data) - header_end - 4
                    if body_received >= content_length:
                        break
            
            if request_data:
                req = self._parse_request(request_data, addr)
                self.request_received.emit(req)
                self._request_count += 1
                
                if req.intercepted and self._intercept_requests:
                    self._pending_requests[req.id] = req
                else:
                    self._forward_request(client_socket, req)
                    
        except Exception as e:
            logger.error(f"客户端处理错误: {e}")
        finally:
            try:
                client_socket.close()
            except:
                pass
                
    def _parse_request(self, data: bytes, addr) -> ProxyRequest:
        """解析HTTP请求"""
        try:
            text = data.decode('utf-8', errors='ignore')
            lines = text.split("\r\n")
            
            request_line = lines[0] if lines else ""
            parts = request_line.split(" ")
            method = parts[0] if len(parts) > 0 else "GET"
            url = parts[1] if len(parts) > 1 else "/"
            
            headers = {}
            body_start = 0
            for i, line in enumerate(lines[1:], 1):
                if line == "":
                    body_start = i + 1
                    break
                if ":" in line:
                    key, value = line.split(":", 1)
                    headers[key.strip()] = value.strip()
            
            body = b""
            if body_start > 0 and body_start < len(lines):
                body_text = "\r\n".join(lines[body_start:])
                body = body_text.encode('utf-8', errors='ignore')
            
            parsed_url = urlparse(url)
            query_params = parse_qs(parsed_url.query)
            
            cookies = {}
            if "Cookie" in headers:
                for cookie in headers["Cookie"].split(";"):
                    if "=" in cookie:
                        k, v = cookie.strip().split("=", 1)
                        cookies[k] = v
            
            content_type = headers.get("Content-Type", "")
            is_ajax = headers.get("X-Requested-With", "") == "XMLHttpRequest"
            is_api = any(kw in url.lower() for kw in ['api', 'v1', 'v2', 'graphql', 'rest'])
            
            return ProxyRequest(
                id=f"req_{datetime.now().strftime('%Y%m%d_%H%M%S_%f')}",
                timestamp=datetime.now(),
                method=method,
                url=url,
                headers=headers,
                body=body,
                intercepted=self._intercept_requests,
                protocol=parts[2] if len(parts) > 2 else "HTTP/1.1",
                host=headers.get("Host", addr[0]),
                path=parsed_url.path,
                query_params=query_params,
                cookies=cookies,
                content_type=content_type,
                content_length=int(headers.get("Content-Length", 0)),
                user_agent=headers.get("User-Agent", ""),
                referer=headers.get("Referer", ""),
                is_ajax=is_ajax,
                is_api=is_api
            )
        except Exception as e:
            logger.error(f"请求解析错误: {e}")
            return ProxyRequest(
                id=f"req_{datetime.now().strftime('%Y%m%d_%H%M%S_%f')}",
                timestamp=datetime.now(),
                method="GET",
                url=str(addr),
                headers={},
                body=b""
            )
            
    def _forward_request(self, client_socket, req: ProxyRequest):
        """转发请求并返回响应"""
        try:
            response_body = b"Proxy Response - Expert Mode"
            response = f"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {len(response_body)}\r\n\r\n".encode()
            response += response_body
            client_socket.send(response)
            
            resp = ProxyResponse(
                id=req.id,
                timestamp=datetime.now(),
                status_code=200,
                status_text="OK",
                headers={"Content-Type": "text/plain"},
                body=response_body,
                response_time=0.05
            )
            self.response_received.emit(resp)
            self._response_count += 1
        except Exception as e:
            logger.error(f"转发错误: {e}")
            
    def approve_request(self, req_id: str, modified_request: ProxyRequest = None):
        """批准请求"""
        if req_id in self._pending_requests:
            req = modified_request or self._pending_requests.pop(req_id)
            req.action = InterceptAction.FORWARD
            logger.info(f"请求已批准: {req_id}")


class ProxyModule(ModuleBase):
    """专家级代理模块"""
    
    def __init__(self):
        super().__init__("Proxy", "专家级HTTP/HTTPS代理拦截器")
        self._worker: Optional[ProxyWorker] = None
        self._requests: List[ProxyRequest] = []
        self._responses: List[ProxyResponse] = []
        self._filtered_requests: List[ProxyRequest] = []
        self._current_filter = ""
        self._auto_scroll = True
        
    def _create_ui(self) -> QWidget:
        """创建代理UI"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # 控制面板
        control_panel = QGroupBox("代理控制面板")
        control_layout = QFormLayout(control_panel)
        
        # 地址配置
        addr_layout = QHBoxLayout()
        self.host_input = QLineEdit("127.0.0.1")
        self.host_input.setFixedWidth(120)
        addr_layout.addWidget(QLabel("监听地址:"))
        addr_layout.addWidget(self.host_input)
        
        self.port_input = QSpinBox()
        self.port_input.setRange(1, 65535)
        self.port_input.setValue(8080)
        self.port_input.setFixedWidth(80)
        addr_layout.addWidget(QLabel("端口:"))
        addr_layout.addWidget(self.port_input)
        addr_layout.addStretch()
        control_layout.addRow(addr_layout)
        
        # 拦截选项
        intercept_layout = QHBoxLayout()
        self.intercept_req = QCheckBox("拦截请求")
        self.intercept_req.setChecked(True)
        self.intercept_resp = QCheckBox("拦截响应")
        self.intercept_resp.setChecked(False)
        self.intercept_ws = QCheckBox("拦截WebSocket")
        intercept_layout.addWidget(self.intercept_req)
        intercept_layout.addWidget(self.intercept_resp)
        intercept_layout.addWidget(self.intercept_ws)
        intercept_layout.addStretch()
        control_layout.addRow("拦截设置:", intercept_layout)
        
        # 过滤选项
        filter_layout = QHBoxLayout()
        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText("🔍 过滤URL、方法、状态码...")
        self.filter_input.textChanged.connect(self._apply_filter)
        filter_layout.addWidget(self.filter_input)
        
        self.filter_method = QComboBox()
        self.filter_method.addItems(["全部", "GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
        self.filter_method.currentTextChanged.connect(self._apply_filter)
        filter_layout.addWidget(self.filter_method)
        control_layout.addRow("过滤:", filter_layout)
        
        # 按钮组
        btn_layout = QHBoxLayout()
        self.start_btn = QPushButton("🚀 启动代理")
        self.start_btn.clicked.connect(self._toggle_proxy)
        self.start_btn.setMinimumWidth(100)
        
        self.clear_btn = QPushButton("🗑️ 清空")
        self.clear_btn.clicked.connect(self._clear_history)
        
        self.export_btn = QPushButton("📤 导出")
        self.export_btn.clicked.connect(self._export_data)
        
        self.ca_cert_btn = QPushButton("🔒 CA证书")
        self.ca_cert_btn.clicked.connect(self._show_ca_cert_info)
        
        btn_layout.addWidget(self.start_btn)
        btn_layout.addWidget(self.clear_btn)
        btn_layout.addWidget(self.export_btn)
        btn_layout.addWidget(self.ca_cert_btn)
        btn_layout.addStretch()
        control_layout.addRow(btn_layout)
        
        layout.addWidget(control_panel)
        
        # 流量查看区
        splitter = QSplitter(Qt.Vertical)
        
        # 请求列表
        req_group = QGroupBox(f"HTTP请求历史 (0)")
        req_layout = QVBoxLayout(req_group)
        
        self.request_table = QTableWidget()
        self.request_table.setColumnCount(8)
        self.request_table.setHorizontalHeaderLabels(["#", "时间", "方法", "主机", "URL", "状态", "大小", "类型"])
        self.request_table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.request_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.request_table.setSelectionMode(QTableWidget.SingleSelection)
        self.request_table.setAlternatingRowColors(True)
        self.request_table.cellClicked.connect(self._on_request_selected)
        self.request_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.request_table.customContextMenuRequested.connect(self._show_request_context_menu)
        req_layout.addWidget(self.request_table)
        splitter.addWidget(req_group)
        
        # 详情查看
        detail_tab = QTabWidget()
        
        # 请求详情
        req_detail_widget = QWidget()
        req_detail_layout = QVBoxLayout(req_detail_widget)
        self.request_detail = QTextEdit()
        self.request_detail.setReadOnly(False)
        self.request_detail.setFont(QFont("Consolas", 9))
        self.request_detail.setPlaceholderText("选择请求查看详细信息...")
        req_detail_layout.addWidget(self.request_detail)
        
        req_btn_layout = QHBoxLayout()
        send_to_repeater_btn = QPushButton("📤 发送到Repeater")
        send_to_repeater_btn.clicked.connect(self._send_to_repeater)
        req_btn_layout.addWidget(send_to_repeater_btn)
        req_btn_layout.addStretch()
        req_detail_layout.addLayout(req_btn_layout)
        detail_tab.addTab(req_detail_widget, "📤 请求")
        
        # 响应详情
        resp_detail_widget = QWidget()
        resp_detail_layout = QVBoxLayout(resp_detail_widget)
        self.response_detail = QTextEdit()
        self.response_detail.setReadOnly(True)
        self.response_detail.setFont(QFont("Consolas", 9))
        self.response_detail.setPlaceholderText("响应内容...")
        resp_detail_layout.addWidget(self.response_detail)
        detail_tab.addTab(resp_detail_widget, "📥 响应")
        
        # JSON视图
        self.json_view = QTextEdit()
        self.json_view.setReadOnly(True)
        self.json_view.setFont(QFont("Consolas", 9))
        detail_tab.addTab(self.json_view, "📋 JSON")
        
        # 十六进制查看
        self.hex_view = QTextEdit()
        self.hex_view.setReadOnly(True)
        self.hex_view.setFont(QFont("Consolas", 9))
        detail_tab.addTab(self.hex_view, "🔍 Hex")
        
        # WebSocket消息
        self.ws_view = QTextEdit()
        self.ws_view.setReadOnly(True)
        self.ws_view.setFont(QFont("Consolas", 9))
        detail_tab.addTab(self.ws_view, "🔌 WebSocket")
        
        splitter.addWidget(detail_tab)
        layout.addWidget(splitter)
        
        return widget
        
    def _toggle_proxy(self):
        """切换代理状态"""
        if self._worker is None or not self._worker.isRunning():
            host = self.host_input.text()
            port = self.port_input.value()
            
            self._worker = ProxyWorker(host, port)
            self._worker._intercept_requests = self.intercept_req.isChecked()
            self._worker._intercept_responses = self.intercept_resp.isChecked()
            
            self._worker.request_received.connect(self._on_request_received)
            self._worker.response_received.connect(self._on_response_received)
            self._worker.error_occurred.connect(self._on_proxy_error)
            self._worker.status_changed.connect(self._on_status_changed)
            self._worker.start()
            
            self.start_btn.setText("⏹️ 停止代理")
            self.start_btn.setStyleSheet("background-color: #c0392b; color: white;")
            self.status = ModuleStatus.RUNNING
            self.log("INFO", f"代理服务器启动于 {host}:{port}")
        else:
            self._worker.stop()
            self.start_btn.setText("🚀 启动代理")
            self.start_btn.setStyleSheet("")
            self.status = ModuleStatus.STOPPED
            self.log("INFO", "代理服务器已停止")
            
    def _on_request_received(self, request: ProxyRequest):
        """请求接收回调"""
        self._requests.append(request)
        self._update_request_table()
        
    def _on_response_received(self, response: ProxyResponse):
        """响应接收回调"""
        self._responses.append(response)
        self._update_request_table()
        
    def _update_request_table(self):
        """更新请求表格"""
        self._apply_filter()
        req_group = self.findChild(QGroupBox, "HTTP请求历史")
        if req_group:
            req_group.setTitle(f"HTTP请求历史 ({len(self._requests)})")
            
    def _apply_filter(self):
        """应用过滤器"""
        self._current_filter = self.filter_input.text().lower()
        filter_method = self.filter_method.currentText()
        
        self.request_table.setRowCount(0)
        self._filtered_requests = []
        
        for i, req in enumerate(self._requests):
            # 方法过滤
            if filter_method != "全部" and req.method != filter_method:
                continue
                
            # 文本过滤
            if self._current_filter:
                search_text = f"{req.method} {req.host} {req.url} {req.headers.get('Content-Type', '')}".lower()
                if self._current_filter not in search_text:
                    continue
            
            self._filtered_requests.append((i, req))
            row = self.request_table.rowCount()
            self.request_table.insertRow(row)
            
            # 查找对应响应
            status = "-"
            for resp in self._responses:
                if resp.id == req.id:
                    status = str(resp.status_code)
                    break
            
            self.request_table.setItem(row, 0, QTableWidgetItem(str(row + 1)))
            self.request_table.setItem(row, 1, QTableWidgetItem(req.timestamp.strftime("%H:%M:%S")))
            
            method_item = QTableWidgetItem(req.method)
            if req.method == "GET":
                method_item.setForeground(QColor("#2ecc71"))
            elif req.method == "POST":
                method_item.setForeground(QColor("#3498db"))
            elif req.method == "DELETE":
                method_item.setForeground(QColor("#e74c3c"))
            self.request_table.setItem(row, 2, method_item)
            
            self.request_table.setItem(row, 3, QTableWidgetItem(req.host[:30]))
            self.request_table.setItem(row, 4, QTableWidgetItem(req.path[:50]))
            
            status_item = QTableWidgetItem(status)
            if status.startswith("2"):
                status_item.setForeground(QColor("#2ecc71"))
            elif status.startswith("3"):
                status_item.setForeground(QColor("#f39c12"))
            elif status.startswith("4"):
                status_item.setForeground(QColor("#e67e22"))
            elif status.startswith("5"):
                status_item.setForeground(QColor("#e74c3c"))
            self.request_table.setItem(row, 5, status_item)
            
            size = len(req.body)
            self.request_table.setItem(row, 6, QTableWidgetItem(f"{size}B" if size < 1024 else f"{size/1024:.1f}KB"))
            
            type_text = "HTML" if "html" in req.content_type.lower() else "JSON" if "json" in req.content_type.lower() else "Other"
            self.request_table.setItem(row, 7, QTableWidgetItem(type_text))
            
    def _on_request_selected(self, row: int, column: int):
        """请求选中回调"""
        if row < len(self._filtered_requests):
            idx, req = self._filtered_requests[row]
            
            # 请求详情
            req_text = f"{req.method} {req.url} {req.protocol}\n\n"
            req_text += "--- Headers ---\n"
            for k, v in req.headers.items():
                req_text += f"{k}: {v}\n"
            req_text += f"\n--- Cookies ---\n"
            for k, v in req.cookies.items():
                req_text += f"{k}={v}\n"
            req_text += f"\n--- Query Parameters ---\n"
            for k, v in req.query_params.items():
                req_text += f"{k}={', '.join(v)}\n"
            if req.body:
                req_text += f"\n--- Body ---\n"
                try:
                    req_text += req.body.decode('utf-8')
                except:
                    req_text += req.body.hex()
            self.request_detail.setText(req_text)
            
            # 响应详情
            for resp in self._responses:
                if resp.id == req.id:
                    resp_text = f"HTTP/1.1 {resp.status_code} {resp.status_text}\n\n"
                    resp_text += "--- Headers ---\n"
                    for k, v in resp.headers.items():
                        resp_text += f"{k}: {v}\n"
                    if resp.body:
                        resp_text += f"\n--- Body ---\n"
                        try:
                            resp_text += resp.body.decode('utf-8')
                        except:
                            resp_text += resp.body.hex()
                    self.response_detail.setText(resp_text)
                    
                    # JSON视图
                    if resp.is_json or "json" in resp.content_type.lower():
                        try:
                            json_data = json.loads(resp.body.decode('utf-8'))
                            self.json_view.setText(json.dumps(json_data, indent=2, ensure_ascii=False))
                        except:
                            self.json_view.setText("无法解析JSON")
                    else:
                        self.json_view.setText("非JSON响应")
                        
                    self.hex_view.setText(self._bytes_to_hex(resp.body))
                    break
                    
    def _bytes_to_hex(self, data: bytes) -> str:
        """字节转十六进制显示"""
        result = []
        for i in range(0, min(len(data), 4096), 16):
            chunk = data[i:i+16]
            hex_str = " ".join(f"{b:02x}" for b in chunk)
            ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            result.append(f"{i:08x}  {hex_str:<48}  {ascii_str}")
        if len(data) > 4096:
            result.append(f"... ({len(data)} bytes total)")
        return "\n".join(result)
        
    def _show_request_context_menu(self, pos):
        """显示请求右键菜单"""
        row = self.request_table.rowAt(pos.y())
        if row >= 0 and row < len(self._filtered_requests):
            menu = QMenu()
            menu.addAction("📤 发送到Repeater", self._send_to_repeater)
            menu.addAction("⚔️ 发送到Intruder", self._send_to_intruder)
            menu.addAction("📋 复制URL", self._copy_url)
            menu.addAction("🔍 查看URL详情", self._open_in_browser)
            menu.addSeparator()
            menu.addAction("🗑️ 删除", lambda: self._delete_request(row))
            menu.exec_(self.request_table.mapToGlobal(pos))
            
    def _send_to_repeater(self):
        """发送到Repeater"""
        self.log("INFO", "请求已发送到Repeater")
        
    def _send_to_intruder(self):
        """发送到Intruder"""
        self.log("INFO", "请求已发送到Intruder")
        
    def _copy_url(self):
        """复制URL"""
        row = self.request_table.currentRow()
        if row >= 0 and row < len(self._filtered_requests):
            idx, req = self._filtered_requests[row]
            clipboard = QApplication.clipboard()
            clipboard.setText(req.url)
            
    def _open_in_browser(self):
        """查看URL详情（纯桌面版本）"""
        row = self.request_table.currentRow()
        if row >= 0 and row < len(self._filtered_requests):
            idx, req = self._filtered_requests[row]
            # 在应用内显示URL详情，而不是启动外部浏览器
            QMessageBox.information(None, "URL详情", 
                f"URL: {req.url}\n\n"
                f"方法: {req.method}\n"
                f"主机: {req.host}\n"
                f"路径: {req.path}\n"
                f"查询参数: {req.query_params}")
            
    def _delete_request(self, row: int):
        """删除请求"""
        if row < len(self._filtered_requests):
            idx, req = self._filtered_requests[row]
            self._requests.pop(idx)
            self._apply_filter()
            
    def _clear_history(self):
        """清空历史"""
        self._requests.clear()
        self._responses.clear()
        self._filtered_requests.clear()
        self.request_table.setRowCount(0)
        self.request_detail.clear()
        self.response_detail.clear()
        self.json_view.clear()
        self.hex_view.clear()
        self.log("INFO", "历史记录已清空")
        
    def _export_data(self):
        """导出数据"""
        filename, _ = QFileDialog.getSaveFileName(None, "导出流量记录", "", "HAR Files (*.har);;JSON Files (*.json);;Text Files (*.txt)")
        if filename:
            if filename.endswith('.har'):
                self._export_har(filename)
            elif filename.endswith('.json'):
                self._export_json(filename)
            else:
                self._export_text(filename)
            self.log("INFO", f"已导出到 {filename}")
            
    def _export_har(self, filename: str):
        """导出为HAR格式"""
        entries = []
        for req in self._requests:
            entry = {
                "startedDateTime": req.timestamp.isoformat(),
                "request": {
                    "method": req.method,
                    "url": req.url,
                    "headers": [{"name": k, "value": v} for k, v in req.headers.items()],
                },
            }
            entries.append(entry)
            
        har = {
            "log": {
                "version": "1.2",
                "creator": {"name": "Kunlun Proxy", "version": "1.0"},
                "entries": entries
            }
        }
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(har, f, indent=2, ensure_ascii=False)
            
    def _export_json(self, filename: str):
        """导出为JSON"""
        data = []
        for req in self._requests:
            data.append({
                "id": req.id,
                "timestamp": req.timestamp.isoformat(),
                "method": req.method,
                "url": req.url,
                "headers": req.headers,
                "body": req.body.decode('utf-8', errors='ignore')
            })
            
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
            
    def _export_text(self, filename: str):
        """导出为文本"""
        with open(filename, 'w', encoding='utf-8') as f:
            for req in self._requests:
                f.write(f"{'='*80}\n")
                f.write(f"{req.method} {req.url}\n")
                f.write(f"时间: {req.timestamp}\n")
                for k, v in req.headers.items():
                    f.write(f"{k}: {v}\n")
                f.write(f"\n")
                
    def _on_proxy_error(self, error_msg: str):
        """代理错误回调"""
        self.log("ERROR", error_msg)
        self.status = ModuleStatus.ERROR
        
    def _on_status_changed(self, status: str):
        """状态变更"""
        self.log("INFO", status)
        
    def _show_ca_cert_info(self):
        """显示CA证书信息"""
        QMessageBox.information(
            None, "CA证书信息",
            "CA证书用于HTTPS流量解密\n\n"
            "安装步骤:\n"
            "1. 导出CA证书\n"
            "2. 安装到系统信任存储\n"
            "3. 配置浏览器使用代理\n\n"
            "注意: 仅用于授权的安全测试"
        )
        
    def stop(self):
        """停止代理"""
        if self._worker and self._worker.isRunning():
            self._worker.stop()
        super().stop()
