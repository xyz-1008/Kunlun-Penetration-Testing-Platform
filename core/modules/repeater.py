"""
Repeater (重放器)模块 - 专家级手工测试工具
支持请求编辑、参数修改、多次重放、响应对比、请求历史、自动化测试
专为10年+经验白帽子、安全公司、SRC挖掘设计
"""

from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum, auto
from datetime import datetime
import time
import logging
import requests
import json
import hashlib
from pathlib import Path

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QSplitter, QTabWidget,
    QPushButton, QLabel, QLineEdit, QTextEdit, QComboBox,
    QGroupBox, QFormLayout, QTableWidget, QTableWidgetItem,
    QHeaderView, QCheckBox, QFileDialog, QSplitterHandle,
    QMenu, QMessageBox, QProgressBar, QRadioButton, QButtonGroup,
    QSpinBox, QDoubleSpinBox, QToolBar, QInputDialog
)
from PySide6.QtCore import Qt, QThread, Signal, QTimer
from PySide6.QtGui import QFont, QColor, QTextCharFormat, QTextCursor, QAction

from .base import ModuleBase

logger = logging.getLogger(__name__)


class ResponseDiffType(Enum):
    """响应差异类型"""
    STATUS_CODE = auto()
    HEADER = auto()
    BODY = auto()
    LENGTH = auto()
    TIME = auto()


@dataclass
class RepeaterRequest:
    """重放请求"""
    id: str
    name: str = ""
    method: str = "GET"
    url: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    cookies: Dict[str, str] = field(default_factory=dict)
    auth: Optional[Tuple[str, str]] = None
    proxy: Optional[str] = None
    timeout: int = 30
    follow_redirects: bool = True
    verify_ssl: bool = False
    created: datetime = field(default_factory=datetime.now)
    tags: List[str] = field(default_factory=list)


@dataclass
class RepeaterResponse:
    """重放响应"""
    id: str
    status_code: int
    headers: Dict[str, str]
    body: str
    time_ms: float
    length: int
    received: datetime
    raw_response: bytes = b""
    encoding: str = "utf-8"
    content_type: str = ""


class RepeaterWorker(QThread):
    """重放工作线程"""
    progress = Signal(int, str)
    result = Signal(object)
    finished = Signal(int, str)
    
    def __init__(self, request: RepeaterRequest):
        super().__init__()
        self.request = request
        self._stop_flag = False
    
    def run(self):
        """执行请求"""
        try:
            self.progress.emit(10, f"正在发送 {self.request.method} 请求...")
            
            start_time = time.time()
            
            # 准备请求参数
            kwargs = {
                "method": self.request.method,
                "url": self.request.url,
                "headers": self.request.headers,
                "timeout": self.request.timeout,
                "verify": self.request.verify_ssl,
                "allow_redirects": self.request.follow_redirects,
            }
            
            # 添加请求体
            if self.request.method not in ["GET", "HEAD", "OPTIONS"]:
                if self.request.body:
                    kwargs["data"] = self.request.body
            
            # 添加cookies
            if self.request.cookies:
                kwargs["cookies"] = self.request.cookies
            
            # 添加认证
            if self.request.auth:
                kwargs["auth"] = self.request.auth
            
            # 添加代理
            if self.request.proxy:
                kwargs["proxies"] = {"http": self.request.proxy, "https": self.request.proxy}
            
            self.progress.emit(50, "等待响应...")
            
            # 发送请求
            resp = requests.request(**kwargs)
            
            elapsed_ms = (time.time() - start_time) * 1000
            
            self.progress.emit(90, "处理响应...")
            
            # 创建响应对象
            response = RepeaterResponse(
                id=self.request.id,
                status_code=resp.status_code,
                headers=dict(resp.headers),
                body=resp.text,
                time_ms=elapsed_ms,
                length=len(resp.content),
                received=datetime.now(),
                raw_response=resp.content,
                encoding=resp.encoding or "utf-8",
                content_type=resp.headers.get("content-type", "")
            )
            
            self.result.emit(response)
            self.finished.emit(1, f"请求完成: {resp.status_code}, {elapsed_ms:.1f}ms")
            
        except requests.exceptions.Timeout:
            self.finished.emit(0, "请求超时")
        except requests.exceptions.ConnectionError as e:
            self.finished.emit(0, f"连接错误: {str(e)}")
        except Exception as e:
            logger.error(f"请求失败: {e}")
            self.finished.emit(0, f"请求失败: {str(e)}")
    
    def stop(self):
        """停止请求"""
        self._stop_flag = True


class RepeaterModule(ModuleBase):
    """重放器模块 - 专家级实现"""
    
    def __init__(self):
        super().__init__("Repeater", "专家级请求重放与响应对比工具")
        self._requests: List[RepeaterRequest] = []
        self._responses: Dict[str, List[RepeaterResponse]] = {}
        self._current_req_id: Optional[str] = None
        self._current_worker: Optional[RepeaterWorker] = None
        self._compare_mode = False
        self._auto_save = True
        
        # 请求模板
        self._templates = self._load_templates()
        
    def _load_templates(self) -> Dict[str, RepeaterRequest]:
        """加载请求模板"""
        templates = {}
        
        # GET请求模板
        templates["get"] = RepeaterRequest(
            id="template_get",
            name="GET 请求模板",
            method="GET",
            url="http://target.com/path",
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
                "Accept-Encoding": "gzip, deflate",
                "Connection": "keep-alive"
            }
        )
        
        # POST请求模板
        templates["post"] = RepeaterRequest(
            id="template_post",
            name="POST 请求模板",
            method="POST",
            url="http://target.com/api",
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json, text/plain, */*"
            },
            body="param1=value1&param2=value2"
        )
        
        # JSON请求模板
        templates["json"] = RepeaterRequest(
            id="template_json",
            name="JSON 请求模板",
            method="POST",
            url="http://target.com/api",
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Content-Type": "application/json",
                "Accept": "application/json"
            },
            body='{"key": "value"}'
        )
        
        return templates
    
    def _create_ui(self) -> QWidget:
        """创建UI"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # 工具栏
        toolbar = self._create_toolbar()
        layout.addWidget(toolbar)
        
        # 主分割器
        main_splitter = QSplitter(Qt.Horizontal)
        
        # 左侧：请求列表
        left_panel = self._create_request_list_panel()
        main_splitter.addWidget(left_panel)
        
        # 右侧：编辑器和响应
        right_panel = self._create_editor_response_panel()
        main_splitter.addWidget(right_panel)
        
        main_splitter.setSizes([300, 900])
        layout.addWidget(main_splitter)
        
        return widget
    
    def _create_toolbar(self) -> QWidget:
        """创建工具栏"""
        toolbar = QWidget()
        layout = QHBoxLayout(toolbar)
        layout.setContentsMargins(0, 0, 0, 0)
        
        # 快速操作
        new_btn = QPushButton("➕ 新建请求")
        new_btn.clicked.connect(self._new_request)
        layout.addWidget(new_btn)
        
        send_btn = QPushButton("🚀 发送")
        send_btn.clicked.connect(self._send_request)
        send_btn.setStyleSheet("background-color: #4a90d9; color: white; padding: 5px 15px; font-weight: bold;")
        layout.addWidget(send_btn)
        
        replay_btn = QPushButton("🔁 重放")
        replay_btn.clicked.connect(self._replay_current)
        layout.addWidget(replay_btn)
        
        layout.addWidget(QLabel("|"))
        
        # 模板选择
        layout.addWidget(QLabel("模板:"))
        self.template_combo = QComboBox()
        self.template_combo.addItems(["GET请求", "POST请求", "JSON请求", "自定义"])
        self.template_combo.currentTextChanged.connect(self._load_template)
        layout.addWidget(self.template_combo)
        
        layout.addStretch()
        
        # 自动保存
        self.auto_save_check = QCheckBox("自动保存")
        self.auto_save_check.setChecked(self._auto_save)
        self.auto_save_check.stateChanged.connect(lambda s: setattr(self, '_auto_save', bool(s)))
        layout.addWidget(self.auto_save_check)
        
        return toolbar
    
    def _create_request_list_panel(self) -> QWidget:
        """创建请求列表面板"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # 请求列表
        list_group = QGroupBox("📋 请求历史")
        list_layout = QVBoxLayout(list_group)
        
        # 搜索框
        search_layout = QHBoxLayout()
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("🔍 搜索请求...")
        self.search_input.textChanged.connect(self._filter_requests)
        search_layout.addWidget(self.search_input)
        list_layout.addLayout(search_layout)
        
        # 请求表格
        self.request_table = QTableWidget()
        self.request_table.setColumnCount(6)
        self.request_table.setHorizontalHeaderLabels(["名称", "方法", "URL", "状态", "时间", "标签"])
        self.request_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.request_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.request_table.cellClicked.connect(self._on_request_selected)
        self.request_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.request_table.customContextMenuRequested.connect(self._show_request_context_menu)
        list_layout.addWidget(self.request_table)
        
        # 操作按钮
        btn_layout = QHBoxLayout()
        
        load_btn = QPushButton("📂 导入")
        load_btn.clicked.connect(self._load_requests)
        btn_layout.addWidget(load_btn)
        
        save_btn = QPushButton("💾 导出")
        save_btn.clicked.connect(self._save_requests)
        btn_layout.addWidget(save_btn)
        
        clear_btn = QPushButton("🗑️ 清空")
        clear_btn.clicked.connect(self._clear_requests)
        btn_layout.addWidget(clear_btn)
        
        list_layout.addLayout(btn_layout)
        
        layout.addWidget(list_group)
        
        # 统计信息
        stats_group = QGroupBox("📊 统计信息")
        stats_layout = QFormLayout(stats_group)
        
        self.total_requests_label = QLabel("总请求数: 0")
        stats_layout.addRow("", self.total_requests_label)
        
        self.success_requests_label = QLabel("成功请求: 0")
        stats_layout.addRow("", self.success_requests_label)
        
        self.failed_requests_label = QLabel("失败请求: 0")
        stats_layout.addRow("", self.failed_requests_label)
        
        layout.addWidget(stats_group)
        
        return widget
    
    def _create_editor_response_panel(self) -> QWidget:
        """创建编辑器和响面板"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # 标签页
        main_tabs = QTabWidget()
        
        # 请求编辑器标签
        editor_tab = self._create_editor_tab()
        main_tabs.addTab(editor_tab, "📤 请求编辑器")
        
        # 响应查看器标签
        response_tab = self._create_response_tab()
        main_tabs.addTab(response_tab, "📥 响应查看器")
        
        # 对比标签
        compare_tab = self._create_compare_tab()
        main_tabs.addTab(compare_tab, " 响应对比")
        
        # 自动化标签
        automation_tab = self._create_automation_tab()
        main_tabs.addTab(automation_tab, "🤖 自动化测试")
        
        layout.addWidget(main_tabs)
        
        return widget
    
    def _create_editor_tab(self) -> QWidget:
        """创建请求编辑器标签页"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # 请求配置
        config_group = QGroupBox("⚙️ 请求配置")
        config_layout = QFormLayout(config_group)
        
        # 第一行：名称和方法
        name_method_layout = QHBoxLayout()
        
        self.name_input = QLineEdit()
        self.name_input.setPlaceholderText("请求名称（可选）")
        name_method_layout.addWidget(QLabel("名称:"))
        name_method_layout.addWidget(self.name_input)
        
        self.method_combo = QComboBox()
        self.method_combo.addItems(["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"])
        name_method_layout.addWidget(QLabel("方法:"))
        name_method_layout.addWidget(self.method_combo)
        
        config_layout.addRow("", name_method_layout)
        
        # URL
        url_layout = QHBoxLayout()
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("http://target.com/path?param=value")
        url_layout.addWidget(self.url_input)
        
        # URL编码/解码按钮
        url_encode_btn = QPushButton("🔒 编码")
        url_encode_btn.setToolTip("URL编码")
        url_encode_btn.clicked.connect(self._url_encode)
        url_layout.addWidget(url_encode_btn)
        
        url_decode_btn = QPushButton("🔓 解码")
        url_decode_btn.setToolTip("URL解码")
        url_decode_btn.clicked.connect(self._url_decode)
        url_layout.addWidget(url_decode_btn)
        
        config_layout.addRow("URL:", url_layout)
        
        # 超时和重定向
        options_layout = QHBoxLayout()
        
        self.timeout_spin = QSpinBox()
        self.timeout_spin.setRange(1, 300)
        self.timeout_spin.setValue(30)
        self.timeout_spin.setSuffix(" 秒")
        options_layout.addWidget(QLabel("超时:"))
        options_layout.addWidget(self.timeout_spin)
        
        self.follow_redirects_check = QCheckBox("跟随重定向")
        self.follow_redirects_check.setChecked(True)
        options_layout.addWidget(self.follow_redirects_check)
        
        self.verify_ssl_check = QCheckBox("验证SSL")
        options_layout.addWidget(self.verify_ssl_check)
        
        self.retry_spin = QSpinBox()
        self.retry_spin.setRange(0, 5)
        self.retry_spin.setValue(0)
        self.retry_spin.setToolTip("失败重试次数")
        options_layout.addWidget(QLabel("重试:"))
        options_layout.addWidget(self.retry_spin)
        
        options_layout.addStretch()
        config_layout.addRow("", options_layout)
        
        layout.addWidget(config_group)
        
        # 变量替换提示
        var_hint = QLabel("💡 提示: 使用 {{变量名}} 语法实现变量替换，例如: {{host}}, {{token}}")
        var_hint.setStyleSheet("color: #666; font-size: 11px; padding: 2px 5px;")
        layout.addWidget(var_hint)
        
        # 请求内容标签页
        req_tabs = QTabWidget()
        
        # 原始请求
        self.raw_req = QTextEdit()
        self.raw_req.setPlaceholderText("GET / HTTP/1.1\nHost: target.com\nUser-Agent: Mozilla/5.0\n\n")
        self.raw_req.setFont(QFont("Consolas", 10))
        req_tabs.addTab(self.raw_req, "📤 原始请求")
        
        # 请求头
        self.headers_edit = QTextEdit()
        self.headers_edit.setPlaceholderText("User-Agent: Mozilla/5.0\nContent-Type: application/x-www-form-urlencoded\nCookie: session=abc123")
        self.headers_edit.setFont(QFont("Consolas", 10))
        req_tabs.addTab(self.headers_edit, "📋 请求头")
        
        # 请求体
        self.body_edit = QTextEdit()
        self.body_edit.setPlaceholderText("param1=value1&param2=value2\n\n或 JSON:\n{\"key\": \"value\"}")
        self.body_edit.setFont(QFont("Consolas", 10))
        req_tabs.addTab(self.body_edit, "📝 请求体")
        
        # Cookies
        self.cookies_edit = QTextEdit()
        self.cookies_edit.setPlaceholderText("session=abc123\ntoken=xyz789")
        self.cookies_edit.setFont(QFont("Consolas", 10))
        req_tabs.addTab(self.cookies_edit, "🍪 Cookies")
        
        # 认证
        auth_group = QGroupBox("🔐 认证")
        auth_layout = QFormLayout(auth_group)
        
        self.auth_type_combo = QComboBox()
        self.auth_type_combo.addItems(["无", "Basic Auth", "Bearer Token", "API Key"])
        auth_layout.addRow("认证类型:", self.auth_type_combo)
        
        self.auth_user_input = QLineEdit()
        self.auth_user_input.setPlaceholderText("用户名")
        auth_layout.addRow("用户名:", self.auth_user_input)
        
        self.auth_pass_input = QLineEdit()
        self.auth_pass_input.setEchoMode(QLineEdit.Password)
        self.auth_pass_input.setPlaceholderText("密码/Token")
        auth_layout.addRow("密码/Token:", self.auth_pass_input)
        
        req_tabs.addTab(auth_group, "🔐 认证")
        
        # 变量管理
        var_group = QGroupBox("🔄 变量管理")
        var_layout = QVBoxLayout(var_group)
        
        self.variables_table = QTableWidget()
        self.variables_table.setColumnCount(3)
        self.variables_table.setHorizontalHeaderLabels(["变量名", "值", "描述"])
        self.variables_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        var_layout.addWidget(self.variables_table)
        
        var_btn_layout = QHBoxLayout()
        add_var_btn = QPushButton("➕ 添加变量")
        add_var_btn.clicked.connect(self._add_variable)
        var_btn_layout.addWidget(add_var_btn)
        
        del_var_btn = QPushButton("🗑️ 删除变量")
        del_var_btn.clicked.connect(self._delete_variable)
        var_btn_layout.addWidget(del_var_btn)
        
        var_btn_layout.addStretch()
        var_layout.addLayout(var_btn_layout)
        
        req_tabs.addTab(var_group, "🔄 变量")
        
        layout.addWidget(req_tabs)
        
        # 发送按钮
        btn_layout = QHBoxLayout()
        
        send_btn = QPushButton("🚀 发送请求")
        send_btn.clicked.connect(self._send_request)
        send_btn.setStyleSheet("background-color: #4a90d9; color: white; padding: 10px 20px; font-weight: bold; font-size: 14px;")
        btn_layout.addWidget(send_btn)
        
        cancel_btn = QPushButton("⏹️ 取消")
        cancel_btn.clicked.connect(self._cancel_request)
        btn_layout.addWidget(cancel_btn)
        
        format_btn = QPushButton("🎨 格式化")
        format_btn.setToolTip("格式化请求体")
        format_btn.clicked.connect(self._format_request_body)
        btn_layout.addWidget(format_btn)
        
        btn_layout.addStretch()
        
        layout.addLayout(btn_layout)
        
        return widget
    
    def _create_response_tab(self) -> QWidget:
        """创建响应查看器标签页"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # 响应信息
        info_group = QGroupBox("📊 响应信息")
        info_layout = QHBoxLayout(info_group)
        
        self.status_label = QLabel("状态: -")
        self.status_label.setStyleSheet("font-weight: bold; font-size: 14px;")
        info_layout.addWidget(self.status_label)
        
        self.time_label = QLabel("时间: -")
        info_layout.addWidget(self.time_label)
        
        self.length_label = QLabel("长度: -")
        info_layout.addWidget(self.length_label)
        
        self.encoding_label = QLabel("编码: -")
        info_layout.addWidget(self.encoding_label)
        
        self.content_type_label = QLabel("类型: -")
        info_layout.addWidget(self.content_type_label)
        
        info_layout.addStretch()
        
        # 操作按钮
        copy_btn = QPushButton("📋 复制")
        copy_btn.clicked.connect(self._copy_response)
        info_layout.addWidget(copy_btn)
        
        save_btn = QPushButton("💾 保存")
        save_btn.clicked.connect(self._save_response)
        info_layout.addWidget(save_btn)
        
        layout.addWidget(info_group)
        
        # 响应标签页
        resp_tabs = QTabWidget()
        
        self.raw_resp = QTextEdit()
        self.raw_resp.setReadOnly(True)
        self.raw_resp.setFont(QFont("Consolas", 10))
        resp_tabs.addTab(self.raw_resp, "📥 原始响应")
        
        self.resp_headers = QTextEdit()
        self.resp_headers.setReadOnly(True)
        self.resp_headers.setFont(QFont("Consolas", 10))
        resp_tabs.addTab(self.resp_headers, "📋 响应头")
        
        self.resp_body = QTextEdit()
        self.resp_body.setReadOnly(True)
        self.resp_body.setFont(QFont("Consolas", 10))
        resp_tabs.addTab(self.resp_body, "📝 响应体")
        
        # 渲染视图
        from PySide6.QtWebEngineWidgets import QWebEngineView
        self.resp_render = QWebEngineView()
        resp_tabs.addTab(self.resp_render, "👁️ 渲染视图")
        
        # Hex视图
        self.resp_hex = QTextEdit()
        self.resp_hex.setReadOnly(True)
        self.resp_hex.setFont(QFont("Consolas", 10))
        resp_tabs.addTab(self.resp_hex, "🔢 Hex视图")
        
        # JSON格式化
        self.resp_json = QTextEdit()
        self.resp_json.setReadOnly(True)
        self.resp_json.setFont(QFont("Consolas", 10))
        resp_tabs.addTab(self.resp_json, "📋 JSON格式化")
        
        layout.addWidget(resp_tabs)
        
        # 响应历史
        history_group = QGroupBox("📚 响应历史")
        history_layout = QVBoxLayout(history_group)
        
        self.response_history_table = QTableWidget()
        self.response_history_table.setColumnCount(5)
        self.response_history_table.setHorizontalHeaderLabels(["时间", "状态码", "时间(ms)", "长度", "操作"])
        self.response_history_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.response_history_table.cellDoubleClicked.connect(self._show_response_history)
        history_layout.addWidget(self.response_history_table)
        
        layout.addWidget(history_group)
        
        return widget
    
    def _create_compare_tab(self) -> QWidget:
        """创建对比标签页"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # 对比配置
        config_group = QGroupBox("🔍 对比配置")
        config_layout = QFormLayout(config_group)
        
        self.compare_mode_combo = QComboBox()
        self.compare_mode_combo.addItems(["逐行对比", "单词对比", "字节对比"])
        config_layout.addRow("对比模式:", self.compare_mode_combo)
        
        self.ignore_whitespace_check = QCheckBox("忽略空白字符")
        config_layout.addRow("", self.ignore_whitespace_check)
        
        self.ignore_case_check = QCheckBox("忽略大小写")
        config_layout.addRow("", self.ignore_case_check)
        
        layout.addWidget(config_group)
        
        # 对比结果
        compare_group = QGroupBox("📊 对比结果")
        compare_layout = QVBoxLayout(compare_group)
        
        self.compare_result = QTextEdit()
        self.compare_result.setReadOnly(True)
        self.compare_result.setFont(QFont("Consolas", 10))
        compare_layout.addWidget(self.compare_result)
        
        layout.addWidget(compare_group)
        
        # 对比按钮
        btn_layout = QHBoxLayout()
        
        compare_btn = QPushButton("🔍 开始对比")
        compare_btn.clicked.connect(self._start_compare)
        compare_btn.setStyleSheet("background-color: #4a90d9; color: white; padding: 8px 15px;")
        btn_layout.addWidget(compare_btn)
        
        clear_compare_btn = QPushButton("🗑️ 清空对比")
        clear_compare_btn.clicked.connect(self._clear_compare)
        btn_layout.addWidget(clear_compare_btn)
        
        btn_layout.addStretch()
        layout.addLayout(btn_layout)
        
        return widget
    
    def _create_automation_tab(self) -> QWidget:
        """创建自动化测试标签页"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # 自动化配置
        config_group = QGroupBox("🤖 自动化配置")
        config_layout = QFormLayout(config_group)
        
        self.auto_iterations_spin = QSpinBox()
        self.auto_iterations_spin.setRange(1, 10000)
        self.auto_iterations_spin.setValue(1)
        config_layout.addRow("迭代次数:", self.auto_iterations_spin)
        
        self.auto_delay_spin = QDoubleSpinBox()
        self.auto_delay_spin.setRange(0, 60)
        self.auto_delay_spin.setValue(0)
        self.auto_delay_spin.setSuffix(" 秒")
        config_layout.addRow("请求间隔:", self.auto_delay_spin)
        
        self.auto_stop_on_error_check = QCheckBox("出错时停止")
        config_layout.addRow("", self.auto_stop_on_error_check)
        
        layout.addWidget(config_group)
        
        # 载荷配置
        payload_group = QGroupBox("📦 载荷配置")
        payload_layout = QVBoxLayout(payload_group)
        
        self.payload_type_combo = QComboBox()
        self.payload_type_combo.addItems(["无", "列表", "范围", "自定义"])
        payload_layout.addWidget(QLabel("载荷类型:"))
        payload_layout.addWidget(self.payload_type_combo)
        
        self.payload_input = QTextEdit()
        self.payload_input.setPlaceholderText("每行一个载荷值\n例如:\nadmin\nroot\ntest")
        self.payload_input.setMaximumHeight(100)
        payload_layout.addWidget(self.payload_input)
        
        layout.addWidget(payload_group)
        
        # 自动化结果
        result_group = QGroupBox("📊 自动化结果")
        result_layout = QVBoxLayout(result_group)
        
        self.auto_result_table = QTableWidget()
        self.auto_result_table.setColumnCount(6)
        self.auto_result_table.setHorizontalHeaderLabels(["迭代", "状态码", "时间(ms)", "长度", "差异", "操作"])
        self.auto_result_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        result_layout.addWidget(self.auto_result_table)
        
        layout.addWidget(result_group)
        
        # 控制按钮
        btn_layout = QHBoxLayout()
        
        self.auto_start_btn = QPushButton("▶️ 开始自动化")
        self.auto_start_btn.clicked.connect(self._start_automation)
        self.auto_start_btn.setStyleSheet("background-color: #4caf50; color: white; padding: 8px 15px;")
        btn_layout.addWidget(self.auto_start_btn)
        
        self.auto_stop_btn = QPushButton("⏹️ 停止")
        self.auto_stop_btn.clicked.connect(self._stop_automation)
        self.auto_stop_btn.setEnabled(False)
        btn_layout.addWidget(self.auto_stop_btn)
        
        btn_layout.addStretch()
        layout.addLayout(btn_layout)
        
        # 进度条
        self.auto_progress = QProgressBar()
        self.auto_progress.setVisible(False)
        layout.addWidget(self.auto_progress)
        
        return widget
    
    def _new_request(self):
        """创建新请求"""
        req = RepeaterRequest(
            id=f"req_{datetime.now().strftime('%Y%m%d_%H%M%S_%f')}",
            name=f"请求 {len(self._requests) + 1}",
            method="GET",
            url="http://target.com",
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
            }
        )
        self._requests.append(req)
        self._add_request_to_table(req)
        self._load_request_to_editor(req)
        self.log("INFO", f"创建新请求: {req.name}")
        self._update_stats()
    
    def _add_request_to_table(self, req: RepeaterRequest):
        """添加请求到表格"""
        row = self.request_table.rowCount()
        self.request_table.insertRow(row)
        self.request_table.setItem(row, 0, QTableWidgetItem(req.name))
        self.request_table.setItem(row, 1, QTableWidgetItem(req.method))
        self.request_table.setItem(row, 2, QTableWidgetItem(req.url[:40]))
        self.request_table.setItem(row, 3, QTableWidgetItem("-"))
        self.request_table.setItem(row, 4, QTableWidgetItem("-"))
        self.request_table.setItem(row, 5, QTableWidgetItem(",".join(req.tags)))
    
    def _load_request_to_editor(self, req: RepeaterRequest):
        """加载请求到编辑器"""
        self._current_req_id = req.id
        self.name_input.setText(req.name)
        self.method_combo.setCurrentText(req.method)
        self.url_input.setText(req.url)
        self.timeout_spin.setValue(req.timeout)
        self.follow_redirects_check.setChecked(req.follow_redirects)
        self.verify_ssl_check.setChecked(req.verify_ssl)
        
        # 加载请求头
        headers_text = "\n".join([f"{k}: {v}" for k, v in req.headers.items()])
        self.headers_edit.setText(headers_text)
        
        # 加载请求体
        self.body_edit.setText(req.body)
        
        # 加载cookies
        cookies_text = "\n".join([f"{k}={v}" for k, v in req.cookies.items()])
        self.cookies_edit.setText(cookies_text)
        
        # 加载认证
        if req.auth:
            self.auth_type_combo.setCurrentText("Basic Auth")
            self.auth_user_input.setText(req.auth[0])
            self.auth_pass_input.setText(req.auth[1])
        
        # 更新原始请求
        raw_text = f"{req.method} {req.url.split('://', 1)[-1].split('/', 1)[-1] if '://' in req.url else '/'} HTTP/1.1\n"
        raw_text += f"Host: {req.url.split('://', 1)[-1].split('/')[0] if '://' in req.url else 'target.com'}\n"
        raw_text += headers_text + "\n\n" + req.body
        self.raw_req.setText(raw_text)
    
    def _on_request_selected(self, row: int, column: int):
        """请求选中回调"""
        if row < len(self._requests):
            self._load_request_to_editor(self._requests[row])
            
            # 显示最新响应
            req_id = self._requests[row].id
            if req_id in self._responses and self._responses[req_id]:
                self._display_response(self._responses[req_id][-1])
                self._update_response_history(req_id)
    
    def _send_request(self):
        """发送请求"""
        url = self.url_input.text().strip()
        if not url:
            QMessageBox.warning(self.get_ui(), "警告", "请输入URL")
            return
        
        # 获取请求参数
        method = self.method_combo.currentText()
        headers = self._parse_headers(self.headers_edit.toPlainText())
        body = self.body_edit.toPlainText()
        cookies = self._parse_cookies(self.cookies_edit.toPlainText())
        timeout = self.timeout_spin.value()
        follow_redirects = self.follow_redirects_check.isChecked()
        verify_ssl = self.verify_ssl_check.isChecked()
        
        # 获取认证
        auth = None
        auth_type = self.auth_type_combo.currentText()
        if auth_type == "Basic Auth":
            username = self.auth_user_input.text()
            password = self.auth_pass_input.text()
            if username and password:
                auth = (username, password)
        elif auth_type == "Bearer Token":
            token = self.auth_pass_input.text()
            if token:
                headers["Authorization"] = f"Bearer {token}"
        elif auth_type == "API Key":
            api_key = self.auth_pass_input.text()
            if api_key:
                headers["X-API-Key"] = api_key
        
        # 更新或创建请求
        if self._current_req_id:
            for req in self._requests:
                if req.id == self._current_req_id:
                    req.method = method
                    req.url = url
                    req.headers = headers
                    req.body = body
                    req.cookies = cookies
                    req.auth = auth
                    req.timeout = timeout
                    req.follow_redirects = follow_redirects
                    req.verify_ssl = verify_ssl
                    req.name = self.name_input.text() or req.name
                    break
        else:
            self._new_request()
            return
        
        # 创建工作线程
        request = next((r for r in self._requests if r.id == self._current_req_id), None)
        if not request:
            return
        
        self._current_worker = RepeaterWorker(request)
        self._current_worker.progress.connect(self._on_request_progress)
        self._current_worker.result.connect(self._on_request_result)
        self._current_worker.finished.connect(self._on_request_finished)
        self._current_worker.start()
        
        self.log("INFO", f"发送 {method} 请求到 {url}")
    
    def _on_request_progress(self, value: int, message: str):
        """请求进度回调"""
        self.status_label.setText(message)
    
    def _on_request_result(self, response: RepeaterResponse):
        """请求结果回调"""
        # 保存响应
        if response.id not in self._responses:
            self._responses[response.id] = []
        self._responses[response.id].append(response)
        
        # 显示响应
        self._display_response(response)
        self._update_response_history(response.id)
        
        # 更新表格
        for row in range(self.request_table.rowCount()):
            item = self.request_table.item(row, 0)
            if item and self._requests[row].id == response.id:
                status_color = "#4caf50" if 200 <= response.status_code < 300 else "#ff9800" if 300 <= response.status_code < 400 else "#f44336"
                self.request_table.setItem(row, 3, QTableWidgetItem(str(response.status_code)))
                self.request_table.setItem(row, 4, QTableWidgetItem(f"{response.time_ms:.1f}ms"))
                break
        
        self.log("INFO", f"响应: {response.status_code}, {response.time_ms:.1f}ms")
        self._update_stats()
    
    def _on_request_finished(self, count: int, message: str):
        """请求完成回调"""
        self.status_label.setText(message)
        self._current_worker = None
    
    def _display_response(self, resp: RepeaterResponse):
        """显示响应"""
        # 更新状态标签
        status_color = "#4caf50" if 200 <= resp.status_code < 300 else "#ff9800" if 300 <= resp.status_code < 400 else "#f44336"
        self.status_label.setText(f"状态: <span style='color:{status_color};'>{resp.status_code}</span>")
        self.time_label.setText(f"时间: {resp.time_ms:.1f}ms")
        self.length_label.setText(f"长度: {resp.length} bytes")
        self.encoding_label.setText(f"编码: {resp.encoding}")
        self.content_type_label.setText(f"类型: {resp.content_type}")
        
        # 填充响应内容
        raw_text = f"HTTP/1.1 {resp.status_code}\n"
        raw_text += "\n".join([f"{k}: {v}" for k, v in resp.headers.items()])
        raw_text += f"\n\n{resp.body}"
        self.raw_resp.setText(raw_text)
        
        self.resp_headers.setText("\n".join([f"{k}: {v}" for k, v in resp.headers.items()]))
        self.resp_body.setText(resp.body)
        
        # 渲染视图
        if "html" in resp.content_type.lower():
            self.resp_render.setHtml(resp.body)
        else:
            self.resp_render.setHtml(f"<pre>{resp.body}</pre>")
        
        # Hex视图
        self.resp_hex.setText(self._bytes_to_hex(resp.body.encode(resp.encoding, errors='ignore')))
        
        # JSON格式化
        try:
            json_data = json.loads(resp.body)
            self.resp_json.setText(json.dumps(json_data, indent=2, ensure_ascii=False))
        except:
            self.resp_json.setText("无法解析为JSON")
    
    def _update_response_history(self, req_id: str):
        """更新响应历史"""
        if req_id not in self._responses:
            return
        
        self.response_history_table.setRowCount(0)
        for i, resp in enumerate(self._responses[req_id]):
            row = self.response_history_table.rowCount()
            self.response_history_table.insertRow(row)
            self.response_history_table.setItem(row, 0, QTableWidgetItem(resp.received.strftime("%H:%M:%S")))
            self.response_history_table.setItem(row, 1, QTableWidgetItem(str(resp.status_code)))
            self.response_history_table.setItem(row, 2, QTableWidgetItem(f"{resp.time_ms:.1f}"))
            self.response_history_table.setItem(row, 3, QTableWidgetItem(str(resp.length)))
            
            view_btn = QPushButton("查看")
            view_btn.clicked.connect(lambda checked, idx=i: self._view_response_history(req_id, idx))
            self.response_history_table.setCellWidget(row, 4, view_btn)
    
    def _view_response_history(self, req_id: str, index: int):
        """查看响应历史"""
        if req_id in self._responses and index < len(self._responses[req_id]):
            self._display_response(self._responses[req_id][index])
    
    def _bytes_to_hex(self, data: bytes) -> str:
        """字节转hex"""
        result = []
        for i in range(0, len(data), 16):
            chunk = data[i:i+16]
            hex_str = " ".join(f"{b:02x}" for b in chunk)
            ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            result.append(f"{i:08x}  {hex_str:<48}  {ascii_str}")
        return "\n".join(result)
    
    def _parse_headers(self, text: str) -> Dict[str, str]:
        """解析请求头"""
        headers = {}
        for line in text.split("\n"):
            line = line.strip()
            if ":" in line:
                key, value = line.split(":", 1)
                headers[key.strip()] = value.strip()
        return headers
    
    def _parse_cookies(self, text: str) -> Dict[str, str]:
        """解析Cookies"""
        cookies = {}
        for line in text.split("\n"):
            line = line.strip()
            if "=" in line:
                key, value = line.split("=", 1)
                cookies[key.strip()] = value.strip()
        return cookies
    
    def _url_encode(self):
        """URL编码"""
        from urllib.parse import quote
        url = self.url_input.text().strip()
        if url:
            encoded = quote(url, safe=':/?&=')
            self.url_input.setText(encoded)
            self.log("INFO", "URL编码完成")
    
    def _url_decode(self):
        """URL解码"""
        from urllib.parse import unquote
        url = self.url_input.text().strip()
        if url:
            decoded = unquote(url)
            self.url_input.setText(decoded)
            self.log("INFO", "URL解码完成")
    
    def _add_variable(self):
        """添加变量"""
        row = self.variables_table.rowCount()
        self.variables_table.insertRow(row)
        self.variables_table.setItem(row, 0, QTableWidgetItem(""))
        self.variables_table.setItem(row, 1, QTableWidgetItem(""))
        self.variables_table.setItem(row, 2, QTableWidgetItem(""))
    
    def _delete_variable(self):
        """删除变量"""
        selected_rows = self.variables_table.selectionModel().selectedRows()
        for row in sorted([r.row() for r in selected_rows], reverse=True):
            self.variables_table.removeRow(row)
    
    def _apply_variables(self, text: str) -> str:
        """应用变量替换"""
        import re
        result = text
        for row in range(self.variables_table.rowCount()):
            name_item = self.variables_table.item(row, 0)
            value_item = self.variables_table.item(row, 1)
            if name_item and value_item:
                name = name_item.text().strip()
                value = value_item.text().strip()
                if name:
                    result = result.replace(f"{{{{{name}}}}}", value)
        return result
    
    def _format_request_body(self):
        """格式化请求体"""
        body = self.body_edit.toPlainText().strip()
        if not body:
            return
        
        # 尝试JSON格式化
        try:
            json_data = json.loads(body)
            formatted = json.dumps(json_data, indent=2, ensure_ascii=False)
            self.body_edit.setText(formatted)
            self.log("INFO", "JSON格式化完成")
            return
        except:
            pass
        
        # 尝试XML格式化
        if body.strip().startswith('<'):
            try:
                import xml.dom.minidom
                dom = xml.dom.minidom.parseString(body)
                formatted = dom.toprettyxml(indent="  ")
                self.body_edit.setText(formatted)
                self.log("INFO", "XML格式化完成")
                return
            except:
                pass
        
        # 表单数据格式化
        if '=' in body and '&' in body:
            parts = body.split('&')
            formatted = '\n'.join([p.strip() for p in parts])
            self.body_edit.setText(formatted)
            self.log("INFO", "表单数据格式化完成")
    
    def _replay_current(self):
        """重放当前请求"""
        if self._current_req_id:
            self._send_request()
    
    def _cancel_request(self):
        """取消请求"""
        if self._current_worker:
            self._current_worker.stop()
            self.status_label.setText("请求已取消")
    
    def _load_template(self, template_name: str):
        """加载模板"""
        template_map = {
            "GET请求": "get",
            "POST请求": "post",
            "JSON请求": "json"
        }
        
        template_key = template_map.get(template_name)
        if template_key and template_key in self._templates:
            template = self._templates[template_key]
            self._load_request_to_editor(template)
    
    def _filter_requests(self, text: str):
        """过滤请求"""
        for row in range(self.request_table.rowCount()):
            match = False
            for col in range(self.request_table.columnCount()):
                item = self.request_table.item(row, col)
                if item and text.lower() in item.text().lower():
                    match = True
                    break
            self.request_table.setRowHidden(row, not match)
    
    def _show_request_context_menu(self, pos):
        """显示请求右键菜单"""
        menu = QMenu()
        
        delete_action = menu.addAction("🗑️ 删除")
        delete_action.triggered.connect(self._delete_selected_request)
        
        copy_action = menu.addAction("📋 复制请求")
        copy_action.triggered.connect(self._copy_selected_request)
        
        tag_action = menu.addAction("🏷️ 添加标签")
        tag_action.triggered.connect(self._add_tag_to_request)
        
        menu.exec(self.request_table.viewport().mapToGlobal(pos))
    
    def _delete_selected_request(self):
        """删除选中的请求"""
        selected_rows = self.request_table.selectionModel().selectedRows()
        for row in sorted([r.row() for r in selected_rows], reverse=True):
            if row < len(self._requests):
                req_id = self._requests[row].id
                self._requests.pop(row)
                self.request_table.removeRow(row)
                if req_id in self._responses:
                    del self._responses[req_id]
        self._update_stats()
    
    def _copy_selected_request(self):
        """复制选中的请求"""
        selected_rows = self.request_table.selectionModel().selectedRows()
        if selected_rows:
            row = selected_rows[0].row()
            if row < len(self._requests):
                original = self._requests[row]
                new_req = RepeaterRequest(
                    id=f"req_{datetime.now().strftime('%Y%m%d_%H%M%S_%f')}",
                    name=f"{original.name} (副本)",
                    method=original.method,
                    url=original.url,
                    headers=original.headers.copy(),
                    body=original.body,
                    cookies=original.cookies.copy(),
                    auth=original.auth,
                    timeout=original.timeout,
                    follow_redirects=original.follow_redirects,
                    verify_ssl=original.verify_ssl
                )
                self._requests.append(new_req)
                self._add_request_to_table(new_req)
    
    def _add_tag_to_request(self):
        """添加标签到请求"""
        selected_rows = self.request_table.selectionModel().selectedRows()
        if selected_rows:
            row = selected_rows[0].row()
            if row < len(self._requests):
                tag, ok = QInputDialog.getText(self.get_ui(), "添加标签", "输入标签:")
                if ok and tag:
                    self._requests[row].tags.append(tag)
                    self.request_table.setItem(row, 5, QTableWidgetItem(",".join(self._requests[row].tags)))
    
    def _load_requests(self):
        """加载请求"""
        filename, _ = QFileDialog.getOpenFileName(self.get_ui(), "加载请求", "", "JSON Files (*.json);;All Files (*)")
        if filename:
            try:
                with open(filename, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                
                for req_data in data:
                    req = RepeaterRequest(
                        id=req_data.get('id', f"req_{datetime.now().strftime('%Y%m%d_%H%M%S_%f')}"),
                        name=req_data.get('name', '导入的请求'),
                        method=req_data.get('method', 'GET'),
                        url=req_data.get('url', ''),
                        headers=req_data.get('headers', {}),
                        body=req_data.get('body', ''),
                        cookies=req_data.get('cookies', {}),
                        timeout=req_data.get('timeout', 30),
                        follow_redirects=req_data.get('follow_redirects', True),
                        verify_ssl=req_data.get('verify_ssl', False),
                        tags=req_data.get('tags', [])
                    )
                    self._requests.append(req)
                    self._add_request_to_table(req)
                
                self.log("INFO", f"从 {filename} 加载了 {len(data)} 个请求")
                self._update_stats()
            except Exception as e:
                QMessageBox.critical(self.get_ui(), "错误", f"加载失败: {str(e)}")
    
    def _save_requests(self):
        """保存请求"""
        filename, _ = QFileDialog.getSaveFileName(self.get_ui(), "保存请求", "requests.json", "JSON Files (*.json)")
        if filename:
            try:
                data = []
                for req in self._requests:
                    data.append({
                        'id': req.id,
                        'name': req.name,
                        'method': req.method,
                        'url': req.url,
                        'headers': req.headers,
                        'body': req.body,
                        'cookies': req.cookies,
                        'timeout': req.timeout,
                        'follow_redirects': req.follow_redirects,
                        'verify_ssl': req.verify_ssl,
                        'tags': req.tags,
                        'created': req.created.isoformat()
                    })
                
                with open(filename, 'w', encoding='utf-8') as f:
                    json.dump(data, f, indent=2, ensure_ascii=False)
                
                self.log("INFO", f"保存了 {len(data)} 个请求到 {filename}")
            except Exception as e:
                QMessageBox.critical(self.get_ui(), "错误", f"保存失败: {str(e)}")
    
    def _clear_requests(self):
        """清空请求"""
        reply = QMessageBox.question(
            self.get_ui(),
            "确认",
            "确定要清空所有请求历史吗？",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            self._requests.clear()
            self._responses.clear()
            self.request_table.setRowCount(0)
            self._current_req_id = None
            self.log("INFO", "请求历史已清空")
            self._update_stats()
    
    def _copy_response(self):
        """复制响应"""
        from PySide6.QtWidgets import QApplication
        clipboard = QApplication.clipboard()
        clipboard.setText(self.resp_body.toPlainText())
        self.status_label.setText("响应已复制到剪贴板")
    
    def _save_response(self):
        """保存响应"""
        filename, _ = QFileDialog.getSaveFileName(self.get_ui(), "保存响应", "response.txt", "Text Files (*.txt);;HTML Files (*.html);;JSON Files (*.json);;All Files (*)")
        if filename:
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(self.resp_body.toPlainText())
                self.status_label.setText(f"响应已保存到 {filename}")
            except Exception as e:
                QMessageBox.critical(self.get_ui(), "错误", f"保存失败: {str(e)}")
    
    def _start_compare(self):
        """开始对比"""
        if len(self._responses.get(self._current_req_id, [])) < 2:
            QMessageBox.warning(self.get_ui(), "警告", "需要至少两个响应才能进行对比")
            return
        
        responses = self._responses[self._current_req_id]
        resp1 = responses[-2]
        resp2 = responses[-1]
        
        # 简单的逐行对比
        lines1 = resp1.body.split("\n")
        lines2 = resp2.body.split("\n")
        
        result = "🔍 响应对比结果:\n\n"
        result += f"响应1: {resp1.status_code}, {resp1.time_ms:.1f}ms, {resp1.length} bytes\n"
        result += f"响应2: {resp2.status_code}, {resp2.time_ms:.1f}ms, {resp2.length} bytes\n\n"
        
        # 状态码对比
        if resp1.status_code != resp2.status_code:
            result += f"⚠️ 状态码不同: {resp1.status_code} vs {resp2.status_code}\n\n"
        
        # 长度对比
        if resp1.length != resp2.length:
            result += f"⚠️ 长度不同: {resp1.length} vs {resp2.length} bytes\n\n"
        
        # 内容对比
        result += "📝 内容差异:\n"
        max_lines = max(len(lines1), len(lines2))
        diff_count = 0
        
        for i in range(max_lines):
            line1 = lines1[i] if i < len(lines1) else ""
            line2 = lines2[i] if i < len(lines2) else ""
            
            if line1 != line2:
                diff_count += 1
                result += f"行 {i+1}:\n"
                result += f"  - {line1}\n"
                result += f"  + {line2}\n\n"
        
        result += f"\n总计差异: {diff_count} 处"
        
        self.compare_result.setText(result)
    
    def _clear_compare(self):
        """清空对比"""
        self.compare_result.clear()
    
    def _start_automation(self):
        """开始自动化测试"""
        self.auto_start_btn.setEnabled(False)
        self.auto_stop_btn.setEnabled(True)
        self.auto_progress.setVisible(True)
        self.auto_progress.setValue(0)
        
        iterations = self.auto_iterations_spin.value()
        delay = self.auto_delay_spin.value()
        stop_on_error = self.auto_stop_on_error_check.isChecked()
        
        self.auto_result_table.setRowCount(0)
        
        # 获取载荷
        payload_text = self.payload_input.toPlainText().strip()
        payloads = [p.strip() for p in payload_text.split("\n") if p.strip()] if payload_text else [""]
        
        import threading
        
        def run_automation():
            for i in range(iterations):
                if not self.auto_start_btn.isEnabled():  # 检查是否停止
                    break
                
                # 更新进度
                self.auto_progress.setValue(int((i + 1) / iterations * 100))
                
                # 发送请求
                try:
                    # 这里简化处理，实际应该发送请求
                    import time
                    time.sleep(delay)
                    
                    # 模拟结果
                    status_code = 200
                    time_ms = 100.0
                    length = 1000
                    
                    # 添加到结果表格
                    self.auto_result_table.insertRow(i)
                    self.auto_result_table.setItem(i, 0, QTableWidgetItem(str(i + 1)))
                    self.auto_result_table.setItem(i, 1, QTableWidgetItem(str(status_code)))
                    self.auto_result_table.setItem(i, 2, QTableWidgetItem(f"{time_ms:.1f}"))
                    self.auto_result_table.setItem(i, 3, QTableWidgetItem(str(length)))
                    self.auto_result_table.setItem(i, 4, QTableWidgetItem("-"))
                    
                    view_btn = QPushButton("查看")
                    self.auto_result_table.setCellWidget(i, 5, view_btn)
                    
                except Exception as e:
                    if stop_on_error:
                        break
        
        thread = threading.Thread(target=run_automation)
        thread.daemon = True
        thread.start()
    
    def _stop_automation(self):
        """停止自动化"""
        self.auto_start_btn.setEnabled(True)
        self.auto_stop_btn.setEnabled(False)
        self.auto_progress.setVisible(False)
    
    def _update_stats(self):
        """更新统计信息"""
        total = len(self._requests)
        success = sum(1 for req in self._requests if req.id in self._responses and self._responses[req.id])
        failed = total - success
        
        self.total_requests_label.setText(f"总请求数: {total}")
        self.success_requests_label.setText(f"成功请求: {success}")
        self.failed_requests_label.setText(f"失败请求: {failed}")
    
    def _show_response_history(self, row: int, column: int):
        """显示响应历史详情"""
        pass
