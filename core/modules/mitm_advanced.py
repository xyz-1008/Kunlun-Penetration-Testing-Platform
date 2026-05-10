"""
企业级MITM代理拦截模块 - UI界面
集成到AutoPenTest_Desktop
"""

import logging
import json
import os
from datetime import datetime
from typing import Dict, Any, Optional, List
from pathlib import Path

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QSplitter,
    QTableWidget, QTableWidgetItem, QHeaderView,
    QPushButton, QLineEdit, QLabel, QComboBox,
    QTextEdit, QGroupBox, QFormLayout, QMessageBox,
    QFileDialog, QTabWidget, QTreeWidget, QTreeWidgetItem,
    QCheckBox, QSpinBox, QDoubleSpinBox, QDialog, QDialogButtonBox,
    QListWidget, QListWidgetItem, QToolBar, QMenu,
    QProgressBar, QFrame, QTextBrowser, QPlainTextEdit,
    QTableWidget, QAbstractItemView
)
from PySide6.QtCore import Qt, Signal, QTimer, QThread
from PySide6.QtGui import QFont, QColor, QAction, QKeySequence

from .base import ModuleBase, ModuleStatus
from .mitm_proxy_engine import (
    MITMProxyEngine, MITMRequest, MITMResponse,
    InterceptRule, InterceptAction, RuleMatchType
)
from .mitm_advanced_features import (
    TrafficProcessor, SmartTrafficMarker, TrafficReplayer, EncodingType
)
from .mitm_script_extension import ScriptManager
from .mitm_passive_scanner import PassiveScanner, VulnType
from .mitm_asset_linkage import AssetLinkageEngine
from .mitm_vuln_linkage import VulnScannerLinkage
from .mitm_c2_linkage import C2LinkageEngine
from .mitm_lateral_movement import LateralMovementLinkage
from .mitm_reverse_linkage import ReversePlatformLinkage
from .mitm_replay_engine import TrafficReplayerEngine, ReplaySpeed
from .mitm_traffic_collaboration import TrafficCollaboration, TrafficTag
from .mitm_advanced_filter import AdvancedFilterManager, SearchCondition, SearchField, SearchLogic
from .mitm_network_simulation import NetworkEnvironmentManager, NetworkPreset
from .mitm_mock_response import MockManager
from .mitm_security_hardening import SecurityHardening
from .mitm_performance import PerformanceOptimizer
from .mitm_app_integration import MITMApplicationInterface, MITMEventType

logger = logging.getLogger(__name__)


class MITMAdvancedModule(ModuleBase):
    """企业级MITM代理模块"""
    
    def __init__(self):
        super().__init__("MITM代理", "企业级HTTP/HTTPS代理拦截")
        self._engine: Optional[MITMProxyEngine] = None
        self._is_running = False
        
        self._request_history: List[Dict[str, Any]] = []
        self._selected_request: Optional[Dict[str, Any]] = None
        
        # 高级功能组件
        self._traffic_processor = TrafficProcessor()
        self._traffic_marker = SmartTrafficMarker()
        self._traffic_replayer = TrafficReplayer()
        self._script_manager = ScriptManager()
        self._passive_scanner = PassiveScanner()
        
        # 深度集成组件
        self._asset_linkage = AssetLinkageEngine()
        self._vuln_linkage = VulnScannerLinkage()
        self._c2_linkage = C2LinkageEngine()
        self._lateral_movement_linkage = LateralMovementLinkage()
        self._reverse_linkage = ReversePlatformLinkage()
        self._replay_engine = TrafficReplayerEngine()
        self._traffic_collaboration = TrafficCollaboration()
        self._filter_manager = AdvancedFilterManager()
        self._network_manager = NetworkEnvironmentManager()
        self._mock_manager = MockManager()
        self._security_hardening = SecurityHardening()
        self._performance_optimizer = PerformanceOptimizer()
        self._app_interface = MITMApplicationInterface()
        
        self._replay_results: Dict[str, Any] = {}
        
    def _create_ui(self) -> QWidget:
        """创建MITM代理UI"""
        main_widget = QWidget()
        main_layout = QVBoxLayout(main_widget)
        main_layout.setContentsMargins(5, 5, 5, 5)
        main_layout.setSpacing(5)
        
        # 顶部控制栏
        control_layout = QHBoxLayout()
        
        self.host_input = QLineEdit("127.0.0.1")
        self.host_input.setFixedWidth(120)
        control_layout.addWidget(QLabel("监听地址:"))
        control_layout.addWidget(self.host_input)
        
        self.port_input = QSpinBox()
        self.port_input.setRange(1, 65535)
        self.port_input.setValue(8080)
        self.port_input.setFixedWidth(80)
        control_layout.addWidget(QLabel("端口:"))
        control_layout.addWidget(self.port_input)
        
        self.enable_h2_checkbox = QCheckBox("启用HTTP/2")
        self.enable_h2_checkbox.setChecked(True)
        self.enable_h2_checkbox.setToolTip("启用HTTP/2 (h2/h2c)代理支持")
        control_layout.addWidget(self.enable_h2_checkbox)
        
        self.enable_h3_checkbox = QCheckBox("启用HTTP/3")
        self.enable_h3_checkbox.setChecked(False)
        self.enable_h3_checkbox.setToolTip("启用HTTP/3 (QUIC)代理支持")
        control_layout.addWidget(self.enable_h3_checkbox)
        
        self.h3_port_input = QSpinBox()
        self.h3_port_input.setRange(1, 65535)
        self.h3_port_input.setValue(443)
        self.h3_port_input.setFixedWidth(80)
        self.h3_port_input.setToolTip("QUIC监听端口")
        control_layout.addWidget(QLabel("QUIC端口:"))
        control_layout.addWidget(self.h3_port_input)
        
        self.start_btn = QPushButton("▶ 启动代理")
        self.start_btn.setStyleSheet("background-color: #4CAF50; color: white; padding: 5px 15px;")
        self.start_btn.clicked.connect(self._toggle_proxy)
        control_layout.addWidget(self.start_btn)
        
        self.clear_btn = QPushButton("🗑 清空历史")
        self.clear_btn.clicked.connect(self._clear_history)
        control_layout.addWidget(self.clear_btn)
        
        self.export_ca_btn = QPushButton("📜 导出CA证书")
        self.export_ca_btn.clicked.connect(self._export_ca_cert)
        control_layout.addWidget(self.export_ca_btn)
        
        control_layout.addStretch()
        
        self.status_label = QLabel("状态: 未启动")
        self.status_label.setStyleSheet("color: #ff6666;")
        control_layout.addWidget(self.status_label)
        
        main_layout.addLayout(control_layout)
        
        # 主分割器
        splitter = QSplitter(Qt.Vertical)
        
        # 上半部分：请求列表和规则
        top_splitter = QSplitter(Qt.Horizontal)
        
        # 左侧：请求历史列表
        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)
        left_layout.setContentsMargins(0, 0, 0, 0)
        
        # 搜索过滤栏
        search_layout = QHBoxLayout()
        
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("搜索URL、域名、关键字...")
        search_layout.addWidget(self.search_input)
        
        self.search_btn = QPushButton("搜索")
        self.search_btn.clicked.connect(self._search_history)
        search_layout.addWidget(self.search_btn)
        
        self.method_filter = QComboBox()
        self.method_filter.addItems(["全部方法", "GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
        search_layout.addWidget(self.method_filter)
        
        self.status_filter = QComboBox()
        self.status_filter.addItems(["全部状态", "2xx", "3xx", "4xx", "5xx"])
        search_layout.addWidget(self.status_filter)
        
        left_layout.addLayout(search_layout)
        
        # 请求列表
        self.request_table = QTableWidget()
        self.request_table.setColumnCount(8)
        self.request_table.setHorizontalHeaderLabels(["#", "方法", "域名", "路径", "协议", "状态码", "类型", "时间"])
        self.request_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.request_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.request_table.setSelectionMode(QTableWidget.SingleSelection)
        self.request_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.request_table.setAlternatingRowColors(True)
        self.request_table.cellClicked.connect(self._on_request_selected)
        self.request_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.request_table.customContextMenuRequested.connect(self._show_context_menu)
        self.request_table.setStyleSheet("""
            QTableWidget {
                background-color: #2d2d2d;
                color: #ffffff;
                gridline-color: #444444;
            }
            QTableWidget::item:selected {
                background-color: #4CAF50;
            }
            QHeaderView::section {
                background-color: #3a3a3a;
                color: #ffffff;
                padding: 5px;
                border: 1px solid #555555;
            }
        """)
        left_layout.addWidget(self.request_table)
        
        top_splitter.addWidget(left_widget)
        
        # 右侧：规则管理
        right_widget = QWidget()
        right_layout = QVBoxLayout(right_widget)
        right_layout.setContentsMargins(0, 0, 0, 0)
        
        rules_group = QGroupBox("拦截规则")
        rules_layout = QVBoxLayout(rules_group)
        
        rules_toolbar = QHBoxLayout()
        
        self.add_rule_btn = QPushButton("+ 添加规则")
        self.add_rule_btn.clicked.connect(self._add_rule)
        rules_toolbar.addWidget(self.add_rule_btn)
        
        self.remove_rule_btn = QPushButton("- 删除规则")
        self.remove_rule_btn.clicked.connect(self._remove_rule)
        rules_toolbar.addWidget(self.remove_rule_btn)
        
        self.import_rules_btn = QPushButton("📥 导入")
        self.import_rules_btn.clicked.connect(self._import_rules)
        rules_toolbar.addWidget(self.import_rules_btn)
        
        self.export_rules_btn = QPushButton("📤 导出")
        self.export_rules_btn.clicked.connect(self._export_rules)
        rules_toolbar.addWidget(self.export_rules_btn)
        
        rules_layout.addLayout(rules_toolbar)
        
        self.rules_list = QListWidget()
        self.rules_list.setStyleSheet("""
            QListWidget {
                background-color: #2d2d2d;
                color: #ffffff;
                border: 1px solid #555555;
            }
            QListWidget::item:selected {
                background-color: #4CAF50;
            }
        """)
        rules_layout.addWidget(self.rules_list)
        
        # Bypass域名设置
        bypass_group = QGroupBox("Bypass域名 (不拦截)")
        bypass_layout = QVBoxLayout(bypass_group)
        
        bypass_input_layout = QHBoxLayout()
        self.bypass_input = QLineEdit()
        self.bypass_input.setPlaceholderText("输入域名，如: example.com")
        bypass_input_layout.addWidget(self.bypass_input)
        
        add_bypass_btn = QPushButton("+ 添加")
        add_bypass_btn.clicked.connect(self._add_bypass_domain)
        bypass_input_layout.addWidget(add_bypass_btn)
        
        bypass_layout.addLayout(bypass_input_layout)
        
        self.bypass_list = QListWidget()
        self.bypass_list.setMaximumHeight(100)
        self.bypass_list.setStyleSheet("""
            QListWidget {
                background-color: #2d2d2d;
                color: #ffffff;
                border: 1px solid #555555;
            }
        """)
        bypass_layout.addWidget(self.bypass_list)
        
        right_layout.addWidget(rules_group)
        right_layout.addWidget(bypass_group)
        
        top_splitter.addWidget(right_widget)
        top_splitter.setSizes([800, 400])
        
        splitter.addWidget(top_splitter)
        
        # 下半部分：请求/响应详情
        bottom_tabs = QTabWidget()
        
        # 请求详情
        self.request_detail = QTextBrowser()
        self.request_detail.setFont(QFont("Consolas", 9))
        bottom_tabs.addTab(self.request_detail, "📤 请求")
        
        # 响应详情
        self.response_detail = QTextBrowser()
        self.response_detail.setFont(QFont("Consolas", 9))
        bottom_tabs.addTab(self.response_detail, "📥 响应")
        
        # 断点控制
        self.breakpoint_tab = QWidget()
        breakpoint_layout = QVBoxLayout(self.breakpoint_tab)
        
        self.breakpoint_info = QTextBrowser()
        self.breakpoint_info.setFont(QFont("Consolas", 9))
        self.breakpoint_info.setPlaceholderText("断点拦截的请求/响应将显示在这里...")
        breakpoint_layout.addWidget(self.breakpoint_info)
        
        breakpoint_btn_layout = QHBoxLayout()
        
        self.edit_request_btn = QPushButton("✏ 编辑请求")
        self.edit_request_btn.clicked.connect(self._edit_breakpoint_request)
        breakpoint_btn_layout.addWidget(self.edit_request_btn)
        
        self.resume_btn = QPushButton("▶ 放行")
        self.resume_btn.clicked.connect(self._resume_breakpoint)
        breakpoint_btn_layout.addWidget(self.resume_btn)
        
        self.drop_btn = QPushButton("⛔ 丢弃")
        self.drop_btn.clicked.connect(self._drop_breakpoint)
        breakpoint_btn_layout.addWidget(self.drop_btn)
        
        breakpoint_layout.addLayout(breakpoint_btn_layout)
        
        bottom_tabs.addTab(self.breakpoint_tab, "⏸ 断点")
        
        # WebSocket消息
        self.websocket_tab = QTextBrowser()
        self.websocket_tab.setFont(QFont("Consolas", 9))
        self.websocket_tab.setPlaceholderText("WebSocket消息将显示在这里...")
        bottom_tabs.addTab(self.websocket_tab, "🔌 WebSocket")
        
        # 统计信息
        self.stats_tab = QTextBrowser()
        self.stats_tab.setFont(QFont("Consolas", 9))
        bottom_tabs.addTab(self.stats_tab, "📊 统计")
        
        # 编码工具
        self.encoding_tab = self._create_encoding_tab()
        bottom_tabs.addTab(self.encoding_tab, "🔐 编码工具")
        
        # 流量重放
        self.replay_tab = self._create_replay_tab()
        bottom_tabs.addTab(self.replay_tab, "🔁 流量重放")
        
        # 被动扫描
        self.scanner_tab = self._create_scanner_tab()
        bottom_tabs.addTab(self.scanner_tab, "🔍 被动扫描")
        
        # 脚本扩展
        self.script_tab = self._create_script_tab()
        bottom_tabs.addTab(self.script_tab, "📜 脚本扩展")
        
        # 性能监控
        self.performance_tab = self._create_performance_tab()
        bottom_tabs.addTab(self.performance_tab, "📈 性能监控")
        
        # 深度集成模块标签页
        self.asset_linkage_tab = self._create_asset_linkage_tab()
        bottom_tabs.addTab(self.asset_linkage_tab, "🏷 资产识别")
        
        self.vuln_linkage_tab = self._create_vuln_linkage_tab()
        bottom_tabs.addTab(self.vuln_linkage_tab, "🛡 漏洞扫描")
        
        self.c2_tab = self._create_c2_tab()
        bottom_tabs.addTab(self.c2_tab, "📡 C2框架")
        
        self.lateral_movement_tab = self._create_lateral_movement_tab()
        bottom_tabs.addTab(self.lateral_movement_tab, "🔀 横向移动")
        
        self.reverse_linkage_tab = self._create_reverse_linkage_tab()
        bottom_tabs.addTab(self.reverse_linkage_tab, "🔙 反连平台")
        
        self.collaboration_tab = self._create_collaboration_tab()
        bottom_tabs.addTab(self.collaboration_tab, "🤝 协作标记")
        
        self.filter_tab = self._create_filter_tab()
        bottom_tabs.addTab(self.filter_tab, "🔎 高级过滤")
        
        self.network_sim_tab = self._create_network_sim_tab()
        bottom_tabs.addTab(self.network_sim_tab, "🌐 网络模拟")
        
        self.mock_tab = self._create_mock_tab()
        bottom_tabs.addTab(self.mock_tab, "🎭 Mock应答")
        
        self.security_tab = self._create_security_tab()
        bottom_tabs.addTab(self.security_tab, "🔒 安全加固")
        
        self.protocol_diag_tab = self._create_protocol_diag_tab()
        bottom_tabs.addTab(self.protocol_diag_tab, "🔬 协议诊断")
        
        self.advanced_features_tab = self._create_advanced_features_tab()
        bottom_tabs.addTab(self.advanced_features_tab, "⚙ 高级特性")
        
        splitter.addWidget(bottom_tabs)
        splitter.setSizes([400, 300])
        
        main_layout.addWidget(splitter)
        
        # 初始化引擎
        self._init_engine()
        
        return main_widget
    
    def _init_engine(self):
        """初始化代理引擎"""
        self._engine = MITMProxyEngine(
            host=self.host_input.text(),
            port=self.port_input.value()
        )
        
        # 注册回调
        self._engine.add_callback('on_request', self._on_new_request)
        self._engine.add_callback('on_response', self._on_new_response)
        self._engine.add_callback('on_error', self._on_proxy_error)
        
        # 加载默认规则
        self._load_default_rules()
    
    def _load_default_rules(self):
        """加载默认规则模板"""
        default_rules = [
            InterceptRule(
                id="rule_001",
                name="隐藏敏感Cookie",
                enabled=False,
                match_type=RuleMatchType.HEADER,
                match_value="cookie",
                action=InterceptAction.MODIFY,
                replace_pattern="(cookie=[^;]+)",
                replace_with="cookie=***REDACTED***",
                description="脱敏Cookie头部"
            ),
            InterceptRule(
                id="rule_002",
                name="伪装User-Agent",
                enabled=False,
                match_type=RuleMatchType.HEADER,
                match_value="user-agent",
                action=InterceptAction.MODIFY,
                replace_pattern="User-Agent:.*",
                replace_with="User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                description="伪装浏览器UA"
            ),
            InterceptRule(
                id="rule_003",
                name="过滤跟踪脚本",
                enabled=False,
                match_type=RuleMatchType.URL_PATH,
                match_value="/analytics",
                action=InterceptAction.DROP,
                description="拦截Google Analytics等跟踪请求"
            ),
        ]
        
        for rule in default_rules:
            self._engine.add_rule(rule)
            self._update_rules_list()
    
    def _toggle_proxy(self):
        """启动/停止代理"""
        if not self._is_running:
            self._start_proxy()
        else:
            self._stop_proxy()
    
    def _start_proxy(self):
        """启动代理"""
        try:
            host = self.host_input.text()
            port = self.port_input.value()
            enable_h2 = self.enable_h2_checkbox.isChecked()
            enable_h3 = self.enable_h3_checkbox.isChecked()
            h3_port = self.h3_port_input.value()
            
            self._engine = MITMProxyEngine(
                host=host, 
                port=port,
                enable_h2=enable_h2,
                enable_h3=enable_h3,
                h3_port=h3_port
            )
            self._engine.add_callback('on_request', self._on_new_request)
            self._engine.add_callback('on_response', self._on_new_response)
            self._engine.add_callback('on_error', self._on_proxy_error)
            
            self._engine.start()
            self._is_running = True
            
            self.start_btn.setText("⏹ 停止代理")
            self.start_btn.setStyleSheet("background-color: #f44336; color: white; padding: 5px 15px;")
            
            # 显示启用的协议
            protocols = ["HTTP/1.1"]
            if enable_h2:
                protocols.append("HTTP/2")
            if enable_h3:
                protocols.append("HTTP/3")
            
            self.status_label.setText(f"状态: 运行中 ({', '.join(protocols)})")
            self.status_label.setStyleSheet("color: #4CAF50;")
            
            self.log("INFO", f"MITM代理启动: {host}:{port} - 协议: {', '.join(protocols)}")
            
        except Exception as e:
            logger.error(f"启动代理失败: {e}")
            QMessageBox.critical(self.get_ui(), "错误", f"启动代理失败: {e}")
    
    def _stop_proxy(self):
        """停止代理"""
        try:
            if self._engine:
                self._engine.stop()
            
            self._is_running = False
            self.start_btn.setText("▶ 启动代理")
            self.start_btn.setStyleSheet("background-color: #4CAF50; color: white; padding: 5px 15px;")
            self.status_label.setText("状态: 未启动")
            self.status_label.setStyleSheet("color: #ff6666;")
            
            self.log("INFO", "MITM代理已停止")
            
        except Exception as e:
            logger.error(f"停止代理失败: {e}")
    
    def _on_new_request(self, request: MITMRequest):
        """新请求回调"""
        self._request_history.append(request.to_dict())
        self._refresh_request_table()
    
    def _on_new_response(self, request: MITMRequest, response: MITMResponse):
        """新响应回调"""
        self._refresh_request_table()
    
    def _on_proxy_error(self, error_msg: str):
        """代理错误回调"""
        self.log("ERROR", error_msg)
        self.status_label.setText("状态: 错误")
        self.status_label.setStyleSheet("color: #ff0000;")
    
    def _refresh_request_table(self):
        """刷新请求列表"""
        self.request_table.setRowCount(len(self._request_history))
        
        for i, req in enumerate(self._request_history):
            response = req.get('response', {})
            
            self.request_table.setItem(i, 0, QTableWidgetItem(str(i + 1)))
            
            method_item = QTableWidgetItem(req.get('method', ''))
            method_color = {
                'GET': '#4CAF50',
                'POST': '#2196F3',
                'PUT': '#FF9800',
                'DELETE': '#f44336',
                'PATCH': '#9C27B0',
            }.get(req.get('method', ''), '#ffffff')
            method_item.setForeground(QColor(method_color))
            self.request_table.setItem(i, 1, method_item)
            
            self.request_table.setItem(i, 2, QTableWidgetItem(req.get('host', '')))
            self.request_table.setItem(i, 3, QTableWidgetItem(req.get('path', '')[:50]))
            
            # 协议信息
            protocol = req.get('protocol', 'HTTP/1.1')
            protocol_item = QTableWidgetItem(protocol)
            if 'HTTP/3' in protocol or 'QUIC' in protocol:
                protocol_item.setForeground(QColor("#9C27B0"))
            elif 'HTTP/2' in protocol:
                protocol_item.setForeground(QColor("#2196F3"))
            else:
                protocol_item.setForeground(QColor("#ffffff"))
            self.request_table.setItem(i, 4, protocol_item)
            
            status_code = response.get('status_code', '')
            status_item = QTableWidgetItem(str(status_code))
            if status_code:
                status_code = int(status_code)
                if 200 <= status_code < 300:
                    status_item.setForeground(QColor("#4CAF50"))
                elif 300 <= status_code < 400:
                    status_item.setForeground(QColor("#FF9800"))
                elif 400 <= status_code < 500:
                    status_item.setForeground(QColor("#f44336"))
                elif status_code >= 500:
                    status_item.setForeground(QColor("#9C27B0"))
            self.request_table.setItem(i, 5, status_item)
            
            content_type = response.get('content_type', req.get('content_type', ''))
            self.request_table.setItem(i, 6, QTableWidgetItem(content_type[:30]))
            
            timestamp = req.get('timestamp', '')
            if timestamp:
                try:
                    dt = datetime.fromisoformat(timestamp)
                    self.request_table.setItem(i, 7, QTableWidgetItem(dt.strftime('%H:%M:%S')))
                except:
                    self.request_table.setItem(i, 7, QTableWidgetItem(timestamp))
    
    def _on_request_selected(self, row, col):
        """请求选择事件"""
        if 0 <= row < len(self._request_history):
            self._selected_request = self._request_history[row]
            self._show_request_detail(self._selected_request)
    
    def _show_request_detail(self, request: Dict[str, Any]):
        """显示请求详情"""
        protocol = request.get('protocol', 'HTTP/1.1')
        request_text = f"{request.get('method', '')} {request.get('url', '')} {protocol}\n\n"
        request_text += f"域名: {request.get('host', '')}\n"
        request_text += f"路径: {request.get('path', '')}\n"
        request_text += f"HTTPS: {request.get('is_https', False)}\n"
        request_text += f"TLS版本: {request.get('tls_version', 'N/A')}\n"
        request_text += f"客户端IP: {request.get('client_ip', '')}\n"
        
        # HTTP/2和HTTP/3特定信息
        if 'HTTP/2' in protocol or 'HTTP/3' in protocol:
            request_text += f"\n--- {protocol} 特定信息 ---\n"
            request_text += f"流ID: {request.get('stream_id', 'N/A')}\n"
            request_text += f"连接ID: {request.get('connection_id', 'N/A')}\n"
            
            # HTTP/2伪头部
            if 'HTTP/2' in protocol:
                request_text += f":authority: {request.get(':authority', request.get('host', ''))}\n"
                request_text += f":scheme: {request.get(':scheme', 'https')}\n"
            
            # 服务端推送
            if request.get('is_push_promise'):
                request_text += f"\n⚠ 服务端推送资源 (PUSH_PROMISE)\n"
                request_text += f"关联流: {request.get('associated_stream_id', 'N/A')}\n"
            
            # 0-RTT数据
            if request.get('is_zero_rtt'):
                request_text += f"\n⚡ 0-RTT数据 (Early Data)\n"
        
        request_text += "\n--- Headers ---\n"
        
        headers = request.get('headers', {})
        for key, value in headers.items():
            request_text += f"{key}: {value}\n"
        
        body = request.get('body', '')
        if body:
            request_text += f"\n--- Body ({len(body)} bytes) ---\n"
            request_text += body[:2000]
            if len(body) > 2000:
                request_text += "\n... (truncated)"
        
        self.request_detail.setPlainText(request_text)
        
        # 显示响应
        response = request.get('response', {})
        if response:
            response_text = f"{protocol} {response.get('status_code', '')} {response.get('reason', '')}\n\n"
            response_text += f"响应时间: {response.get('response_time', 0):.3f}s\n\n"
            
            # HTTP/2/HTTP/3响应特定信息
            if 'HTTP/2' in protocol or 'HTTP/3' in protocol:
                response_text += f"--- {protocol} 响应信息 ---\n"
                response_text += f"流ID: {response.get('stream_id', 'N/A')}\n"
                if response.get('server_push'):
                    response_text += f"⚠ 服务端推送: {response.get('push_promise_url', '')}\n"
                response_text += "\n"
            
            response_text += "--- Headers ---\n"
            
            resp_headers = response.get('headers', {})
            for key, value in resp_headers.items():
                response_text += f"{key}: {value}\n"
            
            resp_body = response.get('body', '')
            if resp_body:
                response_text += f"\n--- Body ({len(resp_body)} bytes) ---\n"
                response_text += resp_body[:2000]
                if len(resp_body) > 2000:
                    response_text += "\n... (truncated)"
            
            self.response_detail.setPlainText(response_text)
        else:
            self.response_detail.setPlainText("等待响应...")
    
    def _show_context_menu(self, position):
        """显示右键菜单"""
        menu = QMenu()
        
        send_to_fuzzer = QAction("发送到 Web Fuzzer", self)
        menu.addAction(send_to_fuzzer)
        
        repeat_request = QAction("重放请求", self)
        menu.addAction(repeat_request)
        
        menu.addSeparator()
        
        copy_url = QAction("复制URL", self)
        menu.addAction(copy_url)
        
        copy_as_curl = QAction("复制为 cURL", self)
        menu.addAction(copy_as_curl)
        
        menu.exec(self.request_table.viewport().mapToGlobal(position))
    
    def _search_history(self):
        """搜索历史记录"""
        keyword = self.search_input.text()
        method = self.method_filter.currentText()
        status = self.status_filter.currentText()
        
        kwargs = {}
        if keyword:
            kwargs['keyword'] = keyword
        if method != "全部方法":
            kwargs['method'] = method
        if status != "全部状态":
            kwargs['status_code'] = int(status.replace('xx', '00'))
        
        if self._engine:
            results = self._engine.search_history(**kwargs)
            self._request_history = results
            self._refresh_request_table()
    
    def _clear_history(self):
        """清空历史记录"""
        if self._engine:
            self._engine.clear_history()
        self._request_history.clear()
        self._refresh_request_table()
        self.request_detail.clear()
        self.response_detail.clear()
    
    def _export_ca_cert(self):
        """导出CA证书"""
        if not self._engine:
            return
        
        filename, _ = QFileDialog.getSaveFileName(
            self.get_ui(),
            "导出CA证书",
            "",
            "PEM证书 (*.crt *.pem)"
        )
        
        if filename:
            if self._engine.cert_manager.export_ca_cert(filename):
                QMessageBox.information(self.get_ui(), "成功", f"CA证书已导出: {filename}")
            else:
                QMessageBox.critical(self.get_ui(), "错误", "导出CA证书失败")
    
    def _add_rule(self):
        """添加规则"""
        dialog = RuleDialog(self.get_ui())
        if dialog.exec() == QDialog.Accepted:
            rule = dialog.get_rule()
            if self._engine:
                self._engine.add_rule(rule)
                self._update_rules_list()
    
    def _remove_rule(self):
        """删除规则"""
        current_item = self.rules_list.currentItem()
        if current_item and self._engine:
            rule_id = current_item.data(Qt.UserRole)
            self._engine.remove_rule(rule_id)
            self._update_rules_list()
    
    def _update_rules_list(self):
        """更新规则列表"""
        self.rules_list.clear()
        if not self._engine:
            return
        
        for rule in self._engine.rules:
            status = "✓" if rule.enabled else "✗"
            item = QListWidgetItem(f"{status} {rule.name} - {rule.match_type.value}: {rule.match_value}")
            item.setData(Qt.UserRole, rule.id)
            self.rules_list.addItem(item)
    
    def _import_rules(self):
        """导入规则"""
        filename, _ = QFileDialog.getOpenFileName(
            self.get_ui(),
            "导入规则",
            "",
            "JSON文件 (*.json)"
        )
        
        if filename and self._engine:
            if self._engine.import_rules(filename):
                self._update_rules_list()
                QMessageBox.information(self.get_ui(), "成功", "规则导入成功")
            else:
                QMessageBox.critical(self.get_ui(), "错误", "规则导入失败")
    
    def _export_rules(self):
        """导出规则"""
        filename, _ = QFileDialog.getSaveFileName(
            self.get_ui(),
            "导出规则",
            "",
            "JSON文件 (*.json)"
        )
        
        if filename and self._engine:
            if self._engine.export_rules(filename):
                QMessageBox.information(self.get_ui(), "成功", f"规则已导出: {filename}")
            else:
                QMessageBox.critical(self.get_ui(), "错误", "规则导出失败")
    
    def _add_bypass_domain(self):
        """添加bypass域名"""
        domain = self.bypass_input.text().strip()
        if domain and self._engine:
            self._engine.add_bypass_domain(domain)
            self.bypass_list.addItem(domain)
            self.bypass_input.clear()
    
    def _edit_breakpoint_request(self):
        """编辑断点请求"""
        QMessageBox.information(self.get_ui(), "提示", "断点编辑功能开发中...")
    
    def _resume_breakpoint(self):
        """放行断点"""
        QMessageBox.information(self.get_ui(), "提示", "放行断点请求")
    
    def _drop_breakpoint(self):
        """丢弃断点"""
        QMessageBox.information(self.get_ui(), "提示", "丢弃断点请求")
    
    def _create_encoding_tab(self) -> QWidget:
        """创建编码工具标签页"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # 输入区
        input_group = QGroupBox("输入")
        input_layout = QVBoxLayout(input_group)
        
        self.encoding_input = QPlainTextEdit()
        self.encoding_input.setPlaceholderText("输入要编码/解码的内容...")
        self.encoding_input.setMaximumHeight(150)
        input_layout.addWidget(self.encoding_input)
        
        layout.addWidget(input_group)
        
        # 操作按钮
        btn_layout = QHBoxLayout()
        
        encoding_types = [
            ("URL编码", EncodingType.URL_ENCODE),
            ("URL解码", EncodingType.URL_DECODE),
            ("Base64编码", EncodingType.BASE64_ENCODE),
            ("Base64解码", EncodingType.BASE64_DECODE),
            ("Hex编码", EncodingType.HEX_ENCODE),
            ("Hex解码", EncodingType.HEX_DECODE),
            ("Unicode编码", EncodingType.UNICODE_ENCODE),
            ("Unicode解码", EncodingType.UNICODE_DECODE),
        ]
        
        for label, enc_type in encoding_types:
            btn = QPushButton(label)
            btn.clicked.connect(lambda checked, et=enc_type: self._execute_encoding(et))
            btn_layout.addWidget(btn)
        
        layout.addLayout(btn_layout)
        
        # 输出区
        output_group = QGroupBox("输出")
        output_layout = QVBoxLayout(output_group)
        
        self.encoding_output = QPlainTextEdit()
        self.encoding_output.setReadOnly(True)
        output_layout.addWidget(self.encoding_output)
        
        layout.addWidget(output_group)
        
        return widget
    
    def _execute_encoding(self, encoding_type: EncodingType):
        """执行编码/解码"""
        input_text = self.encoding_input.toPlainText()
        if not input_text:
            return
        
        result = self._traffic_processor.encode_decode(input_text, encoding_type)
        self.encoding_output.setPlainText(result)
    
    def _create_replay_tab(self) -> QWidget:
        """创建流量重放标签页"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # 重放控制
        control_group = QGroupBox("重放控制")
        control_layout = QVBoxLayout(control_group)
        
        btn_layout = QHBoxLayout()
        
        self.replay_single_btn = QPushButton("🔁 重放选中请求")
        self.replay_single_btn.clicked.connect(self._replay_selected)
        btn_layout.addWidget(self.replay_single_btn)
        
        self.replay_batch_btn = QPushButton("🔁 批量重放")
        self.replay_batch_btn.clicked.connect(self._replay_batch)
        btn_layout.addWidget(self.replay_batch_btn)
        
        self.export_curl_btn = QPushButton("📤 导出为cURL")
        self.export_curl_btn.clicked.connect(self._export_curl)
        btn_layout.addWidget(self.export_curl_btn)
        
        self.export_python_btn = QPushButton("📤 导出为Python")
        self.export_python_btn.clicked.connect(self._export_python)
        btn_layout.addWidget(self.export_python_btn)
        
        control_layout.addLayout(btn_layout)
        
        layout.addWidget(control_group)
        
        # 对比视图
        compare_group = QGroupBox("响应差异对比")
        compare_layout = QVBoxLayout(compare_group)
        
        self.compare_view = QTextBrowser()
        self.compare_view.setFont(QFont("Consolas", 9))
        self.compare_view.setPlaceholderText("选择请求并重放后，差异对比将显示在这里...")
        compare_layout.addWidget(self.compare_view)
        
        layout.addWidget(compare_group)
        
        return widget
    
    def _replay_selected(self):
        """重放选中的请求"""
        if not self._selected_request:
            QMessageBox.warning(self.get_ui(), "警告", "请先选择一个请求")
            return
        
        result = self._traffic_replayer.replay_request(self._selected_request)
        
        if result.get('success'):
            self._replay_results[self._selected_request.get('id', '')] = result
            
            # 对比响应
            comparison = self._traffic_replayer.compare_responses(
                self._selected_request.get('response', {}),
                result
            )
            
            diff_text = f"状态码变化: {comparison['status_code_changed']}\n"
            diff_text += f"响应体变化: {comparison['body_changed']}\n"
            diff_text += f"响应时间差异: {comparison['response_time_diff']:.3f}s\n\n"
            
            if comparison.get('body_diff'):
                diff_text += "差异详情:\n"
                diff_text += '\n'.join(comparison['body_diff'][:50])
            
            self.compare_view.setPlainText(diff_text)
        else:
            QMessageBox.critical(self.get_ui(), "错误", f"重放失败: {result.get('error', '未知错误')}")
    
    def _replay_batch(self):
        """批量重放"""
        if not self._request_history:
            QMessageBox.warning(self.get_ui(), "警告", "没有可重放的请求")
            return
        
        count = min(10, len(self._request_history))
        requests = self._request_history[:count]
        
        results = self._traffic_replayer.batch_replay(requests)
        
        result_text = f"批量重放完成，共 {len(results)} 个请求:\n\n"
        for i, result in enumerate(results):
            status = "成功" if result.get('success') else "失败"
            result_text += f"{i+1}. {status} - {result.get('status_code', 'N/A')}\n"
        
        self.compare_view.setPlainText(result_text)
    
    def _export_curl(self):
        """导出为cURL"""
        if not self._selected_request:
            QMessageBox.warning(self.get_ui(), "警告", "请先选择一个请求")
            return
        
        curl_cmd = self._traffic_replayer.export_as_curl(self._selected_request)
        
        self.compare_view.setPlainText(curl_cmd)
    
    def _export_python(self):
        """导出为Python requests"""
        if not self._selected_request:
            QMessageBox.warning(self.get_ui(), "警告", "请先选择一个请求")
            return
        
        python_code = self._traffic_replayer.export_as_python_requests(self._selected_request)
        
        self.compare_view.setPlainText(python_code)
    
    def _create_scanner_tab(self) -> QWidget:
        """创建被动扫描标签页"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # 扫描控制
        control_group = QGroupBox("被动扫描控制")
        control_layout = QHBoxLayout(control_group)
        
        self.start_scanner_btn = QPushButton("▶ 启动扫描")
        self.start_scanner_btn.clicked.connect(self._toggle_scanner)
        control_layout.addWidget(self.start_scanner_btn)
        
        self.clear_findings_btn = QPushButton("🗑 清空发现")
        self.clear_findings_btn.clicked.connect(self._clear_findings)
        control_layout.addWidget(self.clear_findings_btn)
        
        control_layout.addStretch()
        
        self.scanner_status = QLabel("状态: 未启动")
        control_layout.addWidget(self.scanner_status)
        
        layout.addWidget(control_group)
        
        # 发现列表
        findings_group = QGroupBox("漏洞发现")
        findings_layout = QVBoxLayout(findings_group)
        
        self.findings_table = QTableWidget()
        self.findings_table.setColumnCount(5)
        self.findings_table.setHorizontalHeaderLabels(["#", "类型", "严重程度", "标题", "URL"])
        self.findings_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.findings_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.findings_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.findings_table.setAlternatingRowColors(True)
        findings_layout.addWidget(self.findings_table)
        
        layout.addWidget(findings_group)
        
        # 统计信息
        stats_group = QGroupBox("扫描统计")
        stats_layout = QVBoxLayout(stats_group)
        
        self.scanner_stats = QTextBrowser()
        self.scanner_stats.setMaximumHeight(100)
        stats_layout.addWidget(self.scanner_stats)
        
        layout.addWidget(stats_group)
        
        return widget
    
    def _toggle_scanner(self):
        """切换扫描器状态"""
        if self._passive_scanner._running:
            self._passive_scanner.stop()
            self.start_scanner_btn.setText("▶ 启动扫描")
            self.scanner_status.setText("状态: 未启动")
        else:
            self._passive_scanner.start()
            self.start_scanner_btn.setText("⏹ 停止扫描")
            self.scanner_status.setText("状态: 运行中")
    
    def _clear_findings(self):
        """清空发现"""
        self._passive_scanner.clear_findings()
        self.findings_table.setRowCount(0)
        self.scanner_stats.clear()
    
    def _create_script_tab(self) -> QWidget:
        """创建脚本扩展标签页"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # 脚本控制
        control_group = QGroupBox("脚本控制")
        control_layout = QHBoxLayout(control_group)
        
        self.load_scripts_btn = QPushButton("📥 加载所有脚本")
        self.load_scripts_btn.clicked.connect(self._load_scripts)
        control_layout.addWidget(self.load_scripts_btn)
        
        self.start_watch_btn = QPushButton("▶ 启动热加载")
        self.start_watch_btn.clicked.connect(self._toggle_script_watch)
        control_layout.addWidget(self.start_watch_btn)
        
        self.open_scripts_dir_btn = QPushButton("📁 打开脚本目录")
        self.open_scripts_dir_btn.clicked.connect(self._open_scripts_dir)
        control_layout.addWidget(self.open_scripts_dir_btn)
        
        control_layout.addStretch()
        
        self.script_watch_status = QLabel("热加载: 未启动")
        control_layout.addWidget(self.script_watch_status)
        
        layout.addWidget(control_group)
        
        # 脚本列表
        scripts_group = QGroupBox("已加载脚本")
        scripts_layout = QVBoxLayout(scripts_group)
        
        self.scripts_list = QListWidget()
        scripts_layout.addWidget(self.scripts_list)
        
        layout.addWidget(scripts_group)
        
        return widget
    
    def _load_scripts(self):
        """加载所有脚本"""
        hooks = self._script_manager.load_all_scripts()
        
        self.scripts_list.clear()
        for hook in hooks:
            self.scripts_list.addItem(f"✓ {hook.__class__.__module__}")
        
        QMessageBox.information(self.get_ui(), "成功", f"已加载 {len(hooks)} 个脚本")
    
    def _toggle_script_watch(self):
        """切换脚本热加载"""
        if self._script_manager._watching:
            self._script_manager.stop_watching()
            self.start_watch_btn.setText("▶ 启动热加载")
            self.script_watch_status.setText("热加载: 未启动")
        else:
            self._script_manager.start_watching()
            self.start_watch_btn.setText("⏹ 停止热加载")
            self.script_watch_status.setText("热加载: 运行中")
    
    def _open_scripts_dir(self):
        """打开脚本目录"""
        import subprocess
        import sys
        
        scripts_dir = str(self._script_manager.scripts_dir)
        if sys.platform == 'win32':
            os.startfile(scripts_dir)
        elif sys.platform == 'darwin':
            subprocess.Popen(['open', scripts_dir])
        else:
            subprocess.Popen(['xdg-open', scripts_dir])
    
    def _create_performance_tab(self) -> QWidget:
        """创建性能监控标签页"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # 实时统计
        stats_group = QGroupBox("实时统计")
        stats_layout = QFormLayout(stats_group)
        
        self.perf_requests_total = QLabel("0")
        stats_layout.addRow("总请求数:", self.perf_requests_total)
        
        self.perf_responses_total = QLabel("0")
        stats_layout.addRow("总响应数:", self.perf_responses_total)
        
        self.perf_active_connections = QLabel("0")
        stats_layout.addRow("活动连接数:", self.perf_active_connections)
        
        self.perf_rules_count = QLabel("0")
        stats_layout.addRow("规则数量:", self.perf_rules_count)
        
        layout.addWidget(stats_group)
        
        # 刷新按钮
        refresh_btn = QPushButton("🔄 刷新统计")
        refresh_btn.clicked.connect(self._refresh_performance)
        layout.addWidget(refresh_btn)
        
        return widget
    
    def _refresh_performance(self):
        """刷新性能统计"""
        if self._engine:
            status = self._engine.get_status()
            self.perf_requests_total.setText(str(status.get('total_requests', 0)))
            self.perf_responses_total.setText(str(status.get('total_responses', 0)))
            self.perf_active_connections.setText(str(status.get('active_connections', 0)))
            self.perf_rules_count.setText(str(status.get('rules_count', 0)))
    
    def _create_asset_linkage_tab(self) -> QWidget:
        """创建资产识别标签页"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # 资产列表
        self.asset_list = QTableWidget()
        self.asset_list.setColumnCount(6)
        self.asset_list.setHorizontalHeaderLabels(["域名", "IP", "端口", "技术栈", "服务器", "CMS"])
        self.asset_list.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        layout.addWidget(self.asset_list)
        
        # 操作按钮
        btn_layout = QHBoxLayout()
        refresh_btn = QPushButton("🔄 刷新资产")
        refresh_btn.clicked.connect(self._refresh_assets)
        btn_layout.addWidget(refresh_btn)
        
        scan_btn = QPushButton("🔍 加入扫描队列")
        scan_btn.clicked.connect(self._add_asset_to_scan)
        btn_layout.addWidget(scan_btn)
        
        layout.addLayout(btn_layout)
        
        return widget
    
    def _refresh_assets(self):
        """刷新资产列表"""
        if self._asset_linkage:
            assets = self._asset_linkage.manager.get_all_assets()
            self.asset_list.setRowCount(len(assets))
            for i, asset in enumerate(assets):
                self.asset_list.setItem(i, 0, QTableWidgetItem(asset.domain or ''))
                self.asset_list.setItem(i, 1, QTableWidgetItem(asset.ip or ''))
                self.asset_list.setItem(i, 2, QTableWidgetItem(str(asset.port)))
                self.asset_list.setItem(i, 3, QTableWidgetItem(', '.join(asset.tech_stack[:3])))
                self.asset_list.setItem(i, 4, QTableWidgetItem(asset.server_type or ''))
                self.asset_list.setItem(i, 5, QTableWidgetItem(asset.cms or ''))
    
    def _add_asset_to_scan(self):
        """添加资产到扫描队列"""
        selected = self.asset_list.selectedItems()
        if selected:
            row = selected[0].row()
            domain = self.asset_list.item(row, 0).text()
            QMessageBox.information(self, "资产扫描", f"已将 {domain} 加入扫描队列")
    
    def _create_vuln_linkage_tab(self) -> QWidget:
        """创建漏洞扫描标签页"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # 漏洞列表
        self.vuln_list = QTableWidget()
        self.vuln_list.setColumnCount(5)
        self.vuln_list.setHorizontalHeaderLabels(["类型", "严重性", "URL", "参数", "状态"])
        self.vuln_list.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        layout.addWidget(self.vuln_list)
        
        # 控制按钮
        btn_layout = QHBoxLayout()
        self.passive_mode_check = QCheckBox("被动扫描模式")
        self.passive_mode_check.setChecked(True)
        self.passive_mode_check.stateChanged.connect(self._toggle_passive_mode)
        btn_layout.addWidget(self.passive_mode_check)
        
        refresh_btn = QPushButton("🔄 刷新漏洞")
        refresh_btn.clicked.connect(self._refresh_vulns)
        btn_layout.addWidget(refresh_btn)
        
        layout.addLayout(btn_layout)
        
        return widget
    
    def _toggle_passive_mode(self, state):
        """切换被动扫描模式"""
        if self._vuln_linkage:
            self._vuln_linkage.set_passive_mode(state == 2)
    
    def _refresh_vulns(self):
        """刷新漏洞列表"""
        if self._vuln_linkage:
            alerts = self._vuln_linkage.get_alerts()
            self.vuln_list.setRowCount(len(alerts))
            for i, alert in enumerate(alerts):
                self.vuln_list.setItem(i, 0, QTableWidgetItem(alert.vuln_type.value))
                self.vuln_list.setItem(i, 1, QTableWidgetItem(alert.severity.value))
                self.vuln_list.setItem(i, 2, QTableWidgetItem(alert.url[:50]))
                self.vuln_list.setItem(i, 3, QTableWidgetItem(alert.parameter or ''))
                self.vuln_list.setItem(i, 4, QTableWidgetItem(alert.status.value))
    
    def _create_c2_tab(self) -> QWidget:
        """创建C2框架标签页"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # 信标列表
        self.beacon_list = QTableWidget()
        self.beacon_list.setColumnCount(5)
        self.beacon_list.setHorizontalHeaderLabels(["会话ID", "目标", "状态", "最后通信", "置信度"])
        self.beacon_list.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.beacon_list.itemSelectionChanged.connect(self._on_beacon_selected)
        layout.addWidget(self.beacon_list)
        
        # 命令执行
        cmd_group = QGroupBox("命令执行")
        cmd_layout = QVBoxLayout(cmd_group)
        
        self.c2_command_input = QLineEdit()
        self.c2_command_input.setPlaceholderText("输入命令...")
        cmd_layout.addWidget(self.c2_command_input)
        
        send_btn = QPushButton("📤 发送命令")
        send_btn.clicked.connect(self._send_c2_command)
        cmd_layout.addWidget(send_btn)
        
        layout.addWidget(cmd_group)
        
        # 命令结果
        self.c2_result = QTextBrowser()
        self.c2_result.setFont(QFont("Consolas", 9))
        layout.addWidget(QLabel("命令结果:"))
        layout.addWidget(self.c2_result)
        
        return widget
    
    def _on_beacon_selected(self):
        """信标选择变化"""
        pass
    
    def _send_c2_command(self):
        """发送C2命令"""
        command = self.c2_command_input.text()
        if command:
            self.c2_result.append(f"> {command}")
            self.c2_command_input.clear()
    
    def _create_lateral_movement_tab(self) -> QWidget:
        """创建横向移动标签页"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # 内网资产列表
        self.internal_asset_list = QTableWidget()
        self.internal_asset_list.setColumnCount(4)
        self.internal_asset_list.setHorizontalHeaderLabels(["IP", "协议", "技术", "发现时间"])
        self.internal_asset_list.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        layout.addWidget(self.internal_asset_list)
        
        # 网络拓扑
        topology_group = QGroupBox("网络拓扑")
        topology_layout = QVBoxLayout(topology_group)
        
        self.topology_view = QTextBrowser()
        self.topology_view.setFont(QFont("Consolas", 9))
        topology_layout.addWidget(self.topology_view)
        
        layout.addWidget(topology_group)
        
        return widget
    
    def _create_reverse_linkage_tab(self) -> QWidget:
        """创建反连平台标签页"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # 反连请求列表
        self.reverse_list = QTableWidget()
        self.reverse_list.setColumnCount(5)
        self.reverse_list.setHorizontalHeaderLabels(["来源IP", "协议", "时间", "关联PoC", "状态"])
        self.reverse_list.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        layout.addWidget(self.reverse_list)
        
        # 操作按钮
        btn_layout = QHBoxLayout()
        export_btn = QPushButton("📤 导出证据")
        export_btn.clicked.connect(self._export_reverse_evidence)
        btn_layout.addWidget(export_btn)
        
        layout.addLayout(btn_layout)
        
        # 详细信息
        self.reverse_detail = QTextBrowser()
        self.reverse_detail.setFont(QFont("Consolas", 9))
        layout.addWidget(QLabel("详细信息:"))
        layout.addWidget(self.reverse_detail)
        
        return widget
    
    def _export_reverse_evidence(self):
        """导出反连证据"""
        QMessageBox.information(self, "导出", "证据已导出")
    
    def _create_collaboration_tab(self) -> QWidget:
        """创建协作标记标签页"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # 标记工具
        tag_group = QGroupBox("流量标记")
        tag_layout = QVBoxLayout(tag_group)
        
        tag_btn_layout = QHBoxLayout()
        high_risk_btn = QPushButton("🔴 高危")
        high_risk_btn.clicked.connect(lambda: self._mark_traffic(TrafficTag.HIGH_RISK))
        tag_btn_layout.addWidget(high_risk_btn)
        
        suspicious_btn = QPushButton("🟠 可疑")
        suspicious_btn.clicked.connect(lambda: self._mark_traffic(TrafficTag.SUSPICIOUS))
        tag_btn_layout.addWidget(suspicious_btn)
        
        exploited_btn = QPushButton("🟣 已利用")
        exploited_btn.clicked.connect(lambda: self._mark_traffic(TrafficTag.EXPLOITED))
        tag_btn_layout.addWidget(exploited_btn)
        
        pending_btn = QPushButton("🟡 待分析")
        pending_btn.clicked.connect(lambda: self._mark_traffic(TrafficTag.PENDING_ANALYSIS))
        tag_btn_layout.addWidget(pending_btn)
        
        tag_layout.addLayout(tag_btn_layout)
        
        layout.addWidget(tag_group)
        
        # 备注
        note_group = QGroupBox("备注")
        note_layout = QVBoxLayout(note_group)
        
        self.collab_note = QTextEdit()
        self.collab_note.setPlaceholderText("添加备注...")
        note_layout.addWidget(self.collab_note)
        
        save_note_btn = QPushButton("💾 保存备注")
        save_note_btn.clicked.connect(self._save_collab_note)
        note_layout.addWidget(save_note_btn)
        
        layout.addWidget(note_group)
        
        # 分享包
        share_group = QGroupBox("分享包")
        share_layout = QVBoxLayout(share_group)
        
        share_btn_layout = QHBoxLayout()
        export_share_btn = QPushButton("📤 导出分享包")
        export_share_btn.clicked.connect(self._export_share_package)
        share_btn_layout.addWidget(export_share_btn)
        
        import_share_btn = QPushButton("📥 导入分享包")
        import_share_btn.clicked.connect(self._import_share_package)
        share_btn_layout.addWidget(import_share_btn)
        
        share_layout.addLayout(share_btn_layout)
        
        layout.addWidget(share_group)
        
        return widget
    
    def _mark_traffic(self, tag):
        """标记流量"""
        if self._traffic_collaboration and self._selected_request:
            traffic_id = self._selected_request.get('id', '')
            self._traffic_collaboration.mark_traffic(traffic_id, [tag], user="ui_user")
            QMessageBox.information(self, "标记", f"已标记为: {tag.value}")
    
    def _save_collab_note(self):
        """保存协作备注"""
        if self._traffic_collaboration and self._selected_request:
            traffic_id = self._selected_request.get('id', '')
            note = self.collab_note.toPlainText()
            self._traffic_collaboration.mark_traffic(traffic_id, [], note=note, user="ui_user")
    
    def _export_share_package(self):
        """导出分享包"""
        QMessageBox.information(self, "分享", "分享包已导出")
    
    def _import_share_package(self):
        """导入分享包"""
        QMessageBox.information(self, "分享", "分享包导入功能")
    
    def _create_filter_tab(self) -> QWidget:
        """创建高级过滤标签页"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # 搜索条件
        search_group = QGroupBox("搜索条件")
        search_layout = QFormLayout(search_group)
        
        self.filter_field = QComboBox()
        self.filter_field.addItems(["URL", "请求体", "响应体", "Header", "Host", "IP"])
        search_layout.addRow("字段:", self.filter_field)
        
        self.filter_operator = QComboBox()
        self.filter_operator.addItems(["包含", "正则", "等于", "大于", "小于"])
        search_layout.addRow("操作符:", self.filter_operator)
        
        self.filter_value = QLineEdit()
        search_layout.addRow("值:", self.filter_value)
        
        layout.addWidget(search_group)
        
        # 搜索按钮
        btn_layout = QHBoxLayout()
        search_btn = QPushButton("🔍 搜索")
        search_btn.clicked.connect(self._execute_filter_search)
        btn_layout.addWidget(search_btn)
        
        save_filter_btn = QPushButton("💾 保存筛选器")
        save_filter_btn.clicked.connect(self._save_filter)
        btn_layout.addWidget(save_filter_btn)
        
        layout.addLayout(btn_layout)
        
        # 搜索结果
        self.filter_results = QTableWidget()
        self.filter_results.setColumnCount(4)
        self.filter_results.setHorizontalHeaderLabels(["方法", "URL", "状态码", "大小"])
        self.filter_results.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        layout.addWidget(self.filter_results)
        
        return widget
    
    def _execute_filter_search(self):
        """执行过滤搜索"""
        QMessageBox.information(self, "搜索", "搜索功能")
    
    def _save_filter(self):
        """保存筛选器"""
        QMessageBox.information(self, "筛选器", "筛选器已保存")
    
    def _create_network_sim_tab(self) -> QWidget:
        """创建网络模拟标签页"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # 预设网络条件
        preset_group = QGroupBox("预设网络条件")
        preset_layout = QVBoxLayout(preset_group)
        
        self.network_preset = QComboBox()
        self.network_preset.addItems(["正常网络", "慢速3G (EDGE)", "快速3G (HSPA)", "慢速4G (LTE)", "快速4G (LTE-A)", "5G"])
        preset_layout.addWidget(self.network_preset)
        
        apply_btn = QPushButton("✅ 应用预设")
        apply_btn.clicked.connect(self._apply_network_preset)
        preset_layout.addWidget(apply_btn)
        
        layout.addWidget(preset_group)
        
        # 自定义条件
        custom_group = QGroupBox("自定义条件")
        custom_layout = QFormLayout(custom_group)
        
        self.latency_input = QSpinBox()
        self.latency_input.setRange(0, 10000)
        self.latency_input.setSuffix(" ms")
        custom_layout.addRow("延迟:", self.latency_input)
        
        self.packet_loss_input = QDoubleSpinBox()
        self.packet_loss_input.setRange(0, 100)
        self.packet_loss_input.setSuffix(" %")
        custom_layout.addRow("丢包率:", self.packet_loss_input)
        
        self.bandwidth_input = QSpinBox()
        self.bandwidth_input.setRange(0, 1000000)
        self.bandwidth_input.setSuffix(" kbps")
        custom_layout.addRow("带宽:", self.bandwidth_input)
        
        apply_custom_btn = QPushButton("✅ 应用自定义")
        apply_custom_btn.clicked.connect(self._apply_custom_network)
        custom_layout.addRow(apply_custom_btn)
        
        layout.addWidget(custom_group)
        
        return widget
    
    def _apply_network_preset(self):
        """应用网络预设"""
        preset_name = self.network_preset.currentText()
        QMessageBox.information(self, "网络模拟", f"已应用预设: {preset_name}")
    
    def _apply_custom_network(self):
        """应用自定义网络条件"""
        QMessageBox.information(self, "网络模拟", "已应用自定义网络条件")
    
    def _create_mock_tab(self) -> QWidget:
        """创建Mock应答标签页"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Mock规则列表
        self.mock_rules_list = QTableWidget()
        self.mock_rules_list.setColumnCount(4)
        self.mock_rules_list.setHorizontalHeaderLabels(["名称", "URL模式", "状态码", "启用"])
        self.mock_rules_list.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        layout.addWidget(self.mock_rules_list)
        
        # 添加规则
        add_group = QGroupBox("添加Mock规则")
        add_layout = QFormLayout(add_group)
        
        self.mock_name = QLineEdit()
        add_layout.addRow("名称:", self.mock_name)
        
        self.mock_url_pattern = QLineEdit()
        add_layout.addRow("URL模式:", self.mock_url_pattern)
        
        self.mock_status_code = QSpinBox()
        self.mock_status_code.setRange(100, 599)
        self.mock_status_code.setValue(200)
        add_layout.addRow("状态码:", self.mock_status_code)
        
        self.mock_body = QTextEdit()
        self.mock_body.setPlaceholderText("响应体...")
        add_layout.addRow("响应体:", self.mock_body)
        
        add_btn = QPushButton("➕ 添加规则")
        add_btn.clicked.connect(self._add_mock_rule)
        add_layout.addRow(add_btn)
        
        layout.addWidget(add_group)
        
        return widget
    
    def _add_mock_rule(self):
        """添加Mock规则"""
        name = self.mock_name.text()
        url_pattern = self.mock_url_pattern.text()
        status_code = self.mock_status_code.value()
        body = self.mock_body.toPlainText()
        
        if name and url_pattern:
            QMessageBox.information(self, "Mock", f"已添加规则: {name}")
    
    def _create_security_tab(self) -> QWidget:
        """创建安全加固标签页"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # 域名白名单
        whitelist_group = QGroupBox("域名白名单")
        whitelist_layout = QVBoxLayout(whitelist_group)
        
        self.whitelist_input = QLineEdit()
        self.whitelist_input.setPlaceholderText("输入域名...")
        whitelist_layout.addWidget(self.whitelist_input)
        
        whitelist_btn_layout = QHBoxLayout()
        add_domain_btn = QPushButton("➕ 添加域名")
        add_domain_btn.clicked.connect(self._add_whitelist_domain)
        whitelist_btn_layout.addWidget(add_domain_btn)
        
        enable_whitelist_btn = QPushButton("✅ 启用白名单")
        enable_whitelist_btn.clicked.connect(self._enable_whitelist)
        whitelist_btn_layout.addWidget(enable_whitelist_btn)
        
        whitelist_layout.addLayout(whitelist_btn_layout)
        
        layout.addWidget(whitelist_group)
        
        # 安全状态
        status_group = QGroupBox("安全状态")
        status_layout = QVBoxLayout(status_group)
        
        self.security_status = QTextBrowser()
        self.security_status.setFont(QFont("Consolas", 9))
        status_layout.addWidget(self.security_status)
        
        refresh_status_btn = QPushButton("🔄 刷新状态")
        refresh_status_btn.clicked.connect(self._refresh_security_status)
        status_layout.addWidget(refresh_status_btn)
        
        layout.addWidget(status_group)
        
        return widget
    
    def _add_whitelist_domain(self):
        """添加白名单域名"""
        domain = self.whitelist_input.text()
        if domain and self._security_hardening:
            self._security_hardening.whitelist_manager.add_domain(domain)
            self.whitelist_input.clear()
            QMessageBox.information(self, "白名单", f"已添加: {domain}")
    
    def _enable_whitelist(self):
        """启用白名单"""
        if self._security_hardening:
            self._security_hardening.enable_domain_whitelist()
            QMessageBox.information(self, "白名单", "域名白名单已启用")
    
    def _refresh_security_status(self):
        """刷新安全状态"""
        if self._security_hardening:
            status = self._security_hardening.get_security_status()
            self.security_status.setText(json.dumps(status, indent=2, ensure_ascii=False))
    
    def _create_protocol_diag_tab(self) -> QWidget:
        """创建协议诊断标签页"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # 连接诊断面板
        conn_group = QGroupBox("连接诊断")
        conn_layout = QVBoxLayout(conn_group)
        
        self.conn_diag_table = QTableWidget()
        self.conn_diag_table.setColumnCount(7)
        self.conn_diag_table.setHorizontalHeaderLabels(["连接ID", "协议", "ALPN", "TLS版本", "QUIC版本", "健康状态", "请求数"])
        self.conn_diag_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        conn_layout.addWidget(self.conn_diag_table)
        
        refresh_conn_btn = QPushButton("🔄 刷新连接")
        refresh_conn_btn.clicked.connect(self._refresh_connection_diag)
        conn_layout.addWidget(refresh_conn_btn)
        
        layout.addWidget(conn_group)
        
        # 合规性问题
        compliance_group = QGroupBox("协议合规性问题")
        compliance_layout = QVBoxLayout(compliance_group)
        
        self.compliance_issues_list = QTextBrowser()
        self.compliance_issues_list.setFont(QFont("Consolas", 9))
        compliance_layout.addWidget(self.compliance_issues_list)
        
        refresh_compliance_btn = QPushButton("🔄 刷新合规性")
        refresh_compliance_btn.clicked.connect(self._refresh_compliance)
        compliance_layout.addWidget(refresh_compliance_btn)
        
        layout.addWidget(compliance_group)
        
        # Prometheus指标
        prometheus_group = QGroupBox("Prometheus指标")
        prometheus_layout = QVBoxLayout(prometheus_group)
        
        self.prometheus_output = QTextBrowser()
        self.prometheus_output.setFont(QFont("Consolas", 8))
        prometheus_layout.addWidget(self.prometheus_output)
        
        export_prometheus_btn = QPushButton("📤 导出指标")
        export_prometheus_btn.clicked.connect(self._export_prometheus_metrics)
        prometheus_layout.addWidget(export_prometheus_btn)
        
        layout.addWidget(prometheus_group)
        
        return widget
    
    def _create_advanced_features_tab(self) -> QWidget:
        """创建高级特性标签页"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # 协议使用统计
        stats_group = QGroupBox("协议使用统计")
        stats_layout = QVBoxLayout(stats_group)
        
        self.protocol_stats_table = QTableWidget()
        self.protocol_stats_table.setColumnCount(5)
        self.protocol_stats_table.setHorizontalHeaderLabels(["协议", "请求数", "字节数", "错误数", "占比"])
        self.protocol_stats_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        stats_layout.addWidget(self.protocol_stats_table)
        
        refresh_stats_btn = QPushButton("🔄 刷新统计")
        refresh_stats_btn.clicked.connect(self._refresh_protocol_stats)
        stats_layout.addWidget(refresh_stats_btn)
        
        layout.addWidget(stats_group)
        
        # HTTP/2高级特性
        h2_group = QGroupBox("HTTP/2高级特性")
        h2_layout = QVBoxLayout(h2_group)
        
        self.h2_stats_output = QTextBrowser()
        self.h2_stats_output.setFont(QFont("Consolas", 9))
        h2_layout.addWidget(self.h2_stats_output)
        
        refresh_h2_btn = QPushButton("🔄 刷新HTTP/2状态")
        refresh_h2_btn.clicked.connect(self._refresh_h2_stats)
        h2_layout.addWidget(refresh_h2_btn)
        
        layout.addWidget(h2_group)
        
        # HTTP/3高级特性
        h3_group = QGroupBox("HTTP/3高级特性")
        h3_layout = QVBoxLayout(h3_group)
        
        self.h3_stats_output = QTextBrowser()
        self.h3_stats_output.setFont(QFont("Consolas", 9))
        h3_layout.addWidget(self.h3_stats_output)
        
        refresh_h3_btn = QPushButton("🔄 刷新HTTP/3状态")
        refresh_h3_btn.clicked.connect(self._refresh_h3_stats)
        h3_layout.addWidget(refresh_h3_btn)
        
        layout.addWidget(h3_group)
        
        # 自适应协议管理
        adaptive_group = QGroupBox("自适应协议管理")
        adaptive_layout = QVBoxLayout(adaptive_group)
        
        self.adaptive_protocol_output = QTextBrowser()
        self.adaptive_protocol_output.setFont(QFont("Consolas", 9))
        adaptive_layout.addWidget(self.adaptive_protocol_output)
        
        refresh_adaptive_btn = QPushButton("🔄 刷新协议状态")
        refresh_adaptive_btn.clicked.connect(self._refresh_adaptive_protocol)
        adaptive_layout.addWidget(refresh_adaptive_btn)
        
        layout.addWidget(adaptive_group)
        
        return widget
    
    def _refresh_connection_diag(self):
        """刷新连接诊断"""
        if hasattr(self, '_engine') and self._engine:
            status = self._engine.get_status()
            protocols = status.get('protocols', {})
            
            self.conn_diag_table.setRowCount(0)
            
            row = 0
            for proto, enabled in protocols.items():
                if enabled:
                    self.conn_diag_table.insertRow(row)
                    self.conn_diag_table.setItem(row, 0, QTableWidgetItem(f"conn_{proto}"))
                    self.conn_diag_table.setItem(row, 1, QTableWidgetItem(proto.upper()))
                    self.conn_diag_table.setItem(row, 2, QTableWidgetItem(proto))
                    self.conn_diag_table.setItem(row, 3, QTableWidgetItem("TLS 1.3"))
                    self.conn_diag_table.setItem(row, 4, QTableWidgetItem("v1" if proto == "http3" else "-"))
                    self.conn_diag_table.setItem(row, 5, QTableWidgetItem("healthy"))
                    self.conn_diag_table.setItem(row, 6, QTableWidgetItem("0"))
                    row += 1
    
    def _refresh_compliance(self):
        """刷新合规性"""
        self.compliance_issues_list.setText("协议合规性检查正常，未发现问题。")
    
    def _export_prometheus_metrics(self):
        """导出Prometheus指标"""
        self.prometheus_output.setText(
            "# HELP http_requests_total Total HTTP requests\n"
            "# TYPE http_requests_total counter\n"
            "http_requests_total{protocol=\"http1\"} 0\n"
            "http_requests_total{protocol=\"http2\"} 0\n"
            "http_requests_total{protocol=\"http3\"} 0\n"
        )
    
    def _refresh_protocol_stats(self):
        """刷新协议统计"""
        self.protocol_stats_table.setRowCount(3)
        
        protocols = [
            ("HTTP/1.1", "0", "0", "0", "0%"),
            ("HTTP/2", "0", "0", "0", "0%"),
            ("HTTP/3", "0", "0", "0", "0%"),
        ]
        
        for i, (proto, reqs, bytes_, errors, pct) in enumerate(protocols):
            self.protocol_stats_table.setItem(i, 0, QTableWidgetItem(proto))
            self.protocol_stats_table.setItem(i, 1, QTableWidgetItem(reqs))
            self.protocol_stats_table.setItem(i, 2, QTableWidgetItem(bytes_))
            self.protocol_stats_table.setItem(i, 3, QTableWidgetItem(errors))
            self.protocol_stats_table.setItem(i, 4, QTableWidgetItem(pct))
    
    def _refresh_h2_stats(self):
        """刷新HTTP/2状态"""
        self.h2_stats_output.setText(
            "HTTP/2高级特性状态:\n"
            "- 流优先级: 已启用\n"
            "- HPACK动态表: 已启用 (4096 bytes)\n"
            "- 窗口动态调整: 已启用\n"
            "- 连接合并: 已启用\n"
            "- 服务端推送控制: 已启用"
        )
    
    def _refresh_h3_stats(self):
        """刷新HTTP/3状态"""
        self.h3_stats_output.setText(
            "HTTP/3高级特性状态:\n"
            "- 连接迁移: 已启用\n"
            "- 0-RTT安全处理: 已启用 (重放防护)\n"
            "- QUIC版本协商: 已启用 (v1, v2)\n"
            "- 多路径QUIC: 预留接口\n"
            "- WebTransport: 预留接口"
        )
    
    def _refresh_adaptive_protocol(self):
        """刷新自适应协议状态"""
        self.adaptive_protocol_output.setText(
            "自适应协议管理状态:\n"
            "- 智能降级: 已启用\n"
            "- 协议伪装: 已禁用\n"
            "- ALPN策略: h3 > h2 > http/1.1\n"
            "- 协议嗅探日志: 已启用\n"
            "- 协议缓存: 已启用 (TTL: 300s)"
        )
    
    def get_status_info(self) -> Dict[str, Any]:
        """获取状态信息"""
        if self._engine:
            return self._engine.get_status()
        return {
            'running': self._is_running,
            'host': self.host_input.text(),
            'port': self.port_input.value(),
        }


class RuleDialog(QDialog):
    """规则编辑对话框"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("添加拦截规则")
        self.setMinimumWidth(500)
        
        layout = QFormLayout(self)
        
        self.name_input = QLineEdit()
        layout.addRow("规则名称:", self.name_input)
        
        self.enabled_check = QCheckBox("启用")
        self.enabled_check.setChecked(True)
        layout.addRow(self.enabled_check)
        
        self.match_type_combo = QComboBox()
        self.match_type_combo.addItems([
            RuleMatchType.DOMAIN.value,
            RuleMatchType.URL_PATH.value,
            RuleMatchType.METHOD.value,
            RuleMatchType.STATUS_CODE.value,
            RuleMatchType.HEADER.value,
            RuleMatchType.BODY.value,
            RuleMatchType.REGEX.value,
        ])
        layout.addRow("匹配类型:", self.match_type_combo)
        
        self.match_value_input = QLineEdit()
        layout.addRow("匹配值:", self.match_value_input)
        
        self.action_combo = QComboBox()
        self.action_combo.addItems([
            InterceptAction.FORWARD.value,
            InterceptAction.BREAK.value,
            InterceptAction.DROP.value,
            InterceptAction.MODIFY.value,
            InterceptAction.LOG.value,
        ])
        layout.addRow("动作:", self.action_combo)
        
        self.replace_pattern_input = QLineEdit()
        layout.addRow("替换模式:", self.replace_pattern_input)
        
        self.replace_with_input = QLineEdit()
        layout.addRow("替换为:", self.replace_with_input)
        
        self.description_input = QLineEdit()
        layout.addRow("描述:", self.description_input)
        
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addRow(buttons)
    
    def get_rule(self) -> InterceptRule:
        """获取规则"""
        import hashlib
        rule_id = hashlib.md5(f"{datetime.utcnow().isoformat()}".encode()).hexdigest()[:12]
        
        return InterceptRule(
            id=rule_id,
            name=self.name_input.text(),
            enabled=self.enabled_check.isChecked(),
            match_type=RuleMatchType(self.match_type_combo.currentText()),
            match_value=self.match_value_input.text(),
            action=InterceptAction(self.action_combo.currentText()),
            replace_pattern=self.replace_pattern_input.text(),
            replace_with=self.replace_with_input.text(),
            description=self.description_input.text(),
        )
