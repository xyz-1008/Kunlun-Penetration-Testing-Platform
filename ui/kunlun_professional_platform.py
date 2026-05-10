"""
昆仑安全测试平台 Pro - 专业级主界面
顶部导航栏设计，便于开发和更新
基于20年UI设计经验
昆仑安全实验室 - 荣誉出品
"""

import logging
from PySide6.QtWidgets import (QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
                               QSplitter, QTabWidget, QToolBar, QStatusBar,
                               QMenuBar, QMenu, QLabel, QLineEdit, QFrame,
                               QPushButton, QStackedWidget, QScrollArea, QGridLayout)
from PySide6.QtCore import Qt, QSize
from PySide6.QtGui import QIcon, QFont, QColor, QAction, QPalette

from ui.professional_components import (ProfTheme, ProfCard, ProfButton, 
                                      ProfStatsCard, ProfBackgroundWidget)
from core.proxy.professional_proxy import ProfessionalProxyServer
from core.scanner.advanced_scanner import AdvancedVulnerabilityScanner
from core.intruder.professional_intruder import ProfessionalIntruder
from core.encoder.advanced_encoder import AdvancedEncoderDecoder

logger = logging.getLogger(__name__)


class KunlunProfessionalPlatform(QMainWindow):
    """昆仑安全测试平台 Pro - 专业级主窗口"""
    
    def __init__(self, app_instance=None):
        super().__init__()
        
        self.app_instance = app_instance
        self.current_page = "dashboard"
        
        # 初始化核心组件
        self.proxy_server = ProfessionalProxyServer()
        self.vuln_scanner = AdvancedVulnerabilityScanner()
        self.intruder_tool = ProfessionalIntruder()
        self.encoder_tool = AdvancedEncoderDecoder()
        
        # 窗口属性
        self.setWindowTitle("昆仑安全测试平台 Pro")
        self.setMinimumSize(1600, 900)
        self.resize(1920, 1080)
        
        # 初始化UI
        self._init_ui()
        
        # 启动后台服务
        self._start_background_services()
        
        logger.info("昆仑安全测试平台 Pro - 专业级UI 初始化完成")
        
    def _init_ui(self):
        """初始化专业级UI"""
        # 主背景
        background = ProfBackgroundWidget()
        self.setCentralWidget(background)
        
        main_layout = QVBoxLayout(background)
        main_layout.setSpacing(0)
        main_layout.setContentsMargins(0, 0, 0, 0)
        
        # 1. 顶部导航栏（主功能切换）
        self._init_top_navigation(main_layout)
        
        # 2. 内容区域
        content_container = QWidget()
        content_layout = QVBoxLayout(content_container)
        content_layout.setSpacing(12)
        content_layout.setContentsMargins(16, 16, 16, 16)
        
        # 统计面板
        self._init_stats_panel(content_layout)
        
        # 主工作区
        self._init_main_workspace(content_layout)
        
        main_layout.addWidget(content_container)
        
        # 3. 底部状态栏
        self._init_status_bar()
        
    def _init_top_navigation(self, parent_layout):
        """初始化顶部导航栏"""
        nav_container = QFrame()
        nav_container.setStyleSheet(f"""
            QFrame {{
                background: {ProfTheme.COLORS['bg_surface']};
                border-bottom: 1px solid {ProfTheme.COLORS['border_medium']};
            }}
        """)
        
        nav_layout = QHBoxLayout(nav_container)
        nav_layout.setSpacing(0)
        nav_layout.setContentsMargins(16, 0, 16, 0)
        
        # Logo区域
        logo_container = QWidget()
        logo_layout = QHBoxLayout(logo_container)
        logo_layout.setSpacing(8)
        logo_layout.setContentsMargins(0, 0, 0, 0)
        
        logo_icon = QLabel("🔒")
        logo_icon.setStyleSheet("font-size: 24px;")
        
        logo_text = QLabel("昆仑安全测试平台 Pro")
        logo_text.setStyleSheet(f"""
            color: {ProfTheme.COLORS['text_primary']};
            font-size: 16px;
            font-weight: 700;
        """)
        
        logo_layout.addWidget(logo_icon)
        logo_layout.addWidget(logo_text)
        nav_layout.addWidget(logo_container)
        
        nav_layout.addSpacing(32)
        
        # 功能导航按钮
        self.nav_buttons = []
        
        nav_items = [
            ("📊", "Dashboard", "dashboard"),
            ("🌐", "Proxy", "proxy"),
            ("🔍", "Scanner", "scanner"),
            ("⚔️", "Intruder", "intruder"),
            ("🔁", "Repeater", "repeater"),
            ("🔐", "Encoder", "encoder"),
            ("📚", "Knowledge", "knowledge")
        ]
        
        for icon, text, page_id in nav_items:
            btn = QPushButton(f" {icon}  {text}")
            btn.setCheckable(True)
            btn.setCursor(Qt.PointingHandCursor)
            btn.setProperty("page_id", page_id)
            btn.clicked.connect(lambda checked, p=page_id: self._on_nav_clicked(p))
            
            btn.setStyleSheet(f"""
                QPushButton {{
                    background: transparent;
                    color: {ProfTheme.COLORS['text_secondary']};
                    border: none;
                    border-bottom: 3px solid transparent;
                    padding: 14px 20px;
                    font-size: 13px;
                    font-weight: 600;
                }}
                
                QPushButton:hover {{
                    color: {ProfTheme.COLORS['text_primary']};
                    background: {ProfTheme.COLORS['bg_elevated']};
                }}
                
                QPushButton:checked {{
                    color: {ProfTheme.COLORS['primary']};
                    border-bottom: 3px solid {ProfTheme.COLORS['primary']};
                    background: rgba(59, 130, 246, 0.08);
                }}
            """)
            
            self.nav_buttons.append((btn, page_id))
            nav_layout.addWidget(btn)
        
        if self.nav_buttons:
            self.nav_buttons[0][0].setChecked(True)
        
        nav_layout.addStretch()
        
        # 快捷操作区
        quick_action_container = QWidget()
        quick_layout = QHBoxLayout(quick_action_container)
        quick_layout.setSpacing(8)
        quick_layout.setContentsMargins(0, 0, 0, 0)
        
        search_input = QLineEdit()
        search_input.setPlaceholderText("搜索功能、POC、工具...")
        search_input.setFixedWidth(280)
        search_input.setStyleSheet(f"""
            QLineEdit {{
                background: {ProfTheme.COLORS['bg_elevated']};
                color: {ProfTheme.COLORS['text_primary']};
                border: 1px solid {ProfTheme.COLORS['border_medium']};
                border-radius: {ProfTheme.RADIUS['small']}px;
                padding: 6px 12px;
                font-size: 13px;
            }}
            
            QLineEdit:focus {{
                border: 1px solid {ProfTheme.COLORS['primary']};
            }}
        """)
        
        new_scan_btn = ProfButton("🔍 新建扫描", "primary")
        new_scan_btn.setMinimumWidth(120)
        
        start_proxy_btn = ProfButton("🌐 启动代理", "success")
        start_proxy_btn.setMinimumWidth(120)
        
        settings_btn = ProfButton("⚙️", "secondary")
        settings_btn.setMinimumWidth(44)
        
        quick_layout.addWidget(search_input)
        quick_layout.addWidget(new_scan_btn)
        quick_layout.addWidget(start_proxy_btn)
        quick_layout.addWidget(settings_btn)
        
        nav_layout.addWidget(quick_action_container)
        
        parent_layout.addWidget(nav_container)
        
    def _init_stats_panel(self, parent_layout):
        """初始化统计面板"""
        stats_container = QWidget()
        stats_layout = QHBoxLayout(stats_container)
        stats_layout.setSpacing(12)
        stats_layout.setContentsMargins(0, 0, 0, 0)
        
        # 统计卡片
        stats_data = [
            ("📊", "活跃任务", "5", "+2", ProfTheme.COLORS['primary']),
            ("⚠️", "已发现漏洞", "23", "+5", ProfTheme.COLORS['warning']),
            ("✅", "已完成扫描", "147", "+12", ProfTheme.COLORS['success']),
            ("🟢", "系统状态", "正常", "", ProfTheme.COLORS['info'])
        ]
        
        for icon, title, value, trend, accent_color in stats_data:
            card = ProfStatsCard(title, value, icon, trend, accent_color)
            stats_layout.addWidget(card)
        
        parent_layout.addWidget(stats_container)
        
    def _init_main_workspace(self, parent_layout):
        """初始化主工作区"""
        # 使用QStackedWidget管理不同页面
        self.page_stack = QStackedWidget()
        
        # Dashboard页面
        dashboard_page = self._create_dashboard_page()
        self.page_stack.addWidget(dashboard_page)
        
        # Proxy页面
        proxy_page = self._create_placeholder_page("Proxy - 代理拦截")
        self.page_stack.addWidget(proxy_page)
        
        # Scanner页面
        scanner_page = self._create_placeholder_page("Scanner - 漏洞扫描")
        self.page_stack.addWidget(scanner_page)
        
        # Intruder页面
        intruder_page = self._create_placeholder_page("Intruder - 攻击工具")
        self.page_stack.addWidget(intruder_page)
        
        # Repeater页面
        repeater_page = self._create_placeholder_page("Repeater - 重放测试")
        self.page_stack.addWidget(repeater_page)
        
        # Encoder页面
        encoder_page = self._create_placeholder_page("Encoder - 编码解码")
        self.page_stack.addWidget(encoder_page)
        
        # Knowledge页面
        knowledge_page = self._create_placeholder_page("Knowledge - 知识库")
        self.page_stack.addWidget(knowledge_page)
        
        parent_layout.addWidget(self.page_stack)
        
    def _create_dashboard_page(self):
        """创建Dashboard页面"""
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setSpacing(16)
        layout.setContentsMargins(0, 8, 0, 0)
        
        # 欢迎区域
        welcome_card = ProfCard()
        welcome_layout = QVBoxLayout(welcome_card)
        welcome_layout.setSpacing(12)
        welcome_layout.setContentsMargins(24, 24, 24, 24)
        
        welcome_title = QLabel("安全态势感知中心")
        welcome_title.setStyleSheet(f"""
            color: {ProfTheme.COLORS['text_primary']};
            font-size: 24px;
            font-weight: 700;
        """)
        
        welcome_desc = QLabel("实时监控网络安全状态，智能识别风险威胁，高效完成渗透测试任务")
        welcome_desc.setStyleSheet(f"""
            color: {ProfTheme.COLORS['text_secondary']};
            font-size: 14px;
        """)
        
        welcome_layout.addWidget(welcome_title)
        welcome_layout.addWidget(welcome_desc)
        
        layout.addWidget(welcome_card)
        
        # 快捷操作网格
        shortcuts_container = QWidget()
        shortcuts_layout = QGridLayout(shortcuts_container)
        shortcuts_layout.setSpacing(12)
        shortcuts_layout.setContentsMargins(0, 0, 0, 0)
        
        shortcut_items = [
            ("🌐", "代理拦截", "实时HTTP/HTTPS流量拦截与分析", 0, 0),
            ("🔍", "漏洞扫描", "智能Web漏洞自动检测与评估", 0, 1),
            ("⚔️", "攻击工具", "专业级爆破与Payload测试", 1, 0),
            ("🔐", "编码解码", "多种编码格式转换工具", 1, 1)
        ]
        
        for icon, title, desc, row, col in shortcut_items:
            card = ProfCard()
            card.setCursor(Qt.PointingHandCursor)
            card_layout = QVBoxLayout(card)
            card_layout.setSpacing(12)
            card_layout.setContentsMargins(20, 20, 20, 20)
            
            icon_label = QLabel(icon)
            icon_label.setStyleSheet("font-size: 36px;")
            
            title_label = QLabel(title)
            title_label.setStyleSheet(f"""
                color: {ProfTheme.COLORS['text_primary']};
                font-size: 18px;
                font-weight: 700;
            """)
            
            desc_label = QLabel(desc)
            desc_label.setWordWrap(True)
            desc_label.setStyleSheet(f"""
                color: {ProfTheme.COLORS['text_secondary']};
                font-size: 13px;
            """)
            
            card_layout.addWidget(icon_label)
            card_layout.addWidget(title_label)
            card_layout.addWidget(desc_label)
            card_layout.addStretch()
            
            shortcuts_layout.addWidget(card, row, col)
        
        layout.addWidget(shortcuts_container)
        layout.addStretch()
        
        return page
        
    def _create_placeholder_page(self, title):
        """创建占位页面"""
        page = ProfCard()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(48, 48, 48, 48)
        
        icon_label = QLabel("🚧")
        icon_label.setAlignment(Qt.AlignCenter)
        icon_label.setStyleSheet("font-size: 72px;")
        
        title_label = QLabel(title)
        title_label.setAlignment(Qt.AlignCenter)
        title_label.setStyleSheet(f"""
            color: {ProfTheme.COLORS['text_primary']};
            font-size: 28px;
            font-weight: 700;
            padding: 24px 0;
        """)
        
        desc_label = QLabel("功能开发中，敬请期待...")
        desc_label.setAlignment(Qt.AlignCenter)
        desc_label.setStyleSheet(f"""
            color: {ProfTheme.COLORS['text_secondary']};
            font-size: 15px;
        """)
        
        layout.addStretch()
        layout.addWidget(icon_label)
        layout.addWidget(title_label)
        layout.addWidget(desc_label)
        layout.addStretch()
        
        return page
        
    def _on_nav_clicked(self, page_id):
        """导航点击处理"""
        self.current_page = page_id
        
        for btn, pid in self.nav_buttons:
            btn.setChecked(pid == page_id)
        
        page_map = {
            "dashboard": 0,
            "proxy": 1,
            "scanner": 2,
            "intruder": 3,
            "repeater": 4,
            "encoder": 5,
            "knowledge": 6
        }
        
        if page_id in page_map:
            self.page_stack.setCurrentIndex(page_map[page_id])
        
    def _init_status_bar(self):
        """初始化状态栏"""
        status_bar = QStatusBar()
        status_bar.setStyleSheet(f"""
            QStatusBar {{
                background: {ProfTheme.COLORS['bg_surface']};
                color: {ProfTheme.COLORS['text_secondary']};
                border-top: 1px solid {ProfTheme.COLORS['border_medium']};
                padding: 4px 16px;
                font-size: 12px;
            }}
        """)
        
        status_bar.addWidget(QLabel("🟢 系统状态：正常"))
        status_bar.addPermanentWidget(QLabel("📊 版本：Pro v2.0.0"))
        
        self.setStatusBar(status_bar)
        
    def _start_background_services(self):
        """启动后台服务"""
        logger.info("后台服务初始化...")