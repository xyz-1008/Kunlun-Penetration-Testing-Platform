"""
昆仑安全测试平台 Pro - 三种风格融合UI主界面
Linear UI + 数据可视化 + 玻璃拟态
参考Burp Suite & Yakit布局设计
基于20年UI设计经验
昆仑安全实验室 - 荣誉出品
"""

import logging
from PySide6.QtWidgets import (QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
                               QSplitter, QTabWidget, QToolBar, QStatusBar,
                               QMenuBar, QMenu, QLabel, QLineEdit, QFrame)
from PySide6.QtCore import Qt, QSize
from PySide6.QtGui import QIcon, QFont, QColor, QAction

from ui.fusion_components import (FusionTheme, FusionCard, FusionButton, 
                                FusionSidebar, FusionTabWidget, FusionStatsCard,
                                FusionBackgroundWidget)
from core.proxy.professional_proxy import ProfessionalProxyServer
from core.scanner.advanced_scanner import AdvancedVulnerabilityScanner
from core.intruder.professional_intruder import ProfessionalIntruder
from core.encoder.advanced_encoder import AdvancedEncoderDecoder

logger = logging.getLogger(__name__)


class KunlunFusionPlatform(QMainWindow):
    """昆仑安全测试平台 Pro - 三种风格融合主窗口"""
    
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
        
        logger.info("昆仑安全测试平台 Pro - 三种风格融合UI 初始化完成")
        
    def _init_ui(self):
        """初始化融合风格UI"""
        # 主背景
        background = FusionBackgroundWidget()
        self.setCentralWidget(background)
        
        main_layout = QVBoxLayout(background)
        main_layout.setSpacing(0)
        main_layout.setContentsMargins(0, 0, 0, 0)
        
        # 1. 顶部工具栏
        self._init_top_toolbar(main_layout)
        
        # 2. 主内容区（分割器）
        content_splitter = QSplitter(Qt.Horizontal)
        
        # 左侧：侧边栏
        self.sidebar = FusionSidebar()
        self.sidebar.page_changed.connect(self._switch_page)
        content_splitter.addWidget(self.sidebar)
        
        # 右侧：主工作区
        work_area = QWidget()
        work_layout = QVBoxLayout(work_area)
        work_layout.setSpacing(8)
        work_layout.setContentsMargins(12, 12, 12, 12)
        
        # 统计面板
        self._init_stats_panel(work_layout)
        
        # 多标签页工作区
        self._init_workspace_tabs(work_layout)
        
        content_splitter.addWidget(work_area)
        content_splitter.setStretchFactor(0, 1)
        content_splitter.setStretchFactor(1, 4)
        
        main_layout.addWidget(content_splitter)
        
        # 3. 底部状态栏
        self._init_status_bar()
        
    def _init_top_toolbar(self, parent_layout):
        """初始化顶部工具栏（Linear风格）"""
        toolbar = QToolBar()
        toolbar.setMovable(False)
        toolbar.setStyleSheet(f"""
            QToolBar {{
                background: {FusionTheme.COLORS['bg_surface']};
                border-bottom: 1px solid {FusionTheme.COLORS['border_subtle']};
                spacing: 8px;
                padding: 4px 12px;
            }}
        """)
        
        # Logo
        logo_label = QLabel("🔒 昆仑安全测试平台 Pro")
        logo_label.setStyleSheet(f"""
            color: {FusionTheme.COLORS['text_primary']};
            font-size: 14px;
            font-weight: 700;
            padding: 0 8px;
        """)
        toolbar.addWidget(logo_label)
        
        toolbar.addSeparator()
        
        # 快捷操作按钮
        new_scan_btn = FusionButton("🔍 新建扫描", "primary")
        new_scan_btn.setMinimumWidth(120)
        toolbar.addWidget(new_scan_btn)
        
        start_proxy_btn = FusionButton("🌐 启动代理", "success")
        start_proxy_btn.setMinimumWidth(120)
        toolbar.addWidget(start_proxy_btn)
        
        toolbar.addSeparator()
        
        # 搜索框
        search_input = QLineEdit()
        search_input.setPlaceholderText("搜索功能、插件、POC...")
        search_input.setStyleSheet(f"""
            QLineEdit {{
                background: {FusionTheme.COLORS['bg_elevated']};
                color: {FusionTheme.COLORS['text_primary']};
                border: 1px solid {FusionTheme.COLORS['border_subtle']};
                border-radius: {FusionTheme.RADIUS['small']}px;
                padding: 6px 12px;
                min-width: 300px;
            }}
            
            QLineEdit:focus {{
                border: 1px solid {FusionTheme.COLORS['primary']};
            }}
        """)
        toolbar.addWidget(search_input)
        
        toolbar.addSeparator()
        
        # 右侧：设置等
        settings_btn = FusionButton("⚙️", "secondary")
        settings_btn.setMinimumWidth(40)
        toolbar.addWidget(settings_btn)
        
        self.addToolBar(toolbar)
        
    def _init_stats_panel(self, parent_layout):
        """初始化统计面板（数据可视化 + 玻璃拟态）"""
        stats_container = QWidget()
        stats_layout = QHBoxLayout(stats_container)
        stats_layout.setSpacing(12)
        stats_layout.setContentsMargins(0, 0, 0, 0)
        
        # 统计卡片
        stats_data = [
            ("📊", "活跃任务", "5", "+2"),
            ("⚠️", "已发现漏洞", "23", "+5"),
            ("✅", "已完成扫描", "147", "+12"),
            ("🟢", "系统状态", "正常", "")
        ]
        
        for icon, title, value, trend in stats_data:
            card = FusionStatsCard(title, value, icon, trend)
            stats_layout.addWidget(card)
        
        parent_layout.addWidget(stats_container)
        
    def _init_workspace_tabs(self, parent_layout):
        """初始化工作区标签页（参考Burp/Yakit）"""
        self.tabs = FusionTabWidget()
        self.tabs.setTabsClosable(False)
        
        # Dashboard页面
        dashboard_page = self._create_dashboard_page()
        self.tabs.addTab(dashboard_page, "📊 Dashboard")
        
        # Proxy页面
        proxy_page = self._create_placeholder_page("Proxy - 代理拦截")
        self.tabs.addTab(proxy_page, "🌐 Proxy")
        
        # Scanner页面
        scanner_page = self._create_placeholder_page("Scanner - 漏洞扫描")
        self.tabs.addTab(scanner_page, "🔍 Scanner")
        
        # Intruder页面
        intruder_page = self._create_placeholder_page("Intruder - 攻击工具")
        self.tabs.addTab(intruder_page, "⚔️ Intruder")
        
        parent_layout.addWidget(self.tabs)
        
    def _create_dashboard_page(self):
        """创建Dashboard页面"""
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setSpacing(16)
        layout.setContentsMargins(0, 16, 0, 0)
        
        # 欢迎区域
        welcome_card = FusionCard()
        welcome_layout = QVBoxLayout(welcome_card)
        welcome_layout.setSpacing(8)
        welcome_layout.setContentsMargins(20, 20, 20, 20)
        
        welcome_title = QLabel("安全态势感知中心")
        welcome_title.setStyleSheet(f"""
            color: {FusionTheme.COLORS['text_primary']};
            font-size: 20px;
            font-weight: 700;
        """)
        
        welcome_desc = QLabel("实时监控网络安全状态，智能识别风险威胁，高效完成渗透测试任务")
        welcome_desc.setStyleSheet(f"""
            color: {FusionTheme.COLORS['text_secondary']};
            font-size: 13px;
        """)
        
        welcome_layout.addWidget(welcome_title)
        welcome_layout.addWidget(welcome_desc)
        
        layout.addWidget(welcome_card)
        
        # 快捷操作网格
        shortcuts_container = QWidget()
        shortcuts_layout = QHBoxLayout(shortcuts_container)
        shortcuts_layout.setSpacing(12)
        shortcuts_layout.setContentsMargins(0, 0, 0, 0)
        
        shortcut_items = [
            ("🌐", "代理拦截", "实时HTTP/HTTPS流量拦截与分析"),
            ("🔍", "漏洞扫描", "智能Web漏洞自动检测与评估"),
            ("⚔️", "攻击工具", "专业级爆破与Payload测试"),
            ("🔐", "编码解码", "多种编码格式转换工具")
        ]
        
        for icon, title, desc in shortcut_items:
            card = FusionCard()
            card_layout = QVBoxLayout(card)
            card_layout.setSpacing(8)
            card_layout.setContentsMargins(16, 16, 16, 16)
            
            icon_label = QLabel(icon)
            icon_label.setStyleSheet("font-size: 32px;")
            
            title_label = QLabel(title)
            title_label.setStyleSheet(f"""
                color: {FusionTheme.COLORS['text_primary']};
                font-size: 16px;
                font-weight: 700;
            """)
            
            desc_label = QLabel(desc)
            desc_label.setWordWrap(True)
            desc_label.setStyleSheet(f"""
                color: {FusionTheme.COLORS['text_secondary']};
                font-size: 12px;
            """)
            
            card_layout.addWidget(icon_label)
            card_layout.addWidget(title_label)
            card_layout.addWidget(desc_label)
            card_layout.addStretch()
            
            shortcuts_layout.addWidget(card)
        
        layout.addWidget(shortcuts_container)
        layout.addStretch()
        
        return page
        
    def _create_placeholder_page(self, title):
        """创建占位页面"""
        page = FusionCard()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(48, 48, 48, 48)
        
        icon_label = QLabel("🚧")
        icon_label.setAlignment(Qt.AlignCenter)
        icon_label.setStyleSheet("font-size: 64px;")
        
        title_label = QLabel(title)
        title_label.setAlignment(Qt.AlignCenter)
        title_label.setStyleSheet(f"""
            color: {FusionTheme.COLORS['text_primary']};
            font-size: 24px;
            font-weight: 700;
            padding: 20px 0;
        """)
        
        desc_label = QLabel("功能开发中，敬请期待...")
        desc_label.setAlignment(Qt.AlignCenter)
        desc_label.setStyleSheet(f"""
            color: {FusionTheme.COLORS['text_secondary']};
            font-size: 14px;
        """)
        
        layout.addStretch()
        layout.addWidget(icon_label)
        layout.addWidget(title_label)
        layout.addWidget(desc_label)
        layout.addStretch()
        
        return page
        
    def _switch_page(self, page_id):
        """切换页面"""
        self.current_page = page_id
        
    def _init_status_bar(self):
        """初始化状态栏（Linear风格）"""
        status_bar = QStatusBar()
        status_bar.setStyleSheet(f"""
            QStatusBar {{
                background: {FusionTheme.COLORS['bg_surface']};
                color: {FusionTheme.COLORS['text_secondary']};
                border-top: 1px solid {FusionTheme.COLORS['border_subtle']};
                padding: 2px 12px;
                font-size: 12px;
            }}
        """)
        
        status_bar.addWidget(QLabel("🟢 系统状态：正常"))
        status_bar.addPermanentWidget(QLabel("📊 版本：Pro v2.0.0"))
        
        self.setStatusBar(status_bar)
        
    def _start_background_services(self):
        """启动后台服务"""
        logger.info("后台服务初始化...")