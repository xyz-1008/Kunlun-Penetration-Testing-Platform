"""
昆仑安全测试平台 Pro - 全新玻璃拟态UI主界面
基于20年UI设计经验的数据可视化导向设计
昆仑安全实验室 - 荣誉出品
"""

import logging
import asyncio
from PySide6.QtWidgets import (QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
                               QSplitter, QTabWidget, QStatusBar, QMenuBar, 
                               QMenu, QMessageBox, QLabel, QStackedWidget,
                               QFrame, QScrollArea, QGridLayout)
from PySide6.QtCore import Qt, QTimer, QSize, Signal
from PySide6.QtGui import QIcon, QFont, QColor, QAction, QPainter, QBrush

from ui.glass_components import (GlassEffect, GlassCard, GlassButton, 
                                GlassPanel, GlassSectionHeader, GlassScrollArea,
                                GlassBackgroundWidget, StatsCard)
from ui.data_visualization import (DataVisualizationPanel, CircularProgressWidget,
                                  BarChartWidget, RiskIndicatorWidget)
from core.proxy.professional_proxy import ProfessionalProxyServer
from core.scanner.advanced_scanner import AdvancedVulnerabilityScanner
from core.intruder.professional_intruder import ProfessionalIntruder
from core.encoder.advanced_encoder import AdvancedEncoderDecoder

logger = logging.getLogger(__name__)


class GlassSidebarItem(QFrame):
    """玻璃拟态侧边栏菜单项"""
    
    clicked = Signal()
    
    def __init__(self, icon="", text="", parent=None):
        super().__init__(parent)
        self.icon = icon
        self.text = text
        self.is_selected = False
        self._setup_ui()
        
    def _setup_ui(self):
        layout = QHBoxLayout(self)
        layout.setSpacing(12)
        layout.setContentsMargins(16, 12, 16, 12)
        
        icon_label = QLabel(self.icon)
        icon_label.setStyleSheet("font-size: 20px;")
        
        text_label = QLabel(self.text)
        text_label.setStyleSheet(f"""
            color: {GlassEffect.COLORS['text_secondary']};
            font-size: 14px;
            font-weight: 500;
        """)
        
        layout.addWidget(icon_label)
        layout.addWidget(text_label)
        layout.addStretch()
        
        self._update_style()
        
    def set_selected(self, selected):
        self.is_selected = selected
        self._update_style()
        
    def _update_style(self):
        if self.is_selected:
            self.setStyleSheet(f"""
                GlassSidebarItem {{
                    background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                        stop:0 rgba(59, 130, 246, 0.3),
                        stop:1 rgba(139, 92, 246, 0.2));
                    border: 1px solid rgba(100, 150, 255, 0.3);
                    border-radius: 12px;
                }}
            """)
        else:
            self.setStyleSheet(f"""
                GlassSidebarItem {{
                    background: transparent;
                    border: 1px solid transparent;
                    border-radius: 12px;
                }}
                
                GlassSidebarItem:hover {{
                    background: rgba(255, 255, 255, 0.05);
                    border: 1px solid rgba(100, 150, 255, 0.1);
                }}
            """)
            
    def mousePressEvent(self, event):
        self.clicked.emit()


class GlassSidebar(QFrame):
    """玻璃拟态侧边栏导航"""
    
    page_changed = Signal(str)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self._setup_ui()
        
    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(8)
        layout.setContentsMargins(16, 24, 16, 24)
        
        # Logo
        logo_widget = QWidget()
        logo_layout = QHBoxLayout(logo_widget)
        logo_layout.setContentsMargins(0, 0, 0, 20)
        
        logo_icon = QLabel("🔒")
        logo_icon.setStyleSheet("font-size: 32px;")
        
        logo_text = QLabel("昆仑\n安全测试")
        logo_text.setStyleSheet(f"""
            color: {GlassEffect.COLORS['text_primary']};
            font-size: 16px;
            font-weight: 700;
            line-height: 1.2;
        """)
        
        logo_layout.addWidget(logo_icon)
        logo_layout.addSpacing(12)
        logo_layout.addWidget(logo_text)
        logo_layout.addStretch()
        
        layout.addWidget(logo_widget)
        
        # 菜单项
        self.menu_items = []
        
        menu_data = [
            ("📊", "安全态势", "dashboard"),
            ("🔍", "代理拦截", "proxy"),
            ("🛡️", "漏洞扫描", "scanner"),
            ("⚔️", "攻击工具", "intruder"),
            ("🔐", "编码解码", "encoder"),
            ("📚", "知识库", "knowledge")
        ]
        
        for icon, text, page_id in menu_data:
            item = GlassSidebarItem(icon, text)
            item.clicked.connect(lambda checked=False, p=page_id: self._on_menu_clicked(p))
            self.menu_items.append((item, page_id))
            layout.addWidget(item)
        
        # 默认选中第一项
        if self.menu_items:
            self.menu_items[0][0].set_selected(True)
        
        layout.addStretch()
        
        # 底部：用户信息
        user_widget = GlassCard(radius=12)
        user_layout = QHBoxLayout(user_widget)
        user_layout.setContentsMargins(12, 12, 12, 12)
        
        user_avatar = QLabel("👤")
        user_avatar.setStyleSheet("font-size: 28px;")
        
        user_info = QWidget()
        user_info_layout = QVBoxLayout(user_info)
        user_info_layout.setSpacing(2)
        user_info_layout.setContentsMargins(0, 0, 0, 0)
        
        user_name = QLabel("安全测试员")
        user_name.setStyleSheet(f"""
            color: {GlassEffect.COLORS['text_primary']};
            font-size: 13px;
            font-weight: 600;
        """)
        
        user_role = QLabel("Pro 专业版")
        user_role.setStyleSheet(f"""
            color: {GlassEffect.COLORS['text_tertiary']};
            font-size: 11px;
        """)
        
        user_info_layout.addWidget(user_name)
        user_info_layout.addWidget(user_role)
        
        user_layout.addWidget(user_avatar)
        user_layout.addSpacing(10)
        user_layout.addWidget(user_info)
        user_layout.addStretch()
        
        layout.addWidget(user_widget)
        
        # 侧边栏样式
        self.setStyleSheet(f"""
            GlassSidebar {{
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 rgba(15, 21, 35, 0.9),
                    stop:1 rgba(20, 27, 45, 0.85));
                border-right: 1px solid rgba(100, 150, 255, 0.15);
            }}
        """)
        self.setMinimumWidth(260)
        self.setMaximumWidth(320)
        
    def _on_menu_clicked(self, page_id):
        for item, pid in self.menu_items:
            item.set_selected(pid == page_id)
        self.page_changed.emit(page_id)


class KunlunSecurityPlatformPro(QMainWindow):
    """昆仑安全测试平台 Pro - 全新玻璃拟态UI主窗口"""
    
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
        self.setWindowTitle("昆仑安全测试平台 Pro - 专业级综合安全测试平台")
        self.setMinimumSize(1600, 1000)
        self.resize(1920, 1080)
        
        # 初始化UI
        self._init_ui()
        
        # 启动后台服务
        self._start_background_services()
        
        logger.info("昆仑安全测试平台 Pro - 玻璃拟态UI 初始化完成")
        
    def _init_ui(self):
        """初始化全新玻璃拟态UI"""
        # 主背景
        background = GlassBackgroundWidget()
        self.setCentralWidget(background)
        
        main_layout = QHBoxLayout(background)
        main_layout.setSpacing(0)
        main_layout.setContentsMargins(0, 0, 0, 0)
        
        # 主分割器
        splitter = QSplitter(Qt.Horizontal)
        
        # 左侧：侧边栏
        self.sidebar = GlassSidebar()
        self.sidebar.page_changed.connect(self._switch_page)
        splitter.addWidget(self.sidebar)
        
        # 右侧：主内容区
        content_widget = QWidget()
        content_layout = QVBoxLayout(content_widget)
        content_layout.setSpacing(24)
        content_layout.setContentsMargins(32, 32, 32, 32)
        
        # 顶部：标题栏
        header_widget = QWidget()
        header_layout = QHBoxLayout(header_widget)
        header_layout.setContentsMargins(0, 0, 0, 0)
        
        page_header = GlassSectionHeader(
            title="安全态势感知中心",
            subtitle="实时监控网络安全状态，智能识别风险威胁"
        )
        header_layout.addWidget(page_header)
        header_layout.addStretch()
        
        # 快速操作按钮
        quick_actions = QHBoxLayout()
        quick_actions.setSpacing(12)
        
        scan_btn = GlassButton("🔍 快速扫描", button_type="primary")
        scan_btn.setMinimumWidth(140)
        
        proxy_btn = GlassButton("🛡️ 启动代理", button_type="success")
        proxy_btn.setMinimumWidth(140)
        
        quick_actions.addWidget(scan_btn)
        quick_actions.addWidget(proxy_btn)
        
        header_layout.addLayout(quick_actions)
        
        content_layout.addWidget(header_widget)
        
        # 主内容区 - 使用堆叠窗口
        self.content_stack = QStackedWidget()
        
        # 创建各页面
        self._create_dashboard_page()
        self._create_proxy_page()
        self._create_scanner_page()
        self._create_intruder_page()
        self._create_encoder_page()
        self._create_knowledge_page()
        
        content_layout.addWidget(self.content_stack)
        
        splitter.addWidget(content_widget)
        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 4)
        
        main_layout.addWidget(splitter)
        
        # 状态栏
        self._init_status_bar()
        
    def _create_dashboard_page(self):
        """创建安全态势仪表盘页面"""
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setSpacing(24)
        layout.setContentsMargins(0, 0, 0, 0)
        
        # 数据可视化面板
        viz_panel = GlassPanel()
        viz_layout = QVBoxLayout(viz_panel)
        viz_layout.setContentsMargins(24, 24, 24, 24)
        
        data_viz = DataVisualizationPanel()
        viz_layout.addWidget(data_viz)
        
        layout.addWidget(viz_panel)
        
        # 功能快捷入口
        shortcuts_layout = QGridLayout()
        shortcuts_layout.setSpacing(16)
        
        shortcut_items = [
            ("🌐", "代理拦截", "实时拦截HTTP/HTTPS流量", "proxy"),
            ("🔍", "漏洞扫描", "智能Web漏洞自动检测", "scanner"),
            ("⚔️", "攻击工具", "专业级爆破和Payload测试", "intruder"),
            ("🔐", "编码解码", "多种编码格式转换工具", "encoder")
        ]
        
        for i, (icon, title, desc, page_id) in enumerate(shortcut_items):
            card = GlassCard(radius=16)
            card_layout = QVBoxLayout(card)
            card_layout.setSpacing(12)
            card_layout.setContentsMargins(20, 20, 20, 20)
            
            icon_label = QLabel(icon)
            icon_label.setStyleSheet("font-size: 36px;")
            
            title_label = QLabel(title)
            title_label.setStyleSheet(f"""
                color: {GlassEffect.COLORS['text_primary']};
                font-size: 18px;
                font-weight: 700;
            """)
            
            desc_label = QLabel(desc)
            desc_label.setWordWrap(True)
            desc_label.setStyleSheet(f"""
                color: {GlassEffect.COLORS['text_secondary']};
                font-size: 13px;
            """)
            
            card_layout.addWidget(icon_label)
            card_layout.addWidget(title_label)
            card_layout.addWidget(desc_label)
            card_layout.addStretch()
            
            shortcuts_layout.addWidget(card, i // 2, i % 2)
        
        layout.addLayout(shortcuts_layout)
        
        scroll = GlassScrollArea()
        scroll.setWidget(page)
        
        self.content_stack.addWidget(scroll)
        
    def _create_proxy_page(self):
        """创建代理拦截页面"""
        page = self._create_placeholder_page("🔍 代理拦截", "专业级HTTP/HTTPS流量拦截和分析工具")
        self.content_stack.addWidget(page)
        
    def _create_scanner_page(self):
        """创建漏洞扫描页面"""
        page = self._create_placeholder_page("🛡️ 漏洞扫描", "智能Web漏洞自动检测和风险评估")
        self.content_stack.addWidget(page)
        
    def _create_intruder_page(self):
        """创建攻击工具页面"""
        page = self._create_placeholder_page("⚔️ 攻击工具", "专业级爆破、Payload测试和攻击链构建")
        self.content_stack.addWidget(page)
        
    def _create_encoder_page(self):
        """创建编码解码页面"""
        page = self._create_placeholder_page("🔐 编码解码", "多种编码格式转换和Payload生成工具")
        self.content_stack.addWidget(page)
        
    def _create_knowledge_page(self):
        """创建知识库页面"""
        page = self._create_placeholder_page("📚 知识库", "渗透测试技巧、漏洞库和最佳实践")
        self.content_stack.addWidget(page)
        
    def _create_placeholder_page(self, icon, title):
        """创建占位页面"""
        page = GlassPanel()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(48, 48, 48, 48)
        
        icon_label = QLabel(icon)
        icon_label.setAlignment(Qt.AlignCenter)
        icon_label.setStyleSheet("font-size: 80px;")
        
        title_label = QLabel(title)
        title_label.setAlignment(Qt.AlignCenter)
        title_label.setStyleSheet(f"""
            color: {GlassEffect.COLORS['text_primary']};
            font-size: 32px;
            font-weight: 700;
            padding: 20px 0;
        """)
        
        desc_label = QLabel("功能开发中，敬请期待...")
        desc_label.setAlignment(Qt.AlignCenter)
        desc_label.setStyleSheet(f"""
            color: {GlassEffect.COLORS['text_secondary']};
            font-size: 16px;
        """)
        
        layout.addStretch()
        layout.addWidget(icon_label)
        layout.addWidget(title_label)
        layout.addWidget(desc_label)
        layout.addStretch()
        
        scroll = GlassScrollArea()
        scroll.setWidget(page)
        
        return scroll
        
    def _switch_page(self, page_id):
        """切换页面"""
        self.current_page = page_id
        
        page_index_map = {
            "dashboard": 0,
            "proxy": 1,
            "scanner": 2,
            "intruder": 3,
            "encoder": 4,
            "knowledge": 5
        }
        
        if page_id in page_index_map:
            self.content_stack.setCurrentIndex(page_index_map[page_id])
            
    def _init_status_bar(self):
        """初始化玻璃拟态状态栏"""
        status_bar = QStatusBar()
        status_bar.setStyleSheet(f"""
            QStatusBar {{
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 rgba(20, 27, 45, 0.9),
                    stop:1 rgba(15, 21, 35, 0.95));
                color: {GlassEffect.COLORS['text_secondary']};
                border-top: 1px solid rgba(100, 150, 255, 0.15);
                padding: 4px 16px;
                font-size: 12px;
            }}
        """)
        
        status_bar.addWidget(QLabel("🟢 系统状态：正常"))
        status_bar.addPermanentWidget(QLabel("📊 版本：Pro v1.0.0"))
        
        self.setStatusBar(status_bar)
        
    def _start_background_services(self):
        """启动后台服务"""
        logger.info("后台服务初始化...")