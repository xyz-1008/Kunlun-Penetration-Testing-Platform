"""
专业级安全测试平台主界面
基于20年渗透测试经验和360网络安全标准设计
昆仑安全实验室自主研发的专业平台
"""

import logging
import asyncio
from PySide6.QtWidgets import (QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
                               QSplitter, QTabWidget, QToolBar, QStatusBar,
                               QMenuBar, QMenu, QMessageBox, QLabel, QPushButton,
                               QLineEdit, QTreeWidget, QTreeWidgetItem, QTextEdit,
                               QListWidget, QListWidgetItem, QProgressBar, QDockWidget,
                               QGroupBox, QFrame, QStackedWidget, QTableWidget, 
                               QTableWidgetItem, QHeaderView, QComboBox, QCheckBox,
                               QSpinBox, QDoubleSpinBox, QTextBrowser, QScrollArea)
from PySide6.QtCore import Qt, QTimer, QSize, Signal, QRect, QThread, QObject
from PySide6.QtGui import QIcon, QFont, QColor, QPalette, QAction, QPainter, QBrush, QKeySequence

from core.proxy.professional_proxy import ProfessionalProxyServer
from core.scanner.advanced_scanner import AdvancedVulnerabilityScanner
from core.intruder.professional_intruder import ProfessionalIntruder
from core.encoder.advanced_encoder import AdvancedEncoderDecoder

logger = logging.getLogger(__name__)

class ProfessionalSecurityPlatform(QMainWindow):
    """专业级安全测试平台主窗口"""
    
    # 专业级主题颜色定义
    PROFESSIONAL_THEME = {
        # 背景色
        'bg_primary': '#0d1117',
        'bg_secondary': '#161b22',
        'bg_tertiary': '#21262d',
        'bg_hover': '#30363d',
        'bg_selected': '#1f6feb',
        
        # 边框色
        'border_primary': '#30363d',
        'border_secondary': '#484f58',
        'border_focus': '#1f6feb',
        
        # 文字色
        'text_primary': '#f0f6fc',
        'text_secondary': '#8b949e',
        'text_disabled': '#484f58',
        'text_success': '#3fb950',
        'text_warning': '#d29922',
        'text_error': '#58a6ff',
        'text_info': '#58a6ff',
        
        # 强调色
        'accent_primary': '#1f6feb',
        'accent_secondary': '#58a6ff',
        'accent_success': '#3fb950',
        'accent_warning': '#d29922',
        'accent_error': '#58a6ff',
        
        # 功能色
        'proxy_active': '#1f6feb',
        'intercept_active': '#58a6ff',
        'scan_active': '#3fb950',
        'attack_active': '#d29922'
    }
    
    def __init__(self, app_instance=None):
        super().__init__()
        
        self.app_instance = app_instance
        
        # 初始化核心组件
        self.proxy_server = ProfessionalProxyServer()
        self.vuln_scanner = AdvancedVulnerabilityScanner()
        self.intruder_tool = ProfessionalIntruder()
        self.encoder_tool = AdvancedEncoderDecoder()
        
        # 窗口属性
        self.setWindowTitle("昆仑安全测试平台 Pro - 专业级综合安全测试平台")
        self.setMinimumSize(1400, 900)
        self.resize(1600, 1000)
        
        # 应用专业主题
        self._apply_professional_theme()
        
        # 初始化UI组件
        self._init_ui_components()
        
        # 初始化菜单和工具栏
        self._init_professional_menu_bar()
        self._init_professional_tool_bar()
        self._init_professional_status_bar()
        
        # 初始化功能模块
        self._init_functional_modules()
        
        # 启动后台服务
        self._start_background_services()
        
        logger.info("专业级安全测试平台初始化完成")
    
    def _apply_professional_theme(self):
        """应用专业级主题"""
        palette = QPalette()
        
        # 设置专业级颜色方案
        palette.setColor(QPalette.Window, QColor(self.PROFESSIONAL_THEME['bg_primary']))
        palette.setColor(QPalette.WindowText, QColor(self.PROFESSIONAL_THEME['text_primary']))
        palette.setColor(QPalette.Base, QColor(self.PROFESSIONAL_THEME['bg_secondary']))
        palette.setColor(QPalette.AlternateBase, QColor(self.PROFESSIONAL_THEME['bg_tertiary']))
        palette.setColor(QPalette.ToolTipBase, QColor(self.PROFESSIONAL_THEME['bg_tertiary']))
        palette.setColor(QPalette.ToolTipText, QColor(self.PROFESSIONAL_THEME['text_primary']))
        palette.setColor(QPalette.Text, QColor(self.PROFESSIONAL_THEME['text_primary']))
        palette.setColor(QPalette.Button, QColor(self.PROFESSIONAL_THEME['bg_tertiary']))
        palette.setColor(QPalette.ButtonText, QColor(self.PROFESSIONAL_THEME['text_primary']))
        palette.setColor(QPalette.BrightText, QColor(self.PROFESSIONAL_THEME['text_primary']))
        palette.setColor(QPalette.Highlight, QColor(self.PROFESSIONAL_THEME['accent_primary']))
        palette.setColor(QPalette.HighlightedText, QColor(self.PROFESSIONAL_THEME['text_primary']))
        
        self.setPalette(palette)
        
        # 设置专业级样式表
        self._apply_professional_stylesheet()
    
    def _apply_professional_stylesheet(self):
        """应用专业级样式表"""
        theme = self.PROFESSIONAL_THEME
        
        stylesheet = f"""
        QMainWindow {{
            background-color: {theme['bg_primary']};
            color: {theme['text_primary']};
        }}
        
        /* 菜单栏样式 */
        QMenuBar {{
            background-color: {theme['bg_secondary']};
            color: {theme['text_primary']};
            border-bottom: 1px solid {theme['border_primary']};
            padding: 5px;
        }}
        QMenuBar::item {{
            background-color: transparent;
            padding: 5px 10px;
            border-radius: 3px;
            margin: 2px;
        }}
        QMenuBar::item:selected {{
            background-color: {theme['bg_hover']};
        }}
        QMenuBar::item:pressed {{
            background-color: {theme['accent_primary']};
        }}
        
        /* 工具栏样式 */
        QToolBar {{
            background-color: {theme['bg_secondary']};
            border-bottom: 1px solid {theme['border_primary']};
            spacing: 5px;
            padding: 5px;
        }}
        QToolButton {{
            background-color: {theme['bg_tertiary']};
            color: {theme['text_primary']};
            border: 1px solid {theme['border_primary']};
            border-radius: 3px;
            padding: 5px 10px;
            min-width: 80px;
        }}
        QToolButton:hover {{
            background-color: {theme['bg_hover']};
            border-color: {theme['border_secondary']};
        }}
        QToolButton:pressed {{
            background-color: {theme['accent_primary']};
            border-color: {theme['accent_primary']};
        }}
        QToolButton:checked {{
            background-color: {theme['accent_primary']};
            border-color: {theme['accent_primary']};
        }}
        
        /* 标签页样式 */
        QTabWidget::pane {{
            border: 1px solid {theme['border_primary']};
            background-color: {theme['bg_secondary']};
        }}
        QTabBar::tab {{
            background-color: {theme['bg_tertiary']};
            color: {theme['text_primary']};
            border: 1px solid {theme['border_primary']};
            border-bottom: none;
            padding: 8px 16px;
            margin-right: 2px;
            border-top-left-radius: 4px;
            border-top-right-radius: 4px;
        }}
        QTabBar::tab:selected {{
            background-color: {theme['bg_secondary']};
            border-color: {theme['border_primary']};
            border-bottom-color: {theme['bg_secondary']};
        }}
        QTabBar::tab:hover {{
            background-color: {theme['bg_hover']};
        }}
        
        /* 表格样式 */
        QTableWidget {{
            background-color: {theme['bg_secondary']};
            color: {theme['text_primary']};
            gridline-color: {theme['border_primary']};
            border: 1px solid {theme['border_primary']};
        }}
        QTableWidget::item {{
            background-color: {theme['bg_secondary']};
            color: {theme['text_primary']};
            border: none;
            padding: 5px;
        }}
        QTableWidget::item:selected {{
            background-color: {theme['accent_primary']};
            color: {theme['text_primary']};
        }}
        QHeaderView::section {{
            background-color: {theme['bg_tertiary']};
            color: {theme['text_primary']};
            border: 1px solid {theme['border_primary']};
            padding: 5px;
        }}
        
        /* 按钮样式 */
        QPushButton {{
            background-color: {theme['bg_tertiary']};
            color: {theme['text_primary']};
            border: 1px solid {theme['border_primary']};
            border-radius: 3px;
            padding: 8px 16px;
            font-weight: bold;
        }}
        QPushButton:hover {{
            background-color: {theme['bg_hover']};
            border-color: {theme['border_secondary']};
        }}
        QPushButton:pressed {{
            background-color: {theme['accent_primary']};
            border-color: {theme['accent_primary']};
        }}
        QPushButton:disabled {{
            background-color: {theme['bg_tertiary']};
            color: {theme['text_disabled']};
            border-color: {theme['border_primary']};
        }}
        
        /* 输入框样式 */
        QLineEdit, QTextEdit, QComboBox {{
            background-color: {theme['bg_tertiary']};
            color: {theme['text_primary']};
            border: 1px solid {theme['border_primary']};
            border-radius: 3px;
            padding: 5px;
        }}
        QLineEdit:focus, QTextEdit:focus, QComboBox:focus {{
            border-color: {theme['accent_primary']};
        }}
        
        /* 进度条样式 */
        QProgressBar {{
            border: 1px solid {theme['border_primary']};
            border-radius: 3px;
            background-color: {theme['bg_tertiary']};
            text-align: center;
        }}
        QProgressBar::chunk {{
            background-color: {theme['accent_primary']};
            border-radius: 2px;
        }}
        
        /* 分割器样式 */
        QSplitter::handle {{
            background-color: {theme['border_primary']};
        }}
        QSplitter::handle:hover {{
            background-color: {theme['border_secondary']};
        }}
        
        /* 状态栏样式 */
        QStatusBar {{
            background-color: {theme['bg_secondary']};
            color: {theme['text_primary']};
            border-top: 1px solid {theme['border_primary']};
        }}
        """
        
        self.setStyleSheet(stylesheet)
    
    def _init_ui_components(self):
        """初始化UI组件"""
        # 创建中心部件
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # 主布局
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        
        # 创建主分割器
        main_splitter = QSplitter(Qt.Horizontal)
        main_layout.addWidget(main_splitter)
        
        # 左侧导航面板
        self._create_navigation_panel(main_splitter)
        
        # 右侧主工作区
        self._create_main_workspace(main_splitter)
        
        # 设置分割器比例
        main_splitter.setSizes([300, 1300])
    
    def _create_navigation_panel(self, parent_splitter):
        """创建左侧导航面板"""
        navigation_widget = QWidget()
        navigation_layout = QVBoxLayout(navigation_widget)
        navigation_layout.setContentsMargins(5, 5, 5, 5)
        
        # 功能模块导航
        self._create_module_navigation(navigation_layout)
        
        # 项目树形视图
        self._create_project_tree(navigation_layout)
        
        # 工具快捷面板
        self._create_tool_quick_panel(navigation_layout)
        
        parent_splitter.addWidget(navigation_widget)
    
    def _create_module_navigation(self, parent_layout):
        """创建功能模块导航"""
        module_group = QGroupBox("功能模块")
        module_layout = QVBoxLayout(module_group)
        
        # 代理模块
        proxy_btn = QPushButton("🔄 代理拦截")
        proxy_btn.setCheckable(True)
        proxy_btn.clicked.connect(self._toggle_proxy_module)
        module_layout.addWidget(proxy_btn)
        
        # 扫描模块
        scan_btn = QPushButton("🔍 漏洞扫描")
        scan_btn.setCheckable(True)
        scan_btn.clicked.connect(self._toggle_scan_module)
        module_layout.addWidget(scan_btn)
        
        # 攻击模块
        attack_btn = QPushButton("⚡ 攻击工具")
        attack_btn.setCheckable(True)
        attack_btn.clicked.connect(self._toggle_attack_module)
        module_layout.addWidget(attack_btn)
        
        # 工具模块
        tools_btn = QPushButton("🛠️ 辅助工具")
        tools_btn.setCheckable(True)
        tools_btn.clicked.connect(self._toggle_tools_module)
        module_layout.addWidget(tools_btn)
        
        parent_layout.addWidget(module_group)
    
    def _create_project_tree(self, parent_layout):
        """创建项目树形视图"""
        project_group = QGroupBox("测试项目")
        project_layout = QVBoxLayout(project_group)
        
        self.project_tree = QTreeWidget()
        self.project_tree.setHeaderLabels(["项目", "状态", "进度"])
        project_layout.addWidget(self.project_tree)
        
        # 项目操作按钮
        project_btn_layout = QHBoxLayout()
        new_project_btn = QPushButton("新建")
        open_project_btn = QPushButton("打开")
        save_project_btn = QPushButton("保存")
        
        project_btn_layout.addWidget(new_project_btn)
        project_btn_layout.addWidget(open_project_btn)
        project_btn_layout.addWidget(save_project_btn)
        project_layout.addLayout(project_btn_layout)
        
        parent_layout.addWidget(project_group)
    
    def _create_tool_quick_panel(self, parent_layout):
        """创建工具快捷面板"""
        tool_group = QGroupBox("快捷工具")
        tool_layout = QVBoxLayout(tool_group)
        
        # 编码解码工具
        encoder_btn = QPushButton("🔤 编码解码")
        encoder_btn.clicked.connect(self._open_encoder_tool)
        tool_layout.addWidget(encoder_btn)
        
        # 哈希计算工具
        hash_btn = QPushButton("#️⃣ 哈希计算")
        hash_btn.clicked.connect(self._open_hash_tool)
        tool_layout.addWidget(hash_btn)
        
        # 正则测试工具
        regex_btn = QPushButton(".*? 正则测试")
        regex_btn.clicked.connect(self._open_regex_tool)
        tool_layout.addWidget(regex_btn)
        
        parent_layout.addWidget(tool_group)
    
    def _create_main_workspace(self, parent_splitter):
        """创建右侧主工作区"""
        workspace_widget = QWidget()
        workspace_layout = QVBoxLayout(workspace_widget)
        workspace_layout.setContentsMargins(0, 0, 0, 0)
        
        # 创建标签页容器
        self.workspace_tabs = QTabWidget()
        self.workspace_tabs.setTabsClosable(False)
        workspace_layout.addWidget(self.workspace_tabs)
        
        # 创建默认标签页
        self._create_proxy_tab()
        self._create_scanner_tab()
        self._create_intruder_tab()
        
        parent_splitter.addWidget(workspace_widget)
    
    def _create_proxy_tab(self):
        """创建代理拦截标签页"""
        proxy_tab = QWidget()
        proxy_layout = QVBoxLayout(proxy_tab)
        
        # 代理控制面板
        proxy_control_layout = QHBoxLayout()
        
        self.proxy_start_btn = QPushButton("启动代理")
        self.proxy_start_btn.clicked.connect(self._toggle_proxy)
        proxy_control_layout.addWidget(self.proxy_start_btn)
        
        self.intercept_btn = QPushButton("拦截请求")
        self.intercept_btn.setCheckable(True)
        self.intercept_btn.clicked.connect(self._toggle_intercept)
        proxy_control_layout.addWidget(self.intercept_btn)
        
        proxy_port_input = QLineEdit("8080")
        proxy_control_layout.addWidget(QLabel("端口:"))
        proxy_control_layout.addWidget(proxy_port_input)
        
        proxy_control_layout.addStretch()
        proxy_layout.addLayout(proxy_control_layout)
        
        # 请求/响应分割器
        proxy_splitter = QSplitter(Qt.Horizontal)
        proxy_layout.addWidget(proxy_splitter)
        
        # 请求列表
        request_widget = QWidget()
        request_layout = QVBoxLayout(request_widget)
        request_layout.addWidget(QLabel("请求列表"))
        self.request_table = QTableWidget()
        self.request_table.setColumnCount(5)
        self.request_table.setHorizontalHeaderLabels(["ID", "方法", "URL", "状态", "长度"])
        request_layout.addWidget(self.request_table)
        proxy_splitter.addWidget(request_widget)
        
        # 请求详情
        detail_widget = QWidget()
        detail_layout = QVBoxLayout(detail_widget)
        
        detail_tabs = QTabWidget()
        
        # 请求标签页
        request_detail = QTextEdit()
        detail_tabs.addTab(request_detail, "请求")
        
        # 响应标签页
        response_detail = QTextEdit()
        detail_tabs.addTab(response_detail, "响应")
        
        # 原始数据标签页
        raw_detail = QTextEdit()
        detail_tabs.addTab(raw_detail, "原始数据")
        
        detail_layout.addWidget(detail_tabs)
        proxy_splitter.addWidget(detail_widget)
        
        proxy_splitter.setSizes([400, 600])
        
        self.workspace_tabs.addTab(proxy_tab, "🔄 代理拦截")
    
    def _create_scanner_tab(self):
        """创建漏洞扫描标签页"""
        scanner_tab = QWidget()
        scanner_layout = QVBoxLayout(scanner_tab)
        
        # 扫描控制面板
        scan_control_layout = QHBoxLayout()
        
        target_input = QLineEdit()
        target_input.setPlaceholderText("输入目标URL")
        scan_control_layout.addWidget(QLabel("目标:"))
        scan_control_layout.addWidget(target_input)
        
        scan_type_combo = QComboBox()
        scan_type_combo.addItems(["全面扫描", "快速扫描", "自定义扫描"])
        scan_control_layout.addWidget(QLabel("类型:"))
        scan_control_layout.addWidget(scan_type_combo)
        
        start_scan_btn = QPushButton("开始扫描")
        start_scan_btn.clicked.connect(self._start_scan)
        scan_control_layout.addWidget(start_scan_btn)
        
        scan_control_layout.addStretch()
        scanner_layout.addLayout(scan_control_layout)
        
        # 扫描进度
        scan_progress = QProgressBar()
        scanner_layout.addWidget(scan_progress)
        
        # 扫描结果表格
        result_table = QTableWidget()
        result_table.setColumnCount(6)
        result_table.setHorizontalHeaderLabels(["漏洞", "风险", "URL", "参数", "Payload", "状态"])
        scanner_layout.addWidget(result_table)
        
        self.workspace_tabs.addTab(scanner_tab, "🔍 漏洞扫描")
    
    def _create_intruder_tab(self):
        """创建攻击工具标签页"""
        intruder_tab = QWidget()
        intruder_layout = QVBoxLayout(intruder_tab)
        
        # 攻击配置面板
        config_layout = QHBoxLayout()
        
        attack_type_combo = QComboBox()
        attack_type_combo.addItems(["SQL注入", "XSS", "命令注入", "文件包含", "自定义"])
        config_layout.addWidget(QLabel("攻击类型:"))
        config_layout.addWidget(attack_type_combo)
        
        target_url_input = QLineEdit()
        target_url_input.setPlaceholderText("目标URL")
        config_layout.addWidget(QLabel("目标:"))
        config_layout.addWidget(target_url_input)
        
        start_attack_btn = QPushButton("开始攻击")
        start_attack_btn.clicked.connect(self._start_attack)
        config_layout.addWidget(start_attack_btn)
        
        config_layout.addStretch()
        intruder_layout.addLayout(config_layout)
        
        # Payload配置
        payload_layout = QHBoxLayout()
        
        payload_type_combo = QComboBox()
        payload_type_combo.addItems(["字典", "数字", "字符", "自定义"])
        payload_layout.addWidget(QLabel("Payload类型:"))
        payload_layout.addWidget(payload_type_combo)
        
        payload_file_input = QLineEdit()
        payload_file_input.setPlaceholderText("Payload文件路径")
        payload_layout.addWidget(QLabel("文件:"))
        payload_layout.addWidget(payload_file_input)
        
        payload_layout.addStretch()
        intruder_layout.addLayout(payload_layout)
        
        # 攻击结果表格
        attack_result_table = QTableWidget()
        attack_result_table.setColumnCount(5)
        attack_result_table.setHorizontalHeaderLabels(["请求", "状态", "长度", "时间", "结果"])
        intruder_layout.addWidget(attack_result_table)
        
        self.workspace_tabs.addTab(intruder_tab, "⚡ 攻击工具")
    
    def _init_professional_menu_bar(self):
        """初始化专业级菜单栏"""
        menu_bar = self.menuBar()
        
        # 文件菜单
        file_menu = menu_bar.addMenu("文件")
        file_menu.addAction("新建项目", self._new_project, QKeySequence.New)
        file_menu.addAction("打开项目", self._open_project, QKeySequence.Open)
        file_menu.addAction("保存项目", self._save_project, QKeySequence.Save)
        file_menu.addSeparator()
        file_menu.addAction("导入数据", self._import_data)
        file_menu.addAction("导出报告", self._export_report)
        file_menu.addSeparator()
        file_menu.addAction("退出", self.close, QKeySequence.Quit)
        
        # 编辑菜单
        edit_menu = menu_bar.addMenu("编辑")
        edit_menu.addAction("撤销", self._undo, QKeySequence.Undo)
        edit_menu.addAction("重做", self._redo, QKeySequence.Redo)
        edit_menu.addSeparator()
        edit_menu.addAction("复制", self._copy, QKeySequence.Copy)
        edit_menu.addAction("粘贴", self._paste, QKeySequence.Paste)
        
        # 视图菜单
        view_menu = menu_bar.addMenu("视图")
        view_menu.addAction("全屏", self._toggle_fullscreen, "F11")
        view_menu.addSeparator()
        view_menu.addAction("显示工具栏", self._toggle_toolbar).setCheckable(True)
        view_menu.addAction("显示状态栏", self._toggle_statusbar).setCheckable(True)
        
        # 工具菜单
        tools_menu = menu_bar.addMenu("工具")
        tools_menu.addAction("代理设置", self._open_proxy_settings)
        tools_menu.addAction("扫描配置", self._open_scan_config)
        tools_menu.addAction("攻击配置", self._open_attack_config)
        tools_menu.addSeparator()
        tools_menu.addAction("编码解码", self._open_encoder_tool)
        tools_menu.addAction("哈希计算", self._open_hash_tool)
        
        # 帮助菜单
        help_menu = menu_bar.addMenu("帮助")
        help_menu.addAction("用户手册", self._open_user_manual)
        help_menu.addAction("关于", self._show_about)
    
    def _init_professional_tool_bar(self):
        """初始化专业级工具栏"""
        tool_bar = QToolBar("主工具栏")
        self.addToolBar(tool_bar)
        
        # 代理工具
        proxy_action = QAction("🔄 代理", self)
        proxy_action.triggered.connect(self._toggle_proxy_module)
        tool_bar.addAction(proxy_action)
        
        # 扫描工具
        scan_action = QAction("🔍 扫描", self)
        scan_action.triggered.connect(self._toggle_scan_module)
        tool_bar.addAction(scan_action)
        
        # 攻击工具
        attack_action = QAction("⚡ 攻击", self)
        attack_action.triggered.connect(self._toggle_attack_module)
        tool_bar.addAction(attack_action)
        
        tool_bar.addSeparator()
        
        # 编码工具
        encode_action = QAction("🔤 编码", self)
        encode_action.triggered.connect(self._open_encoder_tool)
        tool_bar.addAction(encode_action)
        
        # 哈希工具
        hash_action = QAction("#️⃣ 哈希", self)
        hash_action.triggered.connect(self._open_hash_tool)
        tool_bar.addAction(hash_action)
    
    def _init_professional_status_bar(self):
        """初始化专业级状态栏"""
        status_bar = self.statusBar()
        
        # 代理状态
        self.proxy_status_label = QLabel("代理: 未启动")
        status_bar.addWidget(self.proxy_status_label)
        
        # 拦截状态
        self.intercept_status_label = QLabel("拦截: 关闭")
        status_bar.addWidget(self.intercept_status_label)
        
        # 扫描状态
        self.scan_status_label = QLabel("扫描: 空闲")
        status_bar.addWidget(self.scan_status_label)
        
        status_bar.addPermanentWidget(QLabel("昆仑安全测试平台 v1.0"))
    
    def _init_functional_modules(self):
        """初始化功能模块"""
        # 这里将初始化各个功能模块的具体实现
        pass
    
    def _start_background_services(self):
        """启动后台服务"""
        # 启动代理服务监控
        self.proxy_monitor_timer = QTimer()
        self.proxy_monitor_timer.timeout.connect(self._update_proxy_status)
        self.proxy_monitor_timer.start(1000)  # 每秒更新一次
    
    # ========== 功能方法实现 ==========
    
    def _toggle_proxy(self):
        """切换代理状态"""
        if self.proxy_start_btn.text() == "启动代理":
            # 启动代理
            asyncio.create_task(self._start_proxy_server())
            self.proxy_start_btn.setText("停止代理")
            self.proxy_status_label.setText("代理: 运行中")
        else:
            # 停止代理
            asyncio.create_task(self._stop_proxy_server())
            self.proxy_start_btn.setText("启动代理")
            self.proxy_status_label.setText("代理: 未启动")
    
    def _toggle_intercept(self):
        """切换拦截状态"""
        if self.intercept_btn.isChecked():
            self.intercept_status_label.setText("拦截: 开启")
        else:
            self.intercept_status_label.setText("拦截: 关闭")
    
    def _start_scan(self):
        """开始扫描"""
        self.scan_status_label.setText("扫描: 进行中")
        # 扫描逻辑实现
        pass
    
    def _start_attack(self):
        """开始攻击"""
        # 攻击逻辑实现
        pass
    
    def _toggle_proxy_module(self):
        """切换代理模块"""
        self.workspace_tabs.setCurrentIndex(0)
    
    def _toggle_scan_module(self):
        """切换扫描模块"""
        self.workspace_tabs.setCurrentIndex(1)
    
    def _toggle_attack_module(self):
        """切换攻击模块"""
        self.workspace_tabs.setCurrentIndex(2)
    
    def _toggle_tools_module(self):
        """切换工具模块"""
        # 工具模块实现
        pass
    
    def _open_encoder_tool(self):
        """打开编码解码工具"""
        # 编码解码工具实现
        pass
    
    def _open_hash_tool(self):
        """打开哈希计算工具"""
        # 哈希计算工具实现
        pass
    
    def _open_regex_tool(self):
        """打开正则测试工具"""
        # 正则测试工具实现
        pass
    
    def _close_tab(self, index):
        """关闭标签页"""
        if self.workspace_tabs.count() > 1:  # 保留至少一个标签页
            self.workspace_tabs.removeTab(index)
    
    # ========== 异步方法 ==========
    
    async def _start_proxy_server(self):
        """启动代理服务器"""
        try:
            await self.proxy_server.start_proxy(8080)
            logger.info("代理服务器启动成功")
        except Exception as e:
            logger.error(f"代理服务器启动失败: {e}")
            self.proxy_start_btn.setText("启动代理")
            self.proxy_status_label.setText("代理: 启动失败")
    
    async def _stop_proxy_server(self):
        """停止代理服务器"""
        try:
            await self.proxy_server.stop_proxy()
            logger.info("代理服务器停止成功")
        except Exception as e:
            logger.error(f"代理服务器停止失败: {e}")
    
    def _update_proxy_status(self):
        """更新代理状态"""
        # 实时更新代理状态显示
        pass
    
    # ========== 菜单方法占位符 ==========
    
    def _new_project(self):
        """新建项目"""
        pass
    
    def _open_project(self):
        """打开项目"""
        pass
    
    def _save_project(self):
        """保存项目"""
        pass
    
    def _import_data(self):
        """导入数据"""
        pass
    
    def _export_report(self):
        """导出报告"""
        pass
    
    def _undo(self):
        """撤销"""
        pass
    
    def _redo(self):
        """重做"""
        pass
    
    def _copy(self):
        """复制"""
        pass
    
    def _paste(self):
        """粘贴"""
        pass
    
    def _toggle_fullscreen(self):
        """切换全屏"""
        if self.isFullScreen():
            self.showNormal()
        else:
            self.showFullScreen()
    
    def _toggle_toolbar(self):
        """切换工具栏显示"""
        pass
    
    def _toggle_statusbar(self):
        """切换状态栏显示"""
        pass
    
    def _open_proxy_settings(self):
        """打开代理设置"""
        pass
    
    def _open_scan_config(self):
        """打开扫描配置"""
        pass
    
    def _open_attack_config(self):
        """打开攻击配置"""
        pass
    
    def _open_user_manual(self):
        """打开用户手册"""
        pass
    
    def _show_about(self):
        """显示关于信息"""
        about_text = """
        <h2>昆仑安全测试平台 Pro</h2>
        <p><b>版本:</b> 1.0.0</p>
        <p><b>基于:</b> 20年渗透测试经验 + 360网络安全标准</p>
        <p>专业级综合安全测试平台，昆仑安全实验室自主研发</p>
        <p><b>开发团队:</b> 昆仑安全实验室</p>
        <p><b>技术支持:</b> 昆仑安全实验室</p>
        """
        QMessageBox.about(self, "关于昆仑安全测试平台", about_text)

# 后台服务线程
class BackgroundServiceThread(QThread):
    """后台服务线程"""
    
    def __init__(self, service_function):
        super().__init__()
        self.service_function = service_function
    
    def run(self):
        """运行后台服务"""
        asyncio.run(self.service_function())