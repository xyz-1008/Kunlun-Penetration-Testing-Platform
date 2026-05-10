"""
昆仑安全测试平台 Pro - 专家级安全测试工具主界面
集成所有19个专业模块
"""

import logging
from PySide6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QSplitter, QTabWidget, QStatusBar,
    QMenuBar, QMenu, QLabel, QPushButton, QListWidget,
    QListWidgetItem, QMessageBox, QDockWidget, QStackedWidget,
    QScrollArea, QFrame
)
from PySide6.QtCore import Qt, Signal, QSize
from PySide6.QtGui import QAction, QPainter, QColor, QFont, QMouseEvent

from core.modules import (
    ProxyModule, RepeaterModule, IntruderModule,
    ScannerModule, SpiderModule, SequencerModule,
    DecoderModule, ComparerModule, TargetModule,
    MITMModule, MITMAdvancedModule, WebFuzzerModule, YakRunnerModule,
    PortScanModule, POCModule, ReverseShellHandler,
    CodecModule, SpaceEngineModule, ExtenderModule,
    PluginStoreModule, KnowledgeBaseModule, AISecurityDetectionModule,
    AttackOrchestrationModule, FingerprintRecognitionModule,
    PluginManagerModule, AssetModule, VulnerabilityModule
)
from core.config.config_manager import ConfigManager
from ui.settings_dialog import SettingsDialog

logger = logging.getLogger(__name__)


class TabButton(QFrame):
    """自定义标签按钮"""
    
    clicked = Signal(int)
    
    def __init__(self, text, index, parent=None):
        super().__init__(parent)
        self.text = text
        self.index = index
        self.is_selected = False
        self.is_separator = False
        self.is_hover = False
        self.setFixedHeight(28)
        self.setCursor(Qt.PointingHandCursor)
        self._update_width()
        
    def _update_width(self):
        if self.is_separator:
            self.setFixedWidth(20)
        else:
            width = max(80, len(self.text) * 10 + 20)
            self.setFixedWidth(width)
        
    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton and not self.is_separator:
            self.clicked.emit(self.index)
        super().mousePressEvent(event)
        
    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        
        if self.is_separator:
            painter.setPen(QColor("#555555"))
            painter.drawText(self.rect(), Qt.AlignCenter, "│")
            return
        
        if self.is_selected:
            painter.fillRect(self.rect(), QColor("#1e1e1e"))
            painter.setPen(QColor("#4CAF50"))
            painter.drawLine(2, self.height() - 2, self.width() - 2, self.height() - 2)
            painter.setPen(QColor("#ffffff"))
        elif self.is_hover:
            painter.fillRect(self.rect(), QColor("#3a3a3a"))
            painter.setPen(QColor("#ffffff"))
        else:
            painter.fillRect(self.rect(), QColor("#2d2d2d"))
            painter.setPen(QColor("#b0b0b0"))
        
        font = QFont()
        font.setPointSize(9)
        painter.setFont(font)
        painter.drawText(self.rect(), Qt.AlignCenter, self.text)
        
    def enterEvent(self, event):
        if not self.is_separator:
            self.is_hover = True
            self.update()
        super().enterEvent(event)
        
    def leaveEvent(self, event):
        self.is_hover = False
        self.update()
        super().leaveEvent(event)


class FlowLayout:
    """自动换行流式布局"""
    
    def __init__(self, parent, margin=0, spacing=0):
        self.parent = parent
        self.margin = margin
        self.spacing = spacing
        self.items = []
        self.height = 0
        
    def addWidget(self, widget):
        self.items.append(widget)
        widget.setParent(self.parent)
        self._do_layout()
        
    def _do_layout(self):
        if not self.items:
            return
        
        parent_width = self.parent.width() - 2 * self.margin
        x = self.margin
        y = self.margin
        line_height = 0
        
        for item in self.items:
            item_width = item.width()
            item_height = item.height()
            
            if x + item_width > parent_width and x > self.margin:
                x = self.margin
                y += line_height + self.spacing
                line_height = 0
            
            item.move(x, y)
            item.show()
            
            x += item_width + self.spacing
            line_height = max(line_height, item_height)
        
        self.height = y + line_height + self.margin
        self.parent.setFixedHeight(self.height)
        
    def clear(self):
        for item in self.items:
            item.setParent(None)
        self.items = []
        self.height = 0


class WrappingTabBar(QWidget):
    """自动换行标签栏 - 标签排满自动换行"""
    
    tabClicked = Signal(int)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedHeight(30)
        self.buttons = []
        self.current_index = -1
        self.layout = FlowLayout(self, margin=2, spacing=1)
        
    def resizeEvent(self, event):
        super().resizeEvent(event)
        self.layout._do_layout()
        
    def addTab(self, text, index):
        """添加标签"""
        btn = TabButton(text, index)
        btn.clicked.connect(self._on_button_clicked)
        self.layout.addWidget(btn)
        self.buttons.append(btn)
        
    def addSeparator(self):
        """添加分隔符"""
        sep = TabButton("", -1)
        sep.is_separator = True
        sep._update_width()
        self.layout.addWidget(sep)
        self.buttons.append(sep)
        
    def setCurrentIndex(self, index):
        """设置当前选中标签"""
        for btn in self.buttons:
            btn.is_selected = (btn.index == index)
            btn.update()
        self.current_index = index
        
    def _on_button_clicked(self, index):
        """按钮点击"""
        self.setCurrentIndex(index)
        self.tabClicked.emit(index)


class KunlunExpertPlatform(QMainWindow):
    """主窗口 - 专家平台"""
    
    def __init__(self, app_instance=None):
        super().__init__()
        
        self.app_instance = app_instance
        
        # 初始化配置管理器
        self.config_manager = ConfigManager()
        
        self.setWindowTitle("昆仑安全测试平台 Pro v1.0")
        self.setMinimumSize(1400, 800)
        self.resize(1600, 950)
        
        # 初始化模块
        self._init_modules()
        
        # 构建UI
        self._create_menu()
        self._create_central_widget()
        self._create_statusbar()
        
        logger.info("昆仑专家平台初始化完成")
        
    def _init_modules(self):
        """初始化所有模块"""
        self.modules = {
            "target": TargetModule(),
            "proxy": ProxyModule(),
            "spider": SpiderModule(),
            "scanner": ScannerModule(),
            "intruder": IntruderModule(),
            "repeater": RepeaterModule(),
            "sequencer": SequencerModule(),
            "decoder": DecoderModule(),
            "comparer": ComparerModule(),
            "extender": ExtenderModule(),
            "mitm": MITMModule(),
            "mitm_advanced": MITMAdvancedModule(),
            "webfuzzer": WebFuzzerModule(),
            "yakrunner": YakRunnerModule(),
            "portscan": PortScanModule(),
            "poc": POCModule(),
            "reverse": ReverseShellHandler(),
            "codec": CodecModule(),
            "spaceengine": SpaceEngineModule(),
            "pluginstore": PluginStoreModule(),
            "knowledgebase": KnowledgeBaseModule(),
            "aisecurity": AISecurityDetectionModule(),
            "attack_orchestrator": AttackOrchestrationModule(),
            "fingerprint": FingerprintRecognitionModule(),
            "plugin_manager": PluginManagerModule(),
            "asset": AssetModule(),
            "vuln": VulnerabilityModule()
        }
        
        # 模块名称映射（中文）
        self.module_names = {
            "target": "🎯 目标管理",
            "proxy": "🔌 代理拦截",
            "spider": "🕷️ 网络爬虫",
            "scanner": "🔍 漏洞扫描",
            "intruder": "⚔️ 攻击爆破",
            "repeater": "🔁 重放测试",
            "sequencer": "🎲 会话分析",
            "decoder": "🔡 编解码",
            "comparer": "📊 响应对比",
            "extender": "🔌 插件扩展",
            "mitm": "🎭 劫持工具",
            "mitm_advanced": "🛡️ MITM代理",
            "webfuzzer": "💥 模糊测试",
            "yakrunner": "🦙 脚本引擎",
            "portscan": "🔌 端口扫描",
            "poc": "💣 专项检测",
            "reverse": "🔙 反连Shell",
            "codec": "🔐 加密工具",
            "spaceengine": "🌐 空间引擎",
            "pluginstore": "🏪 插件商店",
            "knowledgebase": "📚 知识库",
            "aisecurity": "🤖 AI安全检测",
            "attack_orchestrator": "⚔️ 攻击编排",
            "fingerprint": "🔎 指纹识别",
            "plugin_manager": "🧩 插件管理",
            "asset": "🖥️ 资产管理",
            "vuln": "🐛 漏洞管理"
        }
        
    def _create_menu(self):
        """创建菜单栏"""
        menubar = self.menuBar()
        
        # 文件菜单
        file_menu = menubar.addMenu("&文件")
        
        new_project = QAction("&新建项目", self)
        new_project.setShortcut("Ctrl+N")
        file_menu.addAction(new_project)
        
        open_project = QAction("&打开项目", self)
        open_project.setShortcut("Ctrl+O")
        file_menu.addAction(open_project)
        
        file_menu.addSeparator()
        
        settings_action = QAction("⚙️ 设置", self)
        settings_action.setShortcut("Ctrl+,")
        settings_action.triggered.connect(self._show_settings)
        file_menu.addAction(settings_action)
        
        file_menu.addSeparator()
        
        exit_action = QAction("&退出", self)
        exit_action.setShortcut("Ctrl+Q")
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        # 视图菜单
        view_menu = menubar.addMenu("&视图")
        
        # 工具菜单
        tools_menu = menubar.addMenu("&工具")
        
        # 帮助菜单
        help_menu = menubar.addMenu("&帮助")
        
        about_action = QAction("&关于", self)
        about_action.triggered.connect(self._show_about)
        help_menu.addAction(about_action)
        
    def _create_central_widget(self):
        """创建中央部件 - 自动换行标签页布局（可扩展）"""
        central = QWidget()
        self.setCentralWidget(central)
        
        layout = QVBoxLayout(central)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        
        # 自动换行标签栏（标签排满自动换行）
        self.tab_bar = self._create_tab_bar()
        layout.addWidget(self.tab_bar)
        
        # 内容区域（所有模块共享一个StackedWidget）
        self.content_stack = QStackedWidget()
        self.content_stack.setStyleSheet("QStackedWidget { border: none; }")
        layout.addWidget(self.content_stack)
        
        # 模块ID到索引的映射
        self.module_index_map = {}
        
        # 按分类添加所有模块
        info_modules = ["target", "spider", "portscan", "spaceengine"]
        for module_id in info_modules:
            module = self.modules[module_id]
            idx = self.content_stack.addWidget(module.get_ui())
            self.module_index_map[module_id] = idx
            self.tab_bar.addTab(self.module_names[module_id], idx)
        
        self.tab_bar.addSeparator()
        
        vuln_modules = ["scanner", "poc", "fingerprint", "aisecurity", "intruder"]
        for module_id in vuln_modules:
            module = self.modules[module_id]
            idx = self.content_stack.addWidget(module.get_ui())
            self.module_index_map[module_id] = idx
            self.tab_bar.addTab(self.module_names[module_id], idx)
        
        self.tab_bar.addSeparator()
        
        proxy_modules = ["proxy", "repeater", "mitm", "webfuzzer"]
        for module_id in proxy_modules:
            module = self.modules[module_id]
            idx = self.content_stack.addWidget(module.get_ui())
            self.module_index_map[module_id] = idx
            self.tab_bar.addTab(self.module_names[module_id], idx)
        
        self.tab_bar.addSeparator()
        
        analysis_modules = ["sequencer", "decoder", "comparer", "codec"]
        for module_id in analysis_modules:
            module = self.modules[module_id]
            idx = self.content_stack.addWidget(module.get_ui())
            self.module_index_map[module_id] = idx
            self.tab_bar.addTab(self.module_names[module_id], idx)
        
        self.tab_bar.addSeparator()
        
        ext_modules = ["yakrunner", "extender", "pluginstore", "reverse", "knowledgebase", "attack_orchestrator"]
        for module_id in ext_modules:
            module = self.modules[module_id]
            idx = self.content_stack.addWidget(module.get_ui())
            self.module_index_map[module_id] = idx
            self.tab_bar.addTab(self.module_names[module_id], idx)
        
        self.tab_bar.addSeparator()
        
        management_modules = ["asset", "vuln"]
        for module_id in management_modules:
            module = self.modules[module_id]
            idx = self.content_stack.addWidget(module.get_ui())
            self.module_index_map[module_id] = idx
            self.tab_bar.addTab(self.module_names[module_id], idx)
        
        # 默认选中第一个模块
        self.tab_bar.setCurrentIndex(0)
        self.content_stack.setCurrentIndex(0)
        
    def _create_tab_bar(self):
        """创建自动换行标签栏"""
        tab_bar = WrappingTabBar()
        tab_bar.tabClicked.connect(self._on_tab_clicked)
        return tab_bar
    
    def _on_tab_clicked(self, index):
        """标签点击事件"""
        self.content_stack.setCurrentIndex(index)
        tab_text = self.content_stack.widget(index)
        if tab_text:
            # 查找模块名称
            for module_id, idx in self.module_index_map.items():
                if idx == index:
                    self.status_label.setText(f"当前模块: {self.module_names[module_id]}")
                    break
    
    def add_module(self, module_id, module_name, module_widget):
        """动态添加新模块（扩展接口）
        
        Args:
            module_id: 模块唯一ID
            module_name: 模块显示名称
            module_widget: 模块UI部件
        """
        idx = self.content_stack.addWidget(module_widget)
        self.module_index_map[module_id] = idx
        self.tab_bar.addTab(module_name, idx)
        
        self.modules[module_id] = type('obj', (object,), {'get_ui': lambda: module_widget})()
        self.module_names[module_id] = module_name
        
    def _create_statusbar(self):
        """创建状态栏"""
        self.statusbar = QStatusBar()
        self.setStatusBar(self.statusbar)
        
        self.status_label = QLabel("就绪")
        self.statusbar.addWidget(self.status_label, 1)
        
    def _on_tab_changed(self, index):
        """标签切换事件（兼容旧接口）"""
        pass
    
    def _switch_to_module(self, module_id):
        """切换到指定模块"""
        if module_id in self.module_index_map:
            idx = self.module_index_map[module_id]
            self.content_stack.setCurrentIndex(idx)
            self.tab_bar.setCurrentIndex(idx)
            self.status_label.setText(f"当前模块: {self.module_names[module_id]}")
        
    def _show_about(self):
        """显示关于对话框"""
        QMessageBox.about(
            self,
            "关于 昆仑安全测试平台 Pro",
            """<h2>昆仑安全测试平台 Pro v1.0</h2>
            <p>基于20年渗透测试经验的专业级安全测试平台</p>
            <p><b>核心特性：</b></p>
            <ul>
                <li>• Proxy代理 - HTTP/HTTPS拦截</li>
                <li>• Spider爬虫 - 智能站点爬取</li>
                <li>• Scanner扫描器 - 漏洞自动检测</li>
                <li>• Intruder攻击器 - 自动化爆破</li>
                <li>• Repeater重放 - 手工测试工具</li>
                <li>• Decoder解码 - 编解码工具箱</li>
                <li>• Target目标 - 站点地图与范围</li>
                <li>• 还有12+专业模块...</li>
            </ul>
            <p>昆仑安全实验室 · 荣誉出品</p>"""
        )
    
    def _show_settings(self):
        """显示设置对话框"""
        dialog = SettingsDialog(self, self.config_manager)
        dialog.settings_changed.connect(self._on_settings_changed)
        dialog.exec()
    
    def _on_settings_changed(self):
        """设置变更回调"""
        logger.info("设置已更新")
        # 可以在这里应用设置变更
        self.status_label.setText("设置已更新")
    
    def _new_project(self):
        """新建项目"""
        reply = QMessageBox.question(
            self,
            "确认",
            "确定要新建项目吗？未保存的更改将丢失。",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            self.log("INFO", "新建项目")
            self.toolbar_status.setText("新项目已创建")
    
    def _open_project(self):
        """打开项目"""
        from PySide6.QtWidgets import QFileDialog
        filename, _ = QFileDialog.getOpenFileName(
            self,
            "打开项目",
            "",
            "项目文件 (*.json);;所有文件 (*)"
        )
        
        if filename:
            try:
                import json
                with open(filename, 'r', encoding='utf-8') as f:
                    project_data = json.load(f)
                
                self.log("INFO", f"打开项目: {filename}")
                self.toolbar_status.setText(f"项目已打开: {filename}")
            except Exception as e:
                QMessageBox.critical(self, "错误", f"打开项目失败: {str(e)}")
    
    def _save_project(self):
        """保存项目"""
        from PySide6.QtWidgets import QFileDialog
        filename, _ = QFileDialog.getSaveFileName(
            self,
            "保存项目",
            "project.json",
            "项目文件 (*.json);;所有文件 (*)"
        )
        
        if filename:
            try:
                import json
                project_data = {
                    "version": "1.0",
                    "modules": list(self.modules.keys()),
                    "settings": {}
                }
                
                with open(filename, 'w', encoding='utf-8') as f:
                    json.dump(project_data, f, indent=2, ensure_ascii=False)
                
                self.log("INFO", f"保存项目: {filename}")
                self.toolbar_status.setText(f"项目已保存: {filename}")
            except Exception as e:
                QMessageBox.critical(self, "错误", f"保存项目失败: {str(e)}")
    
    def log(self, level: str, message: str):
        """记录日志"""
        logger.log(getattr(logging, level.upper(), logging.INFO), message)
