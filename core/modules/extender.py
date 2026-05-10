"""
Extender (扩展器)模块 - 插件系统
插件管理、加载、API接口、安全沙箱
"""

from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from enum import Enum, auto
import logging
import os
from pathlib import Path
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QSplitter, QTabWidget,
    QPushButton, QLabel, QLineEdit, QTextEdit, QComboBox,
    QGroupBox, QFormLayout, QProgressBar, QTableWidget,
    QTableWidgetItem, QHeaderView, QCheckBox, QFileDialog,
    QListWidget, QListWidgetItem
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QFont

from .base import ModuleBase

logger = logging.getLogger(__name__)


class PluginStatus(Enum):
    """插件状态"""
    LOADED = "已加载"
    UNLOADED = "未加载"
    ERROR = "错误"


@dataclass
class Plugin:
    """插件"""
    id: str
    name: str
    version: str
    author: str
    description: str
    path: str
    status: PluginStatus = PluginStatus.UNLOADED


class ExtenderModule(ModuleBase):
    """扩展器模块"""
    
    def __init__(self):
        super().__init__("Extender", "插件系统与扩展")
        self._plugins: List[Plugin] = []
        self._plugins_dir = Path(__file__).parent.parent.parent / "plugins"
        
    def _create_ui(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # 插件管理
        control_group = QGroupBox("插件管理")
        control_layout = QHBoxLayout(control_group)
        
        add_btn = QPushButton("➕ 添加插件")
        add_btn.clicked.connect(self._add_plugin)
        reload_btn = QPushButton("🔄 重新扫描")
        reload_btn.clicked.connect(self._scan_plugins)
        settings_btn = QPushButton("⚙️ 插件设置")
        
        control_layout.addWidget(add_btn)
        control_layout.addWidget(reload_btn)
        control_layout.addWidget(settings_btn)
        
        layout.addWidget(control_group)
        
        # 插件列表
        self.plugin_list = QListWidget()
        self.plugin_list.itemClicked.connect(self._show_plugin_detail)
        layout.addWidget(self.plugin_list)
        
        # 插件详情标签页
        detail_tabs = QTabWidget()
        
        # 基本信息
        self.plugin_info = QTextEdit()
        self.plugin_info.setReadOnly(True)
        self.plugin_info.setFont(QFont("Consolas", 9))
        detail_tabs.addTab(self.plugin_info, "📄 信息")
        
        # API 文档
        self.api_doc = QTextEdit()
        self.api_doc.setReadOnly(True)
        self.api_doc.setHtml("""
<h3>扩展API参考</h3>
<p>插件可以使用以下API:</p>
<ul>
    <li><b>HttpListener</b> - HTTP请求监听</li>
    <li><b>HttpHandler</b> - 请求/响应处理</li>
    <li><b>ScannerHelper</b> - 扫描辅助</li>
    <li><b>Utils</b> - 工具函数</li>
</ul>
<p>详细文档: 见 docs/api.md</p>
""")
        detail_tabs.addTab(self.api_doc, "📚 API文档")
        
        # 插件输出
        self.plugin_output = QTextEdit()
        self.plugin_output.setReadOnly(True)
        detail_tabs.addTab(self.plugin_output, "📜 输出")
        
        layout.addWidget(detail_tabs)
        
        # 初始化扫描
        self._scan_plugins()
        
        return widget
        
    def _scan_plugins(self):
        """扫描插件"""
        self._plugins.clear()
        self.plugin_list.clear()
        
        # 模拟插件
        sample_plugins = [
            Plugin(
                id="turbo_intruder",
                name="Turbo Intruder",
                version="1.2.0",
                author="PortSwigger",
                description="高速模糊测试和攻击插件",
                path="",
                status=PluginStatus.LOADED
            ),
            Plugin(
                id="autorize",
                name="Autorize",
                version="2.0",
                author="Barak Tawily",
                description="自动权限提升检测",
                path="",
                status=PluginStatus.LOADED
            ),
            Plugin(
                id="json_web_token",
                name="JSON Web Token",
                version="1.0",
                author="Security",
                description="JWT解析和操作",
                path="",
                status=PluginStatus.UNLOADED
            )
        ]
        
        for p in sample_plugins:
            self._plugins.append(p)
            item = QListWidgetItem(f"{p.name} v{p.version} - {p.author}")
            item.setData(Qt.UserRole, p)
            self.plugin_list.addItem(item)
            
        self.log("INFO", f"扫描完成，发现 {len(self._plugins)} 个插件")
        
    def _add_plugin(self):
        """添加插件"""
        filename, _ = QFileDialog.getOpenFileName(
            None, "选择插件", "", "Python Files (*.py);;All Files (*)"
        )
        if filename:
            self.log("INFO", f"插件已添加: {filename}")
            
    def _show_plugin_detail(self, item):
        """显示插件详情"""
        plugin = item.data(Qt.UserRole)
        if plugin:
            detail = f"""
插件信息
========
名称: {plugin.name}
ID: {plugin.id}
版本: {plugin.version}
作者: {plugin.author}
状态: {plugin.status.value}

描述:
{plugin.description}
"""
            self.plugin_info.setText(detail)
