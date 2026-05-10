"""
Plugin Store (插件商店)模块
插件浏览、安装更新、评分
"""

from typing import Dict, Any, List, Optional
from dataclasses import dataclass
from enum import Enum, auto
import logging
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTabWidget,
    QPushButton, QLabel, QLineEdit, QTextEdit, QComboBox,
    QGroupBox, QFormLayout, QListWidget,
    QListWidgetItem, QSplitter
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QFont

from .base import ModuleBase

logger = logging.getLogger(__name__)


@dataclass
class StorePlugin:
    id: str
    name: str
    description: str
    author: str
    stars: int
    version: str
    installed: bool


class PluginStoreModule(ModuleBase):
    """插件商店模块"""
    
    def __init__(self):
        super().__init__("PluginStore", "插件商店")
        
    def _create_ui(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # 搜索
        search_group = QGroupBox("🔎 搜索插件")
        search_layout = QHBoxLayout(search_group)
        
        self.search = QLineEdit()
        self.search.setPlaceholderText("Search plugin name...")
        
        self.cat = QComboBox()
        self.cat.addItems(["All", "Scanner", "Exploit", "Utils", "Fuzzer"])
        
        self.search_btn = QPushButton("🔎 搜索")
        
        search_layout.addWidget(self.search)
        search_layout.addWidget(self.cat)
        search_layout.addWidget(self.search_btn)
        
        layout.addWidget(search_group)
        
        # 分类标签
        tabs = QTabWidget()
        
        # 热门
        hot_tab = self._create_plugin_list([
            StorePlugin("turbo-intruder", "Turbo Intruder", "Fast Fuzzer", "James Kettle", 1200, "1.2", False),
            StorePlugin("authz0", "Authz0", "Authz Bypass", "Author", 950, "2.0", True),
            StorePlugin("jsonwebtoken", "JWT Editor", "JWT Token tool", "Author", 800, "1.0", False)
        ])
        tabs.addTab(hot_tab, "🔥 热门")
        
        # 最新
        new_tab = self._create_plugin_list([
            StorePlugin("new-scanner", "New Vuln Scanner", "New Scanner", "Dev", 42, "0.9", False)
        ])
        tabs.addTab(new_tab, "✨ 最新")
        
        # 已安装
        installed_tab = self._create_plugin_list([
            StorePlugin("authz0", "Authz0", "Authz Bypass", "Author", 950, "2.0", True)
        ])
        tabs.addTab(installed_tab, "✅ 已安装")
        
        layout.addWidget(tabs)
        
        return widget
        
    def _create_plugin_list(self, plugins: List[StorePlugin]):
        w = QWidget()
        lay = QVBoxLayout(w)
        
        for p in plugins:
            item = QWidget()
            item_layout = QHBoxLayout(item)
            
            left = QLabel(f"<b>{p.name}</b><br>{p.description}<br>By: {p.author}")
            left.setMinimumWidth(400)
            right = QWidget()
            right_layout = QVBoxLayout(right)
            right_layout.addWidget(QLabel(f"⭐ {p.stars} | {p.version}"))
            btn = QPushButton("✅ Installed" if p.installed else "📥 Install")
            right_layout.addWidget(btn)
            
            item_layout.addWidget(left)
            item_layout.addStretch()
            item_layout.addWidget(right)
            
            lay.addWidget(item)
            
        lay.addStretch()
        return w
