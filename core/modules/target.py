"""
Target (目标)模块 - 专家级测试范围管理系统
包含站点地图(Site map)、目标URL管理、范围划定、资产指纹识别
"""

from typing import Dict, Any, List, Optional, Set
from dataclasses import dataclass, field
from enum import Enum, auto
from datetime import datetime
import logging
import json
import re
from urllib.parse import urlparse, urljoin
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QSplitter, QTabWidget,
    QPushButton, QLabel, QLineEdit, QTextEdit, QTreeWidget,
    QTreeWidgetItem, QHeaderView, QGroupBox, QFormLayout,
    QCheckBox, QComboBox, QFileDialog, QMenu, QTableWidget,
    QTableWidgetItem, QSplitterHandle, QMessageBox, QInputDialog
)
from PySide6.QtCore import Qt, Signal, QTimer
from PySide6.QtGui import QAction, QFont, QIcon, QColor

from .base import ModuleBase

logger = logging.getLogger(__name__)


class SiteMapNodeType(Enum):
    """站点地图节点类型"""
    ROOT = auto()
    DOMAIN = auto()
    DIRECTORY = auto()
    FILE = auto()
    PARAMETER = auto()
    API_ENDPOINT = auto()


@dataclass
class SiteMapNode:
    """站点地图节点"""
    id: str
    name: str
    url: str
    type: SiteMapNodeType
    status_code: int = 0
    method: str = "GET"
    children: List['SiteMapNode'] = field(default_factory=list)
    parent: Optional['SiteMapNode'] = None
    discovered: datetime = field(default_factory=datetime.now)
    content_type: str = ""
    size: int = 0
    response_time: float = 0.0
    server: str = ""
    technologies: List[str] = field(default_factory=list)
    parameters: List[str] = field(default_factory=list)
    forms: List[Dict] = field(default_factory=list)
    notes: str = ""


@dataclass
class TargetInfo:
    """目标信息"""
    url: str
    ip: str = ""
    status: str = "待检测"
    discovered: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)
    technologies: List[str] = field(default_factory=list)
    ports: List[int] = field(default_factory=list)
    subdomains: List[str] = field(default_factory=list)
    notes: str = ""
    risk_level: str = "未知"


@dataclass
class TargetScope:
    """目标范围"""
    include: Set[str] = field(default_factory=set)
    exclude: Set[str] = field(default_factory=set)
    wildcard_include: bool = False
    follow_redirects: bool = True
    max_depth: int = 5
    
    def is_in_scope(self, url: str) -> bool:
        """判断URL是否在范围内"""
        parsed = urlparse(url)
        domain = parsed.netloc
        
        for excl in self.exclude:
            if excl in domain or excl in url:
                return False
                
        if not self.include:
            return True
            
        for incl in self.include:
            if incl in domain or incl in url:
                return True
                
        return False


class TargetModule(ModuleBase):
    """专家级目标管理模块"""
    
    def __init__(self):
        super().__init__("Target", "专家级目标范围管理与站点地图")
        self._scope = TargetScope()
        self._site_map_root: Optional[SiteMapNode] = None
        self._targets: List[TargetInfo] = []
        self._request_history: List[Dict] = []
        self._auto_refresh_timer = QTimer()
        self._auto_refresh_timer.timeout.connect(self._auto_refresh)
        
    def _create_ui(self) -> QWidget:
        """创建UI"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        splitter = QSplitter(Qt.Horizontal)
        
        # 左侧面板
        left_panel = self._create_left_panel()
        splitter.addWidget(left_panel)
        
        # 右侧面板
        right_panel = self._create_right_panel()
        splitter.addWidget(right_panel)
        
        splitter.setSizes([500, 700])
        layout.addWidget(splitter)
        
        return widget
        
    def _create_left_panel(self) -> QWidget:
        """创建左侧面板 - Site Map和Scope"""
        w = QWidget()
        layout = QVBoxLayout(w)
        
        tabs = QTabWidget()
        
        # Site Map标签
        sitemap_tab = self._create_sitemap_tab()
        tabs.addTab(sitemap_tab, "🗺️ 站点地图")
        
        # Scope标签
        scope_tab = self._create_scope_tab()
        tabs.addTab(scope_tab, "🎯 范围设置")
        
        layout.addWidget(tabs)
        return w
        
    def _create_sitemap_tab(self) -> QWidget:
        """创建站点地图标签"""
        w = QWidget()
        layout = QVBoxLayout(w)
        
        # 工具栏
        toolbar = QHBoxLayout()
        
        add_url_btn = QPushButton("➕ 添加URL")
        add_url_btn.clicked.connect(self._add_url_to_sitemap)
        toolbar.addWidget(add_url_btn)
        
        refresh_btn = QPushButton("🔄 刷新")
        refresh_btn.clicked.connect(self._refresh_sitemap)
        toolbar.addWidget(refresh_btn)
        
        filter_combo = QComboBox()
        filter_combo.addItems(["全部", "仅文件", "仅目录", "仅API", "仅表单"])
        filter_combo.currentTextChanged.connect(self._filter_sitemap)
        toolbar.addWidget(filter_combo)
        
        clear_btn = QPushButton("🗑️ 清空")
        clear_btn.clicked.connect(self._clear_sitemap)
        toolbar.addWidget(clear_btn)
        
        export_btn = QPushButton("📤 导出")
        export_btn.clicked.connect(self._export_sitemap)
        toolbar.addWidget(export_btn)
        
        toolbar.addStretch()
        layout.addLayout(toolbar)
        
        # Site Map树
        self.site_map_tree = QTreeWidget()
        self.site_map_tree.setHeaderLabels(["名称", "状态", "类型", "响应时间", "技术栈"])
        self.site_map_tree.setContextMenuPolicy(Qt.CustomContextMenu)
        self.site_map_tree.customContextMenuRequested.connect(self._show_sitemap_context_menu)
        self.site_map_tree.itemClicked.connect(self._on_sitemap_item_clicked)
        self.site_map_tree.setColumnWidth(0, 200)
        self.site_map_tree.setColumnWidth(1, 60)
        self.site_map_tree.setColumnWidth(2, 80)
        self.site_map_tree.setColumnWidth(3, 80)
        layout.addWidget(self.site_map_tree)
        
        # 统计信息
        self.sitemap_stats = QLabel("节点: 0 | 文件: 0 | 目录: 0 | API: 0")
        self.sitemap_stats.setStyleSheet("padding: 5px; background: #2a2a2a; border-radius: 3px;")
        layout.addWidget(self.sitemap_stats)
        
        return w
        
    def _create_scope_tab(self) -> QWidget:
        """创建范围设置标签"""
        w = QWidget()
        layout = QVBoxLayout(w)
        
        # 高级设置
        advanced_group = QGroupBox("高级设置")
        advanced_layout = QFormLayout(advanced_group)
        
        self.max_depth_spin = QComboBox()
        self.max_depth_spin.addItems(["1", "2", "3", "5", "10"])
        self.max_depth_spin.setCurrentText("5")
        advanced_layout.addRow("最大爬取深度:", self.max_depth_spin)
        
        self.follow_redirects_check = QCheckBox("跟随重定向")
        self.follow_redirects_check.setChecked(True)
        advanced_layout.addRow(self.follow_redirects_check)
        
        self.wildcard_include_check = QCheckBox("通配符匹配")
        advanced_layout.addRow(self.wildcard_include_check)
        
        layout.addWidget(advanced_group)
        
        # 包含范围
        include_group = QGroupBox("包含范围 (Include)")
        include_layout = QVBoxLayout(include_group)
        
        include_input_layout = QHBoxLayout()
        self.include_input = QLineEdit()
        self.include_input.setPlaceholderText("输入域名或URL模式，如: *.example.com")
        include_input_layout.addWidget(self.include_input)
        
        add_include_btn = QPushButton("➕ 添加")
        add_include_btn.clicked.connect(self._add_to_include)
        include_input_layout.addWidget(add_include_btn)
        
        include_layout.addLayout(include_input_layout)
        
        self.include_list = QTextEdit()
        self.include_list.setReadOnly(True)
        include_layout.addWidget(self.include_list)
        
        layout.addWidget(include_group)
        
        # 排除范围
        exclude_group = QGroupBox("排除范围 (Exclude)")
        exclude_layout = QVBoxLayout(exclude_group)
        
        exclude_input_layout = QHBoxLayout()
        self.exclude_input = QLineEdit()
        self.exclude_input.setPlaceholderText("输入要排除的模式，如: admin, logout, *.js")
        exclude_input_layout.addWidget(self.exclude_input)
        
        add_exclude_btn = QPushButton("➕ 添加")
        add_exclude_btn.clicked.connect(self._add_to_exclude)
        exclude_input_layout.addWidget(add_exclude_btn)
        
        exclude_layout.addLayout(exclude_input_layout)
        
        self.exclude_list = QTextEdit()
        self.exclude_list.setReadOnly(True)
        exclude_layout.addWidget(self.exclude_list)
        
        layout.addWidget(exclude_group)
        
        return w
        
    def _create_right_panel(self) -> QWidget:
        """创建右侧面板 - 目标详情和请求历史"""
        w = QWidget()
        layout = QVBoxLayout(w)
        
        tabs = QTabWidget()
        
        # 目标信息
        info_tab = self._create_info_tab()
        tabs.addTab(info_tab, "📋 目标信息")
        
        # 请求历史
        history_tab = self._create_history_tab()
        tabs.addTab(history_tab, "📜 请求历史")
        
        # 资产指纹
        fingerprint_tab = self._create_fingerprint_tab()
        tabs.addTab(fingerprint_tab, "🔍 资产指纹")
        
        layout.addWidget(tabs)
        return w
        
    def _create_info_tab(self) -> QWidget:
        """创建信息标签"""
        w = QWidget()
        layout = QVBoxLayout(w)
        
        # 目标URL添加
        url_group = QGroupBox("添加目标")
        url_layout = QHBoxLayout(url_group)
        
        self.target_url_input = QLineEdit()
        self.target_url_input.setPlaceholderText("http://target.com 或 https://api.target.com/v1")
        url_layout.addWidget(self.target_url_input)
        
        add_target_btn = QPushButton("🎯 添加目标")
        add_target_btn.clicked.connect(self._add_target)
        url_layout.addWidget(add_target_btn)
        
        batch_btn = QPushButton("📋 批量添加")
        batch_btn.clicked.connect(self._batch_add_targets)
        url_layout.addWidget(batch_btn)
        
        layout.addWidget(url_group)
        
        # 目标列表
        self.target_table = QTableWidget()
        self.target_table.setColumnCount(7)
        self.target_table.setHorizontalHeaderLabels(["URL", "IP", "状态", "技术栈", "端口", "风险等级", "备注"])
        self.target_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.target_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.target_table.itemClicked.connect(self._on_target_selected)
        layout.addWidget(self.target_table)
        
        # 统计信息
        self.stats_label = QLabel("统计: 0 个目标, 0 个页面, 0 个API端点")
        self.stats_label.setStyleSheet("padding: 10px; font-weight: bold; background: #2a2a2a; border-radius: 3px;")
        layout.addWidget(self.stats_label)
        
        return w
        
    def _create_history_tab(self) -> QWidget:
        """创建历史标签"""
        w = QWidget()
        layout = QVBoxLayout(w)
        
        # 过滤工具栏
        filter_layout = QHBoxLayout()
        
        self.history_filter = QLineEdit()
        self.history_filter.setPlaceholderText("🔍 过滤请求历史...")
        self.history_filter.textChanged.connect(self._filter_history)
        filter_layout.addWidget(self.history_filter)
        
        clear_history_btn = QPushButton("🗑️ 清空")
        clear_history_btn.clicked.connect(self._clear_history)
        filter_layout.addWidget(clear_history_btn)
        
        layout.addLayout(filter_layout)
        
        self.history_text = QTextEdit()
        self.history_text.setReadOnly(True)
        self.history_text.setFont(QFont("Consolas", 9))
        self.history_text.setPlaceholderText("目标的请求历史将显示在这里...")
        layout.addWidget(self.history_text)
        
        return w
        
    def _create_fingerprint_tab(self) -> QWidget:
        """创建资产指纹标签"""
        w = QWidget()
        layout = QVBoxLayout(w)
        
        self.fingerprint_text = QTextEdit()
        self.fingerprint_text.setReadOnly(True)
        self.fingerprint_text.setFont(QFont("Consolas", 9))
        self.fingerprint_text.setPlaceholderText("资产指纹识别结果将显示在这里...\n\n支持识别: Web服务器、框架、CMS、JS库、WAF等")
        layout.addWidget(self.fingerprint_text)
        
        return w
        
    def _add_url_to_sitemap(self):
        """添加URL到站点地图"""
        url = self.target_url_input.text().strip()
        if url:
            self._add_url_to_tree(url)
            self.log("INFO", f"添加URL到站点地图: {url}")
            self.target_url_input.clear()
            
    def _add_url_to_tree(self, url: str):
        """实际添加URL到树"""
        parsed = urlparse(url)
        
        if self._site_map_root is None:
            self._site_map_root = SiteMapNode(
                id="root", name="Targets", url="",
                type=SiteMapNodeType.ROOT
            )
            
        # 查找或创建域名节点
        domain_node = self._find_or_create_child(
            self._site_map_root,
            parsed.netloc,
            SiteMapNodeType.DOMAIN,
            url
        )
        
        # 处理路径
        path_parts = parsed.path.strip("/").split("/")
        current = domain_node
        
        for i, part in enumerate(path_parts):
            if not part:
                continue
                
            # 判断是否为API端点
            if any(keyword in parsed.path.lower() for keyword in ['api', 'v1', 'v2', 'graphql']):
                node_type = SiteMapNodeType.API_ENDPOINT
            elif i == len(path_parts) - 1 and "." in part:
                node_type = SiteMapNodeType.FILE
            else:
                node_type = SiteMapNodeType.DIRECTORY
                
            current = self._find_or_create_child(
                current,
                part,
                node_type,
                urljoin(url, "/".join(path_parts[:i+1]))
            )
            
            # 添加参数
            if parsed.query:
                params = parsed.query.split("&")
                for param in params:
                    if "=" in param:
                        param_name = param.split("=")[0]
                        if param_name not in current.parameters:
                            current.parameters.append(param_name)
            
        self._refresh_tree_view()
        self._update_sitemap_stats()
        
    def _find_or_create_child(self, parent: SiteMapNode, name: str, 
                            node_type: SiteMapNodeType, url: str) -> SiteMapNode:
        """查找或创建子节点"""
        for child in parent.children:
            if child.name == name:
                return child
                
        new_node = SiteMapNode(
            id=f"{parent.id}_{name}",
            name=name,
            url=url,
            type=node_type,
            parent=parent
        )
        parent.children.append(new_node)
        return new_node
        
    def _refresh_tree_view(self):
        """刷新树视图"""
        self.site_map_tree.clear()
        
        if self._site_map_root:
            for domain in self._site_map_root.children:
                item = QTreeWidgetItem(self.site_map_tree)
                self._populate_tree_item(item, domain)
                
    def _populate_tree_item(self, qitem: QTreeWidgetItem, node: SiteMapNode):
        """填充树节点"""
        qitem.setText(0, node.name)
        qitem.setText(1, str(node.status_code) if node.status_code else "-")
        qitem.setText(2, node.type.name)
        qitem.setText(3, f"{node.response_time:.2f}s" if node.response_time > 0 else "-")
        qitem.setText(4, ", ".join(node.technologies[:3]) if node.technologies else "-")
        qitem.setData(0, Qt.UserRole, node)
        
        for child in node.children:
            child_item = QTreeWidgetItem(qitem)
            self._populate_tree_item(child_item, child)
            
    def _clear_sitemap(self):
        """清空站点地图"""
        self._site_map_root = None
        self.site_map_tree.clear()
        self._update_sitemap_stats()
        self.log("INFO", "站点地图已清空")
        
    def _refresh_sitemap(self):
        """刷新站点地图"""
        self._refresh_tree_view()
        self._update_sitemap_stats()
        self.log("INFO", "站点地图已刷新")
        
    def _filter_sitemap(self, filter_text: str):
        """过滤站点地图"""
        self._refresh_tree_view()
        
    def _update_sitemap_stats(self):
        """更新站点地图统计"""
        if not self._site_map_root:
            self.sitemap_stats.setText("节点: 0 | 文件: 0 | 目录: 0 | API: 0")
            return
            
        nodes = 0
        files = 0
        dirs = 0
        apis = 0
        
        def count_nodes(node):
            nonlocal nodes, files, dirs, apis
            nodes += 1
            if node.type == SiteMapNodeType.FILE:
                files += 1
            elif node.type == SiteMapNodeType.DIRECTORY:
                dirs += 1
            elif node.type == SiteMapNodeType.API_ENDPOINT:
                apis += 1
            for child in node.children:
                count_nodes(child)
                
        for domain in self._site_map_root.children:
            count_nodes(domain)
            
        self.sitemap_stats.setText(f"节点: {nodes} | 文件: {files} | 目录: {dirs} | API: {apis}")
        
    def _export_sitemap(self):
        """导出站点地图"""
        filename, _ = QFileDialog.getSaveFileName(None, "导出站点地图", "", "JSON Files (*.json);;Text Files (*.txt)")
        if filename:
            if filename.endswith('.json'):
                self._export_sitemap_json(filename)
            else:
                self._export_sitemap_text(filename)
            self.log("INFO", f"站点地图已导出到 {filename}")
            
    def _export_sitemap_json(self, filename: str):
        """导出为JSON格式"""
        def node_to_dict(node):
            return {
                "name": node.name,
                "url": node.url,
                "type": node.type.name,
                "status_code": node.status_code,
                "method": node.method,
                "content_type": node.content_type,
                "size": node.size,
                "response_time": node.response_time,
                "server": node.server,
                "technologies": node.technologies,
                "parameters": node.parameters,
                "children": [node_to_dict(c) for c in node.children]
            }
            
        data = {
            "export_time": datetime.now().isoformat(),
            "targets": [node_to_dict(d) for d in self._site_map_root.children] if self._site_map_root else []
        }
        
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
            
    def _export_sitemap_text(self, filename: str):
        """导出为文本格式"""
        with open(filename, "w", encoding="utf-8") as f:
            f.write("站点地图导出\n")
            f.write("="*80 + "\n")
            f.write(f"导出时间: {datetime.now()}\n")
            f.write("="*80 + "\n\n")
            
            if self._site_map_root:
                for domain in self._site_map_root.children:
                    self._write_node_tree(f, domain, 0)
                    
    def _write_node_tree(self, f, node, indent):
        """递归写入节点树"""
        prefix = "  " * indent
        f.write(f"{prefix}{node.name} ({node.type.name})\n")
        if node.url:
            f.write(f"{prefix}  URL: {node.url}\n")
        if node.status_code:
            f.write(f"{prefix}  状态: {node.status_code}\n")
        if node.technologies:
            f.write(f"{prefix}  技术栈: {', '.join(node.technologies)}\n")
        f.write("\n")
        for child in node.children:
            self._write_node_tree(f, child, indent + 1)
            
    def _show_sitemap_context_menu(self, pos):
        """显示右键菜单"""
        item = self.site_map_tree.itemAt(pos)
        if item:
            menu = QMenu()
            send_to_repeater = QAction("📤 发送到Repeater", menu)
            send_to_intruder = QAction("⚔️ 发送到Intruder", menu)
            add_to_scope = QAction("🎯 添加到范围", menu)
            copy_url = QAction("📋 复制URL", menu)
            view_details = QAction("🔍 查看详情", menu)
            
            menu.addActions([send_to_repeater, send_to_intruder, add_to_scope, copy_url, view_details])
            menu.exec_(self.site_map_tree.mapToGlobal(pos))
            
    def _on_sitemap_item_clicked(self, item, column):
        """点击树节点"""
        node = item.data(0, Qt.UserRole)
        if node:
            details = f"""
节点详情
========
名称: {node.name}
URL: {node.url}
类型: {node.type.name}
状态码: {node.status_code}
方法: {node.method}
内容类型: {node.content_type}
大小: {node.size} bytes
响应时间: {node.response_time:.2f}s
服务器: {node.server}
技术栈: {', '.join(node.technologies)}
参数: {', '.join(node.parameters)}
发现时间: {node.discovered}
备注: {node.notes}
            """
            self.history_text.setText(details)
            
    def _add_to_include(self):
        """添加到包含范围"""
        text = self.include_input.text().strip()
        if text:
            self._scope.include.add(text)
            self._update_scope_lists()
            self.include_input.clear()
            self.log("INFO", f"添加到包含范围: {text}")
            
    def _add_to_exclude(self):
        """添加到排除范围"""
        text = self.exclude_input.text().strip()
        if text:
            self._scope.exclude.add(text)
            self._update_scope_lists()
            self.exclude_input.clear()
            self.log("INFO", f"添加到排除范围: {text}")
            
    def _update_scope_lists(self):
        """更新范围列表显示"""
        self.include_list.setText("\n".join(self._scope.include))
        self.exclude_list.setText("\n".join(self._scope.exclude))
        
    def _add_target(self):
        """添加目标"""
        url = self.target_url_input.text().strip()
        if url:
            target = TargetInfo(
                url=url,
                ip="",
                status="待检测",
                technologies=[],
                ports=[],
                subdomains=[],
                risk_level="未知"
            )
            
            self._targets.append(target)
            
            row = self.target_table.rowCount()
            self.target_table.insertRow(row)
            self.target_table.setItem(row, 0, QTableWidgetItem(url))
            self.target_table.setItem(row, 1, QTableWidgetItem(target.ip))
            self.target_table.setItem(row, 2, QTableWidgetItem(target.status))
            self.target_table.setItem(row, 3, QTableWidgetItem(", ".join(target.technologies)))
            self.target_table.setItem(row, 4, QTableWidgetItem(", ".join(map(str, target.ports))))
            self.target_table.setItem(row, 5, QTableWidgetItem(target.risk_level))
            self.target_table.setItem(row, 6, QTableWidgetItem(target.notes))
            
            self._add_url_to_tree(url)
            self._update_stats()
            self.log("INFO", f"添加目标: {url}")
            self.target_url_input.clear()
            
    def _batch_add_targets(self):
        """批量添加目标"""
        text, ok = QInputDialog.getMultiLineText(None, "批量添加目标", "输入目标URL（每行一个）:")
        if ok and text:
            urls = [url.strip() for url in text.split("\n") if url.strip()]
            for url in urls:
                self._add_single_target(url)
            self.log("INFO", f"批量添加 {len(urls)} 个目标")
            
    def _add_single_target(self, url: str):
        """添加单个目标"""
        target = TargetInfo(url=url)
        self._targets.append(target)
        
        row = self.target_table.rowCount()
        self.target_table.insertRow(row)
        self.target_table.setItem(row, 0, QTableWidgetItem(url))
        self.target_table.setItem(row, 1, QTableWidgetItem(""))
        self.target_table.setItem(row, 2, QTableWidgetItem("待检测"))
        self.target_table.setItem(row, 3, QTableWidgetItem(""))
        self.target_table.setItem(row, 4, QTableWidgetItem(""))
        self.target_table.setItem(row, 5, QTableWidgetItem("未知"))
        self.target_table.setItem(row, 6, QTableWidgetItem(""))
        
        self._add_url_to_tree(url)
        self._update_stats()
        
    def _on_target_selected(self, item):
        """目标选中回调"""
        row = item.row()
        if row < len(self._targets):
            target = self._targets[row]
            self.history_text.setText(f"""
目标详情
========
URL: {target.url}
IP: {target.ip}
状态: {target.status}
技术栈: {', '.join(target.technologies)}
端口: {', '.join(map(str, target.ports))}
子域名: {', '.join(target.subdomains)}
风险等级: {target.risk_level}
备注: {target.notes}
发现时间: {target.discovered}
最后访问: {target.last_seen}
            """)
            
    def _update_stats(self):
        """更新统计"""
        page_count = 0
        api_count = 0
        
        def count_nodes(node):
            nonlocal page_count, api_count
            if node.type == SiteMapNodeType.FILE:
                page_count += 1
            elif node.type == SiteMapNodeType.API_ENDPOINT:
                api_count += 1
            for child in node.children:
                count_nodes(child)
                
        if self._site_map_root:
            for domain in self._site_map_root.children:
                count_nodes(domain)
                
        self.stats_label.setText(f"统计: {len(self._targets)} 个目标, {page_count} 个页面, {api_count} 个API端点")
        
    def _filter_history(self, text: str):
        """过滤请求历史"""
        pass
        
    def _clear_history(self):
        """清空请求历史"""
        self._request_history.clear()
        self.history_text.clear()
        self.log("INFO", "请求历史已清空")
        
    def _auto_refresh(self):
        """自动刷新"""
        self._refresh_tree_view()
        self._update_stats()
