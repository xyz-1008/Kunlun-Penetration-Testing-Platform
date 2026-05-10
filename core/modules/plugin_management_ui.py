"""
插件管理UI模块
"""

import os
import sys
import json
import logging
from pathlib import Path
from typing import Dict, List, Optional, Any

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QSplitter,
    QTabWidget, QTreeWidget, QTreeWidgetItem,
    QPushButton, QLabel, QLineEdit, QTextEdit,
    QComboBox, QGroupBox, QFormLayout,
    QMessageBox, QFileDialog, QProgressBar,
    QHeaderView, QScrollArea, QFrame,
    QListWidget, QListWidgetItem, QGridLayout,
    QTableWidget, QTableWidgetItem, QTextBrowser,
    QCheckBox, QSpinBox, QDoubleSpinBox
)
from PySide6.QtCore import Qt, Signal, QTimer, QSize
from PySide6.QtGui import QFont, QIcon, QColor

from .base import ModuleBase
from .plugin_manager import PluginManager, PluginRegistryEntry
from .plugin_engine import PluginType, PluginStatus, PluginContext
from .plugin_market import PluginMarket, PluginMarketEntry
from .plugin_security import SecurityManager
from .plugin_dependency import DependencyResolver, VersionManager
from .workflow_engine import WorkflowEngine, Workflow, WorkflowNode, WorkflowNodeType

logger = logging.getLogger(__name__)


class PluginManagementModule(ModuleBase):
    """插件管理模块"""
    
    def __init__(self):
        super().__init__("插件管理", "企业级插件管理与市场")
        
        plugin_dirs = [
            str(Path(__file__).parent.parent.parent / "plugins" / "examples"),
            str(Path(__file__).parent.parent.parent / "plugins" / "custom"),
        ]
        
        self.plugin_manager = PluginManager(plugin_dirs)
        self.plugin_manager.initialize()
        
        self.plugin_market = PluginMarket()
        self.security_manager = SecurityManager()
        self.dependency_resolver = DependencyResolver()
        self.version_manager = VersionManager()
        self.workflow_engine = WorkflowEngine(self.plugin_manager.event_bus)
    
    def _create_ui(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        tab_widget = QTabWidget()
        tab_widget.addTab(self._create_plugin_list_tab(), "已加载插件")
        tab_widget.addTab(self._create_market_tab(), "插件市场")
        tab_widget.addTab(self._create_workflow_tab(), "工作流编排")
        tab_widget.addTab(self._create_security_tab(), "安全中心")
        tab_widget.addTab(self._create_dependency_tab(), "依赖管理")
        tab_widget.addTab(self._create_settings_tab(), "设置")
        
        layout.addWidget(tab_widget)
        return widget
    
    def _create_plugin_list_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        actions_layout = QHBoxLayout()
        
        self.load_plugin_btn = QPushButton("加载插件")
        self.load_plugin_btn.clicked.connect(self._load_plugin)
        actions_layout.addWidget(self.load_plugin_btn)
        
        self.reload_all_btn = QPushButton("重新加载全部")
        self.reload_all_btn.clicked.connect(self._reload_all_plugins)
        actions_layout.addWidget(self.reload_all_btn)
        
        self.refresh_btn = QPushButton("刷新")
        self.refresh_btn.clicked.connect(self._refresh_plugins)
        actions_layout.addWidget(self.refresh_btn)
        
        layout.addLayout(actions_layout)
        
        self.plugins_table = QTableWidget()
        self.plugins_table.setColumnCount(8)
        self.plugins_table.setHorizontalHeaderLabels(["名称", "版本", "作者", "类型", "状态", "执行次数", "错误数", "描述"])
        self.plugins_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.plugins_table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.plugins_table)
        
        actions_layout2 = QHBoxLayout()
        
        self.enable_btn = QPushButton("启用")
        self.enable_btn.clicked.connect(self._enable_plugin)
        actions_layout2.addWidget(self.enable_btn)
        
        self.disable_btn = QPushButton("禁用")
        self.disable_btn.clicked.connect(self._disable_plugin)
        actions_layout2.addWidget(self.disable_btn)
        
        self.unload_btn = QPushButton("卸载")
        self.unload_btn.clicked.connect(self._unload_plugin)
        actions_layout2.addWidget(self.unload_btn)
        
        self.execute_btn = QPushButton("执行")
        self.execute_btn.clicked.connect(self._execute_plugin)
        actions_layout2.addWidget(self.execute_btn)
        
        layout.addLayout(actions_layout2)
        
        stats_group = QGroupBox("统计")
        stats_layout = QVBoxLayout(stats_group)
        
        self.stats_output = QTextBrowser()
        self.stats_output.setFont(QFont("Consolas", 9))
        stats_layout.addWidget(self.stats_output)
        
        layout.addWidget(stats_group)
        
        self._refresh_plugins()
        
        return widget
    
    def _create_market_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        search_layout = QHBoxLayout()
        
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("搜索插件...")
        search_layout.addWidget(self.search_input)
        
        self.search_btn = QPushButton("搜索")
        self.search_btn.clicked.connect(self._search_market)
        search_layout.addWidget(self.search_btn)
        
        self.refresh_market_btn = QPushButton("刷新市场")
        self.refresh_market_btn.clicked.connect(self._refresh_market)
        search_layout.addWidget(self.refresh_market_btn)
        
        layout.addLayout(search_layout)
        
        self.market_table = QTableWidget()
        self.market_table.setColumnCount(7)
        self.market_table.setHorizontalHeaderLabels(["名称", "版本", "作者", "类型", "评分", "下载量", "价格"])
        self.market_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.market_table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.market_table)
        
        actions_layout = QHBoxLayout()
        
        self.install_btn = QPushButton("安装")
        self.install_btn.clicked.connect(self._install_plugin)
        actions_layout.addWidget(self.install_btn)
        
        self.update_btn = QPushButton("更新")
        self.update_btn.clicked.connect(self._update_plugin)
        actions_layout.addWidget(self.update_btn)
        
        self.uninstall_btn = QPushButton("卸载")
        self.uninstall_btn.clicked.connect(self._uninstall_plugin)
        actions_layout.addWidget(self.uninstall_btn)
        
        layout.addLayout(actions_layout)
        
        return widget
    
    def _create_workflow_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        workflow_layout = QHBoxLayout()
        
        self.workflow_combo = QComboBox()
        workflow_layout.addWidget(QLabel("工作流:"))
        workflow_layout.addWidget(self.workflow_combo)
        
        self.create_workflow_btn = QPushButton("创建工作流")
        self.create_workflow_btn.clicked.connect(self._create_workflow)
        workflow_layout.addWidget(self.create_workflow_btn)
        
        self.execute_workflow_btn = QPushButton("执行工作流")
        self.execute_workflow_btn.clicked.connect(self._execute_workflow)
        workflow_layout.addWidget(self.execute_workflow_btn)
        
        layout.addLayout(workflow_layout)
        
        self.workflow_nodes_table = QTableWidget()
        self.workflow_nodes_table.setColumnCount(5)
        self.workflow_nodes_table.setHorizontalHeaderLabels(["节点ID", "名称", "类型", "插件", "状态"])
        self.workflow_nodes_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.workflow_nodes_table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.workflow_nodes_table)
        
        add_node_layout = QHBoxLayout()
        
        self.add_node_btn = QPushButton("添加节点")
        self.add_node_btn.clicked.connect(self._add_workflow_node)
        add_node_layout.addWidget(self.add_node_btn)
        
        self.remove_node_btn = QPushButton("删除节点")
        self.remove_node_btn.clicked.connect(self._remove_workflow_node)
        add_node_layout.addWidget(self.remove_node_btn)
        
        layout.addLayout(add_node_layout)
        
        self.workflow_output = QTextBrowser()
        self.workflow_output.setFont(QFont("Consolas", 9))
        layout.addWidget(self.workflow_output)
        
        return widget
    
    def _create_security_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        security_layout = QHBoxLayout()
        
        self.refresh_security_btn = QPushButton("刷新安全状态")
        self.refresh_security_btn.clicked.connect(self._refresh_security)
        security_layout.addWidget(self.refresh_security_btn)
        
        self.clear_alerts_btn = QPushButton("清除告警")
        self.clear_alerts_btn.clicked.connect(self._clear_security_alerts)
        security_layout.addWidget(self.clear_alerts_btn)
        
        layout.addLayout(security_layout)
        
        self.alerts_table = QTableWidget()
        self.alerts_table.setColumnCount(5)
        self.alerts_table.setHorizontalHeaderLabels(["时间", "插件", "类型", "威胁级别", "描述"])
        self.alerts_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.alerts_table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.alerts_table)
        
        self.security_stats = QTextBrowser()
        self.security_stats.setFont(QFont("Consolas", 9))
        layout.addWidget(self.security_stats)
        
        return widget
    
    def _create_dependency_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        dep_layout = QHBoxLayout()
        
        self.check_deps_btn = QPushButton("检查依赖")
        self.check_deps_btn.clicked.connect(self._check_dependencies)
        dep_layout.addWidget(self.check_deps_btn)
        
        self.resolve_deps_btn = QPushButton("解析依赖")
        self.resolve_deps_btn.clicked.connect(self._resolve_dependencies)
        dep_layout.addWidget(self.resolve_deps_btn)
        
        layout.addLayout(dep_layout)
        
        self.deps_table = QTableWidget()
        self.deps_table.setColumnCount(4)
        self.deps_table.setHorizontalHeaderLabels(["插件", "依赖", "版本范围", "状态"])
        self.deps_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.deps_table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.deps_table)
        
        self.deps_output = QTextBrowser()
        self.deps_output.setFont(QFont("Consolas", 9))
        layout.addWidget(self.deps_output)
        
        return widget
    
    def _create_settings_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        config_group = QGroupBox("插件配置")
        config_layout = QFormLayout(config_group)
        
        self.max_concurrent_spin = QSpinBox()
        self.max_concurrent_spin.setRange(1, 20)
        self.max_concurrent_spin.setValue(5)
        config_layout.addRow("最大并发数:", self.max_concurrent_spin)
        
        self.plugin_dir_input = QLineEdit()
        self.plugin_dir_input.setPlaceholderText("插件目录")
        config_layout.addRow("插件目录:", self.plugin_dir_input)
        
        self.market_url_input = QLineEdit("https://market.example.com/api")
        config_layout.addRow("市场URL:", self.market_url_input)
        
        layout.addWidget(config_group)
        
        save_btn = QPushButton("保存配置")
        save_btn.clicked.connect(self._save_settings)
        layout.addWidget(save_btn)
        
        layout.addStretch()
        
        return widget
    
    def _refresh_plugins(self):
        """刷新插件列表"""
        plugins = self.plugin_manager.get_all_plugins()
        
        self.plugins_table.setRowCount(0)
        for plugin_id, entry in plugins.items():
            row = self.plugins_table.rowCount()
            self.plugins_table.insertRow(row)
            
            manifest = entry.manifest
            self.plugins_table.setItem(row, 0, QTableWidgetItem(plugin_id))
            self.plugins_table.setItem(row, 1, QTableWidgetItem(manifest.version if manifest else ""))
            self.plugins_table.setItem(row, 2, QTableWidgetItem(manifest.author if manifest else ""))
            self.plugins_table.setItem(row, 3, QTableWidgetItem(manifest.plugin_type.value if manifest else ""))
            self.plugins_table.setItem(row, 4, QTableWidgetItem(entry.status.value))
            self.plugins_table.setItem(row, 5, QTableWidgetItem(str(entry.execution_count)))
            self.plugins_table.setItem(row, 6, QTableWidgetItem(str(entry.error_count)))
            self.plugins_table.setItem(row, 7, QTableWidgetItem(manifest.description if manifest else ""))
        
        stats = self.plugin_manager.get_statistics()
        self.stats_output.setPlainText(json.dumps(stats, indent=2, ensure_ascii=False))
    
    def _load_plugin(self):
        """加载插件"""
        file_path, _ = QFileDialog.getOpenFileName(
            self.get_widget(), "选择插件", "", "Python Files (*.py)"
        )
        
        if file_path:
            success = self.plugin_manager.load_plugin(file_path)
            if success:
                QMessageBox.information(self.get_widget(), "成功", "插件加载成功")
                self._refresh_plugins()
            else:
                QMessageBox.warning(self.get_widget(), "错误", "插件加载失败")
    
    def _reload_all_plugins(self):
        """重新加载所有插件"""
        self.plugin_manager.load_all_plugins()
        self._refresh_plugins()
        QMessageBox.information(self.get_widget(), "成功", "所有插件已重新加载")
    
    def _enable_plugin(self):
        """启用插件"""
        selected = self.plugins_table.selectedItems()
        if not selected:
            QMessageBox.warning(self.get_widget(), "警告", "请先选择插件")
            return
        
        plugin_id = selected[0].text()
        success = self.plugin_manager.enable_plugin(plugin_id)
        
        if success:
            QMessageBox.information(self.get_widget(), "成功", f"插件 {plugin_id} 已启用")
            self._refresh_plugins()
    
    def _disable_plugin(self):
        """禁用插件"""
        selected = self.plugins_table.selectedItems()
        if not selected:
            QMessageBox.warning(self.get_widget(), "警告", "请先选择插件")
            return
        
        plugin_id = selected[0].text()
        success = self.plugin_manager.disable_plugin(plugin_id)
        
        if success:
            QMessageBox.information(self.get_widget(), "成功", f"插件 {plugin_id} 已禁用")
            self._refresh_plugins()
    
    def _unload_plugin(self):
        """卸载插件"""
        selected = self.plugins_table.selectedItems()
        if not selected:
            QMessageBox.warning(self.get_widget(), "警告", "请先选择插件")
            return
        
        plugin_id = selected[0].text()
        success = self.plugin_manager.unload_plugin(plugin_id)
        
        if success:
            QMessageBox.information(self.get_widget(), "成功", f"插件 {plugin_id} 已卸载")
            self._refresh_plugins()
    
    def _execute_plugin(self):
        """执行插件"""
        selected = self.plugins_table.selectedItems()
        if not selected:
            QMessageBox.warning(self.get_widget(), "警告", "请先选择插件")
            return
        
        plugin_id = selected[0].text()
        
        context = PluginContext(
            task_id="manual_execution",
            target="http://example.com"
        )
        
        result = self.plugin_manager.execute_plugin(plugin_id, context)
        
        if result.success:
            QMessageBox.information(self.get_widget(), "成功", f"插件执行成功: {result.data}")
        else:
            QMessageBox.warning(self.get_widget(), "错误", f"插件执行失败: {result.error}")
    
    def _search_market(self):
        """搜索市场"""
        query = self.search_input.text()
        plugins = self.plugin_market.search_plugins(query)
        
        self.market_table.setRowCount(0)
        for plugin in plugins:
            row = self.market_table.rowCount()
            self.market_table.insertRow(row)
            self.market_table.setItem(row, 0, QTableWidgetItem(plugin.name))
            self.market_table.setItem(row, 1, QTableWidgetItem(plugin.version))
            self.market_table.setItem(row, 2, QTableWidgetItem(plugin.author))
            self.market_table.setItem(row, 3, QTableWidgetItem(plugin.plugin_type))
            self.market_table.setItem(row, 4, QTableWidgetItem(str(plugin.rating)))
            self.market_table.setItem(row, 5, QTableWidgetItem(str(plugin.downloads)))
            self.market_table.setItem(row, 6, QTableWidgetItem(f"¥{plugin.price}" if plugin.is_paid else "免费"))
    
    def _refresh_market(self):
        """刷新市场"""
        plugins = self.plugin_market.fetch_plugins()
        
        self.market_table.setRowCount(0)
        for plugin in plugins:
            row = self.market_table.rowCount()
            self.market_table.insertRow(row)
            self.market_table.setItem(row, 0, QTableWidgetItem(plugin.name))
            self.market_table.setItem(row, 1, QTableWidgetItem(plugin.version))
            self.market_table.setItem(row, 2, QTableWidgetItem(plugin.author))
            self.market_table.setItem(row, 3, QTableWidgetItem(plugin.plugin_type))
            self.market_table.setItem(row, 4, QTableWidgetItem(str(plugin.rating)))
            self.market_table.setItem(row, 5, QTableWidgetItem(str(plugin.downloads)))
            self.market_table.setItem(row, 6, QTableWidgetItem(f"¥{plugin.price}" if plugin.is_paid else "免费"))
    
    def _install_plugin(self):
        """安装插件"""
        selected = self.market_table.selectedItems()
        if not selected:
            QMessageBox.warning(self.get_widget(), "警告", "请先选择插件")
            return
        
        plugin_name = selected[0].text()
        save_dir = str(Path(__file__).parent.parent.parent / "plugins" / "installed")
        
        success = self.plugin_market.download_plugin(plugin_name, save_dir)
        
        if success:
            QMessageBox.information(self.get_widget(), "成功", "插件安装成功")
            self.plugin_manager.load_plugin(f"{save_dir}/{plugin_name}.py")
            self._refresh_plugins()
        else:
            QMessageBox.warning(self.get_widget(), "错误", "插件安装失败")
    
    def _update_plugin(self):
        """更新插件"""
        QMessageBox.information(self.get_widget(), "提示", "插件更新功能开发中")
    
    def _uninstall_plugin(self):
        """卸载插件"""
        selected = self.market_table.selectedItems()
        if not selected:
            QMessageBox.warning(self.get_widget(), "警告", "请先选择插件")
            return
        
        plugin_name = selected[0].text()
        QMessageBox.information(self.get_widget(), "提示", f"插件 {plugin_name} 卸载功能开发中")
    
    def _create_workflow(self):
        """创建工作流"""
        workflow_id = f"workflow_{len(self.workflow_engine.get_all_workflows()) + 1}"
        workflow = self.workflow_engine.create_workflow(workflow_id, f"工作流 {workflow_id}")
        
        self.workflow_combo.addItem(workflow_id)
        QMessageBox.information(self.get_widget(), "成功", f"工作流 {workflow_id} 已创建")
    
    def _execute_workflow(self):
        """执行工作流"""
        current_workflow = self.workflow_combo.currentText()
        if not current_workflow:
            QMessageBox.warning(self.get_widget(), "警告", "请先选择工作流")
            return
        
        context = PluginContext(
            task_id="workflow_execution",
            target="http://example.com"
        )
        
        def execute_plugin_func(plugin_id, ctx):
            return self.plugin_manager.execute_plugin(plugin_id, ctx)
        
        execution = self.workflow_engine.execute_workflow(current_workflow, context, execute_plugin_func)
        
        if execution.status.value == "completed":
            QMessageBox.information(self.get_widget(), "成功", "工作流执行成功")
        else:
            QMessageBox.warning(self.get_widget(), "错误", f"工作流执行失败: {execution.error}")
    
    def _add_workflow_node(self):
        """添加工作流节点"""
        current_workflow = self.workflow_combo.currentText()
        if not current_workflow:
            QMessageBox.warning(self.get_widget(), "警告", "请先选择工作流")
            return
        
        node_id = f"node_{len(self.workflow_engine.get_workflow(current_workflow).nodes) + 1}"
        node = WorkflowNode(
            node_id=node_id,
            name=f"节点 {node_id}",
            node_type=WorkflowNodeType.PLUGIN
        )
        
        self.workflow_engine.add_node(current_workflow, node)
        self._refresh_workflow_nodes(current_workflow)
    
    def _remove_workflow_node(self):
        """删除工作流节点"""
        selected = self.workflow_nodes_table.selectedItems()
        if not selected:
            QMessageBox.warning(self.get_widget(), "警告", "请先选择节点")
            return
        
        QMessageBox.information(self.get_widget(), "提示", "节点删除功能开发中")
    
    def _refresh_workflow_nodes(self, workflow_id: str):
        """刷新工作流节点"""
        workflow = self.workflow_engine.get_workflow(workflow_id)
        if not workflow:
            return
        
        self.workflow_nodes_table.setRowCount(0)
        for node_id, node in workflow.nodes.items():
            row = self.workflow_nodes_table.rowCount()
            self.workflow_nodes_table.insertRow(row)
            self.workflow_nodes_table.setItem(row, 0, QTableWidgetItem(node.node_id))
            self.workflow_nodes_table.setItem(row, 1, QTableWidgetItem(node.name))
            self.workflow_nodes_table.setItem(row, 2, QTableWidgetItem(node.node_type.value))
            self.workflow_nodes_table.setItem(row, 3, QTableWidgetItem(node.plugin_id))
            self.workflow_nodes_table.setItem(row, 4, QTableWidgetItem(node.status.value))
    
    def _refresh_security(self):
        """刷新安全状态"""
        alerts = self.security_manager.behavior_monitor.get_alerts()
        
        self.alerts_table.setRowCount(0)
        for alert in alerts:
            row = self.alerts_table.rowCount()
            self.alerts_table.insertRow(row)
            self.alerts_table.setItem(row, 0, QTableWidgetItem(str(alert.timestamp)))
            self.alerts_table.setItem(row, 1, QTableWidgetItem(alert.plugin_id))
            self.alerts_table.setItem(row, 2, QTableWidgetItem(alert.alert_type))
            self.alerts_table.setItem(row, 3, QTableWidgetItem(alert.threat_level.value))
            self.alerts_table.setItem(row, 4, QTableWidgetItem(alert.description))
        
        stats = self.security_manager.behavior_monitor.get_statistics()
        self.security_stats.setPlainText(json.dumps(stats, indent=2, ensure_ascii=False, default=str))
    
    def _clear_security_alerts(self):
        """清除安全告警"""
        self.security_manager.behavior_monitor.clear_alerts()
        self._refresh_security()
    
    def _check_dependencies(self):
        """检查依赖"""
        plugins = self.plugin_manager.get_all_plugins()
        
        self.deps_table.setRowCount(0)
        for plugin_id, entry in plugins.items():
            if entry.manifest and entry.manifest.dependencies:
                for dep in entry.manifest.dependencies:
                    row = self.deps_table.rowCount()
                    self.deps_table.insertRow(row)
                    self.deps_table.setItem(row, 0, QTableWidgetItem(plugin_id))
                    self.deps_table.setItem(row, 1, QTableWidgetItem(dep))
                    self.deps_table.setItem(row, 2, QTableWidgetItem("latest"))
                    self.deps_table.setItem(row, 3, QTableWidgetItem("未检查"))
    
    def _resolve_dependencies(self):
        """解析依赖"""
        plugins = self.plugin_manager.get_all_plugins()
        
        output = []
        for plugin_id, entry in plugins.items():
            if entry.manifest and entry.manifest.dependencies:
                self.dependency_resolver.add_dependency(
                    plugin_id,
                    [type('DependencyInfo', (), {'name': d, 'version_range': 'latest', 'required': True})() for d in entry.manifest.dependencies]
                )
                
                resolution = self.dependency_resolver.resolve(plugin_id)
                output.append(f"插件 {plugin_id}:")
                output.append(f"  成功: {resolution.success}")
                output.append(f"  已解析: {resolution.resolved}")
                output.append(f"  冲突: {resolution.conflicts}")
                output.append(f"  缺失: {resolution.missing}")
                output.append("")
        
        self.deps_output.setPlainText("\n".join(output))
    
    def _save_settings(self):
        """保存设置"""
        self.plugin_manager.scheduler.set_max_concurrent(self.max_concurrent_spin.value())
        QMessageBox.information(self.get_widget(), "成功", "配置已保存")
