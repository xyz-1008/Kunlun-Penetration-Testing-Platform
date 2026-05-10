"""
PoC验证模块UI
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
from PySide6.QtCore import Qt, Signal, QTimer, QSize, QThread
from PySide6.QtGui import QFont, QIcon, QColor

from .base import ModuleBase
from .poc_verification_manager import PoCVerificationManager, PoCExecutionConfig, AssetFingerprint
from .result_models import PoCVerificationResult, PoCStatus, ConfidenceLevel, SeverityLevel

logger = logging.getLogger(__name__)


class PoCVerificationThread(QThread):
    """PoC验证线程"""
    progress = Signal(int, int)
    result_found = Signal(object)
    finished = Signal()
    error = Signal(str)
    
    def __init__(self, manager: PoCVerificationManager, asset: AssetFingerprint):
        super().__init__()
        self.manager = manager
        self.asset = asset
    
    def run(self):
        try:
            report = self.manager.verify_asset(self.asset)
            for result in report.results:
                self.result_found.emit(result)
            self.finished.emit()
        except Exception as e:
            self.error.emit(str(e))


class PoCVerificationModule(ModuleBase):
    """PoC验证模块"""
    
    def __init__(self):
        super().__init__("PoC验证", "专业级PoC验证框架")
        
        poc_dir = str(Path(__file__).parent.parent.parent / "pocs")
        config = PoCExecutionConfig(
            timeout=30,
            max_memory_mb=256,
            max_concurrent=5,
            enable_oob=True
        )
        
        self.manager = PoCVerificationManager(poc_dir, config)
        self.manager.initialize()
        
        self._verification_thread: Optional[PoCVerificationThread] = None
        self._results: List[PoCVerificationResult] = []
    
    def _create_ui(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        tab_widget = QTabWidget()
        tab_widget.addTab(self._create_verification_tab(), "验证")
        tab_widget.addTab(self._create_poc_manager_tab(), "PoC管理")
        tab_widget.addTab(self._create_results_tab(), "结果")
        tab_widget.addTab(self._create_oob_tab(), "OOB检测")
        tab_widget.addTab(self._create_settings_tab(), "设置")
        
        layout.addWidget(tab_widget)
        return widget
    
    def _create_verification_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        target_group = QGroupBox("目标资产")
        target_layout = QFormLayout(target_group)
        
        self.target_input = QLineEdit("http://example.com")
        target_layout.addRow("目标:", self.target_input)
        
        self.product_input = QLineEdit()
        target_layout.addRow("产品:", self.product_input)
        
        self.version_input = QLineEdit()
        target_layout.addRow("版本:", self.version_input)
        
        self.ports_input = QLineEdit()
        self.ports_input.setPlaceholderText("80,443,8080")
        target_layout.addRow("端口:", self.ports_input)
        
        layout.addWidget(target_group)
        
        actions_group = QGroupBox("操作")
        actions_layout = QHBoxLayout(actions_group)
        
        self.match_pocs_btn = QPushButton("匹配PoC")
        self.match_pocs_btn.clicked.connect(self._match_pocs)
        actions_layout.addWidget(self.match_pocs_btn)
        
        self.verify_btn = QPushButton("开始验证")
        self.verify_btn.clicked.connect(self._start_verification)
        self.verify_btn.setStyleSheet("background-color: #4CAF50; color: white; padding: 8px;")
        actions_layout.addWidget(self.verify_btn)
        
        self.stop_btn = QPushButton("停止")
        self.stop_btn.clicked.connect(self._stop_verification)
        self.stop_btn.setEnabled(False)
        actions_layout.addWidget(self.stop_btn)
        
        layout.addWidget(actions_group)
        
        progress_group = QGroupBox("进度")
        progress_layout = QVBoxLayout(progress_group)
        
        self.progress_bar = QProgressBar()
        progress_layout.addWidget(self.progress_bar)
        
        self.status_label = QLabel("就绪")
        progress_layout.addWidget(self.status_label)
        
        layout.addWidget(progress_group)
        
        matched_group = QGroupBox("匹配的PoC")
        matched_layout = QVBoxLayout(matched_group)
        
        self.matched_pocs_list = QListWidget()
        matched_layout.addWidget(self.matched_pocs_list)
        
        layout.addWidget(matched_group)
        
        return widget
    
    def _create_poc_manager_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        actions_layout = QHBoxLayout()
        
        self.load_pocs_btn = QPushButton("加载PoC")
        self.load_pocs_btn.clicked.connect(self._load_pocs)
        actions_layout.addWidget(self.load_pocs_btn)
        
        self.refresh_pocs_btn = QPushButton("刷新")
        self.refresh_pocs_btn.clicked.connect(self._refresh_pocs)
        actions_layout.addWidget(self.refresh_pocs_btn)
        
        layout.addLayout(actions_layout)
        
        self.pocs_table = QTableWidget()
        self.pocs_table.setColumnCount(6)
        self.pocs_table.setHorizontalHeaderLabels(["名称", "CVE", "产品", "版本范围", "风险等级", "类型"])
        self.pocs_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.pocs_table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.pocs_table)
        
        return widget
    
    def _create_results_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        actions_layout = QHBoxLayout()
        
        self.export_results_btn = QPushButton("导出结果")
        self.export_results_btn.clicked.connect(self._export_results)
        actions_layout.addWidget(self.export_results_btn)
        
        self.clear_results_btn = QPushButton("清除结果")
        self.clear_results_btn.clicked.connect(self._clear_results)
        actions_layout.addWidget(self.clear_results_btn)
        
        layout.addLayout(actions_layout)
        
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(7)
        self.results_table.setHorizontalHeaderLabels(["PoC", "目标", "状态", "漏洞", "置信度", "严重程度", "证据"])
        self.results_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.results_table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.results_table)
        
        detail_group = QGroupBox("详细信息")
        detail_layout = QVBoxLayout(detail_group)
        
        self.result_detail = QTextBrowser()
        self.result_detail.setFont(QFont("Consolas", 9))
        detail_layout.addWidget(self.result_detail)
        
        layout.addWidget(detail_group)
        
        return widget
    
    def _create_oob_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        oob_info = QLabel("OOB (Out-of-Band) 检测用于无回显漏洞")
        layout.addWidget(oob_info)
        
        dns_group = QGroupBox("DNSLog")
        dns_layout = QVBoxLayout(dns_group)
        
        self.dns_subdomain = QLabel("子域名: 未生成")
        dns_layout.addWidget(self.dns_subdomain)
        
        generate_dns_btn = QPushButton("生成子域名")
        generate_dns_btn.clicked.connect(self._generate_dns_subdomain)
        dns_layout.addWidget(generate_dns_btn)
        
        layout.addWidget(dns_group)
        
        http_group = QGroupBox("HTTPLog")
        http_layout = QVBoxLayout(http_group)
        
        self.http_callback_url = QLabel("回调URL: 未生成")
        http_layout.addWidget(self.http_callback_url)
        
        generate_http_btn = QPushButton("生成回调URL")
        generate_http_btn.clicked.connect(self._generate_http_callback)
        http_layout.addWidget(generate_http_btn)
        
        layout.addWidget(http_group)
        
        ldap_group = QGroupBox("LDAPLog")
        ldap_layout = QVBoxLayout(ldap_group)
        
        self.ldap_url = QLabel("LDAP URL: 未生成")
        ldap_layout.addWidget(self.ldap_url)
        
        generate_ldap_btn = QPushButton("生成LDAP URL")
        generate_ldap_btn.clicked.connect(self._generate_ldap_url)
        ldap_layout.addWidget(generate_ldap_btn)
        
        layout.addWidget(ldap_group)
        
        requests_group = QGroupBox("OOB请求")
        requests_layout = QVBoxLayout(requests_group)
        
        self.oob_requests_table = QTableWidget()
        self.oob_requests_table.setColumnCount(4)
        self.oob_requests_table.setHorizontalHeaderLabels(["时间", "信道", "来源IP", "数据"])
        self.oob_requests_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        requests_layout.addWidget(self.oob_requests_table)
        
        refresh_oob_btn = QPushButton("刷新")
        refresh_oob_btn.clicked.connect(self._refresh_oob_requests)
        requests_layout.addWidget(refresh_oob_btn)
        
        layout.addWidget(requests_group)
        
        return widget
    
    def _create_settings_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        config_group = QGroupBox("执行配置")
        config_layout = QFormLayout(config_group)
        
        self.timeout_spin = QSpinBox()
        self.timeout_spin.setRange(5, 300)
        self.timeout_spin.setValue(30)
        config_layout.addRow("超时(秒):", self.timeout_spin)
        
        self.memory_spin = QSpinBox()
        self.memory_spin.setRange(64, 2048)
        self.memory_spin.setValue(256)
        config_layout.addRow("最大内存(MB):", self.memory_spin)
        
        self.concurrent_spin = QSpinBox()
        self.concurrent_spin.setRange(1, 20)
        self.concurrent_spin.setValue(5)
        config_layout.addRow("最大并发:", self.concurrent_spin)
        
        self.enable_oob_check = QCheckBox("启用OOB检测")
        self.enable_oob_check.setChecked(True)
        config_layout.addRow("", self.enable_oob_check)
        
        layout.addWidget(config_group)
        
        save_btn = QPushButton("保存配置")
        save_btn.clicked.connect(self._save_config)
        layout.addWidget(save_btn)
        
        layout.addStretch()
        
        return widget
    
    def _match_pocs(self):
        """匹配PoC"""
        try:
            asset = AssetFingerprint(
                product=self.product_input.text(),
                version=self.version_input.text(),
                ports=[int(p.strip()) for p in self.ports_input.text().split(",") if p.strip()],
                tags=[]
            )
            
            matched = self.manager.match_pocs_for_asset(asset)
            
            self.matched_pocs_list.clear()
            for poc_id in matched:
                self.matched_pocs_list.addItem(poc_id)
            
            self.status_label.setText(f"匹配到 {len(matched)} 个PoC")
            
        except Exception as e:
            QMessageBox.warning(self.get_widget(), "错误", f"匹配失败: {e}")
    
    def _start_verification(self):
        """开始验证"""
        try:
            asset = AssetFingerprint(
                product=self.product_input.text() or self.target_input.text(),
                version=self.version_input.text(),
                ports=[int(p.strip()) for p in self.ports_input.text().split(",") if p.strip()],
                tags=[]
            )
            
            self._verification_thread = PoCVerificationThread(self.manager, asset)
            self._verification_thread.result_found.connect(self._on_result_found)
            self._verification_thread.finished.connect(self._on_verification_finished)
            self._verification_thread.error.connect(self._on_verification_error)
            
            self.verify_btn.setEnabled(False)
            self.stop_btn.setEnabled(True)
            self.status_label.setText("验证中...")
            
            self._verification_thread.start()
            
        except Exception as e:
            QMessageBox.warning(self.get_widget(), "错误", f"启动失败: {e}")
    
    def _stop_verification(self):
        """停止验证"""
        if self._verification_thread:
            self._verification_thread.terminate()
            self._verification_thread = None
        
        self.verify_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.status_label.setText("已停止")
    
    def _on_result_found(self, result: PoCVerificationResult):
        """处理结果"""
        self._results.append(result)
        
        row = self.results_table.rowCount()
        self.results_table.insertRow(row)
        self.results_table.setItem(row, 0, QTableWidgetItem(result.poc_name))
        self.results_table.setItem(row, 1, QTableWidgetItem(result.target))
        self.results_table.setItem(row, 2, QTableWidgetItem(result.status.value))
        self.results_table.setItem(row, 3, QTableWidgetItem("是" if result.vulnerable else "否"))
        self.results_table.setItem(row, 4, QTableWidgetItem(result.confidence.value))
        self.results_table.setItem(row, 5, QTableWidgetItem(result.severity.value))
        self.results_table.setItem(row, 6, QTableWidgetItem(result.evidence[:100]))
        
        if result.vulnerable:
            for col in range(7):
                item = self.results_table.item(row, col)
                if item:
                    item.setBackground(QColor("#ffcccc"))
        
        self.status_label.setText(f"发现 {sum(1 for r in self._results if r.vulnerable)} 个漏洞")
    
    def _on_verification_finished(self):
        """验证完成"""
        self.verify_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.status_label.setText("验证完成")
        self.progress_bar.setValue(100)
    
    def _on_verification_error(self, error: str):
        """验证错误"""
        self.verify_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.status_label.setText(f"错误: {error}")
        QMessageBox.critical(self.get_widget(), "错误", f"验证失败: {error}")
    
    def _load_pocs(self):
        """加载PoC"""
        dir_path = QFileDialog.getExistingDirectory(self.get_widget(), "选择PoC目录")
        if dir_path:
            count = self.manager.load_pocs(dir_path)
            self.status_label.setText(f"加载了 {count} 个PoC")
            self._refresh_pocs()
    
    def _refresh_pocs(self):
        """刷新PoC列表"""
        pocs = self.manager.get_available_pocs()
        
        self.pocs_table.setRowCount(0)
        for poc_id, poc_data in pocs.items():
            row = self.pocs_table.rowCount()
            self.pocs_table.insertRow(row)
            
            metadata = poc_data.get("metadata", {})
            self.pocs_table.setItem(row, 0, QTableWidgetItem(metadata.get("name", poc_id)))
            self.pocs_table.setItem(row, 1, QTableWidgetItem(metadata.get("cve", "")))
            self.pocs_table.setItem(row, 2, QTableWidgetItem(metadata.get("product", "")))
            self.pocs_table.setItem(row, 3, QTableWidgetItem(metadata.get("version_range", "")))
            self.pocs_table.setItem(row, 4, QTableWidgetItem(metadata.get("risk_level", "")))
            self.pocs_table.setItem(row, 5, QTableWidgetItem(str(poc_data.get("type", ""))))
    
    def _export_results(self):
        """导出结果"""
        file_path, _ = QFileDialog.getSaveFileName(
            self.get_widget(), "导出结果", "", "JSON Files (*.json)"
        )
        
        if file_path:
            results_data = [r.model_dump() for r in self._results]
            
            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(results_data, f, indent=2, ensure_ascii=False, default=str)
            
            QMessageBox.information(self.get_widget(), "成功", "结果已导出")
    
    def _clear_results(self):
        """清除结果"""
        self._results.clear()
        self.results_table.setRowCount(0)
        self.result_detail.clear()
    
    def _generate_dns_subdomain(self):
        """生成DNS子域名"""
        subdomain = self.manager.oob_manager.generate_dns_subdomain()
        self.dns_subdomain.setText(f"子域名: {subdomain}")
    
    def _generate_http_callback(self):
        """生成HTTP回调"""
        url = self.manager.oob_manager.generate_http_callback_url()
        self.http_callback_url.setText(f"回调URL: {url}")
    
    def _generate_ldap_url(self):
        """生成LDAP URL"""
        url = self.manager.oob_manager.generate_ldap_url()
        self.ldap_url.setText(f"LDAP URL: {url}")
    
    def _refresh_oob_requests(self):
        """刷新OOB请求"""
        requests = self.manager.oob_manager.get_all_requests()
        
        self.oob_requests_table.setRowCount(0)
        for req in requests:
            row = self.oob_requests_table.rowCount()
            self.oob_requests_table.insertRow(row)
            self.oob_requests_table.setItem(row, 0, QTableWidgetItem(str(req.timestamp)))
            self.oob_requests_table.setItem(row, 1, QTableWidgetItem(req.channel))
            self.oob_requests_table.setItem(row, 2, QTableWidgetItem(req.source_ip))
            self.oob_requests_table.setItem(row, 3, QTableWidgetItem(str(req.data)[:100]))
    
    def _save_config(self):
        """保存配置"""
        self.manager.config.timeout = self.timeout_spin.value()
        self.manager.config.max_memory_mb = self.memory_spin.value()
        self.manager.config.max_concurrent = self.concurrent_spin.value()
        self.manager.config.enable_oob = self.enable_oob_check.isChecked()
        
        QMessageBox.information(self.get_widget(), "成功", "配置已保存")
