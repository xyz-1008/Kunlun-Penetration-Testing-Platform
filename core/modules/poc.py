"""
POC (专项漏洞检测)模块 - Nuclei YAML模板
模板管理、自定义PoC、批量扫描
"""

from typing import Dict, Any, List, Optional
from dataclasses import dataclass
from enum import Enum, auto
import logging
import random
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTabWidget,
    QPushButton, QLabel, QLineEdit, QTextEdit, QComboBox,
    QGroupBox, QFormLayout, QProgressBar, QTableWidget,
    QTableWidgetItem, QHeaderView, QCheckBox, QSpinBox,
    QListWidget, QListWidgetItem, QFileDialog
)
from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QFont, QColor

from .base import ModuleBase

logger = logging.getLogger(__name__)


@dataclass
class POCTemplate:
    id: str
    name: str
    severity: str
    description: str


@dataclass
class POCResult:
    template: str
    target: str
    found: bool
    info: str


class POCScannerThread(QThread):
    progress = Signal(int, int)
    found = Signal(POCResult)
    finished = Signal()

    def __init__(self, target: str, templates: List[POCTemplate]):
        super().__init__()
        self.target = target
        self.templates = templates

    def run(self):
        total = len(self.templates)
        for i, t in enumerate(self.templates):
            # 模拟: 随机发现
            found = random.choice([False, False, False, True])
            res = POCResult(
                template=t.id,
                target=self.target,
                found=found,
                info=f"Checked {t.name}" if not found else "VULNERABILITY DETECTED!"
            )
            self.found.emit(res)
            self.progress.emit(i+1, total)
        self.finished.emit()


class POCModule(ModuleBase):
    """POC模块"""
    
    def __init__(self):
        super().__init__("POC", "专项漏洞检测 (Nuclei)")
        self._templates: List[POCTemplate] = []
        self._thread: Optional[POCScannerThread] = None
        self._init_templates()
        
    def _init_templates(self):
        self._templates = [
            POCTemplate("cve-2021-44228", "Log4j RCE", "CRITICAL", "Apache Log4j JNDI RCE"),
            POCTemplate("cve-2023-23397", "Microsoft Outlook RCE", "CRITICAL", "Microsoft Outlook CVE-2023-23397"),
            POCTemplate("cve-2017-5638", "Struts2 S2-045", "HIGH", "Apache Struts2 Content-Type RCE"),
            POCTemplate("cve-2019-0708", "BlueKeep", "CRITICAL", "Microsoft RDP RCE"),
            POCTemplate("wordpress-xmlrpc", "WordPress XML-RPC Bruteforce", "MEDIUM", "WordPress XML-RPC attack"),
            POCTemplate("phpmyadmin-setup", "phpMyAdmin Setup", "HIGH", "phpMyAdmin configuration page")
        ]
        
    def _create_ui(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # 目标设置
        target_group = QGroupBox("🎯 目标设置")
        target_layout = QHBoxLayout(target_group)
        
        self.target_input = QLineEdit("http://example.com")
        target_layout.addWidget(QLabel("目标:"))
        target_layout.addWidget(self.target_input)
        
        self.load_targets_btn = QPushButton("📂 批量导入")
        target_layout.addWidget(self.load_targets_btn)
        
        layout.addWidget(target_group)
        
        # 模板管理
        template_group = QGroupBox("📚 漏洞模板")
        template_layout = QHBoxLayout(template_group)
        
        self.template_list = QListWidget()
        self.template_list.setSelectionMode(QListWidget.MultiSelection)
        for t in self._templates:
            item = QListWidgetItem(f"[{t.severity}] {t.name}")
            item.setData(Qt.UserRole, t)
            self.template_list.addItem(item)
            item.setSelected(True)
            
        template_layout.addWidget(self.template_list)
        
        right_template_panel = QWidget()
        right_template_layout = QVBoxLayout(right_template_panel)
        
        add_btn = QPushButton("➕ 添加")
        add_btn.clicked.connect(self._add_template)
        update_btn = QPushButton("🔄 更新库")
        update_btn.clicked.connect(lambda: self.log("INFO", "Updating POC library..."))
        
        right_template_layout.addWidget(add_btn)
        right_template_layout.addWidget(update_btn)
        right_template_layout.addStretch()
        
        template_layout.addWidget(right_template_panel)
        
        layout.addWidget(template_group)
        
        # 扫描控制
        control_layout = QHBoxLayout()
        
        self.start_btn = QPushButton("▶️ 开始扫描")
        self.start_btn.setStyleSheet("background-color: #f44336; color: white;")
        self.start_btn.clicked.connect(self._start_scan)
        
        control_layout.addWidget(self.start_btn)
        
        layout.addLayout(control_layout)
        
        # 进度条
        self.progress_bar = QProgressBar()
        layout.addWidget(self.progress_bar)
        
        # 结果
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(4)
        self.results_table.setHorizontalHeaderLabels(["模板", "目标", "状态", "信息"])
        self.results_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.results_table.setSelectionBehavior(QTableWidget.SelectRows)
        
        layout.addWidget(self.results_table)
        
        return widget
        
    def _add_template(self):
        filename, _ = QFileDialog.getOpenFileName(None, "添加YAML模板", "", "YAML Files (*.yaml *.yml)")
        if filename:
            self.log("INFO", f"Added template: {filename}")
            
    def _start_scan(self):
        selected = [item.data(Qt.UserRole) for item in self.template_list.selectedItems()]
        if not selected:
            return
            
        self.results_table.setRowCount(0)
        
        self._thread = POCScannerThread(self.target_input.text(), selected)
        self._thread.progress.connect(lambda c,t: self.progress_bar.setValue(int(c*100/t)))
        self._thread.found.connect(self._add_result)
        self._thread.finished.connect(lambda: self.status == ModuleStatus.STOPPED)
        self._thread.start()
        self.status = ModuleStatus.RUNNING
        
    def _add_result(self, res):
        row = self.results_table.rowCount()
        self.results_table.insertRow(row)
        
        item_status = QTableWidgetItem("✅ VULNERABLE" if res.found else "❎ Not Vulnerable")
        if res.found:
            item_status.setForeground(QColor(255,0,0))
            
        self.results_table.setItem(row, 0, QTableWidgetItem(res.template))
        self.results_table.setItem(row, 1, QTableWidgetItem(res.target))
        self.results_table.setItem(row, 2, item_status)
        self.results_table.setItem(row, 3, QTableWidgetItem(res.info))
