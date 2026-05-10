"""
Port Scan (端口扫描)模块 - 网络探测
端口扫描、服务识别、指纹识别
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
    QListWidget, QListWidgetItem
)
from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QFont

from .base import ModuleBase

logger = logging.getLogger(__name__)


class PortStatus(Enum):
    OPEN = "OPEN"
    CLOSED = "CLOSED"
    FILTERED = "FILTERED"


@dataclass
class PortResult:
    port: int
    status: PortStatus
    service: str
    version: str
    banner: str


class ScannerThread(QThread):
    progress = Signal(int, int)
    found = Signal(PortResult)
    finished = Signal()

    def __init__(self, target: str, start: int, end: int):
        super().__init__()
        self.target = target
        self.start_p = start
        self.end_p = end
        
    def run(self):
        total = self.end_p - self.start_p + 1
        
        common_services = {
            22: ("SSH", "OpenSSH 8.2p1"),
            80: ("HTTP", "Apache 2.4.41"),
            443: ("HTTPS", "nginx 1.18.0"),
            3306: ("MySQL", "MySQL 8.0"),
            21: ("FTP", "vsftpd 3.0.3"),
            3389: ("RDP", "Microsoft Terminal Services")
        }
        
        for i, p in enumerate(range(self.start_p, self.end_p + 1)):
            status = PortStatus.CLOSED
            service = ""
            version = ""
            banner = ""
            
            # 模拟扫描: 随机开放
            if p in [22,80,443,3306]:
                status = PortStatus.OPEN
                if p in common_services:
                    service, version = common_services[p]
                    banner = f"{service} {version} (fake banner)"
                    
            res = PortResult(p, status, service, version, banner)
            self.found.emit(res)
            
            self.progress.emit(i+1, total)
            
        self.finished.emit()


class PortScanModule(ModuleBase):
    """端口扫描模块"""
    
    def __init__(self):
        super().__init__("PortScan", "端口扫描与指纹识别")
        self._results: List[PortResult] = []
        self._thread: Optional[ScannerThread] = None
        
    def _create_ui(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # 目标设置
        target_group = QGroupBox("🎯 目标设置")
        target_layout = QFormLayout(target_group)
        
        self.target = QLineEdit("127.0.0.1")
        target_layout.addRow("目标:", self.target)
        
        self.start_port = QSpinBox()
        self.start_port.setRange(1,65535)
        self.start_port.setValue(1)
        target_layout.addRow("起始:", self.start_port)
        
        self.end_port = QSpinBox()
        self.end_port.setRange(1,65535)
        self.end_port.setValue(1000)
        target_layout.addRow("结束:", self.end_port)
        
        self.scan_mode = QComboBox()
        self.scan_mode.addItems(["TCP Connect", "SYN Scan", "UDP Scan"])
        target_layout.addRow("模式:", self.scan_mode)
        
        layout.addWidget(target_group)
        
        # 预设
        preset_group = QGroupBox("📋 快速预设")
        preset_layout = QHBoxLayout(preset_group)
        
        preset_100 = QPushButton("1-100")
        preset_100.clicked.connect(lambda: (self.start_port.setValue(1), self.end_port.setValue(100)))
        preset_1000 = QPushButton("1-1000")
        preset_1000.clicked.connect(lambda: (self.start_port.setValue(1), self.end_port.setValue(1000)))
        preset_common = QPushButton("常用端口")
        preset_common.clicked.connect(lambda: (self.start_port.setValue(1), self.end_port.setValue(100)))
        
        preset_layout.addWidget(preset_100)
        preset_layout.addWidget(preset_1000)
        preset_layout.addWidget(preset_common)
        
        layout.addWidget(preset_group)
        
        # 按钮
        btn_layout = QHBoxLayout()
        self.start_btn = QPushButton("▶️ 开始扫描")
        self.start_btn.clicked.connect(self._start)
        self.stop_btn = QPushButton("⏹️ 停止")
        self.export_btn = QPushButton("📤 导出")
        
        btn_layout.addWidget(self.start_btn)
        btn_layout.addWidget(self.stop_btn)
        btn_layout.addWidget(self.export_btn)
        
        layout.addLayout(btn_layout)
        
        # 进度
        self.progress_bar = QProgressBar()
        layout.addWidget(self.progress_bar)
        
        # 结果
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(5)
        self.results_table.setHorizontalHeaderLabels(["端口", "状态", "服务", "版本", "Banner"])
        self.results_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.results_table.setSelectionBehavior(QTableWidget.SelectRows)
        layout.addWidget(self.results_table)
        
        return widget
        
    def _start(self):
        """开始扫描"""
        self._results.clear()
        self.results_table.setRowCount(0)
        
        self._thread = ScannerThread(
            self.target.text(),
            self.start_port.value(),
            self.end_port.value()
        )
        self._thread.progress.connect(lambda c,t: self.progress_bar.setValue(int(c*100/t)))
        self._thread.found.connect(self._add_result)
        self._thread.finished.connect(lambda: self.status == ModuleStatus.STOPPED)
        self._thread.start()
        self.status = ModuleStatus.RUNNING
        
    def _add_result(self, res):
        self._results.append(res)
        row = self.results_table.rowCount()
        self.results_table.insertRow(row)
        
        item_status = QTableWidgetItem(res.status.value)
        if res.status == PortStatus.OPEN:
            item_status.setForeground(Qt.green)
            
        self.results_table.setItem(row,0,QTableWidgetItem(str(res.port)))
        self.results_table.setItem(row,1,item_status)
        self.results_table.setItem(row,2,QTableWidgetItem(res.service))
        self.results_table.setItem(row,3,QTableWidgetItem(res.version))
        self.results_table.setItem(row,4,QTableWidgetItem(res.banner))
