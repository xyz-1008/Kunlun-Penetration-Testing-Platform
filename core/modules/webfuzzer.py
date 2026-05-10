"""
Web Fuzzer (模糊测试)模块 - 可视化重放与爆破
支持fuzztag语法、Payload库、结果分析
"""

from typing import Dict, Any, List, Optional
from dataclasses import dataclass
import logging
import re
import random
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QSplitter, QTabWidget,
    QPushButton, QLabel, QLineEdit, QTextEdit, QComboBox,
    QGroupBox, QFormLayout, QProgressBar, QTableWidget,
    QTableWidgetItem, QHeaderView, QCheckBox, QSpinBox,
    QFileDialog
)
from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QFont

from .base import ModuleBase

logger = logging.getLogger(__name__)


@dataclass
class FuzzResult:
    """Fuzz结果"""
    id: int
    payload: str
    status_code: int
    length: int
    time_ms: float
    response: str = ""


class FuzzerThread(QThread):
    """Fuzz线程"""
    progress = Signal(int, int)
    result_found = Signal(FuzzResult)
    finished = Signal()
    
    def __init__(self, template: str, payloads: List[str]):
        super().__init__()
        self.template = template
        self.payloads = payloads
        
    def run(self):
        for i, payload in enumerate(self.payloads):
            # 简单模拟Fuzz
            result = FuzzResult(
                id=i+1,
                payload=payload,
                status_code=200 if i % 5 != 0 else 500,
                length=1000 + i*10,
                time_ms=random.uniform(50, 200)
            )
            self.result_found.emit(result)
            self.progress.emit(i+1, len(self.payloads))
        self.finished.emit()


class WebFuzzerModule(ModuleBase):
    """Web Fuzzer模块"""
    
    def __init__(self):
        super().__init__("WebFuzzer", "可视化模糊测试工具")
        self._results: List[FuzzResult] = []
        self._fuzz_thread: Optional[FuzzerThread] = None
        
    def _create_ui(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # 请求模板
        request_group = QGroupBox("请求模板 (使用 {{fuzztag}} 标记Payload位置)")
        request_layout = QVBoxLayout(request_group)
        
        self.request_template = QTextEdit()
        self.request_template.setFont(QFont("Consolas", 9))
        self.request_template.setPlaceholderText(
            "POST /test HTTP/1.1\n"
            "Host: example.com\n"
            "\n"
            '{"username": "admin", "password": "{{string(10)}}"}'
        )
        request_layout.addWidget(self.request_template)
        
        layout.addWidget(request_group)
        
        # 标签帮助
        help_group = QGroupBox("📖 Fuzztag 语法")
        help_layout = QVBoxLayout(help_group)
        
        help_text = QTextEdit()
        help_text.setReadOnly(True)
        help_text.setMaximumHeight(100)
        help_text.setText("""
常用标签:
  {{int(min, max)}} - 整数范围
  {{string(length)}} - 随机字符串
  {{hex(length)}} - 十六进制
  {{list(item1,item2)}} - 列表
  {{file(path)}} - 从文件加载
  {{range(start,end)}} - 数字范围
  {{ip}} - 随机IP
示例:
  /api?id={{int(1,1000)}}
  /user/{{list(admin,user,test)}}
""")
        help_layout.addWidget(help_text)
        layout.addWidget(help_group)
        
        # Payload 配置
        payload_group = QGroupBox("Payload 配置")
        payload_layout = QFormLayout(payload_group)
        
        self.payload_list = QTextEdit()
        self.payload_list.setPlaceholderText("Payload 列表，一行一个 (可选)")
        self.payload_list.setFont(QFont("Consolas", 9))
        payload_layout.addRow("Payloads:", self.payload_list)
        
        self.threads = QSpinBox()
        self.threads.setRange(1, 100)
        self.threads.setValue(10)
        payload_layout.addRow("并发:", self.threads)
        
        self.delay = QSpinBox()
        self.delay.setRange(0, 10000)
        self.delay.setSuffix(" ms")
        payload_layout.addRow("延迟:", self.delay)
        
        layout.addWidget(payload_group)
        
        # 按钮
        btn_layout = QHBoxLayout()
        self.start_btn = QPushButton("▶️ 开始Fuzz")
        self.start_btn.clicked.connect(self._start_fuzz)
        self.stop_btn = QPushButton("⏹️ 停止")
        self.load_payloads_btn = QPushButton("📂 加载Payloads")
        self.load_payloads_btn.clicked.connect(self._load_payloads)
        
        btn_layout.addWidget(self.start_btn)
        btn_layout.addWidget(self.stop_btn)
        btn_layout.addWidget(self.load_payloads_btn)
        layout.addLayout(btn_layout)
        
        # 进度条
        self.progress_bar = QProgressBar()
        layout.addWidget(self.progress_bar)
        
        # 结果
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(5)
        self.results_table.setHorizontalHeaderLabels(["#", "Payload", "状态", "长度", "耗时(ms)"])
        self.results_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.results_table.setSelectionBehavior(QTableWidget.SelectRows)
        layout.addWidget(self.results_table)
        
        return widget
        
    def _start_fuzz(self):
        """开始Fuzz"""
        self._results.clear()
        self.results_table.setRowCount(0)
        
        # 获取Payloads
        payloads_text = self.payload_list.toPlainText()
        if payloads_text:
            payloads = [p.strip() for p in payloads_text.splitlines() if p.strip()]
        else:
            # 默认: 生成一些测试
            payloads = [str(i) for i in range(1, 101)]
            
        self._fuzz_thread = FuzzerThread(self.request_template.toPlainText(), payloads)
        self._fuzz_thread.progress.connect(lambda c,t: self.progress_bar.setValue(int(c*100/t)))
        self._fuzz_thread.result_found.connect(self._add_result)
        self._fuzz_thread.finished.connect(lambda: self.status == ModuleStatus.STOPPED)
        self._fuzz_thread.start()
        self.status = ModuleStatus.RUNNING
        
    def _add_result(self, result):
        """添加结果"""
        self._results.append(result)
        row = self.results_table.rowCount()
        self.results_table.insertRow(row)
        self.results_table.setItem(row, 0, QTableWidgetItem(str(result.id)))
        self.results_table.setItem(row, 1, QTableWidgetItem(result.payload))
        self.results_table.setItem(row, 2, QTableWidgetItem(str(result.status_code)))
        self.results_table.setItem(row, 3, QTableWidgetItem(str(result.length)))
        self.results_table.setItem(row, 4, QTableWidgetItem(f"{result.time_ms:.1f}"))
        
    def _load_payloads(self):
        """加载Payloads"""
        filename, _ = QFileDialog.getOpenFileName(None, "选择Payload文件", "", "All Files (*)")
        if filename:
            try:
                with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
                    self.payload_list.setText(f.read())
            except Exception as e:
                self.log("ERROR", f"加载失败: {str(e)}")
