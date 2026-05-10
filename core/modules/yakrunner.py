"""
Yak Runner (Yak语言)模块 - 脚本引擎
代码编辑、调试、运行、脚本库管理
"""

from typing import Dict, Any, List, Optional
import logging
import sys
from io import StringIO
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QSplitter, QTabWidget,
    QPushButton, QLabel, QLineEdit, QTextEdit, QComboBox,
    QGroupBox, QFormLayout, QFileDialog, QListWidget,
    QListWidgetItem
)
from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QFont, QTextCharFormat, QColor

from .base import ModuleBase

logger = logging.getLogger(__name__)


class YakScriptRunner(QThread):
    """脚本执行线程"""
    output = Signal(str)
    finished = Signal()
    
    def __init__(self, code):
        super().__init__()
        self.code = code
        
    def run(self):
        # 简单模拟执行
        old_stdout = sys.stdout
        redirected_output = sys.stdout = StringIO()
        
        try:
            # 安全执行 (示例)
            print(f"[+] Executing Yak script...")
            print(f"[+] Script length: {len(self.code)} bytes")
            print(f"[+] Log: Starting scan...")
            print(f"[+] Found: Target.com")
            print(f"[+] Done!")
        except Exception as e:
            print(f"Error: {e}")
        finally:
            sys.stdout = old_stdout
            
        self.output.emit(redirected_output.getvalue())
        self.finished.emit()


class YakRunnerModule(ModuleBase):
    """Yak Runner模块"""
    
    def __init__(self):
        super().__init__("YakRunner", "Yak语言脚本引擎")
        self._runner: Optional[YakScriptRunner] = None
        
    def _create_ui(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # 脚本库
        library_group = QGroupBox("📚 脚本库")
        library_layout = QHBoxLayout(library_group)
        
        self.script_list = QListWidget()
        self.script_list.setMaximumWidth(250)
        self.script_list.itemClicked.connect(self._load_script)
        
        # 添加示例脚本
        sample_scripts = [
            "port_scan.yak",
            "web_crawler.yak",
            "vuln_scanner.yak",
            "brute_force.yak"
        ]
        for s in sample_scripts:
            self.script_list.addItem(QListWidgetItem(s))
            
        library_layout.addWidget(self.script_list)
        
        # 编辑区
        right_pane = QWidget()
        right_layout = QVBoxLayout(right_pane)
        
        toolbar = QHBoxLayout()
        new_btn = QPushButton("📄 新建")
        new_btn.clicked.connect(lambda: self.code_edit.clear())
        open_btn = QPushButton("📂 打开")
        open_btn.clicked.connect(self._open_script)
        save_btn = QPushButton("💾 保存")
        save_btn.clicked.connect(self._save_script)
        
        toolbar.addWidget(new_btn)
        toolbar.addWidget(open_btn)
        toolbar.addWidget(save_btn)
        
        right_layout.addLayout(toolbar)
        
        self.code_edit = QTextEdit()
        self.code_edit.setFont(QFont("Consolas", 10))
        self.code_edit.setPlaceholderText(
"""// Yak 语言示例
target = "example.com"
ports = [80, 443, 8080, 22, 3306]

for p in ports {
    println("Scanning", target, ":", p)
    if isOpen(target, p) {
        println("Port", p, "is OPEN!")
    }
}
"""
        )
        right_layout.addWidget(self.code_edit)
        
        library_layout.addWidget(right_pane, stretch=1)
        
        layout.addWidget(library_group)
        
        # 控制栏
        control_layout = QHBoxLayout()
        run_btn = QPushButton("▶️ 运行")
        run_btn.setStyleSheet("background-color: #4CAF50; color: white;")
        run_btn.clicked.connect(self._run)
        stop_btn = QPushButton("⏹️ 停止")
        debug_btn = QPushButton("🐛 调试")
        
        control_layout.addWidget(run_btn)
        control_layout.addWidget(stop_btn)
        control_layout.addWidget(debug_btn)
        
        layout.addLayout(control_layout)
        
        # 输出区
        self.output_view = QTextEdit()
        self.output_view.setReadOnly(True)
        self.output_view.setFont(QFont("Consolas", 9))
        self.output_view.setPlaceholderText("脚本输出...")
        
        output_group = QGroupBox("📜 输出")
        output_layout = QVBoxLayout(output_group)
        output_layout.addWidget(self.output_view)
        
        layout.addWidget(output_group)
        
        return widget
        
    def _load_script(self, item):
        """加载选中脚本"""
        self.code_edit.setText(f"// Script: {item.text()}\n// Ready to edit...\n\n")
        
    def _open_script(self):
        """打开脚本"""
        filename, _ = QFileDialog.getOpenFileName(None, "打开Yak脚本", "", "Yak Files (*.yak);;All Files (*)")
        if filename:
            try:
                with open(filename, 'r', encoding='utf-8') as f:
                    self.code_edit.setText(f.read())
            except Exception as e:
                self.log("ERROR", f"加载失败: {str(e)}")
                
    def _save_script(self):
        """保存脚本"""
        filename, _ = QFileDialog.getSaveFileName(None, "保存Yak脚本", "", "Yak Files (*.yak);;All Files (*)")
        if filename:
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(self.code_edit.toPlainText())
            except Exception as e:
                self.log("ERROR", f"保存失败: {str(e)}")
                
    def _run(self):
        """运行"""
        code = self.code_edit.toPlainText()
        self.output_view.clear()
        
        self._runner = YakScriptRunner(code)
        self._runner.output.connect(lambda t: self.output_view.append(t))
        self._runner.finished.connect(lambda: self.status == ModuleStatus.STOPPED)
        self._runner.start()
        self.status = ModuleStatus.RUNNING
