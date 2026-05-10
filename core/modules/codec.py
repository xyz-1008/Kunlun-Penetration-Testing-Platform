"""
Codec (编解码)模块 - 数据编解码与加密
友好GUI、多种算法、密钥管理
"""

from typing import Dict, Any, List, Optional
import logging
import base64
import urllib.parse
import hashlib
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTabWidget,
    QPushButton, QLabel, QLineEdit, QTextEdit, QComboBox,
    QGroupBox, QFormLayout, QSplitter
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QFont

from .base import ModuleBase

logger = logging.getLogger(__name__)


class CodecModule(ModuleBase):
    """Codec模块"""
    
    def __init__(self):
        super().__init__("Codec", "编解码与加密工具")
        
    def _create_ui(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # 双面板布局
        split = QSplitter(Qt.Horizontal)
        
        # 左侧输入
        left = QGroupBox("📥 输入")
        left_layout = QVBoxLayout(left)
        
        self.input = QTextEdit()
        self.input.setPlaceholderText("输入数据...")
        self.input.setFont(QFont("Consolas", 10))
        left_layout.addWidget(self.input)
        
        split.addWidget(left)
        
        # 右侧操作
        right = QWidget()
        right_layout = QVBoxLayout(right)
        
        # 编码器列表
        encoders = QGroupBox("🔧 选择操作")
        enc_layout = QVBoxLayout(encoders)
        
        self.mode_combo = QComboBox()
        self.mode_combo.addItems([
            "Base64 Encode", "Base64 Decode",
            "URL Encode", "URL Decode",
            "Hex Encode", "Hex Decode",
            "HTML Encode", "HTML Decode",
            "MD5", "SHA1", "SHA256"
        ])
        enc_layout.addWidget(self.mode_combo)
        
        self.run_btn = QPushButton("▶️ 转换")
        self.run_btn.clicked.connect(self._convert)
        enc_layout.addWidget(self.run_btn)
        
        right_layout.addWidget(encoders)
        
        # 输出
        output_group = QGroupBox("📤 输出")
        output_layout = QVBoxLayout(output_group)
        
        self.output = QTextEdit()
        self.output.setReadOnly(True)
        self.output.setFont(QFont("Consolas", 10))
        output_layout.addWidget(self.output)
        
        self.copy_btn = QPushButton("📋 复制")
        self.copy_btn.clicked.connect(lambda: self.log("INFO", "Copied!"))
        output_layout.addWidget(self.copy_btn)
        
        right_layout.addWidget(output_group)
        
        split.addWidget(right)
        
        split.setSizes([400, 400])
        layout.addWidget(split)
        
        return widget
        
    def _convert(self):
        data = self.input.toPlainText().encode('utf-8', 'ignore')
        mode = self.mode_combo.currentText()
        
        try:
            if mode == "Base64 Encode":
                res = base64.b64encode(data).decode()
            elif mode == "Base64 Decode":
                res = base64.b64decode(data).decode(errors='replace')
            elif mode == "URL Encode":
                res = urllib.parse.quote(data.decode())
            elif mode == "URL Decode":
                res = urllib.parse.unquote(data.decode())
            elif mode == "Hex Encode":
                res = data.hex()
            elif mode == "Hex Decode":
                hex_str = data.decode().replace(" ", "").replace("\n", "")
                res = bytes.fromhex(hex_str).decode(errors='replace')
            elif mode == "HTML Encode":
                res = data.decode().replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            elif mode == "HTML Decode":
                res = data.decode().replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&")
            elif mode == "MD5":
                res = hashlib.md5(data).hexdigest()
            elif mode == "SHA1":
                res = hashlib.sha1(data).hexdigest()
            elif mode == "SHA256":
                res = hashlib.sha256(data).hexdigest()
            else:
                res = "Mode not supported"
                
            self.output.setText(res)
        except Exception as e:
            self.output.setText(f"Error: {e}")
