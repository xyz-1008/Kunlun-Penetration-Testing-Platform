"""
Decoder (解码器)模块 - 专家级多功能编码/解码工具箱
支持URL、Base64、Hex、HTML、JWT、XML、Unicode等多种格式
支持加密/解密、哈希计算、编码链、智能识别等高级功能
专为10年+经验白帽子、安全公司、SRC挖掘设计
"""

from typing import Dict, Any, Callable, List, Tuple, Optional
import base64
import urllib.parse
import html
import binascii
import re
import json
import logging
import struct
import zlib
import gzip
import bz2
import hashlib
import hmac
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QSplitter, QTabWidget,
    QPushButton, QLabel, QComboBox, QTextEdit, QGroupBox,
    QFormLayout, QCheckBox, QSpinBox, QFileDialog, QLineEdit,
    QTableWidget, QTableWidgetItem, QHeaderView, QMessageBox,
    QProgressBar, QRadioButton, QButtonGroup, QScrollArea,
    QGridLayout, QFrame
)
from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QFont, QColor, QTextCursor

from .base import ModuleBase

logger = logging.getLogger(__name__)


class DecoderWorker(QThread):
    """解码工作线程 - 处理耗时操作"""
    progress = Signal(int, int, str)
    result = Signal(str, str)
    error = Signal(str)
    
    def __init__(self, func, *args, **kwargs):
        super().__init__()
        self.func = func
        self.args = args
        self.kwargs = kwargs
        
    def run(self):
        try:
            result = self.func(*self.args, **self.kwargs)
            self.result.emit("success", result)
        except Exception as e:
            self.error.emit(str(e))


class DecoderModule(ModuleBase):
    """解码器模块 - 专家级实现"""
    
    # 经典编码器
    CLASSIC_ENCODERS: Dict[str, Callable] = {
        "Base64 编码": lambda x: base64.b64encode(x.encode()).decode(),
        "Base64 解码": lambda x: base64.b64decode(x).decode('utf-8', errors='ignore'),
        "Base64 URL安全 编码": lambda x: base64.urlsafe_b64encode(x.encode()).decode(),
        "Base64 URL安全 解码": lambda x: base64.urlsafe_b64decode(x + '==').decode('utf-8', errors='ignore'),
        "Base64 无填充 编码": lambda x: base64.b64encode(x.encode()).decode().rstrip('='),
        "Base32 编码": lambda x: base64.b32encode(x.encode()).decode(),
        "Base32 解码": lambda x: base64.b32decode(x).decode('utf-8', errors='ignore'),
        "Base16 编码": lambda x: base64.b16encode(x.encode()).decode(),
        "Base16 解码": lambda x: base64.b16decode(x).decode('utf-8', errors='ignore'),
        "URL 编码": lambda x: urllib.parse.quote(x, safe=''),
        "URL 解码": lambda x: urllib.parse.unquote(x),
        "URL 组件编码": lambda x: urllib.parse.quote_plus(x),
        "URL 组件解码": lambda x: urllib.parse.unquote_plus(x),
        "Hex 编码": lambda x: binascii.hexlify(x.encode()).decode(),
        "Hex 解码": lambda x: binascii.unhexlify(x.replace(' ', '')).decode('utf-8', errors='ignore'),
        "HTML 编码": lambda x: html.escape(x),
        "HTML 解码": lambda x: html.unescape(x),
        "XML 编码": lambda x: x.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;').replace("'", '&apos;'),
        "XML 解码": lambda x: x.replace('&apos;', "'").replace('&quot;', '"').replace('&gt;', '>').replace('&lt;', '<').replace('&amp;', '&'),
        "ASCII85 编码": lambda x: base64.a85encode(x.encode()).decode(),
        "ASCII85 解码": lambda x: base64.a85decode(x.encode()).decode('utf-8', errors='ignore'),
        "ROT13": lambda x: x.translate(str.maketrans(
            'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
            'NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm'
        )),
        "ROT47": lambda x: ''.join(chr(33 + (ord(c) - 33 + 47) % 94) if 33 <= ord(c) <= 126 else c for c in x),
        "Binary 编码": lambda x: ' '.join(format(ord(c), '08b') for c in x),
        "Binary 解码": lambda x: ''.join(chr(int(b, 2)) for b in x.split() if b),
        "Octal 编码": lambda x: ' '.join(format(ord(c), '03o') for c in x),
        "Octal 解码": lambda x: ''.join(chr(int(o, 8)) for o in x.split() if o),
        "Decimal 编码": lambda x: ' '.join(str(ord(c)) for c in x),
        "Decimal 解码": lambda x: ''.join(chr(int(d)) for d in x.split() if d),
        "Unicode 编码": lambda x: ''.join(f'\\u{ord(c):04x}' for c in x),
        "Unicode 解码": lambda x: x.encode().decode('unicode_escape'),
        "UTF-7 编码": lambda x: x.encode('utf-7').decode(),
        "UTF-7 解码": lambda x: x.encode().decode('utf-7'),
        "Punycode 编码": lambda x: x.encode('punycode').decode(),
        "Punycode 解码": lambda x: x.encode().decode('punycode'),
    }
    
    # 压缩算法
    COMPRESSORS: Dict[str, Tuple[Callable, Callable]] = {
        "Zlib": (
            lambda x: base64.b64encode(zlib.compress(x.encode())).decode(),
            lambda x: zlib.decompress(base64.b64decode(x)).decode('utf-8', errors='ignore')
        ),
        "Gzip": (
            lambda x: base64.b64encode(gzip.compress(x.encode())).decode(),
            lambda x: gzip.decompress(base64.b64decode(x)).decode('utf-8', errors='ignore')
        ),
        "BZ2": (
            lambda x: base64.b64encode(bz2.compress(x.encode())).decode(),
            lambda x: bz2.decompress(base64.b64decode(x)).decode('utf-8', errors='ignore')
        ),
    }
    
    def __init__(self):
        super().__init__("Decoder", "专家级多功能编码/解码工具箱")
        self._history: list = []
        self._encoding_chain: List[str] = []
        
    def _create_ui(self) -> QWidget:
        """创建UI"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # 主标签页
        main_tab = QTabWidget()
        
        # 智能解码标签
        smart_tab = self._create_smart_decoder_tab()
        main_tab.addTab(smart_tab, "🧠 智能解码")
        
        # 经典编码标签
        classic_tab = self._create_classic_encoder_tab()
        main_tab.addTab(classic_tab, "🔧 经典编码")
        
        # 编码链标签
        chain_tab = self._create_encoding_chain_tab()
        main_tab.addTab(chain_tab, "⛓️ 编码链")
        
        # 加密/解密标签
        crypto_tab = self._create_crypto_tab()
        main_tab.addTab(crypto_tab, "🔐 加密/解密")
        
        # 哈希计算标签
        hash_tab = self._create_hash_tab()
        main_tab.addTab(hash_tab, "🔑 哈希/HMAC")
        
        # 压缩/解压缩标签
        compress_tab = self._create_compress_tab()
        main_tab.addTab(compress_tab, "📦 压缩/解压")
        
        # 数据格式化标签
        format_tab = self._create_format_tab()
        main_tab.addTab(format_tab, "📋 数据格式化")
        
        # 批量处理标签
        batch_tab = self._create_batch_tab()
        main_tab.addTab(batch_tab, "📚 批量处理")
        
        layout.addWidget(main_tab)
        return widget
        
    def _create_smart_decoder_tab(self) -> QWidget:
        """创建智能解码器标签"""
        w = QWidget()
        layout = QVBoxLayout(w)
        
        # 输入区
        input_group = QGroupBox("输入数据")
        input_layout = QVBoxLayout(input_group)
        
        self.smart_input = QTextEdit()
        self.smart_input.setPlaceholderText("粘贴要解码的数据，支持自动识别编码格式...")
        self.smart_input.setFont(QFont("Consolas", 10))
        self.smart_input.textChanged.connect(self._auto_analyze)
        input_layout.addWidget(self.smart_input)
        
        btn_layout = QHBoxLayout()
        analyze_btn = QPushButton("🔍 智能分析")
        analyze_btn.clicked.connect(self._manual_analyze)
        auto_decode_btn = QPushButton("⚡ 自动解码链")
        auto_decode_btn.clicked.connect(self._auto_decode_chain)
        jwt_btn = QPushButton("🎫 JWT解析")
        jwt_btn.clicked.connect(self._parse_jwt)
        clear_btn = QPushButton("🗑️ 清空")
        clear_btn.clicked.connect(self._clear_smart)
        
        btn_layout.addWidget(analyze_btn)
        btn_layout.addWidget(auto_decode_btn)
        btn_layout.addWidget(jwt_btn)
        btn_layout.addWidget(clear_btn)
        input_layout.addLayout(btn_layout)
        
        layout.addWidget(input_group)
        
        # 输出区
        output_group = QGroupBox("分析结果与解码输出")
        output_layout = QVBoxLayout(output_group)
        
        self.analysis_info = QLabel("粘贴数据后进行智能分析...")
        self.analysis_info.setStyleSheet("padding: 8px; background-color: #f0f0f0; border-radius: 4px;")
        output_layout.addWidget(self.analysis_info)
        
        self.smart_output = QTabWidget()
        
        # 多种解码结果
        self.decoded_plain = QTextEdit()
        self.decoded_plain.setReadOnly(True)
        self.decoded_plain.setFont(QFont("Consolas", 10))
        self.smart_output.addTab(self.decoded_plain, "📝 纯文本")
        
        self.decoded_hex = QTextEdit()
        self.decoded_hex.setReadOnly(True)
        self.decoded_hex.setFont(QFont("Consolas", 10))
        self.smart_output.addTab(self.decoded_hex, "🔢 Hex视图")
        
        self.decoded_json = QTextEdit()
        self.decoded_json.setReadOnly(True)
        self.decoded_json.setFont(QFont("Consolas", 10))
        self.smart_output.addTab(self.decoded_json, "📋 JSON视图")
        
        self.decoded_table = QTableWidget()
        self.decoded_table.setColumnCount(3)
        self.decoded_table.setHorizontalHeaderLabels(["编码类型", "解码结果", "置信度"])
        self.decoded_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.smart_output.addTab(self.decoded_table, "📊 分析表格")
        
        output_layout.addWidget(self.smart_output)
        layout.addWidget(output_group)
        
        return w
        
    def _create_classic_encoder_tab(self) -> QWidget:
        """创建经典编码标签"""
        w = QWidget()
        layout = QVBoxLayout(w)
        
        splitter = QSplitter(Qt.Vertical)
        
        # 输入面板
        input_panel = QWidget()
        input_layout = QVBoxLayout(input_panel)
        
        input_layout.addWidget(QLabel("输入数据:"))
        
        self.classic_input = QTextEdit()
        self.classic_input.setPlaceholderText("输入要处理的数据...")
        self.classic_input.setFont(QFont("Consolas", 10))
        input_layout.addWidget(self.classic_input)
        
        # 编码选择器
        encode_layout = QHBoxLayout()
        encode_layout.addWidget(QLabel("转换方式:"))
        self.encode_combo = QComboBox()
        self.encode_combo.addItems(list(self.CLASSIC_ENCODERS.keys()))
        self.encode_combo.setCurrentText("Base64 编码")
        encode_layout.addWidget(self.encode_combo)
        
        convert_btn = QPushButton("🔄 转换")
        convert_btn.clicked.connect(self._do_convert)
        encode_layout.addWidget(convert_btn)
        
        swap_btn = QPushButton("🔃 输入输出交换")
        swap_btn.clicked.connect(self._swap_classic)
        encode_layout.addWidget(swap_btn)
        
        input_layout.addLayout(encode_layout)
        splitter.addWidget(input_panel)
        
        # 输出面板
        output_panel = QWidget()
        output_layout = QVBoxLayout(output_panel)
        
        output_layout.addWidget(QLabel("输出结果:"))
        
        self.classic_output = QTextEdit()
        self.classic_output.setReadOnly(True)
        self.classic_output.setFont(QFont("Consolas", 10))
        output_layout.addWidget(self.classic_output)
        
        btn_layout = QHBoxLayout()
        copy_btn = QPushButton("📋 复制结果")
        copy_btn.clicked.connect(lambda: self.classic_output.copy())
        btn_layout.addWidget(copy_btn)
        
        save_btn = QPushButton("💾 保存结果")
        save_btn.clicked.connect(self._save_classic_result)
        btn_layout.addWidget(save_btn)
        
        output_layout.addLayout(btn_layout)
        
        splitter.addWidget(output_panel)
        splitter.setSizes([200, 200])
        
        layout.addWidget(splitter)
        return w
        
    def _create_encoding_chain_tab(self) -> QWidget:
        """创建编码链标签"""
        w = QWidget()
        layout = QVBoxLayout(w)
        
        # 说明
        info = QLabel("编码链：按顺序应用多个编码/解码操作，适用于多层编码的场景")
        info.setStyleSheet("color: #666; padding: 5px; background-color: #f9f9f9; border-radius: 4px;")
        layout.addWidget(info)
        
        # 输入
        input_group = QGroupBox("输入数据")
        input_layout = QVBoxLayout(input_group)
        self.chain_input = QTextEdit()
        self.chain_input.setPlaceholderText("输入要处理的数据...")
        self.chain_input.setFont(QFont("Consolas", 10))
        self.chain_input.setMaximumHeight(150)
        input_layout.addWidget(self.chain_input)
        layout.addWidget(input_group)
        
        # 编码链配置
        chain_group = QGroupBox("编码链配置")
        chain_layout = QVBoxLayout(chain_group)
        
        self.chain_table = QTableWidget()
        self.chain_table.setColumnCount(3)
        self.chain_table.setHorizontalHeaderLabels(["步骤", "操作", "说明"])
        self.chain_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        chain_layout.addWidget(self.chain_table)
        
        btn_layout = QHBoxLayout()
        add_btn = QPushButton("➕ 添加步骤")
        add_btn.clicked.connect(self._add_chain_step)
        btn_layout.addWidget(add_btn)
        
        remove_btn = QPushButton("➖ 删除选中")
        remove_btn.clicked.connect(self._remove_chain_step)
        btn_layout.addWidget(remove_btn)
        
        clear_chain_btn = QPushButton("🗑️ 清空链")
        clear_chain_btn.clicked.connect(self._clear_chain)
        btn_layout.addWidget(clear_chain_btn)
        
        execute_btn = QPushButton("⚡ 执行编码链")
        execute_btn.setStyleSheet("background-color: #4CAF50; color: white; padding: 8px; font-weight: bold;")
        execute_btn.clicked.connect(self._execute_chain)
        btn_layout.addWidget(execute_btn)
        
        chain_layout.addLayout(btn_layout)
        layout.addWidget(chain_group)
        
        # 输出
        output_group = QGroupBox("输出结果")
        output_layout = QVBoxLayout(output_group)
        self.chain_output = QTextEdit()
        self.chain_output.setReadOnly(True)
        self.chain_output.setFont(QFont("Consolas", 10))
        output_layout.addWidget(self.chain_output)
        layout.addWidget(output_group)
        
        return w
        
    def _create_crypto_tab(self) -> QWidget:
        """创建加密/解密标签"""
        w = QWidget()
        layout = QVBoxLayout(w)
        
        # 加密模式选择
        mode_group = QGroupBox("加密模式")
        mode_layout = QHBoxLayout(mode_group)
        
        self.crypto_mode_group = QButtonGroup()
        encrypt_radio = QRadioButton("加密")
        decrypt_radio = QRadioButton("解密")
        encrypt_radio.setChecked(True)
        self.crypto_mode_group.addButton(encrypt_radio, 0)
        self.crypto_mode_group.addButton(decrypt_radio, 1)
        mode_layout.addWidget(encrypt_radio)
        mode_layout.addWidget(decrypt_radio)
        layout.addWidget(mode_group)
        
        # 算法选择
        algo_group = QGroupBox("算法")
        algo_layout = QFormLayout(algo_group)
        
        self.algo_combo = QComboBox()
        self.algo_combo.addItems([
            "AES-128-ECB", "AES-256-ECB", "AES-128-CBC", "AES-256-CBC",
            "DES-ECB", "DES-CBC", "3DES-ECB", "3DES-CBC",
            "RC4", "ChaCha20"
        ])
        algo_layout.addRow("对称加密:", self.algo_combo)
        
        # 密钥
        self.key_input = QLineEdit()
        self.key_input.setPlaceholderText("输入密钥（将自动派生为合适长度）")
        self.key_input.setEchoMode(QLineEdit.Password)
        algo_layout.addRow("密钥:", self.key_input)
        
        # IV（对于CBC模式）
        self.iv_input = QLineEdit()
        self.iv_input.setPlaceholderText("初始化向量（CBC模式需要，可选）")
        self.iv_input.setEchoMode(QLineEdit.Password)
        algo_layout.addRow("IV:", self.iv_input)
        
        layout.addWidget(algo_group)
        
        # 输入输出
        splitter = QSplitter(Qt.Vertical)
        
        input_panel = QWidget()
        input_layout = QVBoxLayout(input_panel)
        input_layout.addWidget(QLabel("输入数据:"))
        self.crypto_input = QTextEdit()
        self.crypto_input.setFont(QFont("Consolas", 10))
        input_layout.addWidget(self.crypto_input)
        splitter.addWidget(input_panel)
        
        output_panel = QWidget()
        output_layout = QVBoxLayout(output_panel)
        output_layout.addWidget(QLabel("输出结果:"))
        self.crypto_output = QTextEdit()
        self.crypto_output.setReadOnly(True)
        self.crypto_output.setFont(QFont("Consolas", 10))
        output_layout.addWidget(self.crypto_output)
        
        crypto_btn = QPushButton("🔐 执行")
        crypto_btn.setStyleSheet("background-color: #2196F3; color: white; padding: 8px; font-weight: bold;")
        crypto_btn.clicked.connect(self._execute_crypto)
        output_layout.addWidget(crypto_btn)
        
        splitter.addWidget(output_panel)
        splitter.setSizes([200, 200])
        
        layout.addWidget(splitter)
        return w
        
    def _create_hash_tab(self) -> QWidget:
        """创建哈希计算标签"""
        w = QWidget()
        layout = QVBoxLayout(w)
        
        # 输入
        input_group = QGroupBox("输入")
        input_layout = QVBoxLayout(input_group)
        
        self.hash_input = QTextEdit()
        self.hash_input.setPlaceholderText("输入要计算哈希的数据...")
        self.hash_input.setFont(QFont("Consolas", 10))
        self.hash_input.setMaximumHeight(150)
        input_layout.addWidget(self.hash_input)
        
        # 文件哈希
        file_layout = QHBoxLayout()
        file_btn = QPushButton("📂 选择文件计算哈希")
        file_btn.clicked.connect(self._hash_file)
        file_layout.addWidget(file_btn)
        
        self.file_path_label = QLabel("未选择文件")
        file_layout.addWidget(self.file_path_label)
        input_layout.addLayout(file_layout)
        
        layout.addWidget(input_group)
        
        # HMAC配置
        hmac_group = QGroupBox("HMAC配置（可选）")
        hmac_layout = QFormLayout(hmac_group)
        
        self.hmac_key = QLineEdit()
        self.hmac_key.setPlaceholderText("HMAC密钥")
        self.hmac_key.setEchoMode(QLineEdit.Password)
        hmac_layout.addRow("密钥:", self.hmac_key)
        
        self.hmac_algo = QComboBox()
        self.hmac_algo.addItems(["MD5", "SHA1", "SHA256", "SHA512"])
        hmac_layout.addRow("算法:", self.hmac_algo)
        
        layout.addWidget(hmac_group)
        
        # 计算按钮
        hash_btn = QPushButton("🔑 计算哈希")
        hash_btn.setStyleSheet("background-color: #4CAF50; color: white; padding: 10px; font-weight: bold; font-size: 12px;")
        hash_btn.clicked.connect(self._calculate_hashes)
        layout.addWidget(hash_btn)
        
        # 输出
        output_group = QGroupBox("哈希结果")
        output_layout = QVBoxLayout(output_group)
        
        self.hash_output = QTextEdit()
        self.hash_output.setReadOnly(True)
        self.hash_output.setFont(QFont("Consolas", 10))
        output_layout.addWidget(self.hash_output)
        
        copy_hash_btn = QPushButton("📋 复制所有哈希")
        copy_hash_btn.clicked.connect(lambda: self.hash_output.copy())
        output_layout.addWidget(copy_hash_btn)
        
        layout.addWidget(output_group)
        return w
        
    def _create_compress_tab(self) -> QWidget:
        """创建压缩/解压缩标签"""
        w = QWidget()
        layout = QVBoxLayout(w)
        
        # 算法选择
        algo_layout = QHBoxLayout()
        algo_layout.addWidget(QLabel("压缩算法:"))
        self.compress_algo = QComboBox()
        self.compress_algo.addItems(list(self.COMPRESSORS.keys()))
        algo_layout.addWidget(self.compress_algo)
        
        compress_btn = QPushButton("📦 压缩")
        compress_btn.clicked.connect(self._compress_data)
        algo_layout.addWidget(compress_btn)
        
        decompress_btn = QPushButton("📂 解压缩")
        decompress_btn.clicked.connect(self._decompress_data)
        algo_layout.addWidget(decompress_btn)
        
        layout.addLayout(algo_layout)
        
        # 输入输出
        splitter = QSplitter(Qt.Vertical)
        
        input_panel = QWidget()
        input_layout = QVBoxLayout(input_panel)
        input_layout.addWidget(QLabel("输入数据:"))
        self.compress_input = QTextEdit()
        self.compress_input.setFont(QFont("Consolas", 10))
        input_layout.addWidget(self.compress_input)
        splitter.addWidget(input_panel)
        
        output_panel = QWidget()
        output_layout = QVBoxLayout(output_panel)
        output_layout.addWidget(QLabel("输出结果:"))
        self.compress_output = QTextEdit()
        self.compress_output.setReadOnly(True)
        self.compress_output.setFont(QFont("Consolas", 10))
        output_layout.addWidget(self.compress_output)
        splitter.addWidget(output_panel)
        
        splitter.setSizes([200, 200])
        layout.addWidget(splitter)
        return w
        
    def _create_format_tab(self) -> QWidget:
        """创建数据格式化标签"""
        w = QWidget()
        layout = QVBoxLayout(w)
        
        # 输入
        input_group = QGroupBox("输入数据")
        input_layout = QVBoxLayout(input_group)
        self.format_input = QTextEdit()
        self.format_input.setPlaceholderText("粘贴JSON、XML、CSV等数据...")
        self.format_input.setFont(QFont("Consolas", 10))
        self.format_input.setMaximumHeight(200)
        input_layout.addWidget(self.format_input)
        layout.addWidget(input_group)
        
        # 格式化选项
        format_layout = QHBoxLayout()
        
        json_btn = QPushButton("📋 JSON格式化")
        json_btn.clicked.connect(self._format_json)
        format_layout.addWidget(json_btn)
        
        xml_btn = QPushButton("📄 XML格式化")
        xml_btn.clicked.connect(self._format_xml)
        format_layout.addWidget(xml_btn)
        
        csv_btn = QPushButton("📊 CSV转表格")
        csv_btn.clicked.connect(self._format_csv)
        format_layout.addWidget(csv_btn)
        
        sql_btn = QPushButton("💾 SQL格式化")
        sql_btn.clicked.connect(self._format_sql)
        format_layout.addWidget(sql_btn)
        
        layout.addLayout(format_layout)
        
        # 输出
        output_group = QGroupBox("格式化结果")
        output_layout = QVBoxLayout(output_group)
        self.format_output = QTextEdit()
        self.format_output.setReadOnly(True)
        self.format_output.setFont(QFont("Consolas", 10))
        output_layout.addWidget(self.format_output)
        layout.addWidget(output_group)
        
        return w
        
    def _create_batch_tab(self) -> QWidget:
        """创建批量处理标签"""
        w = QWidget()
        layout = QVBoxLayout(w)
        
        info = QLabel("支持文件批量处理，选择编码格式后批量转换...")
        info.setStyleSheet("color: #666; padding: 5px;")
        layout.addWidget(info)
        
        file_layout = QHBoxLayout()
        load_btn = QPushButton("📂 加载文件")
        load_btn.clicked.connect(self._load_batch_files)
        file_layout.addWidget(load_btn)
        
        self.batch_combo = QComboBox()
        self.batch_combo.addItems(list(self.CLASSIC_ENCODERS.keys()))
        file_layout.addWidget(self.batch_combo)
        
        process_btn = QPushButton("⚙️ 批量处理")
        process_btn.clicked.connect(self._process_batch)
        file_layout.addWidget(process_btn)
        
        export_btn = QPushButton("💾 导出结果")
        export_btn.clicked.connect(self._export_batch_results)
        file_layout.addWidget(export_btn)
        
        layout.addLayout(file_layout)
        
        # 进度条
        self.batch_progress = QProgressBar()
        self.batch_progress.setVisible(False)
        layout.addWidget(self.batch_progress)
        
        self.batch_output = QTextEdit()
        self.batch_output.setReadOnly(True)
        self.batch_output.setFont(QFont("Consolas", 9))
        layout.addWidget(self.batch_output)
        
        return w
        
    def _auto_analyze(self):
        """自动分析输入数据"""
        text = self.smart_input.toPlainText()
        if not text:
            return
            
        analysis = []
        
        # 检测多种编码格式
        if self._is_base64(text):
            analysis.append("Base64编码")
        if self._is_base64url(text):
            analysis.append("Base64 URL安全")
        if self._is_hex(text):
            analysis.append("Hex编码")
        if self._is_url_encoded(text):
            analysis.append("URL编码")
        if self._is_html_encoded(text):
            analysis.append("HTML编码")
        if self._is_jwt(text):
            analysis.append("JWT令牌")
        if self._is_binary(text):
            analysis.append("二进制")
            
        if analysis:
            self.analysis_info.setText(f"✓ 检测到: {' | '.join(analysis)}")
            self.analysis_info.setStyleSheet("padding: 8px; background-color: #e8f4fd; color: #0277bd; border-radius: 4px;")
        else:
            self.analysis_info.setText("未检测到常见编码格式")
            self.analysis_info.setStyleSheet("padding: 8px; background-color: #f0f0f0; border-radius: 4px;")
        
    def _manual_analyze(self):
        """手动分析并尝试多种解码"""
        text = self.smart_input.toPlainText()
        if not text:
            return
            
        self.decoded_plain.setText("🔍 尝试多种解码方式...\n\n")
        self.decoded_hex.setText("")
        self.decoded_json.setText("")
        
        # 清空表格
        self.decoded_table.setRowCount(0)
        
        row = 0
        for name, func in self.CLASSIC_ENCODERS.items():
            try:
                if "解码" in name:
                    result = func(text.strip())
                    if result and len(result) > 0:
                        # 添加到纯文本视图
                        self.decoded_plain.append(f"━━━ {name} ━━━\n{result[:500]}\n")
                        
                        # 添加到表格
                        self.decoded_table.insertRow(row)
                        self.decoded_table.setItem(row, 0, QTableWidgetItem(name))
                        self.decoded_table.setItem(row, 1, QTableWidgetItem(result[:100]))
                        
                        # 计算置信度
                        confidence = self._calculate_confidence(result)
                        self.decoded_table.setItem(row, 2, QTableWidgetItem(f"{confidence:.0%}"))
                        
                        if confidence > 0.7:
                            self.decoded_table.item(row, 2).setBackground(QColor("#C8E6C9"))
                        elif confidence > 0.4:
                            self.decoded_table.item(row, 2).setBackground(QColor("#FFF9C4"))
                        else:
                            self.decoded_table.item(row, 2).setBackground(QColor("#FFCDD2"))
                        
                        row += 1
            except:
                continue
        
        # Hex视图
        hex_data = ' '.join(f'{ord(c):02x}' for c in text[:200])
        self.decoded_hex.setText(f"Hex视图（前200字符）:\n{hex_data}")
        
        # 尝试JSON格式化
        try:
            json_obj = json.loads(text)
            self.decoded_json.setText(json.dumps(json_obj, indent=2, ensure_ascii=False))
        except:
            self.decoded_json.setText("无法解析为JSON")
            
        self.log("INFO", f"分析完成，找到 {row} 种可能的解码")
        
    def _auto_decode_chain(self):
        """自动解码链 - 尝试多种编码组合"""
        text = self.smart_input.toPlainText()
        if not text:
            return
            
        self.decoded_plain.setText("⛓️ 正在执行自动解码链...\n\n")
        
        current = text.strip()
        chain = []
        max_depth = 5
        
        for i in range(max_depth):
            decoded = self._try_all_decoders(current)
            if decoded:
                chain.append(decoded[0])
                current = decoded[1]
                self.decoded_plain.append(f"✓ 第{i+1}层: {decoded[0]}\n{current[:300]}\n")
            else:
                break
                
        if chain:
            self.decoded_plain.append(f"\n━━━ 解码链 ━━━\n{' → '.join(chain)}")
            self.decoded_plain.append(f"\n最终结果:\n{current}")
            self.log("INFO", f"解码链完成，共 {len(chain)} 层")
        else:
            self.decoded_plain.append("未能找到有效解码链")
            
    def _try_all_decoders(self, data: str) -> Optional[Tuple[str, str]]:
        """尝试所有解码器"""
        decoders = [
            ("Base64 解码", lambda x: base64.b64decode(x).decode('utf-8', errors='ignore')),
            ("Base64 URL解码", lambda x: base64.urlsafe_b64decode(x + '==').decode('utf-8', errors='ignore')),
            ("URL 解码", lambda x: urllib.parse.unquote(x)),
            ("Hex 解码", lambda x: binascii.unhexlify(x.replace(' ', '')).decode('utf-8', errors='ignore')),
            ("HTML 解码", lambda x: html.unescape(x)),
        ]
        
        for name, func in decoders:
            try:
                result = func(data)
                if result and len(result) > 0 and self._is_printable(result):
                    return (name, result)
            except:
                continue
        return None
        
    def _parse_jwt(self):
        """解析JWT令牌"""
        text = self.smart_input.toPlainText().strip()
        if not text:
            return
            
        try:
            parts = text.split('.')
            if len(parts) != 3:
                self.decoded_plain.setText("❌ 无效的JWT格式（需要3个部分）")
                return
                
            # 解码Header
            header = base64.urlsafe_b64decode(parts[0] + '==').decode('utf-8')
            header_json = json.dumps(json.loads(header), indent=2)
            
            # 解码Payload
            payload = base64.urlsafe_b64decode(parts[1] + '==').decode('utf-8')
            payload_json = json.dumps(json.loads(payload), indent=2)
            
            # 签名
            signature = parts[2]
            
            # 显示结果
            self.decoded_plain.setText(f"━━━ JWT Header ━━━\n{header_json}\n\n")
            self.decoded_plain.append(f"━━━ JWT Payload ━━━\n{payload_json}\n\n")
            self.decoded_plain.append(f"━━━ Signature ━━━\n{signature}")
            
            # 分析payload中的声明
            payload_data = json.loads(payload)
            analysis = []
            
            if 'exp' in payload_data:
                import time
                exp_time = payload_data['exp']
                if exp_time < time.time():
                    analysis.append("⚠️ 令牌已过期")
                else:
                    analysis.append(f"✓ 令牌有效，过期时间: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(exp_time))}")
                    
            if 'iat' in payload_data:
                import time
                iat_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(payload_data['iat']))
                analysis.append(f"签发时间: {iat_time}")
                
            if 'sub' in payload_data:
                analysis.append(f"主题: {payload_data['sub']}")
                
            if analysis:
                self.decoded_plain.append(f"\n━━━ 分析 ━━━\n" + "\n".join(analysis))
                
            self.log("INFO", "JWT解析完成")
            
        except Exception as e:
            self.decoded_plain.setText(f"❌ JWT解析失败: {str(e)}")
            self.log("ERROR", f"JWT解析错误: {e}")
        
    def _do_convert(self):
        """执行转换"""
        text = self.classic_input.toPlainText()
        encoder_name = self.encode_combo.currentText()
        
        if not text:
            return
            
        try:
            func = self.CLASSIC_ENCODERS[encoder_name]
            result = func(text)
            
            self.classic_output.setText(result)
            self.log("INFO", f"完成 {encoder_name} 转换")
        except Exception as e:
            self.classic_output.setText(f"❌ 转换失败: {str(e)}")
            self.log("ERROR", f"转换错误: {e}")
            
    def _swap_classic(self):
        """交换输入输出"""
        output = self.classic_output.toPlainText()
        if output:
            self.classic_input.setText(output)
            
    def _save_classic_result(self):
        """保存经典编码结果"""
        result = self.classic_output.toPlainText()
        if not result:
            return
            
        filename, _ = QFileDialog.getSaveFileName(None, "保存结果", "", "Text Files (*.txt);;All Files (*)")
        if filename:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(result)
            self.log("INFO", f"结果已保存到 {filename}")
            
    def _add_chain_step(self):
        """添加编码链步骤"""
        row = self.chain_table.rowCount()
        self.chain_table.insertRow(row)
        
        # 步骤号
        self.chain_table.setItem(row, 0, QTableWidgetItem(str(row + 1)))
        
        # 操作选择
        combo = QComboBox()
        combo.addItems(list(self.CLASSIC_ENCODERS.keys()))
        self.chain_table.setCellWidget(row, 1, combo)
        
        # 说明
        self.chain_table.setItem(row, 2, QTableWidgetItem(""))
        
    def _remove_chain_step(self):
        """删除选中的编码链步骤"""
        current_row = self.chain_table.currentRow()
        if current_row >= 0:
            self.chain_table.removeRow(current_row)
            # 重新编号
            for i in range(self.chain_table.rowCount()):
                self.chain_table.setItem(i, 0, QTableWidgetItem(str(i + 1)))
                
    def _clear_chain(self):
        """清空编码链"""
        self.chain_table.setRowCount(0)
        self.chain_output.clear()
        
    def _execute_chain(self):
        """执行编码链"""
        text = self.chain_input.toPlainText()
        if not text:
            return
            
        if self.chain_table.rowCount() == 0:
            QMessageBox.warning(None, "警告", "请先添加编码链步骤")
            return
            
        self.chain_output.setText("⛓️ 执行编码链...\n\n")
        
        current = text
        for i in range(self.chain_table.rowCount()):
            combo = self.chain_table.cellWidget(i, 1)
            if combo:
                encoder_name = combo.currentText()
                try:
                    func = self.CLASSIC_ENCODERS[encoder_name]
                    current = func(current)
                    self.chain_output.append(f"步骤 {i+1}: {encoder_name} ✓")
                except Exception as e:
                    self.chain_output.append(f"步骤 {i+1}: {encoder_name} ❌ - {str(e)}")
                    break
                    
        self.chain_output.append(f"\n━━━ 最终结果 ━━━\n{current}")
        self.log("INFO", f"编码链执行完成，共 {self.chain_table.rowCount()} 步")
        
    def _execute_crypto(self):
        """执行加密/解密"""
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            from cryptography.hazmat.backends import default_backend
            from cryptography.hazmat.primitives import padding
        except ImportError:
            self.crypto_output.setText("❌ 需要安装 cryptography 库\npip install cryptography")
            return
            
        text = self.crypto_input.toPlainText()
        key = self.key_input.text()
        iv = self.iv_input.text()
        algo = self.algo_combo.currentText()
        mode = self.crypto_mode_group.checkedId()  # 0=加密, 1=解密
        
        if not text or not key:
            QMessageBox.warning(None, "警告", "请输入数据和密钥")
            return
            
        try:
            # 派生密钥
            key_bytes = hashlib.sha256(key.encode()).digest()
            
            # 根据算法选择密钥长度
            if "128" in algo:
                key_bytes = key_bytes[:16]
            elif "256" in algo or "3DES" in algo:
                key_bytes = key_bytes[:24] if "3DES" in algo else key_bytes[:32]
            elif "DES" in algo:
                key_bytes = key_bytes[:8]
                
            # 处理IV
            iv_bytes = hashlib.md5(iv.encode()).digest()[:16] if iv else b'\x00' * 16
            
            # 选择算法
            if "AES" in algo:
                cipher_algo = algorithms.AES
            elif "DES" in algo and "3" not in algo:
                cipher_algo = algorithms.TripleDES if "3DES" in algo else algorithms.Cipher
            elif "RC4" in algo:
                cipher_algo = algorithms.ARC4
            else:
                raise ValueError(f"不支持的算法: {algo}")
                
            # 执行加密/解密
            if mode == 0:  # 加密
                # PKCS7填充
                padder = padding.PKCS7(128).padder()
                padded_data = padder.update(text.encode()) + padder.finalize()
                
                if "ECB" in algo:
                    cipher = Cipher(cipher_algo(key_bytes), modes.ECB(), backend=default_backend())
                else:
                    cipher = Cipher(cipher_algo(key_bytes), modes.CBC(iv_bytes), backend=default_backend())
                    
                encryptor = cipher.encryptor()
                result = encryptor.update(padded_data) + encryptor.finalize()
                self.crypto_output.setText(f"加密结果（Base64）:\n{base64.b64encode(result).decode()}\n\n加密结果（Hex）:\n{binascii.hexlify(result).decode()}")
            else:  # 解密
                # 尝试Base64或Hex解码
                try:
                    encrypted_data = base64.b64decode(text)
                except:
                    encrypted_data = binascii.unhexlify(text.replace(' ', ''))
                    
                if "ECB" in algo:
                    cipher = Cipher(cipher_algo(key_bytes), modes.ECB(), backend=default_backend())
                else:
                    cipher = Cipher(cipher_algo(key_bytes), modes.CBC(iv_bytes), backend=default_backend())
                    
                decryptor = cipher.decryptor()
                decrypted = decryptor.update(encrypted_data) + decryptor.finalize()
                
                # 去除填充
                unpadder = padding.PKCS7(128).unpadder()
                result = unpadder.update(decrypted) + unpadder.finalize()
                self.crypto_output.setText(f"解密结果:\n{result.decode('utf-8')}")
                
            self.log("INFO", f"{algo} {'加密' if mode == 0 else '解密'}完成")
            
        except Exception as e:
            self.crypto_output.setText(f"❌ 操作失败: {str(e)}")
            self.log("ERROR", f"加密/解密错误: {e}")
        
    def _calculate_hashes(self):
        """计算哈希值"""
        text = self.hash_input.toPlainText()
        if not text:
            return
            
        data = text.encode('utf-8')
        
        results = []
        results.append("━━━ 标准哈希 ━━━")
        results.append(f"MD5:       {hashlib.md5(data).hexdigest()}")
        results.append(f"SHA1:      {hashlib.sha1(data).hexdigest()}")
        results.append(f"SHA224:    {hashlib.sha224(data).hexdigest()}")
        results.append(f"SHA256:    {hashlib.sha256(data).hexdigest()}")
        results.append(f"SHA384:    {hashlib.sha384(data).hexdigest()}")
        results.append(f"SHA512:    {hashlib.sha512(data).hexdigest()}")
        
        try:
            results.append(f"SHA3-224:  {hashlib.sha3_224(data).hexdigest()}")
            results.append(f"SHA3-256:  {hashlib.sha3_256(data).hexdigest()}")
            results.append(f"SHA3-384:  {hashlib.sha3_384(data).hexdigest()}")
            results.append(f"SHA3-512:  {hashlib.sha3_512(data).hexdigest()}")
        except:
            pass
            
        # HMAC
        hmac_key = self.hmac_key.text()
        if hmac_key:
            results.append("\n━━━ HMAC ━━━")
            hmac_algo = self.hmac_algo.currentText()
            hmac_func = getattr(hashlib, f'hmac_{hmac_algo.lower()}', None)
            if hmac_func:
                hmac_result = hmac.new(hmac_key.encode(), data, hmac_func).hexdigest()
                results.append(f"HMAC-{hmac_algo}: {hmac_result}")
            else:
                hmac_result = hmac.new(hmac_key.encode(), data, hmac_algo.lower()).hexdigest()
                results.append(f"HMAC-{hmac_algo}: {hmac_result}")
        
        # 其他哈希
        try:
            import hashlib
            results.append("\n━━━ 其他哈希 ━━━")
            results.append(f"BLAKE2b:   {hashlib.blake2b(data).hexdigest()}")
            results.append(f"BLAKE2s:   {hashlib.blake2s(data).hexdigest()}")
        except:
            pass
            
        self.hash_output.setText("\n".join(results))
        self.log("INFO", "哈希计算完成")
        
    def _hash_file(self):
        """计算文件哈希"""
        filename, _ = QFileDialog.getOpenFileName(None, "选择文件", "", "All Files (*)")
        if not filename:
            return
            
        self.file_path_label.setText(filename)
        self.hash_output.setText("⏳ 正在计算文件哈希...")
        
        try:
            # 计算大文件哈希
            md5 = hashlib.md5()
            sha1 = hashlib.sha1()
            sha256 = hashlib.sha256()
            
            with open(filename, 'rb') as f:
                while True:
                    chunk = f.read(8192)
                    if not chunk:
                        break
                    md5.update(chunk)
                    sha1.update(chunk)
                    sha256.update(chunk)
                    
            results = []
            results.append(f"文件: {filename}")
            results.append(f"\nMD5:    {md5.hexdigest()}")
            results.append(f"SHA1:   {sha1.hexdigest()}")
            results.append(f"SHA256: {sha256.hexdigest()}")
            
            self.hash_output.setText("\n".join(results))
            self.log("INFO", f"文件哈希计算完成: {filename}")
            
        except Exception as e:
            self.hash_output.setText(f"❌ 计算失败: {str(e)}")
            self.log("ERROR", f"文件哈希错误: {e}")
        
    def _compress_data(self):
        """压缩数据"""
        text = self.compress_input.toPlainText()
        if not text:
            return
            
        algo = self.compress_algo.currentText()
        
        try:
            compress_func, _ = self.COMPRESSORS[algo]
            result = compress_func(text)
            self.compress_output.setText(f"压缩结果（Base64编码）:\n{result}")
            self.log("INFO", f"{algo} 压缩完成")
        except Exception as e:
            self.compress_output.setText(f"❌ 压缩失败: {str(e)}")
            self.log("ERROR", f"压缩错误: {e}")
            
    def _decompress_data(self):
        """解压缩数据"""
        text = self.compress_input.toPlainText()
        if not text:
            return
            
        algo = self.compress_algo.currentText()
        
        try:
            _, decompress_func = self.COMPRESSORS[algo]
            result = decompress_func(text)
            self.compress_output.setText(f"解压缩结果:\n{result}")
            self.log("INFO", f"{algo} 解压缩完成")
        except Exception as e:
            self.compress_output.setText(f"❌ 解压缩失败: {str(e)}")
            self.log("ERROR", f"解压缩错误: {e}")
        
    def _format_json(self):
        """格式化JSON"""
        text = self.format_input.toPlainText()
        if not text:
            return
            
        try:
            json_obj = json.loads(text)
            formatted = json.dumps(json_obj, indent=2, ensure_ascii=False)
            self.format_output.setText(formatted)
            self.log("INFO", "JSON格式化完成")
        except Exception as e:
            self.format_output.setText(f"❌ JSON解析失败: {str(e)}")
            self.log("ERROR", f"JSON格式化错误: {e}")
            
    def _format_xml(self):
        """格式化XML"""
        text = self.format_input.toPlainText()
        if not text:
            return
            
        try:
            import xml.dom.minidom
            dom = xml.dom.minidom.parseString(text)
            formatted = dom.toprettyxml(indent="  ")
            self.format_output.setText(formatted)
            self.log("INFO", "XML格式化完成")
        except Exception as e:
            self.format_output.setText(f"❌ XML解析失败: {str(e)}")
            self.log("ERROR", f"XML格式化错误: {e}")
            
    def _format_csv(self):
        """格式化CSV"""
        text = self.format_input.toPlainText()
        if not text:
            return
            
        try:
            import csv
            import io
            
            reader = csv.reader(io.StringIO(text))
            rows = list(reader)
            
            # 计算列宽
            col_widths = [max(len(str(cell)) for cell in col) for col in zip(*rows)]
            
            # 格式化输出
            formatted = []
            for row in rows:
                formatted_row = " | ".join(str(cell).ljust(col_widths[i]) for i, cell in enumerate(row))
                formatted.append(formatted_row)
                
            self.format_output.setText("\n".join(formatted))
            self.log("INFO", "CSV格式化完成")
        except Exception as e:
            self.format_output.setText(f"❌ CSV解析失败: {str(e)}")
            self.log("ERROR", f"CSV格式化错误: {e}")
            
    def _format_sql(self):
        """格式化SQL"""
        text = self.format_input.toPlainText()
        if not text:
            return
            
        # 简单SQL格式化
        keywords = ['SELECT', 'FROM', 'WHERE', 'AND', 'OR', 'ORDER BY', 'GROUP BY', 
                   'INSERT', 'UPDATE', 'DELETE', 'JOIN', 'LEFT', 'RIGHT', 'INNER', 'OUTER']
        
        formatted = text
        for keyword in keywords:
            formatted = formatted.replace(keyword, f'\n{keyword}')
            
        self.format_output.setText(formatted.strip())
        self.log("INFO", "SQL格式化完成")
        
    def _load_batch_files(self):
        """加载批量文件"""
        filenames, _ = QFileDialog.getOpenFileNames(None, "选择文件", "", "All Files (*)")
        if filenames:
            self.batch_output.setText(f"✓ 已加载 {len(filenames)} 个文件\n")
            for fn in filenames:
                self.batch_output.append(f"  - {fn}")
                
    def _process_batch(self):
        """批量处理"""
        encoder_name = self.batch_combo.currentText()
        self.batch_output.append(f"\n⚙️ 开始批量处理: {encoder_name}")
        
        self.batch_progress.setVisible(True)
        self.batch_progress.setValue(0)
        
        # 这里应该从文件列表读取并处理
        self.batch_output.append("\n批量处理功能待完善...")
        self.batch_progress.setVisible(False)
        
    def _export_batch_results(self):
        """导出批量处理结果"""
        filename, _ = QFileDialog.getSaveFileName(None, "导出结果", "", "Text Files (*.txt);;CSV Files (*.csv)")
        if filename:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(self.batch_output.toPlainText())
            self.log("INFO", f"批量结果已导出到 {filename}")
            QMessageBox.information(None, "成功", f"结果已导出到 {filename}")
        
    def _clear_smart(self):
        """清空智能解码器"""
        self.smart_input.clear()
        self.decoded_plain.clear()
        self.decoded_hex.clear()
        self.decoded_json.clear()
        self.decoded_table.setRowCount(0)
        self.analysis_info.setText("粘贴数据后进行智能分析...")
        
    def _is_base64(self, s: str) -> bool:
        """判断是否base64"""
        s = s.strip()
        if len(s) < 4 or len(s) % 4 != 0:
            return False
        return bool(re.match(r'^[A-Za-z0-9+/]*={0,2}$', s))
        
    def _is_base64url(self, s: str) -> bool:
        """判断是否base64url"""
        s = s.strip()
        return bool(re.match(r'^[A-Za-z0-9_-]*={0,2}$', s)) and len(s) > 10
        
    def _is_hex(self, s: str) -> bool:
        """判断是否hex"""
        s = s.strip().replace(' ', '')
        return bool(re.match(r'^[0-9A-Fa-f]+$', s)) and len(s) > 4
        
    def _is_url_encoded(self, s: str) -> bool:
        """判断是否url编码"""
        return '%' in s and len(s) > 5
        
    def _is_html_encoded(self, s: str) -> bool:
        """判断是否html编码"""
        return bool(re.search(r'&[a-zA-Z]+;|&#\d+;|&#x[0-9a-fA-F]+;', s))
        
    def _is_jwt(self, s: str) -> bool:
        """判断是否JWT"""
        parts = s.strip().split('.')
        return len(parts) == 3 and all(len(p) > 0 for p in parts)
        
    def _is_binary(self, s: str) -> bool:
        """判断是否二进制"""
        s = s.strip().replace(' ', '')
        return bool(re.match(r'^[01]+$', s)) and len(s) > 8
        
    def _is_printable(self, s: str) -> bool:
        """判断是否可打印文本"""
        if not s or len(s) == 0:
            return False
        printable_ratio = sum(1 for c in s if 32 <= ord(c) < 127 or c in '\n\r\t') / len(s)
        return printable_ratio > 0.7
        
    def _calculate_confidence(self, text: str) -> float:
        """计算解码结果置信度"""
        if not text:
            return 0.0
            
        # 基于可打印字符比例
        printable_ratio = sum(1 for c in text if 32 <= ord(c) < 127 or c in '\n\r\t') / len(text)
        
        # 基于常见单词
        common_words = ['the', 'and', 'for', 'are', 'but', 'not', 'you', 'all', 'can', 'had',
                       'her', 'was', 'one', 'our', 'out', 'day', 'get', 'has', 'him', 'his',
                       'how', 'its', 'may', 'new', 'now', 'old', 'see', 'two', 'who', 'boy',
                       'did', 'let', 'say', 'she', 'too', 'use', 'function', 'var', 'const',
                       'import', 'from', 'class', 'def', 'if', 'else', 'return', 'true', 'false']
        
        word_count = 0
        text_lower = text.lower()
        for word in common_words:
            if word in text_lower:
                word_count += 1
                
        word_ratio = min(word_count / 10, 1.0)  # 最多1.0
        
        # 综合置信度
        confidence = (printable_ratio * 0.6) + (word_ratio * 0.4)
        return min(confidence, 1.0)
