"""
Comparer (对比器)模块 - 专家级响应/请求对比工具
支持字节级对比、语义差异分析、多视图模式、详细统计报告
专为10年+经验白帽子、安全公司、SRC挖掘设计
"""

from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field
import logging
import difflib
import hashlib
import json
import re
from collections import Counter
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QSplitter, QTabWidget,
    QPushButton, QLabel, QLineEdit, QTextEdit, QComboBox,
    QGroupBox, QFormLayout, QCheckBox, QFileDialog, QTableWidget,
    QTableWidgetItem, QHeaderView, QMessageBox, QProgressBar,
    QRadioButton, QButtonGroup, QScrollArea, QFrame, QToolBar,
    QMenu, QSpinBox
)
from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QColor, QFont, QTextCharFormat, QTextCursor, QActionGroup, QAction

from .base import ModuleBase

logger = logging.getLogger(__name__)


@dataclass
class DiffStats:
    """差异统计"""
    total_lines_a: int = 0
    total_lines_b: int = 0
    added_lines: int = 0
    removed_lines: int = 0
    modified_lines: int = 0
    unchanged_lines: int = 0
    added_bytes: int = 0
    removed_bytes: int = 0
    similarity_ratio: float = 0.0
    hash_a: str = ""
    hash_b: str = ""
    headers_diff: Dict[str, str] = field(default_factory=dict)
    status_code_diff: Tuple[Optional[int], Optional[int]] = (None, None)


class ComparerWorker(QThread):
    """对比工作线程 - 处理大型对比任务"""
    progress = Signal(int)
    complete = Signal(object)
    error = Signal(str)
    
    def __init__(self, func, *args, **kwargs):
        super().__init__()
        self.func = func
        self.args = args
        self.kwargs = kwargs
        
    def run(self):
        try:
            result = self.func(*self.args, **self.kwargs)
            self.complete.emit(result)
        except Exception as e:
            self.error.emit(str(e))


class ComparerModule(ModuleBase):
    """对比器模块 - 专家级实现"""
    
    def __init__(self):
        super().__init__("Comparer", "专家级请求/响应对比工具")
        self._comparison_history: List = []
        
    def _create_ui(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # 工具栏
        toolbar = self._create_toolbar()
        layout.addWidget(toolbar)
        
        # 主标签页
        main_tab = QTabWidget()
        
        # 文本对比标签
        text_compare_tab = self._create_text_compare_tab()
        main_tab.addTab(text_compare_tab, "📝 文本对比")
        
        # 字节对比标签
        byte_compare_tab = self._create_byte_compare_tab()
        main_tab.addTab(byte_compare_tab, "🔢 字节对比")
        
        # HTTP对比标签
        http_compare_tab = self._create_http_compare_tab()
        main_tab.addTab(http_compare_tab, "🌐 HTTP对比")
        
        # JSON/XML对比标签
        structured_compare_tab = self._create_structured_compare_tab()
        main_tab.addTab(structured_compare_tab, "📋 结构化对比")
        
        # 历史对比标签
        history_tab = self._create_history_tab()
        main_tab.addTab(history_tab, "📚 历史记录")
        
        layout.addWidget(main_tab)
        return widget
        
    def _create_toolbar(self) -> QWidget:
        """创建工具栏"""
        toolbar = QWidget()
        toolbar_layout = QHBoxLayout(toolbar)
        toolbar_layout.setContentsMargins(0, 5, 0, 5)
        
        # 快速加载
        load_a_btn = QPushButton("📂 加载A")
        load_a_btn.clicked.connect(lambda: self._load_file(self.text_a))
        toolbar_layout.addWidget(load_a_btn)
        
        load_b_btn = QPushButton("📂 加载B")
        load_b_btn.clicked.connect(lambda: self._load_file(self.text_b))
        toolbar_layout.addWidget(load_b_btn)
        
        swap_btn = QPushButton("🔃 交换A/B")
        swap_btn.clicked.connect(self._swap_texts)
        toolbar_layout.addWidget(swap_btn)
        
        toolbar_layout.addWidget(QLabel("|"))
        
        # 快速对比按钮
        quick_btn = QPushButton("⚡ 快速对比")
        quick_btn.setStyleSheet("background-color: #4CAF50; color: white; padding: 5px 15px; font-weight: bold;")
        quick_btn.clicked.connect(self._quick_compare)
        toolbar_layout.addWidget(quick_btn)
        
        save_btn = QPushButton("💾 保存报告")
        save_btn.clicked.connect(self._save_report)
        toolbar_layout.addWidget(save_btn)
        
        toolbar_layout.addStretch()
        
        return toolbar
        
    def _create_text_compare_tab(self) -> QWidget:
        """创建文本对比标签"""
        w = QWidget()
        layout = QVBoxLayout(w)
        
        # 对比配置
        config_group = QGroupBox("对比配置")
        config_layout = QFormLayout(config_group)
        
        # 对比模式
        mode_layout = QHBoxLayout()
        self.mode_combo = QComboBox()
        self.mode_combo.addItems([
            "统一差异 (Unified Diff)",
            "上下文差异 (Context Diff)",
            "HTML差异 (HTML Diff)",
            "并排对比 (Side-by-Side)",
            "语义差异 (Semantic Diff)"
        ])
        mode_layout.addWidget(self.mode_combo)
        config_layout.addRow("对比模式:", mode_layout)
        
        # 选项
        options_layout = QHBoxLayout()
        self.ignore_whitespace = QCheckBox("忽略空白")
        self.ignore_whitespace.setChecked(True)
        self.ignore_case = QCheckBox("忽略大小写")
        self.ignore_comments = QCheckBox("忽略注释")
        self.ignore_empty_lines = QCheckBox("忽略空行")
        
        options_layout.addWidget(self.ignore_whitespace)
        options_layout.addWidget(self.ignore_case)
        options_layout.addWidget(self.ignore_comments)
        options_layout.addWidget(self.ignore_empty_lines)
        config_layout.addRow("选项:", options_layout)
        
        layout.addWidget(config_group)
        
        # 输入区
        splitter = QSplitter(Qt.Horizontal)
        
        # 文本A
        group_a = QGroupBox("数据 A")
        layout_a = QVBoxLayout(group_a)
        
        a_info_layout = QHBoxLayout()
        a_info_layout.addWidget(QLabel("行数:"))
        self.line_count_a = QLabel("0")
        a_info_layout.addWidget(self.line_count_a)
        a_info_layout.addWidget(QLabel("字节:"))
        self.byte_count_a = QLabel("0")
        a_info_layout.addWidget(self.byte_count_a)
        a_info_layout.addStretch()
        layout_a.addLayout(a_info_layout)
        
        self.text_a = QTextEdit()
        self.text_a.setPlaceholderText("粘贴或加载第一个文本/响应/请求...")
        self.text_a.setFont(QFont("Consolas", 9))
        self.text_a.textChanged.connect(lambda: self._update_counts(self.text_a, self.line_count_a, self.byte_count_a))
        layout_a.addWidget(self.text_a)
        splitter.addWidget(group_a)
        
        # 文本B
        group_b = QGroupBox("数据 B")
        layout_b = QVBoxLayout(group_b)
        
        b_info_layout = QHBoxLayout()
        b_info_layout.addWidget(QLabel("行数:"))
        self.line_count_b = QLabel("0")
        b_info_layout.addWidget(self.line_count_b)
        b_info_layout.addWidget(QLabel("字节:"))
        self.byte_count_b = QLabel("0")
        b_info_layout.addWidget(self.byte_count_b)
        b_info_layout.addStretch()
        layout_b.addLayout(b_info_layout)
        
        self.text_b = QTextEdit()
        self.text_b.setPlaceholderText("粘贴或加载第二个文本/响应/请求...")
        self.text_b.setFont(QFont("Consolas", 9))
        self.text_b.textChanged.connect(lambda: self._update_counts(self.text_b, self.line_count_b, self.byte_count_b))
        layout_b.addWidget(self.text_b)
        splitter.addWidget(group_b)
        
        splitter.setSizes([500, 500])
        layout.addWidget(splitter)
        
        # 对比按钮
        compare_btn = QPushButton("🔍 开始对比")
        compare_btn.setStyleSheet("background-color: #2196F3; color: white; padding: 10px; font-weight: bold; font-size: 12px;")
        compare_btn.clicked.connect(self._compare)
        layout.addWidget(compare_btn)
        
        # 结果标签页
        result_tabs = QTabWidget()
        
        # 统一差异视图
        self.unified_diff = QTextEdit()
        self.unified_diff.setReadOnly(True)
        self.unified_diff.setFont(QFont("Consolas", 9))
        result_tabs.addTab(self.unified_diff, "📊 统一差异")
        
        # 并排视图
        self.side_by_side = QSplitter(Qt.Horizontal)
        self.left_view = QTextEdit()
        self.left_view.setReadOnly(True)
        self.left_view.setFont(QFont("Consolas", 9))
        self.right_view = QTextEdit()
        self.right_view.setReadOnly(True)
        self.right_view.setFont(QFont("Consolas", 9))
        self.side_by_side.addWidget(self.left_view)
        self.side_by_side.addWidget(self.right_view)
        result_tabs.addTab(self.side_by_side, "⬌ 并排视图")
        
        # 统计信息
        self.stats_view = QTextEdit()
        self.stats_view.setReadOnly(True)
        self.stats_view.setFont(QFont("Consolas", 9))
        result_tabs.addTab(self.stats_view, "📈 统计分析")
        
        # 差异表格
        self.diff_table = QTableWidget()
        self.diff_table.setColumnCount(4)
        self.diff_table.setHorizontalHeaderLabels(["类型", "行号A", "行号B", "内容"])
        self.diff_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        result_tabs.addTab(self.diff_table, "📋 差异表格")
        
        layout.addWidget(result_tabs)
        
        return w
        
    def _create_byte_compare_tab(self) -> QWidget:
        """创建字节对比标签"""
        w = QWidget()
        layout = QVBoxLayout(w)
        
        info = QLabel("字节级对比：逐字节比较，适用于二进制文件或精确对比")
        info.setStyleSheet("color: #666; padding: 5px; background-color: #f9f9f9; border-radius: 4px;")
        layout.addWidget(info)
        
        # 输入
        input_layout = QHBoxLayout()
        input_layout.addWidget(QLabel("数据A:"))
        self.byte_input_a = QLineEdit()
        self.byte_input_a.setPlaceholderText("输入或粘贴Hex数据...")
        input_layout.addWidget(self.byte_input_a)
        
        input_layout.addWidget(QLabel("数据B:"))
        self.byte_input_b = QLineEdit()
        self.byte_input_b.setPlaceholderText("输入或粘贴Hex数据...")
        input_layout.addWidget(self.byte_input_b)
        
        byte_compare_btn = QPushButton("🔍 字节对比")
        byte_compare_btn.clicked.connect(self._compare_bytes)
        input_layout.addWidget(byte_compare_btn)
        
        layout.addLayout(input_layout)
        
        # 结果
        result_tabs = QTabWidget()
        
        # Hex视图
        self.hex_diff_view = QTextEdit()
        self.hex_diff_view.setReadOnly(True)
        self.hex_diff_view.setFont(QFont("Consolas", 10))
        result_tabs.addTab(self.hex_diff_view, "🔢 Hex差异")
        
        # 字节统计
        self.byte_stats_view = QTextEdit()
        self.byte_stats_view.setReadOnly(True)
        self.byte_stats_view.setFont(QFont("Consolas", 9))
        result_tabs.addTab(self.byte_stats_view, "📊 字节统计")
        
        # 字节分布
        self.byte_distribution = QTextEdit()
        self.byte_distribution.setReadOnly(True)
        self.byte_distribution.setFont(QFont("Consolas", 9))
        result_tabs.addTab(self.byte_distribution, "📈 字节分布")
        
        layout.addWidget(result_tabs)
        
        return w
        
    def _create_http_compare_tab(self) -> QWidget:
        """创建HTTP对比标签"""
        w = QWidget()
        layout = QVBoxLayout(w)
        
        info = QLabel("HTTP请求/响应对比：自动解析并对比请求行、状态码、头部、主体")
        info.setStyleSheet("color: #666; padding: 5px; background-color: #f9f9f9; border-radius: 4px;")
        layout.addWidget(info)
        
        # HTTP输入
        http_splitter = QSplitter(Qt.Horizontal)
        
        http_a_group = QGroupBox("HTTP A")
        http_a_layout = QVBoxLayout(http_a_group)
        self.http_input_a = QTextEdit()
        self.http_input_a.setPlaceholderText("粘贴完整的HTTP请求或响应A...")
        self.http_input_a.setFont(QFont("Consolas", 9))
        http_a_layout.addWidget(self.http_input_a)
        http_splitter.addWidget(http_a_group)
        
        http_b_group = QGroupBox("HTTP B")
        http_b_layout = QVBoxLayout(http_b_group)
        self.http_input_b = QTextEdit()
        self.http_input_b.setPlaceholderText("粘贴完整的HTTP请求或响应B...")
        self.http_input_b.setFont(QFont("Consolas", 9))
        http_b_layout.addWidget(self.http_input_b)
        http_splitter.addWidget(http_b_group)
        
        http_splitter.setSizes([500, 500])
        layout.addWidget(http_splitter)
        
        http_compare_btn = QPushButton("🌐 HTTP对比")
        http_compare_btn.setStyleSheet("background-color: #FF9800; color: white; padding: 10px; font-weight: bold;")
        http_compare_btn.clicked.connect(self._compare_http)
        layout.addWidget(http_compare_btn)
        
        # HTTP对比结果
        http_result_tabs = QTabWidget()
        
        # 请求行对比
        self.request_line_diff = QTextEdit()
        self.request_line_diff.setReadOnly(True)
        self.request_line_diff.setFont(QFont("Consolas", 9))
        http_result_tabs.addTab(self.request_line_diff, "📝 请求行")
        
        # 头部对比
        self.headers_diff = QTextEdit()
        self.headers_diff.setReadOnly(True)
        self.headers_diff.setFont(QFont("Consolas", 9))
        http_result_tabs.addTab(self.headers_diff, "📋 头部对比")
        
        # 主体对比
        self.body_diff = QTextEdit()
        self.body_diff.setReadOnly(True)
        self.body_diff.setFont(QFont("Consolas", 9))
        http_result_tabs.addTab(self.body_diff, "📄 主体对比")
        
        # 安全分析
        self.security_analysis = QTextEdit()
        self.security_analysis.setReadOnly(True)
        self.security_analysis.setFont(QFont("Consolas", 9))
        http_result_tabs.addTab(self.security_analysis, "🔒 安全分析")
        
        layout.addWidget(http_result_tabs)
        
        return w
        
    def _create_structured_compare_tab(self) -> QWidget:
        """创建结构化数据对比标签"""
        w = QWidget()
        layout = QVBoxLayout(w)
        
        info = QLabel("JSON/XML结构化对比：智能解析并对比键值对、数组、嵌套结构")
        info.setStyleSheet("color: #666; padding: 5px; background-color: #f9f9f9; border-radius: 4px;")
        layout.addWidget(info)
        
        # 输入
        struct_splitter = QSplitter(Qt.Horizontal)
        
        struct_a_group = QGroupBox("数据 A")
        struct_a_layout = QVBoxLayout(struct_a_group)
        self.struct_input_a = QTextEdit()
        self.struct_input_a.setPlaceholderText("粘贴JSON或XML数据A...")
        self.struct_input_a.setFont(QFont("Consolas", 9))
        struct_a_layout.addWidget(self.struct_input_a)
        struct_splitter.addWidget(struct_a_group)
        
        struct_b_group = QGroupBox("数据 B")
        struct_b_layout = QVBoxLayout(struct_b_group)
        self.struct_input_b = QTextEdit()
        self.struct_input_b.setPlaceholderText("粘贴JSON或XML数据B...")
        self.struct_input_b.setFont(QFont("Consolas", 9))
        struct_b_layout.addWidget(self.struct_input_b)
        struct_splitter.addWidget(struct_b_group)
        
        struct_splitter.setSizes([500, 500])
        layout.addWidget(struct_splitter)
        
        struct_compare_btn = QPushButton("📋 结构化对比")
        struct_compare_btn.setStyleSheet("background-color: #9C27B0; color: white; padding: 10px; font-weight: bold;")
        struct_compare_btn.clicked.connect(self._compare_structured)
        layout.addWidget(struct_compare_btn)
        
        # 结果
        struct_result_tabs = QTabWidget()
        
        self.struct_diff_view = QTextEdit()
        self.struct_diff_view.setReadOnly(True)
        self.struct_diff_view.setFont(QFont("Consolas", 9))
        struct_result_tabs.addTab(self.struct_diff_view, "📊 结构差异")
        
        self.struct_tree_view = QTextEdit()
        self.struct_tree_view.setReadOnly(True)
        self.struct_tree_view.setFont(QFont("Consolas", 9))
        struct_result_tabs.addTab(self.struct_tree_view, "🌳 树形视图")
        
        layout.addWidget(struct_result_tabs)
        
        return w
        
    def _create_history_tab(self) -> QWidget:
        """创建历史记录标签"""
        w = QWidget()
        layout = QVBoxLayout(w)
        
        # 历史表格
        self.history_table = QTableWidget()
        self.history_table.setColumnCount(5)
        self.history_table.setHorizontalHeaderLabels(["时间", "对比模式", "相似度", "差异数", "操作"])
        self.history_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        layout.addWidget(self.history_table)
        
        # 操作按钮
        btn_layout = QHBoxLayout()
        clear_history_btn = QPushButton("🗑️ 清空历史")
        clear_history_btn.clicked.connect(self._clear_history)
        btn_layout.addWidget(clear_history_btn)
        
        export_history_btn = QPushButton("💾 导出历史")
        export_history_btn.clicked.connect(self._export_history)
        btn_layout.addWidget(export_history_btn)
        
        layout.addLayout(btn_layout)
        
        return w
        
    def _update_counts(self, text_edit, line_label, byte_label):
        """更新行数和字节计数"""
        text = text_edit.toPlainText()
        lines = text.count('\n') + (1 if text else 0)
        bytes_count = len(text.encode('utf-8'))
        line_label.setText(str(lines))
        byte_label.setText(str(bytes_count))
        
    def _load_file(self, target_edit):
        """加载文件"""
        filename, _ = QFileDialog.getOpenFileName(None, "选择文件", "", "All Files (*)")
        if filename:
            try:
                with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
                    target_edit.setText(f.read())
                self.log("INFO", f"已加载文件: {filename}")
            except Exception as e:
                QMessageBox.critical(None, "错误", f"加载失败: {str(e)}")
                self.log("ERROR", f"加载失败: {str(e)}")
                
    def _swap_texts(self):
        """交换文本"""
        t = self.text_a.toPlainText()
        self.text_a.setText(self.text_b.toPlainText())
        self.text_b.setText(t)
        self.log("INFO", "已交换A/B数据")
        
    def _quick_compare(self):
        """快速对比"""
        self._compare()
        
    def _compare(self):
        """执行对比"""
        text_a = self.text_a.toPlainText()
        text_b = self.text_b.toPlainText()
        
        if not text_a or not text_b:
            QMessageBox.warning(None, "警告", "请提供A和B两份数据")
            return
            
        # 获取配置
        mode = self.mode_combo.currentText()
        ignore_ws = self.ignore_whitespace.isChecked()
        ignore_case = self.ignore_case.isChecked()
        ignore_comments = self.ignore_comments.isChecked()
        ignore_empty = self.ignore_empty_lines.isChecked()
        
        # 预处理
        lines_a = self._preprocess_lines(text_a, ignore_ws, ignore_case, ignore_comments, ignore_empty)
        lines_b = self._preprocess_lines(text_b, ignore_ws, ignore_case, ignore_comments, ignore_empty)
        
        # 执行对比
        if "统一差异" in mode:
            self._unified_diff(lines_a, lines_b)
        elif "上下文差异" in mode:
            self._context_diff(lines_a, lines_b)
        elif "HTML差异" in mode:
            self._html_diff(lines_a, lines_b)
        elif "并排" in mode:
            self._side_by_side_diff(lines_a, lines_b)
        elif "语义" in mode:
            self._semantic_diff(lines_a, lines_b)
            
        # 统计
        self._calculate_and_display_stats(text_a, text_b, lines_a, lines_b)
        
        # 添加到历史
        self._add_to_history(mode)
        
        self.log("INFO", "对比完成")
        
    def _preprocess_lines(self, text: str, ignore_ws: bool, ignore_case: bool, 
                         ignore_comments: bool, ignore_empty: bool) -> List[str]:
        """预处理文本行"""
        lines = text.splitlines()
        
        if ignore_empty:
            lines = [l for l in lines if l.strip()]
            
        if ignore_comments:
            lines = [l for l in lines if not l.strip().startswith(('#', '//', '/*', '*', '--'))]
            
        if ignore_ws:
            lines = [' '.join(l.split()) for l in lines]
            
        if ignore_case:
            lines = [l.lower() for l in lines]
            
        return lines
        
    def _unified_diff(self, lines_a: List[str], lines_b: List[str]):
        """统一差异视图"""
        diff = difflib.unified_diff(lines_a, lines_b, lineterm='')
        diff_text = '\n'.join(diff)
        
        self.unified_diff.clear()
        cursor = self.unified_diff.textCursor()
        
        for line in diff_text.splitlines():
            format = QTextCharFormat()
            if line.startswith('+++') or line.startswith('---'):
                format.setBackground(QColor(255, 255, 200))
                format.setFontWeight(QFont.Bold)
            elif line.startswith('@@'):
                format.setBackground(QColor(200, 200, 255))
                format.setForeground(QColor(0, 0, 128))
            elif line.startswith('+'):
                format.setBackground(QColor(200, 255, 200))
            elif line.startswith('-'):
                format.setBackground(QColor(255, 200, 200))
                
            cursor.setCharFormat(format)
            cursor.insertText(line + "\n")
            
    def _context_diff(self, lines_a: List[str], lines_b: List[str]):
        """上下文差异视图"""
        diff = difflib.context_diff(lines_a, lines_b, lineterm='')
        diff_text = '\n'.join(diff)
        
        self.unified_diff.clear()
        cursor = self.unified_diff.textCursor()
        
        for line in diff_text.splitlines():
            format = QTextCharFormat()
            if line.startswith('***') or line.startswith('---'):
                format.setBackground(QColor(255, 255, 200))
            elif line.startswith('+ '):
                format.setBackground(QColor(200, 255, 200))
            elif line.startswith('! '):
                format.setBackground(QColor(255, 255, 200))
            elif line.startswith('- '):
                format.setBackground(QColor(255, 200, 200))
                
            cursor.setCharFormat(format)
            cursor.insertText(line + "\n")
            
    def _html_diff(self, lines_a: List[str], lines_b: List[str]):
        """HTML差异视图"""
        html = difflib.HtmlDiff().make_table(lines_a, lines_b, context=True)
        self.unified_diff.setHtml(html)
        
    def _side_by_side_diff(self, lines_a: List[str], lines_b: List[str]):
        """并排差异视图"""
        self.left_view.clear()
        self.right_view.clear()
        
        left_cursor = self.left_view.textCursor()
        right_cursor = self.right_view.textCursor()
        
        # 使用SequenceMatcher
        matcher = difflib.SequenceMatcher(None, lines_a, lines_b)
        
        for tag, i1, i2, j1, j2 in matcher.get_opcodes():
            if tag == 'equal':
                for i, j in zip(range(i1, i2), range(j1, j2)):
                    left_cursor.insertText(f"{i+1:4d} | {lines_a[i]}\n")
                    right_cursor.insertText(f"{j+1:4d} | {lines_b[j]}\n")
            elif tag == 'replace':
                for i in range(i1, i2):
                    format = QTextCharFormat()
                    format.setBackground(QColor(255, 200, 200))
                    left_cursor.setCharFormat(format)
                    left_cursor.insertText(f"{i+1:4d} | {lines_a[i]}\n")
                for j in range(j1, j2):
                    format = QTextCharFormat()
                    format.setBackground(QColor(200, 255, 200))
                    right_cursor.setCharFormat(format)
                    right_cursor.insertText(f"{j+1:4d} | {lines_b[j]}\n")
            elif tag == 'delete':
                for i in range(i1, i2):
                    format = QTextCharFormat()
                    format.setBackground(QColor(255, 200, 200))
                    left_cursor.setCharFormat(format)
                    left_cursor.insertText(f"{i+1:4d} | {lines_a[i]}\n")
            elif tag == 'insert':
                for j in range(j1, j2):
                    format = QTextCharFormat()
                    format.setBackground(QColor(200, 255, 200))
                    right_cursor.setCharFormat(format)
                    right_cursor.insertText(f"{j+1:4d} | {lines_b[j]}\n")
                    
    def _semantic_diff(self, lines_a: List[str], lines_b: List[str]):
        """语义差异视图 - 智能识别代码/文本结构"""
        self._unified_diff(lines_a, lines_b)
        self.unified_diff.append("\n\n━━━ 语义分析 ━━━")
        
        # 分析变更类型
        added = []
        removed = []
        
        matcher = difflib.SequenceMatcher(None, lines_a, lines_b)
        for tag, i1, i2, j1, j2 in matcher.get_opcodes():
            if tag == 'insert':
                added.extend(lines_b[j1:j2])
            elif tag == 'delete':
                removed.extend(lines_a[i1:i2])
                
        self.unified_diff.append(f"\n新增内容 ({len(added)} 行):")
        for line in added[:20]:
            self.unified_diff.append(f"  + {line}")
            
        self.unified_diff.append(f"\n删除内容 ({len(removed)} 行):")
        for line in removed[:20]:
            self.unified_diff.append(f"  - {line}")
            
    def _calculate_and_display_stats(self, text_a: str, text_b: str, 
                                     lines_a: List[str], lines_b: List[str]):
        """计算并显示统计"""
        # 计算哈希
        hash_a = hashlib.md5(text_a.encode()).hexdigest()
        hash_b = hashlib.md5(text_b.encode()).hexdigest()
        
        # 使用SequenceMatcher计算相似度
        matcher = difflib.SequenceMatcher(None, lines_a, lines_b)
        similarity = matcher.ratio() * 100
        
        # 统计变更
        added = 0
        removed = 0
        modified = 0
        unchanged = 0
        
        for tag, i1, i2, j1, j2 in matcher.get_opcodes():
            if tag == 'equal':
                unchanged += (i2 - i1)
            elif tag == 'replace':
                modified += max(i2 - i1, j2 - j1)
            elif tag == 'delete':
                removed += (i2 - i1)
            elif tag == 'insert':
                added += (j2 - j1)
                
        # 字节差异
        bytes_a = len(text_a.encode('utf-8'))
        bytes_b = len(text_b.encode('utf-8'))
        bytes_diff = bytes_b - bytes_a
        
        # 显示统计
        stats = f"""━━━ 对比统计 ━━━

文件信息:
  A 行数: {len(lines_a)} | 字节: {bytes_a}
  B 行数: {len(lines_b)} | 字节: {bytes_b}

哈希值:
  A MD5: {hash_a}
  B MD5: {hash_b}
  哈希相同: {'✓ 是' if hash_a == hash_b else '✗ 否'}

差异统计:
  新增行: {added}
  删除行: {removed}
  修改行: {modified}
  未变更: {unchanged}
  总变更: {added + removed + modified}

相似度分析:
  整体相似度: {similarity:.1f}%
  字节差异: {'+' if bytes_diff >= 0 else ''}{bytes_diff} 字节

变更率: {((added + removed + modified) / max(len(lines_a) + len(lines_b), 1)) * 100:.1f}%
"""
        self.stats_view.setText(stats)
        
        # 填充差异表格
        self.diff_table.setRowCount(0)
        row = 0
        for tag, i1, i2, j1, j2 in matcher.get_opcodes():
            if tag != 'equal':
                if tag == 'replace':
                    for i in range(i1, i2):
                        self.diff_table.insertRow(row)
                        self.diff_table.setItem(row, 0, QTableWidgetItem("修改"))
                        self.diff_table.setItem(row, 1, QTableWidgetItem(str(i+1)))
                        self.diff_table.setItem(row, 2, QTableWidgetItem("-"))
                        self.diff_table.setItem(row, 3, QTableWidgetItem(lines_a[i][:100]))
                        row += 1
                    for j in range(j1, j2):
                        self.diff_table.insertRow(row)
                        self.diff_table.setItem(row, 0, QTableWidgetItem("新增"))
                        self.diff_table.setItem(row, 1, QTableWidgetItem("-"))
                        self.diff_table.setItem(row, 2, QTableWidgetItem(str(j+1)))
                        self.diff_table.setItem(row, 3, QTableWidgetItem(lines_b[j][:100]))
                        row += 1
                elif tag == 'delete':
                    for i in range(i1, i2):
                        self.diff_table.insertRow(row)
                        self.diff_table.setItem(row, 0, QTableWidgetItem("删除"))
                        self.diff_table.setItem(row, 1, QTableWidgetItem(str(i+1)))
                        self.diff_table.setItem(row, 2, QTableWidgetItem("-"))
                        self.diff_table.setItem(row, 3, QTableWidgetItem(lines_a[i][:100]))
                        row += 1
                elif tag == 'insert':
                    for j in range(j1, j2):
                        self.diff_table.insertRow(row)
                        self.diff_table.setItem(row, 0, QTableWidgetItem("新增"))
                        self.diff_table.setItem(row, 1, QTableWidgetItem("-"))
                        self.diff_table.setItem(row, 2, QTableWidgetItem(str(j+1)))
                        self.diff_table.setItem(row, 3, QTableWidgetItem(lines_b[j][:100]))
                        row += 1
                        
    def _compare_bytes(self):
        """字节级对比"""
        hex_a = self.byte_input_a.text().replace(' ', '').replace(':', '')
        hex_b = self.byte_input_b.text().replace(' ', '').replace(':', '')
        
        if not hex_a or not hex_b:
            QMessageBox.warning(None, "警告", "请输入Hex数据")
            return
            
        try:
            bytes_a = bytes.fromhex(hex_a)
            bytes_b = bytes.fromhex(hex_b)
        except ValueError as e:
            QMessageBox.critical(None, "错误", f"Hex格式错误: {str(e)}")
            return
            
        # Hex差异视图
        self.hex_diff_view.clear()
        cursor = self.hex_diff_view.textCursor()
        
        max_len = max(len(bytes_a), len(bytes_b))
        diff_count = 0
        
        for offset in range(0, max_len, 16):
            # 偏移量
            format_offset = QTextCharFormat()
            format_offset.setForeground(QColor(128, 128, 128))
            cursor.setCharFormat(format_offset)
            cursor.insertText(f"{offset:08x}  ")
            
            # 字节A
            chunk_a = bytes_a[offset:offset+16]
            chunk_b = bytes_b[offset:offset+16]
            
            for i in range(16):
                if i < len(chunk_a) and i < len(chunk_b):
                    if chunk_a[i] == chunk_b[i]:
                        cursor.insertText(f"{chunk_a[i]:02x} ")
                    else:
                        format_diff = QTextCharFormat()
                        format_diff.setBackground(QColor(255, 200, 200))
                        cursor.setCharFormat(format_diff)
                        cursor.insertText(f"{chunk_a[i]:02x} ")
                        diff_count += 1
                elif i < len(chunk_a):
                    format_del = QTextCharFormat()
                    format_del.setBackground(QColor(255, 200, 200))
                    cursor.setCharFormat(format_del)
                    cursor.insertText(f"{chunk_a[i]:02x} ")
                    diff_count += 1
                else:
                    format_add = QTextCharFormat()
                    format_add.setBackground(QColor(200, 255, 200))
                    cursor.setCharFormat(format_add)
                    cursor.insertText(f"{'--'} ")
                    diff_count += 1
                    
            cursor.insertText("  ")
            
            # ASCII表示
            for i in range(16):
                if i < len(chunk_a) and i < len(chunk_b):
                    if chunk_a[i] == chunk_b[i]:
                        c = chr(chunk_a[i]) if 32 <= chunk_a[i] < 127 else '.'
                        cursor.insertText(c)
                    else:
                        format_diff = QTextCharFormat()
                        format_diff.setBackground(QColor(255, 200, 200))
                        cursor.setCharFormat(format_diff)
                        c = chr(chunk_a[i]) if 32 <= chunk_a[i] < 127 else '.'
                        cursor.insertText(c)
                elif i < len(chunk_a):
                    c = chr(chunk_a[i]) if 32 <= chunk_a[i] < 127 else '.'
                    cursor.insertText(c)
                else:
                    cursor.insertText(" ")
                    
            cursor.insertText("\n")
            
        # 字节统计
        self.byte_stats_view.setText(f"""━━━ 字节统计 ━━━

A 长度: {len(bytes_a)} 字节
B 长度: {len(bytes_b)} 字节
长度差异: {len(bytes_b) - len(bytes_a)} 字节

差异字节数: {diff_count}
相似度: {(1 - diff_count / max(len(bytes_a), len(bytes_b), 1)) * 100:.1f}%
""")
        
        # 字节分布
        counter_a = Counter(bytes_a)
        counter_b = Counter(bytes_b)
        
        distribution = "━━━ 字节分布 ━━━\n\n"
        distribution += "数据A Top 20 字节:\n"
        for byte_val, count in counter_a.most_common(20):
            char_repr = chr(byte_val) if 32 <= byte_val < 127 else '.'
            distribution += f"  0x{byte_val:02x} ({char_repr}): {count} 次 ({count/len(bytes_a)*100:.1f}%)\n"
            
        distribution += "\n数据B Top 20 字节:\n"
        for byte_val, count in counter_b.most_common(20):
            char_repr = chr(byte_val) if 32 <= byte_val < 127 else '.'
            distribution += f"  0x{byte_val:02x} ({char_repr}): {count} 次 ({count/len(bytes_b)*100:.1f}%)\n"
            
        self.byte_distribution.setText(distribution)
        
        self.log("INFO", f"字节对比完成，发现 {diff_count} 处差异")
        
    def _compare_http(self):
        """HTTP请求/响应对比"""
        http_a = self.http_input_a.toPlainText()
        http_b = self.http_input_b.toPlainText()
        
        if not http_a or not http_b:
            QMessageBox.warning(None, "警告", "请提供HTTP A和B")
            return
            
        # 解析HTTP
        parsed_a = self._parse_http(http_a)
        parsed_b = self._parse_http(http_b)
        
        # 请求行对比
        self.request_line_diff.clear()
        if parsed_a['request_line'] != parsed_b['request_line']:
            self.request_line_diff.append("━━━ 请求行差异 ━━━\n")
            self.request_line_diff.append(f"A: {parsed_a['request_line']}")
            self.request_line_diff.append(f"B: {parsed_b['request_line']}")
        else:
            self.request_line_diff.append("✓ 请求行相同\n\n")
            self.request_line_diff.append(parsed_a['request_line'])
            
        # 头部对比
        self.headers_diff.clear()
        all_headers = set(list(parsed_a['headers'].keys()) + list(parsed_b['headers'].keys()))
        
        self.headers_diff.append("━━━ 头部对比 ━━━\n")
        for header in sorted(all_headers):
            val_a = parsed_a['headers'].get(header, '<不存在>')
            val_b = parsed_b['headers'].get(header, '<不存在>')
            
            if val_a != val_b:
                self.headers_diff.append(f"\n❌ {header}:")
                self.headers_diff.append(f"  A: {val_a}")
                self.headers_diff.append(f"  B: {val_b}")
            else:
                self.headers_diff.append(f"\n✓ {header}: {val_a}")
                
        # 主体对比
        self.body_diff.clear()
        if parsed_a['body'] != parsed_b['body']:
            self.body_diff.append("━━━ 主体差异 ━━━\n")
            body_a_lines = parsed_a['body'].splitlines()
            body_b_lines = parsed_b['body'].splitlines()
            
            diff = difflib.unified_diff(body_a_lines, body_b_lines, lineterm='')
            for line in diff:
                if line.startswith('+'):
                    format = QTextCharFormat()
                    format.setBackground(QColor(200, 255, 200))
                elif line.startswith('-'):
                    format = QTextCharFormat()
                    format.setBackground(QColor(255, 200, 200))
                else:
                    format = QTextCharFormat()
                    
                cursor = self.body_diff.textCursor()
                cursor.setCharFormat(format)
                cursor.insertText(line + "\n")
        else:
            self.body_diff.append("✓ 主体相同")
            
        # 安全分析
        self.security_analysis.clear()
        self.security_analysis.append("━━━ 安全分析 ━━━\n")
        
        # 检查安全头部
        security_headers = {
            'Content-Security-Policy': 'CSP策略',
            'X-Content-Type-Options': '防MIME嗅探',
            'X-Frame-Options': '防点击劫持',
            'Strict-Transport-Security': 'HSTS',
            'X-XSS-Protection': 'XSS保护',
            'Referrer-Policy': 'Referrer策略',
        }
        
        for header, desc in security_headers.items():
            val_a = parsed_a['headers'].get(header)
            val_b = parsed_b['headers'].get(header)
            
            if not val_a and not val_b:
                self.security_analysis.append(f"⚠️ 缺少 {desc} ({header})")
            elif val_a != val_b:
                self.security_analysis.append(f"❌ {desc} 不一致")
                self.security_analysis.append(f"  A: {val_a}")
                self.security_analysis.append(f"  B: {val_b}")
            else:
                self.security_analysis.append(f"✓ {desc}: {val_a}")
                
        # 检查Cookie属性
        set_cookie_a = parsed_a['headers'].get('Set-Cookie', '')
        set_cookie_b = parsed_b['headers'].get('Set-Cookie', '')
        
        if set_cookie_a or set_cookie_b:
            self.security_analysis.append("\n━━━ Cookie安全分析 ━━━")
            for cookie in [set_cookie_a, set_cookie_b]:
                if cookie:
                    if 'Secure' not in cookie:
                        self.security_analysis.append("⚠️ Cookie缺少Secure标志")
                    if 'HttpOnly' not in cookie:
                        self.security_analysis.append("⚠️ Cookie缺少HttpOnly标志")
                    if 'SameSite' not in cookie:
                        self.security_analysis.append("⚠️ Cookie缺少SameSite属性")
                        
        self.log("INFO", "HTTP对比完成")
        
    def _parse_http(self, http_text: str) -> Dict:
        """解析HTTP请求/响应"""
        result = {
            'request_line': '',
            'headers': {},
            'body': ''
        }
        
        lines = http_text.splitlines()
        if not lines:
            return result
            
        # 第一行
        result['request_line'] = lines[0]
        
        # 解析头部
        header_end = 0
        for i, line in enumerate(lines[1:], 1):
            if not line.strip():
                header_end = i
                break
            if ':' in line:
                key, value = line.split(':', 1)
                result['headers'][key.strip()] = value.strip()
                
        # 主体
        if header_end > 0:
            result['body'] = '\n'.join(lines[header_end+1:])
            
        return result
        
    def _compare_structured(self):
        """结构化数据对比"""
        text_a = self.struct_input_a.toPlainText()
        text_b = self.struct_input_b.toPlainText()
        
        if not text_a or not text_b:
            QMessageBox.warning(None, "警告", "请提供A和B数据")
            return
            
        # 尝试解析JSON
        try:
            json_a = json.loads(text_a)
            json_b = json.loads(text_b)
            self._compare_json(json_a, json_b)
            return
        except json.JSONDecodeError:
            pass
            
        # 如果不是JSON，进行文本对比
        self.struct_diff_view.setText("无法解析为JSON，执行文本对比...\n\n")
        lines_a = text_a.splitlines()
        lines_b = text_b.splitlines()
        diff = difflib.unified_diff(lines_a, lines_b, lineterm='')
        self.struct_diff_view.append('\n'.join(diff))
        
    def _compare_json(self, json_a: Any, json_b: Any):
        """JSON对比"""
        self.struct_diff_view.clear()
        self.struct_tree_view.clear()
        
        # 展平JSON
        flat_a = self._flatten_json(json_a)
        flat_b = self._flatten_json(json_b)
        
        # 对比
        all_keys = set(list(flat_a.keys()) + list(flat_b.keys()))
        
        self.struct_diff_view.append("━━━ JSON差异 ━━━\n")
        
        added = []
        removed = []
        modified = []
        
        for key in sorted(all_keys):
            val_a = flat_a.get(key)
            val_b = flat_b.get(key)
            
            if val_a is None and val_b is not None:
                added.append(key)
                self.struct_diff_view.append(f"+ {key}: {json.dumps(val_b, ensure_ascii=False)}")
            elif val_a is not None and val_b is None:
                removed.append(key)
                self.struct_diff_view.append(f"- {key}: {json.dumps(val_a, ensure_ascii=False)}")
            elif val_a != val_b:
                modified.append(key)
                self.struct_diff_view.append(f"~ {key}:")
                self.struct_diff_view.append(f"  A: {json.dumps(val_a, ensure_ascii=False)}")
                self.struct_diff_view.append(f"  B: {json.dumps(val_b, ensure_ascii=False)}")
                
        self.struct_diff_view.append(f"\n━━━ 统计 ━━━")
        self.struct_diff_view.append(f"新增: {len(added)}")
        self.struct_diff_view.append(f"删除: {len(removed)}")
        self.struct_diff_view.append(f"修改: {len(modified)}")
        self.struct_diff_view.append(f"相同: {len(all_keys) - len(added) - len(removed) - len(modified)}")
        
        # 树形视图
        self.struct_tree_view.append("━━━ 树形结构 ━━━\n")
        self._print_json_tree(json_a, "A", 0)
        self.struct_tree_view.append("\n")
        self._print_json_tree(json_b, "B", 0)
        
        self.log("INFO", f"JSON对比完成: {len(added)}新增, {len(removed)}删除, {len(modified)}修改")
        
    def _flatten_json(self, obj: Any, prefix: str = '') -> Dict:
        """展平JSON对象"""
        result = {}
        if isinstance(obj, dict):
            for k, v in obj.items():
                new_key = f"{prefix}.{k}" if prefix else k
                if isinstance(v, (dict, list)):
                    result.update(self._flatten_json(v, new_key))
                else:
                    result[new_key] = v
        elif isinstance(obj, list):
            for i, v in enumerate(obj):
                new_key = f"{prefix}[{i}]"
                if isinstance(v, (dict, list)):
                    result.update(self._flatten_json(v, new_key))
                else:
                    result[new_key] = v
        else:
            result[prefix] = obj
        return result
        
    def _print_json_tree(self, obj: Any, label: str, indent: int = 0):
        """打印JSON树"""
        prefix = "  " * indent
        if isinstance(obj, dict):
            self.struct_tree_view.append(f"{prefix}{label}: {{")
            for k, v in obj.items():
                self._print_json_tree(v, k, indent + 1)
            self.struct_tree_view.append(f"{prefix}}}")
        elif isinstance(obj, list):
            self.struct_tree_view.append(f"{prefix}{label}: [")
            for i, v in enumerate(obj):
                self._print_json_tree(v, f"[{i}]", indent + 1)
            self.struct_tree_view.append(f"{prefix}]")
        else:
            self.struct_tree_view.append(f"{prefix}{label}: {json.dumps(obj, ensure_ascii=False)}")
        
    def _add_to_history(self, mode: str):
        """添加到历史"""
        import datetime
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # 计算相似度
        text_a = self.text_a.toPlainText()
        text_b = self.text_b.toPlainText()
        matcher = difflib.SequenceMatcher(None, text_a.splitlines(), text_b.splitlines())
        similarity = f"{matcher.ratio() * 100:.1f}%"
        
        # 计算差异数
        diff_count = sum(1 for tag, _, _, _, _ in matcher.get_opcodes() if tag != 'equal')
        
        # 添加到表格
        row = self.history_table.rowCount()
        self.history_table.insertRow(row)
        self.history_table.setItem(row, 0, QTableWidgetItem(timestamp))
        self.history_table.setItem(row, 1, QTableWidgetItem(mode))
        self.history_table.setItem(row, 2, QTableWidgetItem(similarity))
        self.history_table.setItem(row, 3, QTableWidgetItem(str(diff_count)))
        
        view_btn = QPushButton("查看")
        view_btn.clicked.connect(lambda: self._view_history(row))
        self.history_table.setCellWidget(row, 4, view_btn)
        
    def _view_history(self, row: int):
        """查看历史记录"""
        QMessageBox.information(None, "历史详情", f"查看第 {row + 1} 条历史记录")
        
    def _clear_history(self):
        """清空历史"""
        self.history_table.setRowCount(0)
        self.log("INFO", "已清空历史记录")
        
    def _export_history(self):
        """导出历史"""
        filename, _ = QFileDialog.getSaveFileName(None, "导出历史", "", "CSV Files (*.csv)")
        if filename:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write("时间,对比模式,相似度,差异数\n")
                for row in range(self.history_table.rowCount()):
                    time = self.history_table.item(row, 0).text()
                    mode = self.history_table.item(row, 1).text()
                    similarity = self.history_table.item(row, 2).text()
                    diff_count = self.history_table.item(row, 3).text()
                    f.write(f"{time},{mode},{similarity},{diff_count}\n")
            self.log("INFO", f"历史已导出到 {filename}")
            QMessageBox.information(None, "成功", f"历史已导出到 {filename}")
            
    def _save_report(self):
        """保存对比报告"""
        filename, _ = QFileDialog.getSaveFileName(None, "保存报告", "", "HTML Files (*.html);;Text Files (*.txt)")
        if filename:
            if filename.endswith('.html'):
                content = f"""
                <html>
                <head><title>对比报告</title></head>
                <body>
                <h1>对比报告</h1>
                <pre>{self.stats_view.toPlainText()}</pre>
                <h2>差异详情</h2>
                <pre>{self.unified_diff.toPlainText()}</pre>
                </body>
                </html>
                """
            else:
                content = f"对比报告\n\n{self.stats_view.toPlainText()}\n\n差异详情\n\n{self.unified_diff.toPlainText()}"
                
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(content)
            self.log("INFO", f"报告已保存到 {filename}")
            QMessageBox.information(None, "成功", f"报告已保存到 {filename}")
