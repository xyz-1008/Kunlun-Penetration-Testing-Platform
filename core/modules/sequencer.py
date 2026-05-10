"""
Sequencer (会话分析)模块 - 专家级会话Token随机性分析
支持熵值计算、卡方检验、游程检验、蒙特卡洛测试、自相关分析
适用于10年经验白帽子、安全公司、SRC漏洞挖掘
"""

from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum, auto
from datetime import datetime
import logging
import math
import random
import re
import statistics
from collections import Counter, defaultdict

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QSplitter, QTabWidget,
    QPushButton, QLabel, QLineEdit, QTextEdit, QComboBox,
    QGroupBox, QFormLayout, QProgressBar, QTableWidget,
    QTableWidgetItem, QHeaderView, QCheckBox, QSpinBox,
    QFileDialog, QMessageBox, QListWidget, QListWidgetItem,
    QTextBrowser, QTreeWidget, QTreeWidgetItem, QRadioButton,
    QButtonGroup, QFrame
)
from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QColor, QFont, QTextCursor

from .base import ModuleBase

logger = logging.getLogger(__name__)


class RandomnessScore(Enum):
    """随机性评分"""
    EXCELLENT = "优秀 (密码学安全)"
    GOOD = "良好 (预测困难)"
    FAIR = "一般 (存在风险)"
    POOR = "差 (易于预测)"
    VERY_POOR = "非常差 (高度可预测)"


class TestResult(Enum):
    """测试结果"""
    PASS = "通过"
    FAIL = "失败"
    WARNING = "警告"


@dataclass
class TokenSample:
    """Token样本"""
    id: int
    value: str
    timestamp: datetime
    source: str = ""
    raw_bytes: bytes = b""


@dataclass
class StatisticalTest:
    """统计测试"""
    name: str
    description: str
    result: TestResult
    value: float
    expected_range: str
    details: str = ""


@dataclass
class EntropyAnalysis:
    """熵值分析"""
    shannon_entropy: float
    min_entropy: float
    max_entropy: float
    effective_entropy: float
    bits_per_char: float
    charset_size: int
    charset: str


@dataclass
class RandomnessAnalysis:
    """随机性分析结果"""
    total_samples: int
    sample_lengths: List[int]
    avg_length: float
    std_length: float
    min_length: int
    max_length: int
    unique_tokens: int
    duplicates: int
    entropy: EntropyAnalysis
    tests: List[StatisticalTest]
    overall_score: RandomnessScore
    risk_level: str
    recommendations: List[str]
    timestamp: datetime = field(default_factory=datetime.now)


class SequencerWorker(QThread):
    """会话分析工作线程 - 专家级实现"""
    
    progress_updated = Signal(int, int, str)
    analysis_complete = Signal(RandomnessAnalysis)
    log_message = Signal(str)
    error_occurred = Signal(str)
    status_changed = Signal(str)
    
    def __init__(self, samples: List[TokenSample]):
        super().__init__()
        self.samples = samples
        self._running = False
        
    def run(self):
        """执行分析"""
        try:
            self._running = True
            self.status_changed.emit("开始分析...")
            self.log_message.emit(f"分析 {len(self.samples)} 个Token样本")
            
            if len(self.samples) < 10:
                self.error_occurred.emit("样本数量不足，至少需要10个样本")
                return
                
            self.progress_updated.emit(10, 100, "计算基础统计...")
            self.log_message.emit("计算基础统计...")
            
            lengths = [len(s.value) for s in self.samples]
            avg_length = statistics.mean(lengths)
            std_length = statistics.stdev(lengths) if len(lengths) > 1 else 0
            min_length = min(lengths)
            max_length = max(lengths)
            
            unique_tokens = len(set(s.value for s in self.samples))
            duplicates = len(self.samples) - unique_tokens
            
            self.progress_updated.emit(20, 100, "计算熵值...")
            self.log_message.emit("计算熵值...")
            
            all_chars = ''.join(s.value for s in self.samples)
            entropy_analysis = self._calculate_entropy(all_chars)
            
            self.progress_updated.emit(40, 100, "执行统计测试...")
            self.log_message.emit("执行统计测试...")
            
            tests = []
            tests.append(self._chi_square_test(all_chars))
            self.progress_updated.emit(50, 100, "卡方检验完成")
            
            tests.append(self._runs_test(all_chars))
            self.progress_updated.emit(60, 100, "游程检验完成")
            
            tests.append(self._monte_carlo_pi_test(all_chars))
            self.progress_updated.emit(70, 100, "蒙特卡洛测试完成")
            
            tests.append(self._serial_correlation_test(all_chars))
            self.progress_updated.emit(80, 100, "自相关检验完成")
            
            tests.append(self._compression_test(all_chars))
            self.progress_updated.emit(90, 100, "压缩测试完成")
            
            tests.append(self._length_consistency_test(lengths))
            
            if duplicates > 0:
                tests.append(StatisticalTest(
                    name="重复检测",
                    description="检测是否有重复的Token",
                    result=TestResult.FAIL,
                    value=duplicates,
                    expected_range="0",
                    details=f"发现 {duplicates} 个重复Token"
                ))
            else:
                tests.append(StatisticalTest(
                    name="重复检测",
                    description="检测是否有重复的Token",
                    result=TestResult.PASS,
                    value=0,
                    expected_range="0",
                    details="无重复Token"
                ))
                
            self.progress_updated.emit(95, 100, "综合评估...")
            
            overall_score = self._calculate_overall_score(entropy_analysis, tests)
            risk_level = "高" if overall_score in [RandomnessScore.POOR, RandomnessScore.VERY_POOR] else "中" if overall_score == RandomnessScore.FAIR else "低"
            
            recommendations = self._generate_recommendations(entropy_analysis, tests, duplicates)
            
            analysis = RandomnessAnalysis(
                total_samples=len(self.samples),
                sample_lengths=lengths,
                avg_length=avg_length,
                std_length=std_length,
                min_length=min_length,
                max_length=max_length,
                unique_tokens=unique_tokens,
                duplicates=duplicates,
                entropy=entropy_analysis,
                tests=tests,
                overall_score=overall_score,
                risk_level=risk_level,
                recommendations=recommendations
            )
            
            self.progress_updated.emit(100, 100, "分析完成")
            self.status_changed.emit(f"分析完成! 评分: {overall_score.value}")
            self.analysis_complete.emit(analysis)
            
        except Exception as e:
            self.error_occurred.emit(f"分析错误: {e}")
            logger.error(f"分析错误: {e}")
        finally:
            self._running = False
            
    def stop(self):
        """停止分析"""
        self._running = False
        
    def _calculate_entropy(self, data: str) -> EntropyAnalysis:
        """计算多种熵值"""
        if not data:
            return EntropyAnalysis(0, 0, 0, 0, 0, 0, "")
            
        freq = Counter(data)
        total = len(data)
        charset_size = len(freq)
        charset = ''.join(sorted(freq.keys()))
        
        shannon_entropy = 0.0
        for count in freq.values():
            if count > 0:
                p = count / total
                shannon_entropy -= p * math.log2(p)
                
        min_entropy = -math.log2(max(freq.values()) / total)
        max_entropy = math.log2(charset_size) if charset_size > 0 else 0
        
        effective_bits = shannon_entropy * total
        effective_entropy = effective_bits / total if total > 0 else 0
        
        bits_per_char = shannon_entropy
        
        return EntropyAnalysis(
            shannon_entropy=shannon_entropy,
            min_entropy=min_entropy,
            max_entropy=max_entropy,
            effective_entropy=effective_entropy,
            bits_per_char=bits_per_char,
            charset_size=charset_size,
            charset=charset
        )
        
    def _chi_square_test(self, data: str) -> StatisticalTest:
        """卡方检验 - 检测字符分布是否均匀"""
        if not data:
            return StatisticalTest("卡方检验", "", TestResult.FAIL, 0, "", "无数据")
            
        freq = Counter(data)
        total = len(data)
        charset_size = len(freq)
        expected = total / charset_size
        
        chi_square = sum((count - expected) ** 2 / expected for count in freq.values())
        
        degrees_of_freedom = charset_size - 1
        critical_value = degrees_of_freedom * 1.5
        
        if chi_square < critical_value:
            result = TestResult.PASS
            details = f"卡方值 {chi_square:.2f} < 临界值 {critical_value:.2f}，分布均匀"
        elif chi_square < critical_value * 2:
            result = TestResult.WARNING
            details = f"卡方值 {chi_square:.2f} 略高，分布可能不均匀"
        else:
            result = TestResult.FAIL
            details = f"卡方值 {chi_square:.2f} >> 临界值 {critical_value:.2f}，分布不均匀"
            
        return StatisticalTest(
            name="卡方检验",
            description="检测字符分布是否均匀",
            result=result,
            value=chi_square,
            expected_range=f"< {critical_value:.2f}",
            details=details
        )
        
    def _runs_test(self, data: str) -> StatisticalTest:
        """游程检验 - 检测序列中的游程数量"""
        if len(data) < 2:
            return StatisticalTest("游程检验", "", TestResult.FAIL, 0, "", "数据不足")
            
        bytes_data = [ord(c) for c in data]
        median = statistics.median(bytes_data)
        
        runs = 1
        for i in range(1, len(bytes_data)):
            if (bytes_data[i] >= median) != (bytes_data[i-1] >= median):
                runs += 1
                
        n1 = sum(1 for b in bytes_data if b >= median)
        n2 = len(bytes_data) - n1
        
        if n1 == 0 or n2 == 0:
            return StatisticalTest(
                name="游程检验",
                description="检测序列随机性",
                result=TestResult.FAIL,
                value=runs,
                expected_range="",
                details="数据分布极端，无法计算"
            )
            
        expected_runs = (2 * n1 * n2) / (n1 + n2) + 1
        variance = (2 * n1 * n2 * (2 * n1 * n2 - n1 - n2)) / ((n1 + n2) ** 2 * (n1 + n2 - 1))
        std_dev = math.sqrt(variance) if variance > 0 else 1
        
        z_score = abs(runs - expected_runs) / std_dev if std_dev > 0 else 0
        
        if z_score < 1.96:
            result = TestResult.PASS
            details = f"Z分数 {z_score:.2f} < 1.96，游程数量正常"
        elif z_score < 2.58:
            result = TestResult.WARNING
            details = f"Z分数 {z_score:.2f} 略高，可能存在模式"
        else:
            result = TestResult.FAIL
            details = f"Z分数 {z_score:.2f} >> 1.96，游程异常"
            
        return StatisticalTest(
            name="游程检验",
            description="检测序列中的随机游程",
            result=result,
            value=runs,
            expected_range=f"≈ {expected_runs:.0f}",
            details=details
        )
        
    def _monte_carlo_pi_test(self, data: str) -> StatisticalTest:
        """蒙特卡洛π测试 - 使用随机数估算π"""
        if len(data) < 4:
            return StatisticalTest("蒙特卡洛π测试", "", TestResult.FAIL, 0, "", "数据不足")
            
        bytes_data = [ord(c) for c in data]
        pairs = [(bytes_data[i], bytes_data[i+1]) for i in range(0, len(bytes_data)-1, 2)]
        
        inside_circle = 0
        total_pairs = len(pairs)
        
        for x, y in pairs:
            x_norm = (x / 255.0) * 2 - 1
            y_norm = (y / 255.0) * 2 - 1
            if x_norm**2 + y_norm**2 <= 1:
                inside_circle += 1
                
        if total_pairs == 0:
            return StatisticalTest("蒙特卡洛π测试", "", TestResult.FAIL, 0, "", "无有效对")
            
        pi_estimate = 4 * inside_circle / total_pairs
        error_percent = abs(pi_estimate - math.pi) / math.pi * 100
        
        if error_percent < 5:
            result = TestResult.PASS
            details = f"π估算值 {pi_estimate:.4f}，误差 {error_percent:.2f}%"
        elif error_percent < 10:
            result = TestResult.WARNING
            details = f"π估算值 {pi_estimate:.4f}，误差 {error_percent:.2f}%"
        else:
            result = TestResult.FAIL
            details = f"π估算值 {pi_estimate:.4f}，误差 {error_percent:.2f}%"
            
        return StatisticalTest(
            name="蒙特卡洛π测试",
            description="使用随机数估算π值",
            result=result,
            value=pi_estimate,
            expected_range=f"≈ {math.pi:.4f}",
            details=details
        )
        
    def _serial_correlation_test(self, data: str) -> StatisticalTest:
        """自相关检验 - 检测相邻字符的相关性"""
        if len(data) < 2:
            return StatisticalTest("自相关检验", "", TestResult.FAIL, 0, "", "数据不足")
            
        bytes_data = [ord(c) for c in data]
        n = len(bytes_data)
        
        mean = statistics.mean(bytes_data)
        variance = sum((x - mean) ** 2 for x in bytes_data) / n
        
        if variance == 0:
            return StatisticalTest(
                name="自相关检验",
                description="检测相邻字符相关性",
                result=TestResult.FAIL,
                value=1.0,
                expected_range="≈ 0",
                details="方差为0，数据完全相同"
            )
            
        covariance = sum((bytes_data[i] - mean) * (bytes_data[i+1] - mean) for i in range(n-1)) / (n-1)
        correlation = covariance / variance
        
        if abs(correlation) < 0.05:
            result = TestResult.PASS
            details = f"相关系数 {correlation:.4f}，无自相关"
        elif abs(correlation) < 0.1:
            result = TestResult.WARNING
            details = f"相关系数 {correlation:.4f}，轻微自相关"
        else:
            result = TestResult.FAIL
            details = f"相关系数 {correlation:.4f}，存在自相关"
            
        return StatisticalTest(
            name="自相关检验",
            description="检测相邻字符之间的相关性",
            result=result,
            value=correlation,
            expected_range="≈ 0",
            details=details
        )
        
    def _compression_test(self, data: str) -> StatisticalTest:
        """压缩测试 - 随机数据应该难以压缩"""
        if not data:
            return StatisticalTest("压缩测试", "", TestResult.FAIL, 0, "", "无数据")
            
        try:
            import zlib
            original_size = len(data.encode('utf-8'))
            compressed_size = len(zlib.compress(data.encode('utf-8')))
            compression_ratio = compressed_size / original_size if original_size > 0 else 1
            
            if compression_ratio > 0.95:
                result = TestResult.PASS
                details = f"压缩比 {compression_ratio:.2%}，数据高度随机"
            elif compression_ratio > 0.8:
                result = TestResult.WARNING
                details = f"压缩比 {compression_ratio:.2%}，数据部分可压缩"
            else:
                result = TestResult.FAIL
                details = f"压缩比 {compression_ratio:.2%}，数据高度可压缩，存在模式"
                
            return StatisticalTest(
                name="压缩测试",
                description="检测数据是否可压缩（随机数据难压缩）",
                result=result,
                value=compression_ratio,
                expected_range="> 0.95",
                details=details
            )
        except Exception as e:
            return StatisticalTest(
                name="压缩测试",
                description="检测数据是否可压缩",
                result=TestResult.WARNING,
                value=0,
                expected_range="",
                details=f"压缩测试失败: {e}"
            )
            
    def _length_consistency_test(self, lengths: List[int]) -> StatisticalTest:
        """长度一致性检验"""
        if not lengths:
            return StatisticalTest("长度一致性", "", TestResult.FAIL, 0, "", "无数据")
            
        unique_lengths = len(set(lengths))
        std_dev = statistics.stdev(lengths) if len(lengths) > 1 else 0
        
        if unique_lengths == 1:
            result = TestResult.PASS
            details = f"所有Token长度一致: {lengths[0]}"
        elif std_dev < 2:
            result = TestResult.WARNING
            details = f"长度变化小 (标准差: {std_dev:.2f})，{unique_lengths} 种不同长度"
        else:
            result = TestResult.FAIL
            details = f"长度变化大 (标准差: {std_dev:.2f})，{unique_lengths} 种不同长度"
            
        return StatisticalTest(
            name="长度一致性",
            description="检测Token长度是否一致",
            result=result,
            value=unique_lengths,
            expected_range="1",
            details=details
        )
        
    def _calculate_overall_score(self, entropy: EntropyAnalysis, tests: List[StatisticalTest]) -> RandomnessScore:
        """计算总体评分"""
        pass_count = sum(1 for t in tests if t.result == TestResult.PASS)
        fail_count = sum(1 for t in tests if t.result == TestResult.FAIL)
        warning_count = sum(1 for t in tests if t.result == TestResult.WARNING)
        
        total_tests = len(tests)
        pass_ratio = pass_count / total_tests if total_tests > 0 else 0
        
        entropy_score = entropy.shannon_entropy / 8.0
        
        combined_score = (pass_ratio * 0.6) + (entropy_score * 0.4)
        
        if combined_score >= 0.9:
            return RandomnessScore.EXCELLENT
        elif combined_score >= 0.7:
            return RandomnessScore.GOOD
        elif combined_score >= 0.5:
            return RandomnessScore.FAIR
        elif combined_score >= 0.3:
            return RandomnessScore.POOR
        else:
            return RandomnessScore.VERY_POOR
            
    def _generate_recommendations(self, entropy: EntropyAnalysis, tests: List[StatisticalTest], duplicates: int) -> List[str]:
        """生成建议"""
        recommendations = []
        
        if entropy.shannon_entropy < 4.0:
            recommendations.append("⚠️ 熵值过低，建议使用密码学安全的随机数生成器 (如 /dev/urandom 或 CryptGenRandom)")
            
        if entropy.charset_size < 32:
            recommendations.append("⚠️ 字符集过小，建议扩大字符集 (如包含大小写字母、数字、特殊字符)")
            
        if duplicates > 0:
            recommendations.append(f"❌ 发现 {duplicates} 个重复Token，这严重降低了安全性")
            
        failed_tests = [t for t in tests if t.result == TestResult.FAIL]
        if failed_tests:
            recommendations.append(f"❌ {len(failed_tests)} 个统计测试失败: {', '.join(t.name for t in failed_tests)}")
            
        warning_tests = [t for t in tests if t.result == TestResult.WARNING]
        if warning_tests:
            recommendations.append(f"⚠️ {len(warning_tests)} 个测试警告: {', '.join(t.name for t in warning_tests)}")
            
        if entropy.shannon_entropy >= 6.0 and len(failed_tests) == 0:
            recommendations.append("✅ Token随机性良好，符合安全要求")
            
        if not recommendations:
            recommendations.append("✅ 未发现明显安全问题")
            
        return recommendations


class SequencerModule(ModuleBase):
    """会话分析模块 - 专家级实现"""
    
    def __init__(self):
        super().__init__("Sequencer", "专家级会话Token随机性分析工具")
        self._samples: List[TokenSample] = []
        self._analysis: Optional[RandomnessAnalysis] = None
        self._worker: Optional[SequencerWorker] = None
        
    def _create_ui(self) -> QWidget:
        """创建UI"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        
        tabs = QTabWidget()
        
        collection_tab = self._create_collection_tab()
        tabs.addTab(collection_tab, "📥 样本采集")
        
        analysis_tab = self._create_analysis_tab()
        tabs.addTab(analysis_tab, "📊 分析结果")
        
        statistics_tab = self._create_statistics_tab()
        tabs.addTab(statistics_tab, "📈 统计详情")
        
        distribution_tab = self._create_distribution_tab()
        tabs.addTab(distribution_tab, "📉 字符分布")
        
        layout.addWidget(tabs)
        return widget
        
    def _create_collection_tab(self) -> QWidget:
        """创建样本采集标签"""
        w = QWidget()
        layout = QVBoxLayout(w)
        
        live_capture_group = QGroupBox("实时采集")
        lc_layout = QVBoxLayout(live_capture_group)
        
        lc_info = QLabel("从代理或重放模块自动捕获Token，支持Session ID、CSRF Token、JWT等")
        lc_info.setWordWrap(True)
        lc_info.setStyleSheet("color: #666; padding: 5px; background: #f5f5f5; border-radius: 3px;")
        lc_layout.addWidget(lc_info)
        
        form_layout = QFormLayout()
        
        self.token_regex = QLineEdit()
        self.token_regex.setText("session[_-]?id|csrf[_-]?token|jwt|access[_-]?token")
        form_layout.addRow("Token正则:", self.token_regex)
        
        self.auto_capture = QCheckBox("自动捕获匹配的Token")
        form_layout.addRow(self.auto_capture)
        
        lc_layout.addLayout(form_layout)
        
        btn_layout = QHBoxLayout()
        start_capture_btn = QPushButton("▶️ 开始捕获")
        start_capture_btn.clicked.connect(self._start_capture)
        stop_capture_btn = QPushButton("⏹️ 停止捕获")
        stop_capture_btn.clicked.connect(self._stop_capture)
        btn_layout.addWidget(start_capture_btn)
        btn_layout.addWidget(stop_capture_btn)
        lc_layout.addLayout(btn_layout)
        
        layout.addWidget(live_capture_group)
        
        manual_group = QGroupBox("手动添加")
        m_layout = QVBoxLayout(manual_group)
        
        m_form = QFormLayout()
        
        self.token_input = QTextEdit()
        self.token_input.setMaximumHeight(100)
        self.token_input.setPlaceholderText("每行一个Token...")
        self.token_input.setFont(QFont("Consolas", 9))
        m_form.addRow("Token列表:", self.token_input)
        
        self.token_type = QComboBox()
        self.token_type.addItems(["Session ID", "CSRF Token", "JWT", "API Key", "其他"])
        m_form.addRow("Token类型:", self.token_type)
        
        m_layout.addLayout(m_form)
        
        m_btn_layout = QHBoxLayout()
        add_btn = QPushButton("➕ 添加")
        add_btn.clicked.connect(self._add_samples)
        load_btn = QPushButton("📂 加载文件")
        load_btn.clicked.connect(self._load_samples)
        generate_btn = QPushButton("🎲 生成测试样本")
        generate_btn.clicked.connect(self._generate_samples)
        clear_btn = QPushButton("🗑️ 清空")
        clear_btn.clicked.connect(self._clear_samples)
        
        m_btn_layout.addWidget(add_btn)
        m_btn_layout.addWidget(load_btn)
        m_btn_layout.addWidget(generate_btn)
        m_btn_layout.addWidget(clear_btn)
        m_layout.addLayout(m_btn_layout)
        
        layout.addWidget(manual_group)
        
        samples_group = QGroupBox(f"样本列表 (0)")
        s_layout = QVBoxLayout(samples_group)
        
        self.sample_table = QTableWidget()
        self.sample_table.setColumnCount(4)
        self.sample_table.setHorizontalHeaderLabels(["ID", "Token", "类型", "采集时间"])
        self.sample_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.sample_table.setSelectionBehavior(QTableWidget.SelectRows)
        s_layout.addWidget(self.sample_table)
        
        layout.addWidget(samples_group)
        
        analyze_btn = QPushButton("📊 开始分析")
        analyze_btn.setStyleSheet("background: #4CAF50; color: white; padding: 10px; font-weight: bold;")
        analyze_btn.clicked.connect(self._start_analysis)
        layout.addWidget(analyze_btn)
        
        self.samples_group = samples_group
        return w
        
    def _create_analysis_tab(self) -> QWidget:
        """创建分析结果标签"""
        w = QWidget()
        layout = QVBoxLayout(w)
        
        self.summary_browser = QTextBrowser()
        self.summary_browser.setFont(QFont("Consolas", 10))
        layout.addWidget(QLabel("📋 分析摘要:"))
        layout.addWidget(self.summary_browser)
        
        self.recommendations_browser = QTextBrowser()
        self.recommendations_browser.setFont(QFont("Consolas", 9))
        layout.addWidget(QLabel("💡 安全建议:"))
        layout.addWidget(self.recommendations_browser)
        
        layout.addStretch()
        return w
        
    def _create_statistics_tab(self) -> QWidget:
        """创建统计详情标签"""
        w = QWidget()
        layout = QVBoxLayout(w)
        
        self.tests_tree = QTreeWidget()
        self.tests_tree.setHeaderLabels(["测试名称", "结果", "值", "期望范围", "详情"])
        self.tests_tree.header().setSectionResizeMode(QHeaderView.Stretch)
        layout.addWidget(QLabel("🧪 统计测试:"))
        layout.addWidget(self.tests_tree)
        
        self.entropy_browser = QTextBrowser()
        self.entropy_browser.setFont(QFont("Consolas", 9))
        layout.addWidget(QLabel("🔢 熵值分析:"))
        layout.addWidget(self.entropy_browser)
        
        return w
        
    def _create_distribution_tab(self) -> QWidget:
        """创建字符分布标签"""
        w = QWidget()
        layout = QVBoxLayout(w)
        
        self.distribution_browser = QTextBrowser()
        self.distribution_browser.setFont(QFont("Consolas", 9))
        layout.addWidget(self.distribution_browser)
        
        return w
        
    def _start_capture(self):
        """开始捕获"""
        self.log("INFO", "开始实时捕获Token (模拟)")
        QMessageBox.information(None, "提示", "实时捕获功能需要连接代理模块")
        
    def _stop_capture(self):
        """停止捕获"""
        self.log("INFO", "停止实时捕获")
        
    def _add_samples(self):
        """添加样本"""
        tokens_text = self.token_input.toPlainText()
        tokens = [t.strip() for t in tokens_text.split("\n") if t.strip()]
        
        if not tokens:
            QMessageBox.warning(None, "警告", "请输入至少一个Token")
            return
            
        token_type = self.token_type.currentText()
        
        for token in tokens:
            sample = TokenSample(
                id=len(self._samples) + 1,
                value=token,
                timestamp=datetime.now(),
                source="手动",
            )
            self._samples.append(sample)
            
        self._update_sample_table()
        self.token_input.clear()
        self.log("INFO", f"添加 {len(tokens)} 个Token样本")
        
    def _load_samples(self):
        """加载样本"""
        filename, _ = QFileDialog.getOpenFileName(None, "选择样本文件", "", "Text Files (*.txt);;All Files (*)")
        if filename:
            try:
                with open(filename, "r", encoding="utf-8", errors="ignore") as f:
                    tokens = [line.strip() for line in f if line.strip()]
                    
                for token in tokens:
                    sample = TokenSample(
                        id=len(self._samples) + 1,
                        value=token,
                        timestamp=datetime.now(),
                        source=filename
                    )
                    self._samples.append(sample)
                    
                self._update_sample_table()
                self.log("INFO", f"从文件加载 {len(tokens)} 个样本: {filename}")
            except Exception as e:
                QMessageBox.critical(None, "错误", f"加载失败: {e}")
                
    def _generate_samples(self):
        """生成测试样本"""
        count = 100
        token_type = random.choice(["secure", "weak", "medium"])
        
        for i in range(count):
            if token_type == "secure":
                token = ''.join(random.choice('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/') for _ in range(32))
            elif token_type == "weak":
                token = f"session_{i:04d}"
            else:
                timestamp = datetime.now().timestamp()
                random_str = ''.join(random.choice('abcdef0123456789') for _ in range(16))
                token = f"token_{int(timestamp)}_{random_str}"
                
            sample = TokenSample(
                id=len(self._samples) + 1,
                value=token,
                timestamp=datetime.now(),
                source=f"生成 ({token_type})"
            )
            self._samples.append(sample)
            
        self._update_sample_table()
        self.log("INFO", f"生成 {count} 个测试样本 (类型: {token_type})")
        
    def _clear_samples(self):
        """清空样本"""
        self._samples.clear()
        self._analysis = None
        self._update_sample_table()
        self.summary_browser.clear()
        self.recommendations_browser.clear()
        self.tests_tree.clear()
        self.entropy_browser.clear()
        self.distribution_browser.clear()
        self.log("INFO", "清空所有样本")
        
    def _update_sample_table(self):
        """更新样本表格"""
        self.sample_table.setRowCount(0)
        for s in self._samples:
            row = self.sample_table.rowCount()
            self.sample_table.insertRow(row)
            self.sample_table.setItem(row, 0, QTableWidgetItem(str(s.id)))
            self.sample_table.setItem(row, 1, QTableWidgetItem(s.value[:50] + ("..." if len(s.value) > 50 else "")))
            self.sample_table.setItem(row, 2, QTableWidgetItem(s.source))
            self.sample_table.setItem(row, 3, QTableWidgetItem(s.timestamp.strftime("%H:%M:%S")))
            
        self.samples_group.setTitle(f"样本列表 ({len(self._samples)})")
        
    def _start_analysis(self):
        """开始分析"""
        if not self._samples:
            QMessageBox.warning(None, "警告", "请至少添加10个Token样本")
            return
            
        if len(self._samples) < 10:
            QMessageBox.warning(None, "警告", "样本数量不足，至少需要10个样本")
            return
            
        self._worker = SequencerWorker(self._samples)
        self._worker.progress_updated.connect(self._on_progress_updated)
        self._worker.analysis_complete.connect(self._on_analysis_complete)
        self._worker.log_message.connect(lambda msg: self.log("INFO", msg))
        self._worker.error_occurred.connect(lambda err: self.log("ERROR", err))
        self._worker.status_changed.connect(self._on_status_changed)
        
        self._worker.start()
        self.log("INFO", f"开始分析 {len(self._samples)} 个Token样本")
        
    def _on_progress_updated(self, current, total, message):
        """进度更新"""
        self.log("INFO", f"[{current}%] {message}")
        
    def _on_analysis_complete(self, analysis):
        """分析完成"""
        self._analysis = analysis
        self._display_analysis_summary()
        self._display_tests()
        self._display_entropy()
        self._display_distribution()
        self.log("INFO", f"分析完成! 评分: {analysis.overall_score.value}")
        
    def _on_status_changed(self, status):
        """状态改变"""
        self.log("INFO", status)
        
    def _display_analysis_summary(self):
        """显示分析摘要"""
        if not self._analysis:
            return
            
        score_color = {
            RandomnessScore.EXCELLENT: "#4CAF50",
            RandomnessScore.GOOD: "#8BC34A",
            RandomnessScore.FAIR: "#FFC107",
            RandomnessScore.POOR: "#FF9800",
            RandomnessScore.VERY_POOR: "#F44336"
        }.get(self._analysis.overall_score, "#666")
        
        summary = f"""
<h2 style="color: {score_color}">随机性分析报告</h2>

<table style="width: 100%; border-collapse: collapse;">
  <tr><td style="padding: 5px;"><b>样本总数:</b></td><td>{self._analysis.total_samples}</td></tr>
  <tr><td style="padding: 5px;"><b>唯一Token:</b></td><td>{self._analysis.unique_tokens}</td></tr>
  <tr><td style="padding: 5px;"><b>重复Token:</b></td><td style="color: {'red' if self._analysis.duplicates > 0 else 'green'}">{self._analysis.duplicates}</td></tr>
  <tr><td style="padding: 5px;"><b>平均长度:</b></td><td>{self._analysis.avg_length:.2f} (±{self._analysis.std_length:.2f})</td></tr>
  <tr><td style="padding: 5px;"><b>长度范围:</b></td><td>{self._analysis.min_length} - {self._analysis.max_length}</td></tr>
  <tr><td style="padding: 5px;"><b>香农熵:</b></td><td>{self._analysis.entropy.shannon_entropy:.4f} bits/char</td></tr>
  <tr><td style="padding: 5px;"><b>字符集大小:</b></td><td>{self._analysis.entropy.charset_size}</td></tr>
  <tr><td style="padding: 5px;"><b>总体评分:</b></td><td style="color: {score_color}; font-weight: bold">{self._analysis.overall_score.value}</td></tr>
  <tr><td style="padding: 5px;"><b>风险等级:</b></td><td style="color: {'red' if self._analysis.risk_level == '高' else 'green'}">{self._analysis.risk_level}</td></tr>
</table>
"""
        self.summary_browser.setHtml(summary)
        
        rec_text = "📝 安全建议:\n\n"
        for rec in self._analysis.recommendations:
            rec_text += f"• {rec}\n"
        self.recommendations_browser.setText(rec_text)
        
    def _display_tests(self):
        """显示测试结果"""
        if not self._analysis:
            return
            
        self.tests_tree.clear()
        
        for test in self._analysis.tests:
            result_icon = {
                TestResult.PASS: "✅",
                TestResult.FAIL: "❌",
                TestResult.WARNING: "⚠️"
            }.get(test.result, "")
            
            item = QTreeWidgetItem([
                test.name,
                f"{result_icon} {test.result.value}",
                f"{test.value:.4f}" if isinstance(test.value, float) else str(test.value),
                test.expected_range,
                test.details
            ])
            
            color = {
                TestResult.PASS: QColor("#4CAF50"),
                TestResult.FAIL: QColor("#F44336"),
                TestResult.WARNING: QColor("#FFC107")
            }.get(test.result, QColor("#666"))
            
            for col in range(5):
                item.setForeground(col, color)
                
            self.tests_tree.addTopLevelItem(item)
            
    def _display_entropy(self):
        """显示熵值分析"""
        if not self._analysis:
            return
            
        entropy = self._analysis.entropy
        
        entropy_text = f"""
🔢 熵值分析详情

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
香农熵:        {entropy.shannon_entropy:.4f} bits/char
最小熵:        {entropy.min_entropy:.4f} bits/char
最大熵:        {entropy.max_entropy:.4f} bits/char
有效熵:        {entropy.effective_entropy:.4f} bits/char
每字符位数:    {entropy.bits_per_char:.4f} bits
字符集大小:    {entropy.charset_size}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

字符集: {entropy.charset[:100]}{'...' if len(entropy.charset) > 100 else ''}

📊 熵值评级:
"""
        if entropy.shannon_entropy >= 6.0:
            entropy_text += "✅ 优秀 (密码学安全级别)"
        elif entropy.shannon_entropy >= 5.0:
            entropy_text += "✅ 良好 (预测困难)"
        elif entropy.shannon_entropy >= 4.0:
            entropy_text += "⚠️ 一般 (存在可预测风险)"
        elif entropy.shannon_entropy >= 3.0:
            entropy_text += "❌ 差 (易于预测)"
        else:
            entropy_text += "❌ 非常差 (高度可预测)"
            
        self.entropy_browser.setText(entropy_text)
        
    def _display_distribution(self):
        """显示字符分布"""
        if not self._analysis or not self._samples:
            return
            
        all_chars = ''.join(s.value for s in self._samples)
        freq = Counter(all_chars)
        total = len(all_chars)
        
        sorted_dist = sorted(freq.items(), key=lambda x: -x[1])
        
        dist_text = "📉 字符分布 (前30):\n\n"
        dist_text += "字符 | 出现次数 | 百分比 | 分布图\n"
        dist_text += "━" * 60 + "\n"
        
        max_count = sorted_dist[0][1] if sorted_dist else 1
        
        for char, count in sorted_dist[:30]:
            percentage = (count / total) * 100
            bar_length = int(30 * count / max_count)
            display_char = repr(char) if char in ['\n', '\t', ' ', '\x00'] else char
            bar = "█" * bar_length
            
            dist_text += f"{display_char:<6} | {count:<8} | {percentage:5.2f}% | {bar}\n"
            
        self.distribution_browser.setText(dist_text)
        
    def get_samples(self) -> List[TokenSample]:
        """获取样本"""
        return self._samples.copy()
        
    def get_analysis(self) -> Optional[RandomnessAnalysis]:
        """获取分析结果"""
        return self._analysis
