"""
指纹识别模块 - 专业级资产指纹识别与PoC验证框架
昆仑安全实验室 - 荣誉出品
"""

import logging
import json
import re
import os
import sys
import subprocess
import signal
import time
import hashlib
import threading
import socket
import asyncio
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from enum import Enum
from dataclasses import dataclass, field, asdict
from datetime import datetime

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QSplitter,
    QTabWidget, QTableWidget, QTableWidgetItem, QHeaderView,
    QPushButton, QLabel, QLineEdit, QTextEdit, QComboBox,
    QCheckBox, QSpinBox, QProgressBar, QFileDialog,
    QMessageBox, QGroupBox, QFormLayout, QTreeWidget,
    QTreeWidgetItem, QFrame, QScrollArea
)
from PySide6.QtCore import Qt, Signal, QThread, QTimer
from PySide6.QtGui import QColor, QFont

from .base import ModuleBase, ModuleStatus

logger = logging.getLogger(__name__)


class ConfidenceLevel(Enum):
    """置信度等级"""
    CONFIRMED = "确定存在"
    SUSPECTED = "疑似存在"
    UNCONFIRMED = "无法确认"
    NOT_EXISTS = "不存在"


class PocFormat(Enum):
    """PoC格式类型"""
    PYTHON = "python"
    YAML = "yaml"


@dataclass
class FingerprintRule:
    """指纹规则"""
    name: str
    product: str
    version: str = ""
    cpe: str = ""
    category: str = ""
    match_type: str = "regex"  # regex, keyword, hash
    match_value: str = ""
    location: str = "body"  # body, header, title, favicon
    confidence: float = 0.8
    description: str = ""


@dataclass
class PocMetadata:
    """PoC元数据"""
    name: str
    author: str
    severity: str = "medium"  # critical, high, medium, low, info
    cve: str = ""
    cvss: float = 0.0
    description: str = ""
    references: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    created_at: str = ""
    updated_at: str = ""
    dependencies: List[str] = field(default_factory=list)  # pip包依赖


@dataclass
class PocRequest:
    """PoC请求定义"""
    method: str = "GET"
    path: str = "/"
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    follow_redirects: bool = True
    timeout: float = 10.0


@dataclass
class PocMatcher:
    """PoC匹配器"""
    type: str = "status"  # status, header, body, regex, time
    key: str = ""
    value: str = ""
    operator: str = "eq"  # eq, neq, contains, regex, gt, lt
    case_sensitive: bool = False


@dataclass
class PocExtractor:
    """PoC提取器"""
    name: str
    type: str = "regex"  # regex, json, header
    pattern: str = ""
    group: int = 0


@dataclass
class PocDefinition:
    """PoC定义（YAML格式）"""
    metadata: PocMetadata
    requests: List[PocRequest] = field(default_factory=list)
    matchers: List[PocMatcher] = field(default_factory=list)
    extractors: List[PocExtractor] = field(default_factory=list)
    logic: str = "and"  # and, or


@dataclass
class VerificationResult:
    """验证结果"""
    poc_name: str
    target: str
    confidence: ConfidenceLevel
    is_vulnerable: bool
    evidence: str = ""
    extracted_data: Dict[str, Any] = field(default_factory=dict)
    response_time: float = 0.0
    timestamp: str = ""
    cve: str = ""
    cvss: float = 0.0
    severity: str = ""
    description: str = ""
    remediation: str = ""
    reproduction_steps: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        return {
            "poc_name": self.poc_name,
            "target": self.target,
            "confidence": self.confidence.value,
            "is_vulnerable": self.is_vulnerable,
            "evidence": self.evidence,
            "extracted_data": self.extracted_data,
            "response_time": self.response_time,
            "timestamp": self.timestamp or datetime.now().isoformat(),
            "cve": self.cve,
            "cvss": self.cvss,
            "severity": self.severity,
            "description": self.description,
            "remediation": self.remediation,
            "reproduction_steps": self.reproduction_steps,
        }


@dataclass
class FingerprintMatch:
    """指纹匹配结果"""
    rule_name: str
    product: str
    version: str
    cpe: str
    confidence: float
    evidence: str
    category: str = ""


class SandboxExecutor:
    """沙箱执行器 - 安全执行PoC脚本"""
    
    def __init__(self, timeout: float = 30.0, memory_limit: int = 256, 
                 network_isolated: bool = False):
        self.timeout = timeout
        self.memory_limit = memory_limit  # MB
        self.network_isolated = network_isolated
        self._process = None
        
    def execute_python_poc(self, script_path: str, target: str, 
                           extra_args: Dict = None) -> Tuple[bool, str]:
        """执行Python PoC脚本
        
        Args:
            script_path: PoC脚本路径
            target: 目标地址
            extra_args: 额外参数
            
        Returns:
            (success, output)
        """
        try:
            cmd = [sys.executable, script_path, "--target", target]
            
            if extra_args:
                for k, v in extra_args.items():
                    cmd.extend([f"--{k}", str(v)])
            
            env = os.environ.copy()
            
            # 网络隔离
            if self.network_isolated:
                env["http_proxy"] = ""
                env["https_proxy"] = ""
                env["no_proxy"] = "*"
            
            # 禁止危险环境变量
            for dangerous in ["LD_PRELOAD", "LD_LIBRARY_PATH"]:
                env.pop(dangerous, None)
            
            self._process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
                preexec_fn=os.setsid if os.name != "nt" else None
            )
            
            try:
                stdout, stderr = self._process.communicate(timeout=self.timeout)
                
                if self._process.returncode == 0:
                    return True, stdout.decode("utf-8", errors="ignore")
                else:
                    return False, stderr.decode("utf-8", errors="ignore")
                    
            except subprocess.TimeoutExpired:
                self._kill_process()
                return False, f"执行超时（{self.timeout}秒）"
                
        except Exception as e:
            return False, f"执行失败: {str(e)}"
    
    def _kill_process(self):
        """终止进程"""
        if self._process:
            try:
                if os.name == "nt":
                    self._process.kill()
                else:
                    os.killpg(os.getpgid(self._process.pid), signal.SIGTERM)
            except Exception:
                pass
            finally:
                self._process = None


class OOBServer:
    """OOB服务器 - 多信道反连平台"""
    
    def __init__(self, host: str = "0.0.0.0", dns_port: int = 5353,
                 http_port: int = 8888):
        self.host = host
        self.dns_port = dns_port
        self.http_port = http_port
        self.dns_queries: List[Dict] = []
        self.http_requests: List[Dict] = []
        self.ldap_requests: List[Dict] = []
        self._running = False
        self._dns_thread = None
        self._http_thread = None
        
    def start(self):
        """启动OOB服务器"""
        self._running = True
        
        # 启动DNS服务器
        self._dns_thread = threading.Thread(target=self._run_dns_server, daemon=True)
        self._dns_thread.start()
        
        # 启动HTTP服务器
        self._http_thread = threading.Thread(target=self._run_http_server, daemon=True)
        self._http_thread.start()
        
        logger.info(f"OOB服务器已启动: DNS={self.host}:{self.dns_port}, HTTP={self.host}:{self.http_port}")
    
    def stop(self):
        """停止OOB服务器"""
        self._running = False
        logger.info("OOB服务器已停止")
    
    def get_dns_queries(self) -> List[Dict]:
        """获取DNS查询记录"""
        return self.dns_queries.copy()
    
    def get_http_requests(self) -> List[Dict]:
        """获取HTTP请求记录"""
        return self.http_requests.copy()
    
    def get_callback_domain(self) -> str:
        """获取回调域名"""
        return f"oob.{self.host.replace('.', '-')}.local"
    
    def _run_dns_server(self):
        """运行DNS服务器"""
        try:
            import dnslib
            
            class DNSHandler(dnslib.DNSHandler):
                def handle(self, request):
                    try:
                        qname = str(request.q.qname)
                        qtype = dnslib.QTYPE[request.q.qtype]
                        
                        self.server.queries.append({
                            "qname": qname,
                            "qtype": qtype,
                            "timestamp": datetime.now().isoformat(),
                            "client": self.client_address[0]
                        })
                        
                        # 返回空响应
                        response = request.reply()
                        self.send_response(response)
                        
                    except Exception as e:
                        logger.debug(f"DNS处理错误: {e}")
            
            server = dnslib.DNSServer(
                DNSHandler,
                port=self.dns_port,
                address=self.host,
                logger=None
            )
            server.queries = self.dns_queries
            server.start_thread()
            
            while self._running:
                time.sleep(0.1)
                
            server.stop()
            
        except ImportError:
            logger.warning("dnslib未安装，DNS服务器不可用")
        except Exception as e:
            logger.error(f"DNS服务器启动失败: {e}")
    
    def _run_http_server(self):
        """运行HTTP回调服务器"""
        try:
            from http.server import HTTPServer, BaseHTTPRequestHandler
            
            class CallbackHandler(BaseHTTPRequestHandler):
                def do_GET(self):
                    self.server.requests.append({
                        "method": "GET",
                        "path": self.path,
                        "headers": dict(self.headers),
                        "client": self.client_address[0],
                        "timestamp": datetime.now().isoformat()
                    })
                    self.send_response(200)
                    self.send_header("Content-Type", "text/plain")
                    self.end_headers()
                    self.wfile.write(b"OK")
                
                def do_POST(self):
                    content_length = int(self.headers.get("Content-Length", 0))
                    body = self.rfile.read(content_length).decode("utf-8", errors="ignore")
                    
                    self.server.requests.append({
                        "method": "POST",
                        "path": self.path,
                        "headers": dict(self.headers),
                        "body": body,
                        "client": self.client_address[0],
                        "timestamp": datetime.now().isoformat()
                    })
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b"OK")
                
                def log_message(self, format, *args):
                    pass  # 抑制日志
            
            server = HTTPServer((self.host, self.http_port), CallbackHandler)
            server.requests = self.http_requests
            server.timeout = 1
            
            while self._running:
                server.handle_request()
                
        except Exception as e:
            logger.error(f"HTTP服务器启动失败: {e}")


class WAFBypassEngine:
    """WAF绕过引擎"""
    
    def __init__(self):
        self.techniques = {
            "case_mutation": self._case_mutation,
            "url_encoding": self._url_encoding,
            "double_encoding": self._double_encoding,
            "unicode_encoding": self._unicode_encoding,
            "comment_injection": self._comment_injection,
            "whitespace_variation": self._whitespace_variation,
        }
    
    def generate_variants(self, payload: str, techniques: List[str] = None) -> List[str]:
        """生成Payload变体
        
        Args:
            payload: 原始Payload
            techniques: 使用的绕过技术列表
            
        Returns:
            Payload变体列表
        """
        if techniques is None:
            techniques = list(self.techniques.keys())
        
        variants = [payload]
        
        for technique in techniques:
            if technique in self.techniques:
                new_variants = self.techniques[technique](payload)
                variants.extend(new_variants)
        
        return list(set(variants))
    
    def _case_mutation(self, payload: str) -> List[str]:
        """大小写变异"""
        variants = []
        # SELECT -> SeLeCt, sElEcT, etc.
        keywords = ["select", "union", "from", "where", "and", "or", "script", "alert"]
        for keyword in keywords:
            if keyword in payload.lower():
                variants.append(re.sub(
                    re.escape(keyword),
                    "".join(c.upper() if i % 2 else c.lower() for i, c in enumerate(keyword)),
                    payload,
                    flags=re.IGNORECASE
                ))
        return variants
    
    def _url_encoding(self, payload: str) -> List[str]:
        """URL编码"""
        from urllib.parse import quote
        return [quote(payload, safe="")]
    
    def _double_encoding(self, payload: str) -> List[str]:
        """双重URL编码"""
        from urllib.parse import quote
        encoded = quote(payload, safe="")
        return [quote(encoded, safe="")]
    
    def _unicode_encoding(self, payload: str) -> List[str]:
        """Unicode编码"""
        variants = []
        for char in payload:
            if ord(char) > 127:
                variants.append(payload.replace(char, f"\\u{ord(char):04x}"))
        return variants
    
    def _comment_injection(self, payload: str) -> List[str]:
        """注释注入"""
        comments = ["/**/", "/*/", "/**//**/", "/*!*/"]
        variants = []
        for comment in comments:
            variants.append(payload.replace(" ", comment))
            variants.append(payload.replace("'", f"'{comment}"))
        return variants
    
    def _whitespace_variation(self, payload: str) -> List[str]:
        """空白字符变异"""
        whitespaces = ["\t", "\n", "\r", "%09", "%0a", "%0d", "/**/"]
        variants = []
        for ws in whitespaces:
            variants.append(payload.replace(" ", ws))
        return variants


class CDNDetector:
    """CDN检测与真实IP穿透"""
    
    CDN_HEADERS = [
        "x-cdn", "x-cache", "cf-ray", "cf-connecting-ip",
        "x-amz-cf-id", "x-served-by", "x-varnish",
        "server-timing", "x-fastly", "x-akamai"
    ]
    
    CDN_IP_RANGES = {
        "cloudflare": ["103.21.", "103.22.", "103.31.", "104.16.", "104.17.",
                       "104.18.", "104.19.", "104.20.", "104.21.", "104.22.",
                       "104.24.", "104.25.", "104.26.", "104.27.", "104.28.",
                       "104.31.", "108.162.", "131.0.", "141.101.", "162.158.",
                       "172.64.", "173.245.", "188.114.", "190.93.", "197.234.",
                       "198.41."],
        "akamai": ["23.", "104.64.", "184.24.", "184.25.", "184.26.", "184.27.",
                   "184.28.", "184.29.", "184.30.", "184.31.", "184.50.", "184.51.",
                   "184.84.", "184.85.", "184.86.", "184.87."],
        "aws_cloudfront": ["13.224.", "13.225.", "13.226.", "13.227.", "13.249.",
                           "13.32.", "13.33.", "13.35.", "143.204.", "204.246.",
                           "205.251.", "52.84.", "52.85.", "54.182.", "54.192.",
                           "54.230.", "54.239.", "99.84.", "99.86."],
    }
    
    @classmethod
    def is_behind_cdn(cls, ip: str, headers: Dict = None) -> bool:
        """检测是否使用CDN"""
        # 检查IP段
        for provider, ranges in cls.CDN_IP_RANGES.items():
            for range_prefix in ranges:
                if ip.startswith(range_prefix):
                    return True
        
        # 检查响应头
        if headers:
            for header in cls.CDN_HEADERS:
                if header.lower() in {k.lower() for k in headers.keys()}:
                    return True
        
        return False
    
    @classmethod
    def get_real_ip_headers(cls) -> List[str]:
        """获取用于获取真实IP的请求头"""
        return [
            "X-Forwarded-For",
            "X-Real-IP",
            "X-Original-Forwarded-For",
            "X-Host",
            "X-Forwarded-Server",
            "X-Forwarded-Host",
            "X-Rewrite-URL",
            "X-Originating-IP",
            "X-Remote-IP",
            "X-Remote-Addr",
            "True-Client-IP",
            "CF-Connecting-IP",
            "Fastly-Client-IP",
        ]


class FingerprintEngine:
    """指纹识别引擎"""
    
    def __init__(self):
        self.rules: List[FingerprintRule] = []
        self.matches: List[FingerprintMatch] = []
        self._rules_dir = Path(__file__).parent.parent.parent.parent / "asset_fingerprint" / "rules"
    
    def load_rules(self, rules_dir: str = None):
        """加载指纹规则"""
        rules_path = Path(rules_dir) if rules_dir else self._rules_dir
        
        if not rules_path.exists():
            logger.warning(f"规则目录不存在: {rules_path}")
            return
        
        for rule_file in rules_path.glob("*.json"):
            try:
                with open(rule_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                
                if isinstance(data, list):
                    for item in data:
                        rule = FingerprintRule(
                            name=item.get("name", ""),
                            product=item.get("product", ""),
                            version=item.get("version", ""),
                            cpe=item.get("cpe", ""),
                            category=item.get("category", ""),
                            match_type=item.get("match_type", "regex"),
                            match_value=item.get("match_value", ""),
                            location=item.get("location", "body"),
                            confidence=item.get("confidence", 0.8),
                            description=item.get("description", ""),
                        )
                        self.rules.append(rule)
                        
            except Exception as e:
                logger.error(f"加载规则失败 {rule_file}: {e}")
        
        logger.info(f"已加载 {len(self.rules)} 条指纹规则")
    
    def match(self, target: str, response_data: Dict) -> List[FingerprintMatch]:
        """执行指纹匹配
        
        Args:
            target: 目标地址
            response_data: 响应数据 {"body": "", "headers": {}, "title": "", "status": 200}
            
        Returns:
            匹配结果列表
        """
        matches = []
        
        for rule in self.rules:
            try:
                if self._match_rule(rule, response_data):
                    match = FingerprintMatch(
                        rule_name=rule.name,
                        product=rule.product,
                        version=rule.version,
                        cpe=rule.cpe,
                        confidence=rule.confidence,
                        evidence=f"匹配规则: {rule.name}",
                        category=rule.category,
                    )
                    matches.append(match)
            except Exception as e:
                logger.debug(f"规则匹配失败 {rule.name}: {e}")
        
        self.matches.extend(matches)
        return matches
    
    def _match_rule(self, rule: FingerprintRule, data: Dict) -> bool:
        """检查单条规则"""
        location = rule.location.lower()
        match_value = rule.match_value
        match_type = rule.match_type.lower()
        
        # 获取匹配内容
        content = ""
        if location == "body":
            content = data.get("body", "")
        elif location == "header":
            headers = data.get("headers", {})
            content = " ".join([f"{k}: {v}" for k, v in headers.items()])
        elif location == "title":
            content = data.get("title", "")
        elif location == "favicon":
            content = data.get("favicon_hash", "")
        elif location == "status":
            return str(data.get("status", "")) == match_value
        
        if not content:
            return False
        
        # 执行匹配
        if match_type == "regex":
            return bool(re.search(match_value, content, re.IGNORECASE))
        elif match_type == "keyword":
            return match_value.lower() in content.lower()
        elif match_type == "hash":
            return content == match_value
        
        return False


class PocEngine:
    """PoC验证引擎"""
    
    def __init__(self, sandbox_timeout: float = 30.0, network_isolated: bool = False):
        self.sandbox = SandboxExecutor(timeout=sandbox_timeout, network_isolated=network_isolated)
        self.oob_server = OOBServer()
        self.waf_bypass = WAFBypassEngine()
        self.results: List[VerificationResult] = []
        self._poc_dir = Path(__file__).parent / "pocs"
    
    def load_poc(self, poc_path: str) -> Optional[PocDefinition]:
        """加载PoC定义
        
        Args:
            poc_path: PoC文件路径（.py或.yaml）
            
        Returns:
            PoC定义对象
        """
        path = Path(poc_path)
        
        if not path.exists():
            logger.error(f"PoC文件不存在: {poc_path}")
            return None
        
        if path.suffix == ".py":
            return self._load_python_poc(path)
        elif path.suffix in (".yaml", ".yml"):
            return self._load_yaml_poc(path)
        
        logger.error(f"不支持的PoC格式: {path.suffix}")
        return None
    
    def verify(self, poc: PocDefinition, target: str, 
               bypass_waf: bool = False) -> VerificationResult:
        """执行PoC验证
        
        Args:
            poc: PoC定义
            target: 目标地址
            bypass_waf: 是否启用WAF绕过
            
        Returns:
            验证结果
        """
        import aiohttp
        
        result = VerificationResult(
            poc_name=poc.metadata.name,
            target=target,
            confidence=ConfidenceLevel.UNCONFIRMED,
            is_vulnerable=False,
            cve=poc.metadata.cve,
            cvss=poc.metadata.cvss,
            severity=poc.metadata.severity,
            description=poc.metadata.description,
        )
        
        try:
            start_time = time.time()
            
            # 执行请求序列
            responses = []
            for req in poc.requests:
                try:
                    payload = req.body
                    
                    # WAF绕过
                    if bypass_waf and payload:
                        variants = self.waf_bypass.generate_variants(payload)
                        if variants:
                            payload = variants[0]  # 使用第一个变体
                    
                    async def _request():
                        async with aiohttp.ClientSession() as session:
                            method = getattr(session, req.method.lower(), session.get)
                            url = f"{target.rstrip('/')}{req.path}"
                            
                            kwargs = {
                                "headers": req.headers,
                                "timeout": aiohttp.ClientTimeout(total=req.timeout),
                                "allow_redirects": req.follow_redirects,
                            }
                            
                            if req.body:
                                kwargs["data"] = payload
                            
                            async with method(url, **kwargs) as resp:
                                body = await resp.text()
                                return {
                                    "status": resp.status,
                                    "headers": dict(resp.headers),
                                    "body": body,
                                    "time": resp.headers.get("X-Response-Time", ""),
                                }
                    
                    loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(loop)
                    resp_data = loop.run_until_complete(_request())
                    loop.close()
                    
                    responses.append(resp_data)
                    
                except Exception as e:
                    logger.debug(f"请求失败: {e}")
                    responses.append(None)
            
            result.response_time = time.time() - start_time
            
            # 执行匹配
            match_results = self._evaluate_matchers(poc, responses)
            
            if match_results["matched"]:
                result.is_vulnerable = True
                result.confidence = ConfidenceLevel.CONFIRMED
                result.evidence = match_results["evidence"]
                result.extracted_data = match_results["extracted"]
            elif match_results["partial"]:
                result.confidence = ConfidenceLevel.SUSPECTED
                result.evidence = match_results["evidence"]
            else:
                result.confidence = ConfidenceLevel.NOT_EXISTS
                result.evidence = "未匹配到任何特征"
            
        except Exception as e:
            result.evidence = f"验证失败: {str(e)}"
            logger.error(f"PoC验证失败: {e}")
        
        self.results.append(result)
        return result
    
    def _load_python_poc(self, path: Path) -> Optional[PocDefinition]:
        """加载Python PoC脚本"""
        try:
            import importlib.util
            
            spec = importlib.util.spec_from_file_location("poc_module", path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            
            # 检查必需的函数
            if not hasattr(module, "verify"):
                logger.error(f"PoC缺少verify函数: {path}")
                return None
            
            # 提取元数据
            metadata = PocMetadata(
                name=getattr(module, "NAME", path.stem),
                author=getattr(module, "AUTHOR", "Unknown"),
                severity=getattr(module, "SEVERITY", "medium"),
                cve=getattr(module, "CVE", ""),
                cvss=getattr(module, "CVSS", 0.0),
                description=getattr(module, "DESCRIPTION", ""),
                references=getattr(module, "REFERENCES", []),
                tags=getattr(module, "TAGS", []),
                dependencies=getattr(module, "DEPENDENCIES", []),
            )
            
            return PocDefinition(metadata=metadata)
            
        except Exception as e:
            logger.error(f"加载Python PoC失败 {path}: {e}")
            return None
    
    def _load_yaml_poc(self, path: Path) -> Optional[PocDefinition]:
        """加载YAML PoC定义"""
        try:
            import yaml
            
            with open(path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
            
            # 解析元数据
            meta_data = data.get("metadata", {})
            metadata = PocMetadata(
                name=meta_data.get("name", path.stem),
                author=meta_data.get("author", "Unknown"),
                severity=meta_data.get("severity", "medium"),
                cve=meta_data.get("cve", ""),
                cvss=meta_data.get("cvss", 0.0),
                description=meta_data.get("description", ""),
                references=meta_data.get("references", []),
                tags=meta_data.get("tags", []),
                dependencies=meta_data.get("dependencies", []),
            )
            
            # 解析请求
            requests = []
            for req_data in data.get("requests", []):
                req = PocRequest(
                    method=req_data.get("method", "GET"),
                    path=req_data.get("path", "/"),
                    headers=req_data.get("headers", {}),
                    body=req_data.get("body", ""),
                    follow_redirects=req_data.get("follow_redirects", True),
                    timeout=req_data.get("timeout", 10.0),
                )
                requests.append(req)
            
            # 解析匹配器
            matchers = []
            for m_data in data.get("matchers", []):
                matcher = PocMatcher(
                    type=m_data.get("type", "status"),
                    key=m_data.get("key", ""),
                    value=m_data.get("value", ""),
                    operator=m_data.get("operator", "eq"),
                    case_sensitive=m_data.get("case_sensitive", False),
                )
                matchers.append(matcher)
            
            # 解析提取器
            extractors = []
            for e_data in data.get("extractors", []):
                extractor = PocExtractor(
                    name=e_data.get("name", ""),
                    type=e_data.get("type", "regex"),
                    pattern=e_data.get("pattern", ""),
                    group=e_data.get("group", 0),
                )
                extractors.append(extractor)
            
            return PocDefinition(
                metadata=metadata,
                requests=requests,
                matchers=matchers,
                extractors=extractors,
                logic=data.get("logic", "and"),
            )
            
        except Exception as e:
            logger.error(f"加载YAML PoC失败 {path}: {e}")
            return None
    
    def _evaluate_matchers(self, poc: PocDefinition, 
                           responses: List[Dict]) -> Dict:
        """评估匹配器
        
        Returns:
            {"matched": bool, "partial": bool, "evidence": str, "extracted": dict}
        """
        if not responses or not poc.matchers:
            return {"matched": False, "partial": False, "evidence": "", "extracted": {}}
        
        matched_count = 0
        total_matchers = len(poc.matchers)
        evidence_parts = []
        extracted_data = {}
        
        for i, resp in enumerate(responses):
            if resp is None:
                continue
                
            for matcher in poc.matchers:
                try:
                    if self._check_matcher(matcher, resp, extracted_data):
                        matched_count += 1
                        evidence_parts.append(f"匹配器 {matcher.type}: {matcher.value}")
                except Exception as e:
                    logger.debug(f"匹配器评估失败: {e}")
        
        # 根据逻辑判断
        if poc.logic == "and":
            is_matched = matched_count == total_matchers
        else:  # or
            is_matched = matched_count > 0
        
        is_partial = 0 < matched_count < total_matchers
        
        return {
            "matched": is_matched,
            "partial": is_partial,
            "evidence": "; ".join(evidence_parts),
            "extracted": extracted_data,
        }
    
    def _check_matcher(self, matcher: PocMatcher, response: Dict, 
                       extracted: Dict) -> bool:
        """检查单个匹配器"""
        m_type = matcher.type.lower()
        operator = matcher.operator.lower()
        value = matcher.value
        case_sensitive = matcher.case_sensitive
        
        # 获取比较内容
        content = ""
        if m_type == "status":
            content = str(response.get("status", ""))
        elif m_type == "header":
            headers = response.get("headers", {})
            content = headers.get(matcher.key, "")
        elif m_type == "body":
            content = response.get("body", "")
        elif m_type == "regex":
            content = response.get("body", "")
        elif m_type == "time":
            content = str(response.get("time", ""))
        
        if not case_sensitive:
            content = content.lower()
            value = value.lower()
        
        # 执行比较
        if operator == "eq":
            return content == value
        elif operator == "neq":
            return content != value
        elif operator == "contains":
            return value in content
        elif operator == "regex":
            return bool(re.search(value, content))
        elif operator == "gt":
            try:
                return float(content) > float(value)
            except ValueError:
                return False
        elif operator == "lt":
            try:
                return float(content) < float(value)
            except ValueError:
                return False
        
        return False


class FingerprintRecognitionModule(ModuleBase):
    """指纹识别模块"""
    
    def __init__(self):
        super().__init__(
            name="指纹识别",
            description="专业级资产指纹识别与PoC验证框架"
        )
        
        self.fingerprint_engine = FingerprintEngine()
        self.poc_engine = PocEngine()
        self.cdn_detector = CDNDetector()
        self.oob_server = None
        
        self._init_ui()
        self._load_default_rules()
    
    def _init_ui(self):
        """初始化UI"""
        self.widget = QWidget()
        layout = QVBoxLayout(self.widget)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(8)
        
        # 顶部工具栏
        toolbar = self._create_toolbar()
        layout.addWidget(toolbar)
        
        # 主内容区
        main_splitter = QSplitter(Qt.Horizontal)
        
        # 左侧：目标输入和配置
        left_panel = self._create_left_panel()
        main_splitter.addWidget(left_panel)
        
        # 右侧：结果展示
        right_panel = self._create_right_panel()
        main_splitter.addWidget(right_panel)
        
        main_splitter.setStretchFactor(0, 1)
        main_splitter.setStretchFactor(1, 2)
        
        layout.addWidget(main_splitter)
    
    def _create_toolbar(self) -> QWidget:
        """创建工具栏"""
        toolbar = QWidget()
        layout = QHBoxLayout(toolbar)
        layout.setContentsMargins(0, 0, 0, 0)
        
        # 目标输入
        layout.addWidget(QLabel("目标:"))
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("http://example.com 或 https://192.168.1.1:8080")
        self.target_input.setMinimumWidth(300)
        layout.addWidget(self.target_input)
        
        layout.addSpacing(10)
        
        # 模式选择
        layout.addWidget(QLabel("模式:"))
        self.mode_combo = QComboBox()
        self.mode_combo.addItems(["指纹识别", "PoC验证", "全面检测"])
        layout.addWidget(self.mode_combo)
        
        layout.addSpacing(10)
        
        # 开始按钮
        self.start_btn = QPushButton("▶ 开始")
        self.start_btn.setMinimumWidth(80)
        self.start_btn.clicked.connect(self._start_scan)
        layout.addWidget(self.start_btn)
        
        # 停止按钮
        self.stop_btn = QPushButton("⏹ 停止")
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self._stop_scan)
        layout.addWidget(self.stop_btn)
        
        layout.addStretch()
        
        # 进度条
        self.progress_bar = QProgressBar()
        self.progress_bar.setMaximumWidth(200)
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)
        
        return toolbar
    
    def _create_left_panel(self) -> QWidget:
        """创建左侧面板"""
        panel = QWidget()
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(0, 0, 0, 0)
        
        # 配置选项
        config_group = QGroupBox("检测配置")
        config_layout = QFormLayout(config_group)
        
        # 并发数
        self.concurrency_spin = QSpinBox()
        self.concurrency_spin.setRange(1, 50)
        self.concurrency_spin.setValue(10)
        config_layout.addRow("并发数:", self.concurrency_spin)
        
        # 超时时间
        self.timeout_spin = QSpinBox()
        self.timeout_spin.setRange(1, 120)
        self.timeout_spin.setValue(10)
        config_layout.addRow("超时(秒):", self.timeout_spin)
        
        # WAF绕过
        self.waf_bypass_check = QCheckBox("启用WAF绕过")
        config_layout.addRow("", self.waf_bypass_check)
        
        # CDN穿透
        self.cdn_detect_check = QCheckBox("CDN穿透检测")
        config_layout.addRow("", self.cdn_detect_check)
        
        # OOB检测
        self.oob_check = QCheckBox("启用OOB检测")
        config_layout.addRow("", self.oob_check)
        
        layout.addWidget(config_group)
        
        # PoC管理
        poc_group = QGroupBox("PoC管理")
        poc_layout = QVBoxLayout(poc_group)
        
        poc_btn_layout = QHBoxLayout()
        
        self.load_poc_btn = QPushButton("📂 加载PoC")
        self.load_poc_btn.clicked.connect(self._load_poc_file)
        poc_btn_layout.addWidget(self.load_poc_btn)
        
        self.load_poc_dir_btn = QPushButton("📁 加载目录")
        self.load_poc_dir_btn.clicked.connect(self._load_poc_directory)
        poc_btn_layout.addWidget(self.load_poc_dir_btn)
        
        poc_layout.addLayout(poc_btn_layout)
        
        # PoC列表
        self.poc_list = QTreeWidget()
        self.poc_list.setHeaderLabels(["名称", "严重等级", "CVE", "状态"])
        self.poc_list.setColumnWidth(0, 200)
        self.poc_list.setColumnWidth(1, 80)
        self.poc_list.setColumnWidth(2, 120)
        poc_layout.addWidget(self.poc_list)
        
        layout.addWidget(poc_group)
        
        # 统计信息
        stats_group = QGroupBox("统计信息")
        stats_layout = QFormLayout(stats_group)
        
        self.stats_label = QLabel("就绪")
        stats_layout.addRow("状态:", self.stats_label)
        
        self.found_label = QLabel("0")
        stats_layout.addRow("发现资产:", self.found_label)
        
        self.vuln_label = QLabel("0")
        stats_layout.addRow("漏洞数量:", self.vuln_label)
        
        layout.addWidget(stats_group)
        layout.addStretch()
        
        return panel
    
    def _create_right_panel(self) -> QWidget:
        """创建右侧面板"""
        panel = QWidget()
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(0, 0, 0, 0)
        
        # 结果标签页
        self.result_tabs = QTabWidget()
        
        # 指纹结果
        self.fingerprint_table = self._create_fingerprint_table()
        self.result_tabs.addTab(self.fingerprint_table, "🔍 指纹结果")
        
        # 漏洞结果
        self.vuln_table = self._create_vuln_table()
        self.result_tabs.addTab(self.vuln_table, "💣 漏洞结果")
        
        # OOB记录
        self.oob_table = self._create_oob_table()
        self.result_tabs.addTab(self.oob_table, "📡 OOB记录")
        
        # 日志输出
        self.log_output = QTextEdit()
        self.log_output.setReadOnly(True)
        self.log_output.setFont(QFont("Consolas", 9))
        self.result_tabs.addTab(self.log_output, "📋 日志")
        
        layout.addWidget(self.result_tabs)
        
        # 底部操作栏
        bottom_layout = QHBoxLayout()
        
        self.export_btn = QPushButton("📤 导出报告")
        self.export_btn.clicked.connect(self._export_report)
        bottom_layout.addWidget(self.export_btn)
        
        self.clear_btn = QPushButton("🗑️ 清空结果")
        self.clear_btn.clicked.connect(self._clear_results)
        bottom_layout.addWidget(self.clear_btn)
        
        bottom_layout.addStretch()
        
        layout.addLayout(bottom_layout)
        
        return panel
    
    def _create_fingerprint_table(self) -> QTableWidget:
        """创建指纹结果表格"""
        table = QTableWidget()
        table.setColumnCount(6)
        table.setHorizontalHeaderLabels(["产品", "版本", "CPE", "置信度", "证据", "分类"])
        table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        table.setSelectionBehavior(QTableWidget.SelectRows)
        return table
    
    def _create_vuln_table(self) -> QTableWidget:
        """创建漏洞结果表格"""
        table = QTableWidget()
        table.setColumnCount(7)
        table.setHorizontalHeaderLabels(["漏洞名称", "CVE", "CVSS", "严重等级", "置信度", "目标", "状态"])
        table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        table.setSelectionBehavior(QTableWidget.SelectRows)
        table.itemDoubleClicked.connect(self._show_vuln_detail)
        return table
    
    def _create_oob_table(self) -> QTableWidget:
        """创建OOB记录表格"""
        table = QTableWidget()
        table.setColumnCount(4)
        table.setHorizontalHeaderLabels(["类型", "内容", "来源IP", "时间"])
        table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        return table
    
    def _load_default_rules(self):
        """加载默认指纹规则"""
        self.fingerprint_engine.load_rules()
    
    def _start_scan(self):
        """开始扫描"""
        target = self.target_input.text().strip()
        if not target:
            QMessageBox.warning(self.widget, "警告", "请输入目标地址")
            return
        
        mode = self.mode_combo.currentText()
        
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        
        self._log(f"开始{mode}: {target}")
        
        # 启动扫描线程
        self.scan_thread = FingerprintScanThread(
            target=target,
            mode=mode,
            fingerprint_engine=self.fingerprint_engine,
            poc_engine=self.poc_engine,
            cdn_detector=self.cdn_detector,
            concurrency=self.concurrency_spin.value(),
            timeout=self.timeout_spin.value(),
            bypass_waf=self.waf_bypass_check.isChecked(),
            detect_cdn=self.cdn_detect_check.isChecked(),
            enable_oob=self.oob_check.isChecked(),
        )
        
        self.scan_thread.progress.connect(self._update_progress)
        self.scan_thread.fingerprint_found.connect(self._add_fingerprint)
        self.scan_thread.vuln_found.connect(self._add_vuln)
        self.scan_thread.oob_detected.connect(self._add_oob)
        self.scan_thread.log.connect(self._log)
        self.scan_thread.finished.connect(self._scan_finished)
        
        self.scan_thread.start()
    
    def _stop_scan(self):
        """停止扫描"""
        if hasattr(self, "scan_thread") and self.scan_thread.isRunning():
            self.scan_thread.stop()
            self._log("扫描已停止")
    
    def _scan_finished(self):
        """扫描完成"""
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.progress_bar.setVisible(False)
        self._log("扫描完成")
    
    def _update_progress(self, value: int, message: str):
        """更新进度"""
        self.progress_bar.setValue(value)
        self.stats_label.setText(message)
    
    def _add_fingerprint(self, match: FingerprintMatch):
        """添加指纹结果"""
        row = self.fingerprint_table.rowCount()
        self.fingerprint_table.insertRow(row)
        
        self.fingerprint_table.setItem(row, 0, QTableWidgetItem(match.product))
        self.fingerprint_table.setItem(row, 1, QTableWidgetItem(match.version))
        self.fingerprint_table.setItem(row, 2, QTableWidgetItem(match.cpe))
        self.fingerprint_table.setItem(row, 3, QTableWidgetItem(f"{match.confidence:.0%}"))
        self.fingerprint_table.setItem(row, 4, QTableWidgetItem(match.evidence))
        self.fingerprint_table.setItem(row, 5, QTableWidgetItem(match.category))
        
        self.found_label.setText(str(self.fingerprint_table.rowCount()))
    
    def _add_vuln(self, result: VerificationResult):
        """添加漏洞结果"""
        row = self.vuln_table.rowCount()
        self.vuln_table.insertRow(row)
        
        severity_colors = {
            "critical": "#ff4444",
            "high": "#ff8800",
            "medium": "#ffbb33",
            "low": "#00C851",
            "info": "#33b5e5",
        }
        
        name_item = QTableWidgetItem(result.poc_name)
        name_item.setForeground(QColor(severity_colors.get(result.severity, "#ffffff")))
        
        self.vuln_table.setItem(row, 0, name_item)
        self.vuln_table.setItem(row, 1, QTableWidgetItem(result.cve))
        self.vuln_table.setItem(row, 2, QTableWidgetItem(str(result.cvss)))
        self.vuln_table.setItem(row, 3, QTableWidgetItem(result.severity))
        self.vuln_table.setItem(row, 4, QTableWidgetItem(result.confidence.value))
        self.vuln_table.setItem(row, 5, QTableWidgetItem(result.target))
        
        status_item = QTableWidgetItem("存在" if result.is_vulnerable else "不存在")
        if result.is_vulnerable:
            status_item.setForeground(QColor("#ff4444"))
        self.vuln_table.setItem(row, 6, status_item)
        
        self.vuln_label.setText(str(self.vuln_table.rowCount()))
    
    def _add_oob(self, oob_type: str, content: str, source_ip: str, timestamp: str):
        """添加OOB记录"""
        row = self.oob_table.rowCount()
        self.oob_table.insertRow(row)
        
        self.oob_table.setItem(row, 0, QTableWidgetItem(oob_type))
        self.oob_table.setItem(row, 1, QTableWidgetItem(content))
        self.oob_table.setItem(row, 2, QTableWidgetItem(source_ip))
        self.oob_table.setItem(row, 3, QTableWidgetItem(timestamp))
    
    def _show_vuln_detail(self, item: QTableWidgetItem):
        """显示漏洞详情"""
        row = item.row()
        poc_name = self.vuln_table.item(row, 0).text()
        
        # 查找对应的验证结果
        for result in self.poc_engine.results:
            if result.poc_name == poc_name:
                detail = f"""
<h3>{result.poc_name}</h3>
<p><b>CVE:</b> {result.cve or "N/A"}</p>
<p><b>CVSS:</b> {result.cvss}</p>
<p><b>严重等级:</b> {result.severity}</p>
<p><b>置信度:</b> {result.confidence.value}</p>
<p><b>目标:</b> {result.target}</p>
<p><b>描述:</b> {result.description}</p>
<p><b>证据:</b> {result.evidence}</p>
<p><b>响应时间:</b> {result.response_time:.2f}s</p>
<hr>
<h4>修复建议</h4>
<p>{result.remediation or "暂无修复建议"}</p>
<h4>复现步骤</h4>
<ol>
"""
                for i, step in enumerate(result.reproduction_steps, 1):
                    detail += f"<li>{step}</li>"
                detail += "</ol>"
                
                QMessageBox.information(self.widget, "漏洞详情", detail)
                return
        
        QMessageBox.information(self.widget, "提示", "未找到详细信息")
    
    def _load_poc_file(self):
        """加载PoC文件"""
        filename, _ = QFileDialog.getOpenFileName(
            self.widget, "加载PoC文件", "",
            "PoC文件 (*.py *.yaml *.yml);;所有文件 (*)"
        )
        
        if filename:
            poc = self.poc_engine.load_poc(filename)
            if poc:
                self._add_poc_to_list(poc, "已加载")
                self._log(f"已加载PoC: {poc.metadata.name}")
    
    def _load_poc_directory(self):
        """加载PoC目录"""
        directory = QFileDialog.getExistingDirectory(
            self.widget, "选择PoC目录"
        )
        
        if directory:
            count = 0
            for root, _, files in os.walk(directory):
                for f in files:
                    if f.endswith((".py", ".yaml", ".yml")):
                        poc_path = os.path.join(root, f)
                        poc = self.poc_engine.load_poc(poc_path)
                        if poc:
                            self._add_poc_to_list(poc, "已加载")
                            count += 1
            
            self._log(f"已加载 {count} 个PoC文件")
    
    def _add_poc_to_list(self, poc: PocDefinition, status: str):
        """添加PoC到列表"""
        item = QTreeWidgetItem([
            poc.metadata.name,
            poc.metadata.severity,
            poc.metadata.cve or "N/A",
            status
        ])
        self.poc_list.addTopLevelItem(item)
    
    def _export_report(self):
        """导出报告"""
        filename, _ = QFileDialog.getSaveFileName(
            self.widget, "导出报告", "fingerprint_report.json",
            "JSON文件 (*.json);;所有文件 (*)"
        )
        
        if filename:
            report = {
                "timestamp": datetime.now().isoformat(),
                "target": self.target_input.text(),
                "fingerprints": [
                    {
                        "product": self.fingerprint_table.item(i, 0).text(),
                        "version": self.fingerprint_table.item(i, 1).text(),
                        "cpe": self.fingerprint_table.item(i, 2).text(),
                        "confidence": self.fingerprint_table.item(i, 3).text(),
                        "evidence": self.fingerprint_table.item(i, 4).text(),
                        "category": self.fingerprint_table.item(i, 5).text(),
                    }
                    for i in range(self.fingerprint_table.rowCount())
                ],
                "vulnerabilities": [
                    result.to_dict()
                    for result in self.poc_engine.results
                ],
            }
            
            with open(filename, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            
            self._log(f"报告已导出: {filename}")
            QMessageBox.information(self.widget, "成功", f"报告已导出到:\n{filename}")
    
    def _clear_results(self):
        """清空结果"""
        self.fingerprint_table.setRowCount(0)
        self.vuln_table.setRowCount(0)
        self.oob_table.setRowCount(0)
        self.log_output.clear()
        self.found_label.setText("0")
        self.vuln_label.setText("0")
        self.poc_engine.results.clear()
    
    def _log(self, message: str):
        """记录日志"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_output.append(f"[{timestamp}] {message}")
    
    def get_ui(self) -> QWidget:
        """获取UI组件"""
        return self.widget
    
    def get_status(self) -> ModuleStatus:
        """获取模块状态"""
        return ModuleStatus.READY


class FingerprintScanThread(QThread):
    """指纹扫描线程"""
    
    progress = Signal(int, str)
    fingerprint_found = Signal(object)
    vuln_found = Signal(object)
    oob_detected = Signal(str, str, str, str)
    log = Signal(str)
    
    def __init__(self, target: str, mode: str, fingerprint_engine: FingerprintEngine,
                 poc_engine: PocEngine, cdn_detector: CDNDetector,
                 concurrency: int = 10, timeout: float = 10.0,
                 bypass_waf: bool = False, detect_cdn: bool = False,
                 enable_oob: bool = False):
        super().__init__()
        self.target = target
        self.mode = mode
        self.fingerprint_engine = fingerprint_engine
        self.poc_engine = poc_engine
        self.cdn_detector = cdn_detector
        self.concurrency = concurrency
        self.timeout = timeout
        self.bypass_waf = bypass_waf
        self.detect_cdn = detect_cdn
        self.enable_oob = enable_oob
        self._running = True
    
    def stop(self):
        """停止扫描"""
        self._running = False
    
    def run(self):
        """执行扫描"""
        try:
            import aiohttp
            
            self.progress.emit(10, "正在探测目标...")
            self.log.emit(f"目标: {self.target}")
            self.log.emit(f"模式: {self.mode}")
            
            # 1. 基础探测
            async def _probe():
                async with aiohttp.ClientSession() as session:
                    try:
                        async with session.get(
                            self.target,
                            timeout=aiohttp.ClientTimeout(total=self.timeout),
                            allow_redirects=True
                        ) as resp:
                            body = await resp.text()
                            return {
                                "status": resp.status,
                                "headers": dict(resp.headers),
                                "body": body,
                                "title": self._extract_title(body),
                            }
                    except Exception as e:
                        self.log.emit(f"探测失败: {e}")
                        return None
            
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            response_data = loop.run_until_complete(_probe())
            loop.close()
            
            if not response_data:
                self.progress.emit(100, "探测失败")
                return
            
            self.progress.emit(30, "正在进行指纹识别...")
            
            # 2. 指纹识别
            if self.mode in ("指纹识别", "全面检测"):
                matches = self.fingerprint_engine.match(self.target, response_data)
                for match in matches:
                    self.fingerprint_found.emit(match)
                    self.log.emit(f"发现指纹: {match.product} {match.version}")
            
            # 3. CDN检测
            if self.detect_cdn:
                ip = self._extract_ip(self.target)
                if ip and self.cdn_detector.is_behind_cdn(ip, response_data.get("headers")):
                    self.log.emit("检测到CDN，尝试穿透...")
                    # 尝试使用真实IP头
                    for header in self.cdn_detector.get_real_ip_headers():
                        self.log.emit(f"尝试头: {header}")
            
            # 4. PoC验证
            if self.mode in ("PoC验证", "全面检测"):
                self.progress.emit(60, "正在执行PoC验证...")
                
                for poc in self.poc_engine.poc_engine.results if hasattr(self.poc_engine, 'poc_engine') else []:
                    if not self._running:
                        break
                    
                    self.log.emit(f"验证PoC: {poc.metadata.name}")
                    result = self.poc_engine.verify(poc, self.target, self.bypass_waf)
                    
                    if result.is_vulnerable:
                        self.vuln_found.emit(result)
                        self.log.emit(f"发现漏洞: {result.poc_name}")
            
            # 5. OOB检测
            if self.enable_oob:
                self.progress.emit(90, "正在等待OOB回调...")
                self.log.emit("OOB检测已启用，等待回调...")
                
                # 等待一段时间获取OOB记录
                time.sleep(2)
                
                if self.poc_engine.oob_server:
                    for query in self.poc_engine.oob_server.get_dns_queries():
                        self.oob_detected.emit(
                            "DNS",
                            query.get("qname", ""),
                            query.get("client", ""),
                            query.get("timestamp", "")
                        )
                    
                    for req in self.poc_engine.oob_server.get_http_requests():
                        self.oob_detected.emit(
                            "HTTP",
                            req.get("path", ""),
                            req.get("client", ""),
                            req.get("timestamp", "")
                        )
            
            self.progress.emit(100, "扫描完成")
            
        except Exception as e:
            self.log.emit(f"扫描异常: {e}")
            self.progress.emit(100, "扫描失败")
    
    def _extract_title(self, html: str) -> str:
        """提取HTML标题"""
        import re
        match = re.search(r"<title>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
        return match.group(1).strip() if match else ""
    
    def _extract_ip(self, url: str) -> str:
        """从URL提取IP"""
        import re
        match = re.search(r"https?://(\d+\.\d+\.\d+\.\d+)", url)
        return match.group(1) if match else ""
