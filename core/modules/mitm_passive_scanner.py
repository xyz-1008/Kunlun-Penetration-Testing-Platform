"""
MITM代理被动扫描集成模块
异步扫描流量，检测常见漏洞
"""

import asyncio
import logging
import re
import json
from typing import Dict, Any, Optional, List, Callable
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

logger = logging.getLogger(__name__)


class VulnType(Enum):
    """漏洞类型"""
    SQL_INJECTION = "SQL注入"
    XSS = "跨站脚本"
    PATH_TRAVERSAL = "路径遍历"
    INFO_DISCLOSURE = "信息泄露"
    AUTH_BYPASS = "越权访问"
    SSRF = "服务端请求伪造"
    COMMAND_INJECTION = "命令注入"


@dataclass
class VulnFinding:
    """漏洞发现"""
    id: str
    vuln_type: VulnType
    severity: str  # low, medium, high, critical
    title: str
    description: str
    request: Any
    response: Any
    evidence: str
    timestamp: datetime
    poc_id: Optional[str] = None


class PassiveScanner:
    """被动扫描器"""
    
    def __init__(self):
        self._rules = []
        self._findings: List[VulnFinding] = []
        self._callbacks: List[Callable] = []
        self._scan_queue = asyncio.Queue()
        self._running = False
        self._scan_task = None
        
        self._load_default_rules()
    
    def _load_default_rules(self):
        """加载默认扫描规则"""
        self._rules = [
            {
                'name': 'SQL注入检测',
                'type': VulnType.SQL_INJECTION,
                'checks': [
                    self._check_sqli_error,
                    self._check_sqli_pattern,
                ]
            },
            {
                'name': 'XSS检测',
                'type': VulnType.XSS,
                'checks': [
                    self._check_xss_reflection,
                ]
            },
            {
                'name': '路径遍历检测',
                'type': VulnType.PATH_TRAVERSAL,
                'checks': [
                    self._check_path_traversal,
                ]
            },
            {
                'name': '信息泄露检测',
                'type': VulnType.INFO_DISCLOSURE,
                'checks': [
                    self._check_info_disclosure,
                ]
            },
            {
                'name': '越权访问检测',
                'type': VulnType.AUTH_BYPASS,
                'checks': [
                    self._check_auth_bypass,
                ]
            },
        ]
    
    def add_callback(self, callback: Callable):
        """添加发现回调"""
        self._callbacks.append(callback)
    
    def start(self):
        """启动扫描器"""
        self._running = True
        self._scan_task = asyncio.create_task(self._scan_loop())
        logger.info("被动扫描器已启动")
    
    def stop(self):
        """停止扫描器"""
        self._running = False
        if self._scan_task:
            self._scan_task.cancel()
        logger.info("被动扫描器已停止")
    
    async def _scan_loop(self):
        """扫描循环"""
        while self._running:
            try:
                request, response = await asyncio.wait_for(
                    self._scan_queue.get(), 
                    timeout=1.0
                )
                await self._scan_request(request, response)
                self._scan_queue.task_done()
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.error(f"扫描循环异常: {e}")
    
    async def submit_request(self, request: Any, response: Any):
        """提交请求到扫描队列"""
        await self._scan_queue.put((request, response))
    
    async def _scan_request(self, request: Any, response: Any):
        """扫描单个请求"""
        import hashlib
        
        for rule in self._rules:
            for check in rule['checks']:
                try:
                    finding = check(request, response)
                    if finding:
                        finding.id = hashlib.md5(
                            f"{request.id}_{rule['name']}_{datetime.utcnow().isoformat()}".encode()
                        ).hexdigest()[:12]
                        finding.timestamp = datetime.utcnow()
                        
                        self._findings.append(finding)
                        
                        # 通知回调
                        for callback in self._callbacks:
                            try:
                                callback(finding)
                            except Exception as e:
                                logger.error(f"回调执行失败: {e}")
                        
                        logger.info(
                            f"发现漏洞: [{finding.severity}] {finding.title} - {request.url}"
                        )
                except Exception as e:
                    logger.error(f"规则检查失败 [{rule['name']}]: {e}")
    
    def _check_sqli_error(self, request: Any, response: Any) -> Optional[VulnFinding]:
        """SQL注入错误检测"""
        if not response or not response.body:
            return None
        
        body_str = response.body.decode('utf-8', errors='replace').lower()
        
        sqli_errors = [
            (r'mysql.*syntax error', 'MySQL语法错误'),
            (r'postgresql.*syntax error', 'PostgreSQL语法错误'),
            (r'sqlite.*syntax error', 'SQLite语法错误'),
            (r'oracle.*sql command not properly ended', 'Oracle SQL错误'),
            (r'microsoft.*oledb.*provider', 'MSSQL错误'),
            (r'you have an error in your sql syntax', '通用SQL语法错误'),
            (r'warning.*mysql_fetch', 'MySQL函数警告'),
        ]
        
        for pattern, desc in sqli_errors:
            if re.search(pattern, body_str):
                return VulnFinding(
                    id='',
                    vuln_type=VulnType.SQL_INJECTION,
                    severity='high',
                    title=f'SQL注入 - {desc}',
                    description=f'响应中包含{desc}，可能存在SQL注入漏洞',
                    request=request,
                    response=response,
                    evidence=re.search(pattern, body_str).group()[:200],
                    timestamp=datetime.utcnow(),
                )
        
        return None
    
    def _check_sqli_pattern(self, request: Any, response: Any) -> Optional[VulnFinding]:
        """SQL注入模式检测"""
        if not request:
            return None
        
        url_lower = request.url.lower()
        body_lower = request.body.decode('utf-8', errors='replace').lower() if request.body else ''
        
        sqli_patterns = [
            r"(?i)('\s*or\s*')",
            r"(?i)(union\s+select)",
            r"(?i)(or\s+1\s*=\s*1)",
            r"(?i)(and\s+1\s*=\s*1)",
        ]
        
        for pattern in sqli_patterns:
            if re.search(pattern, url_lower) or re.search(pattern, body_lower):
                return VulnFinding(
                    id='',
                    vuln_type=VulnType.SQL_INJECTION,
                    severity='medium',
                    title='SQL注入模式',
                    description='请求中包含SQL注入特征模式',
                    request=request,
                    response=response,
                    evidence=f'Pattern: {pattern}',
                    timestamp=datetime.utcnow(),
                )
        
        return None
    
    def _check_xss_reflection(self, request: Any, response: Any) -> Optional[VulnFinding]:
        """XSS反射检测"""
        if not request or not response or not response.body:
            return None
        
        body_str = response.body.decode('utf-8', errors='replace')
        
        # 检查请求参数是否在响应中反射
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(request.url)
        params = parse_qs(parsed.query)
        
        for param_name, param_values in params.items():
            for value in param_values:
                if len(value) > 5 and value in body_str:
                    # 检查是否包含危险字符
                    if any(c in value for c in ['<', '>', '"', "'", 'javascript:', 'onerror']):
                        return VulnFinding(
                            id='',
                            vuln_type=VulnType.XSS,
                            severity='high',
                            title='XSS反射',
                            description=f'参数 {param_name} 的值在响应中反射，可能存在XSS',
                            request=request,
                            response=response,
                            evidence=f'Parameter: {param_name}={value[:100]}',
                            timestamp=datetime.utcnow(),
                        )
        
        return None
    
    def _check_path_traversal(self, request: Any, response: Any) -> Optional[VulnFinding]:
        """路径遍历检测"""
        if not request:
            return None
        
        traversal_patterns = [
            r'\.\./',
            r'\.\.\\',
            r'%2e%2e%2f',
            r'%2e%2e/',
            r'\.\.%2f',
            r'/etc/passwd',
            r'/etc/shadow',
            r'\\windows\\',
            r'c:\\',
        ]
        
        url_lower = request.url.lower()
        for pattern in traversal_patterns:
            if re.search(pattern, url_lower, re.IGNORECASE):
                return VulnFinding(
                    id='',
                    vuln_type=VulnType.PATH_TRAVERSAL,
                    severity='high',
                    title='路径遍历',
                    description='请求中包含路径遍历特征',
                    request=request,
                    response=response,
                    evidence=f'Pattern: {pattern}',
                    timestamp=datetime.utcnow(),
                )
        
        return None
    
    def _check_info_disclosure(self, request: Any, response: Any) -> Optional[VulnFinding]:
        """信息泄露检测"""
        if not response or not response.body:
            return None
        
        body_str = response.body.decode('utf-8', errors='replace')
        headers = response.headers if hasattr(response, 'headers') else {}
        
        # 检查敏感信息
        sensitive_patterns = [
            (r'(?i)(password|passwd|pwd)\s*[:=]\s*\S+', '密码泄露'),
            (r'(?i)(api[_-]?key|apikey)\s*[:=]\s*\S+', 'API密钥泄露'),
            (r'(?i)(token|access_token)\s*[:=]\s*\S+', '令牌泄露'),
            (r'(?i)(secret|private[_-]?key)\s*[:=]\s*\S+', '密钥泄露'),
            (r'(?i)internal[_-]?ip\s*[:=]\s*\S+', '内网IP泄露'),
        ]
        
        for pattern, desc in sensitive_patterns:
            if re.search(pattern, body_str):
                return VulnFinding(
                    id='',
                    vuln_type=VulnType.INFO_DISCLOSURE,
                    severity='medium',
                    title=desc,
                    description=f'响应中包含{desc}',
                    request=request,
                    response=response,
                    evidence=re.search(pattern, body_str).group()[:100],
                    timestamp=datetime.utcnow(),
                )
        
        # 检查敏感响应头
        sensitive_headers = ['server', 'x-powered-by', 'x-aspnet-version']
        for header in sensitive_headers:
            if header in headers:
                return VulnFinding(
                    id='',
                    vuln_type=VulnType.INFO_DISCLOSURE,
                    severity='low',
                    title='敏感响应头',
                    description=f'响应头 {header} 泄露服务器信息',
                    request=request,
                    response=response,
                    evidence=f'{header}: {headers[header]}',
                    timestamp=datetime.utcnow(),
                )
        
        return None
    
    def _check_auth_bypass(self, request: Any, response: Any) -> Optional[VulnFinding]:
        """越权访问检测"""
        if not request or not response:
            return None
        
        # 检查没有认证头但返回200的敏感路径
        sensitive_paths = ['/admin', '/api/admin', '/manage', '/dashboard']
        has_auth = any(
            key.lower() in ['authorization', 'cookie', 'x-token']
            for key in request.headers.keys()
        )
        
        if not has_auth and response.status_code == 200:
            for path in sensitive_paths:
                if path in request.path.lower():
                    return VulnFinding(
                        id='',
                        vuln_type=VulnType.AUTH_BYPASS,
                        severity='high',
                        title='可能的越权访问',
                        description=f'未认证的请求访问了敏感路径: {request.path}',
                        request=request,
                        response=response,
                        evidence=f'Path: {request.path}, Status: {response.status_code}',
                        timestamp=datetime.utcnow(),
                    )
        
        return None
    
    def get_findings(self, limit: int = 100) -> List[VulnFinding]:
        """获取发现列表"""
        return self._findings[-limit:]
    
    def clear_findings(self):
        """清空发现"""
        self._findings.clear()
    
    def get_statistics(self) -> Dict[str, Any]:
        """获取统计信息"""
        stats = {
            'total_findings': len(self._findings),
            'by_severity': {'low': 0, 'medium': 0, 'high': 0, 'critical': 0},
            'by_type': {},
        }
        
        for finding in self._findings:
            stats['by_severity'][finding.severity] = stats['by_severity'].get(finding.severity, 0) + 1
            vuln_type = finding.vuln_type.value
            stats['by_type'][vuln_type] = stats['by_type'].get(vuln_type, 0) + 1
        
        return stats
