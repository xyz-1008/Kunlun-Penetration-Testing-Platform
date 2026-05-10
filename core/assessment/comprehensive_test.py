"""
专业级综合测试脚本模块
基于20年渗透测试经验的自动化测试框架
支持多阶段攻击、漏洞验证和报告生成
"""

import asyncio
import logging
import json
import time
from typing import Dict, List, Optional, Callable, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import aiohttp

logger = logging.getLogger(__name__)

class TestPhase(Enum):
    """测试阶段枚举"""
    RECONNAISSANCE = "reconnaissance"  # 信息收集
    SCANNING = "scanning"              # 扫描探测
    EXPLOITATION = "exploitation"      # 漏洞利用
    POST_EXPLOITATION = "post_exploitation"  # 后渗透
    REPORTING = "reporting"            # 报告生成

class VulnerabilitySeverity(Enum):
    """漏洞严重程度"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

@dataclass
class Target:
    """测试目标"""
    url: str
    host: str = ""
    port: int = 80
    protocol: str = "http"
    parameters: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)
    
    def __post_init__(self):
        if not self.host:
            from urllib.parse import urlparse
            parsed = urlparse(self.url)
            self.host = parsed.hostname or ""
            self.port = parsed.port or (443 if parsed.scheme == 'https' else 80)
            self.protocol = parsed.scheme or "http"

@dataclass
class Vulnerability:
    """漏洞信息"""
    id: str
    name: str
    severity: VulnerabilitySeverity
    description: str
    target: Target
    poc: str = ""
    evidence: str = ""
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    cvss_score: float = 0.0
    timestamp: datetime = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now()
    
    def to_dict(self) -> Dict:
        return {
            'id': self.id,
            'name': self.name,
            'severity': self.severity.value,
            'description': self.description,
            'target': {
                'url': self.target.url,
                'host': self.target.host,
                'port': self.target.port,
                'protocol': self.target.protocol
            },
            'poc': self.poc,
            'evidence': self.evidence,
            'remediation': self.remediation,
            'references': self.references,
            'cvss_score': self.cvss_score,
            'timestamp': self.timestamp.isoformat()
        }

@dataclass
class TestResult:
    """测试结果"""
    test_id: str
    name: str
    phase: TestPhase
    start_time: datetime
    end_time: datetime
    status: str  # running, completed, failed, skipped
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    findings: List[Dict[str, Any]] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    duration: float = 0.0
    
    def to_dict(self) -> Dict:
        return {
            'test_id': self.test_id,
            'name': self.name,
            'phase': self.phase.value,
            'start_time': self.start_time.isoformat(),
            'end_time': self.end_time.isoformat() if self.end_time else "",
            'status': self.status,
            'vulnerabilities': [v.to_dict() for v in self.vulnerabilities],
            'findings': self.findings,
            'errors': self.errors,
            'duration': self.duration
        }

class ComprehensiveTestScript:
    """专业级综合测试脚本"""
    
    def __init__(self):
        # 测试配置
        self.config = {
            'timeout': 30,
            'max_concurrent': 5,
            'retry_count': 3,
            'delay_between_requests': 0.5,
            'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
        # 测试目标
        self.targets: List[Target] = []
        
        # 测试结果
        self.results: Dict[str, TestResult] = {}
        self.vulnerabilities: List[Vulnerability] = []
        
        # 当前测试状态
        self.current_test_id: Optional[str] = None
        self.is_running: bool = False
        
        # 回调函数
        self.on_test_start: Optional[Callable] = None
        self.on_test_progress: Optional[Callable] = None
        self.on_vulnerability_found: Optional[Callable] = None
        self.on_test_complete: Optional[Callable] = None
        
        logger.info("综合测试脚本模块初始化完成")
    
    async def run_comprehensive_test(self, targets: List[Target], 
                                   phases: List[TestPhase] = None) -> str:
        """运行综合测试"""
        if not targets:
            raise ValueError("测试目标不能为空")
        
        self.targets = targets
        test_id = f"test_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        self.current_test_id = test_id
        self.is_running = True
        
        if phases is None:
            phases = list(TestPhase)
        
        # 创建主测试结果
        main_result = TestResult(
            test_id=test_id,
            name="综合安全测试",
            phase=TestPhase.RECONNAISSANCE,
            start_time=datetime.now(),
            end_time=None,
            status="running"
        )
        self.results[test_id] = main_result
        
        # 触发测试开始回调
        if self.on_test_start:
            self.on_test_start(test_id, targets, len(phases))
        
        try:
            for i, phase in enumerate(phases):
                try:
                    # 执行各阶段测试
                    phase_result = await self._execute_phase(phase, targets)
                    
                    # 合并结果
                    main_result.vulnerabilities.extend(phase_result.vulnerabilities)
                    main_result.findings.extend(phase_result.findings)
                    main_result.errors.extend(phase_result.errors)
                    
                    # 记录子结果
                    sub_test_id = f"{test_id}_{phase.value}"
                    self.results[sub_test_id] = phase_result
                    
                    # 触发进度回调
                    if self.on_test_progress:
                        progress = ((i + 1) / len(phases)) * 100
                        self.on_test_progress(test_id, progress, phase.value, i + 1, len(phases))
                
                except Exception as e:
                    error_msg = f"阶段 {phase.value} 执行失败: {str(e)}"
                    main_result.errors.append(error_msg)
                    logger.error(error_msg)
            
            # 完成测试
            main_result.end_time = datetime.now()
            main_result.status = "completed"
            main_result.duration = (main_result.end_time - main_result.start_time).total_seconds()
            
            self.vulnerabilities = main_result.vulnerabilities
            
            # 触发完成回调
            if self.on_test_complete:
                self.on_test_complete(test_id, main_result)
            
            logger.info(f"综合测试完成: {test_id}, 发现 {len(self.vulnerabilities)} 个漏洞")
            return test_id
            
        except Exception as e:
            main_result.status = "failed"
            main_result.errors.append(str(e))
            raise
        finally:
            self.is_running = False
    
    async def _execute_phase(self, phase: TestPhase, targets: List[Target]) -> TestResult:
        """执行测试阶段"""
        phase_result = TestResult(
            test_id=f"{self.current_test_id}_{phase.value}",
            name=f"{phase.value}阶段",
            phase=phase,
            start_time=datetime.now(),
            end_time=None,
            status="running"
        )
        
        if phase == TestPhase.RECONNAISSANCE:
            await self._run_reconnaissance(targets, phase_result)
        elif phase == TestPhase.SCANNING:
            await self._run_scanning(targets, phase_result)
        elif phase == TestPhase.EXPLOITATION:
            await self._run_exploitation(targets, phase_result)
        elif phase == TestPhase.POST_EXPLOITATION:
            await self._run_post_exploitation(targets, phase_result)
        elif phase == TestPhase.REPORTING:
            await self._generate_report(phase_result)
        
        phase_result.end_time = datetime.now()
        phase_result.status = "completed"
        phase_result.duration = (phase_result.end_time - phase_result.start_time).total_seconds()
        
        return phase_result
    
    async def _run_reconnaissance(self, targets: List[Target], result: TestResult):
        """信息收集阶段"""
        for target in targets:
            try:
                findings = {}
                
                # DNS信息收集
                dns_info = await self._collect_dns_info(target)
                if dns_info:
                    findings['dns'] = dns_info
                
                # 端口扫描（简化版）
                port_info = await self._quick_port_scan(target)
                if port_info:
                    findings['ports'] = port_info
                
                # HTTP指纹识别
                http_fingerprint = await self._identify_http_fingerprint(target)
                if http_fingerprint:
                    findings['http_fingerprint'] = http_fingerprint
                
                # 技术栈识别
                tech_stack = await self._identify_tech_stack(target)
                if tech_stack:
                    findings['tech_stack'] = tech_stack
                
                result.findings.append({
                    'target': target.url,
                    'type': 'reconnaissance',
                    'data': findings
                })
                
            except Exception as e:
                result.errors.append(f"信息收集失败 [{target.url}]: {str(e)}")
    
    async def _run_scanning(self, targets: List[Target], result: TestResult):
        """扫描探测阶段"""
        for target in targets:
            try:
                vulnerabilities = []
                
                # SQL注入检测
                sqli_vulns = await self._detect_sql_injection(target)
                vulnerabilities.extend(sqli_vulns)
                
                # XSS检测
                xss_vulns = await self._detect_xss(target)
                vulnerabilities.extend(xss_vulns)
                
                # 目录遍历检测
                traversal_vulns = await self._detect_path_traversal(target)
                vulnerabilities.extend(traversal_vulns)
                
                # 敏感信息泄露检测
                info_leak_vulns = await self._detect_information_leakage(target)
                vulnerabilities.extend(info_leak_vulns)
                
                # 安全头缺失检测
                header_vulns = await self._check_security_headers(target)
                vulnerabilities.extend(header_vulns)
                
                for vuln in vulnerabilities:
                    result.vulnerabilities.append(vuln)
                    if self.on_vulnerability_found:
                        self.on_vulnerability_found(vuln)
                        
            except Exception as e:
                result.errors.append(f"扫描失败 [{target.url}]: {str(e)}")
    
    async def _run_exploitation(self, targets: List[Target], result: TestResult):
        """漏洞利用阶段"""
        # 基于已发现的漏洞进行利用尝试
        known_vulns = [v for v in self.vulnerabilities if v.severity in [VulnerabilitySeverity.CRITICAL, VulnerabilitySeverity.HIGH]]
        
        for vuln in known_vulns[:3]:  # 只尝试前3个高危漏洞
            try:
                exploit_result = await self._attempt_exploit(vuln)
                if exploit_result:
                    result.findings.append({
                        'type': 'exploitation',
                        'vulnerability_id': vuln.id,
                        'result': exploit_result
                    })
            except Exception as e:
                result.errors.append(f"漏洞利用失败 [{vuln.name}]: {str(e)}")
    
    async def _run_post_exploitation(self, targets: List[Target], result: TestResult):
        """后渗透阶段（模拟）"""
        for target in targets:
            post_exploit_findings = []
            
            # 权限提升检查（模拟）
            post_exploit_findings.append({
                'check': 'privilege_escalation',
                'status': 'simulated',
                'message': '后渗透测试需要实际环境'
            })
            
            # 横向移动检查（模拟）
            post_exploit_findings.append({
                'check': 'lateral_movement',
                'status': 'simulated',
                'message': '横向移动评估需要授权环境'
            })
            
            result.findings.append({
                'target': target.url,
                'type': 'post_exploitation',
                'data': post_exploit_findings
            })
    
    async def _generate_report(self, result: TestResult):
        """报告生成阶段"""
        report_data = {
            'summary': {
                'total_targets': len(self.targets),
                'total_vulnerabilities': len(self.vulnerabilities),
                'by_severity': {
                    'critical': len([v for v in self.vulnerabilities if v.severity == VulnerabilitySeverity.CRITICAL]),
                    'high': len([v for v in self.vulnerabilities if v.severity == VulnerabilitySeverity.HIGH]),
                    'medium': len([v for v in self.vulnerabilities if v.severity == VulnerabilitySeverity.MEDIUM]),
                    'low': len([v for v in self.vulnerabilities if v.severity == VulnerabilitySeverity.LOW])
                }
            },
            'vulnerabilities': [v.to_dict() for v in self.vulnerabilities],
            'findings': result.findings,
            'generated_at': datetime.now().isoformat()
        }
        
        result.findings.append({
            'type': 'report',
            'data': report_data
        })
    
    # ========== 具体检测方法 ==========
    
    async def _collect_dns_info(self, target: Target) -> Dict:
        """收集DNS信息"""
        import socket
        dns_info = {}
        
        try:
            ip = socket.gethostbyname(target.host)
            dns_info['ip_address'] = ip
            
            # 获取IP地理位置（简化）
            dns_info['geo_location'] = "未知"
            
        except Exception as e:
            dns_info['error'] = str(e)
        
        return dns_info
    
    async def _quick_port_scan(self, target: Target) -> Dict:
        """快速端口扫描"""
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3306, 3389, 5432, 6379, 8080, 8443]
        open_ports = []
        
        import socket
        for port in common_ports[:10]:  # 只扫描前10个端口以节省时间
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((target.host, port))
                if result == 0:
                    open_ports.append(port)
                sock.close()
            except:
                pass
        
        return {'open_ports': open_ports}
    
    async def _identify_http_fingerprint(self, target: Target) -> Dict:
        """识别HTTP指纹"""
        fingerprint = {}
        
        try:
            async with aiohttp.ClientSession() as session:
                url = f"{target.protocol}://{target.host}:{target.port}/"
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as response:
                    # Server头
                    server_header = response.headers.get('Server', '')
                    fingerprint['server'] = server_header
                    
                    # X-Powered-By头
                    powered_by = response.headers.get('X-Powered-By', '')
                    if powered_by:
                        fingerprint['powered_by'] = powered_by
                    
                    # 状态码
                    fingerprint['status_code'] = response.status
                    
        except Exception as e:
            fingerprint['error'] = str(e)
        
        return fingerprint
    
    async def _identify_tech_stack(self, target: Target) -> Dict:
        """识别技术栈"""
        tech_stack = {}
        
        try:
            async with aiohttp.ClientSession() as session:
                url = f"{target.protocol}://{target.host}:{target.port}/"
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as response:
                    html = await response.text()
                    
                    # 检测常见框架
                    frameworks = {
                        'WordPress': ['wp-content', 'wp-includes', 'wordpress'],
                        'Drupal': ['drupal', '/sites/default/'],
                        'Joomla': ['joomla', '/media/jui/'],
                        'Django': ['csrfmiddlewaretoken', 'django'],
                        'Flask': ['flask', '_ga'],
                        'Spring': ['spring', 'X-Application-Context'],
                        'ASP.NET': ['__VIEWSTATE', '__EVENTVALIDATION'],
                        'PHP': ['.php', 'PHPSESSID'],
                        'Java': ['.jsp', '.do', 'JSESSIONID']
                    }
                    
                    detected_frameworks = []
                    for framework, indicators in frameworks.items():
                        for indicator in indicators:
                            if indicator.lower() in html.lower():
                                detected_frameworks.append(framework)
                                break
                    
                    if detected_frameworks:
                        tech_stack['frameworks'] = detected_frameworks
                    
        except Exception as e:
            tech_stack['error'] = str(e)
        
        return tech_stack
    
    async def _detect_sql_injection(self, target: Target) -> List[Vulnerability]:
        """检测SQL注入"""
        vulnerabilities = []
        payloads = [
            "' OR '1'='1",
            "' UNION SELECT NULL--",
            "'; DROP TABLE users--",
            "' AND SLEEP(5)--",
            "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--"
        ]
        
        try:
            async with aiohttp.ClientSession() as session:
                base_url = f"{target.protocol}://{target.host}:{target.port}{target.path or '/'}"
                
                for payload in payloads:
                    params = target.parameters.copy() if target.parameters else {'id': '1'}
                    if params:
                        param_name = list(params.keys())[0]
                        params[param_name] = payload
                    
                    start_time = time.time()
                    async with session.get(
                        base_url, 
                        params=params,
                        headers=target.headers,
                        timeout=aiohttp.ClientTimeout(total=self.config['timeout'])
                    ) as response:
                        elapsed = time.time() - start_time
                        response_text = await response.text()
                        
                        # 检测SQL错误
                        sql_errors = [
                            'sql syntax', 'mysql', 'oracle', 'postgresql',
                            'microsoft', 'odbc', 'unclosed quotation mark'
                        ]
                        
                        is_vulnerable = any(
                            error.lower() in response_text.lower() 
                            for error in sql_errors
                        ) or (elapsed > 4 and 'SLEEP' in payload)
                        
                        if is_vulnerable:
                            vuln = Vulnerability(
                                id=f"SQLI_{int(time.time())}",
                                name="SQL注入漏洞",
                                severity=VulnerabilitySeverity.CRITICAL,
                                description=f"在参数中发现SQL注入漏洞，Payload: {payload}",
                                target=target,
                                evidence=response_text[:500],
                                cvss_score=9.8
                            )
                            vulnerabilities.append(vuln)
                            
        except Exception as e:
            logger.warning(f"SQL注入检测异常: {e}")
        
        return vulnerabilities
    
    async def _detect_xss(self, target: Target) -> List[Vulnerability]:
        """检测XSS漏洞"""
        vulnerabilities = []
        payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')"
        ]
        
        try:
            async with aiohttp.ClientSession() as session:
                base_url = f"{target.protocol}://{target.host}:{target.port}{target.path or '/'}"
                
                for payload in payloads:
                    params = target.parameters.copy() if target.parameters else {'q': 'test'}
                    if params:
                        param_name = list(params.keys())[0]
                        params[param_name] = payload
                    
                    async with session.get(
                        base_url,
                        params=params,
                        headers=target.headers,
                        timeout=aiohttp.ClientTimeout(total=self.config['timeout'])
                    ) as response:
                        response_text = await response.text()
                        
                        # 检查Payload是否在响应中反射
                        if payload.lower() in response_text.lower():
                            vuln = Vulnerability(
                                id=f"XSS_{int(time.time())}",
                                name="跨站脚本攻击(XSS)",
                                severity=VulnerabilitySeverity.HIGH,
                                description=f"在参数中发现XSS漏洞，Payload被反射到页面",
                                target=target,
                                evidence=f"Payload: {payload}",
                                cvss_score=7.5
                            )
                            vulnerabilities.append(vuln)
                            
        except Exception as e:
            logger.warning(f"XSS检测异常: {e}")
        
        return vulnerabilities
    
    async def _detect_path_traversal(self, target: Target) -> List[Vulnerability]:
        """检测路径遍历"""
        vulnerabilities = []
        payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\win.ini",
            "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..%2f..%2f..%2f..%2fetc%2fpasswd"
        ]
        
        try:
            async with aiohttp.ClientSession() as session:
                base_url = f"{target.protocol}://{target.host}:{target.port}{target.path or '/'}"
                
                for payload in payloads:
                    test_url = f"{base_url}?file={payload}"
                    
                    async with session.get(
                        test_url,
                        headers=target.headers,
                        timeout=aiohttp.ClientTimeout(total=self.config['timeout'])
                    ) as response:
                        response_text = await response.text()
                        
                        # 检测敏感文件内容
                        sensitive_patterns = [
                            'root:', 'bin/bash', '[boot]',
                            '[fonts]', 'extension=php'
                        ]
                        
                        is_vulnerable = any(
                            pattern in response_text 
                            for pattern in sensitive_patterns
                        )
                        
                        if is_vulnerable:
                            vuln = Vulnerability(
                                id=f"LFI_{int(time.time())}",
                                name="路径遍历/本地文件包含",
                                severity=VulnerabilitySeverity.HIGH,
                                description="发现路径遍历漏洞，可读取服务器本地文件",
                                target=target,
                                evidence=response_text[:300],
                                cvss_score=7.5
                            )
                            vulnerabilities.append(vuln)
                            
        except Exception as e:
            logger.warning(f"路径遍历检测异常: {e}")
        
        return vulnerabilities
    
    async def _detect_information_leakage(self, target: Target) -> List[Vulnerability]:
        """检测敏感信息泄露"""
        vulnerabilities = []
        sensitive_paths = [
            '/.git/config',
            '/.env',
            '/.svn/entries',
            '/WEB-INF/web.xml',
            '/server-status',
            '/phpinfo.php',
            '/robots.txt',
            '/sitemap.xml'
        ]
        
        try:
            async with aiohttp.ClientSession() as session:
                for path in sensitive_paths:
                    url = f"{target.protocol}://{target.host}:{target.port}{path}"
                    
                    async with session.get(
                        url,
                        headers=target.headers,
                        timeout=aiohttp.ClientTimeout(total=10)
                    ) as response:
                        if response.status == 200:
                            content = await response.text()
                            
                            # 排除正常页面
                            if len(content) > 50 and '<html' not in content.lower()[:100]:
                                vuln = Vulnerability(
                                    id=f"INFO_{int(time.time())}",
                                    name="敏感信息泄露",
                                    severity=VulnerabilitySeverity.MEDIUM,
                                    description=f"发现敏感文件泄露: {path}",
                                    target=target,
                                    evidence=f"URL: {url}, 内容长度: {len(content)}",
                                    cvss_score=5.3
                                )
                                vulnerabilities.append(vuln)
                                
        except Exception as e:
            logger.warning(f"信息泄露检测异常: {e}")
        
        return vulnerabilities
    
    async def _check_security_headers(self, target: Target) -> List[Vulnerability]:
        """检查安全头配置"""
        vulnerabilities = []
        
        required_headers = {
            'Strict-Transport-Security': ('HSTS未配置', VulnerabilitySeverity.MEDIUM, 5.0),
            'Content-Security-Policy': ('CSP未配置', VulnerabilitySeverity.MEDIUM, 4.3),
            'X-Frame-Options': ('点击劫持防护缺失', VulnerabilitySeverity.LOW, 4.3),
            'X-Content-Type-Options': ('MIME类型嗅探未禁用', VulnerabilitySeverity.LOW, 3.7),
            'X-XSS-Protection': ('XSS过滤器未启用', VulnerabilitySeverity.LOW, 3.5),
            'Referrer-Policy': ('Referer策略未配置', VulnerabilitySeverity.INFO, 2.0)
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                url = f"{target.protocol}://{target.host}:{target.port}/"
                
                async with session.get(
                    url,
                    headers=target.headers,
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as response:
                    for header, (desc, severity, score) in required_headers.items():
                        if header not in response.headers:
                            vuln = Vulnerability(
                                id=f"HEADER_{header.replace('-', '_')}_{int(time.time())}",
                                name=desc,
                                severity=severity,
                                description=f"缺少安全响应头: {header}",
                                target=target,
                                cvss_score=score
                            )
                            vulnerabilities.append(vuln)
                            
        except Exception as e:
            logger.warning(f"安全头检查异常: {e}")
        
        return vulnerabilities
    
    async def _attempt_exploit(self, vulnerability: Vulnerability) -> Dict:
        """尝试漏洞利用（仅记录，不实际执行）"""
        return {
            'status': 'logged_only',
            'message': '漏洞利用需要授权环境，已记录漏洞详情供后续处理',
            'vulnerability_id': vulnerability.id,
            'recommendation': '建议使用专业的POC管理工具进行验证性测试'
        }
    
    # ========== 报告和导出方法 ==========
    
    def generate_report_json(self, test_id: str) -> str:
        """生成JSON格式报告"""
        if test_id not in self.results:
            return "{}"
        
        result = self.results[test_id]
        report = {
            'test_info': {
                'test_id': test_id,
                'name': result.name,
                'start_time': result.start_time.isoformat(),
                'end_time': result.end_time.isoformat() if result.end_time else "",
                'duration': result.duration,
                'status': result.status
            },
            'targets': [{'url': t.url, 'host': t.host} for t in self.targets],
            'vulnerabilities_summary': {
                'total': len(result.vulnerabilities),
                'by_severity': {
                    'critical': len([v for v in result.vulnerabilities if v.severity == VulnerabilitySeverity.CRITICAL]),
                    'high': len([v for v in result.vulnerabilities if v.severity == VulnerabilitySeverity.HIGH]),
                    'medium': len([v for v in result.vulnerabilities if v.severity == VulnerabilitySeverity.MEDIUM]),
                    'low': len([v for v in result.vulnerabilities if v.severity == VulnerabilitySeverity.LOW])
                }
            },
            'vulnerabilities': [v.to_dict() for v in result.vulnerabilities],
            'findings': result.findings,
            'errors': result.errors
        }
        
        return json.dumps(report, indent=2, ensure_ascii=False)
    
    def generate_report_markdown(self, test_id: str) -> str:
        """生成Markdown格式报告"""
        if test_id not in self.results:
            return "# 报告不存在\n"
        
        result = self.results[test_id]
        
        md = f"""# 综合安全测试报告

## 测试概要
- **测试ID**: {test_id}
- **测试名称**: {result.name}
- **开始时间**: {result.start_time.strftime('%Y-%m-%d %H:%M:%S')}
- **结束时间**: {result.end_time.strftime('%Y-%m-%d %H:%M:%S') if result.end_time else '进行中'}
- **总耗时**: {result.duration:.2f} 秒
- **状态**: {result.status}

## 目标列表
"""
        
        for t in self.targets:
            md += f"- {t.url} ({t.host}:{t.port})\n"
        
        md += f"""
## 漏洞统计
- **总计**: {len(result.vulnerabilities)}
- **严重**: {len([v for v in result.vulnerabilities if v.severity == VulnerabilitySeverity.CRITICAL])}
- **高危**: {len([v for v in result.vulnerabilities if v.severity == VulnerabilitySeverity.HIGH])}
- **中危**: {len([v for v in result.vulnerabilities if v.severity == VulnerabilitySeverity.MEDIUM])}
- **低危**: {len([v for v in result.vulnerabilities if v.severity == VulnerabilitySeverity.LOW])}

## 详细漏洞列表

"""
        
        for vuln in result.vulnerabilities:
            md += f"""### {vuln.name}
- **ID**: {vuln.id}
- **严重程度**: {vuln.severity.value.upper()}
- **CVSS评分**: {vuln.cvss_score}
- **目标**: {vuln.target.url}
- **描述**: {vuln.description}

"""
            if vuln.evidence:
                md += f"- **证据**: `{vuln.evidence[:200]}...`\n\n"
        
        return md
    
    # ========== 公共方法 ==========
    
    def stop_test(self):
        """停止当前测试"""
        self.is_running = False
        logger.info("测试已停止")
    
    def get_test_result(self, test_id: str) -> Optional[TestResult]:
        """获取测试结果"""
        return self.results.get(test_id)
    
    def get_all_results(self) -> Dict[str, TestResult]:
        """获取所有测试结果"""
        return self.results.copy()
    
    def get_vulnerabilities_by_severity(self, severity: VulnerabilitySeverity) -> List[Vulnerability]:
        """按严重程度获取漏洞"""
        return [v for v in self.vulnerabilities if v.severity == severity]
    
    def set_config(self, config: Dict[str, Any]):
        """设置配置"""
        self.config.update(config)
        logger.info("配置已更新")
    
    def add_target(self, target: Target):
        """添加测试目标"""
        self.targets.append(target)
    
    def clear_targets(self):
        """清空测试目标"""
        self.targets.clear()
    
    def clear_results(self):
        """清空测试结果"""
        self.results.clear()
        self.vulnerabilities.clear()

# 测试管理器
class TestManager:
    """测试管理器"""
    
    def __init__(self):
        self.tests: Dict[str, ComprehensiveTestScript] = {}
        self.active_tests: Dict[str, asyncio.Task] = {}
    
    def create_test(self, test_id: str) -> ComprehensiveTestScript:
        """创建测试实例"""
        test = ComprehensiveTestScript()
        self.tests[test_id] = test
        return test
    
    async def run_test(self, test_id: str, targets: List[Target], 
                      phases: List[TestPhase] = None) -> str:
        """运行测试"""
        if test_id not in self.tests:
            raise ValueError(f"测试不存在: {test_id}")
        
        test = self.tests[test_id]
        result_id = await test.run_comprehensive_test(targets, phases)
        
        return result_id
    
    def get_test(self, test_id: str) -> Optional[ComprehensiveTestScript]:
        """获取测试"""
        return self.tests.get(test_id)
    
    def get_all_tests(self) -> Dict[str, ComprehensiveTestScript]:
        """获取所有测试"""
        return self.tests.copy()
