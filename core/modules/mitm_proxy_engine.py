"""
企业级MITM代理核心引擎
支持HTTP/HTTPS/HTTP2/HTTP3代理、证书管理、请求拦截、规则引擎等功能
"""

import asyncio
import ssl
import logging
import os
import json
import re
import hashlib
import tempfile
import threading
from typing import Dict, Any, Optional, List, Callable, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from enum import Enum
from urllib.parse import urlparse

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

from .mitm_h2_engine import H2ProxyEngine
from .mitm_h3_engine import H3ProxyEngine
from .mitm_protocol_negotiator import ProtocolNegotiator, ProtocolConverter, ProtocolVersion

logger = logging.getLogger(__name__)


class InterceptAction(Enum):
    """拦截动作"""
    FORWARD = "forward"
    BREAK = "break"
    DROP = "drop"
    MODIFY = "modify"
    LOG = "log"


class RuleMatchType(Enum):
    """规则匹配类型"""
    DOMAIN = "domain"
    URL_PATH = "url_path"
    METHOD = "method"
    STATUS_CODE = "status_code"
    HEADER = "header"
    BODY = "body"
    REGEX = "regex"


@dataclass
class MITMRequest:
    """MITM请求数据"""
    id: str
    timestamp: datetime
    method: str
    url: str
    host: str
    path: str
    headers: Dict[str, str]
    body: bytes
    protocol: str = "HTTP/1.1"
    query_params: Dict[str, List[str]] = field(default_factory=dict)
    content_type: str = ""
    content_length: int = 0
    is_https: bool = False
    tls_version: str = ""
    client_ip: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat(),
            'method': self.method,
            'url': self.url,
            'host': self.host,
            'path': self.path,
            'headers': self.headers,
            'body': self.body.decode('utf-8', errors='replace') if self.body else '',
            'protocol': self.protocol,
            'query_params': self.query_params,
            'content_type': self.content_type,
            'content_length': self.content_length,
            'is_https': self.is_https,
            'tls_version': self.tls_version,
            'client_ip': self.client_ip
        }


@dataclass
class MITMResponse:
    """MITM响应数据"""
    id: str
    request_id: str
    timestamp: datetime
    status_code: int
    reason: str
    headers: Dict[str, str]
    body: bytes
    protocol: str = "HTTP/1.1"
    content_type: str = ""
    content_length: int = 0
    response_time: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'request_id': self.request_id,
            'timestamp': self.timestamp.isoformat(),
            'status_code': self.status_code,
            'reason': self.reason,
            'headers': self.headers,
            'body': self.body.decode('utf-8', errors='replace') if self.body else '',
            'protocol': self.protocol,
            'content_type': self.content_type,
            'content_length': self.content_length,
            'response_time': self.response_time
        }


@dataclass
class InterceptRule:
    """拦截规则"""
    id: str
    name: str
    enabled: bool = True
    match_type: RuleMatchType = RuleMatchType.DOMAIN
    match_value: str = ""
    action: InterceptAction = InterceptAction.FORWARD
    replace_pattern: str = ""
    replace_with: str = ""
    description: str = ""
    
    def matches(self, request: MITMRequest, response: Optional[MITMResponse] = None) -> bool:
        """检查请求/响应是否匹配规则"""
        if not self.enabled:
            return False
        
        if self.match_type == RuleMatchType.DOMAIN:
            return self.match_value.lower() in request.host.lower()
        elif self.match_type == RuleMatchType.URL_PATH:
            return self.match_value.lower() in request.path.lower()
        elif self.match_type == RuleMatchType.METHOD:
            return self.match_value.upper() == request.method.upper()
        elif self.match_type == RuleMatchType.STATUS_CODE and response:
            return str(self.match_value) == str(response.status_code)
        elif self.match_type == RuleMatchType.HEADER:
            for key, value in request.headers.items():
                if self.match_value.lower() in f"{key}: {value}".lower():
                    return True
        elif self.match_type == RuleMatchType.BODY and request.body:
            return self.match_value.lower() in request.body.decode('utf-8', errors='replace').lower()
        elif self.match_type == RuleMatchType.REGEX:
            try:
                return bool(re.search(self.match_value, request.url))
            except re.error:
                return False
        return False


class CertificateManager:
    """证书管理器 - 动态生成和管理MITM证书"""
    
    def __init__(self, cert_dir: str = "data/mitm_certs"):
        self.cert_dir = Path(cert_dir)
        self.cert_dir.mkdir(parents=True, exist_ok=True)
        
        self.ca_cert_path = self.cert_dir / "ca.crt"
        self.ca_key_path = self.cert_dir / "ca.key"
        self.cert_cache: Dict[str, Tuple[ssl.SSLContext, datetime]] = {}
        
        self._ca_cert = None
        self._ca_key = None
        self._ensure_ca_cert()
    
    def _ensure_ca_cert(self):
        """确保CA证书存在"""
        if not self.ca_cert_path.exists() or not self.ca_key_path.exists():
            self._generate_ca_cert()
        else:
            self._load_ca_cert()
    
    def _generate_ca_cert(self):
        """生成CA根证书"""
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "CN"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Beijing"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Beijing"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "AutoPenTest MITM CA"),
            x509.NameAttribute(NameOID.COMMON_NAME, "AutoPenTest MITM CA"),
        ])
        
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.utcnow())
            .not_valid_after(datetime.utcnow() + timedelta(days=3650))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=None),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=True,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .sign(key, hashes.SHA256(), default_backend())
        )
        
        with open(self.ca_cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        
        with open(self.ca_key_path, "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
        
        self._ca_cert = cert
        self._ca_key = key
        logger.info(f"CA证书已生成: {self.ca_cert_path}")
    
    def _load_ca_cert(self):
        """加载CA证书"""
        with open(self.ca_cert_path, "rb") as f:
            self._ca_cert = x509.load_pem_x509_certificate(f.read())
        
        with open(self.ca_key_path, "rb") as f:
            self._ca_key = serialization.load_pem_private_key(
                f.read(),
                password=None,
                backend=default_backend()
            )
        logger.info("CA证书已加载")
    
    def get_domain_ssl_context(self, domain: str) -> ssl.SSLContext:
        """为指定域名生成SSL上下文"""
        cache_key = domain
        if cache_key in self.cert_cache:
            ctx, created = self.cert_cache[cache_key]
            if (datetime.utcnow() - created).total_seconds() < 3600:
                return ctx
        
        ctx = self._create_domain_ssl_context(domain)
        self.cert_cache[cache_key] = (ctx, datetime.utcnow())
        return ctx
    
    def _create_domain_ssl_context(self, domain: str) -> ssl.SSLContext:
        """为域名创建SSL上下文"""
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "CN"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "AutoPenTest MITM"),
            x509.NameAttribute(NameOID.COMMON_NAME, domain),
        ])
        
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self._ca_cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.utcnow())
            .not_valid_after(datetime.utcnow() + timedelta(days=365))
            .add_extension(
                x509.SubjectAlternativeName([
                    x509.DNSName(domain),
                    x509.DNSName(f"*.{domain}"),
                ]),
                critical=False,
            )
            .sign(self._ca_key, hashes.SHA256(), default_backend())
        )
        
        ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        key_pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        cert_file = tempfile.NamedTemporaryFile(mode='wb', suffix='.pem', delete=False)
        cert_file.write(cert_pem)
        cert_file.close()
        
        key_file = tempfile.NamedTemporaryFile(mode='wb', suffix='.pem', delete=False)
        key_file.write(key_pem)
        key_file.close()
        
        ctx.load_cert_chain(certfile=cert_file.name, keyfile=key_file.name)
        
        return ctx
    
    def export_ca_cert(self, output_path: str) -> bool:
        """导出CA证书"""
        try:
            import shutil
            shutil.copy2(self.ca_cert_path, output_path)
            return True
        except Exception as e:
            logger.error(f"导出CA证书失败: {e}")
            return False


class MITMProxyEngine:
    """MITM代理引擎核心"""
    
    def __init__(self, host: str = "127.0.0.1", port: int = 8080,
                 enable_h2: bool = True, enable_h3: bool = False,
                 h3_port: int = 443):
        self.host = host
        self.port = port
        self._running = False
        self._server = None
        self._loop = None
        self._thread = None
        
        # 协议支持配置
        self.enable_h2 = enable_h2
        self.enable_h3 = enable_h3
        self.h3_port = h3_port
        
        # 协议引擎
        self.cert_manager = CertificateManager()
        self.protocol_negotiator = ProtocolNegotiator()
        self.h2_engine = H2ProxyEngine(self.cert_manager) if enable_h2 else None
        self.h3_engine = H3ProxyEngine(self.cert_manager) if enable_h3 else None
        
        self.rules: List[InterceptRule] = []
        self.bypass_domains: Set[str] = set()
        
        self.request_history: List[MITMRequest] = []
        self.response_history: List[MITMResponse] = []
        
        self._breakpoints: Dict[str, asyncio.Event] = {}
        self._pending_requests: Dict[str, MITMRequest] = {}
        self._pending_responses: Dict[str, MITMResponse] = {}
        
        self._callbacks: Dict[str, List[Callable]] = {
            'on_request': [],
            'on_response': [],
            'on_websocket': [],
            'on_error': [],
        }
        
        self._max_connections = 100
        self._active_connections = 0
        self._connection_lock = threading.Lock()
        
        self._desensitize_headers = {'authorization', 'cookie', 'set-cookie'}
        self._ip_whitelist: Set[str] = set()
    
    def add_callback(self, event: str, callback: Callable):
        """添加回调函数"""
        if event in self._callbacks:
            self._callbacks[event].append(callback)
    
    def remove_callback(self, event: str, callback: Callable):
        """移除回调函数"""
        if event in self._callbacks and callback in self._callbacks[event]:
            self._callbacks[event].remove(callback)
    
    def _notify_callbacks(self, event: str, *args, **kwargs):
        """通知回调"""
        for callback in self._callbacks.get(event, []):
            try:
                callback(*args, **kwargs)
            except Exception as e:
                logger.error(f"回调执行失败 [{event}]: {e}")
    
    def add_rule(self, rule: InterceptRule):
        """添加规则"""
        self.rules.append(rule)
        logger.info(f"添加规则: {rule.name}")
    
    def remove_rule(self, rule_id: str):
        """移除规则"""
        self.rules = [r for r in self.rules if r.id != rule_id]
    
    def set_rules(self, rules: List[InterceptRule]):
        """设置规则列表"""
        self.rules = rules
    
    def export_rules(self, path: str) -> bool:
        """导出规则"""
        try:
            rules_data = []
            for rule in self.rules:
                rules_data.append({
                    'id': rule.id,
                    'name': rule.name,
                    'enabled': rule.enabled,
                    'match_type': rule.match_type.value,
                    'match_value': rule.match_value,
                    'action': rule.action.value,
                    'replace_pattern': rule.replace_pattern,
                    'replace_with': rule.replace_with,
                    'description': rule.description,
                })
            
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(rules_data, f, ensure_ascii=False, indent=2)
            return True
        except Exception as e:
            logger.error(f"导出规则失败: {e}")
            return False
    
    def import_rules(self, path: str) -> bool:
        """导入规则"""
        try:
            with open(path, 'r', encoding='utf-8') as f:
                rules_data = json.load(f)
            
            self.rules = []
            for data in rules_data:
                rule = InterceptRule(
                    id=data['id'],
                    name=data['name'],
                    enabled=data['enabled'],
                    match_type=RuleMatchType(data['match_type']),
                    match_value=data['match_value'],
                    action=InterceptAction(data['action']),
                    replace_pattern=data.get('replace_pattern', ''),
                    replace_with=data.get('replace_with', ''),
                    description=data.get('description', ''),
                )
                self.rules.append(rule)
            return True
        except Exception as e:
            logger.error(f"导入规则失败: {e}")
            return False
    
    def add_bypass_domain(self, domain: str):
        """添加 bypass 域名"""
        self.bypass_domains.add(domain.lower())
    
    def remove_bypass_domain(self, domain: str):
        """移除 bypass 域名"""
        self.bypass_domains.discard(domain.lower())
    
    def is_bypass_domain(self, domain: str) -> bool:
        """检查是否为 bypass 域名"""
        domain = domain.lower()
        for bypass in self.bypass_domains:
            if domain == bypass or domain.endswith(f".{bypass}"):
                return True
        return False
    
    def start(self):
        """启动代理"""
        if self._running:
            return
        
        self._running = True
        self._thread = threading.Thread(target=self._run_async_loop, daemon=True)
        self._thread.start()
        
        # 启动HTTP/3服务器（如果启用）
        if self.enable_h3 and self.h3_engine:
            try:
                asyncio.create_task(self.h3_engine.start_quic_server("0.0.0.0", self.h3_port))
                logger.info(f"HTTP/3(QUIC)服务器启动: 0.0.0.0:{self.h3_port}")
            except Exception as e:
                logger.error(f"启动HTTP/3服务器失败: {e}")
        
        logger.info(f"MITM代理启动: {self.host}:{self.port} (H2:{self.enable_h2}, H3:{self.enable_h3})")
    
    def stop(self):
        """停止代理"""
        self._running = False
        if self._server:
            self._server.close()
        if self._loop and self._loop.is_running():
            self._loop.call_soon_threadsafe(self._loop.stop)
        if self._thread:
            self._thread.join(timeout=5)
        logger.info("MITM代理已停止")
    
    def _run_async_loop(self):
        """运行异步循环"""
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        self._loop.run_until_complete(self._start_server())
    
    async def _start_server(self):
        """启动代理服务器"""
        try:
            self._server = await asyncio.start_server(
                self._handle_client,
                self.host,
                self.port
            )
            logger.info(f"代理服务器监听 {self.host}:{self.port}")
            
            async with self._server:
                await self._server.serve_forever()
        except Exception as e:
            logger.error(f"代理服务器启动失败: {e}")
            self._notify_callbacks('on_error', str(e))
    
    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """处理客户端连接"""
        with self._connection_lock:
            if self._active_connections >= self._max_connections:
                writer.close()
                return
            self._active_connections += 1
        
        try:
            peername = writer.get_extra_info('peername')
            client_ip = peername[0] if peername else "unknown"
            
            if self._ip_whitelist and client_ip not in self._ip_whitelist:
                writer.close()
                return
            
            # 检测HTTP/2连接升级（h2c）
            first_line = await asyncio.wait_for(reader.readline(), timeout=30)
            if not first_line:
                return
            
            first_line_str = first_line.decode('utf-8', errors='replace').strip()
            
            # 检查HTTP/2连接升级头部
            if self.enable_h2 and 'Upgrade: h2c' in first_line_str:
                await self._handle_h2c_upgrade(reader, writer, first_line_str, client_ip)
                return
            
            if first_line_str.startswith('CONNECT'):
                await self._handle_https(reader, writer, first_line_str, client_ip)
            else:
                await self._handle_http(reader, writer, first_line_str, client_ip)
        except asyncio.TimeoutError:
            pass
        except Exception as e:
            logger.error(f"处理客户端连接失败: {e}")
        finally:
            with self._connection_lock:
                self._active_connections -= 1
            try:
                writer.close()
                await writer.wait_closed()
            except:
                pass
    
    async def _handle_http(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, 
                          first_line: str, client_ip: str):
        """处理HTTP请求"""
        parts = first_line.split(' ')
        if len(parts) < 3:
            return
        
        method = parts[0]
        url = parts[1]
        protocol = parts[2]
        
        headers = {}
        while True:
            line = await asyncio.wait_for(reader.readline(), timeout=30)
            line_str = line.decode('utf-8', errors='replace').strip()
            if not line_str:
                break
            if ':' in line_str:
                key, value = line_str.split(':', 1)
                headers[key.strip()] = value.strip()
        
        host = headers.get('Host', urlparse(url).hostname or 'unknown')
        path = urlparse(url).path
        query = urlparse(url).query
        
        body = b''
        content_length = int(headers.get('Content-Length', 0))
        if content_length > 0:
            body = await asyncio.wait_for(reader.readexactly(content_length), timeout=30)
        
        request_id = hashlib.md5(f"{datetime.utcnow().isoformat()}{url}".encode()).hexdigest()[:12]
        
        request = MITMRequest(
            id=request_id,
            timestamp=datetime.utcnow(),
            method=method,
            url=url,
            host=host,
            path=path,
            headers=headers,
            body=body,
            protocol=protocol,
            query_params={},
            content_type=headers.get('Content-Type', ''),
            content_length=content_length,
            is_https=False,
            client_ip=client_ip
        )
        
        action = self._apply_rules(request)
        
        if action == InterceptAction.BREAK:
            self._pending_requests[request_id] = request
            event = asyncio.Event()
            self._breakpoints[request_id] = event
            await event.wait()
            request = self._pending_requests.get(request_id, request)
        
        self._notify_callbacks('on_request', request)
        self.request_history.append(request)
        
        if action == InterceptAction.DROP:
            return
        
        try:
            target_host = host.split(':')[0]
            target_port = int(host.split(':')[1]) if ':' in host else 80
            
            target_reader, target_writer = await asyncio.open_connection(target_host, target_port)
            
            request_line = f"{request.method} {request.path} {request.protocol}\r\n"
            target_writer.write(request_line.encode())
            
            for key, value in request.headers.items():
                target_writer.write(f"{key}: {value}\r\n".encode())
            target_writer.write(b"\r\n")
            
            if request.body:
                target_writer.write(request.body)
            
            await target_writer.drain()
            
            response_line = await asyncio.wait_for(target_reader.readline(), timeout=30)
            response_parts = response_line.decode('utf-8', errors='replace').strip().split(' ', 2)
            status_code = int(response_parts[1]) if len(response_parts) > 1 else 0
            reason = response_parts[2] if len(response_parts) > 2 else ''
            
            response_headers = {}
            while True:
                line = await asyncio.wait_for(target_reader.readline(), timeout=30)
                line_str = line.decode('utf-8', errors='replace').strip()
                if not line_str:
                    break
                if ':' in line_str:
                    key, value = line_str.split(':', 1)
                    response_headers[key.strip()] = value.strip()
            
            response_body = b''
            resp_content_length = int(response_headers.get('Content-Length', 0))
            if resp_content_length > 0:
                response_body = await asyncio.wait_for(target_reader.readexactly(resp_content_length), timeout=30)
            
            response_id = hashlib.md5(f"{request_id}_response".encode()).hexdigest()[:12]
            response = MITMResponse(
                id=response_id,
                request_id=request_id,
                timestamp=datetime.utcnow(),
                status_code=status_code,
                reason=reason,
                headers=response_headers,
                body=response_body,
                content_type=response_headers.get('Content-Type', ''),
                content_length=resp_content_length
            )
            
            resp_action = self._apply_response_rules(request, response)
            
            if resp_action == InterceptAction.BREAK:
                self._pending_responses[response_id] = response
                event = asyncio.Event()
                self._breakpoints[response_id] = event
                await event.wait()
                response = self._pending_responses.get(response_id, response)
            
            self._notify_callbacks('on_response', request, response)
            self.response_history.append(response)
            
            writer.write(response_line)
            for key, value in response.headers.items():
                writer.write(f"{key}: {value}\r\n".encode())
            writer.write(b"\r\n")
            
            if response.body:
                writer.write(response.body)
            
            await writer.drain()
            
            target_writer.close()
            
        except Exception as e:
            logger.error(f"转发HTTP请求失败: {e}")
            error_response = b"HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/html\r\n\r\n<html><body>Bad Gateway</body></html>"
            writer.write(error_response)
            await writer.drain()
    
    async def _handle_h2c_upgrade(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                                   first_line: str, client_ip: str):
        """处理HTTP/2明文连接升级"""
        if not self.enable_h2 or not self.h2_engine:
            logger.warning("HTTP/2未启用，降级到HTTP/1.1")
            await self._handle_http(reader, writer, first_line, client_ip)
            return
        
        logger.info(f"HTTP/2连接升级请求: {client_ip}")
        
        # 读取完整的HTTP/1.1升级请求
        headers = {}
        while True:
            line = await asyncio.wait_for(reader.readline(), timeout=30)
            line_str = line.decode('utf-8', errors='replace').strip()
            if not line_str:
                break
            if ':' in line_str:
                key, value = line_str.split(':', 1)
                headers[key.strip()] = value.strip()
        
        # 发送HTTP/1.1 101 Switching Protocols响应
        response = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: h2c\r\nConnection: Upgrade\r\n\r\n"
        writer.write(response)
        await writer.drain()
        
        # 切换到HTTP/2处理
        await self.h2_engine.handle_h2_connection(reader, writer, client_ip)
    
    async def _handle_https(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                           first_line: str, client_ip: str):
        """处理HTTPS CONNECT请求"""
        parts = first_line.split(' ')
        if len(parts) < 3:
            return
        
        target = parts[1]
        target_host = target.split(':')[0]
        target_port = int(target.split(':')[1]) if ':' in target else 443
        
        if self.is_bypass_domain(target_host):
            try:
                target_reader, target_writer = await asyncio.open_connection(target_host, target_port)
                writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                await writer.drain()
                
                async def forward(src, dst):
                    while True:
                        data = await src.read(4096)
                        if not data:
                            break
                        dst.write(data)
                        await dst.drain()
                
                await asyncio.gather(
                    forward(reader, target_writer),
                    forward(target_reader, writer)
                )
            except Exception as e:
                logger.error(f"HTTPS直通失败: {e}")
            return
        
        writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await writer.drain()
        
        ssl_context = self.cert_manager.get_domain_ssl_context(target_host)
        
        # 如果启用HTTP/2，设置ALPN协议
        if self.enable_h2:
            ssl_context.set_alpn_protocols(['h2', 'http/1.1'])
        
        ssl_socket = ssl_context.wrap_socket(
            writer.get_extra_info('socket'),
            server_side=True,
            do_handshake_on_connect=False
        )
        
        try:
            ssl_socket.settimeout(10)
            ssl_socket.do_handshake()
            
            # 检测协商的协议
            negotiated_protocol = ssl_socket.selected_alpn_protocol()
            logger.debug(f"TLS ALPN协商结果: {negotiated_protocol}")
            
            # 如果协商为HTTP/2，使用H2引擎处理
            if negotiated_protocol == 'h2' and self.enable_h2 and self.h2_engine:
                logger.info(f"HTTP/2 over TLS连接: {target}")
                # 这里需要将SSL socket转换为asyncio流
                # 由于asyncio对SSL socket支持有限，我们继续使用原始方式处理
                # 但标记协议为HTTP/2
                await self._handle_https_with_protocol(reader, writer, ssl_socket, target, target_host, target_port, client_ip, "HTTP/2")
            else:
                # 使用HTTP/1.1处理
                await self._handle_https_with_protocol(reader, writer, ssl_socket, target, target_host, target_port, client_ip, "HTTP/1.1")
                
        except Exception as e:
            logger.error(f"SSL握手失败: {e}")
            return
    
    async def _handle_https_with_protocol(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                                          ssl_socket, target: str, target_host: str, target_port: int,
                                          client_ip: str, protocol: str = "HTTP/1.1"):
        """处理HTTPS连接（支持协议参数）"""
        ssl_reader = asyncio.StreamReader()
        protocol_obj = asyncio.StreamReaderProtocol(ssl_reader)
        transport, _ = await asyncio.get_event_loop().create_connection(
            lambda: protocol_obj,
            sock=ssl_socket
        )
        
        try:
            first_line = await asyncio.wait_for(ssl_reader.readline(), timeout=30)
            if not first_line:
                return
            
            first_line_str = first_line.decode('utf-8', errors='replace').strip()
            parts = first_line_str.split(' ')
            
            if len(parts) >= 3:
                method = parts[0]
                path = parts[1]
                protocol = parts[2]
                
                headers = {}
                while True:
                    line = await asyncio.wait_for(ssl_reader.readline(), timeout=30)
                    line_str = line.decode('utf-8', errors='replace').strip()
                    if not line_str:
                        break
                    if ':' in line_str:
                        key, value = line_str.split(':', 1)
                        headers[key.strip()] = value.strip()
                
                body = b''
                content_length = int(headers.get('Content-Length', 0))
                if content_length > 0:
                    body = await asyncio.wait_for(ssl_reader.readexactly(content_length), timeout=30)
                
                request_id = hashlib.md5(f"{datetime.utcnow().isoformat()}{target}{path}".encode()).hexdigest()[:12]
                
                request = MITMRequest(
                    id=request_id,
                    timestamp=datetime.utcnow(),
                    method=method,
                    url=f"https://{target}{path}",
                    host=target,
                    path=path,
                    headers=headers,
                    body=body,
                    protocol=protocol,
                    content_type=headers.get('Content-Type', ''),
                    content_length=content_length,
                    is_https=True,
                    tls_version=ssl_socket.version() or 'TLS',
                    client_ip=client_ip
                )
                
                self._notify_callbacks('on_request', request)
                self.request_history.append(request)
                
                try:
                    target_reader, target_writer = await asyncio.open_connection(target_host, target_port)
                    
                    target_ssl_context = ssl.create_default_context()
                    target_ssl_context.check_hostname = False
                    target_ssl_context.verify_mode = ssl.CERT_NONE
                    
                    target_ssl_socket = target_ssl_context.wrap_socket(
                        target_writer.get_extra_info('socket'),
                        server_side=False,
                        do_handshake_on_connect=False
                    )
                    target_ssl_socket.settimeout(10)
                    target_ssl_socket.do_handshake()
                    
                    target_ssl_reader = asyncio.StreamReader()
                    target_protocol = asyncio.StreamReaderProtocol(target_ssl_reader)
                    target_transport, _ = await asyncio.get_event_loop().create_connection(
                        lambda: target_protocol,
                        sock=target_ssl_socket
                    )
                    
                    request_line = f"{method} {path} {protocol}\r\n"
                    target_writer.write(request_line.encode())
                    
                    for key, value in headers.items():
                        target_writer.write(f"{key}: {value}\r\n".encode())
                    target_writer.write(b"\r\n")
                    
                    if body:
                        target_writer.write(body)
                    
                    await target_writer.drain()
                    
                    response_line = await asyncio.wait_for(target_ssl_reader.readline(), timeout=30)
                    response_parts = response_line.decode('utf-8', errors='replace').strip().split(' ', 2)
                    status_code = int(response_parts[1]) if len(response_parts) > 1 else 0
                    reason = response_parts[2] if len(response_parts) > 2 else ''
                    
                    response_headers = {}
                    while True:
                        line = await asyncio.wait_for(target_ssl_reader.readline(), timeout=30)
                        line_str = line.decode('utf-8', errors='replace').strip()
                        if not line_str:
                            break
                        if ':' in line_str:
                            key, value = line_str.split(':', 1)
                            response_headers[key.strip()] = value.strip()
                    
                    response_body = b''
                    resp_content_length = int(response_headers.get('Content-Length', 0))
                    if resp_content_length > 0:
                        response_body = await asyncio.wait_for(target_ssl_reader.readexactly(resp_content_length), timeout=30)
                    
                    response_id = hashlib.md5(f"{request_id}_response".encode()).hexdigest()[:12]
                    response = MITMResponse(
                        id=response_id,
                        request_id=request_id,
                        timestamp=datetime.utcnow(),
                        status_code=status_code,
                        reason=reason,
                        headers=response_headers,
                        body=response_body,
                        content_type=response_headers.get('Content-Type', ''),
                        content_length=resp_content_length
                    )
                    
                    self._notify_callbacks('on_response', request, response)
                    self.response_history.append(response)
                    
                    ssl_writer = asyncio.StreamWriter(transport, protocol, ssl_reader, asyncio.get_event_loop())
                    ssl_writer.write(response_line)
                    for key, value in response.headers.items():
                        ssl_writer.write(f"{key}: {value}\r\n".encode())
                    ssl_writer.write(b"\r\n")
                    
                    if response.body:
                        ssl_writer.write(response.body)
                    
                    await ssl_writer.drain()
                    
                    target_writer.close()
                    
                except Exception as e:
                    logger.error(f"转发HTTPS请求失败: {e}")
                    error_response = b"HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/html\r\n\r\n<html><body>Bad Gateway</body></html>"
                    ssl_writer = asyncio.StreamWriter(transport, protocol, ssl_reader, asyncio.get_event_loop())
                    ssl_writer.write(error_response)
                    await ssl_writer.drain()
        except Exception as e:
            logger.error(f"处理HTTPS请求失败: {e}")
    
    def _apply_rules(self, request: MITMRequest) -> InterceptAction:
        """应用请求规则"""
        for rule in self.rules:
            if rule.matches(request):
                if rule.action == InterceptAction.MODIFY and rule.replace_pattern:
                    try:
                        request.url = re.sub(rule.replace_pattern, rule.replace_with, request.url)
                        request.path = re.sub(rule.replace_pattern, rule.replace_with, request.path)
                    except re.error:
                        pass
                return rule.action
        return InterceptAction.FORWARD
    
    def _apply_response_rules(self, request: MITMRequest, response: MITMResponse) -> InterceptAction:
        """应用响应规则"""
        for rule in self.rules:
            if rule.matches(request, response):
                if rule.action == InterceptAction.MODIFY and rule.replace_pattern:
                    try:
                        if response.body:
                            body_str = response.body.decode('utf-8', errors='replace')
                            new_body = re.sub(rule.replace_pattern, rule.replace_with, body_str)
                            response.body = new_body.encode('utf-8')
                            response.content_length = len(response.body)
                            response.headers['Content-Length'] = str(response.content_length)
                    except re.error:
                        pass
                return rule.action
        return InterceptAction.FORWARD
    
    def resume_request(self, request_id: str, modified_request: Optional[MITMRequest] = None):
        """放行请求"""
        if request_id in self._breakpoints:
            if modified_request:
                self._pending_requests[request_id] = modified_request
            self._breakpoints[request_id].set()
    
    def resume_response(self, response_id: str, modified_response: Optional[MITMResponse] = None):
        """放行响应"""
        if response_id in self._breakpoints:
            if modified_response:
                self._pending_responses[response_id] = modified_response
            self._breakpoints[response_id].set()
    
    def get_history(self, limit: int = 1000) -> List[Dict[str, Any]]:
        """获取历史记录"""
        result = []
        for request in self.request_history[-limit:]:
            response = next((r for r in self.response_history if r.request_id == request.id), None)
            entry = request.to_dict()
            if response:
                entry['response'] = response.to_dict()
            result.append(entry)
        return result
    
    def search_history(self, **kwargs) -> List[Dict[str, Any]]:
        """搜索历史记录"""
        results = []
        for request in self.request_history:
            match = True
            
            if 'domain' in kwargs and kwargs['domain']:
                if kwargs['domain'].lower() not in request.host.lower():
                    match = False
            
            if 'method' in kwargs and kwargs['method']:
                if kwargs['method'].upper() != request.method.upper():
                    match = False
            
            if 'status_code' in kwargs and kwargs['status_code']:
                response = next((r for r in self.response_history if r.request_id == request.id), None)
                if not response or response.status_code != kwargs['status_code']:
                    match = False
            
            if 'keyword' in kwargs and kwargs['keyword']:
                keyword = kwargs['keyword'].lower()
                if (keyword not in request.url.lower() and
                    keyword not in request.host.lower() and
                    keyword not in request.body.decode('utf-8', errors='replace').lower()):
                    match = False
            
            if match:
                response = next((r for r in self.response_history if r.request_id == request.id), None)
                entry = request.to_dict()
                if response:
                    entry['response'] = response.to_dict()
                results.append(entry)
        
        return results
    
    def clear_history(self):
        """清空历史记录"""
        self.request_history.clear()
        self.response_history.clear()
        self._breakpoints.clear()
        self._pending_requests.clear()
        self._pending_responses.clear()
    
    def set_desensitize_headers(self, headers: Set[str]):
        """设置脱敏头部"""
        self._desensitize_headers = {h.lower() for h in headers}
    
    def set_ip_whitelist(self, ips: Set[str]):
        """设置IP白名单"""
        self._ip_whitelist = ips
    
    def get_status(self) -> Dict[str, Any]:
        """获取状态信息"""
        status = {
            'running': self._running,
            'host': self.host,
            'port': self.port,
            'active_connections': self._active_connections,
            'max_connections': self._max_connections,
            'total_requests': len(self.request_history),
            'total_responses': len(self.response_history),
            'rules_count': len(self.rules),
            'bypass_domains': list(self.bypass_domains),
            'protocols': {
                'http1': True,
                'http2': self.enable_h2,
                'http3': self.enable_h3,
                'h3_port': self.h3_port if self.enable_h3 else None,
            }
        }
        
        # 添加HTTP/2统计
        if self.h2_engine:
            status['http2_stats'] = self.h2_engine.get_stats()
        
        # 添加HTTP/3统计
        if self.h3_engine:
            status['http3_stats'] = self.h3_engine.get_stats()
        
        # 添加协议协商统计
        status['protocol_negotiator'] = self.protocol_negotiator.get_stats()
        
        return status
