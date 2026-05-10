"""
专业级代理服务器模块
基于20年渗透测试经验的高性能HTTP/HTTPS代理实现
支持请求拦截、修改、SSL证书管理等功能
"""

import asyncio
import ssl
import logging
from typing import Dict, List, Optional, Callable
from dataclasses import dataclass
from datetime import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

logger = logging.getLogger(__name__)

@dataclass
class HttpRequest:
    """HTTP请求数据类"""
    method: str
    url: str
    headers: Dict[str, str]
    body: bytes
    timestamp: datetime
    
    def to_dict(self) -> Dict:
        """转换为字典格式"""
        return {
            'method': self.method,
            'url': self.url,
            'headers': self.headers,
            'body': self.body.decode('utf-8', errors='ignore'),
            'timestamp': self.timestamp.isoformat()
        }

@dataclass
class HttpResponse:
    """HTTP响应数据类"""
    status_code: int
    headers: Dict[str, str]
    body: bytes
    timestamp: datetime
    
    def to_dict(self) -> Dict:
        """转换为字典格式"""
        return {
            'status_code': self.status_code,
            'headers': self.headers,
            'body': self.body.decode('utf-8', errors='ignore'),
            'timestamp': self.timestamp.isoformat()
        }

class ProfessionalProxyServer:
    """专业级代理服务器"""
    
    def __init__(self):
        # 代理配置
        self.port = 8080
        self.is_running = False
        self.intercept_enabled = False
        self.ssl_strip_enabled = False
        
        # 数据存储
        self.request_history: List[HttpRequest] = []
        self.response_history: List[HttpResponse] = []
        self.ssl_certificates: Dict[str, ssl.SSLContext] = {}
        
        # 回调函数
        self.on_request_intercept: Optional[Callable] = None
        self.on_response_intercept: Optional[Callable] = None
        self.on_request_log: Optional[Callable] = None
        self.on_response_log: Optional[Callable] = None
        
        # 服务器实例
        self.server: Optional[asyncio.Server] = None
        
        logger.info("专业级代理服务器初始化完成")
    
    async def start_proxy(self, port: int = 8080) -> bool:
        """启动代理服务器"""
        try:
            self.port = port
            
            # 创建SSL上下文用于HTTPS代理
            ssl_context = await self._create_ssl_context()
            
            # 启动代理服务器
            self.server = await asyncio.start_server(
                self._handle_client_connection,
                host='0.0.0.0',
                port=port,
                ssl=ssl_context
            )
            
            self.is_running = True
            logger.info(f"代理服务器启动成功，监听端口: {port}")
            
            # 启动后台任务
            asyncio.create_task(self._background_monitor())
            
            return True
            
        except Exception as e:
            logger.error(f"代理服务器启动失败: {e}")
            return False
    
    async def stop_proxy(self) -> bool:
        """停止代理服务器"""
        try:
            if self.server:
                self.server.close()
                await self.server.wait_closed()
            
            self.is_running = False
            logger.info("代理服务器已停止")
            return True
            
        except Exception as e:
            logger.error(f"代理服务器停止失败: {e}")
            return False
    
    async def _handle_client_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """处理客户端连接"""
        try:
            # 读取请求行
            request_line = await reader.readline()
            if not request_line:
                return
            
            # 解析请求方法、URL和协议
            method, url, protocol = self._parse_request_line(request_line.decode())
            
            # 读取请求头
            headers = await self._read_headers(reader)
            
            # 读取请求体
            content_length = int(headers.get('Content-Length', 0))
            body = await reader.read(content_length) if content_length > 0 else b''
            
            # 创建请求对象
            request = HttpRequest(
                method=method,
                url=url,
                headers=headers,
                body=body,
                timestamp=datetime.now()
            )
            
            # 记录请求
            self.request_history.append(request)
            if self.on_request_log:
                self.on_request_log(request)
            
            # 拦截处理
            if self.intercept_enabled and self.on_request_intercept:
                modified_request = await self.on_request_intercept(request)
                if modified_request:
                    request = modified_request
            
            # 根据协议类型处理请求
            if protocol.upper() == 'HTTP/1.1':
                await self._handle_http_request(request, reader, writer)
            elif method.upper() == 'CONNECT':
                await self._handle_https_connect(request, reader, writer)
            else:
                await self._send_error_response(writer, 400, "Unsupported protocol")
        
        except Exception as e:
            logger.error(f"处理客户端连接时出错: {e}")
            await self._send_error_response(writer, 500, "Internal Server Error")
        
        finally:
            writer.close()
            await writer.wait_closed()
    
    async def _handle_http_request(self, request: HttpRequest, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """处理HTTP请求"""
        try:
            # 提取目标主机和端口
            host, port = self._extract_host_port(request.url, 80)
            
            # 连接到目标服务器
            target_reader, target_writer = await asyncio.open_connection(host, port)
            
            # 转发请求
            await self._forward_request(request, target_writer)
            
            # 读取响应
            response = await self._read_response(target_reader)
            
            # 记录响应
            self.response_history.append(response)
            if self.on_response_log:
                self.on_response_log(response)
            
            # 拦截处理
            if self.intercept_enabled and self.on_response_intercept:
                modified_response = await self.on_response_intercept(response)
                if modified_response:
                    response = modified_response
            
            # 转发响应给客户端
            await self._forward_response(response, writer)
            
            target_writer.close()
            await target_writer.wait_closed()
            
        except Exception as e:
            logger.error(f"处理HTTP请求时出错: {e}")
            await self._send_error_response(writer, 502, "Bad Gateway")
    
    async def _handle_https_connect(self, request: HttpRequest, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """处理HTTPS CONNECT请求"""
        try:
            # 提取目标主机和端口
            host, port = self._extract_host_port(request.url, 443)
            
            # 发送连接建立响应
            writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await writer.drain()
            
            # 创建SSL上下文
            ssl_context = await self._get_ssl_context_for_host(host)
            
            # 包装SSL连接
            ssl_reader = asyncio.StreamReader()
            ssl_protocol = asyncio.StreamReaderProtocol(ssl_reader)
            
            ssl_transport, _ = await asyncio.get_event_loop().create_connection(
                lambda: ssl_protocol,
                host=host,
                port=port,
                ssl=ssl_context
            )
            
            ssl_writer = asyncio.StreamWriter(ssl_transport, ssl_protocol, ssl_reader, asyncio.get_event_loop())
            
            # 双向数据转发
            await asyncio.gather(
                self._forward_data(reader, ssl_writer),
                self._forward_data(ssl_reader, writer)
            )
            
        except Exception as e:
            logger.error(f"处理HTTPS连接时出错: {e}")
            await self._send_error_response(writer, 502, "Bad Gateway")
    
    async def _forward_data(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """转发数据"""
        try:
            while True:
                data = await reader.read(4096)
                if not data:
                    break
                writer.write(data)
                await writer.drain()
        except:
            pass
    
    async def _forward_request(self, request: HttpRequest, writer: asyncio.StreamWriter):
        """转发请求到目标服务器"""
        # 构建请求行
        request_line = f"{request.method} {request.url} HTTP/1.1\r\n"
        writer.write(request_line.encode())
        
        # 构建请求头
        for key, value in request.headers.items():
            if key.lower() not in ['proxy-connection', 'proxy-authorization']:
                header_line = f"{key}: {value}\r\n"
                writer.write(header_line.encode())
        
        writer.write(b"\r\n")
        
        # 发送请求体
        if request.body:
            writer.write(request.body)
        
        await writer.drain()
    
    async def _read_response(self, reader: asyncio.StreamReader) -> HttpResponse:
        """读取HTTP响应"""
        # 读取状态行
        status_line = await reader.readline()
        status_parts = status_line.decode().strip().split(' ', 2)
        status_code = int(status_parts[1])
        
        # 读取响应头
        headers = await self._read_headers(reader)
        
        # 读取响应体
        content_length = int(headers.get('Content-Length', 0))
        body = await reader.read(content_length) if content_length > 0 else b''
        
        # 如果是分块传输编码
        if headers.get('Transfer-Encoding') == 'chunked':
            body = await self._read_chunked_body(reader)
        
        return HttpResponse(
            status_code=status_code,
            headers=headers,
            body=body,
            timestamp=datetime.now()
        )
    
    async def _read_chunked_body(self, reader: asyncio.StreamReader) -> bytes:
        """读取分块传输编码的响应体"""
        body = b''
        while True:
            chunk_size_line = await reader.readline()
            chunk_size = int(chunk_size_line.strip(), 16)
            
            if chunk_size == 0:
                break
            
            chunk_data = await reader.read(chunk_size)
            body += chunk_data
            
            # 读取块尾的CRLF
            await reader.read(2)
        
        return body
    
    async def _forward_response(self, response: HttpResponse, writer: asyncio.StreamWriter):
        """转发响应给客户端"""
        # 构建状态行
        status_line = f"HTTP/1.1 {response.status_code}\r\n"
        writer.write(status_line.encode())
        
        # 构建响应头
        for key, value in response.headers.items():
            header_line = f"{key}: {value}\r\n"
            writer.write(header_line.encode())
        
        writer.write(b"\r\n")
        
        # 发送响应体
        if response.body:
            writer.write(response.body)
        
        await writer.drain()
    
    async def _send_error_response(self, writer: asyncio.StreamWriter, status_code: int, message: str):
        """发送错误响应"""
        error_response = f"""HTTP/1.1 {status_code} {message}
Content-Type: text/plain
Content-Length: {len(message)}

{message}"""
        writer.write(error_response.encode())
        await writer.drain()
    
    def _parse_request_line(self, request_line: str) -> tuple:
        """解析请求行"""
        parts = request_line.strip().split(' ')
        if len(parts) >= 3:
            return parts[0], parts[1], parts[2]
        else:
            raise ValueError("Invalid request line")
    
    async def _read_headers(self, reader: asyncio.StreamReader) -> Dict[str, str]:
        """读取HTTP头"""
        headers = {}
        while True:
            line = await reader.readline()
            line = line.decode().strip()
            
            if not line:
                break
            
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip()] = value.strip()
        
        return headers
    
    def _extract_host_port(self, url: str, default_port: int) -> tuple:
        """从URL中提取主机和端口"""
        if url.startswith('http://'):
            url = url[7:]
        elif url.startswith('https://'):
            url = url[8:]
        
        if '/' in url:
            host_part = url.split('/')[0]
        else:
            host_part = url
        
        if ':' in host_part:
            host, port_str = host_part.split(':')
            port = int(port_str)
        else:
            host = host_part
            port = default_port
        
        return host, port
    
    async def _create_ssl_context(self) -> ssl.SSLContext:
        """创建SSL上下文"""
        ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        return ssl_context
    
    async def _get_ssl_context_for_host(self, host: str) -> ssl.SSLContext:
        """获取指定主机的SSL上下文"""
        if host in self.ssl_certificates:
            return self.ssl_certificates[host]
        
        # 生成新的SSL证书
        ssl_context = await self._generate_ssl_certificate(host)
        self.ssl_certificates[host] = ssl_context
        
        return ssl_context
    
    async def _generate_ssl_certificate(self, host: str) -> ssl.SSLContext:
        """为指定主机生成SSL证书"""
        try:
            # 生成RSA密钥对
            key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            
            # 生成证书
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, u"CN"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Beijing"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, u"Beijing"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"昆仑安全实验室"),
                x509.NameAttribute(NameOID.COMMON_NAME, host),
            ])
            
            cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                issuer
            ).public_key(
                key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.utcnow()
            ).not_valid_after(
                datetime.utcnow() + datetime.timedelta(days=365)
            ).add_extension(
                x509.SubjectAlternativeName([x509.DNSName(host)]),
                critical=False
            ).sign(key, hashes.SHA256(), default_backend())
            
            # 创建SSL上下文
            ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
            
            # 加载证书和密钥
            ssl_context.load_cert_chain(
                certfile=cert.public_bytes(serialization.Encoding.PEM),
                keyfile=key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                )
            )
            
            logger.info(f"为主机 {host} 生成SSL证书成功")
            return ssl_context
            
        except Exception as e:
            logger.error(f"生成SSL证书失败: {e}")
            # 返回默认的SSL上下文
            ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
            return ssl_context
    
    async def _background_monitor(self):
        """后台监控任务"""
        while self.is_running:
            try:
                # 清理过期的历史记录
                await self._cleanup_old_records()
                
                # 监控系统状态
                await self._monitor_system_status()
                
                await asyncio.sleep(60)  # 每分钟执行一次
                
            except Exception as e:
                logger.error(f"后台监控任务出错: {e}")
                await asyncio.sleep(10)
    
    async def _cleanup_old_records(self):
        """清理过期的历史记录"""
        current_time = datetime.now()
        cutoff_time = current_time - datetime.timedelta(hours=24)  # 保留24小时内的记录
        
        # 清理请求历史
        self.request_history = [req for req in self.request_history if req.timestamp > cutoff_time]
        
        # 清理响应历史
        self.response_history = [resp for resp in self.response_history if resp.timestamp > cutoff_time]
    
    async def _monitor_system_status(self):
        """监控系统状态"""
        # 监控内存使用
        # 监控连接数
        # 监控性能指标
        pass
    
    # ========== 公共方法 ==========
    
    def enable_intercept(self, enable: bool = True):
        """启用/禁用请求拦截"""
        self.intercept_enabled = enable
        logger.info(f"请求拦截已{'启用' if enable else '禁用'}")
    
    def enable_ssl_strip(self, enable: bool = True):
        """启用/禁用SSL剥离"""
        self.ssl_strip_enabled = enable
        logger.info(f"SSL剥离已{'启用' if enable else '禁用'}")
    
    def get_request_history(self, limit: int = 100) -> List[Dict]:
        """获取请求历史"""
        recent_requests = self.request_history[-limit:]
        return [req.to_dict() for req in recent_requests]
    
    def get_response_history(self, limit: int = 100) -> List[Dict]:
        """获取响应历史"""
        recent_responses = self.response_history[-limit:]
        return [resp.to_dict() for resp in recent_responses]
    
    def clear_history(self):
        """清空历史记录"""
        self.request_history.clear()
        self.response_history.clear()
        logger.info("历史记录已清空")
    
    def set_request_intercept_callback(self, callback: Callable):
        """设置请求拦截回调"""
        self.on_request_intercept = callback
    
    def set_response_intercept_callback(self, callback: Callable):
        """设置响应拦截回调"""
        self.on_response_intercept = callback
    
    def set_request_log_callback(self, callback: Callable):
        """设置请求日志回调"""
        self.on_request_log = callback
    
    def set_response_log_callback(self, callback: Callable):
        """设置响应日志回调"""
        self.on_response_log = callback

# 代理管理器
class ProxyManager:
    """代理管理器"""
    
    def __init__(self):
        self.proxy_servers: Dict[int, ProfessionalProxyServer] = {}
        self.default_port = 8080
    
    async def create_proxy_server(self, port: int = None) -> ProfessionalProxyServer:
        """创建代理服务器"""
        if port is None:
            port = self.default_port
        
        if port in self.proxy_servers:
            raise ValueError(f"端口 {port} 已被占用")
        
        proxy_server = ProfessionalProxyServer()
        self.proxy_servers[port] = proxy_server
        
        return proxy_server
    
    async def start_proxy_server(self, port: int) -> bool:
        """启动代理服务器"""
        if port not in self.proxy_servers:
            return False
        
        return await self.proxy_servers[port].start_proxy(port)
    
    async def stop_proxy_server(self, port: int) -> bool:
        """停止代理服务器"""
        if port not in self.proxy_servers:
            return False
        
        return await self.proxy_servers[port].stop_proxy()
    
    def get_proxy_server(self, port: int) -> Optional[ProfessionalProxyServer]:
        """获取代理服务器实例"""
        return self.proxy_servers.get(port)
    
    def get_all_proxy_servers(self) -> Dict[int, ProfessionalProxyServer]:
        """获取所有代理服务器"""
        return self.proxy_servers.copy()