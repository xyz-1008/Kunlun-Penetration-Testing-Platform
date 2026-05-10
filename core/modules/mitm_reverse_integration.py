"""
MITM代理与反连平台联动模块
实现外带请求检测、PoC关联和反向连接记录
"""

import re
import json
import socket
import logging
import threading
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, field
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

logger = logging.getLogger(__name__)


@dataclass
class OOBRequest:
    """外带请求记录"""
    id: str
    timestamp: datetime
    source_ip: str
    protocol: str  # HTTP, DNS, LDAP
    request_data: Dict[str, Any]
    identifier: str  # 唯一标识符
    associated_poc: str = ""  # 关联的PoC
    vuln_status: str = "pending"  # pending, verified, false_positive


@dataclass
class ReverseConnection:
    """反向连接记录"""
    id: str
    timestamp: datetime
    source_ip: str
    source_port: int
    protocol: str  # TCP, UDP, HTTP, DNS
    payload: bytes = b""
    associated_poc: str = ""
    vuln_status: str = "pending"


class HTTPCallbackHandler(BaseHTTPRequestHandler):
    """HTTP回调处理器"""
    
    def do_GET(self):
        self.server.callback_handler.handle_request(self, 'GET')
    
    def do_POST(self):
        self.server.callback_handler.handle_request(self, 'POST')
    
    def log_message(self, format, *args):
        logger.debug(f"HTTP回调: {format % args}")


class CallbackServer:
    """回调服务器"""
    
    def __init__(self, host: str = "0.0.0.0", port: int = 8888):
        self.host = host
        self.port = port
        self._server: Optional[HTTPServer] = None
        self._thread: Optional[threading.Thread] = None
        self._running = False
        
        self._records: List[OOBRequest] = []
        self._callbacks: List[Callable] = []
        self._identifiers: Dict[str, str] = {}  # identifier -> poc_id
    
    def start(self) -> bool:
        """启动回调服务器"""
        try:
            self._server = HTTPServer((self.host, self.port), HTTPCallbackHandler)
            self._server.callback_handler = self
            
            self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
            self._thread.start()
            self._running = True
            
            logger.info(f"回调服务器已启动: {self.host}:{self.port}")
            return True
        except Exception as e:
            logger.error(f"回调服务器启动失败: {e}")
            return False
    
    def stop(self):
        """停止回调服务器"""
        self._running = False
        if self._server:
            self._server.shutdown()
        logger.info("回调服务器已停止")
    
    def handle_request(self, handler, method: str):
        """处理回调请求"""
        try:
            # 解析请求
            parsed = urlparse(handler.path)
            identifier = parsed.path.strip('/')
            
            # 获取客户端信息
            source_ip = handler.client_address[0]
            
            # 构建请求数据
            request_data = {
                'method': method,
                'path': handler.path,
                'headers': dict(handler.headers),
                'query_params': parse_qs(parsed.query),
            }
            
            # 读取POST数据
            if method == 'POST':
                content_length = int(handler.headers.get('Content-Length', 0))
                if content_length > 0:
                    request_data['body'] = handler.rfile.read(content_length).decode('utf-8', errors='replace')
            
            # 创建记录
            import uuid
            record = OOBRequest(
                id=str(uuid.uuid4())[:12],
                timestamp=datetime.utcnow(),
                source_ip=source_ip,
                protocol='HTTP',
                request_data=request_data,
                identifier=identifier,
                associated_poc=self._identifiers.get(identifier, ""),
            )
            
            self._records.append(record)
            
            # 更新漏洞状态
            if record.associated_poc:
                record.vuln_status = "verified"
            
            # 发送响应
            handler.send_response(200)
            handler.send_header('Content-Type', 'text/plain')
            handler.end_headers()
            handler.wfile.write(b'OK')
            
            # 通知回调
            for callback in self._callbacks:
                try:
                    callback(record)
                except Exception as e:
                    logger.error(f"回调执行失败: {e}")
            
            logger.info(f"收到外带请求: {source_ip} -> {identifier}")
            
        except Exception as e:
            logger.error(f"处理回调请求失败: {e}")
            handler.send_response(500)
            handler.end_headers()
    
    def add_callback(self, callback: Callable):
        """添加回调函数"""
        self._callbacks.append(callback)
    
    def register_identifier(self, identifier: str, poc_id: str):
        """注册标识符与PoC的关联"""
        self._identifiers[identifier] = poc_id
        logger.info(f"注册标识符: {identifier} -> PoC: {poc_id}")
    
    def generate_identifier(self) -> str:
        """生成唯一标识符"""
        import uuid
        return uuid.uuid4().hex[:12]
    
    def get_callback_url(self, identifier: str) -> str:
        """获取回调URL"""
        return f"http://{self.host}:{self.port}/{identifier}"
    
    def get_records(self, identifier: Optional[str] = None) -> List[OOBRequest]:
        """获取外带请求记录"""
        if identifier:
            return [r for r in self._records if identifier in r.identifier]
        return self._records
    
    def get_statistics(self) -> Dict[str, Any]:
        """获取统计信息"""
        return {
            'total_records': len(self._records),
            'verified_count': sum(1 for r in self._records if r.vuln_status == 'verified'),
            'pending_count': sum(1 for r in self._records if r.vuln_status == 'pending'),
            'unique_sources': len(set(r.source_ip for r in self._records)),
            'protocols': {
                'HTTP': sum(1 for r in self._records if r.protocol == 'HTTP'),
            }
        }


class ReverseConnectionListener:
    """反向连接监听器"""
    
    def __init__(self, host: str = "0.0.0.0", port: int = 4444):
        self.host = host
        self.port = port
        self._socket: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._running = False
        
        self._connections: List[ReverseConnection] = []
        self._callbacks: List[Callable] = []
    
    def start(self) -> bool:
        """启动监听"""
        try:
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._socket.bind((self.host, self.port))
            self._socket.listen(5)
            self._socket.settimeout(1.0)
            
            self._running = True
            self._thread = threading.Thread(target=self._listen_loop, daemon=True)
            self._thread.start()
            
            logger.info(f"反向连接监听器已启动: {self.host}:{self.port}")
            return True
        except Exception as e:
            logger.error(f"反向连接监听器启动失败: {e}")
            return False
    
    def stop(self):
        """停止监听"""
        self._running = False
        if self._socket:
            self._socket.close()
        logger.info("反向连接监听器已停止")
    
    def _listen_loop(self):
        """监听循环"""
        while self._running:
            try:
                client_socket, addr = self._socket.accept()
                
                # 接收数据
                data = b""
                try:
                    client_socket.settimeout(5.0)
                    data = client_socket.recv(4096)
                except socket.timeout:
                    pass
                
                # 创建记录
                import uuid
                connection = ReverseConnection(
                    id=str(uuid.uuid4())[:12],
                    timestamp=datetime.utcnow(),
                    source_ip=addr[0],
                    source_port=addr[1],
                    protocol='TCP',
                    payload=data,
                )
                
                self._connections.append(connection)
                
                # 通知回调
                for callback in self._callbacks:
                    try:
                        callback(connection)
                    except Exception as e:
                        logger.error(f"回调执行失败: {e}")
                
                logger.info(f"收到反向连接: {addr[0]}:{addr[1]}")
                
                # 关闭连接
                client_socket.close()
                
            except socket.timeout:
                continue
            except Exception as e:
                if self._running:
                    logger.error(f"监听循环异常: {e}")
    
    def add_callback(self, callback: Callable):
        """添加回调函数"""
        self._callbacks.append(callback)
    
    def get_connections(self) -> List[ReverseConnection]:
        """获取反向连接记录"""
        return self._connections
    
    def get_statistics(self) -> Dict[str, Any]:
        """获取统计信息"""
        return {
            'total_connections': len(self._connections),
            'unique_sources': len(set(c.source_ip for c in self._connections)),
        }


class ReversePlatformIntegration:
    """反连平台集成器"""
    
    def __init__(self, callback_port: int = 8888, reverse_port: int = 4444):
        self.callback_server = CallbackServer(port=callback_port)
        self.reverse_listener = ReverseConnectionListener(port=reverse_port)
        
        self._highlight_callback: Optional[Callable] = None
        self._poc_update_callback: Optional[Callable] = None
    
    def start(self) -> bool:
        """启动反连平台"""
        success = True
        
        if not self.callback_server.start():
            success = False
        
        if not self.reverse_listener.start():
            success = False
        
        # 设置回调
        self.callback_server.add_callback(self._on_oob_request)
        self.reverse_listener.add_callback(self._on_reverse_connection)
        
        return success
    
    def stop(self):
        """停止反连平台"""
        self.callback_server.stop()
        self.reverse_listener.stop()
    
    def set_highlight_callback(self, callback: Callable):
        """设置高亮回调"""
        self._highlight_callback = callback
    
    def set_poc_update_callback(self, callback: Callable):
        """设置PoC更新回调"""
        self._poc_update_callback = callback
    
    def register_poc(self, poc_id: str, identifier: Optional[str] = None) -> str:
        """注册PoC并获取回调URL"""
        if not identifier:
            identifier = self.callback_server.generate_identifier()
        
        self.callback_server.register_identifier(identifier, poc_id)
        return self.callback_server.get_callback_url(identifier)
    
    def _on_oob_request(self, record: OOBRequest):
        """处理外带请求"""
        # 高亮记录
        if self._highlight_callback:
            self._highlight_callback(record)
        
        # 更新PoC状态
        if record.associated_poc and self._poc_update_callback:
            self._poc_update_callback(record.associated_poc, "verified")
    
    def _on_reverse_connection(self, connection: ReverseConnection):
        """处理反向连接"""
        if self._highlight_callback:
            self._highlight_callback(connection)
    
    def get_oob_records(self) -> List[OOBRequest]:
        """获取外带请求记录"""
        return self.callback_server.get_records()
    
    def get_reverse_connections(self) -> List[ReverseConnection]:
        """获取反向连接记录"""
        return self.reverse_listener.get_connections()
    
    def get_statistics(self) -> Dict[str, Any]:
        """获取统计信息"""
        return {
            'callback_server': self.callback_server.get_statistics(),
            'reverse_listener': self.reverse_listener.get_statistics(),
        }
