"""
多信道OOB检测模块
支持DNSLog、HTTPLog、LDAPLog
"""

import os
import sys
import socket
import threading
import logging
import time
import uuid
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

logger = logging.getLogger(__name__)


@dataclass
class OOBRequest:
    """OOB请求"""
    request_id: str
    timestamp: float
    channel: str
    source_ip: str
    data: Dict[str, Any] = field(default_factory=dict)


class DNSLogServer:
    """DNSLog服务器"""
    
    def __init__(self, domain: str = "oob.local", port: int = 5353):
        self.domain = domain
        self.port = port
        self._requests: List[OOBRequest] = []
        self._callbacks: List[Callable] = []
        self._server_thread: Optional[threading.Thread] = None
        self._running = False
        self._lock = threading.RLock()
    
    def start(self):
        """启动DNSLog服务器"""
        if self._running:
            return
        
        self._running = True
        self._server_thread = threading.Thread(target=self._run_server, daemon=True)
        self._server_thread.start()
        logger.info(f"DNSLog服务器启动: {self.domain}:{self.port}")
    
    def stop(self):
        """停止DNSLog服务器"""
        self._running = False
        if self._server_thread:
            self._server_thread.join(timeout=5)
        logger.info("DNSLog服务器已停止")
    
    def _run_server(self):
        """运行DNS服务器"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind(("0.0.0.0", self.port))
            sock.settimeout(1.0)
            
            while self._running:
                try:
                    data, addr = sock.recvfrom(512)
                    self._handle_dns_request(data, addr)
                except socket.timeout:
                    continue
        except Exception as e:
            logger.error(f"DNSLog服务器异常: {e}")
    
    def _handle_dns_request(self, data: bytes, addr: tuple):
        """处理DNS请求"""
        try:
            query = self._parse_dns_query(data)
            if query:
                request_id = str(uuid.uuid4())
                request = OOBRequest(
                    request_id=request_id,
                    timestamp=time.time(),
                    channel="dns",
                    source_ip=addr[0],
                    data={"query": query}
                )
                
                with self._lock:
                    self._requests.append(request)
                
                for callback in self._callbacks:
                    try:
                        callback(request)
                    except Exception as e:
                        logger.error(f"回调执行失败: {e}")
                
                response = self._build_dns_response(data, query)
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.sendto(response, addr)
        except Exception as e:
            logger.error(f"处理DNS请求失败: {e}")
    
    def _parse_dns_query(self, data: bytes) -> Optional[str]:
        """解析DNS查询"""
        if len(data) < 12:
            return None
        
        qname = ""
        idx = 12
        while idx < len(data):
            length = data[idx]
            if length == 0:
                break
            idx += 1
            if idx + length <= len(data):
                if qname:
                    qname += "."
                qname += data[idx:idx+length].decode("utf-8", errors="ignore")
                idx += length
            else:
                break
        
        return qname if qname else None
    
    def _build_dns_response(self, request_data: bytes, query: str) -> bytes:
        """构建DNS响应"""
        response = bytearray(request_data[:2])
        response.extend(b"\x81\x80")
        response.extend(request_data[4:6])
        response.extend(b"\x00\x00")
        response.extend(b"\x00\x01")
        response.extend(b"\x00\x00")
        
        if query:
            for part in query.split("."):
                response.append(len(part))
                response.extend(part.encode())
            response.append(0)
        
        response.extend(b"\x00\x01\x00\x01")
        response.extend(b"\x00\x00\x00\x3c")
        response.extend(b"\x00\x04")
        response.extend(b"\x7f\x00\x00\x01")
        
        return bytes(response)
    
    def generate_subdomain(self) -> str:
        """生成唯一子域名"""
        unique_id = uuid.uuid4().hex[:12]
        return f"{unique_id}.{self.domain}"
    
    def get_requests(self, limit: int = 100) -> List[OOBRequest]:
        """获取请求列表"""
        with self._lock:
            return self._requests[-limit:]
    
    def add_callback(self, callback: Callable):
        """添加回调"""
        self._callbacks.append(callback)
    
    def clear_requests(self):
        """清除请求记录"""
        with self._lock:
            self._requests.clear()


class HTTPLogHandler(BaseHTTPRequestHandler):
    """HTTPLog处理器"""
    
    def do_GET(self):
        self._handle_request("GET")
    
    def do_POST(self):
        self._handle_request("POST")
    
    def _handle_request(self, method: str):
        """处理HTTP请求"""
        try:
            parsed = urlparse(self.path)
            params = parse_qs(parsed.query)
            
            request_id = str(uuid.uuid4())
            request = OOBRequest(
                request_id=request_id,
                timestamp=time.time(),
                channel="http",
                source_ip=self.client_address[0],
                data={
                    "method": method,
                    "path": parsed.path,
                    "params": params,
                    "headers": dict(self.headers),
                }
            )
            
            server = self.server
            if hasattr(server, "add_request"):
                server.add_request(request)
            
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"OK")
        except Exception as e:
            logger.error(f"处理HTTP请求失败: {e}")
            self.send_response(500)
            self.end_headers()
    
    def log_message(self, format, *args):
        pass


class HTTPLogServer:
    """HTTPLog服务器"""
    
    def __init__(self, host: str = "0.0.0.0", port: int = 8080):
        self.host = host
        self.port = port
        self._requests: List[OOBRequest] = []
        self._callbacks: List[Callable] = []
        self._server: Optional[HTTPServer] = None
        self._server_thread: Optional[threading.Thread] = None
        self._running = False
        self._lock = threading.RLock()
    
    def start(self):
        """启动HTTPLog服务器"""
        if self._running:
            return
        
        self._server = HTTPServer((self.host, self.port), HTTPLogHandler)
        self._server.add_request = self._add_request
        
        self._running = True
        self._server_thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._server_thread.start()
        logger.info(f"HTTPLog服务器启动: {self.host}:{self.port}")
    
    def stop(self):
        """停止HTTPLog服务器"""
        self._running = False
        if self._server:
            self._server.shutdown()
        logger.info("HTTPLog服务器已停止")
    
    def _add_request(self, request: OOBRequest):
        """添加请求"""
        with self._lock:
            self._requests.append(request)
        
        for callback in self._callbacks:
            try:
                callback(request)
            except Exception as e:
                logger.error(f"回调执行失败: {e}")
    
    def generate_callback_url(self, path: str = "/callback") -> str:
        """生成回调URL"""
        unique_id = uuid.uuid4().hex[:12]
        return f"http://{self.host}:{self.port}{path}/{unique_id}"
    
    def get_requests(self, limit: int = 100) -> List[OOBRequest]:
        """获取请求列表"""
        with self._lock:
            return self._requests[-limit:]
    
    def add_callback(self, callback: Callable):
        """添加回调"""
        self._callbacks.append(callback)
    
    def clear_requests(self):
        """清除请求记录"""
        with self._lock:
            self._requests.clear()


class LDAPLogServer:
    """LDAPLog服务器 (用于JNDI注入检测)"""
    
    def __init__(self, host: str = "0.0.0.0", port: int = 1389):
        self.host = host
        self.port = port
        self._requests: List[OOBRequest] = []
        self._callbacks: List[Callable] = []
        self._server_thread: Optional[threading.Thread] = None
        self._running = False
        self._lock = threading.RLock()
    
    def start(self):
        """启动LDAPLog服务器"""
        if self._running:
            return
        
        self._running = True
        self._server_thread = threading.Thread(target=self._run_server, daemon=True)
        self._server_thread.start()
        logger.info(f"LDAPLog服务器启动: {self.host}:{self.port}")
    
    def stop(self):
        """停止LDAPLog服务器"""
        self._running = False
        if self._server_thread:
            self._server_thread.join(timeout=5)
        logger.info("LDAPLog服务器已停止")
    
    def _run_server(self):
        """运行LDAP服务器"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((self.host, self.port))
            sock.listen(5)
            sock.settimeout(1.0)
            
            while self._running:
                try:
                    conn, addr = sock.accept()
                    self._handle_ldap_connection(conn, addr)
                except socket.timeout:
                    continue
        except Exception as e:
            logger.error(f"LDAPLog服务器异常: {e}")
    
    def _handle_ldap_connection(self, conn: socket.socket, addr: tuple):
        """处理LDAP连接"""
        try:
            data = conn.recv(1024)
            if data:
                request_id = str(uuid.uuid4())
                request = OOBRequest(
                    request_id=request_id,
                    timestamp=time.time(),
                    channel="ldap",
                    source_ip=addr[0],
                    data={"raw_data": data.hex()}
                )
                
                with self._lock:
                    self._requests.append(request)
                
                for callback in self._callbacks:
                    try:
                        callback(request)
                    except Exception as e:
                        logger.error(f"回调执行失败: {e}")
                
                conn.close()
        except Exception as e:
            logger.error(f"处理LDAP连接失败: {e}")
        finally:
            try:
                conn.close()
            except:
                pass
    
    def generate_ldap_url(self, path: str = "/exp") -> str:
        """生成LDAP URL"""
        unique_id = uuid.uuid4().hex[:12]
        return f"ldap://{self.host}:{self.port}/{path}/{unique_id}"
    
    def get_requests(self, limit: int = 100) -> List[OOBRequest]:
        """获取请求列表"""
        with self._lock:
            return self._requests[-limit:]
    
    def add_callback(self, callback: Callable):
        """添加回调"""
        self._callbacks.append(callback)
    
    def clear_requests(self):
        """清除请求记录"""
        with self._lock:
            self._requests.clear()


class OOBManager:
    """OOB管理器"""
    
    def __init__(self, dns_port: int = 15353, http_port: int = 18080, ldap_port: int = 13890):
        self.dns_server = DNSLogServer(port=dns_port)
        self.http_server = HTTPLogServer(port=http_port)
        self.ldap_server = LDAPLogServer(port=ldap_port)
    
    def start_all(self):
        """启动所有服务器"""
        self.dns_server.start()
        self.http_server.start()
        self.ldap_server.start()
        logger.info("所有OOB服务器已启动")
    
    def stop_all(self):
        """停止所有服务器"""
        self.dns_server.stop()
        self.http_server.stop()
        self.ldap_server.stop()
        logger.info("所有OOB服务器已停止")
    
    def generate_dns_subdomain(self) -> str:
        """生成DNS子域名"""
        return self.dns_server.generate_subdomain()
    
    def generate_http_callback_url(self, path: str = "/callback") -> str:
        """生成HTTP回调URL"""
        return self.http_server.generate_callback_url(path)
    
    def generate_ldap_url(self, path: str = "/exp") -> str:
        """生成LDAP URL"""
        return self.ldap_server.generate_ldap_url(path)
    
    def get_all_requests(self, limit: int = 100) -> List[OOBRequest]:
        """获取所有请求"""
        requests = []
        requests.extend(self.dns_server.get_requests(limit))
        requests.extend(self.http_server.get_requests(limit))
        requests.extend(self.ldap_server.get_requests(limit))
        
        requests.sort(key=lambda x: x.timestamp, reverse=True)
        return requests[:limit]
    
    def add_callback(self, callback: Callable):
        """添加回调到所有服务器"""
        self.dns_server.add_callback(callback)
        self.http_server.add_callback(callback)
        self.ldap_server.add_callback(callback)
    
    def clear_all_requests(self):
        """清除所有请求记录"""
        self.dns_server.clear_requests()
        self.http_server.clear_requests()
        self.ldap_server.clear_requests()
