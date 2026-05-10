"""
HTTP/3(QUIC)协议处理引擎
基于UDP的QUIC代理，支持HTTP/3 over QUIC
"""

import asyncio
import ssl
import logging
import hashlib
import threading
from typing import Dict, Any, Optional, List, Callable, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

try:
    from aioquic.asyncio import QuicConnectionProtocol, serve
    from aioquic.quic.configuration import QuicConfiguration
    from aioquic.quic.connection import QuicConnection
    from aioquic.quic.events import (
        QuicEvent, DatagramReceived, ConnectionTerminated,
        StreamDataReceived, StreamReset, ProtocolNegotiated
    )
    from aioquic.h3.connection import H3_ALPN, H3Connection
    from aioquic.h3.events import (
        H3Event, HeadersReceived, DataReceived, H3StreamEnded
    )
    QUIC_AVAILABLE = True
except ImportError:
    QUIC_AVAILABLE = False

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .mitm_proxy_engine import MITMRequest, MITMResponse, CertificateManager

logger = logging.getLogger(__name__)


class H3Protocol(Enum):
    """HTTP/3协议类型"""
    H3 = "h3"  # HTTP/3 over QUIC
    H2 = "h2"  # 降级到HTTP/2
    HTTP1 = "http/1.1"  # 降级到HTTP/1.1


@dataclass
class H3Stream:
    """HTTP/3流信息"""
    stream_id: int
    request: "MITMRequest" = None  # type: ignore
    response: "MITMResponse" = None  # type: ignore
    request_headers: List[Tuple[str, str]] = field(default_factory=list)
    response_headers: List[Tuple[str, str]] = field(default_factory=list)
    request_body: bytes = b""
    response_body: bytes = b""
    timestamp: datetime = field(default_factory=datetime.utcnow)
    state: str = "idle"


class H3ProxyEngine:
    """HTTP/3(QUIC)代理引擎"""
    
    def __init__(self, cert_manager = None):
        if cert_manager is None:
            from .mitm_proxy_engine import CertificateManager
            cert_manager = CertificateManager()
        
        self.cert_manager = cert_manager
        self._running = False
        self._connections: Dict[str, QuicConnection] = {}
        self._h3_connections: Dict[str, H3Connection] = {}
        self._streams: Dict[int, H3Stream] = {}
        self._connection_lock = threading.Lock()
        
        self._callbacks: Dict[str, List[Callable]] = {
            'on_request': [],
            'on_response': [],
            'on_error': [],
        }
        
        self._request_history: List[MITMRequest] = []
        self._response_history: List[MITMResponse] = []
        
        self._max_concurrent_streams = 100
        self._active_streams = 0
        self._quic_port = 443
        self._quic_host = "0.0.0.0"
        
        self._zero_rtt_data: Dict[str, bytes] = {}
        self._fallback_enabled = True
        
        if not QUIC_AVAILABLE:
            logger.warning("aioquic库未安装，HTTP/3功能不可用")
    
    def add_callback(self, event_type: str, callback: Callable):
        """添加回调函数"""
        if event_type in self._callbacks:
            self._callbacks[event_type].append(callback)
    
    def _notify_callbacks(self, event_type: str, *args, **kwargs):
        """通知回调函数"""
        for callback in self._callbacks.get(event_type, []):
            try:
                callback(*args, **kwargs)
            except Exception as e:
                logger.error(f"回调执行失败: {e}")
    
    async def start_quic_server(self, host: str = "0.0.0.0", port: int = 443):
        """启动QUIC服务器"""
        if not QUIC_AVAILABLE:
            logger.error("aioquic库未安装")
            return
        
        self._quic_host = host
        self._quic_port = port
        self._running = True
        
        try:
            # 创建QUIC配置
            configuration = QuicConfiguration(
                is_client=False,
                alpn_protocols=H3_ALPN,
            )
            
            # 加载证书
            cert, private_key = self.cert_manager.get_cert_and_key()
            configuration.load_cert_chain(cert, private_key)
            
            # 启动QUIC服务器
            server = await serve(
                self._quic_host,
                self._quic_port,
                configuration=configuration,
                create_protocol=H3QUICProtocol,
            )
            
            logger.info(f"HTTP/3(QUIC)服务器启动: {self._quic_host}:{self._quic_port}")
            
        except Exception as e:
            logger.error(f"启动QUIC服务器失败: {e}")
            self._running = False
            raise
    
    def stop_quic_server(self):
        """停止QUIC服务器"""
        self._running = False
        self.cleanup()
        logger.info("HTTP/3(QUIC)服务器已停止")
    
    async def handle_h3_event(self, event, 
                              quic_connection,
                              h3_connection,
                              connection_id):
        """处理HTTP/3事件"""
        if not QUIC_AVAILABLE:
            return
        
        from aioquic.h3.events import HeadersReceived, DataReceived, H3StreamEnded
        
        if isinstance(event, HeadersReceived):
            await self._handle_headers_received(event, quic_connection, h3_connection, connection_id)
        elif isinstance(event, DataReceived):
            await self._handle_data_received(event, h3_connection)
        elif isinstance(event, H3StreamEnded):
            await self._handle_stream_ended(event)
    
    async def _handle_headers_received(self, event,
                                       quic_connection,
                                       h3_connection,
                                       connection_id):
        """处理头部接收事件"""
        stream_id = event.stream_id
        
        # 创建流对象
        stream = H3Stream(stream_id=stream_id)
        stream.state = "open"
        stream.request_headers = event.headers
        
        with self._connection_lock:
            self._streams[stream_id] = stream
            self._active_streams += 1
        
        # 解析HTTP/3头部
        headers_dict = {}
        pseudo_headers = {}
        
        for name, value in event.headers:
            if name.startswith(':'):
                pseudo_headers[name] = value
            else:
                headers_dict[name] = value
        
        # 转换伪头部为标准HTTP头部
        method = pseudo_headers.get(':method', 'GET')
        path = pseudo_headers.get(':path', '/')
        authority = pseudo_headers.get(':authority', '')
        
        url = f"https://{authority}{path}" if authority else path
        
        # 创建MITMRequest对象
        request_id = hashlib.md5(
            f"{datetime.utcnow().isoformat()}{url}{stream_id}".encode()
        ).hexdigest()[:12]
        
        request = MITMRequest(
            id=request_id,
            timestamp=datetime.utcnow(),
            method=method,
            url=url,
            host=authority,
            path=path,
            headers=headers_dict,
            body=b"",
            protocol="HTTP/3",
            is_https=True,
            client_ip=quic_connection._network_paths[0].host_name if quic_connection._network_paths else ""
        )
        
        stream.request = request
        
        # 通知回调
        self._notify_callbacks('on_request', request)
        self._request_history.append(request)
        
        logger.debug(f"HTTP/3请求接收: {method} {url} (stream {stream_id})")
    
    async def _handle_data_received(self, event,
                                    h3_connection):
        """处理数据接收事件"""
        stream_id = event.stream_id
        stream = self._streams.get(stream_id)
        
        if not stream:
            logger.warning(f"未找到流: {stream_id}")
            return
        
        # 累积数据
        if stream.request and not stream.response:
            stream.request_body += event.data
        elif stream.response:
            stream.response_body += event.data
    
    async def _handle_stream_ended(self, event):
        """处理流结束事件"""
        stream_id = event.stream_id
        stream = self._streams.get(stream_id)
        
        if not stream:
            return
        
        stream.state = "closed"
        
        # 更新请求/响应体
        if stream.request and stream.request_body:
            stream.request.body = stream.request_body
        
        if stream.response and stream.response_body:
            stream.response.body = stream.response_body
            stream.response.content_length = len(stream.response_body)
            
            # 通知回调
            self._notify_callbacks('on_response', stream.response)
            self._response_history.append(stream.response)
        
        # 清理流
        with self._connection_lock:
            self._streams.pop(stream_id, None)
            self._active_streams -= 1
        
        logger.debug(f"HTTP/3流结束: {stream_id}")
    
    def create_h3_request(self, request) -> List[Tuple[str, str]]:
        """创建HTTP/3请求头部"""
        headers = [
            (':method', request.method),
            (':path', request.path),
            (':authority', request.host),
            (':scheme', 'https'),
        ]
        
        for name, value in request.headers.items():
            if name.lower() not in ['host', 'connection', 'transfer-encoding']:
                headers.append((name.lower(), value))
        
        return headers
    
    def create_h3_response(self, response) -> List[Tuple[str, str]]:
        """创建HTTP/3响应头部"""
        headers = [
            (':status', str(response.status_code)),
        ]
        
        for name, value in response.headers.items():
            if name.lower() not in ['connection', 'transfer-encoding']:
                headers.append((name.lower(), value))
        
        return headers
    
    def modify_request(self, stream_id: int, new_headers: Dict[str, str] = None,
                       new_body: bytes = None) -> bool:
        """修改请求"""
        stream = self._streams.get(stream_id)
        if not stream or not stream.request:
            return False
        
        if new_headers:
            stream.request.headers.update(new_headers)
        
        if new_body is not None:
            stream.request.body = new_body
            stream.request.content_length = len(new_body)
        
        return True
    
    def modify_response(self, stream_id: int, new_headers: Dict[str, str] = None,
                        new_body: bytes = None) -> bool:
        """修改响应"""
        stream = self._streams.get(stream_id)
        if not stream or not stream.response:
            return False
        
        if new_headers:
            stream.response.headers.update(new_headers)
        
        if new_body is not None:
            stream.response.body = new_body
            stream.response.content_length = len(new_body)
        
        return True
    
    def handle_zero_rtt(self, connection_id: str, data: bytes):
        """处理0-RTT数据"""
        self._zero_rtt_data[connection_id] = data
        logger.info(f"HTTP/3 0-RTT数据接收: {connection_id}")
    
    def get_zero_rtt_data(self, connection_id: str) -> Optional[bytes]:
        """获取0-RTT数据"""
        return self._zero_rtt_data.get(connection_id)
    
    def fallback_to_h2(self, request) -> bool:
        """降级到HTTP/2"""
        if not self._fallback_enabled:
            return False
        
        logger.info(f"HTTP/3降级到HTTP/2: {request.url}")
        return True
    
    def fallback_to_http1(self, request) -> bool:
        """降级到HTTP/1.1"""
        if not self._fallback_enabled:
            return False
        
        logger.info(f"HTTP/3降级到HTTP/1.1: {request.url}")
        return True
    
    def get_stream_info(self, stream_id: int) -> Optional[Dict[str, Any]]:
        """获取流信息"""
        stream = self._streams.get(stream_id)
        if not stream:
            return None
        
        return {
            'stream_id': stream.stream_id,
            'state': stream.state,
            'request': stream.request.to_dict() if stream.request else None,
            'response': stream.response.to_dict() if stream.response else None,
        }
    
    def get_active_streams(self) -> List[int]:
        """获取活跃流列表"""
        return [
            stream_id for stream_id, stream in self._streams.items()
            if stream.state in ['open', 'half_closed']
        ]
    
    def get_stats(self) -> Dict[str, Any]:
        """获取统计信息"""
        return {
            'total_connections': len(self._connections),
            'active_streams': self._active_streams,
            'total_requests': len(self._request_history),
            'total_responses': len(self._response_history),
            'max_concurrent_streams': self._max_concurrent_streams,
            'quic_port': self._quic_port,
            'zero_rtt_connections': len(self._zero_rtt_data),
        }
    
    def cleanup(self):
        """清理资源"""
        with self._connection_lock:
            self._connections.clear()
            self._h3_connections.clear()
            self._streams.clear()
            self._active_streams = 0
        
        self._request_history.clear()
        self._response_history.clear()
        self._zero_rtt_data.clear()
        
        logger.info("HTTP/3(QUIC)代理引擎已清理")


class H3QUICProtocol:
    """HTTP/3 QUIC协议处理器"""
    
    def __init__(self, quic_connection):
        self._quic = quic_connection
        self._h3 = None
    
    def quic_event_received(self, event):
        """接收QUIC事件"""
        if not QUIC_AVAILABLE:
            return
        
        from aioquic.quic.events import ConnectionTerminated, StreamDataReceived, ProtocolNegotiated
        
        if isinstance(event, ConnectionTerminated):
            self._handle_connection_terminated(event)
        elif isinstance(event, StreamDataReceived):
            self._handle_stream_data_received(event)
        elif isinstance(event, ProtocolNegotiated):
            self._handle_protocol_negotiated(event)
    
    def _handle_connection_terminated(self, event):
        """处理连接终止事件"""
        logger.info(f"QUIC连接终止: {event}")
    
    def _handle_stream_data_received(self, event):
        """处理流数据接收事件"""
        if self._h3:
            h3_events = self._h3.receive_data(event.data, event.stream_ended)
            for h3_event in h3_events:
                pass
    
    def _handle_protocol_negotiated(self, event):
        """处理协议协商事件"""
        if event.alpn_protocol in H3_ALPN:
            from aioquic.h3.connection import H3Connection
            self._h3 = H3Connection(self._quic, event.alpn_protocol)
            logger.info(f"HTTP/3协议协商成功: {event.alpn_protocol}")
