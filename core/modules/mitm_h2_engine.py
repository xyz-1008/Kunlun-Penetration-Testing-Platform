"""
HTTP/2协议处理引擎
支持h2（HTTP/2 over TLS）和h2c（HTTP/2明文）代理
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
    from h2.connection import H2Connection
    from h2.events import (
        RequestReceived, ResponseReceived, DataReceived,
        StreamEnded, StreamReset, SettingsAcknowledged,
        PushPromiseReceived, WindowUpdated
    )
    from h2.settings import SettingCodes
    from h2.errors import ErrorCodes
    from h2.exceptions import ProtocolError, FlowControlError
    H2_AVAILABLE = True
except ImportError:
    H2_AVAILABLE = False

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .mitm_proxy_engine import MITMRequest, MITMResponse, CertificateManager

logger = logging.getLogger(__name__)


class H2Protocol(Enum):
    """HTTP/2协议类型"""
    H2 = "h2"  # HTTP/2 over TLS
    H2C = "h2c"  # HTTP/2 cleartext
    HTTP1 = "http/1.1"  # HTTP/1.1


@dataclass
class H2Stream:
    """HTTP/2流信息"""
    stream_id: int
    request: "MITMRequest" = None  # type: ignore
    response: "MITMResponse" = None  # type: ignore
    request_headers: List[Tuple[str, str]] = field(default_factory=list)
    response_headers: List[Tuple[str, str]] = field(default_factory=list)
    request_body: bytes = b""
    response_body: bytes = b""
    is_push_promise: bool = False
    parent_stream_id: Optional[int] = None
    timestamp: datetime = field(default_factory=datetime.utcnow)
    state: str = "idle"


class H2ProxyEngine:
    """HTTP/2代理引擎"""
    
    def __init__(self, cert_manager = None):
        if cert_manager is None:
            from .mitm_proxy_engine import CertificateManager
            cert_manager = CertificateManager()
        
        self.cert_manager = cert_manager
        self._running = False
        self._connections: Dict[str, H2Connection] = {}
        self._streams: Dict[int, H2Stream] = {}
        self._connection_lock = threading.Lock()
        
        self._callbacks: Dict[str, List[Callable]] = {
            'on_request': [],
            'on_response': [],
            'on_push_promise': [],
            'on_error': [],
        }
        
        self._request_history: List[MITMRequest] = []
        self._response_history: List[MITMResponse] = []
        
        self._max_concurrent_streams = 100
        self._active_streams = 0
        self._flow_control_window = 65535
        
        if not H2_AVAILABLE:
            logger.warning("h2库未安装，HTTP/2功能不可用")
    
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
    
    async def handle_h2_connection(self, reader: asyncio.StreamReader, 
                                    writer: asyncio.StreamWriter,
                                    client_ip: str):
        """处理HTTP/2连接"""
        if not H2_AVAILABLE:
            logger.error("h2库未安装")
            return
        
        conn = H2Connection()
        connection_id = f"{client_ip}:{id(conn)}"
        
        try:
            # 初始化HTTP/2连接
            conn.initiate_connection()
            writer.write(conn.data_to_send())
            await writer.drain()
            
            with self._connection_lock:
                self._connections[connection_id] = conn
            
            logger.info(f"HTTP/2连接建立: {connection_id}")
            
            # 处理HTTP/2帧
            while True:
                data = await reader.read(4096)
                if not data:
                    break
                
                try:
                    events = conn.receive_data(data)
                    writer.write(conn.data_to_send())
                    await writer.drain()
                    
                    for event in events:
                        await self._handle_h2_event(event, conn, reader, writer, connection_id)
                
                except ProtocolError as e:
                    logger.error(f"HTTP/2协议错误: {e}")
                    break
                except FlowControlError as e:
                    logger.error(f"HTTP/2流控错误: {e}")
                    break
            
        except Exception as e:
            logger.error(f"HTTP/2连接处理失败: {e}")
            self._notify_callbacks('on_error', connection_id, str(e))
        finally:
            with self._connection_lock:
                self._connections.pop(connection_id, None)
            writer.close()
            await writer.wait_closed()
            logger.info(f"HTTP/2连接关闭: {connection_id}")
    
    async def _handle_h2_event(self, event, conn,
                               reader,
                               writer,
                               connection_id):
        """处理HTTP/2事件"""
        if isinstance(event, RequestReceived):
            await self._handle_request_received(event, conn, writer)
        elif isinstance(event, ResponseReceived):
            await self._handle_response_received(event, conn)
        elif isinstance(event, DataReceived):
            await self._handle_data_received(event, conn, writer)
        elif isinstance(event, StreamEnded):
            await self._handle_stream_ended(event, conn)
        elif isinstance(event, PushPromiseReceived):
            await self._handle_push_promise(event, conn)
        elif isinstance(event, WindowUpdated):
            await self._handle_window_updated(event, conn)
        elif isinstance(event, SettingsAcknowledged):
            logger.debug("HTTP/2设置已确认")
    
    async def _handle_request_received(self, event,
                                       conn,
                                       writer):
        """处理请求接收事件"""
        stream_id = event.stream_id
        
        # 创建流对象
        stream = H2Stream(stream_id=stream_id)
        stream.state = "open"
        stream.request_headers = event.headers
        
        with self._connection_lock:
            self._streams[stream_id] = stream
            self._active_streams += 1
        
        # 解析HTTP/2伪头部
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
            protocol="HTTP/2",
            is_https=True,
            client_ip=writer.get_extra_info('peername')[0] if writer.get_extra_info('peername') else ""
        )
        
        stream.request = request
        
        # 通知回调
        self._notify_callbacks('on_request', request)
        self._request_history.append(request)
        
        logger.debug(f"HTTP/2请求接收: {method} {url} (stream {stream_id})")
    
    async def _handle_response_received(self, event,
                                        conn):
        """处理响应接收事件"""
        stream_id = event.stream_id
        stream = self._streams.get(stream_id)
        
        if not stream:
            logger.warning(f"未找到流: {stream_id}")
            return
        
        stream.response_headers = event.headers
        
        # 解析响应头部
        headers_dict = {}
        status_code = 200
        
        for name, value in event.headers:
            if name == ':status':
                status_code = int(value)
            else:
                headers_dict[name] = value
        
        # 创建MITMResponse对象
        response_id = hashlib.md5(
            f"{datetime.utcnow().isoformat()}{stream_id}".encode()
        ).hexdigest()[:12]
        
        response = MITMResponse(
            id=response_id,
            request_id=stream.request.id if stream.request else "",
            timestamp=datetime.utcnow(),
            status_code=status_code,
            reason="",
            headers=headers_dict,
            body=b"",
            protocol="HTTP/2"
        )
        
        stream.response = response
        
        # 通知回调
        self._notify_callbacks('on_response', response)
        self._response_history.append(response)
        
        logger.debug(f"HTTP/2响应接收: {status_code} (stream {stream_id})")
    
    async def _handle_data_received(self, event,
                                    conn,
                                    writer):
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
        
        # 更新流控窗口
        conn.acknowledge_received_data(len(event.data), stream_id)
        writer.write(conn.data_to_send())
        await writer.drain()
    
    async def _handle_stream_ended(self, event,
                                   conn):
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
        
        # 清理流
        with self._connection_lock:
            self._streams.pop(stream_id, None)
            self._active_streams -= 1
        
        logger.debug(f"HTTP/2流结束: {stream_id}")
    
    async def _handle_push_promise(self, event,
                                   conn):
        """处理服务器推送承诺事件"""
        stream_id = event.pushed_stream_id
        parent_stream_id = event.stream_id
        
        # 创建推送流
        stream = H2Stream(
            stream_id=stream_id,
            is_push_promise=True,
            parent_stream_id=parent_stream_id
        )
        stream.request_headers = event.headers
        
        with self._connection_lock:
            self._streams[stream_id] = stream
        
        # 解析推送资源信息
        headers_dict = {}
        for name, value in event.headers:
            if not name.startswith(':'):
                headers_dict[name] = value
        
        logger.info(f"HTTP/2服务器推送: stream {stream_id} (parent: {parent_stream_id})")
        
        # 通知回调
        self._notify_callbacks('on_push_promise', stream_id, parent_stream_id, headers_dict)
    
    async def _handle_window_updated(self, event,
                                     conn):
        """处理窗口更新事件"""
        stream_id = event.stream_id
        logger.debug(f"HTTP/2窗口更新: stream {stream_id}, delta: {event.delta}")
    
    def create_h2_request(self, request) -> List[Tuple[str, str]]:
        """创建HTTP/2请求头部"""
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
    
    def create_h2_response(self, response) -> List[Tuple[str, str]]:
        """创建HTTP/2响应头部"""
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
    
    def drop_push_promise(self, stream_id: int) -> bool:
        """丢弃服务器推送"""
        stream = self._streams.get(stream_id)
        if not stream or not stream.is_push_promise:
            return False
        
        stream.state = "closed"
        with self._connection_lock:
            self._streams.pop(stream_id, None)
        
        logger.info(f"丢弃服务器推送: stream {stream_id}")
        return True
    
    def get_stream_info(self, stream_id: int) -> Optional[Dict[str, Any]]:
        """获取流信息"""
        stream = self._streams.get(stream_id)
        if not stream:
            return None
        
        return {
            'stream_id': stream.stream_id,
            'state': stream.state,
            'is_push_promise': stream.is_push_promise,
            'parent_stream_id': stream.parent_stream_id,
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
            'flow_control_window': self._flow_control_window,
        }
    
    def cleanup(self):
        """清理资源"""
        with self._connection_lock:
            self._connections.clear()
            self._streams.clear()
            self._active_streams = 0
        
        self._request_history.clear()
        self._response_history.clear()
        
        logger.info("HTTP/2代理引擎已清理")
