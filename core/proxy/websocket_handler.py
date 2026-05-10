"""
WebSocket处理器模块
基于20年渗透测试经验的专业级WebSocket流量处理
支持WebSocket连接拦截、修改、重放等功能
"""

import asyncio
import struct
import base64
import hashlib
import logging
from typing import Dict, List, Optional, Callable
from dataclasses import dataclass
from datetime import datetime

logger = logging.getLogger(__name__)


@dataclass
class WebSocketFrame:
    """WebSocket帧数据类"""
    opcode: int
    fin: bool
    rsv1: bool
    rsv2: bool
    rsv3: bool
    payload: bytes
    masked: bool
    timestamp: datetime
    
    def to_dict(self) -> Dict:
        """转换为字典格式"""
        opcode_names = {
            0: 'CONTINUATION',
            1: 'TEXT',
            2: 'BINARY',
            8: 'CLOSE',
            9: 'PING',
            10: 'PONG'
        }
        return {
            'opcode': opcode_names.get(self.opcode, f'UNKNOWN({self.opcode})'),
            'fin': self.fin,
            'rsv1': self.rsv1,
            'rsv2': self.rsv2,
            'rsv3': self.rsv3,
            'payload': self._decode_payload(),
            'masked': self.masked,
            'timestamp': self.timestamp.isoformat()
        }
    
    def _decode_payload(self) -> str:
        """解码payload"""
        try:
            if self.opcode in [1, 8, 9, 10]:
                return self.payload.decode('utf-8', errors='ignore')
            return base64.b64encode(self.payload).decode('utf-8')
        except:
            return base64.b64encode(self.payload).decode('utf-8')


@dataclass
class WebSocketConnection:
    """WebSocket连接数据类"""
    id: str
    host: str
    port: int
    path: str
    upgrade_request: Dict
    upgrade_response: Dict
    client_reader: asyncio.StreamReader
    client_writer: asyncio.StreamWriter
    server_reader: asyncio.StreamReader
    server_writer: asyncio.StreamWriter
    frames: List[WebSocketFrame]
    is_closed: bool
    timestamp: datetime


class WebSocketHandler:
    """专业级WebSocket处理器"""
    
    def __init__(self):
        self.connections: Dict[str, WebSocketConnection] = {}
        self.frame_history: List[WebSocketFrame] = []
        
        # 回调函数
        self.on_frame_intercept: Optional[Callable] = None
        self.on_frame_log: Optional[Callable] = None
        self.on_connection_open: Optional[Callable] = None
        self.on_connection_close: Optional[Callable] = None
        
        logger.info("专业级WebSocket处理器初始化完成")
    
    async def handle_websocket_upgrade(self, request, reader, writer):
        """处理WebSocket升级请求"""
        try:
            # 解析WebSocket握手信息
            websocket_key = request.headers.get('Sec-WebSocket-Key', '')
            host, port = self._extract_host_port(request.url, 80)
            
            # 连接到目标服务器
            server_reader, server_writer = await asyncio.open_connection(host, port)
            
            # 转发升级请求
            await self._forward_websocket_request(request, server_writer)
            
            # 读取升级响应
            response = await self._read_websocket_response(server_reader)
            
            # 转发升级响应给客户端
            await self._forward_websocket_response(response, writer)
            
            # 如果升级成功，建立双向通道
            if response.get('status_code') == 101:
                connection_id = self._generate_connection_id()
                connection = WebSocketConnection(
                    id=connection_id,
                    host=host,
                    port=port,
                    path=request.url,
                    upgrade_request=request.to_dict(),
                    upgrade_response=response,
                    client_reader=reader,
                    client_writer=writer,
                    server_reader=server_reader,
                    server_writer=server_writer,
                    frames=[],
                    is_closed=False,
                    timestamp=datetime.now()
                )
                self.connections[connection_id] = connection
                
                if self.on_connection_open:
                    self.on_connection_open(connection)
                
                logger.info(f"WebSocket连接建立成功: {host}{request.url}")
                
                # 启动双向数据转发
                await self._relay_websocket_traffic(connection)
            
        except Exception as e:
            logger.error(f"处理WebSocket升级失败: {e}")
    
    async def _relay_websocket_traffic(self, connection: WebSocketConnection):
        """转发WebSocket流量"""
        try:
            client_task = asyncio.create_task(
                self._client_to_server(connection)
            )
            server_task = asyncio.create_task(
                self._server_to_client(connection)
            )
            
            await asyncio.gather(client_task, server_task)
            
        except Exception as e:
            logger.error(f"WebSocket流量转发失败: {e}")
        finally:
            connection.is_closed = True
            if self.on_connection_close:
                self.on_connection_close(connection)
            if connection.id in self.connections:
                del self.connections[connection.id]
    
    async def _client_to_server(self, connection: WebSocketConnection):
        """从客户端转发到服务器"""
        try:
            while not connection.is_closed:
                frame = await self._read_websocket_frame(connection.client_reader)
                if frame is None:
                    break
                
                connection.frames.append(frame)
                self.frame_history.append(frame)
                
                if self.on_frame_log:
                    self.on_frame_log(frame, 'client')
                
                if self.on_frame_intercept:
                    modified_frame = await self.on_frame_intercept(frame, 'client')
                    if modified_frame:
                        frame = modified_frame
                
                await self._write_websocket_frame(frame, connection.server_writer, masked=False)
                
        except Exception as e:
            logger.error(f"客户端到服务器转发失败: {e}")
    
    async def _server_to_client(self, connection: WebSocketConnection):
        """从服务器转发到客户端"""
        try:
            while not connection.is_closed:
                frame = await self._read_websocket_frame(connection.server_reader)
                if frame is None:
                    break
                
                connection.frames.append(frame)
                self.frame_history.append(frame)
                
                if self.on_frame_log:
                    self.on_frame_log(frame, 'server')
                
                if self.on_frame_intercept:
                    modified_frame = await self.on_frame_intercept(frame, 'server')
                    if modified_frame:
                        frame = modified_frame
                
                await self._write_websocket_frame(frame, connection.client_writer, masked=False)
                
        except Exception as e:
            logger.error(f"服务器到客户端转发失败: {e}")
    
    async def _read_websocket_frame(self, reader: asyncio.StreamReader) -> Optional[WebSocketFrame]:
        """读取WebSocket帧"""
        try:
            header = await reader.read(2)
            if len(header) < 2:
                return None
            
            byte1, byte2 = struct.unpack('BB', header)
            
            fin = bool(byte1 & 0x80)
            rsv1 = bool(byte1 & 0x40)
            rsv2 = bool(byte1 & 0x20)
            rsv3 = bool(byte1 & 0x10)
            opcode = byte1 & 0x0F
            
            masked = bool(byte2 & 0x80)
            payload_length = byte2 & 0x7F
            
            if payload_length == 126:
                length_data = await reader.read(2)
                payload_length = struct.unpack('!H', length_data)[0]
            elif payload_length == 127:
                length_data = await reader.read(8)
                payload_length = struct.unpack('!Q', length_data)[0]
            
            mask_key = b''
            if masked:
                mask_key = await reader.read(4)
            
            payload = await reader.read(payload_length)
            
            if masked:
                payload = bytes([b ^ mask_key[i % 4] for i, b in enumerate(payload)])
            
            return WebSocketFrame(
                opcode=opcode,
                fin=fin,
                rsv1=rsv1,
                rsv2=rsv2,
                rsv3=rsv3,
                payload=payload,
                masked=masked,
                timestamp=datetime.now()
            )
            
        except Exception as e:
            logger.error(f"读取WebSocket帧失败: {e}")
            return None
    
    async def _write_websocket_frame(self, frame: WebSocketFrame, writer: asyncio.StreamWriter, masked: bool = False):
        """写入WebSocket帧"""
        try:
            byte1 = 0
            if frame.fin:
                byte1 |= 0x80
            if frame.rsv1:
                byte1 |= 0x40
            if frame.rsv2:
                byte1 |= 0x20
            if frame.rsv3:
                byte1 |= 0x10
            byte1 |= frame.opcode & 0x0F
            
            byte2 = 0
            if masked:
                byte2 |= 0x80
            
            payload_length = len(frame.payload)
            
            if payload_length <= 125:
                byte2 |= payload_length
                header = struct.pack('BB', byte1, byte2)
            elif payload_length <= 65535:
                byte2 |= 126
                header = struct.pack('!BBH', byte1, byte2, payload_length)
            else:
                byte2 |= 127
                header = struct.pack('!BBQ', byte1, byte2, payload_length)
            
            writer.write(header)
            
            if masked:
                import os
                mask_key = os.urandom(4)
                writer.write(mask_key)
                masked_payload = bytes([b ^ mask_key[i % 4] for i, b in enumerate(frame.payload)])
                writer.write(masked_payload)
            else:
                writer.write(frame.payload)
            
            await writer.drain()
            
        except Exception as e:
            logger.error(f"写入WebSocket帧失败: {e}")
    
    async def _forward_websocket_request(self, request, writer):
        """转发WebSocket升级请求"""
        request_line = f"{request.method} {request.url} HTTP/1.1\r\n"
        writer.write(request_line.encode())
        
        for key, value in request.headers.items():
            header_line = f"{key}: {value}\r\n"
            writer.write(header_line.encode())
        
        writer.write(b"\r\n")
        if request.body:
            writer.write(request.body)
        
        await writer.drain()
    
    async def _read_websocket_response(self, reader):
        """读取WebSocket升级响应"""
        status_line = await reader.readline()
        status_parts = status_line.decode().strip().split(' ', 2)
        status_code = int(status_parts[1]) if len(status_parts) >= 2 else 500
        
        headers = await self._read_headers(reader)
        
        return {
            'status_code': status_code,
            'headers': headers
        }
    
    async def _forward_websocket_response(self, response, writer):
        """转发WebSocket升级响应"""
        status_line = f"HTTP/1.1 {response['status_code']} Switching Protocols\r\n"
        writer.write(status_line.encode())
        
        for key, value in response['headers'].items():
            header_line = f"{key}: {value}\r\n"
            writer.write(header_line.encode())
        
        writer.write(b"\r\n")
        await writer.drain()
    
    async def _read_headers(self, reader):
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
    
    def _extract_host_port(self, url, default_port):
        """从URL中提取主机和端口"""
        if url.startswith('http://'):
            url = url[7:]
        elif url.startswith('https://'):
            url = url[8:]
        elif url.startswith('ws://'):
            url = url[5:]
        elif url.startswith('wss://'):
            url = url[6:]
        
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
    
    def _generate_connection_id(self):
        """生成连接ID"""
        import uuid
        return str(uuid.uuid4())
    
    async def replay_frame(self, frame: WebSocketFrame, target_host: str, target_port: int):
        """重放WebSocket帧"""
        try:
            reader, writer = await asyncio.open_connection(target_host, target_port)
            
            await self._write_websocket_frame(frame, writer, masked=True)
            
            writer.close()
            await writer.wait_closed()
            
            logger.info(f"WebSocket帧重放成功: {target_host}:{target_port}")
            return True
            
        except Exception as e:
            logger.error(f"WebSocket帧重放失败: {e}")
            return False
    
    def get_active_connections(self) -> List[Dict]:
        """获取活动连接列表"""
        return [
            {
                'id': conn.id,
                'host': conn.host,
                'port': conn.port,
                'path': conn.path,
                'frame_count': len(conn.frames),
                'timestamp': conn.timestamp.isoformat()
            }
            for conn in self.connections.values()
        ]
    
    def get_frame_history(self, limit: int = 100) -> List[Dict]:
        """获取帧历史记录"""
        recent_frames = self.frame_history[-limit:]
        return [frame.to_dict() for frame in recent_frames]
    
    def clear_frame_history(self):
        """清空帧历史记录"""
        self.frame_history.clear()
        logger.info("WebSocket帧历史记录已清空")
    
    def set_frame_intercept_callback(self, callback: Callable):
        """设置帧拦截回调"""
        self.on_frame_intercept = callback
    
    def set_frame_log_callback(self, callback: Callable):
        """设置帧日志回调"""
        self.on_frame_log = callback
    
    def set_connection_open_callback(self, callback: Callable):
        """设置连接打开回调"""
        self.on_connection_open = callback
    
    def set_connection_close_callback(self, callback: Callable):
        """设置连接关闭回调"""
        self.on_connection_close = callback
