"""
性能优化与资源管理模块
包含UDP连接池、帧批处理、内存零拷贝优化、协议处理并发控制等功能
"""

import logging
import time
import asyncio
from typing import Dict, List, Optional, Tuple, Any, Callable
from dataclasses import dataclass, field
from collections import defaultdict, deque
from enum import Enum
import threading
import queue

logger = logging.getLogger(__name__)


class ConnectionType(Enum):
    """连接类型"""
    TCP = "tcp"
    UDP = "udp"
    QUIC = "quic"


@dataclass
class ConnectionPoolStats:
    """连接池统计"""
    total_connections: int = 0
    active_connections: int = 0
    idle_connections: int = 0
    total_created: int = 0
    total_reused: int = 0
    total_closed: int = 0
    reuse_rate: float = 0.0


@dataclass
class FrameBatch:
    """帧批次"""
    frames: List[bytes] = field(default_factory=list)
    total_size: int = 0
    max_size: int = 16384
    max_count: int = 10
    created_at: float = 0.0
    
    def can_add(self, frame: bytes) -> bool:
        """判断是否可以添加帧"""
        return (len(self.frames) < self.max_count and 
                self.total_size + len(frame) <= self.max_size)
    
    def add(self, frame: bytes):
        """添加帧"""
        self.frames.append(frame)
        self.total_size += len(frame)
    
    def is_full(self) -> bool:
        """判断是否已满"""
        return len(self.frames) >= self.max_count or self.total_size >= self.max_size
    
    def clear(self) -> List[bytes]:
        """清空并返回所有帧"""
        frames = list(self.frames)
        self.frames.clear()
        self.total_size = 0
        self.created_at = time.time()
        return frames


class ZeroCopyBuffer:
    """零拷贝缓冲区"""
    
    def __init__(self, initial_size: int = 65536):
        self._buffer = bytearray(initial_size)
        self._read_pos = 0
        self._write_pos = 0
        self._lock = threading.Lock()
    
    def write(self, data: bytes) -> int:
        """写入数据"""
        with self._lock:
            available = len(self._buffer) - self._write_pos
            if available < len(data):
                self._expand_buffer(len(data) - available)
            
            self._buffer[self._write_pos:self._write_pos + len(data)] = data
            self._write_pos += len(data)
            return len(data)
    
    def read(self, size: int) -> bytes:
        """读取数据"""
        with self._lock:
            available = self._write_pos - self._read_pos
            read_size = min(size, available)
            
            if read_size == 0:
                return b''
            
            data = bytes(self._buffer[self._read_pos:self._read_pos + read_size])
            self._read_pos += read_size
            return data
    
    def peek(self, size: int) -> bytes:
        """预览数据（不移动读指针）"""
        with self._lock:
            available = self._write_pos - self._read_pos
            peek_size = min(size, available)
            return bytes(self._buffer[self._read_pos:self._read_pos + peek_size])
    
    def discard(self, size: int):
        """丢弃数据"""
        with self._lock:
            available = self._write_pos - self._read_pos
            discard_size = min(size, available)
            self._read_pos += discard_size
    
    def compact(self):
        """压缩缓冲区"""
        with self._lock:
            if self._read_pos > 0:
                used = self._write_pos - self._read_pos
                if used > 0:
                    self._buffer[:used] = self._buffer[self._read_pos:self._write_pos]
                self._write_pos = used
                self._read_pos = 0
    
    def _expand_buffer(self, needed: int):
        """扩展缓冲区"""
        new_size = max(len(self._buffer) * 2, len(self._buffer) + needed)
        new_buffer = bytearray(new_size)
        new_buffer[:self._write_pos - self._read_pos] = self._buffer[self._read_pos:self._write_pos]
        self._write_pos -= self._read_pos
        self._read_pos = 0
        self._buffer = new_buffer
    
    @property
    def available_data(self) -> int:
        """可用数据大小"""
        return self._write_pos - self._read_pos
    
    @property
    def capacity(self) -> int:
        """总容量"""
        return len(self._buffer)


class UDPConnectionPool:
    """UDP连接池（用于QUIC）"""
    
    def __init__(self, max_connections: int = 50, 
                 idle_timeout: float = 300.0,
                 max_reuse_count: int = 1000):
        self._max_connections = max_connections
        self._idle_timeout = idle_timeout
        self._max_reuse_count = max_reuse_count
        
        self._connections: Dict[str, Dict[str, Any]] = {}
        self._idle_queue: deque = deque()
        self._lock = threading.Lock()
        
        self._stats = ConnectionPoolStats()
        self._stats_lock = threading.Lock()
    
    def acquire(self, host: str, port: int) -> Optional[Any]:
        """获取连接"""
        key = f"{host}:{port}"
        
        with self._lock:
            if key in self._connections:
                conn = self._connections[key]
                if not self._is_expired(conn):
                    conn['last_used'] = time.time()
                    conn['reuse_count'] += 1
                    
                    with self._stats_lock:
                        self._stats.total_reused += 1
                        self._stats.active_connections += 1
                    
                    logger.debug(f"连接复用: {key}")
                    return conn.get('connection')
                else:
                    self._remove_connection(key)
        
        if self._stats.total_connections >= self._max_connections:
            self._evict_idle()
        
        return None
    
    def release(self, host: str, port: int, connection: Any):
        """释放连接"""
        key = f"{host}:{port}"
        
        with self._lock:
            if key not in self._connections:
                self._add_connection(key, connection)
            else:
                self._connections[key]['last_used'] = time.time()
                self._connections[key]['connection'] = connection
    
    def _add_connection(self, key: str, connection: Any):
        """添加连接"""
        self._connections[key] = {
            'connection': connection,
            'created_at': time.time(),
            'last_used': time.time(),
            'reuse_count': 0,
        }
        
        with self._stats_lock:
            self._stats.total_connections += 1
            self._stats.total_created += 1
            self._stats.active_connections += 1
    
    def _remove_connection(self, key: str):
        """移除连接"""
        if key in self._connections:
            del self._connections[key]
            
            with self._stats_lock:
                self._stats.total_connections -= 1
                self._stats.total_closed += 1
                self._stats.active_connections = max(0, self._stats.active_connections - 1)
    
    def _is_expired(self, conn: Dict[str, Any]) -> bool:
        """判断连接是否过期"""
        now = time.time()
        return (now - conn['last_used'] > self._idle_timeout or 
                conn['reuse_count'] >= self._max_reuse_count)
    
    def _evict_idle(self):
        """驱逐空闲连接"""
        now = time.time()
        to_remove = []
        
        for key, conn in self._connections.items():
            if self._is_expired(conn):
                to_remove.append(key)
        
        for key in to_remove:
            self._remove_connection(key)
    
    def get_stats(self) -> ConnectionPoolStats:
        """获取统计信息"""
        with self._stats_lock:
            stats = ConnectionPoolStats(
                total_connections=self._stats.total_connections,
                active_connections=self._stats.active_connections,
                idle_connections=self._stats.total_connections - self._stats.active_connections,
                total_created=self._stats.total_created,
                total_reused=self._stats.total_reused,
                total_closed=self._stats.total_closed,
            )
            if stats.total_created > 0:
                stats.reuse_rate = stats.total_reused / stats.total_created
            return stats
    
    def close_all(self):
        """关闭所有连接"""
        with self._lock:
            self._connections.clear()
        
        with self._stats_lock:
            self._stats.total_closed += self._stats.total_connections
            self._stats.total_connections = 0
            self._stats.active_connections = 0


class FrameBatchProcessor:
    """帧批处理器"""
    
    def __init__(self, max_batch_size: int = 16384,
                 max_frame_count: int = 10,
                 flush_interval: float = 0.01):
        self._max_batch_size = max_batch_size
        self._max_frame_count = max_frame_count
        self._flush_interval = flush_interval
        
        self._batches: Dict[str, FrameBatch] = {}
        self._lock = threading.Lock()
        
        self._flush_callback: Optional[Callable] = None
        
        self._stats = {
            'total_frames': 0,
            'total_batches': 0,
            'total_bytes': 0,
            'avg_batch_size': 0.0,
        }
        self._stats_lock = threading.Lock()
    
    def set_flush_callback(self, callback: Callable):
        """设置刷新回调"""
        self._flush_callback = callback
    
    def add_frame(self, connection_id: str, frame: bytes):
        """添加帧"""
        with self._lock:
            if connection_id not in self._batches:
                self._batches[connection_id] = FrameBatch(
                    max_size=self._max_batch_size,
                    max_count=self._max_frame_count,
                    created_at=time.time()
                )
            
            batch = self._batches[connection_id]
            
            if batch.can_add(frame):
                batch.add(frame)
            else:
                self._flush_batch(connection_id)
                self._batches[connection_id] = FrameBatch(
                    max_size=self._max_batch_size,
                    max_count=self._max_frame_count,
                    created_at=time.time()
                )
                self._batches[connection_id].add(frame)
            
            with self._stats_lock:
                self._stats['total_frames'] += 1
                self._stats['total_bytes'] += len(frame)
    
    def flush_all(self):
        """刷新所有批次"""
        with self._lock:
            for conn_id in list(self._batches.keys()):
                self._flush_batch(conn_id)
    
    def _flush_batch(self, connection_id: str):
        """刷新批次"""
        if connection_id in self._batches:
            batch = self._batches[connection_id]
            if batch.frames:
                frames = batch.clear()
                
                with self._stats_lock:
                    self._stats['total_batches'] += 1
                
                if self._flush_callback:
                    try:
                        self._flush_callback(connection_id, frames)
                    except Exception as e:
                        logger.error(f"帧刷新回调失败: {e}")
    
    def get_stats(self) -> Dict[str, Any]:
        """获取统计信息"""
        with self._stats_lock:
            stats = dict(self._stats)
            if stats['total_batches'] > 0:
                stats['avg_batch_size'] = stats['total_bytes'] / stats['total_batches']
            return stats


class ConcurrencyController:
    """并发控制器"""
    
    def __init__(self, max_http2_streams: int = 100,
                 max_quic_connections: int = 50,
                 queue_size: int = 1000):
        self._max_http2_streams = max_http2_streams
        self._max_quic_connections = max_quic_connections
        self._queue_size = queue_size
        
        self._active_http2_streams = 0
        self._active_quic_connections = 0
        self._lock = threading.Lock()
        
        self._http2_queue: queue.Queue = queue.Queue(maxsize=queue_size)
        self._quic_queue: queue.Queue = queue.Queue(maxsize=queue_size)
        
        self._stats = {
            'total_streams_queued': 0,
            'total_connections_queued': 0,
            'total_streams_rejected': 0,
            'total_connections_rejected': 0,
        }
        self._stats_lock = threading.Lock()
    
    def try_acquire_http2_stream(self) -> bool:
        """尝试获取HTTP/2流"""
        with self._lock:
            if self._active_http2_streams < self._max_http2_streams:
                self._active_http2_streams += 1
                return True
            
            try:
                self._http2_queue.put_nowait(1)
                with self._stats_lock:
                    self._stats['total_streams_queued'] += 1
                return False
            except queue.Full:
                with self._stats_lock:
                    self._stats['total_streams_rejected'] += 1
                return False
    
    def release_http2_stream(self):
        """释放HTTP/2流"""
        with self._lock:
            self._active_http2_streams = max(0, self._active_http2_streams - 1)
            
            try:
                self._http2_queue.get_nowait()
            except queue.Empty:
                pass
    
    def try_acquire_quic_connection(self) -> bool:
        """尝试获取QUIC连接"""
        with self._lock:
            if self._active_quic_connections < self._max_quic_connections:
                self._active_quic_connections += 1
                return True
            
            try:
                self._quic_queue.put_nowait(1)
                with self._stats_lock:
                    self._stats['total_connections_queued'] += 1
                return False
            except queue.Full:
                with self._stats_lock:
                    self._stats['total_connections_rejected'] += 1
                return False
    
    def release_quic_connection(self):
        """释放QUIC连接"""
        with self._lock:
            self._active_quic_connections = max(0, self._active_quic_connections - 1)
            
            try:
                self._quic_queue.get_nowait()
            except queue.Empty:
                pass
    
    def get_active_http2_streams(self) -> int:
        """获取活跃HTTP/2流数"""
        with self._lock:
            return self._active_http2_streams
    
    def get_active_quic_connections(self) -> int:
        """获取活跃QUIC连接数"""
        with self._lock:
            return self._active_quic_connections
    
    def get_stats(self) -> Dict[str, Any]:
        """获取统计信息"""
        with self._stats_lock:
            stats = dict(self._stats)
        
        with self._lock:
            stats['active_http2_streams'] = self._active_http2_streams
            stats['active_quic_connections'] = self._active_quic_connections
            stats['http2_queue_size'] = self._http2_queue.qsize()
            stats['quic_queue_size'] = self._quic_queue.qsize()
        
        return stats


class PerformanceOptimizer:
    """性能优化器"""
    
    def __init__(self,
                 max_http2_streams: int = 100,
                 max_quic_connections: int = 50,
                 enable_frame_batching: bool = True,
                 enable_zero_copy: bool = True):
        self._udp_pool = UDPConnectionPool(max_connections=max_quic_connections)
        self._frame_processor = FrameBatchProcessor() if enable_frame_batching else None
        self._concurrency = ConcurrencyController(
            max_http2_streams=max_http2_streams,
            max_quic_connections=max_quic_connections
        )
        self._zero_copy_enabled = enable_zero_copy
        
        self._zero_copy_buffers: Dict[str, ZeroCopyBuffer] = {}
        self._buffer_lock = threading.Lock()
        
        self._stats = {
            'zero_copy_allocations': 0,
            'zero_copy_bytes_saved': 0,
        }
        self._stats_lock = threading.Lock()
    
    def get_udp_pool(self) -> UDPConnectionPool:
        """获取UDP连接池"""
        return self._udp_pool
    
    def get_frame_processor(self) -> Optional[FrameBatchProcessor]:
        """获取帧处理器"""
        return self._frame_processor
    
    def get_concurrency_controller(self) -> ConcurrencyController:
        """获取并发控制器"""
        return self._concurrency
    
    def get_zero_copy_buffer(self, stream_id: str) -> ZeroCopyBuffer:
        """获取零拷贝缓冲区"""
        with self._buffer_lock:
            if stream_id not in self._zero_copy_buffers:
                self._zero_copy_buffers[stream_id] = ZeroCopyBuffer()
                with self._stats_lock:
                    self._stats['zero_copy_allocations'] += 1
            return self._zero_copy_buffers[stream_id]
    
    def release_zero_copy_buffer(self, stream_id: str):
        """释放零拷贝缓冲区"""
        with self._buffer_lock:
            if stream_id in self._zero_copy_buffers:
                buffer = self._zero_copy_buffers[stream_id]
                with self._stats_lock:
                    self._stats['zero_copy_bytes_saved'] += buffer.available_data
                del self._zero_copy_buffers[stream_id]
    
    def get_stats(self) -> Dict[str, Any]:
        """获取统计信息"""
        stats = {
            'udp_pool': self._udp_pool.get_stats().__dict__,
            'concurrency': self._concurrency.get_stats(),
        }
        
        if self._frame_processor:
            stats['frame_batching'] = self._frame_processor.get_stats()
        
        with self._stats_lock:
            stats['zero_copy'] = dict(self._stats)
        
        stats['zero_copy_enabled'] = self._zero_copy_enabled
        
        return stats
    
    def cleanup(self):
        """清理资源"""
        self._udp_pool.close_all()
        
        if self._frame_processor:
            self._frame_processor.flush_all()
        
        with self._buffer_lock:
            self._zero_copy_buffers.clear()
