"""
HTTP/2高级特性模块
包含流优先级处理、HPACK动态表管理、窗口动态调整、连接合并等高级功能
"""

import logging
import time
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from collections import defaultdict
from enum import Enum
import threading

logger = logging.getLogger(__name__)


class StreamPriority:
    """HTTP/2流优先级"""
    HIGHEST = 0
    HIGH = 32
    MEDIUM = 128
    LOW = 192
    LOWEST = 255


@dataclass
class PriorityNode:
    """优先级树节点"""
    stream_id: int
    weight: int = 16  # 1-256
    parent_stream_id: Optional[int] = None
    exclusive: bool = False
    children: List[int] = field(default_factory=list)
    
    def get_effective_priority(self) -> int:
        """获取有效优先级"""
        if self.parent_stream_id is None:
            return self.weight
        return self.weight // 2


@dataclass
class HPACKStats:
    """HPACK统计信息"""
    total_headers_compressed: int = 0
    total_headers_decompressed: int = 0
    compression_ratio: float = 1.0
    dynamic_table_size: int = 4096
    max_dynamic_table_size: int = 4096
    entries_count: int = 0


class H2AdvancedFeatures:
    """HTTP/2高级特性管理器"""
    
    def __init__(self, 
                 max_concurrent_streams: int = 100,
                 initial_window_size: int = 65535,
                 max_frame_size: int = 16384,
                 enable_connection_coalescing: bool = True):
        self._max_concurrent_streams = max_concurrent_streams
        self._initial_window_size = initial_window_size
        self._max_frame_size = max_frame_size
        self._enable_connection_coalescing = enable_connection_coalescing
        
        # 流优先级管理
        self._priority_tree: Dict[int, PriorityNode] = {}
        self._priority_lock = threading.Lock()
        
        # HPACK动态表管理
        self._hpack_stats = HPACKStats()
        self._hpack_lock = threading.Lock()
        self._dynamic_table: List[Tuple[str, str]] = []
        self._dynamic_table_size = 0
        
        # 窗口大小动态调整
        self._stream_windows: Dict[int, int] = {}
        self._connection_window: int = initial_window_size
        self._window_lock = threading.Lock()
        self._window_adjustment_threshold = 0.5  # 50%时触发调整
        
        # 连接合并
        self._connection_groups: Dict[str, List[str]] = defaultdict(list)
        self._authority_to_connection: Dict[str, str] = {}
        self._coalescing_lock = threading.Lock()
        
        # 服务端推送控制
        self._push_promise_policy: Dict[str, str] = {}  # URL -> action (allow/block/modify)
        self._push_promise_lock = threading.Lock()
        
        # 统计信息
        self._stats = {
            'streams_created': 0,
            'streams_closed': 0,
            'priority_updates': 0,
            'window_adjustments': 0,
            'connections_coalesced': 0,
            'push_promises_blocked': 0,
            'push_promises_modified': 0,
        }
        self._stats_lock = threading.Lock()
    
    # ==================== 流优先级管理 ====================
    
    def update_stream_priority(self, stream_id: int, weight: int, 
                               parent_stream_id: Optional[int] = None,
                               exclusive: bool = False):
        """更新流优先级"""
        with self._priority_lock:
            node = PriorityNode(
                stream_id=stream_id,
                weight=max(1, min(256, weight)),
                parent_stream_id=parent_stream_id,
                exclusive=exclusive
            )
            self._priority_tree[stream_id] = node
            
            if parent_stream_id and parent_stream_id in self._priority_tree:
                parent = self._priority_tree[parent_stream_id]
                if exclusive:
                    parent.children = [stream_id]
                else:
                    parent.children.append(stream_id)
            
            with self._stats_lock:
                self._stats['priority_updates'] += 1
            
            logger.debug(f"流优先级更新: stream {stream_id}, weight {weight}, parent {parent_stream_id}")
    
    def get_stream_priority(self, stream_id: int) -> Optional[PriorityNode]:
        """获取流优先级"""
        with self._priority_lock:
            return self._priority_tree.get(stream_id)
    
    def get_priority_ordered_streams(self) -> List[int]:
        """获取按优先级排序的流ID列表"""
        with self._priority_lock:
            streams = list(self._priority_tree.values())
            streams.sort(key=lambda x: x.get_effective_priority(), reverse=True)
            return [s.stream_id for s in streams]
    
    def adjust_priority_for_proxy(self, stream_id: int, new_weight: int) -> bool:
        """代理端调整流优先级"""
        with self._priority_lock:
            if stream_id not in self._priority_tree:
                return False
            
            self._priority_tree[stream_id].weight = max(1, min(256, new_weight))
            logger.info(f"代理调整流优先级: stream {stream_id} -> weight {new_weight}")
            return True
    
    def get_priority_tree(self) -> Dict[int, PriorityNode]:
        """获取完整优先级树"""
        with self._priority_lock:
            return dict(self._priority_tree)
    
    # ==================== HPACK动态表管理 ====================
    
    def add_to_dynamic_table(self, name: str, value: str):
        """添加到HPACK动态表"""
        entry_size = len(name) + len(value) + 32
        
        with self._hpack_lock:
            while (self._dynamic_table_size + entry_size > self._hpack_stats.dynamic_table_size 
                   and self._dynamic_table):
                removed = self._dynamic_table.pop(0)
                self._dynamic_table_size -= len(removed[0]) + len(removed[1]) + 32
                self._hpack_stats.entries_count -= 1
            
            if entry_size <= self._hpack_stats.dynamic_table_size:
                self._dynamic_table.append((name, value))
                self._dynamic_table_size += entry_size
                self._hpack_stats.entries_count += 1
                self._hpack_stats.total_headers_compressed += 1
    
    def lookup_in_dynamic_table(self, index: int) -> Optional[Tuple[str, str]]:
        """从HPACK动态表查找"""
        with self._hpack_lock:
            if 0 <= index < len(self._dynamic_table):
                return self._dynamic_table[index]
            return None
    
    def update_dynamic_table_size(self, new_size: int):
        """更新动态表大小"""
        with self._hpack_lock:
            new_size = max(0, min(self._hpack_stats.max_dynamic_table_size, new_size))
            self._hpack_stats.dynamic_table_size = new_size
            
            while self._dynamic_table_size > new_size and self._dynamic_table:
                removed = self._dynamic_table.pop(0)
                self._dynamic_table_size -= len(removed[0]) + len(removed[1]) + 32
                self._hpack_stats.entries_count -= 1
            
            logger.info(f"HPACK动态表大小更新: {new_size} bytes")
    
    def get_hpack_stats(self) -> HPACKStats:
        """获取HPACK统计信息"""
        with self._hpack_lock:
            return HPACKStats(
                total_headers_compressed=self._hpack_stats.total_headers_compressed,
                total_headers_decompressed=self._hpack_stats.total_headers_decompressed,
                dynamic_table_size=self._hpack_stats.dynamic_table_size,
                max_dynamic_table_size=self._hpack_stats.max_dynamic_table_size,
                entries_count=self._hpack_stats.entries_count,
                compression_ratio=self._hpack_stats.compression_ratio
            )
    
    # ==================== 窗口大小动态调整 ====================
    
    def update_stream_window(self, stream_id: int, delta: int):
        """更新流窗口"""
        with self._window_lock:
            current = self._stream_windows.get(stream_id, 0)
            self._stream_windows[stream_id] = max(0, current + delta)
            
            self._check_window_adjustment(stream_id)
    
    def _check_window_adjustment(self, stream_id: int):
        """检查是否需要调整窗口"""
        current = self._stream_windows.get(stream_id, 0)
        if current < self._initial_window_size * self._window_adjustment_threshold:
            self._adjust_window(stream_id)
    
    def _adjust_window(self, stream_id: int):
        """调整窗口大小"""
        adjustment = self._initial_window_size - self._stream_windows.get(stream_id, 0)
        self._stream_windows[stream_id] = self._initial_window_size
        
        with self._stats_lock:
            self._stats['window_adjustments'] += 1
        
        logger.debug(f"窗口调整: stream {stream_id}, +{adjustment}")
    
    def get_stream_window(self, stream_id: int) -> int:
        """获取流窗口大小"""
        with self._window_lock:
            return self._stream_windows.get(stream_id, self._initial_window_size)
    
    def get_connection_window(self) -> int:
        """获取连接窗口大小"""
        with self._window_lock:
            return self._connection_window
    
    def update_connection_window(self, delta: int):
        """更新连接窗口"""
        with self._window_lock:
            self._connection_window = max(0, self._connection_window + delta)
    
    # ==================== 连接合并 ====================
    
    def can_coalesce_connections(self, authority1: str, authority2: str,
                                 target_ip1: str, target_ip2: str,
                                 cert_domains1: List[str], cert_domains2: List[str]) -> bool:
        """判断是否可以合并连接"""
        if not self._enable_connection_coalescing:
            return False
        
        if target_ip1 != target_ip2:
            return False
        
        for domain in cert_domains1:
            if domain in cert_domains2:
                return True
        
        return False
    
    def register_authority(self, authority: str, connection_id: str):
        """注册authority到连接映射"""
        with self._coalescing_lock:
            self._authority_to_connection[authority] = connection_id
            self._connection_groups[connection_id].append(authority)
    
    def get_connection_for_authority(self, authority: str) -> Optional[str]:
        """获取authority对应的连接"""
        with self._coalescing_lock:
            return self._authority_to_connection.get(authority)
    
    def get_authorities_for_connection(self, connection_id: str) -> List[str]:
        """获取连接对应的所有authority"""
        with self._coalescing_lock:
            return list(self._connection_groups.get(connection_id, []))
    
    def coalesce_if_possible(self, authority: str, target_ip: str, 
                            cert_domains: List[str]) -> Optional[str]:
        """尝试合并连接"""
        with self._coalescing_lock:
            for conn_id, authorities in self._connection_groups.items():
                for existing_auth in authorities:
                    if existing_auth in self._authority_to_connection:
                        existing_ip = self._authority_to_connection.get(existing_auth)
                        if existing_ip == target_ip:
                            self._authority_to_connection[authority] = conn_id
                            self._connection_groups[conn_id].append(authority)
                            
                            with self._stats_lock:
                                self._stats['connections_coalesced'] += 1
                            
                            return conn_id
            return None
    
    # ==================== 服务端推送控制 ====================
    
    def set_push_promise_policy(self, url_pattern: str, action: str):
        """设置推送策略"""
        with self._push_promise_lock:
            self._push_promise_policy[url_pattern] = action
    
    def check_push_promise(self, url: str) -> str:
        """检查推送策略"""
        with self._push_promise_lock:
            for pattern, action in self._push_promise_policy.items():
                if pattern in url:
                    return action
            return 'allow'
    
    def block_push_promise(self, url_pattern: str):
        """阻断推送"""
        self.set_push_promise_policy(url_pattern, 'block')
    
    def allow_push_promise(self, url_pattern: str):
        """允许推送"""
        self.set_push_promise_policy(url_pattern, 'allow')
    
    def modify_push_promise(self, url_pattern: str):
        """修改推送内容"""
        self.set_push_promise_policy(url_pattern, 'modify')
    
    def handle_push_promise(self, url: str, headers: List[Tuple[str, str]], 
                           body: bytes) -> Tuple[str, Optional[List[Tuple[str, str]]], Optional[bytes]]:
        """处理推送承诺"""
        action = self.check_push_promise(url)
        
        if action == 'block':
            with self._stats_lock:
                self._stats['push_promises_blocked'] += 1
            logger.info(f"推送阻断: {url}")
            return 'blocked', None, None
        
        elif action == 'modify':
            with self._stats_lock:
                self._stats['push_promises_modified'] += 1
            modified_headers = list(headers)
            modified_body = body
            logger.info(f"推送修改: {url}")
            return 'modified', modified_headers, modified_body
        
        return 'allowed', headers, body
    
    # ==================== 统计信息 ====================
    
    def record_stream_created(self):
        """记录流创建"""
        with self._stats_lock:
            self._stats['streams_created'] += 1
    
    def record_stream_closed(self):
        """记录流关闭"""
        with self._stats_lock:
            self._stats['streams_closed'] += 1
    
    def get_stats(self) -> Dict[str, Any]:
        """获取统计信息"""
        with self._stats_lock:
            stats = dict(self._stats)
        
        with self._hpack_lock:
            stats['hpack'] = {
                'dynamic_table_size': self._hpack_stats.dynamic_table_size,
                'entries_count': self._hpack_stats.entries_count,
                'total_compressed': self._hpack_stats.total_headers_compressed,
                'total_decompressed': self._hpack_stats.total_headers_decompressed,
            }
        
        with self._priority_lock:
            stats['priority_tree_size'] = len(self._priority_tree)
        
        with self._coalescing_lock:
            stats['connection_groups'] = len(self._connection_groups)
            stats['authorities_mapped'] = len(self._authority_to_connection)
        
        return stats
    
    def reset_stats(self):
        """重置统计信息"""
        with self._stats_lock:
            self._stats = {
                'streams_created': 0,
                'streams_closed': 0,
                'priority_updates': 0,
                'window_adjustments': 0,
                'connections_coalesced': 0,
                'push_promises_blocked': 0,
                'push_promises_modified': 0,
            }
