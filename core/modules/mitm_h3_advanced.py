"""
HTTP/3(QUIC)高级特性模块
包含连接迁移、0-RTT安全处理、版本协商、多路径预留、WebTransport预留等高级功能
"""

import logging
import time
import hashlib
from typing import Dict, List, Optional, Tuple, Any, Set
from dataclasses import dataclass, field
from collections import defaultdict
from enum import Enum
import threading

logger = logging.getLogger(__name__)


class QUICVersion(Enum):
    """QUIC版本"""
    V1 = "0x00000001"
    V2_DRAFT = "0xff000002"
    V2 = "0x6b3343cf"


class ZeroRTTRiskLevel(Enum):
    """0-RTT风险等级"""
    SAFE = "safe"
    CAUTION = "caution"
    DANGEROUS = "dangerous"


@dataclass
class ConnectionMigrationInfo:
    """连接迁移信息"""
    old_connection_id: bytes
    new_connection_id: bytes
    old_path: Tuple[str, int]
    new_path: Tuple[str, int]
    migration_time: float
    streams_preserved: List[int] = field(default_factory=list)


@dataclass
class ZeroRTTData:
    """0-RTT数据"""
    connection_id: bytes
    data: bytes
    timestamp: float
    is_replay: bool = False
    risk_level: ZeroRTTRiskLevel = ZeroRTTRiskLevel.CAUTION
    method: str = "GET"
    url: str = ""


@dataclass
class QUICVersionNegotiation:
    """QUIC版本协商信息"""
    client_versions: List[str] = field(default_factory=list)
    server_versions: List[str] = field(default_factory=list)
    negotiated_version: str = ""
    negotiation_time: float = 0.0


class H3AdvancedFeatures:
    """HTTP/3高级特性管理器"""
    
    def __init__(self,
                 max_connections: int = 50,
                 max_streams_per_connection: int = 100,
                 enable_connection_migration: bool = True,
                 enable_zero_rtt: bool = True,
                 zero_rtt_replay_protection: bool = True):
        self._max_connections = max_connections
        self._max_streams_per_connection = max_streams_per_connection
        self._enable_connection_migration = enable_connection_migration
        self._enable_zero_rtt = enable_zero_rtt
        self._zero_rtt_replay_protection = zero_rtt_replay_protection
        
        # 连接迁移管理
        self._connection_migration_history: Dict[bytes, ConnectionMigrationInfo] = {}
        self._connection_id_mapping: Dict[bytes, bytes] = {}
        self._migration_lock = threading.Lock()
        
        # 0-RTT安全管理
        self._zero_rtt_data_store: Dict[bytes, ZeroRTTData] = {}
        self._zero_rtt_seen_hashes: Set[str] = set()
        self._zero_rtt_idempotent_methods: Set[str] = {'GET', 'HEAD', 'OPTIONS'}
        self._zero_rtt_lock = threading.Lock()
        
        # QUIC版本协商
        self._version_negotiation_history: List[QUICVersionNegotiation] = []
        self._supported_versions: List[str] = [QUICVersion.V1.value, QUICVersion.V2.value]
        self._version_lock = threading.Lock()
        
        # 多路径QUIC预留
        self._multipath_connections: Dict[bytes, List[Tuple[str, int]]] = defaultdict(list)
        self._multipath_lock = threading.Lock()
        
        # WebTransport预留
        self._webtransport_sessions: Dict[str, Dict[str, Any]] = {}
        self._webtransport_lock = threading.Lock()
        
        # 统计信息
        self._stats = {
            'connections_migrated': 0,
            'zero_rtt_requests': 0,
            'zero_rtt_replays_blocked': 0,
            'version_negotiations': 0,
            'multipath_connections': 0,
            'webtransport_sessions': 0,
        }
        self._stats_lock = threading.Lock()
    
    # ==================== 连接迁移支持 ====================
    
    def handle_connection_migration(self, old_conn_id: bytes, new_conn_id: bytes,
                                   old_path: Tuple[str, int], new_path: Tuple[str, int],
                                   active_streams: List[int]) -> bool:
        """处理连接迁移"""
        if not self._enable_connection_migration:
            logger.warning("连接迁移功能已禁用")
            return False
        
        migration_info = ConnectionMigrationInfo(
            old_connection_id=old_conn_id,
            new_connection_id=new_conn_id,
            old_path=old_path,
            new_path=new_path,
            migration_time=time.time(),
            streams_preserved=active_streams
        )
        
        with self._migration_lock:
            self._connection_migration_history[new_conn_id] = migration_info
            self._connection_id_mapping[old_conn_id] = new_conn_id
        
        with self._stats_lock:
            self._stats['connections_migrated'] += 1
        
        logger.info(f"连接迁移: {old_conn_id.hex()[:8]} -> {new_conn_id.hex()[:8]}, "
                   f"路径: {old_path} -> {new_path}, 保留流: {len(active_streams)}")
        
        return True
    
    def get_original_connection_id(self, current_conn_id: bytes) -> Optional[bytes]:
        """获取原始连接ID"""
        with self._migration_lock:
            for old_id, new_id in self._connection_id_mapping.items():
                if new_id == current_conn_id:
                    return old_id
            return None
    
    def get_migration_history(self, conn_id: bytes) -> Optional[ConnectionMigrationInfo]:
        """获取迁移历史"""
        with self._migration_lock:
            return self._connection_migration_history.get(conn_id)
    
    def get_all_migration_paths(self) -> List[ConnectionMigrationInfo]:
        """获取所有迁移路径"""
        with self._migration_lock:
            return list(self._connection_migration_history.values())
    
    # ==================== 0-RTT安全处理 ====================
    
    def process_zero_rtt_data(self, conn_id: bytes, data: bytes, 
                             method: str, url: str) -> ZeroRTTData:
        """处理0-RTT数据"""
        if not self._enable_zero_rtt:
            logger.warning("0-RTT功能已禁用")
            return ZeroRTTData(
                connection_id=conn_id,
                data=data,
                timestamp=time.time(),
                risk_level=ZeroRTTRiskLevel.DANGEROUS
            )
        
        data_hash = hashlib.sha256(data).hexdigest()
        is_replay = False
        
        if self._zero_rtt_replay_protection:
            if data_hash in self._zero_rtt_seen_hashes:
                is_replay = True
            else:
                self._zero_rtt_seen_hashes.add(data_hash)
        
        risk_level = self._assess_zero_rtt_risk(method, url, is_replay)
        
        zero_rtt = ZeroRTTData(
            connection_id=conn_id,
            data=data,
            timestamp=time.time(),
            is_replay=is_replay,
            risk_level=risk_level,
            method=method,
            url=url
        )
        
        with self._zero_rtt_lock:
            self._zero_rtt_data_store[conn_id] = zero_rtt
        
        with self._stats_lock:
            self._stats['zero_rtt_requests'] += 1
            if is_replay:
                self._stats['zero_rtt_replays_blocked'] += 1
        
        if is_replay:
            logger.warning(f"0-RTT重放检测: {method} {url}")
        else:
            logger.debug(f"0-RTT数据接收: {method} {url}, 风险: {risk_level.value}")
        
        return zero_rtt
    
    def _assess_zero_rtt_risk(self, method: str, url: str, is_replay: bool) -> ZeroRTTRiskLevel:
        """评估0-RTT风险等级"""
        if is_replay:
            return ZeroRTTRiskLevel.DANGEROUS
        
        if method not in self._zero_rtt_idempotent_methods:
            return ZeroRTTRiskLevel.DANGEROUS
        
        sensitive_paths = ['/api/payment', '/api/transfer', '/api/delete', '/api/update']
        if any(path in url.lower() for path in sensitive_paths):
            return ZeroRTTRiskLevel.CAUTION
        
        return ZeroRTTRiskLevel.SAFE
    
    def should_block_zero_rtt(self, method: str, url: str) -> bool:
        """判断是否应阻断0-RTT请求"""
        if method not in self._zero_rtt_idempotent_methods:
            return True
        
        dangerous_paths = ['/api/payment', '/api/transfer', '/api/delete']
        return any(path in url.lower() for path in dangerous_paths)
    
    def get_zero_rtt_data(self, conn_id: bytes) -> Optional[ZeroRTTData]:
        """获取0-RTT数据"""
        with self._zero_rtt_lock:
            return self._zero_rtt_data_store.get(conn_id)
    
    def clear_zero_rtt_cache(self):
        """清除0-RTT缓存"""
        with self._zero_rtt_lock:
            self._zero_rtt_data_store.clear()
            self._zero_rtt_seen_hashes.clear()
            logger.info("0-RTT缓存已清除")
    
    # ==================== QUIC版本协商 ====================
    
    def negotiate_version(self, client_versions: List[str]) -> Optional[str]:
        """协商QUIC版本"""
        negotiated = None
        
        for version in client_versions:
            if version in self._supported_versions:
                negotiated = version
                break
        
        negotiation = QUICVersionNegotiation(
            client_versions=client_versions,
            server_versions=list(self._supported_versions),
            negotiated_version=negotiated or "",
            negotiation_time=time.time()
        )
        
        with self._version_lock:
            self._version_negotiation_history.append(negotiation)
        
        with self._stats_lock:
            self._stats['version_negotiations'] += 1
        
        if negotiated:
            logger.info(f"QUIC版本协商成功: {negotiated}")
        else:
            logger.warning(f"QUIC版本协商失败, 客户端版本: {client_versions}")
        
        return negotiated
    
    def get_supported_versions(self) -> List[str]:
        """获取支持的版本"""
        with self._version_lock:
            return list(self._supported_versions)
    
    def add_supported_version(self, version: str):
        """添加支持的版本"""
        with self._version_lock:
            if version not in self._supported_versions:
                self._supported_versions.append(version)
                logger.info(f"添加QUIC版本支持: {version}")
    
    def get_version_negotiation_history(self) -> List[QUICVersionNegotiation]:
        """获取版本协商历史"""
        with self._version_lock:
            return list(self._version_negotiation_history)
    
    # ==================== 多路径QUIC预留 ====================
    
    def add_multipath(self, conn_id: bytes, path: Tuple[str, int]):
        """添加多路径"""
        with self._multipath_lock:
            if path not in self._multipath_connections[conn_id]:
                self._multipath_connections[conn_id].append(path)
                
                if len(self._multipath_connections[conn_id]) == 2:
                    with self._stats_lock:
                        self._stats['multipath_connections'] += 1
                
                logger.debug(f"多路径添加: {conn_id.hex()[:8]} -> {path}")
    
    def get_multipaths(self, conn_id: bytes) -> List[Tuple[str, int]]:
        """获取多路径"""
        with self._multipath_lock:
            return list(self._multipath_connections.get(conn_id, []))
    
    def remove_multipath(self, conn_id: bytes, path: Tuple[str, int]):
        """移除多路径"""
        with self._multipath_lock:
            if conn_id in self._multipath_connections:
                if path in self._multipath_connections[conn_id]:
                    self._multipath_connections[conn_id].remove(path)
    
    # ==================== WebTransport预留 ====================
    
    def create_webtransport_session(self, session_id: str, 
                                   conn_id: bytes,
                                   stream_id: int) -> Dict[str, Any]:
        """创建WebTransport会话"""
        session = {
            'session_id': session_id,
            'connection_id': conn_id,
            'stream_id': stream_id,
            'created_at': time.time(),
            'state': 'active',
            'datagrams_received': 0,
            'datagrams_sent': 0,
        }
        
        with self._webtransport_lock:
            self._webtransport_sessions[session_id] = session
        
        with self._stats_lock:
            self._stats['webtransport_sessions'] += 1
        
        logger.info(f"WebTransport会话创建: {session_id}")
        return session
    
    def get_webtransport_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """获取WebTransport会话"""
        with self._webtransport_lock:
            return self._webtransport_sessions.get(session_id)
    
    def close_webtransport_session(self, session_id: str):
        """关闭WebTransport会话"""
        with self._webtransport_lock:
            if session_id in self._webtransport_sessions:
                self._webtransport_sessions[session_id]['state'] = 'closed'
                logger.info(f"WebTransport会话关闭: {session_id}")
    
    def get_active_webtransport_sessions(self) -> List[Dict[str, Any]]:
        """获取活跃的WebTransport会话"""
        with self._webtransport_lock:
            return [s for s in self._webtransport_sessions.values() 
                    if s.get('state') == 'active']
    
    # ==================== 统计信息 ====================
    
    def get_stats(self) -> Dict[str, Any]:
        """获取统计信息"""
        with self._stats_lock:
            stats = dict(self._stats)
        
        with self._migration_lock:
            stats['total_migrations'] = len(self._connection_migration_history)
        
        with self._zero_rtt_lock:
            stats['zero_rtt_cached'] = len(self._zero_rtt_data_store)
            stats['zero_rtt_hashes'] = len(self._zero_rtt_seen_hashes)
        
        with self._multipath_lock:
            stats['multipath_total'] = sum(
                len(paths) for paths in self._multipath_connections.values()
            )
        
        with self._webtransport_lock:
            stats['webtransport_active'] = len(
                [s for s in self._webtransport_sessions.values() 
                 if s.get('state') == 'active']
            )
        
        return stats
    
    def reset_stats(self):
        """重置统计信息"""
        with self._stats_lock:
            self._stats = {
                'connections_migrated': 0,
                'zero_rtt_requests': 0,
                'zero_rtt_replays_blocked': 0,
                'version_negotiations': 0,
                'multipath_connections': 0,
                'webtransport_sessions': 0,
            }
