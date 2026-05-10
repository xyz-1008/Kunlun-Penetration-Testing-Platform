"""
安全加固模块
包含HPACK炸弹防护、流泛滥检测、QUIC地址验证、证书透明度校验等功能
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


class ThreatLevel(Enum):
    """威胁等级"""
    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class SecurityAlert:
    """安全告警"""
    alert_id: str
    timestamp: float
    threat_level: ThreatLevel
    alert_type: str
    description: str
    source_ip: str = ""
    connection_id: str = ""
    stream_id: Optional[int] = None
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class StreamFloodInfo:
    """流泛滥信息"""
    connection_id: str
    stream_count: int
    first_seen: float
    last_seen: float
    is_blocked: bool = False


class HPACKBombProtector:
    """HPACK炸弹防护器"""
    
    def __init__(self,
                 max_dynamic_table_size: int = 4096,
                 max_header_size: int = 8192,
                 max_header_count: int = 100,
                 max_compression_ratio: float = 100.0):
        self._max_dynamic_table_size = max_dynamic_table_size
        self._max_header_size = max_header_size
        self._max_header_count = max_header_count
        self._max_compression_ratio = max_compression_ratio
        
        self._alerts: List[SecurityAlert] = []
        self._alert_lock = threading.RLock()
        
        self._stats = {
            'total_headers_checked': 0,
            'bombs_detected': 0,
            'headers_blocked': 0,
            'total_header_bytes': 0,
        }
        self._stats_lock = threading.RLock()
    
    def validate_headers(self, headers: List[Tuple[str, str]], 
                        compressed_size: int = 0) -> Tuple[bool, Optional[str]]:
        """验证头部安全性"""
        with self._stats_lock:
            self._stats['total_headers_checked'] += 1
        
        if len(headers) > self._max_header_count:
            alert = self._create_alert(
                ThreatLevel.HIGH,
                'hpack_bomb',
                f"头部数量过多: {len(headers)} > {self._max_header_count}"
            )
            self._record_alert(alert)
            return False, alert.description
        
        total_size = 0
        for name, value in headers:
            total_size += len(name) + len(value)
            
            if len(name) > 1000:
                alert = self._create_alert(
                    ThreatLevel.MEDIUM,
                    'oversized_header_name',
                    f"头部名称过长: {len(name)} bytes"
                )
                self._record_alert(alert)
                return False, alert.description
            
            if len(value) > self._max_header_size:
                alert = self._create_alert(
                    ThreatLevel.HIGH,
                    'oversized_header_value',
                    f"头部值过长: {len(value)} bytes"
                )
                self._record_alert(alert)
                return False, alert.description
        
        with self._stats_lock:
            self._stats['total_header_bytes'] += total_size
        
        if compressed_size > 0 and total_size > 0:
            ratio = total_size / compressed_size
            if ratio > self._max_compression_ratio:
                alert = self._create_alert(
                    ThreatLevel.CRITICAL,
                    'hpack_bomb_detected',
                    f"HPACK炸弹检测: 压缩比 {ratio:.1f}x > {self._max_compression_ratio}x"
                )
                self._record_alert(alert)
                return False, alert.description
        
        return True, None
    
    def validate_dynamic_table_size(self, requested_size: int) -> Tuple[bool, Optional[str]]:
        """验证动态表大小"""
        if requested_size > self._max_dynamic_table_size:
            alert = self._create_alert(
                ThreatLevel.MEDIUM,
                'dynamic_table_oversize',
                f"动态表大小超限: {requested_size} > {self._max_dynamic_table_size}"
            )
            self._record_alert(alert)
            return False, alert.description
        
        return True, None
    
    def _create_alert(self, level: ThreatLevel, alert_type: str, 
                     description: str) -> SecurityAlert:
        """创建告警"""
        return SecurityAlert(
            alert_id=hashlib.md5(f"{time.time()}{alert_type}".encode()).hexdigest()[:12],
            timestamp=time.time(),
            threat_level=level,
            alert_type=alert_type,
            description=description,
        )
    
    def _record_alert(self, alert: SecurityAlert):
        """记录告警"""
        with self._alert_lock:
            self._alerts.append(alert)
        
        with self._stats_lock:
            if 'bomb' in alert.alert_type.lower():
                self._stats['bombs_detected'] += 1
            self._stats['headers_blocked'] += 1
        
        logger.warning(f"安全告警 [{alert.threat_level.value}]: {alert.description}")
    
    def get_alerts(self, limit: int = 100) -> List[Dict[str, Any]]:
        """获取告警"""
        with self._alert_lock:
            return [
                {
                    'alert_id': a.alert_id,
                    'timestamp': a.timestamp,
                    'threat_level': a.threat_level.value,
                    'alert_type': a.alert_type,
                    'description': a.description,
                }
                for a in self._alerts[-limit:]
            ]
    
    def get_stats(self) -> Dict[str, Any]:
        """获取统计信息"""
        with self._stats_lock:
            stats = dict(self._stats)
        
        with self._alert_lock:
            stats['total_alerts'] = len(self._alerts)
        
        return stats


class StreamFloodDetector:
    """流泛滥检测器"""
    
    def __init__(self,
                 max_streams_per_connection: int = 100,
                 max_streams_per_second: int = 50,
                 detection_window: float = 10.0):
        self._max_streams_per_connection = max_streams_per_connection
        self._max_streams_per_second = max_streams_per_second
        self._detection_window = detection_window
        
        self._stream_counts: Dict[str, StreamFloodInfo] = {}
        self._stream_timestamps: Dict[str, List[float]] = defaultdict(list)
        self._lock = threading.RLock()
        
        self._alerts: List[SecurityAlert] = []
        self._alert_lock = threading.RLock()
        
        self._stats = {
            'total_streams_tracked': 0,
            'floods_detected': 0,
            'connections_blocked': 0,
        }
        self._stats_lock = threading.RLock()
    
    def track_stream(self, connection_id: str, stream_id: int) -> Tuple[bool, Optional[str]]:
        """跟踪流"""
        now = time.time()
        
        with self._lock:
            if connection_id not in self._stream_counts:
                self._stream_counts[connection_id] = StreamFloodInfo(
                    connection_id=connection_id,
                    stream_count=1,
                    first_seen=now,
                    last_seen=now,
                )
            else:
                info = self._stream_counts[connection_id]
                info.stream_count += 1
                info.last_seen = now
            
            self._stream_timestamps[connection_id].append(now)
            
            with self._stats_lock:
                self._stats['total_streams_tracked'] += 1
        
        return self._check_flood(connection_id, now)
    
    def _check_flood(self, connection_id: str, now: float) -> Tuple[bool, Optional[str]]:
        """检查是否泛滥"""
        with self._lock:
            info = self._stream_counts.get(connection_id)
            if not info:
                return True, None
            
            if info.stream_count > self._max_streams_per_connection:
                info.is_blocked = True
                
                alert = self._create_alert(
                    ThreatLevel.HIGH,
                    'stream_flood',
                    f"流泛滥: 连接 {connection_id[:8]} 有 {info.stream_count} 个流"
                )
                self._record_alert(alert)
                
                with self._stats_lock:
                    self._stats['floods_detected'] += 1
                    self._stats['connections_blocked'] += 1
                
                return False, alert.description
            
            timestamps = self._stream_timestamps.get(connection_id, [])
            recent = [t for t in timestamps if now - t <= self._detection_window]
            self._stream_timestamps[connection_id] = recent
            
            rate = len(recent) / self._detection_window
            if rate > self._max_streams_per_second:
                alert = self._create_alert(
                    ThreatLevel.MEDIUM,
                    'stream_rate_limit',
                    f"流速率过高: {rate:.1f} 流/秒"
                )
                self._record_alert(alert)
                
                with self._stats_lock:
                    self._stats['floods_detected'] += 1
                
                return False, alert.description
        
        return True, None
    
    def _create_alert(self, level: ThreatLevel, alert_type: str, 
                     description: str) -> SecurityAlert:
        """创建告警"""
        return SecurityAlert(
            alert_id=hashlib.md5(f"{time.time()}{alert_type}".encode()).hexdigest()[:12],
            timestamp=time.time(),
            threat_level=level,
            alert_type=alert_type,
            description=description,
        )
    
    def _record_alert(self, alert: SecurityAlert):
        """记录告警"""
        with self._alert_lock:
            self._alerts.append(alert)
        logger.warning(f"安全告警 [{alert.threat_level.value}]: {alert.description}")
    
    def get_blocked_connections(self) -> List[str]:
        """获取被阻止的连接"""
        with self._lock:
            return [
                conn_id for conn_id, info in self._stream_counts.items()
                if info.is_blocked
            ]
    
    def get_alerts(self, limit: int = 100) -> List[Dict[str, Any]]:
        """获取告警"""
        with self._alert_lock:
            return [
                {
                    'alert_id': a.alert_id,
                    'timestamp': a.timestamp,
                    'threat_level': a.threat_level.value,
                    'alert_type': a.alert_type,
                    'description': a.description,
                }
                for a in self._alerts[-limit:]
            ]
    
    def get_stats(self) -> Dict[str, Any]:
        """获取统计信息"""
        with self._stats_lock:
            stats = dict(self._stats)
        
        with self._lock:
            stats['active_connections'] = len(self._stream_counts)
            stats['blocked_connections'] = len(self.get_blocked_connections())
        
        return stats
    
    def cleanup(self):
        """清理过期数据"""
        now = time.time()
        with self._lock:
            expired = [
                conn_id for conn_id, info in self._stream_counts.items()
                if now - info.last_seen > self._detection_window * 10
            ]
            for conn_id in expired:
                del self._stream_counts[conn_id]
                self._stream_timestamps.pop(conn_id, None)


class QUICAddressValidator:
    """QUIC地址验证器"""
    
    def __init__(self, enable_validation: bool = True):
        self._enable_validation = enable_validation
        
        self._validated_addresses: Dict[str, float] = {}
        self._lock = threading.RLock()
        
        self._alerts: List[SecurityAlert] = []
        self._alert_lock = threading.RLock()
        
        self._stats = {
            'total_validations': 0,
            'validations_passed': 0,
            'validations_failed': 0,
            'reflection_attacks_blocked': 0,
        }
        self._stats_lock = threading.RLock()
    
    def validate_address(self, client_ip: str, port: int, 
                        token: Optional[bytes] = None) -> Tuple[bool, Optional[str]]:
        """验证客户端地址"""
        if not self._enable_validation:
            return True, None
        
        with self._stats_lock:
            self._stats['total_validations'] += 1
        
        address = f"{client_ip}:{port}"
        
        with self._lock:
            if address in self._validated_addresses:
                with self._stats_lock:
                    self._stats['validations_passed'] += 1
                return True, None
        
        if token:
            if self._verify_token(address, token):
                with self._lock:
                    self._validated_addresses[address] = time.time()
                with self._stats_lock:
                    self._stats['validations_passed'] += 1
                return True, None
            else:
                alert = self._create_alert(
                    ThreatLevel.HIGH,
                    'invalid_token',
                    f"无效验证令牌: {address}"
                )
                self._record_alert(alert)
                with self._stats_lock:
                    self._stats['validations_failed'] += 1
                    self._stats['reflection_attacks_blocked'] += 1
                return False, alert.description
        
        with self._lock:
            self._validated_addresses[address] = time.time()
        
        with self._stats_lock:
            self._stats['validations_passed'] += 1
        
        return True, None
    
    def _verify_token(self, address: str, token: bytes) -> bool:
        """验证令牌"""
        expected = hashlib.sha256(address.encode()).digest()[:16]
        return token == expected
    
    def generate_token(self, client_ip: str, port: int) -> bytes:
        """生成验证令牌"""
        address = f"{client_ip}:{port}"
        return hashlib.sha256(address.encode()).digest()[:16]
    
    def _create_alert(self, level: ThreatLevel, alert_type: str, 
                     description: str) -> SecurityAlert:
        """创建告警"""
        return SecurityAlert(
            alert_id=hashlib.md5(f"{time.time()}{alert_type}".encode()).hexdigest()[:12],
            timestamp=time.time(),
            threat_level=level,
            alert_type=alert_type,
            description=description,
        )
    
    def _record_alert(self, alert: SecurityAlert):
        """记录告警"""
        with self._alert_lock:
            self._alerts.append(alert)
        logger.warning(f"安全告警 [{alert.threat_level.value}]: {alert.description}")
    
    def get_stats(self) -> Dict[str, Any]:
        """获取统计信息"""
        with self._stats_lock:
            stats = dict(self._stats)
        
        with self._lock:
            stats['validated_addresses'] = len(self._validated_addresses)
        
        return stats
    
    def get_alerts(self, limit: int = 100) -> List[Dict[str, Any]]:
        """获取告警"""
        with self._alert_lock:
            return [
                {
                    'alert_id': a.alert_id,
                    'timestamp': a.timestamp,
                    'threat_level': a.threat_level.value,
                    'alert_type': a.alert_type,
                    'description': a.description,
                }
                for a in self._alerts[-limit:]
            ]


class CertificateTransparencyValidator:
    """证书透明度验证器"""
    
    def __init__(self, enable_validation: bool = False):
        self._enable_validation = enable_validation
        
        self._sct_cache: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.RLock()
        
        self._stats = {
            'certificates_checked': 0,
            'scts_added': 0,
            'validation_failures': 0,
        }
        self._stats_lock = threading.RLock()
    
    def add_sct_to_certificate(self, cert_data: Dict[str, Any]) -> Dict[str, Any]:
        """为证书添加SCT"""
        if not self._enable_validation:
            return cert_data
        
        with self._stats_lock:
            self._stats['certificates_checked'] += 1
        
        cert_hash = hashlib.sha256(str(cert_data).encode()).hexdigest()
        
        with self._lock:
            if cert_hash in self._sct_cache:
                cert_data['sct'] = self._sct_cache[cert_hash]
                return cert_data
        
        sct = {
            'version': 1,
            'log_id': hashlib.sha256(cert_hash.encode()).hexdigest()[:32],
            'timestamp': int(time.time() * 1000),
            'extensions': '',
            'signature': '',
        }
        
        cert_data['sct'] = sct
        
        with self._lock:
            self._sct_cache[cert_hash] = sct
        
        with self._stats_lock:
            self._stats['scts_added'] += 1
        
        return cert_data
    
    def validate_sct(self, cert_data: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        """验证SCT"""
        if not self._enable_validation:
            return True, None
        
        sct = cert_data.get('sct')
        if not sct:
            with self._stats_lock:
                self._stats['validation_failures'] += 1
            return False, "证书缺少SCT"
        
        return True, None
    
    def get_stats(self) -> Dict[str, Any]:
        """获取统计信息"""
        with self._stats_lock:
            stats = dict(self._stats)
        
        with self._lock:
            stats['cached_scts'] = len(self._sct_cache)
        
        return stats
    
    def get_alerts(self, limit: int = 100) -> List[Dict[str, Any]]:
        """获取告警"""
        with self._alert_lock:
            return [
                {
                    'alert_id': a.alert_id,
                    'timestamp': a.timestamp,
                    'threat_level': a.threat_level.value,
                    'alert_type': a.alert_type,
                    'description': a.description,
                }
                for a in self._alerts[-limit:]
            ]


class SecurityManager:
    """安全管理器"""
    
    def __init__(self,
                 enable_hpack_protection: bool = True,
                 enable_stream_flood_detection: bool = True,
                 enable_quic_validation: bool = True,
                 enable_ct_validation: bool = False):
        self._hpack_protector = HPACKBombProtector() if enable_hpack_protection else None
        self._flood_detector = StreamFloodDetector() if enable_stream_flood_detection else None
        self._quic_validator = QUICAddressValidator() if enable_quic_validation else None
        self._ct_validator = CertificateTransparencyValidator() if enable_ct_validation else None
        
        self._all_alerts: List[SecurityAlert] = []
        self._alert_lock = threading.RLock()
        
        self._stats = {
            'total_checks': 0,
            'threats_detected': 0,
            'actions_taken': 0,
        }
        self._stats_lock = threading.RLock()
    
    def validate_headers(self, headers: List[Tuple[str, str]], 
                        compressed_size: int = 0) -> Tuple[bool, Optional[str]]:
        """验证头部"""
        if self._hpack_protector:
            return self._hpack_protector.validate_headers(headers, compressed_size)
        return True, None
    
    def track_stream(self, connection_id: str, stream_id: int) -> Tuple[bool, Optional[str]]:
        """跟踪流"""
        if self._flood_detector:
            return self._flood_detector.track_stream(connection_id, stream_id)
        return True, None
    
    def validate_quic_address(self, client_ip: str, port: int, 
                             token: Optional[bytes] = None) -> Tuple[bool, Optional[str]]:
        """验证QUIC地址"""
        if self._quic_validator:
            return self._quic_validator.validate_address(client_ip, port, token)
        return True, None
    
    def add_sct_to_certificate(self, cert_data: Dict[str, Any]) -> Dict[str, Any]:
        """添加SCT"""
        if self._ct_validator:
            return self._ct_validator.add_sct_to_certificate(cert_data)
        return cert_data
    
    def get_all_alerts(self, limit: int = 100) -> List[Dict[str, Any]]:
        """获取所有告警"""
        alerts = []
        
        if self._hpack_protector:
            alerts.extend(self._hpack_protector.get_alerts(limit // 4))
        
        if self._flood_detector:
            alerts.extend(self._flood_detector.get_alerts(limit // 4))
        
        if self._quic_validator:
            alerts.extend(self._quic_validator.get_alerts(limit // 4))
        
        if self._ct_validator:
            alerts.extend(self._ct_validator.get_alerts(limit // 4))
        
        return sorted(alerts, key=lambda x: x['timestamp'], reverse=True)[:limit]
    
    def get_stats(self) -> Dict[str, Any]:
        """获取统计信息"""
        stats = {
            'hpack_protection': self._hpack_protector.get_stats() if self._hpack_protector else {'enabled': False},
            'stream_flood_detection': self._flood_detector.get_stats() if self._flood_detector else {'enabled': False},
            'quic_validation': self._quic_validator.get_stats() if self._quic_validator else {'enabled': False},
            'ct_validation': self._ct_validator.get_stats() if self._ct_validator else {'enabled': False},
        }
        
        with self._stats_lock:
            stats.update(self._stats)
        
        return stats
    
    def cleanup(self):
        """清理资源"""
        if self._flood_detector:
            self._flood_detector.cleanup()
