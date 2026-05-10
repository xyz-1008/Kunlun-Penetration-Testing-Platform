"""
自适应协议降级与升级管理器
包含智能降级、协议伪装、ALPN策略配置、协议嗅探日志等功能
"""

import logging
import time
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from collections import defaultdict
from enum import Enum
import threading
import json

logger = logging.getLogger(__name__)


class ProtocolVersion(Enum):
    """协议版本"""
    HTTP3 = "HTTP/3"
    HTTP2 = "HTTP/2"
    HTTP1 = "HTTP/1.1"


class FallbackReason(Enum):
    """降级原因"""
    SERVER_NOT_SUPPORTED = "server_not_supported"
    CLIENT_NOT_SUPPORTED = "client_not_supported"
    CONNECTION_ERROR = "connection_error"
    TIMEOUT = "timeout"
    CERTIFICATE_ERROR = "certificate_error"
    FORCED_DOWNGRADE = "forced_downgrade"
    PROXY_ERROR = "proxy_error"


@dataclass
class ProtocolNegotiationResult:
    """协议协商结果"""
    client_protocol: ProtocolVersion
    server_protocol: ProtocolVersion
    negotiated_protocol: ProtocolVersion
    alpn_order: List[str]
    negotiation_time: float
    fallback_chain: List[ProtocolVersion]
    reason: Optional[FallbackReason] = None
    is_forced: bool = False


@dataclass
class ProtocolSniffLog:
    """协议嗅探日志"""
    timestamp: float
    client_ip: str
    server_host: str
    server_port: int
    client_alpn: List[str]
    server_alpn: List[str]
    negotiated_protocol: str
    fallback_occurred: bool = False
    fallback_reason: Optional[str] = None
    connection_duration: float = 0.0


class AdaptiveProtocolManager:
    """自适应协议管理器"""
    
    def __init__(self,
                 default_alpn_order: Optional[List[str]] = None,
                 enable_smart_fallback: bool = True,
                 enable_protocol_spoofing: bool = False,
                 max_fallback_attempts: int = 3):
        self._enable_smart_fallback = enable_smart_fallback
        self._enable_protocol_spoofing = enable_protocol_spoofing
        self._max_fallback_attempts = max_fallback_attempts
        
        self._alpn_order = default_alpn_order or ['h3', 'h2', 'http/1.1']
        self._alpn_lock = threading.Lock()
        
        self._sniff_logs: List[ProtocolSniffLog] = []
        self._sniff_log_lock = threading.Lock()
        self._max_sniff_logs = 10000
        
        self._fallback_history: Dict[str, int] = defaultdict(int)
        self._fallback_lock = threading.Lock()
        
        self._protocol_cache: Dict[str, ProtocolVersion] = {}
        self._protocol_cache_lock = threading.Lock()
        self._cache_ttl = 300
        
        self._forced_downgrade_rules: Dict[str, ProtocolVersion] = {}
        self._forced_lock = threading.Lock()
        
        self._stats = {
            'total_negotiations': 0,
            'successful_h3': 0,
            'successful_h2': 0,
            'successful_h1': 0,
            'fallbacks_occurred': 0,
            'forced_downgrades': 0,
            'cache_hits': 0,
            'cache_misses': 0,
        }
        self._stats_lock = threading.Lock()
    
    # ==================== 智能降级 ====================
    
    def negotiate_protocol(self, client_alpn: List[str], server_alpn: List[str],
                          host: str, port: int,
                          client_ip: str = "") -> ProtocolNegotiationResult:
        """协商协议"""
        start_time = time.time()
        
        cached = self._check_cache(host, port)
        if cached:
            with self._stats_lock:
                self._stats['cache_hits'] += 1
                self._stats['total_negotiations'] += 1
            
            return ProtocolNegotiationResult(
                client_protocol=self._alpn_to_protocol(client_alpn),
                server_protocol=self._alpn_to_protocol(server_alpn),
                negotiated_protocol=cached,
                alpn_order=list(self._alpn_order),
                negotiation_time=time.time() - start_time,
                fallback_chain=self._get_fallback_chain(cached)
            )
        
        with self._stats_lock:
            self._stats['cache_misses'] += 1
        
        forced = self._check_forced_downgrade(host)
        if forced:
            result = self._force_protocol(forced, client_alpn, server_alpn, host)
            result.negotiation_time = time.time() - start_time
            with self._stats_lock:
                self._stats['total_negotiations'] += 1
                self._stats['forced_downgrades'] += 1
            
            self._log_negotiation(client_ip, host, port, client_alpn, server_alpn, result)
            return result
        
        negotiated = self._find_common_protocol(client_alpn, server_alpn)
        
        if negotiated is None and self._enable_smart_fallback:
            negotiated, fallback_chain, reason = self._smart_fallback(
                client_alpn, server_alpn, host
            )
        elif negotiated is None:
            negotiated = ProtocolVersion.HTTP1
            fallback_chain = [negotiated]
            reason = FallbackReason.SERVER_NOT_SUPPORTED
        else:
            fallback_chain = self._get_fallback_chain(negotiated)
            reason = None
        
        result = ProtocolNegotiationResult(
            client_protocol=self._alpn_to_protocol(client_alpn),
            server_protocol=self._alpn_to_protocol(server_alpn),
            negotiated_protocol=negotiated,
            alpn_order=list(self._alpn_order),
            negotiation_time=time.time() - start_time,
            fallback_chain=fallback_chain,
            reason=reason
        )
        
        self._update_cache(host, port, negotiated)
        self._log_negotiation(client_ip, host, port, client_alpn, server_alpn, result)
        
        with self._stats_lock:
            self._stats['total_negotiations'] += 1
            if negotiated == ProtocolVersion.HTTP3:
                self._stats['successful_h3'] += 1
            elif negotiated == ProtocolVersion.HTTP2:
                self._stats['successful_h2'] += 1
            else:
                self._stats['successful_h1'] += 1
            
            if reason:
                self._stats['fallbacks_occurred'] += 1
        
        logger.info(f"协议协商: {host}:{port} -> {negotiated.value}")
        
        return result
    
    def _find_common_protocol(self, client_alpn: List[str], 
                             server_alpn: List[str]) -> Optional[ProtocolVersion]:
        """查找共同支持的协议"""
        with self._alpn_lock:
            preferred_order = list(self._alpn_order)
        
        for preferred in preferred_order:
            if preferred in client_alpn and preferred in server_alpn:
                return self._alpn_to_protocol([preferred])
        
        return None
    
    def _smart_fallback(self, client_alpn: List[str], server_alpn: List[str],
                       host: str) -> Tuple[ProtocolVersion, List[ProtocolVersion], FallbackReason]:
        """智能降级"""
        with self._alpn_lock:
            preferred_order = list(self._alpn_order)
        
        for preferred in preferred_order:
            if preferred in server_alpn:
                protocol = self._alpn_to_protocol([preferred])
                fallback_chain = self._get_fallback_chain(protocol)
                return protocol, fallback_chain, FallbackReason.SERVER_NOT_SUPPORTED
        
        return ProtocolVersion.HTTP1, [ProtocolVersion.HTTP1], FallbackReason.SERVER_NOT_SUPPORTED
    
    def _get_fallback_chain(self, protocol: ProtocolVersion) -> List[ProtocolVersion]:
        """获取降级链"""
        if protocol == ProtocolVersion.HTTP3:
            return [ProtocolVersion.HTTP3, ProtocolVersion.HTTP2, ProtocolVersion.HTTP1]
        elif protocol == ProtocolVersion.HTTP2:
            return [ProtocolVersion.HTTP2, ProtocolVersion.HTTP1]
        return [ProtocolVersion.HTTP1]
    
    # ==================== 协议伪装 ====================
    
    def force_protocol_downgrade(self, host_pattern: str, target_protocol: ProtocolVersion):
        """强制协议降级"""
        with self._forced_lock:
            self._forced_downgrade_rules[host_pattern] = target_protocol
            logger.info(f"强制降级规则添加: {host_pattern} -> {target_protocol.value}")
    
    def remove_forced_downgrade(self, host_pattern: str):
        """移除强制降级规则"""
        with self._forced_lock:
            if host_pattern in self._forced_downgrade_rules:
                del self._forced_downgrade_rules[host_pattern]
                logger.info(f"强制降级规则移除: {host_pattern}")
    
    def _check_forced_downgrade(self, host: str) -> Optional[ProtocolVersion]:
        """检查是否有强制降级规则"""
        with self._forced_lock:
            for pattern, protocol in self._forced_downgrade_rules.items():
                if pattern in host:
                    return protocol
            return None
    
    def _force_protocol(self, protocol: ProtocolVersion, client_alpn: List[str],
                       server_alpn: List[str], host: str) -> ProtocolNegotiationResult:
        """强制使用指定协议"""
        return ProtocolNegotiationResult(
            client_protocol=self._alpn_to_protocol(client_alpn),
            server_protocol=self._alpn_to_protocol(server_alpn),
            negotiated_protocol=protocol,
            alpn_order=list(self._alpn_order),
            negotiation_time=0.0,
            fallback_chain=[protocol],
            reason=FallbackReason.FORCED_DOWNGRADE,
            is_forced=True
        )
    
    def get_forced_downgrade_rules(self) -> Dict[str, str]:
        """获取强制降级规则"""
        with self._forced_lock:
            return {k: v.value for k, v in self._forced_downgrade_rules.items()}
    
    # ==================== ALPN策略配置 ====================
    
    def set_alpn_order(self, order: List[str]):
        """设置ALPN协商顺序"""
        with self._alpn_lock:
            self._alpn_order = order
            logger.info(f"ALPN顺序更新: {order}")
    
    def get_alpn_order(self) -> List[str]:
        """获取ALPN协商顺序"""
        with self._alpn_lock:
            return list(self._alpn_order)
    
    def add_alpn_protocol(self, protocol: str, position: int = -1):
        """添加ALPN协议"""
        with self._alpn_lock:
            if protocol not in self._alpn_order:
                if position == -1:
                    self._alpn_order.append(protocol)
                else:
                    self._alpn_order.insert(position, protocol)
    
    def remove_alpn_protocol(self, protocol: str):
        """移除ALPN协议"""
        with self._alpn_lock:
            if protocol in self._alpn_order:
                self._alpn_order.remove(protocol)
    
    def prioritize_protocol(self, protocol: str):
        """优先使用指定协议"""
        with self._alpn_lock:
            if protocol in self._alpn_order:
                self._alpn_order.remove(protocol)
            self._alpn_order.insert(0, protocol)
    
    # ==================== 协议嗅探日志 ====================
    
    def _log_negotiation(self, client_ip: str, host: str, port: int,
                        client_alpn: List[str], server_alpn: List[str],
                        result: ProtocolNegotiationResult):
        """记录协商日志"""
        log = ProtocolSniffLog(
            timestamp=time.time(),
            client_ip=client_ip,
            server_host=host,
            server_port=port,
            client_alpn=client_alpn,
            server_alpn=server_alpn,
            negotiated_protocol=result.negotiated_protocol.value,
            fallback_occurred=result.reason is not None,
            fallback_reason=result.reason.value if result.reason else None,
            connection_duration=result.negotiation_time
        )
        
        with self._sniff_log_lock:
            self._sniff_logs.append(log)
            
            if len(self._sniff_logs) > self._max_sniff_logs:
                self._sniff_logs = self._sniff_logs[-self._max_sniff_logs:]
    
    def get_sniff_logs(self, limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        """获取嗅探日志"""
        with self._sniff_log_lock:
            logs = self._sniff_logs[offset:offset+limit]
            return [self._log_to_dict(log) for log in logs]
    
    def _log_to_dict(self, log: ProtocolSniffLog) -> Dict[str, Any]:
        """日志转字典"""
        return {
            'timestamp': log.timestamp,
            'client_ip': log.client_ip,
            'server_host': log.server_host,
            'server_port': log.server_port,
            'client_alpn': log.client_alpn,
            'server_alpn': log.server_alpn,
            'negotiated_protocol': log.negotiated_protocol,
            'fallback_occurred': log.fallback_occurred,
            'fallback_reason': log.fallback_reason,
            'connection_duration': log.connection_duration,
        }
    
    def export_sniff_logs(self, format: str = 'json') -> str:
        """导出嗅探日志"""
        with self._sniff_log_lock:
            logs = [self._log_to_dict(log) for log in self._sniff_logs]
        
        if format == 'json':
            return json.dumps(logs, indent=2)
        elif format == 'csv':
            if not logs:
                return ""
            headers = logs[0].keys()
            csv_lines = [','.join(headers)]
            for log in logs:
                csv_lines.append(','.join(str(log.get(h, '')) for h in headers))
            return '\n'.join(csv_lines)
        
        return json.dumps(logs, indent=2)
    
    def clear_sniff_logs(self):
        """清除嗅探日志"""
        with self._sniff_log_lock:
            self._sniff_logs.clear()
    
    # ==================== 协议缓存 ====================
    
    def _check_cache(self, host: str, port: int) -> Optional[ProtocolVersion]:
        """检查协议缓存"""
        key = f"{host}:{port}"
        with self._protocol_cache_lock:
            if key in self._protocol_cache:
                protocol, timestamp = self._protocol_cache[key]
                if time.time() - timestamp < self._cache_ttl:
                    return protocol
                else:
                    del self._protocol_cache[key]
        return None
    
    def _update_cache(self, host: str, port: int, protocol: ProtocolVersion):
        """更新协议缓存"""
        key = f"{host}:{port}"
        with self._protocol_cache_lock:
            self._protocol_cache[key] = (protocol, time.time())
    
    def clear_protocol_cache(self):
        """清除协议缓存"""
        with self._protocol_cache_lock:
            self._protocol_cache.clear()
    
    # ==================== 工具方法 ====================
    
    def _alpn_to_protocol(self, alpn_list: List[str]) -> ProtocolVersion:
        """ALPN转协议版本"""
        if not alpn_list:
            return ProtocolVersion.HTTP1
        
        first = alpn_list[0]
        if first in ['h3', 'hq']:
            return ProtocolVersion.HTTP3
        elif first in ['h2', 'h2c']:
            return ProtocolVersion.HTTP2
        return ProtocolVersion.HTTP1
    
    # ==================== 统计信息 ====================
    
    def get_stats(self) -> Dict[str, Any]:
        """获取统计信息"""
        with self._stats_lock:
            stats = dict(self._stats)
        
        with self._alpn_lock:
            stats['alpn_order'] = list(self._alpn_order)
        
        with self._forced_lock:
            stats['forced_rules'] = len(self._forced_downgrade_rules)
        
        with self._sniff_log_lock:
            stats['sniff_logs_count'] = len(self._sniff_logs)
        
        with self._protocol_cache_lock:
            stats['cache_size'] = len(self._protocol_cache)
        
        return stats
    
    def reset_stats(self):
        """重置统计信息"""
        with self._stats_lock:
            self._stats = {
                'total_negotiations': 0,
                'successful_h3': 0,
                'successful_h2': 0,
                'successful_h1': 0,
                'fallbacks_occurred': 0,
                'forced_downgrades': 0,
                'cache_hits': 0,
                'cache_misses': 0,
            }
