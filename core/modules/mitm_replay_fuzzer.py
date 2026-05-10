"""
协议重放与Fuzzer适配器
包含协议保持重放、QUIC重放、Fuzzer协议适配、Fuzztag协议感知等功能
"""

import logging
import time
import copy
from typing import Dict, List, Optional, Tuple, Any, Callable
from dataclasses import dataclass, field
from collections import defaultdict
from enum import Enum
import threading
import json

logger = logging.getLogger(__name__)


class ProtocolType(Enum):
    """协议类型"""
    HTTP1 = "HTTP/1.1"
    HTTP2 = "HTTP/2"
    HTTP3 = "HTTP/3"


class ReplayMode(Enum):
    """重放模式"""
    SAME_PROTOCOL = "same_protocol"
    FORCE_HTTP1 = "force_http1"
    FORCE_HTTP2 = "force_http2"
    FORCE_HTTP3 = "force_http3"
    AUTO_DETECT = "auto_detect"


@dataclass
class ReplayRequest:
    """重放请求"""
    id: str
    original_protocol: ProtocolType
    target_protocol: ProtocolType
    method: str
    url: str
    headers: Dict[str, str]
    body: bytes
    priority: Optional[int] = None
    stream_id: Optional[int] = None
    connection_id: Optional[str] = None
    is_zero_rtt: bool = False
    timestamp: float = 0.0
    hpack_context: Optional[bytes] = None


@dataclass
class ReplayResponse:
    """重放响应"""
    request_id: str
    status_code: int
    headers: Dict[str, str]
    body: bytes
    protocol_used: ProtocolType
    response_time: float
    success: bool
    error_message: Optional[str] = None


@dataclass
class FuzzPayload:
    """Fuzz载荷"""
    original_value: str
    fuzzed_value: str
    fuzz_type: str
    protocol: ProtocolType
    target_field: str
    timestamp: float = 0.0


class ProtocolReplayAdapter:
    """协议重放适配器"""
    
    def __init__(self):
        self._replay_history: List[Dict[str, Any]] = []
        self._replay_lock = threading.Lock()
        self._hpack_contexts: Dict[str, bytes] = {}
        self._hpack_lock = threading.Lock()
        
        self._stats = {
            'total_replays': 0,
            'successful_replays': 0,
            'failed_replays': 0,
            'protocol_conversions': 0,
            'zero_rtt_replays': 0,
        }
        self._stats_lock = threading.Lock()
    
    def prepare_replay(self, original_request: Dict[str, Any],
                      mode: ReplayMode = ReplayMode.SAME_PROTOCOL) -> ReplayRequest:
        """准备重放请求"""
        protocol = ProtocolType(original_request.get('protocol', 'HTTP/1.1'))
        
        if mode == ReplayMode.SAME_PROTOCOL:
            target_protocol = protocol
        elif mode == ReplayMode.FORCE_HTTP1:
            target_protocol = ProtocolType.HTTP1
        elif mode == ReplayMode.FORCE_HTTP2:
            target_protocol = ProtocolType.HTTP2
        elif mode == ReplayMode.FORCE_HTTP3:
            target_protocol = ProtocolType.HTTP3
        else:
            target_protocol = protocol
        
        replay = ReplayRequest(
            id=original_request.get('id', str(time.time())),
            original_protocol=protocol,
            target_protocol=target_protocol,
            method=original_request.get('method', 'GET'),
            url=original_request.get('url', ''),
            headers=dict(original_request.get('headers', {})),
            body=original_request.get('body', b''),
            priority=original_request.get('priority'),
            stream_id=original_request.get('stream_id'),
            connection_id=original_request.get('connection_id'),
            is_zero_rtt=original_request.get('is_zero_rtt', False),
            timestamp=time.time(),
        )
        
        if protocol == ProtocolType.HTTP2:
            with self._hpack_lock:
                replay.hpack_context = self._hpack_contexts.get(
                    original_request.get('connection_id', '')
                )
        
        logger.debug(f"重放准备: {replay.method} {replay.url} "
                    f"({replay.original_protocol.value} -> {replay.target_protocol.value})")
        
        return replay
    
    def convert_request_for_protocol(self, request: ReplayRequest) -> Dict[str, Any]:
        """转换请求以适配目标协议"""
        if request.original_protocol == request.target_protocol:
            return self._build_same_protocol_request(request)
        
        if request.target_protocol == ProtocolType.HTTP1:
            return self._convert_to_http1(request)
        elif request.target_protocol == ProtocolType.HTTP2:
            return self._convert_to_http2(request)
        elif request.target_protocol == ProtocolType.HTTP3:
            return self._convert_to_http3(request)
        
        return self._build_same_protocol_request(request)
    
    def _build_same_protocol_request(self, request: ReplayRequest) -> Dict[str, Any]:
        """构建相同协议请求"""
        return {
            'method': request.method,
            'url': request.url,
            'headers': request.headers,
            'body': request.body,
            'protocol': request.target_protocol.value,
            'priority': request.priority,
            'stream_id': request.stream_id,
        }
    
    def _convert_to_http1(self, request: ReplayRequest) -> Dict[str, Any]:
        """转换为HTTP/1.1"""
        from urllib.parse import urlparse
        parsed = urlparse(request.url)
        
        headers = dict(request.headers)
        headers['Host'] = parsed.hostname or ''
        
        for pseudo_header in [':method', ':path', ':authority', ':scheme']:
            headers.pop(pseudo_header, None)
        
        headers.pop('connection', None)
        headers.pop('transfer-encoding', None)
        
        with self._stats_lock:
            self._stats['protocol_conversions'] += 1
        
        return {
            'method': request.method,
            'url': request.url,
            'headers': headers,
            'body': request.body,
            'protocol': ProtocolType.HTTP1.value,
        }
    
    def _convert_to_http2(self, request: ReplayRequest) -> Dict[str, Any]:
        """转换为HTTP/2"""
        from urllib.parse import urlparse
        parsed = urlparse(request.url)
        
        h2_headers = [
            (':method', request.method),
            (':path', parsed.path or '/'),
            (':authority', parsed.hostname or ''),
            (':scheme', parsed.scheme or 'https'),
        ]
        
        for name, value in request.headers.items():
            if not name.startswith(':') and name.lower() not in ['host', 'connection', 'transfer-encoding']:
                h2_headers.append((name.lower(), value))
        
        with self._stats_lock:
            self._stats['protocol_conversions'] += 1
        
        return {
            'method': request.method,
            'url': request.url,
            'headers': h2_headers,
            'body': request.body,
            'protocol': ProtocolType.HTTP2.value,
            'priority': request.priority,
            'hpack_context': request.hpack_context,
        }
    
    def _convert_to_http3(self, request: ReplayRequest) -> Dict[str, Any]:
        """转换为HTTP/3"""
        from urllib.parse import urlparse
        parsed = urlparse(request.url)
        
        h3_headers = [
            (':method', request.method),
            (':path', parsed.path or '/'),
            (':authority', parsed.hostname or ''),
            (':scheme', parsed.scheme or 'https'),
        ]
        
        for name, value in request.headers.items():
            if not name.startswith(':') and name.lower() not in ['host', 'connection', 'transfer-encoding']:
                h3_headers.append((name.lower(), value))
        
        with self._stats_lock:
            self._stats['protocol_conversions'] += 1
        
        return {
            'method': request.method,
            'url': request.url,
            'headers': h3_headers,
            'body': request.body,
            'protocol': ProtocolType.HTTP3.value,
            'is_zero_rtt': request.is_zero_rtt,
        }
    
    def record_replay_result(self, request_id: str, response: ReplayResponse):
        """记录重放结果"""
        with self._replay_lock:
            self._replay_history.append({
                'request_id': request_id,
                'response': {
                    'status_code': response.status_code,
                    'protocol_used': response.protocol_used.value,
                    'response_time': response.response_time,
                    'success': response.success,
                    'error_message': response.error_message,
                },
                'timestamp': time.time(),
            })
        
        with self._stats_lock:
            self._stats['total_replays'] += 1
            if response.success:
                self._stats['successful_replays'] += 1
            else:
                self._stats['failed_replays'] += 1
    
    def get_replay_history(self, limit: int = 100) -> List[Dict[str, Any]]:
        """获取重放历史"""
        with self._replay_lock:
            return list(self._replay_history[-limit:])
    
    def get_stats(self) -> Dict[str, Any]:
        """获取统计信息"""
        with self._stats_lock:
            return dict(self._stats)


class FuzzerProtocolAdapter:
    """Fuzzer协议适配器"""
    
    def __init__(self):
        self._protocol_templates: Dict[ProtocolType, Dict[str, Any]] = {}
        self._fuzz_history: List[FuzzPayload] = []
        self._fuzz_lock = threading.Lock()
        
        self._init_protocol_templates()
        
        self._stats = {
            'total_fuzz_requests': 0,
            'protocol_adaptations': 0,
            'successful_fuzz': 0,
            'failed_fuzz': 0,
        }
        self._stats_lock = threading.Lock()
    
    def _init_protocol_templates(self):
        """初始化协议模板"""
        self._protocol_templates[ProtocolType.HTTP1] = {
            'request_line': '{method} {path} HTTP/1.1',
            'headers_format': '{name}: {value}',
            'line_ending': '\r\n',
            'supports_multiplexing': False,
            'supports_priority': False,
        }
        
        self._protocol_templates[ProtocolType.HTTP2] = {
            'pseudo_headers': [':method', ':path', ':authority', ':scheme'],
            'supports_multiplexing': True,
            'supports_priority': True,
            'supports_push': True,
            'header_compression': 'HPACK',
        }
        
        self._protocol_templates[ProtocolType.HTTP3] = {
            'pseudo_headers': [':method', ':path', ':authority', ':scheme'],
            'supports_multiplexing': True,
            'supports_priority': True,
            'supports_zero_rtt': True,
            'header_compression': 'QPACK',
            'transport': 'QUIC',
        }
    
    def detect_target_protocol(self, url: str, headers: Dict[str, str] = None) -> ProtocolType:
        """检测目标支持的协议"""
        if headers:
            alt_svc = headers.get('alt-svc', '')
            if 'h3=' in alt_svc:
                return ProtocolType.HTTP3
            if 'h2=' in alt_svc:
                return ProtocolType.HTTP2
        
        return ProtocolType.HTTP1
    
    def adapt_fuzz_payload(self, payload: str, target_protocol: ProtocolType,
                          field: str) -> Dict[str, Any]:
        """适配Fuzz载荷到目标协议"""
        template = self._protocol_templates.get(target_protocol, {})
        
        adapted = {
            'original': payload,
            'protocol': target_protocol.value,
            'field': field,
            'template': template,
        }
        
        if target_protocol == ProtocolType.HTTP2:
            adapted['fuzzed'] = self._adapt_for_http2(payload, field)
        elif target_protocol == ProtocolType.HTTP3:
            adapted['fuzzed'] = self._adapt_for_http3(payload, field)
        else:
            adapted['fuzzed'] = self._adapt_for_http1(payload, field)
        
        with self._stats_lock:
            self._stats['protocol_adaptations'] += 1
        
        return adapted
    
    def _adapt_for_http1(self, payload: str, field: str) -> str:
        """为HTTP/1.1适配"""
        if field == 'request_line':
            return f"GET {payload} HTTP/1.1"
        elif field == 'header':
            return f"X-Fuzz: {payload}"
        return payload
    
    def _adapt_for_http2(self, payload: str, field: str) -> str:
        """为HTTP/2适配"""
        if field.startswith(':'):
            return payload
        elif field == 'header':
            return f"x-fuzz: {payload}"
        return payload
    
    def _adapt_for_http3(self, payload: str, field: str) -> str:
        """为HTTP/3适配"""
        if field.startswith(':'):
            return payload
        elif field == 'header':
            return f"x-fuzz: {payload}"
        return payload
    
    def generate_fuzz_variants(self, base_payload: str, 
                              protocol: ProtocolType) -> List[FuzzPayload]:
        """生成Fuzz变体"""
        variants = []
        
        fuzz_types = [
            ('overflow', base_payload * 100),
            ('special_chars', '!@#$%^&*()_+-=[]{}|;:,.<>?'),
            ('unicode', '\u0000\u0001\u0002\u0003'),
            ('null_byte', base_payload + '\x00'),
            ('newline_injection', base_payload + '\r\n\r\nGET /injected HTTP/1.1'),
        ]
        
        for fuzz_type, fuzzed_value in fuzz_types:
            variant = FuzzPayload(
                original_value=base_payload,
                fuzzed_value=fuzzed_value,
                fuzz_type=fuzz_type,
                protocol=protocol,
                target_field='body',
                timestamp=time.time(),
            )
            variants.append(variant)
        
        with self._fuzz_lock:
            self._fuzz_history.extend(variants)
        
        with self._stats_lock:
            self._stats['total_fuzz_requests'] += len(variants)
        
        return variants
    
    def get_protocol_info(self, protocol: ProtocolType) -> Dict[str, Any]:
        """获取协议信息"""
        return self._protocol_templates.get(protocol, {})
    
    def get_fuzz_history(self, limit: int = 100) -> List[Dict[str, Any]]:
        """获取Fuzz历史"""
        with self._fuzz_lock:
            return [
                {
                    'original': v.original_value,
                    'fuzzed': v.fuzzed_value,
                    'type': v.fuzz_type,
                    'protocol': v.protocol.value,
                    'field': v.target_field,
                    'timestamp': v.timestamp,
                }
                for v in self._fuzz_history[-limit:]
            ]
    
    def get_stats(self) -> Dict[str, Any]:
        """获取统计信息"""
        with self._stats_lock:
            return dict(self._stats)


class FuzztagProtocolResolver:
    """Fuzztag协议解析器"""
    
    @staticmethod
    def resolve_fuzztag(tag: str, request_context: Dict[str, Any]) -> str:
        """解析Fuzztag"""
        if tag == '${protocol}':
            return request_context.get('protocol', 'HTTP/1.1')
        elif tag == '${protocol_version}':
            protocol = request_context.get('protocol', 'HTTP/1.1')
            if protocol == 'HTTP/3':
                return '3'
            elif protocol == 'HTTP/2':
                return '2'
            return '1.1'
        elif tag == '${stream_id}':
            return str(request_context.get('stream_id', 0))
        elif tag == '${connection_id}':
            return str(request_context.get('connection_id', ''))
        elif tag == '${is_multiplexed}':
            protocol = request_context.get('protocol', 'HTTP/1.1')
            return 'true' if protocol in ['HTTP/2', 'HTTP/3'] else 'false'
        elif tag == '${priority}':
            return str(request_context.get('priority', 0))
        elif tag == '${is_zero_rtt}':
            return 'true' if request_context.get('is_zero_rtt', False) else 'false'
        elif tag == '${hpack_table_size}':
            return str(request_context.get('hpack_table_size', 4096))
        
        return tag
    
    @staticmethod
    def resolve_all_fuzztags(payload: str, request_context: Dict[str, Any]) -> str:
        """解析所有Fuzztag"""
        import re
        pattern = r'\$\{(\w+)\}'
        
        def replacer(match):
            tag = '${' + match.group(1) + '}'
            return FuzztagProtocolResolver.resolve_fuzztag(tag, request_context)
        
        return re.sub(pattern, replacer, payload)
