"""
反连平台深度集成模块 - MITM代理与反连平台深度集成
功能：
- 代理端口与反连平台端口共享多协议复用
- 反连请求到达时自动关联对应PoC，更新验证状态
- 反连记录包含完整请求/响应，可像普通流量一样查看和重放
- 支持一键将反连请求导出为PoC验证证据
"""

import re
import json
import uuid
import logging
from typing import Dict, List, Any, Optional, Callable
from datetime import datetime
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class ReverseProtocol(Enum):
    """反连协议类型"""
    HTTP = "http"
    HTTPS = "https"
    DNS = "dns"
    LDAP = "ldap"
    RMI = "rmi"
    FTP = "ftp"
    SMTP = "smtp"


class PoCStatus(Enum):
    """PoC验证状态"""
    PENDING = "pending"
    WAITING_CALLBACK = "waiting_callback"
    VERIFIED = "verified"
    FAILED = "failed"
    TIMEOUT = "timeout"


@dataclass
class ReverseConnection:
    """反连记录"""
    id: str
    timestamp: datetime
    source_ip: str
    source_port: int
    protocol: ReverseProtocol
    request_data: Dict[str, Any]
    response_data: Dict[str, Any]
    poc_id: Optional[str] = None
    poc_name: Optional[str] = None
    vulnerability_id: Optional[str] = None
    is_highlighted: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PoCCallback:
    """PoC回调记录"""
    id: str
    poc_id: str
    poc_name: str
    target_url: str
    callback_time: datetime
    reverse_connection_id: str
    status: PoCStatus
    evidence: Dict[str, Any] = field(default_factory=dict)


class ReverseConnectionDetector:
    """反连请求检测器"""
    
    def __init__(self):
        # DNS反连特征
        self._dns_patterns = [
            r'\.dnslog\.cn$',
            r'\.ceye\.io$',
            r'\.burpcollaborator\.net$',
            r'\.interact\.sh$',
            r'\.requestbin\.net$',
        ]
        
        # HTTP反连特征
        self._http_patterns = [
            r'/callback',
            r'/webhook',
            r'/notify',
            r'/ping',
            r'/health',
        ]
        
        # LDAP/RMI反连特征
        self._ldap_rmi_patterns = [
            r'ldap://',
            r'rmi://',
        ]
    
    def detect_reverse_connection(self, request_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """检测反连请求"""
        try:
            url = request_data.get('url', '')
            headers = request_data.get('headers', {})
            body = request_data.get('body', '')
            
            detection = {
                'is_reverse': False,
                'protocol': None,
                'confidence': 0.0,
                'indicators': [],
            }
            
            # 检测DNS反连
            for pattern in self._dns_patterns:
                if re.search(pattern, url, re.IGNORECASE):
                    detection['is_reverse'] = True
                    detection['protocol'] = ReverseProtocol.DNS
                    detection['confidence'] = 0.9
                    detection['indicators'].append('dns_reverse')
                    break
            
            # 检测HTTP反连
            for pattern in self._http_patterns:
                if re.search(pattern, url, re.IGNORECASE):
                    detection['is_reverse'] = True
                    detection['protocol'] = ReverseProtocol.HTTP
                    detection['confidence'] = max(detection['confidence'], 0.5)
                    detection['indicators'].append('http_reverse')
                    break
            
            # 检测LDAP/RMI反连
            for pattern in self._ldap_rmi_patterns:
                if re.search(pattern, url, re.IGNORECASE):
                    detection['is_reverse'] = True
                    if 'ldap' in pattern:
                        detection['protocol'] = ReverseProtocol.LDAP
                    else:
                        detection['protocol'] = ReverseProtocol.RMI
                    detection['confidence'] = 0.8
                    detection['indicators'].append('ldap_rmi_reverse')
                    break
            
            # 检测常见的反连平台域名
            from urllib.parse import urlparse
            parsed = urlparse(url)
            domain = parsed.hostname or ''
            
            # 检查是否是已知的反连平台
            known_platforms = [
                'dnslog.cn', 'ceye.io', 'burpcollaborator.net',
                'interact.sh', 'requestbin.net', 'webhook.site',
            ]
            
            for platform in known_platforms:
                if platform in domain:
                    detection['is_reverse'] = True
                    detection['confidence'] = max(detection['confidence'], 0.7)
                    detection['indicators'].append(f'known_platform_{platform}')
                    break
            
            return detection if detection['is_reverse'] else None
            
        except Exception as e:
            logger.error(f"反连检测失败: {e}")
            return None


class PoCCallbackMatcher:
    """PoC回调匹配器"""
    
    def __init__(self):
        self._pending_pocs: Dict[str, Dict[str, Any]] = {}
        self._callbacks: List[Callable] = []
    
    def register_poc(self, poc_id: str, poc_name: str, target_url: str, 
                     expected_callback: Dict[str, Any] = None):
        """注册待验证的PoC"""
        self._pending_pocs[poc_id] = {
            'poc_id': poc_id,
            'poc_name': poc_name,
            'target_url': target_url,
            'expected_callback': expected_callback,
            'registered_at': datetime.utcnow(),
            'status': PoCStatus.WAITING_CALLBACK,
        }
    
    def match_callback(self, reverse_connection: ReverseConnection) -> Optional[PoCCallback]:
        """匹配反连请求到对应的PoC"""
        try:
            request_data = reverse_connection.request_data
            source_ip = reverse_connection.source_ip
            
            # 遍历待验证的PoC
            for poc_id, poc_info in self._pending_pocs.items():
                target_url = poc_info['target_url']
                expected_callback = poc_info.get('expected_callback', {})
                
                # 检查是否匹配
                if self._is_callback_match(request_data, target_url, expected_callback):
                    # 创建回调记录
                    callback = PoCCallback(
                        id=str(uuid.uuid4())[:12],
                        poc_id=poc_id,
                        poc_name=poc_info['poc_name'],
                        target_url=target_url,
                        callback_time=reverse_connection.timestamp,
                        reverse_connection_id=reverse_connection.id,
                        status=PoCStatus.VERIFIED,
                        evidence={
                            'source_ip': source_ip,
                            'request_data': request_data,
                            'response_data': reverse_connection.response_data,
                        }
                    )
                    
                    # 更新PoC状态
                    poc_info['status'] = PoCStatus.VERIFIED
                    
                    # 通知匹配结果
                    for cb in self._callbacks:
                        try:
                            cb(callback)
                        except Exception as e:
                            logger.error(f"PoC回调通知失败: {e}")
                    
                    return callback
            
            return None
            
        except Exception as e:
            logger.error(f"PoC回调匹配失败: {e}")
            return None
    
    def on_callback_matched(self, callback: Callable):
        """注册回调匹配通知"""
        self._callbacks.append(callback)
    
    def _is_callback_match(self, request_data: Dict, target_url: str, 
                           expected_callback: Dict) -> bool:
        """检查是否为预期回调"""
        try:
            # 检查来源IP
            if expected_callback.get('source_ip'):
                if request_data.get('client_ip') != expected_callback['source_ip']:
                    return False
            
            # 检查请求路径
            if expected_callback.get('path'):
                url = request_data.get('url', '')
                if expected_callback['path'] not in url:
                    return False
            
            # 检查请求体特征
            if expected_callback.get('body_pattern'):
                body = request_data.get('body', '')
                if not re.search(expected_callback['body_pattern'], body):
                    return False
            
            # 检查Header特征
            if expected_callback.get('headers'):
                headers = request_data.get('headers', {})
                for key, value in expected_callback['headers'].items():
                    if headers.get(key) != value:
                        return False
            
            return True
            
        except:
            return False


class ReverseConnectionManager:
    """反连记录管理器"""
    
    def __init__(self):
        self._connections: Dict[str, ReverseConnection] = {}
        self._poc_callbacks: Dict[str, PoCCallback] = {}
        self._callbacks: Dict[str, List[Callable]] = {
            'on_new_connection': [],
            'on_poc_matched': [],
        }
    
    def add_connection(self, connection: ReverseConnection):
        """添加反连记录"""
        self._connections[connection.id] = connection
        
        # 通知新连接
        for callback in self._callbacks['on_new_connection']:
            try:
                callback(connection)
            except Exception as e:
                logger.error(f"新反连通知失败: {e}")
    
    def add_poc_callback(self, callback: PoCCallback):
        """添加PoC回调记录"""
        self._poc_callbacks[callback.id] = callback
        
        # 更新对应的反连记录
        if callback.reverse_connection_id in self._connections:
            conn = self._connections[callback.reverse_connection_id]
            conn.poc_id = callback.poc_id
            conn.poc_name = callback.poc_name
            conn.is_highlighted = True
        
        # 通知PoC匹配
        for callback_fn in self._callbacks['on_poc_matched']:
            try:
                callback_fn(callback)
            except Exception as e:
                logger.error(f"PoC匹配通知失败: {e}")
    
    def get_connections(self) -> List[ReverseConnection]:
        """获取所有反连记录"""
        return list(self._connections.values())
    
    def get_poc_callbacks(self) -> List[PoCCallback]:
        """获取所有PoC回调记录"""
        return list(self._poc_callbacks.values())
    
    def export_as_evidence(self, connection_id: str) -> Optional[Dict[str, Any]]:
        """导出为PoC验证证据"""
        if connection_id not in self._connections:
            return None
        
        connection = self._connections[connection_id]
        
        evidence = {
            'evidence_id': str(uuid.uuid4())[:12],
            'exported_at': datetime.utcnow(),
            'reverse_connection': {
                'id': connection.id,
                'timestamp': connection.timestamp.isoformat(),
                'source_ip': connection.source_ip,
                'protocol': connection.protocol.value,
                'request': connection.request_data,
                'response': connection.response_data,
            },
        }
        
        # 如果有关联的PoC，添加PoC信息
        if connection.poc_id:
            evidence['poc'] = {
                'id': connection.poc_id,
                'name': connection.poc_name,
                'vulnerability_id': connection.vulnerability_id,
            }
        
        return evidence
    
    def on_new_connection(self, callback: Callable):
        """注册新反连回调"""
        self._callbacks['on_new_connection'].append(callback)
    
    def on_poc_matched(self, callback: Callable):
        """注册PoC匹配回调"""
        self._callbacks['on_poc_matched'].append(callback)


class ReversePlatformLinkage:
    """反连平台联动引擎"""
    
    def __init__(self):
        self.detector = ReverseConnectionDetector()
        self.poc_matcher = PoCCallbackMatcher()
        self.connection_manager = ReverseConnectionManager()
        
        self._reverse_callbacks: List[Callable] = []
        self._poc_match_callbacks: List[Callable] = []
        
        # 注册内部回调
        self.poc_matcher.on_callback_matched(self._on_poc_matched)
        self.connection_manager.on_poc_matched(self._on_poc_matched_internal)
    
    def process_traffic(self, request_data: Dict[str, Any], 
                       response_data: Dict[str, Any]):
        """处理流量，检测反连请求"""
        try:
            # 检测反连请求
            detection = self.detector.detect_reverse_connection(request_data)
            
            if detection:
                # 创建反连记录
                connection = ReverseConnection(
                    id=str(uuid.uuid4())[:12],
                    timestamp=datetime.utcnow(),
                    source_ip=request_data.get('client_ip', ''),
                    source_port=request_data.get('client_port', 0),
                    protocol=detection['protocol'] or ReverseProtocol.HTTP,
                    request_data=request_data,
                    response_data=response_data,
                    is_highlighted=True,
                    metadata=detection,
                )
                
                # 添加到管理器
                self.connection_manager.add_connection(connection)
                
                # 尝试匹配PoC
                matched_callback = self.poc_matcher.match_callback(connection)
                
                if matched_callback:
                    self.connection_manager.add_poc_callback(matched_callback)
                
                # 通知反连事件
                for callback in self._reverse_callbacks:
                    try:
                        callback(connection, detection)
                    except Exception as e:
                        logger.error(f"反连通知失败: {e}")
            
        except Exception as e:
            logger.error(f"反连平台联动处理失败: {e}")
    
    def register_poc(self, poc_id: str, poc_name: str, target_url: str,
                     expected_callback: Dict[str, Any] = None):
        """注册待验证的PoC"""
        self.poc_matcher.register_poc(poc_id, poc_name, target_url, expected_callback)
    
    def export_evidence(self, connection_id: str) -> Optional[Dict[str, Any]]:
        """导出为PoC验证证据"""
        return self.connection_manager.export_as_evidence(connection_id)
    
    def get_connections(self) -> List[ReverseConnection]:
        """获取所有反连记录"""
        return self.connection_manager.get_connections()
    
    def get_poc_callbacks(self) -> List[PoCCallback]:
        """获取所有PoC回调记录"""
        return self.connection_manager.get_poc_callbacks()
    
    def on_reverse_connection(self, callback: Callable):
        """注册反连回调"""
        self._reverse_callbacks.append(callback)
    
    def on_poc_matched(self, callback: Callable):
        """注册PoC匹配回调"""
        self._poc_match_callbacks.append(callback)
    
    def _on_poc_matched(self, callback: PoCCallback):
        """PoC匹配内部回调"""
        for cb in self._poc_match_callbacks:
            try:
                cb(callback)
            except Exception as e:
                logger.error(f"PoC匹配通知失败: {e}")
    
    def _on_poc_matched_internal(self, callback: PoCCallback):
        """PoC匹配内部回调（管理器级别）"""
        pass
