"""
协议协商与降级管理器
负责HTTP/2、HTTP/3协议识别、协商和降级
"""

import ssl
import logging
import asyncio
from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass
from datetime import datetime
from enum import Enum

logger = logging.getLogger(__name__)


class ProtocolVersion(Enum):
    """协议版本"""
    HTTP1 = "HTTP/1.1"
    HTTP2 = "HTTP/2"
    HTTP3 = "HTTP/3"


class ALPNProtocol(Enum):
    """ALPN协议标识"""
    H2 = "h2"
    H2C = "h2c"
    H3 = "h3"
    HTTP1 = "http/1.1"


@dataclass
class ProtocolInfo:
    """协议信息"""
    version: ProtocolVersion
    alpn_protocol: Optional[str] = None
    tls_version: Optional[str] = None
    is_secure: bool = True
    supports_multiplexing: bool = False
    supports_server_push: bool = False
    supports_zero_rtt: bool = False


class ProtocolNegotiator:
    """协议协商器"""
    
    def __init__(self):
        self._protocol_cache: Dict[str, ProtocolInfo] = {}
        self._fallback_order = [
            ProtocolVersion.HTTP3,
            ProtocolVersion.HTTP2,
            ProtocolVersion.HTTP1,
        ]
        self._h2_enabled = True
        self._h3_enabled = True
        self._h1_enabled = True
    
    def detect_protocol_from_alpn(self, alpn_protocols: List[str]) -> ProtocolInfo:
        """从ALPN扩展检测协议"""
        for protocol in alpn_protocols:
            if protocol == ALPNProtocol.H3.value and self._h3_enabled:
                return ProtocolInfo(
                    version=ProtocolVersion.HTTP3,
                    alpn_protocol=ALPNProtocol.H3.value,
                    is_secure=True,
                    supports_multiplexing=True,
                    supports_server_push=False,
                    supports_zero_rtt=True,
                )
            elif protocol == ALPNProtocol.H2.value and self._h2_enabled:
                return ProtocolInfo(
                    version=ProtocolVersion.HTTP2,
                    alpn_protocol=ALPNProtocol.H2.value,
                    is_secure=True,
                    supports_multiplexing=True,
                    supports_server_push=True,
                    supports_zero_rtt=False,
                )
            elif protocol == ALPNProtocol.H2C.value and self._h2_enabled:
                return ProtocolInfo(
                    version=ProtocolVersion.HTTP2,
                    alpn_protocol=ALPNProtocol.H2C.value,
                    is_secure=False,
                    supports_multiplexing=True,
                    supports_server_push=True,
                    supports_zero_rtt=False,
                )
        
        # 默认HTTP/1.1
        return ProtocolInfo(
            version=ProtocolVersion.HTTP1,
            alpn_protocol=ALPNProtocol.HTTP1.value,
            is_secure=False,
            supports_multiplexing=False,
            supports_server_push=False,
            supports_zero_rtt=False,
        )
    
    def detect_protocol_from_tls(self, ssl_object) -> ProtocolInfo:
        """从TLS连接检测协议"""
        try:
            alpn_protocol = ssl_object.selected_alpn_protocol()
            if alpn_protocol:
                return self.detect_protocol_from_alpn([alpn_protocol])
        except Exception as e:
            logger.warning(f"ALPN协议检测失败: {e}")
        
        # 使用TLS版本推断
        tls_version = ssl_object.version()
        if tls_version and 'TLSv1.3' in tls_version:
            return ProtocolInfo(
                version=ProtocolVersion.HTTP2,
                tls_version=tls_version,
                is_secure=True,
                supports_multiplexing=True,
                supports_server_push=True,
            )
        
        return ProtocolInfo(
            version=ProtocolVersion.HTTP1,
            tls_version=tls_version,
            is_secure=True,
        )
    
    def negotiate_protocol(self, host: str, port: int, 
                           client_alpn: List[str] = None) -> ProtocolInfo:
        """协商协议"""
        cache_key = f"{host}:{port}"
        
        # 检查缓存
        if cache_key in self._protocol_cache:
            return self._protocol_cache[cache_key]
        
        # 检测协议
        if client_alpn:
            protocol_info = self.detect_protocol_from_alpn(client_alpn)
        else:
            protocol_info = ProtocolInfo(version=ProtocolVersion.HTTP1)
        
        # 缓存结果
        self._protocol_cache[cache_key] = protocol_info
        
        logger.debug(f"协议协商: {host}:{port} -> {protocol_info.version.value}")
        
        return protocol_info
    
    def should_fallback(self, current_protocol: ProtocolVersion, 
                        error: Exception = None) -> Optional[ProtocolVersion]:
        """判断是否需要降级"""
        if current_protocol == ProtocolVersion.HTTP3 and self._h2_enabled:
            logger.info(f"HTTP/3降级到HTTP/2: {error}")
            return ProtocolVersion.HTTP2
        
        if current_protocol == ProtocolVersion.HTTP2 and self._h1_enabled:
            logger.info(f"HTTP/2降级到HTTP/1.1: {error}")
            return ProtocolVersion.HTTP1
        
        return None
    
    def get_fallback_chain(self, current_protocol: ProtocolVersion) -> List[ProtocolVersion]:
        """获取降级链"""
        idx = self._fallback_order.index(current_protocol)
        return self._fallback_order[idx + 1:]
    
    def create_ssl_context_for_protocol(self, protocol: ProtocolVersion,
                                        cert_manager=None) -> ssl.SSLContext:
        """为指定协议创建SSL上下文"""
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        
        if cert_manager:
            ctx.load_cert_chain(
                certfile=cert_manager.ca_cert_path,
                keyfile=cert_manager.ca_key_path,
            )
        
        if protocol == ProtocolVersion.HTTP3:
            # HTTP/3需要TLS 1.3
            ctx.minimum_version = ssl.TLSVersion.TLSv1_3
            ctx.set_alpn_protocols([ALPNProtocol.H3.value])
        elif protocol == ProtocolVersion.HTTP2:
            # HTTP/2支持TLS 1.2+
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            ctx.set_alpn_protocols([ALPNProtocol.H2.value, ALPNProtocol.H2C.value])
        else:
            # HTTP/1.1兼容所有TLS版本
            ctx.set_alpn_protocols([ALPNProtocol.HTTP1.value])
        
        return ctx
    
    def get_supported_protocols(self) -> List[ProtocolVersion]:
        """获取支持的协议列表"""
        supported = []
        if self._h3_enabled:
            supported.append(ProtocolVersion.HTTP3)
        if self._h2_enabled:
            supported.append(ProtocolVersion.HTTP2)
        if self._h1_enabled:
            supported.append(ProtocolVersion.HTTP1)
        return supported
    
    def enable_protocol(self, protocol: ProtocolVersion):
        """启用协议"""
        if protocol == ProtocolVersion.HTTP3:
            self._h3_enabled = True
        elif protocol == ProtocolVersion.HTTP2:
            self._h2_enabled = True
        elif protocol == ProtocolVersion.HTTP1:
            self._h1_enabled = True
    
    def disable_protocol(self, protocol: ProtocolVersion):
        """禁用协议"""
        if protocol == ProtocolVersion.HTTP3:
            self._h3_enabled = False
        elif protocol == ProtocolVersion.HTTP2:
            self._h2_enabled = False
        elif protocol == ProtocolVersion.HTTP1:
            self._h1_enabled = False
    
    def clear_cache(self):
        """清理协议缓存"""
        self._protocol_cache.clear()
    
    def get_stats(self) -> Dict[str, Any]:
        """获取统计信息"""
        return {
            'cached_connections': len(self._protocol_cache),
            'h2_enabled': self._h2_enabled,
            'h3_enabled': self._h3_enabled,
            'h1_enabled': self._h1_enabled,
            'supported_protocols': [p.value for p in self.get_supported_protocols()],
        }


class ProtocolConverter:
    """协议转换器"""
    
    @staticmethod
    def h2_to_http1(h2_headers: List[Tuple[str, str]], 
                    h2_body: bytes) -> Tuple[Dict[str, str], bytes]:
        """将HTTP/2转换为HTTP/1.1格式"""
        headers = {}
        method = "GET"
        path = "/"
        authority = ""
        
        for name, value in h2_headers:
            if name == ':method':
                method = value
            elif name == ':path':
                path = value
            elif name == ':authority':
                authority = value
            elif name == ':scheme':
                continue  # 忽略scheme
            else:
                headers[name] = value
        
        # 添加Host头部
        if authority and 'host' not in headers:
            headers['Host'] = authority
        
        return headers, h2_body
    
    @staticmethod
    def http1_to_h2(method: str, path: str, host: str,
                    http1_headers: Dict[str, str],
                    http1_body: bytes) -> List[Tuple[str, str]]:
        """将HTTP/1.1转换为HTTP/2格式"""
        h2_headers = [
            (':method', method),
            (':path', path),
            (':authority', host),
            (':scheme', 'https'),
        ]
        
        for name, value in http1_headers.items():
            if name.lower() not in ['host', 'connection', 'transfer-encoding']:
                h2_headers.append((name.lower(), value))
        
        return h2_headers
    
    @staticmethod
    def h3_to_http1(h3_headers: List[Tuple[str, str]],
                    h3_body: bytes) -> Tuple[Dict[str, str], bytes]:
        """将HTTP/3转换为HTTP/1.1格式"""
        return ProtocolConverter.h2_to_http1(h3_headers, h3_body)
    
    @staticmethod
    def http1_to_h3(method: str, path: str, host: str,
                    http1_headers: Dict[str, str],
                    http1_body: bytes) -> List[Tuple[str, str]]:
        """将HTTP/1.1转换为HTTP/3格式"""
        return ProtocolConverter.http1_to_h2(method, path, host, http1_headers, http1_body)
    
    @staticmethod
    def normalize_request(protocol: ProtocolVersion, 
                          request_data: Any) -> Dict[str, Any]:
        """标准化请求数据"""
        if protocol == ProtocolVersion.HTTP1:
            return request_data
        elif protocol == ProtocolVersion.HTTP2:
            # HTTP/2请求标准化
            if hasattr(request_data, 'to_dict'):
                return request_data.to_dict()
            return request_data
        elif protocol == ProtocolVersion.HTTP3:
            # HTTP/3请求标准化
            if hasattr(request_data, 'to_dict'):
                return request_data.to_dict()
            return request_data
        
        return request_data
    
    @staticmethod
    def normalize_response(protocol: ProtocolVersion,
                           response_data: Any) -> Dict[str, Any]:
        """标准化响应数据"""
        if protocol == ProtocolVersion.HTTP1:
            return response_data
        elif protocol == ProtocolVersion.HTTP2:
            # HTTP/2响应标准化
            if hasattr(response_data, 'to_dict'):
                return response_data.to_dict()
            return response_data
        elif protocol == ProtocolVersion.HTTP3:
            # HTTP/3响应标准化
            if hasattr(response_data, 'to_dict'):
                return response_data.to_dict()
            return response_data
        
        return response_data
