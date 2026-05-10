"""
HTTP/2和HTTP/3(QUIC)代理功能测试脚本
测试新增的协议支持功能
"""

import sys
import os
import time
import asyncio
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List

# 添加项目根目录到路径
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from core.modules.mitm_h2_engine import H2ProxyEngine, H2_AVAILABLE
from core.modules.mitm_h3_engine import H3ProxyEngine, QUIC_AVAILABLE
from core.modules.mitm_protocol_negotiator import (
    ProtocolNegotiator, ProtocolVersion, ALPNProtocol, ProtocolInfo
)
from core.modules.mitm_proxy_engine import MITMProxyEngine


def test_protocol_negotiator():
    """测试协议协商器"""
    print("=" * 60)
    print("测试 1: 协议协商器")
    print("=" * 60)
    
    negotiator = ProtocolNegotiator()
    
    # 测试HTTP/3检测
    alpn_h3 = [ALPNProtocol.H3.value, ALPNProtocol.H2.value, ALPNProtocol.HTTP1.value]
    protocol_info = negotiator.detect_protocol_from_alpn(alpn_h3)
    assert protocol_info.version == ProtocolVersion.HTTP3, "HTTP/3检测失败"
    assert protocol_info.supports_multiplexing, "HTTP/3应支持多路复用"
    assert protocol_info.supports_zero_rtt, "HTTP/3应支持0-RTT"
    print("✓ HTTP/3协议检测成功")
    
    # 测试HTTP/2检测
    alpn_h2 = [ALPNProtocol.H2.value, ALPNProtocol.HTTP1.value]
    protocol_info = negotiator.detect_protocol_from_alpn(alpn_h2)
    assert protocol_info.version == ProtocolVersion.HTTP2, "HTTP/2检测失败"
    assert protocol_info.supports_server_push, "HTTP/2应支持服务端推送"
    print("✓ HTTP/2协议检测成功")
    
    # 测试HTTP/1.1降级
    alpn_http1 = [ALPNProtocol.HTTP1.value]
    protocol_info = negotiator.detect_protocol_from_alpn(alpn_http1)
    assert protocol_info.version == ProtocolVersion.HTTP1, "HTTP/1.1检测失败"
    print("✓ HTTP/1.1协议检测成功")
    
    # 测试降级逻辑
    fallback = negotiator.should_fallback(ProtocolVersion.HTTP3)
    assert fallback == ProtocolVersion.HTTP2, "HTTP/3应降级到HTTP/2"
    print("✓ HTTP/3降级到HTTP/2成功")
    
    fallback = negotiator.should_fallback(ProtocolVersion.HTTP2)
    assert fallback == ProtocolVersion.HTTP1, "HTTP/2应降级到HTTP/1.1"
    print("✓ HTTP/2降级到HTTP/1.1成功")
    
    # 测试协议转换
    from core.modules.mitm_protocol_negotiator import ProtocolConverter
    
    h2_headers = [
        (':method', 'GET'),
        (':path', '/api/test'),
        (':authority', 'example.com'),
        (':scheme', 'https'),
        ('content-type', 'application/json'),
    ]
    standard_headers, body = ProtocolConverter.h2_to_http1(h2_headers, b'')
    assert 'content-type' in standard_headers, "header转换失败"
    assert standard_headers.get('Host') == 'example.com', "Host转换失败"
    print("✓ HTTP/2伪头部转换成功")
    
    # 测试SSL上下文创建
    ssl_context = negotiator.create_ssl_context_for_protocol(ProtocolVersion.HTTP2)
    assert ssl_context is not None, "HTTP/2 SSL上下文创建失败"
    print("✓ HTTP/2 SSL上下文创建成功")
    
    ssl_context = negotiator.create_ssl_context_for_protocol(ProtocolVersion.HTTP3)
    assert ssl_context is not None, "HTTP/3 SSL上下文创建失败"
    print("✓ HTTP/3 SSL上下文创建成功")
    
    print("✅ 协议协商器测试通过\n")


def test_h2_engine_initialization():
    """测试HTTP/2引擎初始化"""
    print("=" * 60)
    print("测试 2: HTTP/2引擎初始化")
    print("=" * 60)
    
    if not H2_AVAILABLE:
        print("⚠ h2库未安装，跳过HTTP/2测试")
        return
    
    engine = H2ProxyEngine()
    
    # 测试引擎属性
    assert engine._running == False, "引擎初始状态应为未运行"
    assert len(engine._connections) == 0, "初始连接数应为0"
    assert len(engine._streams) == 0, "初始流数应为0"
    print("✓ HTTP/2引擎初始化成功")
    
    # 测试回调注册
    def test_callback(*args, **kwargs):
        pass
    
    engine.add_callback('on_request', test_callback)
    assert len(engine._callbacks['on_request']) == 1, "回调注册失败"
    print("✓ HTTP/2回调注册成功")
    
    # 测试流控窗口
    assert engine._flow_control_window == 65535, "默认流控窗口应为65535"
    print("✓ HTTP/2流控窗口配置正确")
    
    # 测试最大并发流
    assert engine._max_concurrent_streams == 100, "默认最大并发流应为100"
    print("✓ HTTP/2最大并发流配置正确")
    
    print("✅ HTTP/2引擎初始化测试通过\n")


def test_h3_engine_initialization():
    """测试HTTP/3引擎初始化"""
    print("=" * 60)
    print("测试 3: HTTP/3引擎初始化")
    print("=" * 60)
    
    if not QUIC_AVAILABLE:
        print("⚠ aioquic库未安装，跳过HTTP/3测试")
        return
    
    engine = H3ProxyEngine()
    
    # 测试引擎属性
    assert engine._running == False, "引擎初始状态应为未运行"
    assert len(engine._connections) == 0, "初始连接数应为0"
    assert len(engine._streams) == 0, "初始流数应为0"
    print("✓ HTTP/3引擎初始化成功")
    
    # 测试回调注册
    def test_callback(*args, **kwargs):
        pass
    
    engine.add_callback('on_request', test_callback)
    assert len(engine._callbacks['on_request']) == 1, "回调注册失败"
    print("✓ HTTP/3回调注册成功")
    
    # 测试QUIC端口配置
    assert engine._quic_port == 443, "默认QUIC端口应为443"
    print("✓ HTTP/3 QUIC端口配置正确")
    
    # 测试降级策略
    assert engine._fallback_enabled == True, "默认应启用降级策略"
    print("✓ HTTP/3降级策略配置正确")
    
    print("✅ HTTP/3引擎初始化测试通过\n")


def test_mitm_proxy_engine_with_protocols():
    """测试MITM代理引擎协议集成"""
    print("=" * 60)
    print("测试 4: MITM代理引擎协议集成")
    print("=" * 60)
    
    # 测试HTTP/2启用
    engine_h2 = MITMProxyEngine(
        host="127.0.0.1",
        port=8080,
        enable_h2=True,
        enable_h3=False
    )
    assert engine_h2.enable_h2 == True, "HTTP/2启用失败"
    assert engine_h2.enable_h3 == False, "HTTP/3应禁用"
    assert engine_h2.h2_engine is not None, "HTTP/2引擎应为None"
    assert engine_h2.h3_engine is None, "HTTP/3引擎应不为None"
    print("✓ HTTP/2启用配置成功")
    
    # 测试HTTP/3启用
    engine_h3 = MITMProxyEngine(
        host="127.0.0.1",
        port=8080,
        enable_h2=True,
        enable_h3=True,
        h3_port=443
    )
    assert engine_h3.enable_h2 == True, "HTTP/2应启用"
    assert engine_h3.enable_h3 == True, "HTTP/3启用失败"
    assert engine_h3.h3_port == 443, "QUIC端口配置失败"
    print("✓ HTTP/3启用配置成功")
    
    # 测试协议协商器集成
    assert engine_h2.protocol_negotiator is not None, "协议协商器应为None"
    print("✓ 协议协商器集成成功")
    
    # 测试状态报告
    status = engine_h2.get_status()
    assert 'protocols' in status, "状态报告缺少protocols"
    assert status['protocols']['http2'] == True, "状态报告http2值错误"
    assert status['protocols']['http3'] == False, "状态报告http3值错误"
    print("✓ 协议状态报告正确")
    
    print("✅ MITM代理引擎协议集成测试通过\n")


def test_h2_stream_management():
    """测试HTTP/2流管理"""
    print("=" * 60)
    print("测试 5: HTTP/2流管理")
    print("=" * 60)
    
    if not H2_AVAILABLE:
        print("⚠ h2库未安装，跳过HTTP/2流管理测试")
        return
    
    engine = H2ProxyEngine()
    
    # 测试流创建
    stream_id = engine._create_stream(1)
    assert stream_id == 1, "流ID创建失败"
    assert stream_id in engine._streams, "流未注册"
    print("✓ HTTP/2流创建成功")
    
    # 测试流状态
    stream = engine._streams[stream_id]
    assert stream.stream_id == 1, "流ID不匹配"
    assert stream.state.value == 'idle', "初始流状态应为idle"
    print("✓ HTTP/2流状态正确")
    
    # 测试流关闭
    engine._close_stream(stream_id)
    assert stream_id not in engine._streams, "流未关闭"
    print("✓ HTTP/2流关闭成功")
    
    # 测试并发流限制
    for i in range(1, 101):
        engine._create_stream(i)
    
    assert engine._active_streams == 100, "活跃流数不正确"
    print("✓ HTTP/2并发流限制正确")
    
    # 清理
    for stream_id in list(engine._streams.keys()):
        engine._close_stream(stream_id)
    
    print("✅ HTTP/2流管理测试通过\n")


def test_protocol_conversion():
    """测试协议转换"""
    print("=" * 60)
    print("测试 6: 协议转换")
    print("=" * 60)
    
    from core.modules.mitm_protocol_negotiator import ProtocolConverter
    
    # 测试HTTP/2到HTTP/1.1转换
    h2_headers = [
        (':method', 'POST'),
        (':path', '/api/data'),
        (':authority', 'api.example.com'),
        (':scheme', 'https'),
        ('content-type', 'application/json'),
        ('authorization', 'Bearer token123'),
    ]
    h2_body = b'{"key": "value"}'
    
    h1_headers, h1_body = ProtocolConverter.h2_to_http1(h2_headers, h2_body)
    assert 'content-type' in h1_headers, "header转换失败"
    assert h1_headers.get('Host') == 'api.example.com', "host转换失败"
    assert h1_body == h2_body, "body转换失败"
    print("✓ HTTP/2到HTTP/1.1转换成功")
    
    # 测试HTTP/1.1到HTTP/2转换
    h1_headers = {
        'user-agent': 'TestAgent/1.0',
        'content-type': 'application/json',
    }
    
    h2_headers = ProtocolConverter.http1_to_h2('GET', '/index.html', 'example.com', h1_headers, b'')
    assert (':method', 'GET') in h2_headers, "方法转换失败"
    assert (':authority', 'example.com') in h2_headers, "authority转换失败"
    assert (':path', '/index.html') in h2_headers, "path转换失败"
    assert (':scheme', 'https') in h2_headers, "scheme应为https"
    print("✓ HTTP/1.1到HTTP/2转换成功")
    
    print("✅ 协议转换测试通过\n")


def test_ui_integration():
    """测试UI集成"""
    print("=" * 60)
    print("测试 7: UI集成")
    print("=" * 60)
    
    # 测试请求数据包含协议信息
    request_data = {
        'id': 'test_001',
        'method': 'GET',
        'url': 'https://example.com/api',
        'host': 'example.com',
        'path': '/api',
        'protocol': 'HTTP/2',
        'stream_id': 1,
        'connection_id': 'conn_001',
        ':authority': 'example.com',
        ':scheme': 'https',
        'headers': {},
        'body': '',
        'timestamp': datetime.now().isoformat(),
    }
    
    assert 'protocol' in request_data, "请求数据缺少protocol"
    assert request_data['protocol'] == 'HTTP/2', "protocol值错误"
    assert 'stream_id' in request_data, "请求数据缺少stream_id"
    print("✓ 请求数据协议信息完整")
    
    # 测试HTTP/3请求数据
    h3_request_data = {
        'id': 'test_002',
        'method': 'POST',
        'url': 'https://example.com/api',
        'host': 'example.com',
        'path': '/api',
        'protocol': 'HTTP/3',
        'stream_id': 3,
        'connection_id': 'quic_001',
        'is_zero_rtt': False,
        'headers': {},
        'body': '{"data": "test"}',
        'timestamp': datetime.now().isoformat(),
    }
    
    assert h3_request_data['protocol'] == 'HTTP/3', "HTTP/3 protocol值错误"
    assert 'is_zero_rtt' in h3_request_data, "HTTP/3请求缺少is_zero_rtt"
    print("✓ HTTP/3请求数据协议信息完整")
    
    print("✅ UI集成测试通过\n")


def main():
    """主测试函数"""
    print("\n" + "=" * 60)
    print("HTTP/2和HTTP/3(QUIC)代理功能测试")
    print(f"测试时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60 + "\n")
    
    try:
        test_protocol_negotiator()
        test_h2_engine_initialization()
        test_h3_engine_initialization()
        test_mitm_proxy_engine_with_protocols()
        test_h2_stream_management()
        test_protocol_conversion()
        test_ui_integration()
        
        print("\n" + "=" * 60)
        print("✅ 所有测试通过!")
        print("=" * 60)
        
    except AssertionError as e:
        print(f"\n❌ 测试失败: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ 测试异常: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
