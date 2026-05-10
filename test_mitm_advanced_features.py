"""
HTTP/2和HTTP/3高级特性测试脚本
测试流优先级、连接迁移、协议降级、重放适配、性能优化、安全加固、诊断等功能
"""

import sys
import os
import time
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def test_h2_advanced_features():
    """测试HTTP/2高级特性"""
    print("=" * 60)
    print("测试 1: HTTP/2高级特性")
    print("=" * 60)
    
    from core.modules.mitm_h2_advanced import H2AdvancedFeatures, StreamPriority
    
    features = H2AdvancedFeatures()
    
    # 测试流优先级
    features.update_stream_priority(1, 256, exclusive=True)
    features.update_stream_priority(3, 128, parent_stream_id=1)
    features.update_stream_priority(5, 64, parent_stream_id=1)
    
    priority = features.get_stream_priority(1)
    assert priority is not None, "流优先级获取失败"
    assert priority.weight == 256, "权重错误"
    assert priority.exclusive == True, "exclusive标志错误"
    print("✓ 流优先级管理测试通过")
    
    # 测试优先级排序
    ordered = features.get_priority_ordered_streams()
    assert len(ordered) == 3, "流数量错误"
    assert ordered[0] == 1, "最高优先级流错误"
    print("✓ 优先级排序测试通过")
    
    # 测试HPACK动态表
    features.add_to_dynamic_table('content-type', 'application/json')
    features.add_to_dynamic_table('authorization', 'Bearer token123')
    
    hpack_stats = features.get_hpack_stats()
    assert hpack_stats.entries_count == 2, "动态表条目数错误"
    print("✓ HPACK动态表管理测试通过")
    
    # 测试窗口调整
    features.update_stream_window(1, 32768)
    window = features.get_stream_window(1)
    assert window > 0, "窗口大小错误"
    print("✓ 窗口动态调整测试通过")
    
    # 测试连接合并
    can_coalesce = features.can_coalesce_connections(
        'example.com', 'www.example.com',
        '93.184.216.34', '93.184.216.34',
        ['example.com', '*.example.com'],
        ['www.example.com', '*.example.com']
    )
    assert can_coalesce == True, "连接合并判断错误"
    print("✓ 连接合并测试通过")
    
    # 测试推送控制
    features.block_push_promise('/ads/')
    action = features.check_push_promise('/ads/banner.js')
    assert action == 'block', "推送策略检查失败"
    print("✓ 服务端推送控制测试通过")
    
    stats = features.get_stats()
    assert 'streams_created' in stats, "统计信息缺失"
    print("✓ HTTP/2统计信息测试通过")
    
    print("✅ HTTP/2高级特性测试通过\n")


def test_h3_advanced_features():
    """测试HTTP/3高级特性"""
    print("=" * 60)
    print("测试 2: HTTP/3高级特性")
    print("=" * 60)
    
    from core.modules.mitm_h3_advanced import H3AdvancedFeatures, ZeroRTTRiskLevel
    
    features = H3AdvancedFeatures()
    
    # 测试连接迁移
    old_conn_id = b'\x01\x02\x03\x04'
    new_conn_id = b'\x05\x06\x07\x08'
    
    success = features.handle_connection_migration(
        old_conn_id, new_conn_id,
        ('192.168.1.1', 443),
        ('192.168.1.2', 443),
        [1, 3, 5]
    )
    assert success == True, "连接迁移失败"
    print("✓ 连接迁移测试通过")
    
    # 测试迁移历史查询
    history = features.get_migration_history(new_conn_id)
    assert history is not None, "迁移历史获取失败"
    assert len(history.streams_preserved) == 3, "保留流数量错误"
    print("✓ 迁移历史查询测试通过")
    
    # 测试0-RTT安全处理
    zero_rtt = features.process_zero_rtt_data(
        b'conn123',
        b'GET /api/data HTTP/3',
        'GET',
        'https://example.com/api/data'
    )
    assert zero_rtt.risk_level == ZeroRTTRiskLevel.SAFE, "0-RTT风险评估错误"
    assert zero_rtt.is_replay == False, "重放检测错误"
    print("✓ 0-RTT安全处理测试通过")
    
    # 测试0-RTT重放检测
    zero_rtt_replay = features.process_zero_rtt_data(
        b'conn123',
        b'GET /api/data HTTP/3',
        'GET',
        'https://example.com/api/data'
    )
    assert zero_rtt_replay.is_replay == True, "重放检测失败"
    print("✓ 0-RTT重放检测测试通过")
    
    # 测试0-RTT阻断
    should_block = features.should_block_zero_rtt('POST', '/api/payment')
    assert should_block == True, "0-RTT阻断判断错误"
    print("✓ 0-RTT阻断策略测试通过")
    
    # 测试QUIC版本协商
    negotiated = features.negotiate_version(['0xff000002', '0x00000001'])
    assert negotiated is not None, "版本协商失败"
    print("✓ QUIC版本协商测试通过")
    
    # 测试多路径预留
    features.add_multipath(b'conn1', ('192.168.1.1', 443))
    features.add_multipath(b'conn1', ('192.168.1.2', 443))
    
    paths = features.get_multipaths(b'conn1')
    assert len(paths) == 2, "多路径数量错误"
    print("✓ 多路径QUIC预留测试通过")
    
    # 测试WebTransport预留
    session = features.create_webtransport_session('session1', b'conn1', 1)
    assert session['state'] == 'active', "WebTransport会话状态错误"
    
    active_sessions = features.get_active_webtransport_sessions()
    assert len(active_sessions) == 1, "活跃会话数量错误"
    print("✓ WebTransport预留测试通过")
    
    stats = features.get_stats()
    assert 'connections_migrated' in stats, "统计信息缺失"
    print("✓ HTTP/3统计信息测试通过")
    
    print("✅ HTTP/3高级特性测试通过\n")


def test_adaptive_protocol():
    """测试自适应协议管理"""
    print("=" * 60)
    print("测试 3: 自适应协议管理")
    print("=" * 60)
    
    from core.modules.mitm_adaptive_protocol import AdaptiveProtocolManager, ProtocolVersion
    
    manager = AdaptiveProtocolManager()
    
    # 测试协议协商
    result = manager.negotiate_protocol(
        ['h3', 'h2', 'http/1.1'],
        ['h3', 'h2', 'http/1.1'],
        'example.com',
        443,
        '192.168.1.100'
    )
    assert result.negotiated_protocol == ProtocolVersion.HTTP3, "协议协商失败"
    print("✓ 协议协商测试通过")
    
    # 测试降级
    result_fallback = manager.negotiate_protocol(
        ['h3', 'h2'],
        ['http/1.1'],
        'old.example.com',
        80
    )
    assert result_fallback.negotiated_protocol == ProtocolVersion.HTTP1, "降级失败"
    assert result_fallback.reason is not None, "降级原因缺失"
    print("✓ 智能降级测试通过")
    
    # 测试强制降级
    manager.force_protocol_downgrade('test.example.com', ProtocolVersion.HTTP1)
    result_forced = manager.negotiate_protocol(
        ['h3', 'h2'],
        ['h3', 'h2'],
        'test.example.com',
        443
    )
    assert result_forced.is_forced == True, "强制降级标志错误"
    assert result_forced.negotiated_protocol == ProtocolVersion.HTTP1, "强制降级失败"
    print("✓ 强制降级测试通过")
    
    # 测试ALPN策略
    manager.set_alpn_order(['h2', 'h3', 'http/1.1'])
    order = manager.get_alpn_order()
    assert order[0] == 'h2', "ALPN顺序设置失败"
    print("✓ ALPN策略配置测试通过")
    
    # 测试协议优先
    manager.prioritize_protocol('h3')
    order = manager.get_alpn_order()
    assert order[0] == 'h3', "协议优先设置失败"
    print("✓ 协议优先测试通过")
    
    # 测试嗅探日志
    logs = manager.get_sniff_logs(limit=10)
    assert len(logs) > 0, "嗅探日志缺失"
    print("✓ 协议嗅探日志测试通过")
    
    # 测试日志导出
    json_logs = manager.export_sniff_logs(format='json')
    assert len(json_logs) > 0, "JSON导出失败"
    print("✓ 日志导出测试通过")
    
    stats = manager.get_stats()
    assert 'total_negotiations' in stats, "统计信息缺失"
    print("✓ 自适应协议统计测试通过")
    
    print("✅ 自适应协议管理测试通过\n")


def test_replay_fuzzer_adapter():
    """测试重放与Fuzzer适配器"""
    print("=" * 60)
    print("测试 4: 重放与Fuzzer适配器")
    print("=" * 60)
    
    from core.modules.mitm_replay_fuzzer import (
        ProtocolReplayAdapter, FuzzerProtocolAdapter, 
        FuzztagProtocolResolver, ReplayMode, ProtocolType
    )
    
    # 测试协议重放
    replay_adapter = ProtocolReplayAdapter()
    
    original_request = {
        'id': 'req123',
        'protocol': 'HTTP/2',
        'method': 'GET',
        'url': 'https://example.com/api/data',
        'headers': {
            ':method': 'GET',
            ':path': '/api/data',
            ':authority': 'example.com',
            'content-type': 'application/json',
        },
        'body': b'',
        'stream_id': 1,
    }
    
    replay = replay_adapter.prepare_replay(original_request, ReplayMode.SAME_PROTOCOL)
    assert replay.original_protocol == ProtocolType.HTTP2, "原始协议识别失败"
    assert replay.target_protocol == ProtocolType.HTTP2, "目标协议设置失败"
    print("✓ 重放请求准备测试通过")
    
    # 测试协议转换
    converted = replay_adapter.convert_request_for_protocol(replay)
    assert 'headers' in converted, "转换结果缺失"
    print("✓ 协议转换测试通过")
    
    # 测试HTTP/1.1转换
    replay_http1 = replay_adapter.prepare_replay(original_request, ReplayMode.FORCE_HTTP1)
    converted_http1 = replay_adapter.convert_request_for_protocol(replay_http1)
    assert converted_http1['protocol'] == 'HTTP/1.1', "HTTP/1.1转换失败"
    print("✓ HTTP/1.1转换测试通过")
    
    # 测试Fuzzer协议适配
    fuzzer = FuzzerProtocolAdapter()
    
    detected = fuzzer.detect_target_protocol('https://example.com', {'alt-svc': 'h3=":443"'})
    assert detected == ProtocolType.HTTP3, "协议检测失败"
    print("✓ 目标协议检测测试通过")
    
    # 测试Fuzz载荷适配
    adapted = fuzzer.adapt_fuzz_payload('test_payload', ProtocolType.HTTP2, 'header')
    assert 'fuzzed' in adapted, "Fuzz载荷适配失败"
    print("✓ Fuzz载荷适配测试通过")
    
    # 测试Fuzz变体生成
    variants = fuzzer.generate_fuzz_variants('test', ProtocolType.HTTP2)
    assert len(variants) > 0, "Fuzz变体生成失败"
    print("✓ Fuzz变体生成测试通过")
    
    # 测试Fuzztag解析
    context = {
        'protocol': 'HTTP/2',
        'stream_id': 1,
        'connection_id': 'conn123',
        'priority': 128,
    }
    
    resolved = FuzztagProtocolResolver.resolve_fuzztag('${protocol}', context)
    assert resolved == 'HTTP/2', "Fuzztag解析失败"
    print("✓ Fuzztag协议解析测试通过")
    
    # 测试多Fuzztag解析
    payload = 'Protocol: ${protocol}, Stream: ${stream_id}, Multiplexed: ${is_multiplexed}'
    resolved_all = FuzztagProtocolResolver.resolve_all_fuzztags(payload, context)
    assert '${protocol}' not in resolved_all, "Fuzztag未完全解析"
    assert 'HTTP/2' in resolved_all, "协议值解析错误"
    print("✓ 多Fuzztag解析测试通过")
    
    print("✅ 重放与Fuzzer适配器测试通过\n")


def test_performance_optimizer():
    """测试性能优化器"""
    print("=" * 60)
    print("测试 5: 性能优化器")
    print("=" * 60)
    
    from core.modules.mitm_performance import (
        PerformanceOptimizer, ZeroCopyBuffer, FrameBatch, ConcurrencyController
    )
    
    # 测试零拷贝缓冲区
    buffer = ZeroCopyBuffer(initial_size=1024)
    
    written = buffer.write(b'Hello, World!')
    assert written == 13, "写入大小错误"
    
    data = buffer.read(5)
    assert data == b'Hello', "读取数据错误"
    print("✓ 零拷贝缓冲区测试通过")
    
    # 测试缓冲区压缩
    buffer.write(b'More data')
    buffer.compact()
    assert buffer.available_data > 0, "压缩后数据丢失"
    print("✓ 缓冲区压缩测试通过")
    
    # 测试帧批处理
    batch = FrameBatch(max_size=100, max_count=5)
    
    assert batch.can_add(b'frame1') == True, "帧添加判断错误"
    batch.add(b'frame1')
    batch.add(b'frame2')
    
    assert batch.is_full() == False, "批次满判断错误"
    print("✓ 帧批处理测试通过")
    
    # 测试并发控制
    controller = ConcurrencyController(max_http2_streams=5, max_quic_connections=3)
    
    acquired = controller.try_acquire_http2_stream()
    assert acquired == True, "HTTP/2流获取失败"
    
    active = controller.get_active_http2_streams()
    assert active == 1, "活跃流数错误"
    
    controller.release_http2_stream()
    active = controller.get_active_http2_streams()
    assert active == 0, "流释放失败"
    print("✓ 并发控制测试通过")
    
    # 测试性能优化器
    optimizer = PerformanceOptimizer(
        max_http2_streams=10,
        max_quic_connections=5,
        enable_frame_batching=True,
        enable_zero_copy=True
    )
    
    udp_pool = optimizer.get_udp_pool()
    assert udp_pool is not None, "UDP连接池获取失败"
    
    frame_processor = optimizer.get_frame_processor()
    assert frame_processor is not None, "帧处理器获取失败"
    
    concurrency = optimizer.get_concurrency_controller()
    assert concurrency is not None, "并发控制器获取失败"
    
    zero_copy = optimizer.get_zero_copy_buffer('stream1')
    assert zero_copy is not None, "零拷贝缓冲区获取失败"
    print("✓ 性能优化器集成测试通过")
    
    stats = optimizer.get_stats()
    assert 'udp_pool' in stats, "统计信息缺失"
    print("✓ 性能优化统计测试通过")
    
    optimizer.cleanup()
    print("✓ 资源清理测试通过")
    
    print("✅ 性能优化器测试通过\n")


def test_security_manager():
    """测试安全管理器"""
    print("=" * 60)
    print("测试 6: 安全管理器")
    print("=" * 60)
    
    from core.modules.mitm_security import (
        SecurityManager, HPACKBombProtector, StreamFloodDetector,
        QUICAddressValidator, ThreatLevel
    )
    
    # 测试HPACK炸弹防护
    hpack_protector = HPACKBombProtector()
    
    # 正常头部
    normal_headers = [
        (':method', 'GET'),
        (':path', '/api/data'),
        ('content-type', 'application/json'),
    ]
    is_safe, reason = hpack_protector.validate_headers(normal_headers)
    assert is_safe == True, "正常头部被误判"
    print("✓ 正常头部验证测试通过")
    
    # 过多头部
    excessive_headers = [(f'header{i}', f'value{i}') for i in range(150)]
    is_safe, reason = hpack_protector.validate_headers(excessive_headers)
    assert is_safe == False, "过多头部未被检测"
    print("✓ 头部数量限制测试通过")
    
    # 过大头部
    oversized_headers = [(':method', 'GET'), ('x-large', 'x' * 10000)]
    is_safe, reason = hpack_protector.validate_headers(oversized_headers)
    assert is_safe == False, "过大头部未被检测"
    print("✓ 头部大小限制测试通过")
    
    # 测试流泛滥检测
    flood_detector = StreamFloodDetector(
        max_streams_per_connection=10,
        max_streams_per_second=5
    )
    
    for i in range(10):
        is_ok, _ = flood_detector.track_stream('conn1', i)
    
    is_ok, reason = flood_detector.track_stream('conn1', 11)
    assert is_ok == False, "流泛滥未被检测"
    print("✓ 流泛滥检测测试通过")
    
    # 测试QUIC地址验证
    quic_validator = QUICAddressValidator()
    
    is_valid, _ = quic_validator.validate_address('192.168.1.1', 443)
    assert is_valid == True, "地址验证失败"
    print("✓ QUIC地址验证测试通过")
    
    # 测试令牌生成与验证
    token = quic_validator.generate_token('192.168.1.2', 443)
    is_valid, _ = quic_validator.validate_address('192.168.1.2', 443, token)
    assert is_valid == True, "令牌验证失败"
    print("✓ QUIC令牌验证测试通过")
    
    # 测试安全管理器集成
    security = SecurityManager(
        enable_hpack_protection=True,
        enable_stream_flood_detection=True,
        enable_quic_validation=True,
        enable_ct_validation=False
    )
    
    is_safe, _ = security.validate_headers(normal_headers)
    assert is_safe == True, "安全管理器头部验证失败"
    
    is_ok, _ = security.track_stream('conn2', 1)
    assert is_ok == True, "安全管理器流跟踪失败"
    
    is_valid, _ = security.validate_quic_address('192.168.1.3', 443)
    assert is_valid == True, "安全管理器QUIC验证失败"
    print("✓ 安全管理器集成测试通过")
    
    alerts = security.get_all_alerts()
    assert isinstance(alerts, list), "告警获取失败"
    print("✓ 安全告警获取测试通过")
    
    stats = security.get_stats()
    assert 'hpack_protection' in stats, "统计信息缺失"
    print("✓ 安全统计测试通过")
    
    print("✅ 安全管理器测试通过\n")


def test_diagnostics_observability():
    """测试诊断与可观测性"""
    print("=" * 60)
    print("测试 7: 诊断与可观测性")
    print("=" * 60)
    
    from core.modules.mitm_diagnostics import (
        DiagnosticsAndObservability, ConnectionDiagnosisPanel,
        ProtocolComplianceChecker, PrometheusMetricsExporter,
        ProtocolUsageStatistics
    )
    
    # 测试连接诊断
    diag = DiagnosticsAndObservability()
    
    diag.register_connection('conn1', 'HTTP/2', 
                            alpn='h2', tls_version='TLS 1.3')
    diag.register_connection('conn2', 'HTTP/3',
                            alpn='h3', quic_version='0x00000001')
    
    diag.update_connection_activity('conn1', request_count=5, response_count=5)
    
    conn_info = diag.get_connection_diagnosis('conn1')
    assert conn_info is not None, "连接诊断信息获取失败"
    assert conn_info['protocol'] == 'HTTP/2', "协议信息错误"
    print("✓ 连接诊断测试通过")
    
    # 测试流映射
    diag._diagnosis_panel.add_stream_mapping('conn1', 1, 'GET /api/data')
    diag._diagnosis_panel.add_stream_mapping('conn1', 3, 'POST /api/submit')
    
    conn_info = diag.get_connection_diagnosis('conn1')
    assert len(conn_info['stream_id_mapping']) == 2, "流映射数量错误"
    print("✓ 流映射测试通过")
    
    # 测试合规性检查
    issues = diag.check_compliance('HTTP/2', [
        (':method', 'GET'),
        (':path', '/api/data'),
        ('connection', 'keep-alive'),
    ], 'conn1')
    
    assert len(issues) > 0, "合规性问题未检测"
    assert any(i['severity'] == 'critical' for i in issues), "关键问题未检测"
    print("✓ 协议合规性检查测试通过")
    
    # 测试Prometheus指标
    diag.record_request('HTTP/2', 1024)
    diag.record_request('HTTP/3', 2048)
    diag.record_response('HTTP/2', 4096)
    diag.record_response('HTTP/3', 8192)
    
    prometheus_output = diag.get_prometheus_metrics(format='prometheus')
    assert len(prometheus_output) > 0, "Prometheus指标导出失败"
    print("✓ Prometheus指标导出测试通过")
    
    # 测试使用统计
    usage_stats = diag.get_usage_statistics()
    assert 'total_requests' in usage_stats, "使用统计缺失"
    assert usage_stats['total_requests'] == 2, "请求统计错误"
    print("✓ 使用统计测试通过")
    
    # 测试协议分布
    distribution = diag._usage_stats.get_protocol_distribution()
    assert 'HTTP/2' in distribution, "HTTP/2分布缺失"
    assert 'HTTP/3' in distribution, "HTTP/3分布缺失"
    print("✓ 协议分布测试通过")
    
    # 测试完整状态
    full_status = diag.get_full_status()
    assert 'diagnosis' in full_status, "诊断状态缺失"
    assert 'usage' in full_status, "使用状态缺失"
    print("✓ 完整状态获取测试通过")
    
    # 测试连接关闭
    diag.close_connection('conn1')
    all_connections = diag.get_all_connections()
    assert len(all_connections) == 1, "连接关闭后数量错误"
    print("✓ 连接关闭测试通过")
    
    print("✅ 诊断与可观测性测试通过\n")


def main():
    """主测试函数"""
    print("\n" + "=" * 60)
    print("HTTP/2和HTTP/3高级特性测试")
    print(f"测试时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60 + "\n")
    
    try:
        test_h2_advanced_features()
        test_h3_advanced_features()
        test_adaptive_protocol()
        test_replay_fuzzer_adapter()
        test_performance_optimizer()
        test_security_manager()
        test_diagnostics_observability()
        
        print("\n" + "=" * 60)
        print("✅ 所有高级特性测试通过!")
        print("=" * 60 + "\n")
        
    except Exception as e:
        print(f"\n❌ 测试异常: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
