"""
MITM代理联动功能测试脚本
测试Web Fuzzer联动、反连平台联动、移动端支持、安全审计
"""

import sys
import os
import json
import time
from datetime import datetime
from pathlib import Path

# 添加项目根目录到路径
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))


def test_fuzzer_integration():
    """测试Web Fuzzer联动"""
    print("=" * 60)
    print("测试 1: Web Fuzzer联动")
    print("=" * 60)
    
    from core.modules.mitm_fuzzer_integration import FuzzerIntegration
    
    fuzzer = FuzzerIntegration()
    
    # 测试请求分析 - Query参数
    request_data = {
        'id': 'test_001',
        'method': 'GET',
        'url': 'http://example.com/api/search?q=test&page=1&limit=10',
        'headers': {'Content-Type': 'application/json'},
        'body': ''
    }
    
    result = fuzzer.analyze_request(request_data)
    assert result.method == 'GET', "方法识别错误"
    assert len(result.fuzzable_params) > 0, "未识别到可Fuzz参数"
    print("✓ Query参数识别成功")
    
    # 测试JSON Body参数识别
    request_data = {
        'id': 'test_002',
        'method': 'POST',
        'url': 'http://example.com/api/login',
        'headers': {'Content-Type': 'application/json'},
        'body': json.dumps({
            'username': 'admin',
            'password': 'secret123',
            'remember': True
        })
    }
    
    result = fuzzer.analyze_request(request_data)
    json_params = [p for p in result.fuzzable_params if p.position == 'body']
    assert len(json_params) > 0, "未识别到JSON Body参数"
    print("✓ JSON Body参数识别成功")
    
    # 测试可疑参数检测
    request_data = {
        'id': 'test_003',
        'method': 'GET',
        'url': "http://example.com/api/user?id=1' OR 1=1 --&redirect=http://evil.com",
        'headers': {},
        'body': ''
    }
    
    result = fuzzer.analyze_request(request_data)
    suspicious = [p for p in result.fuzzable_params if p.is_suspicious]
    assert len(suspicious) > 0, "未检测到可疑参数"
    print("✓ 可疑参数检测成功")
    
    # 测试Fuzzer模板生成
    assert '{{fuzz:' in result.template, "Fuzzer模板生成失败"
    print("✓ Fuzzer模板生成成功")
    
    # 测试参数统计
    stats = fuzzer.get_param_statistics(result)
    assert stats['total_params'] > 0, "参数统计错误"
    print("✓ 参数统计成功")
    
    # 测试回调设置
    callback_called = []
    def mock_callback(req):
        callback_called.append(req)
    
    fuzzer.set_fuzzer_callback(mock_callback)
    success = fuzzer.send_to_fuzzer(request_data)
    assert success == True, "发送到Fuzzer失败"
    assert len(callback_called) == 1, "回调未执行"
    print("✓ Fuzzer回调执行成功")
    
    print("✅ Web Fuzzer联动测试通过\n")


def test_reverse_integration():
    """测试反连平台联动"""
    print("=" * 60)
    print("测试 2: 反连平台联动")
    print("=" * 60)
    
    from core.modules.mitm_reverse_integration import (
        ReversePlatformIntegration, CallbackServer, ReverseConnectionListener
    )
    
    # 测试回调服务器
    callback_server = CallbackServer(port=18888)
    assert callback_server.start() == True, "回调服务器启动失败"
    print("✓ 回调服务器启动成功")
    
    # 测试标识符生成
    identifier = callback_server.generate_identifier()
    assert len(identifier) > 0, "标识符生成失败"
    print("✓ 标识符生成成功")
    
    # 测试回调URL生成
    callback_url = callback_server.get_callback_url(identifier)
    assert identifier in callback_url, "回调URL生成失败"
    print("✓ 回调URL生成成功")
    
    # 测试PoC注册
    callback_server.register_identifier(identifier, 'poc_test_001')
    print("✓ PoC注册成功")
    
    # 测试统计信息
    stats = callback_server.get_statistics()
    assert 'total_records' in stats, "统计信息获取失败"
    print("✓ 统计信息获取成功")
    
    callback_server.stop()
    print("✓ 回调服务器停止成功")
    
    # 测试反向连接监听器
    reverse_listener = ReverseConnectionListener(port=14444)
    assert reverse_listener.start() == True, "反向连接监听器启动失败"
    print("✓ 反向连接监听器启动成功")
    
    time.sleep(0.5)
    
    reverse_listener.stop()
    print("✓ 反向连接监听器停止成功")
    
    # 测试集成器
    integration = ReversePlatformIntegration(
        callback_port=18889,
        reverse_port=14445
    )
    
    highlight_called = []
    def mock_highlight(record):
        highlight_called.append(record)
    
    integration.set_highlight_callback(mock_highlight)
    assert integration.start() == True, "反连平台启动失败"
    print("✓ 反连平台启动成功")
    
    # 测试PoC注册
    callback_url = integration.register_poc('poc_test_002')
    assert '18889' in callback_url, "PoC注册失败"
    print("✓ 集成器PoC注册成功")
    
    integration.stop()
    print("✓ 反连平台停止成功")
    
    print("✅ 反连平台联动测试通过\n")


def test_mobile_support():
    """测试移动端抓包支持"""
    print("=" * 60)
    print("测试 3: 移动端抓包支持")
    print("=" * 60)
    
    from core.modules.mitm_mobile_support import MobileSupport, CertificateExport, WeakNetworkSimulator
    
    # 创建测试目录
    test_dir = "test_data/mobile_certs"
    os.makedirs(test_dir, exist_ok=True)
    
    # 测试证书导出
    cert_export = CertificateExport()
    
    android_cert = cert_export.export_for_android(test_dir)
    assert os.path.exists(android_cert), "Android证书导出失败"
    print("✓ Android证书导出成功")
    
    ios_config = cert_export.export_for_ios(test_dir)
    assert os.path.exists(ios_config), "iOS配置导出失败"
    print("✓ iOS配置导出成功")
    
    install_guide = cert_export.generate_install_guide(test_dir)
    assert os.path.exists(install_guide), "安装指南生成失败"
    print("✓ 安装指南生成成功")
    
    # 测试弱网模拟器
    weak_network = WeakNetworkSimulator()
    
    # 测试预设配置
    weak_network.set_preset('3g')
    config = weak_network.get_config()
    assert config['enabled'] == True, "弱网模拟启用失败"
    assert config['delay_ms'] == 200, "3G预设延迟错误"
    print("✓ 3G预设配置成功")
    
    weak_network.set_preset('edge')
    config = weak_network.get_config()
    assert config['delay_ms'] == 500, "EDGE预设延迟错误"
    print("✓ EDGE预设配置成功")
    
    weak_network.set_preset('2g')
    config = weak_network.get_config()
    assert config['delay_ms'] == 1000, "2G预设延迟错误"
    print("✓ 2G预设配置成功")
    
    # 测试延迟应用
    start_time = time.time()
    weak_network.apply_delay()
    elapsed = time.time() - start_time
    # 2G预设延迟1000ms + 抖动200ms，大约1秒左右
    assert elapsed > 0.5, "延迟应用失败"
    print("✓ 延迟应用成功")
    
    # 测试丢包
    weak_network.enable(delay_ms=0, packet_loss=0.5)
    drop_count = 0
    for _ in range(100):
        if weak_network.should_drop_packet():
            drop_count += 1
    # 50%丢包率，100次应该有大约50次丢包
    assert 20 < drop_count < 80, f"丢包率异常: {drop_count}/100"
    print("✓ 丢包模拟成功")
    
    # 测试带宽限制
    weak_network.enable(delay_ms=0, packet_loss=0, bandwidth_limit=100, jitter_ms=0)
    wait_time = weak_network.apply_bandwidth_limit(10240)  # 10KB
    assert wait_time > 0, "带宽限制计算失败"
    print("✓ 带宽限制计算成功")
    
    weak_network.disable()
    assert weak_network.get_config()['enabled'] == False, "弱网模拟禁用失败"
    print("✓ 弱网模拟禁用成功")
    
    # 测试移动端支持管理器
    mobile_support = MobileSupport()
    results = mobile_support.export_all(test_dir)
    assert 'android_cert' in results, "移动端配置导出失败"
    assert 'ios_config' in results, "移动端配置导出失败"
    assert 'install_guide' in results, "移动端配置导出失败"
    print("✓ 移动端配置导出成功")
    
    print("✅ 移动端抓包支持测试通过\n")


def test_security_audit():
    """测试安全与审计"""
    print("=" * 60)
    print("测试 4: 安全与审计")
    print("=" * 60)
    
    from core.modules.mitm_security_audit import (
        SecurityAuditor, AccessController, SensitiveDataProtector, 
        AuditLogger, DataCleaner
    )
    
    # 测试访问控制器
    access_controller = AccessController()
    
    # 测试IP白名单
    access_controller.add_ip_whitelist('192.168.1.100', '测试机器')
    assert access_controller.check_access('192.168.1.100') == True, "白名单访问检查失败"
    assert access_controller.check_access('10.0.0.1') == False, "非白名单访问检查失败"
    print("✓ IP白名单功能成功")
    
    access_controller.remove_ip_whitelist('192.168.1.100')
    assert access_controller.check_access('192.168.1.100') == True, "白名单移除后访问检查失败"
    print("✓ IP白名单移除成功")
    
    # 测试IP黑名单
    access_controller.add_ip_blacklist('10.0.0.1', '恶意IP')
    assert access_controller.check_access('10.0.0.1') == False, "黑名单访问检查失败"
    assert access_controller.check_access('192.168.1.100') == True, "非黑名单访问检查失败"
    print("✓ IP黑名单功能成功")
    
    access_controller.remove_ip_blacklist('10.0.0.1')
    assert access_controller.check_access('10.0.0.1') == True, "黑名单移除后访问检查失败"
    print("✓ IP黑名单移除成功")
    
    # 测试认证
    access_controller.enable_auth('admin', 'password123')
    assert access_controller.check_access('192.168.1.100', 'admin', 'password123') == True, "认证失败"
    assert access_controller.check_access('192.168.1.100', 'admin', 'wrongpassword') == False, "错误密码认证检查失败"
    print("✓ 认证功能成功")
    
    access_controller.disable_auth()
    assert access_controller.check_access('192.168.1.100') == True, "禁用认证后访问检查失败"
    print("✓ 认证禁用成功")
    
    # 测试敏感数据保护
    protector = SensitiveDataProtector()
    
    test_data = {
        'username': 'admin',
        'password': 'secret123',
        'api_key': 'abc123xyz',
        'email': 'admin@example.com'
    }
    
    masked = protector.mask_sensitive_data(test_data)
    assert masked['password'] != 'secret123', "密码未模糊化"
    assert masked['api_key'] != 'abc123xyz', "API密钥未模糊化"
    assert masked['username'] == 'admin', "用户名被错误模糊化"
    print("✓ 敏感数据模糊化成功")
    
    # 测试请求头模糊化
    headers = {
        'Authorization': 'Bearer token123',
        'Content-Type': 'application/json',
        'Cookie': 'session=abc123'
    }
    
    masked_headers = protector.mask_headers(headers)
    assert masked_headers['Authorization'] != 'Bearer token123', "Authorization头未模糊化"
    assert masked_headers['Cookie'] != 'session=abc123', "Cookie头未模糊化"
    print("✓ 请求头模糊化成功")
    
    # 测试审计日志
    test_dir = "test_data"
    os.makedirs(test_dir, exist_ok=True)
    
    audit_logger = AuditLogger(os.path.join(test_dir, "test_audit.log"))
    
    audit_logger.log('admin', 'PROXY_START', 'mitm_proxy', {'port': 8080})
    audit_logger.log('admin', 'CONFIG_CHANGE', 'proxy_port', {'old': 8080, 'new': 9090})
    
    logs = audit_logger.get_logs()
    assert len(logs) >= 2, "审计日志记录失败"
    print("✓ 审计日志记录成功")
    
    # 测试日志过滤
    filtered = audit_logger.get_logs(action='CONFIG_CHANGE')
    assert len(filtered) >= 1, "审计日志过滤失败"
    print("✓ 审计日志过滤成功")
    
    # 测试日志导出
    export_file = os.path.join(test_dir, "audit_export.json")
    audit_logger.export_logs(export_file)
    assert os.path.exists(export_file), "审计日志导出失败"
    print("✓ 审计日志导出成功")
    
    # 测试数据清理器
    cleaner = DataCleaner()
    
    cleanup_results = {}
    def mock_cleanup_certs():
        cleanup_results['certs'] = True
        return True
    
    def mock_cleanup_history():
        cleanup_results['history'] = True
        return True
    
    cleaner.register_callback(mock_cleanup_certs, 'certs')
    cleaner.register_callback(mock_cleanup_history, 'history')
    
    results = cleaner.cleanup_all(include_certs=True, include_history=True)
    assert results.get('certs') == True, "证书清理回调未执行"
    assert results.get('history') == True, "历史清理回调未执行"
    print("✓ 数据清理器成功")
    
    # 测试安全审计管理器
    auditor = SecurityAuditor(os.path.join(test_dir, "test_audit2.log"))
    
    auditor.log_config_change('admin', 'proxy_port', 8080, 9090)
    auditor.log_intercept_modify('admin', 'req_001', {'header': 'modified'})
    
    status = auditor.get_security_status()
    assert 'access_control' in status, "安全状态获取失败"
    assert 'audit_logs' in status, "安全状态获取失败"
    print("✓ 安全审计管理器成功")
    
    print("✅ 安全与审计测试通过\n")


def run_all_tests():
    """运行所有测试"""
    print("\n" + "=" * 60)
    print("MITM代理联动功能测试套件")
    print("=" * 60 + "\n")
    
    # 创建测试目录
    os.makedirs("test_data", exist_ok=True)
    
    try:
        test_fuzzer_integration()
        test_reverse_integration()
        test_mobile_support()
        test_security_audit()
        
        print("=" * 60)
        print("🎉 所有联动功能测试通过!")
        print("=" * 60)
        
    except AssertionError as e:
        print(f"\n❌ 测试失败: {e}")
        import traceback
        traceback.print_exc()
        return False
    except Exception as e:
        print(f"\n❌ 测试异常: {e}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        # 清理测试数据
        import shutil
        if os.path.exists("test_data"):
            shutil.rmtree("test_data")
    
    return True


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
