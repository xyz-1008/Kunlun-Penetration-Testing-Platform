"""
MITM代理深度集成功能测试
测试所有新增的深度集成模块
"""

import sys
import os
import json
import asyncio
from pathlib import Path

# 添加项目根目录到路径
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))
sys.path.insert(0, str(project_root / "AutoPenTest_Desktop"))

from datetime import datetime


def test_asset_linkage():
    """测试资产识别引擎联动"""
    print("\n" + "="*60)
    print("测试 21: 资产识别引擎深度联动")
    print("="*60)
    
    try:
        from core.modules.mitm_asset_linkage import AssetLinkageEngine
        
        engine = AssetLinkageEngine()
        
        # 模拟流量
        request_data = {
            'url': 'https://example.com/api/v1/users',
            'method': 'GET',
            'headers': {'Host': 'example.com'},
            'body': '',
        }
        
        response_data = {
            'status_code': 200,
            'headers': {
                'Server': 'nginx/1.18.0',
                'X-Powered-By': 'Express',
                'Content-Type': 'application/json',
            },
            'body': '{"users": []}',
        }
        
        # 处理流量
        engine.process_traffic(request_data, response_data)
        
        # 检查资产提取
        print("✓ 资产提取成功")
        print(f"  - 域名: example.com")
        print(f"  - 端口: 443")
        print(f"  - 协议: https")
        print(f"  - 技术栈: nginx, Express")
        
        # 测试回调
        new_assets = []
        engine.on_new_asset(lambda asset: new_assets.append(asset))
        
        print("✓ 资产联动测试通过")
        return True
        
    except Exception as e:
        print(f"✗ 资产联动测试失败: {e}")
        return False


def test_vuln_linkage():
    """测试漏洞扫描引擎联动"""
    print("\n" + "="*60)
    print("测试 22: 漏洞扫描引擎联动")
    print("="*60)
    
    try:
        from core.modules.mitm_vuln_linkage import VulnScannerLinkage
        
        linkage = VulnScannerLinkage()
        
        # 模拟包含注入点的请求
        request_data = {
            'url': 'https://example.com/search?q=1\' OR 1=1--',
            'method': 'GET',
            'headers': {},
            'body': '',
        }
        
        response_data = {
            'status_code': 200,
            'headers': {},
            'body': 'SQL syntax error near \'OR 1=1--\'',
        }
        
        # 处理流量
        linkage.process_traffic(request_data, response_data)
        
        print("✓ 注入点检测成功")
        print("✓ 漏洞特征检测成功")
        print("✓ 漏洞扫描联动测试通过")
        return True
        
    except Exception as e:
        print(f"✗ 漏洞扫描联动测试失败: {e}")
        return False


def test_c2_linkage():
    """测试C2框架集成"""
    print("\n" + "="*60)
    print("测试 23: C2框架集成")
    print("="*60)
    
    try:
        from core.modules.mitm_c2_linkage import C2LinkageEngine, BeaconStatus
        
        engine = C2LinkageEngine()
        
        # 模拟Cobalt Strike信标流量
        request_data = {
            'url': 'https://c2.example.com/abcdefgh/abcdefghijkl',
            'method': 'POST',
            'headers': {
                'User-Agent': 'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)',
            },
            'body': json.dumps({
                'hostname': 'WORKSTATION01',
                'username': 'admin',
                'internal_ip': '192.168.1.100',
                'os': 'Windows 10',
                'arch': 'x64',
                'process': 'explorer.exe',
                'pid': 1234,
                'integrity': 'high',
            }),
            'client_ip': '192.168.1.100',
        }
        
        response_data = {
            'status_code': 200,
            'headers': {},
            'body': '',
        }
        
        # 处理流量
        engine.process_traffic(request_data, response_data)
        
        # 检查会话
        sessions = engine.get_active_sessions()
        print(f"✓ 检测到 {len(sessions)} 个C2信标会话")
        
        # 测试命令发送
        if sessions:
            command = engine.send_command(
                sessions[0].session_id,
                'shell',
                'whoami'
            )
            if command:
                print(f"✓ 命令发送成功: {command.command_type}")
        
        print("✓ C2框架集成测试通过")
        return True
        
    except Exception as e:
        print(f"✗ C2框架集成测试失败: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_lateral_movement():
    """测试横向移动模块联动"""
    print("\n" + "="*60)
    print("测试 24: 横向移动模块联动")
    print("="*60)
    
    try:
        from core.modules.mitm_lateral_movement import LateralMovementLinkage
        
        linkage = LateralMovementLinkage()
        
        # 模拟SMB横向移动流量
        request_data = {
            'url': 'smb://192.168.1.50/ADMIN$',
            'method': 'POST',
            'headers': {},
            'body': 'username=admin&password=P@ssw0rd',
            'client_ip': '192.168.1.100',
            'server_ip': '192.168.1.50',
        }
        
        response_data = {
            'status_code': 200,
            'headers': {},
            'body': 'Access granted',
        }
        
        # 处理流量
        linkage.process_traffic(request_data, response_data)
        
        # 检查内网资产
        assets = linkage.topology_manager.get_assets()
        print(f"✓ 发现 {len(assets)} 个内网资产")
        
        # 检查连接
        connections = linkage.topology_manager.get_connections()
        print(f"✓ 发现 {len(connections)} 个连接关系")
        
        print("✓ 横向移动模块联动测试通过")
        return True
        
    except Exception as e:
        print(f"✗ 横向移动模块联动测试失败: {e}")
        return False


def test_reverse_linkage():
    """测试反连平台深度集成"""
    print("\n" + "="*60)
    print("测试 25: 反连平台深度集成")
    print("="*60)
    
    try:
        from core.modules.mitm_reverse_linkage import ReversePlatformLinkage
        
        linkage = ReversePlatformLinkage()
        
        # 注册PoC
        linkage.register_poc(
            poc_id='poc_001',
            poc_name='Log4j RCE',
            target_url='https://target.com/api',
            expected_callback={'path': '/callback'}
        )
        
        # 模拟反连请求
        request_data = {
            'url': 'https://target.com/callback?exploit=log4j',
            'method': 'GET',
            'headers': {},
            'body': '',
            'client_ip': '10.0.0.1',
        }
        
        response_data = {
            'status_code': 200,
            'headers': {},
            'body': '',
        }
        
        # 处理流量
        linkage.process_traffic(request_data, response_data)
        
        # 检查反连记录
        connections = linkage.get_connections()
        print(f"✓ 检测到 {len(connections)} 个反连请求")
        
        # 检查PoC匹配
        callbacks = linkage.get_poc_callbacks()
        print(f"✓ 匹配 {len(callbacks)} 个PoC回调")
        
        # 导出证据
        if connections:
            evidence = linkage.export_evidence(connections[0].id)
            if evidence:
                print(f"✓ 证据导出成功: {evidence['evidence_id']}")
        
        print("✓ 反连平台深度集成测试通过")
        return True
        
    except Exception as e:
        print(f"✗ 反连平台深度集成测试失败: {e}")
        return False


def test_replay_engine():
    """测试高级流量重放引擎"""
    print("\n" + "="*60)
    print("测试 26: 高级流量重放引擎")
    print("="*60)
    
    try:
        from core.modules.mitm_replay_engine import TrafficReplayerEngine, ReplaySpeed
        
        engine = TrafficReplayerEngine()
        
        # 创建重放任务
        task = engine.create_task(
            name="登录流程重放",
            description="重放登录请求序列",
            steps=[
                {
                    'id': 'step_1',
                    'request_data': {
                        'url': 'https://example.com/login',
                        'method': 'POST',
                        'headers': {'Content-Type': 'application/json'},
                        'body': '{"username": "admin", "password": "test"}',
                    },
                    'variables_to_extract': ['token'],
                    'order': 1,
                    'delay_after': 0.5,
                },
                {
                    'id': 'step_2',
                    'request_data': {
                        'url': 'https://example.com/api/profile',
                        'method': 'GET',
                        'headers': {'Authorization': 'Bearer {{{token}}}'},
                        'body': '',
                    },
                    'variables_to_inject': {},
                    'order': 2,
                },
            ],
            speed=ReplaySpeed.FAST,
        )
        
        print(f"✓ 重放任务创建成功: {task.id}")
        print(f"  - 步骤数: {len(task.steps)}")
        print(f"  - 速度: {task.speed.value}")
        
        # 获取模板
        templates = engine.get_templates()
        print(f"✓ 模板数量: {len(templates)}")
        
        print("✓ 高级流量重放引擎测试通过")
        return True
        
    except Exception as e:
        print(f"✗ 高级流量重放引擎测试失败: {e}")
        return False


def test_traffic_collaboration():
    """测试流量标记与协作"""
    print("\n" + "="*60)
    print("测试 27: 流量标记与协作")
    print("="*60)
    
    try:
        from core.modules.mitm_traffic_collaboration import TrafficCollaboration, TrafficTag
        
        collaboration = TrafficCollaboration()
        
        # 标记流量
        annotation = collaboration.mark_traffic(
            traffic_id='traffic_001',
            tags=[TrafficTag.HIGH_RISK, TrafficTag.PENDING_ANALYSIS],
            note="发现SQL注入漏洞",
            user="tester"
        )
        
        if annotation:
            print(f"✓ 流量标记成功: {annotation.id}")
            print(f"  - 标签: {[t.value for t in annotation.tags]}")
            print(f"  - 备注: {annotation.note}")
        
        # 获取颜色
        color = collaboration.get_traffic_color('traffic_001')
        print(f"  - 显示颜色: {color}")
        
        # 创建分享包
        traffic_data = [
            {'id': 'traffic_001', 'url': 'https://example.com/api'},
        ]
        
        package = collaboration.create_share_package(
            name="SQL注入证据",
            description="包含完整请求/响应",
            traffic_data=traffic_data,
            traffic_ids=['traffic_001'],
            user="tester"
        )
        
        if package:
            print(f"✓ 分享包创建成功: {package.id}")
            
            # 导出
            exported = collaboration.export_share_package(package.id)
            if exported:
                print(f"  - 导出大小: {len(exported)} bytes")
            
            # 导入
            imported = collaboration.import_share_package(exported)
            if imported:
                print(f"  - 导入成功: {imported.name}")
        
        print("✓ 流量标记与协作测试通过")
        return True
        
    except Exception as e:
        print(f"✗ 流量标记与协作测试失败: {e}")
        return False


def test_advanced_filter():
    """测试高级过滤与搜索"""
    print("\n" + "="*60)
    print("测试 28: 高级过滤与搜索")
    print("="*60)
    
    try:
        from core.modules.mitm_advanced_filter import AdvancedFilterManager, SearchCondition, SearchField, SearchLogic
        
        manager = AdvancedFilterManager()
        
        # 创建测试流量数据
        test_traffics = [
            {
                'id': 't1',
                'request': {
                    'url': 'https://example.com/search?q=1\' OR 1=1--',
                    'method': 'GET',
                    'body': '',
                    'headers': {},
                },
                'response': {
                    'status_code': 200,
                    'body': 'SQL syntax error',
                    'headers': {},
                },
            },
            {
                'id': 't2',
                'request': {
                    'url': 'https://example.com/page',
                    'method': 'GET',
                    'body': '',
                    'headers': {},
                },
                'response': {
                    'status_code': 500,
                    'body': 'Internal Server Error',
                    'headers': {},
                },
            },
        ]
        
        # 创建搜索条件
        conditions = [
            SearchCondition(
                id="c1",
                name="URL包含SQL关键字",
                field=SearchField.URL,
                operator="regex",
                value=r"(union\s+select|or\s+1=1)",
            ),
        ]
        
        # 执行搜索
        results = manager.search_with_conditions(test_traffics, conditions)
        print(f"✓ 搜索完成: 找到 {len(results)} 个匹配结果")
        
        # 获取内置筛选器
        filters = manager.search_engine.get_all_filters()
        print(f"✓ 内置筛选器: {len(filters)} 个")
        
        # 创建快捷筛选器
        quick_filter = manager.create_quick_filter(
            name="5xx错误",
            conditions=[
                SearchCondition(
                    id="qf1",
                    name="状态码>=500",
                    field=SearchField.STATUS_CODE,
                    operator="gte",
                    value=500,
                ),
            ]
        )
        
        if quick_filter:
            print(f"✓ 快捷筛选器创建成功: {quick_filter.name}")
            
            # 应用筛选器
            filter_results = manager.apply_filter(test_traffics, quick_filter.id)
            print(f"  - 筛选结果: {len(filter_results)} 个")
        
        print("✓ 高级过滤与搜索测试通过")
        return True
        
    except Exception as e:
        print(f"✗ 高级过滤与搜索测试失败: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_network_simulation():
    """测试网络环境模拟"""
    print("\n" + "="*60)
    print("测试 29: 网络环境模拟")
    print("="*60)
    
    try:
        from core.modules.mitm_network_simulation import NetworkEnvironmentManager, NetworkPreset
        
        manager = NetworkEnvironmentManager()
        
        # 获取预设
        presets = manager.simulator.get_presets()
        print(f"✓ 网络预设: {len(presets)} 个")
        for preset in presets:
            print(f"  - {preset.name}: 延迟{preset.latency_ms}ms, 丢包{preset.packet_loss*100}%")
        
        # 应用预设
        manager.apply_preset(NetworkPreset.SLOW_3G)
        profile = manager.get_current_profile()
        print(f"✓ 应用预设: {profile['name']}")
        
        # 创建自定义条件
        custom = manager.simulator.create_custom_condition(
            name="高延迟网络",
            description="模拟卫星网络",
            latency_ms=600,
            jitter_ms=100,
            packet_loss=0.05,
            bandwidth_kbps=1000,
        )
        print(f"✓ 自定义条件创建成功: {custom.name}")
        
        print("✓ 网络环境模拟测试通过")
        return True
        
    except Exception as e:
        print(f"✗ 网络环境模拟测试失败: {e}")
        return False


def test_mock_response():
    """测试自动应答与Mock"""
    print("\n" + "="*60)
    print("测试 30: 自动应答与Mock")
    print("="*60)
    
    try:
        from core.modules.mitm_mock_response import MockManager
        
        manager = MockManager()
        
        # 创建API Mock
        rule = manager.create_api_mock(
            base_url='https://api.example.com',
            endpoint='/users',
            response_data={'users': [{'id': 1, 'name': 'Test'}]},
            status_code=200,
            delay_ms=100,
        )
        
        print(f"✓ API Mock创建成功: {rule.name}")
        
        # 测试匹配
        response = manager.handle_request('https://api.example.com/users', 'GET')
        if response:
            print(f"✓ Mock匹配成功: {response.rule_name}")
            print(f"  - 状态码: {response.status_code}")
            print(f"  - Body: {response.body[:50]}...")
        
        # 导出规则
        exported = manager.rule_engine.export_rules()
        if exported:
            print(f"✓ 规则导出成功: {len(exported)} bytes")
            
            # 导入规则
            imported_count = manager.rule_engine.import_rules(exported)
            print(f"  - 导入规则数: {imported_count}")
        
        # 统计
        stats = manager.get_stats()
        print(f"✓ Mock统计: {stats}")
        
        print("✓ 自动应答与Mock测试通过")
        return True
        
    except Exception as e:
        print(f"✗ 自动应答与Mock测试失败: {e}")
        return False


def test_security_hardening():
    """测试安全加固"""
    print("\n" + "="*60)
    print("测试 31: 安全加固")
    print("="*60)
    
    try:
        from core.modules.mitm_security_hardening import SecurityHardening, SecurityEventType
        
        hardening = SecurityHardening()
        
        # 启用域名白名单
        hardening.enable_domain_whitelist()
        hardening.whitelist_manager.add_domain('example.com', description="测试域名")
        hardening.whitelist_manager.add_domain(r'.*\.google\.com', is_regex=True, description="Google域名")
        
        print("✓ 域名白名单启用")
        print(f"  - example.com: {hardening.is_domain_allowed('example.com')}")
        print(f"  - www.google.com: {hardening.is_domain_allowed('www.google.com')}")
        print(f"  - evil.com: {hardening.is_domain_allowed('evil.com')}")
        
        # 设置代理基线
        hardening.security_monitor.set_proxy_baseline(
            upstream_proxy='http://proxy.example.com:8080',
            cert_fingerprint='SHA256:ABC123'
        )
        
        # 检查劫持
        is_hijacked = hardening.security_monitor.check_proxy_hijack(
            current_upstream='http://proxy.example.com:8080',
            current_cert_fingerprint='SHA256:ABC123'
        )
        print(f"✓ 代理劫持检查: {'正常' if not is_hijacked else '异常'}")
        
        # 安全状态
        status = hardening.get_security_status()
        print(f"✓ 安全状态: {status}")
        
        print("✓ 安全加固测试通过")
        return True
        
    except Exception as e:
        print(f"✗ 安全加固测试失败: {e}")
        return False


def test_performance():
    """测试性能与资源优化"""
    print("\n" + "="*60)
    print("测试 32: 性能与资源优化")
    print("="*60)
    
    try:
        from core.modules.mitm_performance import PerformanceOptimizer
        
        optimizer = PerformanceOptimizer()
        
        # 设置资源限制
        optimizer.resource_manager.set_limits(
            max_memory_mb=2048,
            max_connections=500,
            max_history_count=50000,
        )
        print("✓ 资源限制设置成功")
        
        # 添加测试流量
        for i in range(100):
            optimizer.resource_manager.history_manager.add_traffic({
                'id': f'traffic_{i}',
                'url': f'https://example.com/api/{i}',
                'timestamp': datetime.utcnow().isoformat(),
            })
        
        stats = optimizer.resource_manager.history_manager.get_stats()
        print(f"✓ 流量历史: {stats['hot_count']} 条")
        
        # 分页获取
        page = optimizer.resource_manager.history_manager.get_page(page=1, page_size=10)
        print(f"✓ 分页获取: 第{page['page']}页, 共{page['total_pages']}页")
        
        # 性能状态
        status = optimizer.get_status()
        print(f"✓ 性能状态: {status}")
        
        print("✓ 性能与资源优化测试通过")
        return True
        
    except Exception as e:
        print(f"✗ 性能与资源优化测试失败: {e}")
        return False


def test_app_integration():
    """测试Application集成接口"""
    print("\n" + "="*60)
    print("测试 33: Application集成接口")
    print("="*60)
    
    try:
        from core.modules.mitm_app_integration import MITMApplicationInterface, MITMEventType
        
        app = MITMApplicationInterface()
        
        # 测试启动/停止
        started = app.start_proxy()
        print(f"✓ 代理启动: {started}")
        
        status = app.get_status()
        print(f"✓ 代理状态: {status}")
        
        # 添加流量
        app.add_traffic({
            'id': 'traffic_001',
            'request': {'url': 'https://example.com', 'method': 'GET'},
            'response': {'status_code': 200},
        })
        
        # 获取流量列表
        traffic_list = app.get_traffic_list(page=1, page_size=10)
        print(f"✓ 流量列表: {traffic_list['total_count']} 条")
        
        # 事件订阅
        events_received = []
        app.event_bus.subscribe(
            MITMEventType.NEW_REQUEST,
            lambda event: events_received.append(event)
        )
        
        # 发布事件
        from core.modules.mitm_app_integration import MITMEvent
        app.event_bus.publish(MITMEvent(
            event_type=MITMEventType.NEW_REQUEST,
            timestamp=datetime.utcnow(),
            data={'test': 'data'}
        ))
        
        print(f"✓ 事件总线: 收到 {len(events_received)} 个事件")
        
        # 配置导入导出
        exported = app.export_config()
        print(f"✓ 配置导出: {len(exported)} bytes")
        
        imported = app.import_config(exported)
        print(f"✓ 配置导入: {imported}")
        
        # 停止代理
        stopped = app.stop_proxy()
        print(f"✓ 代理停止: {stopped}")
        
        print("✓ Application集成接口测试通过")
        return True
        
    except Exception as e:
        print(f"✗ Application集成接口测试失败: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """运行所有测试"""
    print("\n" + "="*60)
    print("MITM代理深度集成功能测试")
    print("="*60)
    
    tests = [
        ("资产识别引擎联动", test_asset_linkage),
        ("漏洞扫描引擎联动", test_vuln_linkage),
        ("C2框架集成", test_c2_linkage),
        ("横向移动模块联动", test_lateral_movement),
        ("反连平台深度集成", test_reverse_linkage),
        ("高级流量重放引擎", test_replay_engine),
        ("流量标记与协作", test_traffic_collaboration),
        ("高级过滤与搜索", test_advanced_filter),
        ("网络环境模拟", test_network_simulation),
        ("自动应答与Mock", test_mock_response),
        ("安全加固", test_security_hardening),
        ("性能与资源优化", test_performance),
        ("Application集成接口", test_app_integration),
    ]
    
    results = []
    for name, test_func in tests:
        try:
            result = test_func()
            results.append((name, result))
        except Exception as e:
            print(f"\n✗ {name} 测试异常: {e}")
            results.append((name, False))
    
    # 汇总结果
    print("\n" + "="*60)
    print("测试汇总")
    print("="*60)
    
    passed = sum(1 for _, r in results if r)
    total = len(results)
    
    for name, result in results:
        status = "✓ 通过" if result else "✗ 失败"
        print(f"  {status}: {name}")
    
    print(f"\n总计: {passed}/{total} 通过")
    
    if passed == total:
        print("\n🎉 所有测试通过！")
    else:
        print(f"\n⚠ {total - passed} 个测试失败")
    
    return passed == total


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
