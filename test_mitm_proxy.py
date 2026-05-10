"""
MITM代理模块测试脚本
"""

import sys
import os
import time
import threading
from datetime import datetime
from pathlib import Path

# 添加项目根目录到路径
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from core.modules.mitm_proxy_engine import (
    MITMProxyEngine, MITMRequest, MITMResponse,
    InterceptRule, InterceptAction, RuleMatchType,
    CertificateManager
)

def test_certificate_manager():
    """测试证书管理器"""
    print("=" * 60)
    print("测试 1: 证书管理器")
    print("=" * 60)
    
    cert_manager = CertificateManager("test_data/mitm_certs")
    
    # 检查CA证书是否生成
    assert cert_manager.ca_cert_path.exists(), "CA证书未生成"
    assert cert_manager.ca_key_path.exists(), "CA密钥未生成"
    print("✓ CA证书和密钥已生成")
    
    # 测试域名证书生成
    ssl_ctx = cert_manager.get_domain_ssl_context("example.com")
    assert ssl_ctx is not None, "域名SSL上下文生成失败"
    print("✓ 域名SSL上下文生成成功")
    
    # 测试证书缓存
    ssl_ctx2 = cert_manager.get_domain_ssl_context("example.com")
    assert ssl_ctx is ssl_ctx2, "证书缓存未生效"
    print("✓ 证书缓存工作正常")
    
    # 测试导出
    export_path = "test_data/exported_ca.crt"
    result = cert_manager.export_ca_cert(export_path)
    assert result, "导出CA证书失败"
    assert os.path.exists(export_path), "导出文件不存在"
    print("✓ CA证书导出成功")
    
    print("✅ 证书管理器测试通过\n")

def test_rule_engine():
    """测试规则引擎"""
    print("=" * 60)
    print("测试 2: 规则引擎")
    print("=" * 60)
    
    # 创建测试请求
    request = MITMRequest(
        id="test_001",
        timestamp=time.time(),
        method="GET",
        url="https://example.com/api/users",
        host="example.com",
        path="/api/users",
        headers={"Content-Type": "application/json", "Cookie": "session=abc123"},
        body=b'{"test": "data"}',
        is_https=True
    )
    
    # 测试域名匹配
    rule1 = InterceptRule(
        id="rule_001",
        name="域名匹配测试",
        enabled=True,
        match_type=RuleMatchType.DOMAIN,
        match_value="example.com",
        action=InterceptAction.BREAK
    )
    assert rule1.matches(request), "域名匹配失败"
    print("✓ 域名匹配规则工作正常")
    
    # 测试路径匹配
    rule2 = InterceptRule(
        id="rule_002",
        name="路径匹配测试",
        enabled=True,
        match_type=RuleMatchType.URL_PATH,
        match_value="/api/users",
        action=InterceptAction.DROP
    )
    assert rule2.matches(request), "路径匹配失败"
    print("✓ 路径匹配规则工作正常")
    
    # 测试方法匹配
    rule3 = InterceptRule(
        id="rule_003",
        name="方法匹配测试",
        enabled=True,
        match_type=RuleMatchType.METHOD,
        match_value="GET",
        action=InterceptAction.LOG
    )
    assert rule3.matches(request), "方法匹配失败"
    print("✓ 方法匹配规则工作正常")
    
    # 测试Header匹配
    rule4 = InterceptRule(
        id="rule_004",
        name="Header匹配测试",
        enabled=True,
        match_type=RuleMatchType.HEADER,
        match_value="cookie",
        action=InterceptAction.MODIFY
    )
    assert rule4.matches(request), "Header匹配失败"
    print("✓ Header匹配规则工作正常")
    
    # 测试禁用规则
    rule5 = InterceptRule(
        id="rule_005",
        name="禁用规则",
        enabled=False,
        match_type=RuleMatchType.DOMAIN,
        match_value="example.com",
        action=InterceptAction.DROP
    )
    assert not rule5.matches(request), "禁用规则仍然生效"
    print("✓ 禁用规则正确不匹配")
    
    print("✅ 规则引擎测试通过\n")

def test_proxy_engine():
    """测试代理引擎"""
    print("=" * 60)
    print("测试 3: 代理引擎")
    print("=" * 60)
    
    engine = MITMProxyEngine(host="127.0.0.1", port=18080)
    
    # 测试回调注册
    request_count = [0]
    def on_request(req):
        request_count[0] += 1
    
    engine.add_callback('on_request', on_request)
    print("✓ 回调注册成功")
    
    # 测试规则添加
    rule = InterceptRule(
        id="test_rule",
        name="测试规则",
        enabled=True,
        match_type=RuleMatchType.DOMAIN,
        match_value="test.com",
        action=InterceptAction.LOG
    )
    engine.add_rule(rule)
    assert len(engine.rules) == 1, "规则添加失败"
    print("✓ 规则添加成功")
    
    # 测试Bypass域名
    engine.add_bypass_domain("bypass.com")
    assert engine.is_bypass_domain("bypass.com"), "Bypass域名添加失败"
    assert engine.is_bypass_domain("sub.bypass.com"), "Bypass子域名匹配失败"
    assert not engine.is_bypass_domain("other.com"), "非Bypass域名错误匹配"
    print("✓ Bypass域名设置正确")
    
    # 测试状态获取
    status = engine.get_status()
    assert 'running' in status, "状态信息不完整"
    assert 'host' in status, "状态信息缺少host"
    assert 'port' in status, "状态信息缺少port"
    print("✓ 状态信息获取正常")
    
    # 测试启动/停止
    engine.start()
    time.sleep(1)  # 等待启动
    assert engine._running, "代理未启动"
    print("✓ 代理启动成功")
    
    engine.stop()
    time.sleep(0.5)  # 等待停止
    assert not engine._running, "代理未停止"
    print("✓ 代理停止成功")
    
    print("✅ 代理引擎测试通过\n")

def test_history_management():
    """测试历史记录管理"""
    print("=" * 60)
    print("测试 4: 历史记录管理")
    print("=" * 60)
    
    engine = MITMProxyEngine(host="127.0.0.1", port=18081)
    
    # 添加测试数据
    for i in range(5):
        request = MITMRequest(
            id=f"req_{i}",
            timestamp=datetime.utcnow(),
            method="GET" if i % 2 == 0 else "POST",
            url=f"https://example{i}.com/path{i}",
            host=f"example{i}.com",
            path=f"/path{i}",
            headers={},
            body=b'',
            is_https=True
        )
        engine.request_history.append(request)
    
    # 测试获取历史
    history = engine.get_history()
    assert len(history) == 5, f"历史记录数量错误: {len(history)}"
    print("✓ 历史记录获取正确")
    
    # 测试搜索 - 按域名
    results = engine.search_history(domain="example2")
    assert len(results) == 1, f"域名搜索结果错误: {len(results)}"
    print("✓ 域名搜索工作正常")
    
    # 测试搜索 - 按方法
    results = engine.search_history(method="POST")
    assert len(results) == 2, f"方法搜索结果错误: {len(results)}"
    print("✓ 方法搜索工作正常")
    
    # 测试清空历史
    engine.clear_history()
    assert len(engine.request_history) == 0, "历史清空失败"
    print("✓ 历史清空成功")
    
    print("✅ 历史记录管理测试通过\n")

def test_rule_import_export():
    """测试规则导入导出"""
    print("=" * 60)
    print("测试 5: 规则导入导出")
    print("=" * 60)
    
    engine = MITMProxyEngine(host="127.0.0.1", port=18082)
    
    # 添加规则
    rules = [
        InterceptRule(
            id="rule_001",
            name="规则1",
            enabled=True,
            match_type=RuleMatchType.DOMAIN,
            match_value="test1.com",
            action=InterceptAction.BREAK
        ),
        InterceptRule(
            id="rule_002",
            name="规则2",
            enabled=False,
            match_type=RuleMatchType.URL_PATH,
            match_value="/api",
            action=InterceptAction.DROP
        ),
    ]
    
    for rule in rules:
        engine.add_rule(rule)
    
    # 导出规则
    export_path = "test_data/rules_export.json"
    result = engine.export_rules(export_path)
    assert result, "规则导出失败"
    assert os.path.exists(export_path), "导出文件不存在"
    print("✓ 规则导出成功")
    
    # 导入规则
    engine2 = MITMProxyEngine(host="127.0.0.1", port=18083)
    result = engine2.import_rules(export_path)
    assert result, "规则导入失败"
    assert len(engine2.rules) == 2, f"规则导入数量错误: {len(engine2.rules)}"
    print("✓ 规则导入成功")
    
    print("✅ 规则导入导出测试通过\n")

def test_desensitization():
    """测试脱敏功能"""
    print("=" * 60)
    print("测试 6: 脱敏功能")
    print("=" * 60)
    
    engine = MITMProxyEngine(host="127.0.0.1", port=18084)
    
    # 设置脱敏头部
    engine.set_desensitize_headers({'authorization', 'cookie'})
    assert 'authorization' in engine._desensitize_headers, "脱敏头部设置失败"
    print("✓ 脱敏头部设置成功")
    
    # 测试IP白名单
    engine.set_ip_whitelist({'127.0.0.1', '192.168.1.100'})
    assert '127.0.0.1' in engine._ip_whitelist, "IP白名单设置失败"
    print("✓ IP白名单设置成功")
    
    print("✅ 脱敏功能测试通过\n")

def run_all_tests():
    """运行所有测试"""
    print("\n" + "=" * 60)
    print("MITM代理模块测试套件")
    print("=" * 60 + "\n")
    
    # 创建测试目录
    os.makedirs("test_data", exist_ok=True)
    
    try:
        test_certificate_manager()
        test_rule_engine()
        test_proxy_engine()
        test_history_management()
        test_rule_import_export()
        test_desensitization()
        
        print("=" * 60)
        print("🎉 所有测试通过!")
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
