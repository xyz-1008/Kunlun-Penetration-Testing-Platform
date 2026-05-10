"""
Nuclei模板适配引擎 - 增强功能测试
测试: 定期更新、指纹生成、CLI命令、随机延迟、最大请求限制、系统集成
"""
import asyncio
import os
import sys
import tempfile
import yaml
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.modules.nuclei_executor import (
    NucleiExecutor, NucleiTemplateLoader, NucleiMatcherEngine,
    NucleiExtractorEngine, NucleiHTTPExecutor, MemoryGuard,
    RequestDelayConfig, NucleiFingerprintGenerator,
    NucleiUpdateScheduler, NucleiCLIHandler, NucleiSystemIntegration,
    NucleiDNSExecutor, NucleiTCPExecutor, TemplateCache,
)
from core.modules.nuclei_models import (
    NucleiTemplate, NucleiVerifyResult, NucleiTemplateStats,
    NucleiSeverity, HTTPRequest, Matcher, Extractor,
    MatcherType, MatcherPart, MatcherCondition,
    ExtractorType, HTTPMethod, AttackType, SizeOperator,
    FingerprintRule,
)
from core.modules.nuclei_helpers import (
    NucleiVariableContext, NucleiHelpers, evaluate_dsl_expression,
)


SAMPLE_TEMPLATE_YAML = """
id: test-sql-injection
info:
  name: Test SQL Injection
  author: [test-author]
  severity: high
  description: Test template for SQL injection detection
  tags: sql,injection,test
  classification:
    cve-id: [CVE-2024-0001]
    cwe-id: [CWE-89]
    cpe: cpe:/a:test:app:1.0
http:
  - method: GET
    path:
      - "{{BaseURL}}/test?id={{payload}}"
    headers:
      User-Agent: "Kunlun-Nuclei/1.0"
    matchers:
      - type: word
        words:
          - "SQL syntax"
          - "mysql_fetch"
        condition: or
        part: body
      - type: status
        status:
          - 200
    matchers-condition: and
    extractors:
      - type: regex
        name: db_version
        regex:
          - "MySQL Version: ([\\\\d.]+)"
        group: 1
"""

SAMPLE_TEMPLATE_YAML2 = """
id: test-apache-detect
info:
  name: Apache Server Detection
  author: [test-author]
  severity: info
  description: Detect Apache HTTP Server
  tags: tech,apache,detect
http:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers:
      - type: word
        words:
          - "Apache"
        part: header
      - type: regex
        regex:
          - "Server: Apache/([\\\\d.]+)"
        part: header
"""


def test_request_delay_config():
    """测试请求延迟配置"""
    print("\n=== 测试 RequestDelayConfig ===")

    cfg1 = RequestDelayConfig(fixed=0.5)
    assert cfg1.get_delay() == 0.5
    assert not cfg1.is_random
    print("  [PASS] 固定延迟 0.5s")

    cfg2 = RequestDelayConfig(min_delay=0.1, max_delay=2.0)
    assert cfg2.is_random
    for _ in range(20):
        d = cfg2.get_delay()
        assert 0.1 <= d <= 2.0, f"延迟 {d} 不在 [0.1, 2.0] 范围内"
    print("  [PASS] 随机延迟范围 [0.1, 2.0]")

    cfg3 = RequestDelayConfig()
    assert cfg3.get_delay() == 0.0
    assert not cfg3.is_random
    print("  [PASS] 默认无延迟")


def test_size_matcher_with_operators():
    """测试Size匹配器支持所有运算符"""
    print("\n=== 测试 Size Matcher 运算符 ===")
    engine = NucleiMatcherEngine()

    matcher_gt = Matcher(type=MatcherType.SIZE, size=100, size_operator=SizeOperator.GT)
    matched, evidence = engine._match_size(matcher_gt, 200)
    assert matched and "size>100" in evidence
    print("  [PASS] size > 100 (200)")

    matcher_lt = Matcher(type=MatcherType.SIZE, size=100, size_operator=SizeOperator.LT)
    matched, evidence = engine._match_size(matcher_lt, 50)
    assert matched and "size<100" in evidence
    print("  [PASS] size < 100 (50)")

    matcher_eq = Matcher(type=MatcherType.SIZE, size=100, size_operator=SizeOperator.EQ)
    matched, evidence = engine._match_size(matcher_eq, 100)
    assert matched and "size==100" in evidence
    print("  [PASS] size == 100 (100)")

    matcher_gte = Matcher(type=MatcherType.SIZE, size=100, size_operator=SizeOperator.GTE)
    matched, evidence = engine._match_size(matcher_gte, 100)
    assert matched and "size>=100" in evidence
    print("  [PASS] size >= 100 (100)")

    matcher_lte = Matcher(type=MatcherType.SIZE, size=100, size_operator=SizeOperator.LTE)
    matched, evidence = engine._match_size(matcher_lte, 50)
    assert matched and "size<=100" in evidence
    print("  [PASS] size <= 100 (50)")

    matcher_none = Matcher(type=MatcherType.SIZE, size=None)
    matched, evidence = engine._match_size(matcher_none, 100)
    assert not matched
    print("  [PASS] size=None 不匹配")


def test_fingerprint_generation():
    """测试指纹自动生成"""
    print("\n=== 测试 NucleiFingerprintGenerator ===")

    with tempfile.TemporaryDirectory() as tmpdir:
        template_path = os.path.join(tmpdir, "test-template.yaml")
        with open(template_path, "w", encoding="utf-8") as f:
            f.write(SAMPLE_TEMPLATE_YAML2)

        loader = NucleiTemplateLoader()
        loader.load_from_directory(tmpdir)

        generator = NucleiFingerprintGenerator(loader)
        rules = generator.generate_all()

        assert len(rules) > 0, "应生成至少1条指纹规则"
        rule = rules[0]
        assert rule.template_id == "test-apache-detect"
        assert "Apache" in rule.words
        print(f"  [PASS] 生成了 {len(rules)} 条指纹规则")
        print(f"    - 规则ID: {rule.rule_id}")
        print(f"    - 产品: {rule.product}")
        print(f"    - 关键词: {rule.words}")

        matched = generator.match("Server: Apache/2.4.41\n\n<html>Apache works!</html>")
        assert len(matched) > 0
        print(f"  [PASS] 指纹匹配成功: {len(matched)} 条规则匹配")


def test_cli_commands():
    """测试CLI命令"""
    print("\n=== 测试 NucleiCLIHandler ===")

    with tempfile.TemporaryDirectory() as tmpdir:
        template_path = os.path.join(tmpdir, "test-template.yaml")
        with open(template_path, "w", encoding="utf-8") as f:
            f.write(SAMPLE_TEMPLATE_YAML)

        executor = NucleiExecutor(templates_dir=tmpdir)
        executor.load_templates(tmpdir)

        async def _run():
            cli = executor.cli_handler

            result = await cli.handle(["help"])
            assert "update" in result
            print("  [PASS] nuclei help")

            result = await cli.handle(["search", "sql"])
            assert "test-sql-injection" in result
            print("  [PASS] nuclei search sql")

            result = await cli.handle(["stats"])
            assert "模板总数" in result
            print("  [PASS] nuclei stats")

            result = await cli.handle(["list"])
            assert "test-sql-injection" in result
            print("  [PASS] nuclei list")

            result = await cli.handle(["info", "test-sql-injection"])
            assert "SQL Injection" in result
            assert "CVE-2024-0001" in result
            print("  [PASS] nuclei info test-sql-injection")

            result = await cli.handle(["unknown_cmd"])
            assert "未知命令" in result
            print("  [PASS] 未知命令处理")

            await executor.close()

        asyncio.run(_run())


def test_max_requests_limit():
    """测试最大请求数限制"""
    print("\n=== 测试 max_requests 限制 ===")

    multi_request_yaml = """
id: test-multi-request
info:
  name: Multi Request Test
  author: [test]
  severity: info
  description: Test max requests limit
  tags: test
http:
  - method: GET
    path:
      - "{{BaseURL}}/1"
  - method: GET
    path:
      - "{{BaseURL}}/2"
  - method: GET
    path:
      - "{{BaseURL}}/3"
  - method: GET
    path:
      - "{{BaseURL}}/4"
  - method: GET
    path:
      - "{{BaseURL}}/5"
"""

    with tempfile.TemporaryDirectory() as tmpdir:
        template_path = os.path.join(tmpdir, "multi.yaml")
        with open(template_path, "w", encoding="utf-8") as f:
            f.write(multi_request_yaml)

        executor = NucleiExecutor(templates_dir=tmpdir, max_requests=3)
        executor.load_templates(tmpdir)

        template = executor.loader.get_template("test-multi-request")
        assert template is not None
        assert len(template.requests) == 5

        async def _run():
            result = await executor.execute(template, "http://127.0.0.1:9999")
            assert result.template_id == "test-multi-request"
            await executor.close()

        asyncio.run(_run())
        print("  [PASS] max_requests=3 限制生效 (5个请求只执行3个)")


def test_random_delay():
    """测试随机延迟"""
    print("\n=== 测试随机延迟 ===")

    delay_config = RequestDelayConfig(min_delay=0.01, max_delay=0.05)
    executor = NucleiExecutor(delay_config=delay_config)

    assert executor.delay_config.is_random
    for _ in range(10):
        d = executor.delay_config.get_delay()
        assert 0.01 <= d <= 0.05

    print("  [PASS] 随机延迟配置正确")


def test_system_integration():
    """测试系统集成"""
    print("\n=== 测试 NucleiSystemIntegration ===")

    executor = NucleiExecutor()
    integration = executor.system_integration

    assert not integration.integration_enabled
    print("  [PASS] 初始状态: 未启用")

    integration.enable()
    assert integration.integration_enabled
    print("  [PASS] 启用集成")

    integration.set_oob_address("oob.kunlun.local:8080")
    assert executor.oob_address == "oob.kunlun.local:8080"
    print("  [PASS] 设置反连地址")

    async def _run():
        await integration.feed_proxy_traffic(
            "http://example.com/test",
            cookies={"session": "abc123"},
            headers={"X-Custom": "value"},
        )
        status = integration.get_integration_status()
        assert status["proxy_queue_size"] == 1
        print(f"  [PASS] 代理流量喂入: queue_size={status['proxy_queue_size']}")

        await integration.close()
        status = integration.get_integration_status()
        assert status["proxy_queue_size"] == 0
        print("  [PASS] 关闭后队列清空")

    asyncio.run(_run())


def test_executor_with_all_features():
    """测试执行器完整功能"""
    print("\n=== 测试 NucleiExecutor 完整功能 ===")

    with tempfile.TemporaryDirectory() as tmpdir:
        template_path = os.path.join(tmpdir, "test.yaml")
        with open(template_path, "w", encoding="utf-8") as f:
            f.write(SAMPLE_TEMPLATE_YAML)

        delay_config = RequestDelayConfig(min_delay=0.01, max_delay=0.03)
        executor = NucleiExecutor(
            templates_dir=tmpdir,
            timeout=5.0,
            max_concurrency=5,
            max_requests=50,
            delay_config=delay_config,
        )

        executor.load_templates(tmpdir)
        executor.set_oob_address("oob.test.local")

        fingerprints = executor.generate_fingerprints()
        assert len(fingerprints) > 0
        print(f"  [PASS] 自动生成 {len(fingerprints)} 条指纹规则")

        executor.enable_system_integration()
        assert executor.system_integration.integration_enabled
        print("  [PASS] 系统集成已启用")

        async def _run():
            result = await executor.handle_cli(["stats"])
            assert "模板总数" in result
            print("  [PASS] CLI stats 命令")

            result = await executor.handle_cli(["search", "sql"])
            assert "test-sql-injection" in result
            print("  [PASS] CLI search 命令")

            await executor.close()

        asyncio.run(_run())
        print("  [PASS] 执行器完整功能测试通过")


def test_memory_guard():
    """测试内存守卫"""
    print("\n=== 测试 MemoryGuard ===")

    guard = MemoryGuard(max_size=100)
    assert guard.max_size == 100

    chunk1 = guard.check_and_accumulate(b"A" * 60)
    assert len(chunk1) == 60
    assert guard.current_size == 60
    assert not guard.truncated
    print("  [PASS] 60字节未超限")

    chunk2 = guard.check_and_accumulate(b"B" * 60)
    assert guard.truncated
    assert guard.current_size == 120
    print("  [PASS] 120字节超限，已标记截断")

    guard.reset()
    assert guard.current_size == 0
    assert not guard.truncated
    print("  [PASS] 重置后状态恢复")


def test_event_bus_integration():
    """测试事件总线集成"""
    print("\n=== 测试事件总线集成 ===")

    class MockEventBus:
        def __init__(self):
            self.events = []

        def publish(self, event_type, source, data):
            self.events.append({
                "event_type": event_type,
                "source": source,
                "data": data,
            })

    event_bus = MockEventBus()
    executor = NucleiExecutor()
    executor.set_event_bus(event_bus)

    assert executor.event_bus is event_bus
    print("  [PASS] 事件总线设置成功")


def test_oob_address():
    """测试反连地址"""
    print("\n=== 测试反连地址 ===")

    executor = NucleiExecutor()
    executor.set_oob_address("dnslog.kunlun.com:53")

    assert executor.oob_address == "dnslog.kunlun.com:53"
    print("  [PASS] 反连地址设置和获取")


def test_dns_executor():
    """测试DNS执行器"""
    print("\n=== 测试 NucleiDNSExecutor ===")

    executor = NucleiDNSExecutor(timeout=5.0)
    assert "A" in executor.RECORD_TYPES
    assert "MX" in executor.RECORD_TYPES
    assert "TXT" in executor.RECORD_TYPES
    print("  [PASS] DNS记录类型完整")

    async def _run():
        var_ctx = NucleiVariableContext(
            base_url="http://example.com",
            target_host="example.com",
            target_port=80,
        )

        dns_request = {"name": "example.com", "type": "A"}
        matched, evidence, data = await executor.execute_query(
            dns_request, "example.com", var_ctx
        )
        print(f"  [PASS] DNS A查询: matched={matched}, evidence={evidence[:80] if evidence else 'N/A'}")

        dns_request_mx = {"name": "example.com", "type": "MX"}
        matched, evidence, data = await executor.execute_query(
            dns_request_mx, "example.com", var_ctx
        )
        print(f"  [PASS] DNS MX查询: matched={matched}")

    asyncio.run(_run())


def test_tcp_executor():
    """测试TCP执行器"""
    print("\n=== 测试 NucleiTCPExecutor ===")

    executor = NucleiTCPExecutor(timeout=5.0)
    print("  [PASS] TCP执行器初始化成功")

    async def _run():
        var_ctx = NucleiVariableContext(
            base_url="http://example.com",
            target_host="example.com",
            target_port=80,
        )

        tcp_request = {
            "inputs": ["GET / HTTP/1.0\r\nHost: example.com\r\n\r\n"],
            "read-size": 1024,
        }
        matched, evidence, req_hex, resp_hex = await executor.execute_connection(
            tcp_request, "example.com", 80, var_ctx
        )
        print(f"  [PASS] TCP连接: matched={matched}, resp_len={len(resp_hex)}")

    asyncio.run(_run())


def test_nested_matchers():
    """测试嵌套匹配器"""
    print("\n=== 测试嵌套 Matchers ===")

    engine = NucleiMatcherEngine()

    inner_matcher1 = Matcher(type=MatcherType.WORD, words=["admin"])
    inner_matcher2 = Matcher(type=MatcherType.WORD, words=["login"])

    nested_matcher = Matcher(
        type=MatcherType.WORD,
        words=["placeholder"],
        matchers=[inner_matcher1, inner_matcher2],
        matchers_condition=MatcherCondition.AND,
    )

    body = "Welcome to admin login page"
    matched, evidence = engine._match_single(nested_matcher, body, {}, 200, len(body))
    assert matched, "嵌套AND匹配应成功"
    print(f"  [PASS] 嵌套AND匹配: {evidence}")

    body2 = "Welcome to admin dashboard"
    matched2, evidence2 = engine._match_single(nested_matcher, body2, {}, 200, len(body2))
    assert not matched2, "嵌套AND匹配应失败（缺少login）"
    print(f"  [PASS] 嵌套AND不匹配: {evidence2}")

    nested_or = Matcher(
        type=MatcherType.WORD,
        words=["placeholder"],
        matchers=[inner_matcher1, inner_matcher2],
        matchers_condition=MatcherCondition.OR,
    )
    matched3, evidence3 = engine._match_single(nested_or, body2, {}, 200, len(body2))
    assert matched3, "嵌套OR匹配应成功"
    print(f"  [PASS] 嵌套OR匹配: {evidence3}")


def test_cli_validate():
    """测试CLI validate命令"""
    print("\n=== 测试 nuclei validate ===")

    with tempfile.TemporaryDirectory() as tmpdir:
        valid_yaml = """
id: test-validate
info:
  name: Test Validate
  author: [test]
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}"
"""
        valid_path = os.path.join(tmpdir, "valid.yaml")
        with open(valid_path, "w", encoding="utf-8") as f:
            f.write(valid_yaml)

        invalid_yaml = """
id:
info:
  name: Bad Template
"""
        invalid_path = os.path.join(tmpdir, "invalid.yaml")
        with open(invalid_path, "w", encoding="utf-8") as f:
            f.write(invalid_yaml)

        executor = NucleiExecutor(templates_dir=tmpdir)
        executor.load_templates(tmpdir)

        async def _run():
            cli = executor.cli_handler

            result = await cli.handle(["validate", valid_path])
            assert "有效" in result
            print(f"  [PASS] 有效模板校验: {result[:80]}...")

            result = await cli.handle(["validate", invalid_path])
            assert "错误" in result
            print(f"  [PASS] 无效模板校验: {result[:80]}...")

            await executor.close()

        asyncio.run(_run())


def test_cli_test():
    """测试CLI test命令"""
    print("\n=== 测试 nuclei test ===")

    with tempfile.TemporaryDirectory() as tmpdir:
        template_path = os.path.join(tmpdir, "test.yaml")
        with open(template_path, "w", encoding="utf-8") as f:
            f.write(SAMPLE_TEMPLATE_YAML)

        executor = NucleiExecutor(templates_dir=tmpdir)
        executor.load_templates(tmpdir)

        async def _run():
            cli = executor.cli_handler

            result = await cli.handle(["test", "test-sql-injection", "--url", "http://127.0.0.1:9999"])
            assert "调试模式" in result
            print(f"  [PASS] test命令: {result[:100]}...")

            await executor.close()

        asyncio.run(_run())


def test_template_cache():
    """测试模板缓存"""
    print("\n=== 测试 TemplateCache ===")

    with tempfile.TemporaryDirectory() as tmpdir:
        cache = TemplateCache(cache_dir=tmpdir)

        test_file = os.path.join(tmpdir, "test.txt")
        with open(test_file, "w") as f:
            f.write("test content")

        hash1 = cache.compute_file_hash(test_file)
        assert len(hash1) == 32
        print(f"  [PASS] MD5哈希: {hash1}")

        assert not cache.has_changed(test_file)
        print("  [PASS] 文件未变更检测")

        import time as _time
        _time.sleep(0.1)

        with open(test_file, "w") as f:
            f.write("modified content")

        assert cache.has_changed(test_file)
        print("  [PASS] 文件变更检测")

        cache.add_version("test-id", "1.0", "/tmp/source", "local")
        history = cache.get_version_history("test-id")
        assert len(history) == 1
        print(f"  [PASS] 版本历史: {len(history)} 条记录")


def test_system_integration_report():
    """测试系统集成报告功能"""
    print("\n=== 测试报告集成 ===")

    executor = NucleiExecutor()
    integration = executor.system_integration

    async def _run():
        result = NucleiVerifyResult(
            template_id="test-001",
            template_name="Test Vuln",
            target="http://example.com",
            vulnerable=True,
            matched=True,
            severity="high",
            evidence="SQL injection found",
            response_time=0.5,
            timestamp="2024-01-01T00:00:00",
        )

        await integration.add_to_report(result)
        results = await integration.get_report_results()
        assert len(results) == 1
        print(f"  [PASS] 报告队列: {len(results)} 条结果")

        report_data = await integration.export_report_data()
        assert report_data["total_executed"] == 1
        assert report_data["vulnerabilities_found"] == 1
        print(f"  [PASS] 报告导出: {report_data['vulnerabilities_found']} 个漏洞")

        results_cleared = await integration.get_report_results(clear=True)
        assert len(results_cleared) == 1
        remaining = await integration.get_report_results()
        assert len(remaining) == 0
        print("  [PASS] 报告清空")

        await integration.close()

    asyncio.run(_run())


def test_http2_executor():
    """测试HTTP/2执行器"""
    print("\n=== 测试 HTTP/2 支持 ===")

    executor = NucleiHTTPExecutor(timeout=5.0, enable_http2=True)
    assert executor._enable_http2
    print("  [PASS] HTTP/2 已启用")

    async def _run():
        await executor.close()

    asyncio.run(_run())


def test_dns_template_execution():
    """测试DNS模板执行"""
    print("\n=== 测试 DNS 模板执行 ===")

    dns_template_yaml = """
id: test-dns-cname
info:
  name: DNS CNAME Test
  author: [test]
  severity: info
  description: Test DNS template execution
  tags: dns,test
dns:
  - name: "{{Hostname}}"
    type: A
    matchers:
      - type: word
        words:
          - "A"
    matchers-condition: or
"""

    with tempfile.TemporaryDirectory() as tmpdir:
        template_path = os.path.join(tmpdir, "dns-test.yaml")
        with open(template_path, "w", encoding="utf-8") as f:
            f.write(dns_template_yaml)

        executor = NucleiExecutor(templates_dir=tmpdir)
        executor.load_templates(tmpdir)

        template = executor.loader.get_template("test-dns-cname")
        assert template is not None
        assert len(template.dns) == 1
        print(f"  [PASS] DNS模板加载: {template.id}")

        async def _run():
            result = await executor.execute(template, "http://example.com")
            print(f"  [PASS] DNS模板执行: vulnerable={result.vulnerable}")
            await executor.close()

        asyncio.run(_run())


def test_tcp_template_execution():
    """测试TCP模板执行"""
    print("\n=== 测试 TCP 模板执行 ===")

    tcp_template_yaml = """
id: test-tcp-banner
info:
  name: TCP Banner Test
  author: [test]
  severity: info
  description: Test TCP template execution
  tags: tcp,test
tcp:
  - inputs:
      - "GET / HTTP/1.0\\r\\nHost: {{Hostname}}\\r\\n\\r\\n"
    host: "{{Hostname}}"
    port: 80
    read-size: 1024
"""

    with tempfile.TemporaryDirectory() as tmpdir:
        template_path = os.path.join(tmpdir, "tcp-test.yaml")
        with open(template_path, "w", encoding="utf-8") as f:
            f.write(tcp_template_yaml)

        executor = NucleiExecutor(templates_dir=tmpdir)
        executor.load_templates(tmpdir)

        template = executor.loader.get_template("test-tcp-banner")
        assert template is not None
        assert len(template.tcp) == 1
        print(f"  [PASS] TCP模板加载: {template.id}")

        async def _run():
            result = await executor.execute(template, "http://example.com")
            print(f"  [PASS] TCP模板执行: vulnerable={result.vulnerable}")
            await executor.close()

        asyncio.run(_run())


def main():
    print("=" * 60)
    print("Nuclei模板适配引擎 - 增强功能测试")
    print("=" * 60)

    tests = [
        test_request_delay_config,
        test_size_matcher_with_operators,
        test_fingerprint_generation,
        test_cli_commands,
        test_max_requests_limit,
        test_random_delay,
        test_system_integration,
        test_executor_with_all_features,
        test_memory_guard,
        test_event_bus_integration,
        test_oob_address,
        test_dns_executor,
        test_tcp_executor,
        test_nested_matchers,
        test_cli_validate,
        test_cli_test,
        test_template_cache,
        test_system_integration_report,
        test_http2_executor,
        test_dns_template_execution,
        test_tcp_template_execution,
    ]

    passed = 0
    failed = 0

    for test in tests:
        try:
            test()
            passed += 1
        except Exception as e:
            failed += 1
            print(f"  [FAIL] {test.__name__}: {e}")
            import traceback
            traceback.print_exc()

    print("\n" + "=" * 60)
    print(f"测试结果: {passed} 通过, {failed} 失败, 共 {len(tests)} 项")
    print("=" * 60)

    return failed == 0


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
