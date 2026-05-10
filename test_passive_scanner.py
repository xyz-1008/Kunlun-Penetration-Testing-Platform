"""
被动扫描引擎完整功能测试
"""
import asyncio
import sys
import os
import json
import tempfile
import shutil

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.modules.passive_scanner import (
    PassiveScanner, PassiveRuleLoader, PassiveRuleEngine, PassiveRule,
    PassiveScanFinding, PassiveSeverity, PassiveRuleCategory,
    PassiveDedupManager, PassiveResultExporter, PassiveNotificationManager,
    PassiveScannerIntegration, BasePassiveRule, FindingStatus,
)

PASS_COUNT = 0
FAIL_COUNT = 0


def test(name):
    def decorator(fn):
        async def wrapper():
            global PASS_COUNT, FAIL_COUNT
            try:
                await fn()
                PASS_COUNT += 1
                print(f"  [PASS] {name}")
            except Exception as e:
                FAIL_COUNT += 1
                print(f"  [FAIL] {name}: {e}")
                import traceback
                traceback.print_exc()
        return wrapper
    return decorator


# ==================== 数据模型测试 ====================

@test("PassiveScanFinding 创建与序列化")
async def test_finding_creation():
    f = PassiveScanFinding(
        rule_id="test-001",
        rule_name="测试规则",
        category=PassiveRuleCategory.INFO_LEAK,
        severity=PassiveSeverity.HIGH,
        url="http://example.com/test",
        method="GET",
        evidence="password=admin123",
        evidence_location="body",
        status_code=200,
        host="example.com",
        path="/test",
        matched_pattern="password=",
        description="测试描述",
        remediation="测试修复建议",
    )
    d = f.to_dict()
    assert d["rule_id"] == "test-001"
    assert d["severity"] == "high"
    assert d["category"] == "信息泄露"
    assert d["url"] == "http://example.com/test"
    assert d["evidence"] == "password=admin123"
    assert len(d["finding_id"]) == 12
    assert d["status"] == "new"


@test("PassiveScanFinding evidence_context")
async def test_evidence_context():
    body = "line1\nline2\npassword=admin123\nline4\nline5"
    f = PassiveScanFinding(
        rule_id="test-001",
        rule_name="测试",
        category=PassiveRuleCategory.INFO_LEAK,
        severity=PassiveSeverity.HIGH,
        url="http://example.com/test",
        method="GET",
        evidence="password=admin123",
        evidence_location="body",
        response_body_snippet=body,
    )
    ctx = f.get_evidence_context(context_lines=1)
    assert "password=admin123" in ctx
    assert "line2" in ctx
    assert "line4" in ctx


# ==================== 规则引擎测试 ====================

@test("PassiveRuleEngine 内置规则数量")
async def test_builtin_rules_count():
    engine = PassiveRuleEngine()
    rules = engine.get_builtin_rules()
    assert len(rules) >= 30, f"期望至少30条规则，实际 {len(rules)}"
    categories = set(r.category for r in rules)
    assert PassiveRuleCategory.INFO_LEAK in categories
    assert PassiveRuleCategory.SECURITY_CONFIG in categories
    assert PassiveRuleCategory.VULN_PATTERN in categories


@test("信息泄露检测 - 内网IP")
async def test_info_leak_internal_ip():
    engine = PassiveRuleEngine()
    rule = PassiveRule(
        id="passive-info-internal-ip",
        name="内网IP",
        category=PassiveRuleCategory.INFO_LEAK,
        severity=PassiveSeverity.MEDIUM,
        matchers=[{"type": "regex", "part": "body", "patterns": [
            r'\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
            r'\b192\.168\.\d{1,3}\.\d{1,3}\b',
        ]}],
    )
    result = engine.check_rule(
        rule, "http://example.com/api", "GET",
        {}, "", {}, '{"host": "192.168.1.100"}', 200,
    )
    assert result is not None
    assert "192.168.1.100" in result.evidence


@test("信息泄露检测 - 邮箱地址")
async def test_info_leak_email():
    engine = PassiveRuleEngine()
    rule = PassiveRule(
        id="passive-info-email",
        name="邮箱泄露",
        category=PassiveRuleCategory.INFO_LEAK,
        severity=PassiveSeverity.LOW,
        matchers=[{"type": "regex", "part": "all", "patterns": [
            r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
        ]}],
    )
    result = engine.check_rule(
        rule, "http://example.com/contact", "GET",
        {}, "", {}, "联系 admin@example.com", 200,
    )
    assert result is not None
    assert "admin@example.com" in result.evidence


@test("信息泄露检测 - 云密钥(AWS)")
async def test_info_leak_cloud_key():
    engine = PassiveRuleEngine()
    rule = PassiveRule(
        id="passive-info-cloud-key",
        name="云密钥",
        category=PassiveRuleCategory.INFO_LEAK,
        severity=PassiveSeverity.HIGH,
        matchers=[{"type": "regex", "part": "body", "patterns": [
            r'AKIA[0-9A-Z]{16}',
        ]}],
    )
    result = engine.check_rule(
        rule, "http://example.com/config", "GET",
        {}, "", {}, 'aws_key = "AKIA1234567890ABCDEF"', 200,
    )
    assert result is not None
    assert "AKIA1234567890ABCDEF" in result.evidence


@test("信息泄露检测 - JWT Token")
async def test_info_leak_jwt():
    engine = PassiveRuleEngine()
    rule = PassiveRule(
        id="passive-info-jwt",
        name="JWT泄露",
        category=PassiveRuleCategory.INFO_LEAK,
        severity=PassiveSeverity.MEDIUM,
        matchers=[{"type": "regex", "part": "all", "patterns": [
            r'eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.',
        ]}],
    )
    result = engine.check_rule(
        rule, "http://example.com/api", "GET",
        {}, "", {"Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"},
        "ok", 200,
    )
    assert result is not None
    assert "eyJ" in result.evidence


@test("信息泄露检测 - 数据库连接串")
async def test_info_leak_db_connection():
    engine = PassiveRuleEngine()
    rule = PassiveRule(
        id="passive-info-db",
        name="数据库连接串",
        category=PassiveRuleCategory.INFO_LEAK,
        severity=PassiveSeverity.HIGH,
        matchers=[{"type": "regex", "part": "body", "patterns": [
            r'mysql://[^\s"\'<>]+',
        ]}],
    )
    result = engine.check_rule(
        rule, "http://example.com/config", "GET",
        {}, "", {}, 'DATABASE_URL=mysql://root:pass@localhost/db', 200,
    )
    assert result is not None
    assert "mysql://root:pass@localhost/db" in result.evidence


@test("信息泄露检测 - Git地址")
async def test_info_leak_git():
    engine = PassiveRuleEngine()
    rule = PassiveRule(
        id="passive-info-git",
        name="Git泄露",
        category=PassiveRuleCategory.INFO_LEAK,
        severity=PassiveSeverity.MEDIUM,
        matchers=[{"type": "regex", "part": "body", "patterns": [
            r'github\.com/[^\s"\'<>/]+/[^\s"\'<>/]+',
        ]}],
    )
    result = engine.check_rule(
        rule, "http://example.com/page", "GET",
        {}, "", {}, '查看源码: https://github.com/org/repo', 200,
    )
    assert result is not None
    assert "github.com/org/repo" in result.evidence


@test("信息泄露检测 - 服务器版本")
async def test_info_leak_server_version():
    engine = PassiveRuleEngine()
    rule = PassiveRule(
        id="passive-info-server",
        name="服务器版本",
        category=PassiveRuleCategory.INFO_LEAK,
        severity=PassiveSeverity.LOW,
        matchers=[{"type": "regex", "part": "header", "patterns": [
            r'Server:.*(Apache|nginx)[/\s]*[\d.]+',
        ]}],
    )
    result = engine.check_rule(
        rule, "http://example.com/", "GET",
        {}, "", {"Server": "Apache/2.4.41 (Ubuntu)"}, "", 200,
    )
    assert result is not None
    assert "Apache" in result.evidence


@test("信息泄露检测 - HTML注释敏感词")
async def test_info_leak_html_comment():
    engine = PassiveRuleEngine()
    rule = PassiveRule(
        id="passive-info-comment",
        name="HTML注释",
        category=PassiveRuleCategory.INFO_LEAK,
        severity=PassiveSeverity.LOW,
        matchers=[{"type": "regex", "part": "body", "patterns": [
            r'<!--.*?(TODO|FIXME|password|secret).*?-->',
        ]}],
    )
    result = engine.check_rule(
        rule, "http://example.com/", "GET",
        {}, "", {}, "<!-- TODO: fix password = admin123 -->", 200,
    )
    assert result is not None


@test("信息泄露检测 - 手机号码")
async def test_info_leak_phone():
    engine = PassiveRuleEngine()
    rule = PassiveRule(
        id="passive-info-phone",
        name="手机号",
        category=PassiveRuleCategory.INFO_LEAK,
        severity=PassiveSeverity.LOW,
        matchers=[{"type": "regex", "part": "body", "patterns": [r'1[3-9]\d{9}']}],
    )
    result = engine.check_rule(
        rule, "http://example.com/profile", "GET",
        {}, "", {}, "联系电话: 13800138000", 200,
    )
    assert result is not None
    assert "13800138000" in result.evidence


@test("信息泄露检测 - 身份证号")
async def test_info_leak_id_card():
    engine = PassiveRuleEngine()
    rule = PassiveRule(
        id="passive-info-idcard",
        name="身份证",
        category=PassiveRuleCategory.INFO_LEAK,
        severity=PassiveSeverity.HIGH,
        matchers=[{"type": "regex", "part": "body", "patterns": [
            r'[1-9]\d{5}(19|20)\d{2}(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])\d{3}[\dXx]',
        ]}],
    )
    result = engine.check_rule(
        rule, "http://example.com/user", "GET",
        {}, "", {}, '身份证: 110101199001011234', 200,
    )
    assert result is not None
    assert "110101199001011234" in result.evidence


@test("信息泄露检测 - SourceMap")
async def test_info_leak_sourcemap():
    engine = PassiveRuleEngine()
    rule = PassiveRule(
        id="passive-info-sourcemap",
        name="SourceMap",
        category=PassiveRuleCategory.INFO_LEAK,
        severity=PassiveSeverity.MEDIUM,
        matchers=[{"type": "regex", "part": "body", "patterns": [
            r'sourceMappingURL=[^\s"\']+\.map',
        ]}],
    )
    result = engine.check_rule(
        rule, "http://example.com/app.js", "GET",
        {}, "", {}, "//# sourceMappingURL=app.js.map", 200,
    )
    assert result is not None


@test("信息泄露检测 - 敏感文件路径")
async def test_info_leak_sensitive_file():
    engine = PassiveRuleEngine()
    rule = PassiveRule(
        id="passive-info-file",
        name="敏感文件",
        category=PassiveRuleCategory.INFO_LEAK,
        severity=PassiveSeverity.MEDIUM,
        matchers=[{"type": "regex", "part": "body", "patterns": [
            r'(\.env|web\.config|application\.properties)',
        ]}],
    )
    result = engine.check_rule(
        rule, "http://example.com/error", "GET",
        {}, "", {}, "Cannot read .env file", 200,
    )
    assert result is not None


# ==================== 安全配置检测测试 ====================

@test("安全配置检测 - 缺少X-Frame-Options")
async def test_config_xfo_missing():
    engine = PassiveRuleEngine()
    rule = PassiveRule(
        id="passive-config-xfo",
        name="缺少XFO",
        category=PassiveRuleCategory.SECURITY_CONFIG,
        severity=PassiveSeverity.MEDIUM,
        matchers=[{"type": "word", "part": "header", "words": ["X-Frame-Options"], "negative": True}],
    )
    result = engine.check_rule(
        rule, "http://example.com/", "GET",
        {}, "", {"Content-Type": "text/html"}, "", 200,
    )
    assert result is not None


@test("安全配置检测 - 存在X-Frame-Options（不应触发）")
async def test_config_xfo_present():
    engine = PassiveRuleEngine()
    rule = PassiveRule(
        id="passive-config-xfo",
        name="缺少XFO",
        category=PassiveRuleCategory.SECURITY_CONFIG,
        severity=PassiveSeverity.MEDIUM,
        matchers=[{"type": "word", "part": "header", "words": ["X-Frame-Options"], "negative": True}],
    )
    result = engine.check_rule(
        rule, "http://example.com/", "GET",
        {}, "", {"X-Frame-Options": "DENY"}, "", 200,
    )
    assert result is None


@test("安全配置检测 - 缺少HSTS")
async def test_config_hsts_missing():
    engine = PassiveRuleEngine()
    rule = PassiveRule(
        id="passive-config-hsts",
        name="缺少HSTS",
        category=PassiveRuleCategory.SECURITY_CONFIG,
        severity=PassiveSeverity.MEDIUM,
        matchers=[{"type": "word", "part": "header", "words": ["Strict-Transport-Security"], "negative": True}],
    )
    result = engine.check_rule(
        rule, "https://example.com/", "GET",
        {}, "", {"Content-Type": "text/html"}, "", 200,
    )
    assert result is not None


@test("安全配置检测 - 缺少CSP")
async def test_config_csp_missing():
    engine = PassiveRuleEngine()
    rule = PassiveRule(
        id="passive-config-csp",
        name="缺少CSP",
        category=PassiveRuleCategory.SECURITY_CONFIG,
        severity=PassiveSeverity.LOW,
        matchers=[{"type": "word", "part": "header", "words": ["Content-Security-Policy"], "negative": True}],
    )
    result = engine.check_rule(
        rule, "http://example.com/", "GET",
        {}, "", {}, "", 200,
    )
    assert result is not None


@test("安全配置检测 - 缺少X-Content-Type-Options")
async def test_config_xcto_missing():
    engine = PassiveRuleEngine()
    rule = PassiveRule(
        id="passive-config-xcto",
        name="缺少XCTO",
        category=PassiveRuleCategory.SECURITY_CONFIG,
        severity=PassiveSeverity.LOW,
        matchers=[{"type": "word", "part": "header", "words": ["X-Content-Type-Options"], "negative": True}],
    )
    result = engine.check_rule(
        rule, "http://example.com/", "GET",
        {}, "", {}, "", 200,
    )
    assert result is not None


@test("安全配置检测 - Cookie缺少HttpOnly")
async def test_config_cookie_httponly():
    engine = PassiveRuleEngine()
    rule = PassiveRule(
        id="passive-config-cookie",
        name="Cookie标志",
        category=PassiveRuleCategory.SECURITY_CONFIG,
        severity=PassiveSeverity.MEDIUM,
        matchers=[{"type": "regex", "part": "header", "patterns": [
            r'Set-Cookie:(?:(?!HttpOnly).)*$',
        ]}],
    )
    result = engine.check_rule(
        rule, "http://example.com/login", "POST",
        {}, "", {"Set-Cookie": "session=abc123; Path=/"}, "", 200,
    )
    assert result is not None


@test("安全配置检测 - CORS配置宽松")
async def test_config_cors_wildcard():
    engine = PassiveRuleEngine()
    rule = PassiveRule(
        id="passive-config-cors",
        name="CORS宽松",
        category=PassiveRuleCategory.SECURITY_CONFIG,
        severity=PassiveSeverity.MEDIUM,
        matchers=[{"type": "word", "part": "header", "words": ["Access-Control-Allow-Origin: *"]}],
    )
    result = engine.check_rule(
        rule, "http://example.com/api", "GET",
        {}, "", {"Access-Control-Allow-Origin": "*"}, "", 200,
    )
    assert result is not None


@test("安全配置检测 - CORS危险配置(Origin:* + Credentials:true)")
async def test_config_cors_dangerous():
    engine = PassiveRuleEngine()
    rule = PassiveRule(
        id="passive-config-cors-danger",
        name="CORS危险",
        category=PassiveRuleCategory.SECURITY_CONFIG,
        severity=PassiveSeverity.HIGH,
        matchers=[{
            "type": "word", "part": "header",
            "words": ["Access-Control-Allow-Origin: *", "Access-Control-Allow-Credentials: true"],
            "match_all": True,
        }],
    )
    result = engine.check_rule(
        rule, "http://example.com/api", "GET",
        {}, "", {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true",
        }, "", 200,
    )
    assert result is not None


@test("安全配置检测 - 缺少Referrer-Policy")
async def test_config_referrer_policy():
    engine = PassiveRuleEngine()
    rule = PassiveRule(
        id="passive-config-referrer",
        name="缺少Referrer-Policy",
        category=PassiveRuleCategory.SECURITY_CONFIG,
        severity=PassiveSeverity.LOW,
        matchers=[{"type": "word", "part": "header", "words": ["Referrer-Policy"], "negative": True}],
    )
    result = engine.check_rule(
        rule, "http://example.com/", "GET",
        {}, "", {}, "", 200,
    )
    assert result is not None


@test("安全配置检测 - 缺少Permissions-Policy")
async def test_config_permissions_policy():
    engine = PassiveRuleEngine()
    rule = PassiveRule(
        id="passive-config-permissions",
        name="缺少Permissions-Policy",
        category=PassiveRuleCategory.SECURITY_CONFIG,
        severity=PassiveSeverity.LOW,
        matchers=[{"type": "word", "part": "header", "words": ["Permissions-Policy"], "negative": True}],
    )
    result = engine.check_rule(
        rule, "http://example.com/", "GET",
        {}, "", {}, "", 200,
    )
    assert result is not None


@test("安全配置检测 - 缺少Cache-Control")
async def test_config_cache_control():
    engine = PassiveRuleEngine()
    rule = PassiveRule(
        id="passive-config-cache",
        name="缺少Cache-Control",
        category=PassiveRuleCategory.SECURITY_CONFIG,
        severity=PassiveSeverity.LOW,
        matchers=[{"type": "word", "part": "header", "words": ["Cache-Control"], "negative": True}],
    )
    result = engine.check_rule(
        rule, "http://example.com/sensitive", "GET",
        {}, "", {}, "", 200,
    )
    assert result is not None


# ==================== 漏洞模式检测测试 ====================

@test("漏洞模式检测 - SQL错误消息")
async def test_vuln_sql_error():
    engine = PassiveRuleEngine()
    rule = PassiveRule(
        id="passive-vuln-sql",
        name="SQL错误",
        category=PassiveRuleCategory.VULN_PATTERN,
        severity=PassiveSeverity.HIGH,
        matchers=[{"type": "regex", "part": "body", "patterns": [
            r'You have an error in your SQL syntax',
            r'ORA-\d{5}',
        ]}],
    )
    result = engine.check_rule(
        rule, "http://example.com/search?id=1'", "GET",
        {}, "", {}, "You have an error in your SQL syntax; check the manual", 200,
    )
    assert result is not None
    assert "SQL syntax" in result.evidence


@test("漏洞模式检测 - 堆栈跟踪")
async def test_vuln_stack_trace():
    engine = PassiveRuleEngine()
    rule = PassiveRule(
        id="passive-vuln-stack",
        name="堆栈跟踪",
        category=PassiveRuleCategory.VULN_PATTERN,
        severity=PassiveSeverity.MEDIUM,
        matchers=[{"type": "regex", "part": "body", "patterns": [
            r'Traceback \(most recent call last\)',
        ]}],
    )
    result = engine.check_rule(
        rule, "http://example.com/error", "GET",
        {}, "", {}, "Traceback (most recent call last):\n  File \"app.py\", line 10", 500,
    )
    assert result is not None


@test("漏洞模式检测 - 服务器路径泄露")
async def test_vuln_path_disclosure():
    engine = PassiveRuleEngine()
    rule = PassiveRule(
        id="passive-vuln-path",
        name="路径泄露",
        category=PassiveRuleCategory.VULN_PATTERN,
        severity=PassiveSeverity.MEDIUM,
        matchers=[{"type": "regex", "part": "body", "patterns": [
            r'/var/www/[\w/]+',
        ]}],
    )
    result = engine.check_rule(
        rule, "http://example.com/error", "GET",
        {}, "", {}, "File not found: /var/www/html/index.php", 404,
    )
    assert result is not None


@test("漏洞模式检测 - 目录列表暴露")
async def test_vuln_directory_listing():
    engine = PassiveRuleEngine()
    rule = PassiveRule(
        id="passive-vuln-dir",
        name="目录列表",
        category=PassiveRuleCategory.VULN_PATTERN,
        severity=PassiveSeverity.MEDIUM,
        matchers=[{"type": "regex", "part": "body", "patterns": [
            r'<title>Index of /[\w/]*</title>',
        ]}],
    )
    result = engine.check_rule(
        rule, "http://example.com/uploads/", "GET",
        {}, "", {}, "<html><head><title>Index of /uploads/</title></head></html>", 200,
    )
    assert result is not None


@test("漏洞模式检测 - PHP探针(phpinfo)")
async def test_vuln_php_info():
    engine = PassiveRuleEngine()
    rule = PassiveRule(
        id="passive-vuln-phpinfo",
        name="PHP探针",
        category=PassiveRuleCategory.VULN_PATTERN,
        severity=PassiveSeverity.HIGH,
        matchers=[{"type": "regex", "part": "body", "patterns": [
            r'<title>phpinfo\(\)</title>',
        ]}],
    )
    result = engine.check_rule(
        rule, "http://example.com/phpinfo.php", "GET",
        {}, "", {}, "<title>phpinfo()</title>", 200,
    )
    assert result is not None


@test("漏洞模式检测 - 调试模式(Django)")
async def test_vuln_debug_mode():
    engine = PassiveRuleEngine()
    rule = PassiveRule(
        id="passive-vuln-debug",
        name="调试模式",
        category=PassiveRuleCategory.VULN_PATTERN,
        severity=PassiveSeverity.HIGH,
        matchers=[{"type": "regex", "part": "body", "patterns": [
            r'Django DEBUG = True',
        ]}],
    )
    result = engine.check_rule(
        rule, "http://example.com/error", "GET",
        {}, "", {}, "Django DEBUG = True\nSettings...", 500,
    )
    assert result is not None


@test("漏洞模式检测 - Actuator暴露")
async def test_vuln_actuator():
    engine = PassiveRuleEngine()
    rule = PassiveRule(
        id="passive-vuln-actuator",
        name="Actuator",
        category=PassiveRuleCategory.VULN_PATTERN,
        severity=PassiveSeverity.HIGH,
        matchers=[{"type": "regex", "part": "body", "patterns": [
            r'"_links":\s*\{',
        ]}],
    )
    result = engine.check_rule(
        rule, "http://example.com/actuator", "GET",
        {}, "", {}, '{"_links": {"self": {"href": "http://example.com/actuator"}}}', 200,
    )
    assert result is not None


@test("漏洞模式检测 - .env文件泄露")
async def test_vuln_env_exposed():
    engine = PassiveRuleEngine()
    rule = PassiveRule(
        id="passive-vuln-env",
        name=".env泄露",
        category=PassiveRuleCategory.VULN_PATTERN,
        severity=PassiveSeverity.CRITICAL,
        matchers=[{"type": "regex", "part": "body", "patterns": [
            r'^DB_PASSWORD=',
        ]}],
    )
    result = engine.check_rule(
        rule, "http://example.com/.env", "GET",
        {}, "", {}, "DB_PASSWORD=supersecret\nAPP_KEY=base64:xxx", 200,
    )
    assert result is not None


@test("漏洞模式检测 - Swagger暴露")
async def test_vuln_swagger():
    engine = PassiveRuleEngine()
    rule = PassiveRule(
        id="passive-vuln-swagger",
        name="Swagger",
        category=PassiveRuleCategory.VULN_PATTERN,
        severity=PassiveSeverity.MEDIUM,
        matchers=[{"type": "regex", "part": "body", "patterns": [
            r'"swagger":\s*"[\d.]+"',
        ]}],
    )
    result = engine.check_rule(
        rule, "http://example.com/swagger.json", "GET",
        {}, "", {}, '{"swagger": "2.0", "info": {"title": "API"}}', 200,
    )
    assert result is not None


@test("漏洞模式检测 - GraphQL内省")
async def test_vuln_graphql():
    engine = PassiveRuleEngine()
    rule = PassiveRule(
        id="passive-vuln-graphql",
        name="GraphQL",
        category=PassiveRuleCategory.VULN_PATTERN,
        severity=PassiveSeverity.MEDIUM,
        matchers=[{"type": "regex", "part": "body", "patterns": [
            r'"__schema":\s*\{',
        ]}],
    )
    result = engine.check_rule(
        rule, "http://example.com/graphql", "POST",
        {}, "", {}, '{"data": {"__schema": {"types": []}}}', 200,
    )
    assert result is not None


@test("漏洞模式检测 - 详细错误消息")
async def test_vuln_error_message():
    engine = PassiveRuleEngine()
    rule = PassiveRule(
        id="passive-vuln-error",
        name="错误消息",
        category=PassiveRuleCategory.VULN_PATTERN,
        severity=PassiveSeverity.MEDIUM,
        matchers=[{"type": "regex", "part": "body", "patterns": [
            r'Fatal error:\s+.*in\s+[\w/\\\.]+',
        ]}],
    )
    result = engine.check_rule(
        rule, "http://example.com/page.php", "GET",
        {}, "", {}, "Fatal error: Call to undefined function foo() in /var/www/html/page.php on line 42", 500,
    )
    assert result is not None


@test("漏洞模式检测 - crossdomain.xml宽松")
async def test_vuln_crossdomain():
    engine = PassiveRuleEngine()
    rule = PassiveRule(
        id="passive-vuln-crossdomain",
        name="crossdomain",
        category=PassiveRuleCategory.VULN_PATTERN,
        severity=PassiveSeverity.LOW,
        matchers=[{"type": "regex", "part": "body", "patterns": [
            r'<allow-access-from domain="\*"',
        ]}],
    )
    result = engine.check_rule(
        rule, "http://example.com/crossdomain.xml", "GET",
        {}, "", {}, '<allow-access-from domain="*" />', 200,
    )
    assert result is not None


# ==================== 去重管理器测试 ====================

@test("PassiveDedupManager 基本去重")
async def test_dedup_basic():
    tmpdir = tempfile.mkdtemp()
    try:
        db_path = os.path.join(tmpdir, "dedup.db")
        mgr = PassiveDedupManager(db_path)
        assert not mgr.is_duplicate("rule-1", "http://example.com/test", "evidence-1")
        assert mgr.is_duplicate("rule-1", "http://example.com/test", "evidence-1")
        assert not mgr.is_duplicate("rule-1", "http://example.com/test", "evidence-2")
        assert not mgr.is_duplicate("rule-2", "http://example.com/test", "evidence-1")
        assert not mgr.is_duplicate("rule-1", "http://example.com/other", "evidence-1")
        mgr.close()
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


@test("PassiveDedupManager 持久化")
async def test_dedup_persistence():
    tmpdir = tempfile.mkdtemp()
    try:
        db_path = os.path.join(tmpdir, "dedup.db")
        mgr1 = PassiveDedupManager(db_path)
        mgr1.is_duplicate("rule-1", "http://example.com/test", "evidence-1")
        mgr1.close()

        mgr2 = PassiveDedupManager(db_path)
        assert mgr2.is_duplicate("rule-1", "http://example.com/test", "evidence-1")
        mgr2.close()
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


@test("PassiveDedupManager 清除所有")
async def test_dedup_clear_all():
    tmpdir = tempfile.mkdtemp()
    try:
        db_path = os.path.join(tmpdir, "dedup.db")
        mgr = PassiveDedupManager(db_path)
        mgr.is_duplicate("rule-1", "http://example.com/test", "evidence-1")
        mgr.clear_all()
        assert not mgr.is_duplicate("rule-1", "http://example.com/test", "evidence-1")
        mgr.close()
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


@test("PassiveDedupManager 按规则清除")
async def test_dedup_clear_by_rule():
    tmpdir = tempfile.mkdtemp()
    try:
        db_path = os.path.join(tmpdir, "dedup.db")
        mgr = PassiveDedupManager(db_path)
        mgr.is_duplicate("rule-1", "http://example.com/test", "evidence-1")
        mgr.is_duplicate("rule-2", "http://example.com/test", "evidence-1")
        mgr.clear_by_rule("rule-1")
        assert not mgr.is_duplicate("rule-1", "http://example.com/test", "evidence-1")
        assert mgr.is_duplicate("rule-2", "http://example.com/test", "evidence-1")
        mgr.close()
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


@test("PassiveDedupManager 按URL清除")
async def test_dedup_clear_by_url():
    tmpdir = tempfile.mkdtemp()
    try:
        db_path = os.path.join(tmpdir, "dedup.db")
        mgr = PassiveDedupManager(db_path)
        mgr.is_duplicate("rule-1", "http://example.com/test1", "evidence-1")
        mgr.is_duplicate("rule-1", "http://example.com/test2", "evidence-1")
        mgr.clear_by_url("http://example.com/test1")
        assert not mgr.is_duplicate("rule-1", "http://example.com/test1", "evidence-1")
        assert mgr.is_duplicate("rule-1", "http://example.com/test2", "evidence-1")
        mgr.close()
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


# ==================== 结果导出测试 ====================

@test("PassiveResultExporter JSON导出")
async def test_export_json():
    findings = [
        PassiveScanFinding(
            rule_id="test-001", rule_name="测试规则1",
            category=PassiveRuleCategory.INFO_LEAK, severity=PassiveSeverity.HIGH,
            url="http://example.com/test1", method="GET",
            evidence="password=123", evidence_location="body",
        ),
        PassiveScanFinding(
            rule_id="test-002", rule_name="测试规则2",
            category=PassiveRuleCategory.SECURITY_CONFIG, severity=PassiveSeverity.MEDIUM,
            url="http://example.com/test2", method="POST",
            evidence="missing header", evidence_location="header",
        ),
    ]
    json_str = PassiveResultExporter.export_json(findings)
    data = json.loads(json_str)
    assert len(data) == 2
    assert data[0]["rule_id"] == "test-001"
    assert data[1]["severity"] == "medium"


@test("PassiveResultExporter HTML导出")
async def test_export_html():
    findings = [
        PassiveScanFinding(
            rule_id="test-001", rule_name="测试规则",
            category=PassiveRuleCategory.VULN_PATTERN, severity=PassiveSeverity.CRITICAL,
            url="http://example.com/test", method="GET",
            evidence="critical finding", evidence_location="body",
            remediation="立即修复",
        ),
    ]
    html = PassiveResultExporter.export_html(findings, "测试报告")
    assert "<!DOCTYPE html>" in html
    assert "测试报告" in html
    assert "CRITICAL" in html
    assert "critical finding" in html
    assert "立即修复" in html


# ==================== 规则加载器测试 ====================

@test("PassiveRuleLoader 加载YAML规则")
async def test_rule_loader_yaml():
    tmpdir = tempfile.mkdtemp()
    try:
        rule_file = os.path.join(tmpdir, "test_rule.yaml")
        with open(rule_file, "w", encoding="utf-8") as f:
            f.write("""
id: test-yaml-rule
info:
  name: 测试YAML规则
  category: 信息泄露
  severity: medium
  description: 测试描述
  remediation: 测试修复
enabled: true
matchers:
  - type: regex
    part: body
    patterns:
      - 'test_pattern'
""")
        loader = PassiveRuleLoader()
        count = loader.load_from_directory(tmpdir)
        assert count == 1
        assert "test-yaml-rule" in loader.rules
        rule = loader.rules["test-yaml-rule"]
        assert rule.name == "测试YAML规则"
        assert rule.category == PassiveRuleCategory.INFO_LEAK
        assert rule.severity == PassiveSeverity.MEDIUM
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


@test("PassiveRuleLoader 加载Python规则")
async def test_rule_loader_python():
    tmpdir = tempfile.mkdtemp()
    try:
        rule_file = os.path.join(tmpdir, "test_python_rule.py")
        with open(rule_file, "w", encoding="utf-8") as f:
            f.write("""
from core.modules.passive_scanner import BasePassiveRule, PassiveScanFinding

class TestPythonRule(BasePassiveRule):
    RULE_ID = "test-python-rule"
    RULE_NAME = "测试Python规则"
    RULE_CATEGORY = "信息泄露"
    RULE_SEVERITY = "high"
    RULE_DESCRIPTION = "Python规则测试"

    def check(self, task_data):
        if "secret" in task_data.get("response_body", ""):
            return PassiveScanFinding(
                rule_id=self.RULE_ID,
                rule_name=self.RULE_NAME,
                category="信息泄露",
                severity="high",
                url=task_data.get("url", ""),
                method=task_data.get("method", "GET"),
                evidence="found secret",
                evidence_location="body",
            )
        return None
""")
        loader = PassiveRuleLoader()
        count = loader.load_from_directory(tmpdir)
        assert count == 1
        assert "test-python-rule" in loader.rules
        assert "custom_test-python-rule" in loader.python_handlers
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


@test("PassiveRuleLoader 规则搜索")
async def test_rule_loader_search():
    loader = PassiveRuleLoader()
    loader._rules["test-sql-rule"] = PassiveRule(
        id="test-sql-rule", name="SQL注入检测",
        category=PassiveRuleCategory.VULN_PATTERN, severity=PassiveSeverity.HIGH,
    )
    loader._rules["test-xss-rule"] = PassiveRule(
        id="test-xss-rule", name="XSS检测",
        category=PassiveRuleCategory.VULN_PATTERN, severity=PassiveSeverity.MEDIUM,
    )
    results = loader.search_rules("sql")
    assert len(results) == 1
    assert results[0].id == "test-sql-rule"


@test("PassiveRuleLoader 启用/禁用规则")
async def test_rule_loader_enable_disable():
    loader = PassiveRuleLoader()
    loader._rules["test-rule"] = PassiveRule(
        id="test-rule", name="测试",
        category=PassiveRuleCategory.INFO_LEAK, severity=PassiveSeverity.LOW,
        enabled=True,
    )
    loader.disable_rule("test-rule")
    assert not loader.rules["test-rule"].enabled
    loader.enable_rule("test-rule")
    assert loader.rules["test-rule"].enabled


# ==================== 被动扫描器集成测试 ====================

@test("PassiveScanner 初始化和启动停止")
async def test_scanner_lifecycle():
    tmpdir = tempfile.mkdtemp()
    try:
        db_path = os.path.join(tmpdir, "dedup.db")
        scanner = PassiveScanner(
            max_workers=2,
            max_queue_size=100,
            dedup_db_path=db_path,
        )
        scanner.initialize()
        await scanner.start()
        assert scanner._running
        assert len(scanner._workers) == 2
        await scanner.stop()
        assert not scanner._running
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


@test("PassiveScanner 提交和分析流量")
async def test_scanner_submit_and_analyze():
    tmpdir = tempfile.mkdtemp()
    try:
        db_path = os.path.join(tmpdir, "dedup.db")
        scanner = PassiveScanner(
            max_workers=2,
            max_queue_size=100,
            dedup_db_path=db_path,
        )
        scanner.initialize()
        await scanner.start()

        await scanner.submit(
            url="http://example.com/api",
            method="GET",
            request_headers={},
            request_body="",
            response_headers={},
            response_body='{"host": "192.168.1.100", "email": "admin@test.com"}',
            status_code=200,
        )

        await asyncio.sleep(0.5)
        await scanner.stop()

        findings = scanner.findings
        assert len(findings) > 0, f"期望至少1个发现，实际 {len(findings)}"
        rule_ids = [f.rule_id for f in findings]
        assert "passive-info-internal-ip" in rule_ids or "passive-info-email-leak" in rule_ids
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


@test("PassiveScanner 静态资源跳过")
async def test_scanner_skip_static():
    tmpdir = tempfile.mkdtemp()
    try:
        db_path = os.path.join(tmpdir, "dedup.db")
        scanner = PassiveScanner(
            max_workers=1,
            dedup_db_path=db_path,
        )
        scanner.initialize()
        await scanner.start()

        await scanner.submit(
            url="http://example.com/style.css",
            method="GET",
            request_headers={}, request_body="",
            response_headers={}, response_body="body { color: red; }",
            status_code=200,
        )

        await asyncio.sleep(0.3)
        await scanner.stop()

        assert scanner._stats["requests_skipped"] >= 1
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


@test("PassiveScanner 域名黑名单")
async def test_scanner_domain_blacklist():
    tmpdir = tempfile.mkdtemp()
    try:
        db_path = os.path.join(tmpdir, "dedup.db")
        scanner = PassiveScanner(
            max_workers=1,
            dedup_db_path=db_path,
        )
        scanner.add_domain_blacklist("blocked.com")
        scanner.initialize()
        await scanner.start()

        await scanner.submit(
            url="http://blocked.com/api",
            method="GET",
            request_headers={}, request_body="",
            response_headers={}, response_body="sensitive data",
            status_code=200,
        )

        await asyncio.sleep(0.3)
        await scanner.stop()

        assert scanner._stats["requests_skipped"] >= 1
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


@test("PassiveScanner 去重机制")
async def test_scanner_dedup():
    tmpdir = tempfile.mkdtemp()
    try:
        db_path = os.path.join(tmpdir, "dedup.db")
        scanner = PassiveScanner(
            max_workers=1,
            dedup_db_path=db_path,
        )
        scanner.initialize()
        await scanner.start()

        for _ in range(3):
            await scanner.submit(
                url="http://example.com/api",
                method="GET",
                request_headers={}, request_body="",
                response_headers={}, response_body='{"host": "192.168.1.100"}',
                status_code=200,
            )

        await asyncio.sleep(0.5)
        await scanner.stop()

        ip_findings = [f for f in scanner.findings if f.rule_id == "passive-info-internal-ip"]
        assert len(ip_findings) == 1, f"去重失败，期望1个发现，实际 {len(ip_findings)}"
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


@test("PassiveScanner 结果导出")
async def test_scanner_export():
    tmpdir = tempfile.mkdtemp()
    try:
        db_path = os.path.join(tmpdir, "dedup.db")
        scanner = PassiveScanner(
            max_workers=1,
            dedup_db_path=db_path,
        )
        scanner.initialize()
        await scanner.start()

        await scanner.submit(
            url="http://example.com/api",
            method="GET",
            request_headers={}, request_body="",
            response_headers={}, response_body='{"host": "192.168.1.100"}',
            status_code=200,
        )

        await asyncio.sleep(0.5)
        await scanner.stop()

        json_out = scanner.export_findings_json()
        assert len(json.loads(json_out)) > 0

        html_out = scanner.export_findings_html()
        assert "<!DOCTYPE html>" in html_out
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


@test("PassiveScanner 统计信息")
async def test_scanner_stats():
    tmpdir = tempfile.mkdtemp()
    try:
        db_path = os.path.join(tmpdir, "dedup.db")
        scanner = PassiveScanner(
            max_workers=1,
            dedup_db_path=db_path,
        )
        scanner.initialize()
        await scanner.start()

        await scanner.submit(
            url="http://example.com/api",
            method="GET",
            request_headers={}, request_body="",
            response_headers={}, response_body='{"host": "192.168.1.100"}',
            status_code=200,
        )

        await asyncio.sleep(0.5)
        await scanner.stop()

        stats = scanner.stats
        assert stats["requests_analyzed"] >= 1
        assert stats["findings_total"] >= 1
        assert "dedup_stats" in stats
        assert "queue_size" in stats
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


@test("PassiveScanner UI数据")
async def test_scanner_ui_data():
    tmpdir = tempfile.mkdtemp()
    try:
        db_path = os.path.join(tmpdir, "dedup.db")
        scanner = PassiveScanner(
            max_workers=1,
            dedup_db_path=db_path,
        )
        scanner.initialize()
        await scanner.start()

        await scanner.submit(
            url="http://example.com/api",
            method="GET",
            request_headers={}, request_body="",
            response_headers={}, response_body='{"host": "192.168.1.100"}',
            status_code=200,
        )

        await asyncio.sleep(0.5)
        await scanner.stop()

        ui_data = scanner.get_ui_data()
        assert "stats" in ui_data
        assert "recent_findings" in ui_data
        assert "rules_count" in ui_data
        assert "enabled_rules_count" in ui_data
        assert "running" in ui_data
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


# ==================== 集成桥接测试 ====================

@test("PassiveScannerIntegration 创建和挂载")
async def test_integration_create():
    tmpdir = tempfile.mkdtemp()
    try:
        db_path = os.path.join(tmpdir, "dedup.db")
        scanner = PassiveScanner(dedup_db_path=db_path)
        scanner.initialize()
        integration = PassiveScannerIntegration(scanner)
        assert integration._scanner is scanner
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


@test("PassiveScannerIntegration URL高亮信息")
async def test_integration_highlight():
    tmpdir = tempfile.mkdtemp()
    try:
        db_path = os.path.join(tmpdir, "dedup.db")
        scanner = PassiveScanner(dedup_db_path=db_path)
        scanner.initialize()
        await scanner.start()

        await scanner.submit(
            url="http://example.com/vuln",
            method="GET",
            request_headers={}, request_body="",
            response_headers={}, response_body='{"host": "192.168.1.100"}',
            status_code=200,
        )

        await asyncio.sleep(0.5)
        await scanner.stop()

        integration = PassiveScannerIntegration(scanner)
        info = integration.get_url_highlight_info("http://example.com/vuln")
        assert info is not None
        assert info["has_findings"]
        assert info["finding_count"] >= 1

        no_info = integration.get_url_highlight_info("http://example.com/clean")
        assert no_info is None
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


@test("PassiveScannerIntegration 漏洞详情")
async def test_integration_detail():
    tmpdir = tempfile.mkdtemp()
    try:
        db_path = os.path.join(tmpdir, "dedup.db")
        scanner = PassiveScanner(dedup_db_path=db_path)
        scanner.initialize()
        await scanner.start()

        await scanner.submit(
            url="http://example.com/vuln",
            method="GET",
            request_headers={}, request_body="",
            response_headers={}, response_body='{"host": "192.168.1.100"}',
            status_code=200,
        )

        await asyncio.sleep(0.5)
        await scanner.stop()

        integration = PassiveScannerIntegration(scanner)
        finding = scanner.findings[0]
        detail = integration.get_finding_detail(finding.finding_id)
        assert detail is not None
        assert detail["rule_id"] == finding.rule_id
        assert "evidence_context" in detail

        no_detail = integration.get_finding_detail("nonexistent")
        assert no_detail is None
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


@test("PassiveScannerIntegration 发送到Repeater")
async def test_integration_send_repeater():
    tmpdir = tempfile.mkdtemp()
    try:
        db_path = os.path.join(tmpdir, "dedup.db")
        scanner = PassiveScanner(dedup_db_path=db_path)
        scanner.initialize()
        await scanner.start()

        await scanner.submit(
            url="http://example.com/vuln",
            method="POST",
            request_headers={"Content-Type": "application/json"},
            request_body='{"query": "test"}',
            response_headers={}, response_body='{"host": "192.168.1.100"}',
            status_code=200,
        )

        await asyncio.sleep(0.5)
        await scanner.stop()

        integration = PassiveScannerIntegration(scanner)
        finding = scanner.findings[0]
        repeater_data = integration.send_to_repeater(finding.finding_id)
        assert repeater_data is not None
        assert repeater_data["url"] == "http://example.com/vuln"
        assert repeater_data["method"] == "POST"
        assert repeater_data["headers"]["Content-Type"] == "application/json"
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


@test("PassiveScannerIntegration 发送到Fuzzer")
async def test_integration_send_fuzzer():
    tmpdir = tempfile.mkdtemp()
    try:
        db_path = os.path.join(tmpdir, "dedup.db")
        scanner = PassiveScanner(dedup_db_path=db_path)
        scanner.initialize()
        await scanner.start()

        await scanner.submit(
            url="http://example.com/vuln",
            method="GET",
            request_headers={}, request_body="",
            response_headers={}, response_body='{"host": "192.168.1.100"}',
            status_code=200,
        )

        await asyncio.sleep(0.5)
        await scanner.stop()

        integration = PassiveScannerIntegration(scanner)
        finding = scanner.findings[0]
        fuzzer_data = integration.send_to_fuzzer(finding.finding_id)
        assert fuzzer_data is not None
        assert "injection_point" in fuzzer_data
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


@test("PassiveScannerIntegration 白名单和忽略")
async def test_integration_whitelist_ignore():
    tmpdir = tempfile.mkdtemp()
    try:
        db_path = os.path.join(tmpdir, "dedup.db")
        scanner = PassiveScanner(dedup_db_path=db_path)
        scanner.initialize()
        await scanner.start()

        await scanner.submit(
            url="http://example.com/vuln",
            method="GET",
            request_headers={}, request_body="",
            response_headers={}, response_body='{"host": "192.168.1.100"}',
            status_code=200,
        )

        await asyncio.sleep(0.5)
        await scanner.stop()

        integration = PassiveScannerIntegration(scanner)
        integration.add_to_whitelist("http://example.com/vuln")
        assert "http://example.com/vuln" in scanner._url_whitelist

        finding = scanner.findings[0]
        integration.ignore_finding(finding.finding_id)
        assert finding.status == FindingStatus.IGNORED
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


# ==================== BasePassiveRule 测试 ====================

@test("BasePassiveRule 抽象基类")
async def test_base_rule():
    class CustomRule(BasePassiveRule):
        RULE_ID = "custom-test"
        RULE_NAME = "自定义测试规则"
        RULE_CATEGORY = "信息泄露"
        RULE_SEVERITY = "high"
        RULE_DESCRIPTION = "自定义规则描述"

        def check(self, task_data):
            return None

    instance = CustomRule()
    rule = instance.to_passive_rule("test.py")
    assert rule.id == "custom-test"
    assert rule.name == "自定义测试规则"
    assert rule.category == PassiveRuleCategory.INFO_LEAK
    assert rule.severity == PassiveSeverity.HIGH
    assert rule.source_type == "python"


# ==================== 主函数 ====================

async def main():
    global PASS_COUNT, FAIL_COUNT
    print("=" * 60)
    print("昆仑被动扫描引擎 - 完整功能测试")
    print("=" * 60)
    print()

    await test_finding_creation()
    await test_evidence_context()
    await test_builtin_rules_count()

    print("\n--- 信息泄露检测 ---")
    await test_info_leak_internal_ip()
    await test_info_leak_email()
    await test_info_leak_cloud_key()
    await test_info_leak_jwt()
    await test_info_leak_db_connection()
    await test_info_leak_git()
    await test_info_leak_server_version()
    await test_info_leak_html_comment()
    await test_info_leak_phone()
    await test_info_leak_id_card()
    await test_info_leak_sourcemap()
    await test_info_leak_sensitive_file()

    print("\n--- 安全配置检测 ---")
    await test_config_xfo_missing()
    await test_config_xfo_present()
    await test_config_hsts_missing()
    await test_config_csp_missing()
    await test_config_xcto_missing()
    await test_config_cookie_httponly()
    await test_config_cors_wildcard()
    await test_config_cors_dangerous()
    await test_config_referrer_policy()
    await test_config_permissions_policy()
    await test_config_cache_control()

    print("\n--- 漏洞模式检测 ---")
    await test_vuln_sql_error()
    await test_vuln_stack_trace()
    await test_vuln_path_disclosure()
    await test_vuln_directory_listing()
    await test_vuln_php_info()
    await test_vuln_debug_mode()
    await test_vuln_actuator()
    await test_vuln_env_exposed()
    await test_vuln_swagger()
    await test_vuln_graphql()
    await test_vuln_error_message()
    await test_vuln_crossdomain()

    print("\n--- 去重管理器 ---")
    await test_dedup_basic()
    await test_dedup_persistence()
    await test_dedup_clear_all()
    await test_dedup_clear_by_rule()
    await test_dedup_clear_by_url()

    print("\n--- 结果导出 ---")
    await test_export_json()
    await test_export_html()

    print("\n--- 规则加载器 ---")
    await test_rule_loader_yaml()
    await test_rule_loader_python()
    await test_rule_loader_search()
    await test_rule_loader_enable_disable()

    print("\n--- 被动扫描器集成 ---")
    await test_scanner_lifecycle()
    await test_scanner_submit_and_analyze()
    await test_scanner_skip_static()
    await test_scanner_domain_blacklist()
    await test_scanner_dedup()
    await test_scanner_export()
    await test_scanner_stats()
    await test_scanner_ui_data()

    print("\n--- 集成桥接 ---")
    await test_integration_create()
    await test_integration_highlight()
    await test_integration_detail()
    await test_integration_send_repeater()
    await test_integration_send_fuzzer()
    await test_integration_whitelist_ignore()

    print("\n--- 扩展性 ---")
    await test_base_rule()

    print()
    print("=" * 60)
    print(f"测试结果: {PASS_COUNT} 通过, {FAIL_COUNT} 失败, {PASS_COUNT + FAIL_COUNT} 总计")
    print("=" * 60)

    if FAIL_COUNT > 0:
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
