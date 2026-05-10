"""
Windows/Linux提权辅助套件 - 自测试与验证体系模块
===================================================
内置靶机模拟、规则有效性自动验证、CI/CD集成。

核心能力:
    1. 内置靶机模拟 - 轻量级Windows/Linux漏洞场景模拟器
    2. 规则有效性验证 - 命中率/误报率统计、自动降权
    3. CI/CD集成 - 代码提交后自动运行模拟测试

Author: 昆仑安全实验室
License: Internal Use Only
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import platform
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Coroutine, Dict, List, Optional, Set

logger = logging.getLogger(__name__)


# =============================================================================
# 枚举与数据模型
# =============================================================================

class TestResult(str, Enum):
    """测试结果"""
    PASSED = "passed"
    FAILED = "failed"
    SKIPPED = "skipped"
    ERROR = "error"


class VulnScenario(str, Enum):
    """漏洞场景"""
    SUID_BINARY = "suid_binary"
    SUDO_NOPASSWD = "sudo_nopasswd"
    WRITABLE_SERVICE = "writable_service"
    KERNEL_VULN = "kernel_vuln"
    DOCKER_SOCKET = "docker_socket"
    WEAK_FILE_PERMS = "weak_file_perms"
    CACHED_CREDENTIALS = "cached_credentials"
    MISCONFIGURED_CRON = "misconfigured_cron"
    CAPABILITY_ABUSE = "capability_abuse"
    POTATO_FAMILY = "potato_family"


@dataclass
class TestCase:
    """测试用例

    Attributes:
        case_id: 用例ID
        name: 用例名
        scenario: 漏洞场景
        description: 描述
        expected_findings: 预期发现
        setup_commands: 设置命令
        teardown_commands: 清理命令
        platform: 平台
        severity: 严重程度
    """
    case_id: str = ""
    name: str = ""
    scenario: VulnScenario = VulnScenario.SUID_BINARY
    description: str = ""
    expected_findings: List[str] = field(default_factory=list)
    setup_commands: List[str] = field(default_factory=list)
    teardown_commands: List[str] = field(default_factory=list)
    platform: str = "linux"
    severity: str = "high"

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "case_id": self.case_id,
            "name": self.name,
            "scenario": self.scenario.value,
            "description": self.description,
            "expected_findings": self.expected_findings,
            "setup_commands": self.setup_commands,
            "teardown_commands": self.teardown_commands,
            "platform": self.platform,
            "severity": self.severity,
        }


@dataclass
class TestExecutionResult:
    """测试执行结果

    Attributes:
        case_id: 用例ID
        result: 测试结果
        actual_findings: 实际发现
        expected_findings: 预期发现
        false_positives: 误报
        false_negatives: 漏报
        duration: 耗时（秒）
        error: 错误信息
        timestamp: 时间戳
    """
    case_id: str = ""
    result: TestResult = TestResult.SKIPPED
    actual_findings: List[str] = field(default_factory=list)
    expected_findings: List[str] = field(default_factory=list)
    false_positives: List[str] = field(default_factory=list)
    false_negatives: List[str] = field(default_factory=list)
    duration: float = 0.0
    error: str = ""
    timestamp: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "case_id": self.case_id,
            "result": self.result.value,
            "actual_findings": self.actual_findings,
            "expected_findings": self.expected_findings,
            "false_positives": self.false_positives,
            "false_negatives": self.false_negatives,
            "duration": self.duration,
            "error": self.error,
            "timestamp": self.timestamp,
        }


@dataclass
class RuleMetrics:
    """规则指标

    Attributes:
        rule_id: 规则ID
        rule_name: 规则名
        total_executions: 总执行次数
        hit_count: 命中次数
        false_positive_count: 误报次数
        false_negative_count: 漏报次数
        hit_rate: 命中率
        false_positive_rate: 误报率
        last_triggered: 最后触发时间
        status: 状态
    """
    rule_id: str = ""
    rule_name: str = ""
    total_executions: int = 0
    hit_count: int = 0
    false_positive_count: int = 0
    false_negative_count: int = 0
    hit_rate: float = 0.0
    false_positive_rate: float = 0.0
    last_triggered: str = ""
    status: str = "active"

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "total_executions": self.total_executions,
            "hit_count": self.hit_count,
            "false_positive_count": self.false_positive_count,
            "false_negative_count": self.false_negative_count,
            "hit_rate": round(self.hit_rate, 4),
            "false_positive_rate": round(self.false_positive_rate, 4),
            "last_triggered": self.last_triggered,
            "status": self.status,
        }

    def update_metrics(self, hit: bool, false_positive: bool) -> None:
        """更新指标

        Args:
            hit: 是否命中
            false_positive: 是否误报
        """
        self.total_executions += 1
        if hit:
            self.hit_count += 1
            self.last_triggered = datetime.now().isoformat()
        if false_positive:
            self.false_positive_count += 1

        if self.total_executions > 0:
            self.hit_rate = self.hit_count / self.total_executions
            self.false_positive_rate = (
                self.false_positive_count / self.total_executions
            )

        self._evaluate_status()

    def _evaluate_status(self) -> None:
        """评估状态"""
        if self.total_executions < 5:
            self.status = "insufficient_data"
        elif self.hit_rate < 0.1:
            self.status = "low_hit_rate"
        elif self.false_positive_rate > 0.5:
            self.status = "high_false_positive"
        else:
            self.status = "active"


@dataclass
class TestSuiteReport:
    """测试套件报告

    Attributes:
        suite_id: 套件ID
        timestamp: 时间戳
        total_cases: 总用例数
        passed: 通过数
        failed: 失败数
        skipped: 跳过的数
        results: 执行结果
        rule_metrics: 规则指标
        summary: 摘要
    """
    suite_id: str = ""
    timestamp: str = ""
    total_cases: int = 0
    passed: int = 0
    failed: int = 0
    skipped: int = 0
    results: List[TestExecutionResult] = field(default_factory=list)
    rule_metrics: List[RuleMetrics] = field(default_factory=list)
    summary: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "suite_id": self.suite_id,
            "timestamp": self.timestamp,
            "total_cases": self.total_cases,
            "passed": self.passed,
            "failed": self.failed,
            "skipped": self.skipped,
            "results": [r.to_dict() for r in self.results],
            "rule_metrics": [m.to_dict() for m in self.rule_metrics],
            "summary": self.summary,
        }


# =============================================================================
# 内置靶机模拟器
# =============================================================================

class VulnerableScenarioSimulator:
    """漏洞场景模拟器

    模拟Windows/Linux漏洞场景用于测试。

    Attributes:
        _is_windows: 是否为Windows
        _active_scenarios: 活跃场景
    """

    def __init__(self) -> None:
        """初始化漏洞场景模拟器"""
        self._is_windows = platform.system().lower() == "windows"
        self._active_scenarios: Set[VulnScenario] = set()

    async def setup_scenario(self, scenario: VulnScenario) -> bool:
        """设置漏洞场景

        Args:
            scenario: 漏洞场景

        Returns:
            是否成功
        """
        if self._is_windows:
            return await self._setup_windows_scenario(scenario)
        else:
            return await self._setup_linux_scenario(scenario)

    async def teardown_scenario(self, scenario: VulnScenario) -> bool:
        """清理漏洞场景

        Args:
            scenario: 漏洞场景

        Returns:
            是否成功
        """
        if self._is_windows:
            return await self._teardown_windows_scenario(scenario)
        else:
            return await self._teardown_linux_scenario(scenario)

    async def _setup_linux_scenario(self, scenario: VulnScenario) -> bool:
        """设置Linux场景

        Args:
            scenario: 漏洞场景

        Returns:
            是否成功
        """
        try:
            if scenario == VulnScenario.SUID_BINARY:
                cmd = (
                    "cp /bin/bash /tmp/suid_test && "
                    "chmod u+s /tmp/suid_test"
                )
            elif scenario == VulnScenario.SUDO_NOPASSWD:
                cmd = (
                    "echo 'testuser ALL=(ALL) NOPASSWD: ALL' | "
                    "sudo tee /etc/sudoers.d/testuser 2>/dev/null"
                )
            elif scenario == VulnScenario.WEAK_FILE_PERMS:
                cmd = "chmod 777 /tmp/test_weak_perms 2>/dev/null || touch /tmp/test_weak_perms && chmod 777 /tmp/test_weak_perms"
            elif scenario == VulnScenario.DOCKER_SOCKET:
                cmd = "test -S /var/run/docker.sock && echo 'exists' || echo 'not_found'"
            elif scenario == VulnScenario.CAPABILITY_ABUSE:
                cmd = (
                    "which python3 && "
                    "sudo setcap cap_setuid+ep $(which python3) 2>/dev/null"
                )
            elif scenario == VulnScenario.MISCONFIGURED_CRON:
                cmd = (
                    "echo '* * * * * root /tmp/vuln_cron.sh' | "
                    "sudo tee /etc/cron.d/vuln_cron 2>/dev/null"
                )
            else:
                logger.debug(f"不支持的Linux场景: {scenario}")
                return False

            proc = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _, _ = await proc.communicate(timeout=30)

            self._active_scenarios.add(scenario)
            return proc.returncode == 0

        except Exception as e:
            logger.debug(f"设置场景失败: {e}")
            return False

    async def _setup_windows_scenario(self, scenario: VulnScenario) -> bool:
        """设置Windows场景

        Args:
            scenario: 漏洞场景

        Returns:
            是否成功
        """
        try:
            if scenario == VulnScenario.WRITABLE_SERVICE:
                cmd = (
                    'powershell -Command "'
                    "New-Service -Name 'TestVulnService' "
                    "-BinaryPathName 'C:\\Windows\\System32\\cmd.exe' "
                    "-ErrorAction SilentlyContinue"
                    '"'
                )
            elif scenario == VulnScenario.POTATO_FAMILY:
                cmd = (
                    'powershell -Command "'
                    "whoami /priv | Select-String SeImpersonatePrivilege"
                    '"'
                )
            elif scenario == VulnScenario.CACHED_CREDENTIALS:
                cmd = "cmdkey /list"
            else:
                logger.debug(f"不支持的Windows场景: {scenario}")
                return False

            proc = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _, _ = await proc.communicate(timeout=30)

            self._active_scenarios.add(scenario)
            return proc.returncode == 0

        except Exception as e:
            logger.debug(f"设置场景失败: {e}")
            return False

    async def _teardown_linux_scenario(self, scenario: VulnScenario) -> bool:
        """清理Linux场景

        Args:
            scenario: 漏洞场景

        Returns:
            是否成功
        """
        try:
            if scenario == VulnScenario.SUID_BINARY:
                cmd = "rm -f /tmp/suid_test"
            elif scenario == VulnScenario.SUDO_NOPASSWD:
                cmd = "sudo rm -f /etc/sudoers.d/testuser 2>/dev/null"
            elif scenario == VulnScenario.WEAK_FILE_PERMS:
                cmd = "rm -f /tmp/test_weak_perms"
            elif scenario == VulnScenario.CAPABILITY_ABUSE:
                cmd = "sudo setcap -r $(which python3) 2>/dev/null"
            elif scenario == VulnScenario.MISCONFIGURED_CRON:
                cmd = "sudo rm -f /etc/cron.d/vuln_cron 2>/dev/null"
            else:
                return True

            proc = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _, _ = await proc.communicate(timeout=10)

            self._active_scenarios.discard(scenario)
            return True

        except Exception:
            return False

    async def _teardown_windows_scenario(self, scenario: VulnScenario) -> bool:
        """清理Windows场景

        Args:
            scenario: 漏洞场景

        Returns:
            是否成功
        """
        try:
            if scenario == VulnScenario.WRITABLE_SERVICE:
                cmd = 'sc delete TestVulnService 2>nul'
            else:
                return True

            proc = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _, _ = await proc.communicate(timeout=10)

            self._active_scenarios.discard(scenario)
            return True

        except Exception:
            return False


# =============================================================================
# 测试用例库
# =============================================================================

class TestCaseLibrary:
    """测试用例库

    Attributes:
        _test_cases: 测试用例
    """

    LINUX_TEST_CASES = [
        TestCase(
            case_id="linux_suid_001",
            name="SUID二进制文件检测",
            scenario=VulnScenario.SUID_BINARY,
            description="检测SUID位配置不当的二进制文件",
            expected_findings=["发现SUID二进制文件"],
            setup_commands=["cp /bin/bash /tmp/suid_test && chmod u+s /tmp/suid_test"],
            teardown_commands=["rm -f /tmp/suid_test"],
            platform="linux",
            severity="high",
        ),
        TestCase(
            case_id="linux_sudo_001",
            name="Sudo NOPASSWD规则检测",
            scenario=VulnScenario.SUDO_NOPASSWD,
            description="检测无需密码即可执行的sudo规则",
            expected_findings=["存在NOPASSWD sudo规则"],
            setup_commands=["echo 'testuser ALL=(ALL) NOPASSWD: ALL' | sudo tee /etc/sudoers.d/testuser"],
            teardown_commands=["sudo rm -f /etc/sudoers.d/testuser"],
            platform="linux",
            severity="critical",
        ),
        TestCase(
            case_id="linux_perms_001",
            name="弱文件权限检测",
            scenario=VulnScenario.WEAK_FILE_PERMS,
            description="检测权限配置不当的敏感文件",
            expected_findings=["发现弱文件权限"],
            setup_commands=["touch /tmp/test_weak_perms && chmod 777 /tmp/test_weak_perms"],
            teardown_commands=["rm -f /tmp/test_weak_perms"],
            platform="linux",
            severity="medium",
        ),
        TestCase(
            case_id="linux_cap_001",
            name="Capabilities滥用检测",
            scenario=VulnScenario.CAPABILITY_ABUSE,
            description="检测危险的capabilities配置",
            expected_findings=["发现capabilities"],
            setup_commands=["sudo setcap cap_setuid+ep $(which python3)"],
            teardown_commands=["sudo setcap -r $(which python3)"],
            platform="linux",
            severity="high",
        ),
        TestCase(
            case_id="linux_cron_001",
            name="Cron配置不当检测",
            scenario=VulnScenario.MISCONFIGURED_CRON,
            description="检测可被利用的cron任务",
            expected_findings=["发现misconfigured cron"],
            setup_commands=["echo '* * * * * root /tmp/vuln_cron.sh' | sudo tee /etc/cron.d/vuln_cron"],
            teardown_commands=["sudo rm -f /etc/cron.d/vuln_cron"],
            platform="linux",
            severity="high",
        ),
    ]

    WINDOWS_TEST_CASES = [
        TestCase(
            case_id="win_service_001",
            name="可写服务检测",
            scenario=VulnScenario.WRITABLE_SERVICE,
            description="检测可被修改的服务配置",
            expected_findings=["发现可写服务"],
            setup_commands=["sc create TestVulnService binPath= cmd.exe"],
            teardown_commands=["sc delete TestVulnService"],
            platform="windows",
            severity="high",
        ),
        TestCase(
            case_id="win_potato_001",
            name="Potato系列检测",
            scenario=VulnScenario.POTATO_FAMILY,
            description="检测SeImpersonatePrivilege",
            expected_findings=["拥有SeImpersonatePrivilege"],
            setup_commands=[],
            teardown_commands=[],
            platform="windows",
            severity="critical",
        ),
        TestCase(
            case_id="win_cred_001",
            name="缓存凭据检测",
            scenario=VulnScenario.CACHED_CREDENTIALS,
            description="检测缓存的凭据",
            expected_findings=["发现缓存凭据"],
            setup_commands=[],
            teardown_commands=[],
            platform="windows",
            severity="medium",
        ),
    ]

    def __init__(self) -> None:
        """初始化测试用例库"""
        self._test_cases: Dict[str, TestCase] = {}
        self._load_default_cases()

    def _load_default_cases(self) -> None:
        """加载默认用例"""
        is_windows = platform.system().lower() == "windows"
        cases = self.WINDOWS_TEST_CASES if is_windows else self.LINUX_TEST_CASES

        for case in cases:
            self._test_cases[case.case_id] = case

    def get_all_cases(self) -> List[TestCase]:
        """获取所有用例

        Returns:
            用例列表
        """
        return list(self._test_cases.values())

    def get_case(self, case_id: str) -> Optional[TestCase]:
        """获取单个用例

        Args:
            case_id: 用例ID

        Returns:
            用例
        """
        return self._test_cases.get(case_id)

    def get_cases_by_scenario(
        self, scenario: VulnScenario,
    ) -> List[TestCase]:
        """按场景获取用例

        Args:
            scenario: 漏洞场景

        Returns:
            用例列表
        """
        return [
            c for c in self._test_cases.values()
            if c.scenario == scenario
        ]

    def add_case(self, case: TestCase) -> None:
        """添加用例

        Args:
            case: 测试用例
        """
        self._test_cases[case.case_id] = case


# =============================================================================
# 规则验证器
# =============================================================================

class RuleValidator:
    """规则验证器

    验证提权规则的有效性。

    Attributes:
        _metrics: 规则指标
    """

    def __init__(self) -> None:
        """初始化规则验证器"""
        self._metrics: Dict[str, RuleMetrics] = {}

    def record_execution(
        self,
        rule_id: str,
        rule_name: str,
        hit: bool,
        false_positive: bool,
    ) -> None:
        """记录规则执行

        Args:
            rule_id: 规则ID
            rule_name: 规则名
            hit: 是否命中
            false_positive: 是否误报
        """
        if rule_id not in self._metrics:
            self._metrics[rule_id] = RuleMetrics(
                rule_id=rule_id,
                rule_name=rule_name,
            )

        self._metrics[rule_id].update_metrics(hit, false_positive)

    def get_metrics(self, rule_id: str) -> Optional[RuleMetrics]:
        """获取规则指标

        Args:
            rule_id: 规则ID

        Returns:
            规则指标
        """
        return self._metrics.get(rule_id)

    def get_all_metrics(self) -> List[RuleMetrics]:
        """获取所有指标

        Returns:
            指标列表
        """
        return list(self._metrics.values())

    def get_low_quality_rules(self) -> List[RuleMetrics]:
        """获取低质量规则

        Returns:
            低质量规则列表
        """
        low_quality = []
        for metrics in self._metrics.values():
            if metrics.status in ["low_hit_rate", "high_false_positive"]:
                low_quality.append(metrics)
        return low_quality

    def export_metrics(self) -> str:
        """导出指标

        Returns:
            JSON字符串
        """
        data = [m.to_dict() for m in self._metrics.values()]
        return json.dumps(data, indent=2, ensure_ascii=False)

    def import_metrics(self, json_str: str) -> None:
        """导入指标

        Args:
            json_str: JSON字符串
        """
        data = json.loads(json_str)
        for item in data:
            metrics = RuleMetrics()
            metrics.rule_id = item.get("rule_id", "")
            metrics.rule_name = item.get("rule_name", "")
            metrics.total_executions = item.get("total_executions", 0)
            metrics.hit_count = item.get("hit_count", 0)
            metrics.false_positive_count = item.get("false_positive_count", 0)
            metrics.false_negative_count = item.get("false_negative_count", 0)
            metrics.hit_rate = item.get("hit_rate", 0.0)
            metrics.false_positive_rate = item.get("false_positive_rate", 0.0)
            metrics.last_triggered = item.get("last_triggered", "")
            metrics.status = item.get("status", "active")
            self._metrics[metrics.rule_id] = metrics


# =============================================================================
# 测试执行器
# =============================================================================

class TestExecutor:
    """测试执行器

    执行测试用例并收集结果。

    Attributes:
        _simulator: 场景模拟器
        _library: 用例库
        _validator: 规则验证器
        _check_handler: 检查处理器
    """

    def __init__(
        self,
        check_handler: Optional[Callable[..., Coroutine]] = None,
    ) -> None:
        """初始化测试执行器

        Args:
            check_handler: 检查处理器
        """
        self._simulator = VulnerableScenarioSimulator()
        self._library = TestCaseLibrary()
        self._validator = RuleValidator()
        self._check_handler = check_handler

    def set_check_handler(
        self, handler: Callable[..., Coroutine],
    ) -> None:
        """设置检查处理器

        Args:
            handler: 检查处理器
        """
        self._check_handler = handler

    async def run_single_test(self, case: TestCase) -> TestExecutionResult:
        """运行单个测试

        Args:
            case: 测试用例

        Returns:
            测试结果
        """
        result = TestExecutionResult(
            case_id=case.case_id,
            expected_findings=case.expected_findings,
            timestamp=datetime.now().isoformat(),
        )

        start_time = time.time()

        try:
            await self._setup_case(case)

            if self._check_handler:
                findings = await self._check_handler(case.scenario)
                result.actual_findings = findings

                result.false_positives = [
                    f for f in findings
                    if f not in case.expected_findings
                ]
                result.false_negatives = [
                    f for f in case.expected_findings
                    if f not in findings
                ]

                if findings and not result.false_negatives:
                    result.result = TestResult.PASSED
                elif result.false_negatives:
                    result.result = TestResult.FAILED
                else:
                    result.result = TestResult.SKIPPED

            else:
                result.result = TestResult.SKIPPED
                result.error = "无检查处理器"

        except Exception as e:
            result.result = TestResult.ERROR
            result.error = str(e)

        finally:
            await self._teardown_case(case)

        result.duration = time.time() - start_time

        self._validator.record_execution(
            rule_id=case.case_id,
            rule_name=case.name,
            hit=result.result == TestResult.PASSED,
            false_positive=bool(result.false_positives),
        )

        return result

    async def run_suite(
        self,
        case_ids: Optional[List[str]] = None,
    ) -> TestSuiteReport:
        """运行测试套件

        Args:
            case_ids: 用例ID列表

        Returns:
            测试套件报告
        """
        report = TestSuiteReport(
            suite_id=f"suite_{int(time.time())}",
            timestamp=datetime.now().isoformat(),
        )

        cases = (
            [self._library.get_case(cid) for cid in case_ids]
            if case_ids
            else self._library.get_all_cases()
        )
        cases = [c for c in cases if c]

        report.total_cases = len(cases)

        for case in cases:
            if case:
                result = await self.run_single_test(case)
                report.results.append(result)

                if result.result == TestResult.PASSED:
                    report.passed += 1
                elif result.result == TestResult.FAILED:
                    report.failed += 1
                else:
                    report.skipped += 1

        report.rule_metrics = self._validator.get_all_metrics()
        report.summary = self._generate_summary(report)

        return report

    async def _setup_case(self, case: TestCase) -> None:
        """设置用例

        Args:
            case: 测试用例
        """
        await self._simulator.setup_scenario(case.scenario)

    async def _teardown_case(self, case: TestCase) -> None:
        """清理用例

        Args:
            case: 测试用例
        """
        await self._simulator.teardown_scenario(case.scenario)

    def _generate_summary(
        self, report: TestSuiteReport,
    ) -> Dict[str, Any]:
        """生成摘要

        Args:
            report: 测试套件报告

        Returns:
            摘要
        """
        total = report.total_cases
        passed = report.passed

        return {
            "total_cases": total,
            "passed": passed,
            "failed": report.failed,
            "skipped": report.skipped,
            "pass_rate": round(passed / total, 4) if total > 0 else 0,
            "low_quality_rules": len(
                self._validator.get_low_quality_rules()
            ),
        }


# =============================================================================
# 主自测试模块
# =============================================================================

class PrivescSelfTestModule:
    """自测试与验证体系模块

    整合靶机模拟、规则验证、CI/CD集成。

    Attributes:
        _executor: 测试执行器
        _simulator: 场景模拟器
        _library: 用例库
        _validator: 规则验证器
    """

    def __init__(
        self,
        check_handler: Optional[Callable[..., Coroutine]] = None,
    ) -> None:
        """初始化自测试模块

        Args:
            check_handler: 检查处理器
        """
        self._executor = TestExecutor(check_handler)
        self._simulator = VulnerableScenarioSimulator()
        self._library = TestCaseLibrary()
        self._validator = RuleValidator()

    async def run_full_test_suite(
        self, case_ids: Optional[List[str]] = None,
    ) -> TestSuiteReport:
        """运行完整测试套件

        Args:
            case_ids: 用例ID列表

        Returns:
            测试套件报告
        """
        return await self._executor.run_suite(case_ids)

    async def run_single_test(self, case_id: str) -> TestExecutionResult:
        """运行单个测试

        Args:
            case_id: 用例ID

        Returns:
            测试结果
        """
        case = self._library.get_case(case_id)
        if case:
            return await self._executor.run_single_test(case)
        return TestExecutionResult(
            case_id=case_id,
            result=TestResult.ERROR,
            error=f"用例不存在: {case_id}",
        )

    def get_test_cases(self) -> List[TestCase]:
        """获取测试用例

        Returns:
            用例列表
        """
        return self._library.get_all_cases()

    def get_rule_metrics(self) -> List[RuleMetrics]:
        """获取规则指标

        Returns:
            指标列表
        """
        return self._validator.get_all_metrics()

    def get_low_quality_rules(self) -> List[RuleMetrics]:
        """获取低质量规则

        Returns:
            低质量规则列表
        """
        return self._validator.get_low_quality_rules()

    def export_metrics(self) -> str:
        """导出指标

        Returns:
            JSON字符串
        """
        return self._validator.export_metrics()

    def import_metrics(self, json_str: str) -> None:
        """导入指标

        Args:
            json_str: JSON字符串
        """
        self._validator.import_metrics(json_str)


# =============================================================================
# 全局单例
# =============================================================================

_self_test_module: Optional[PrivescSelfTestModule] = None


def get_self_test_module() -> PrivescSelfTestModule:
    """获取自测试模块全局单例

    Returns:
        PrivescSelfTestModule 实例
    """
    global _self_test_module
    if _self_test_module is None:
        _self_test_module = PrivescSelfTestModule()
    return _self_test_module


__all__ = [
    "PrivescSelfTestModule",
    "VulnerableScenarioSimulator",
    "TestCaseLibrary",
    "RuleValidator",
    "TestExecutor",
    "TestCase",
    "TestExecutionResult",
    "RuleMetrics",
    "TestSuiteReport",
    "TestResult",
    "VulnScenario",
    "get_self_test_module",
]
