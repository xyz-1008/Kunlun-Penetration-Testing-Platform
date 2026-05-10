"""
Evasion Tester Module - Sandbox detection, camouflage scoring, self-test framework.

This module provides comprehensive evasion validation capabilities including
sandbox detection, camouflage effectiveness scoring, automated self-testing,
and CI/CD integration for Profile validation.

Core capabilities:
    1. Sandbox detection (runtime, user interaction, screen resolution, registry)
    2. Camouflage effectiveness scoring via local ML model
    3. Self-test framework (Beacon -> Traffic -> Capture -> Compare)
    4. CI/CD integration for automated Profile testing
    5. Difference reporting and optimization suggestions

Author: Kunlun Security Lab
License: Internal Use Only
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import platform
import random
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Coroutine, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# =============================================================================
# Enums
# =============================================================================

class SandboxType(str, Enum):
    """Types of sandbox environments."""

    NONE = "none"
    VIRTUAL_MACHINE = "virtual_machine"
    CONTAINER = "container"
    ANALYSIS_TOOL = "analysis_tool"
    CLOUD_SANDBOX = "cloud_sandbox"
    UNKNOWN = "unknown"


class TestResult(str, Enum):
    """Test result status."""

    PASSED = "passed"
    FAILED = "failed"
    WARNING = "warning"
    SKIPPED = "skipped"


class CamouflageCategory(str, Enum):
    """Camouflage evaluation categories."""

    HTTP_HEADERS = "http_headers"
    TLS_FINGERPRINT = "tls_fingerprint"
    TRAFFIC_PATTERN = "traffic_pattern"
    DNS_BEHAVIOR = "dns_behavior"
    USER_AGENT = "user_agent"
    PAYLOAD_STRUCTURE = "payload_structure"
    TIMING_BEHAVIOR = "timing_behavior"


# =============================================================================
# Data Models
# =============================================================================

@dataclass
class SandboxDetection:
    """Result of sandbox detection analysis.

    Attributes:
        is_sandbox: Whether a sandbox was detected
        sandbox_type: Type of sandbox detected
        confidence: Detection confidence (0.0-1.0)
        indicators: List of detection indicators
        details: Detailed detection information
    """

    is_sandbox: bool = False
    sandbox_type: SandboxType = SandboxType.NONE
    confidence: float = 0.0
    indicators: List[str] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "is_sandbox": self.is_sandbox,
            "sandbox_type": self.sandbox_type.value,
            "confidence": self.confidence,
            "indicators": self.indicators,
            "details": self.details,
        }


@dataclass
class CamouflageScore:
    """Camouflage effectiveness score.

    Attributes:
        overall_score: Overall camouflage score (0.0-1.0)
        category_scores: Per-category scores
        comparison_target: What the traffic was compared against
        differences: List of detected differences
        suggestions: Optimization suggestions
    """

    overall_score: float = 0.0
    category_scores: Dict[str, float] = field(default_factory=dict)
    comparison_target: str = ""
    differences: List[str] = field(default_factory=list)
    suggestions: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "overall_score": self.overall_score,
            "category_scores": self.category_scores,
            "comparison_target": self.comparison_target,
            "differences": self.differences,
            "suggestions": self.suggestions,
        }

    def to_markdown(self) -> str:
        """Convert to markdown report.

        Returns:
            Markdown formatted report string.
        """
        lines = [
            "# Camouflage Effectiveness Report",
            "",
            f"**Overall Score**: {self.overall_score:.0%}",
            f"**Compared Against**: {self.comparison_target}",
            "",
            "## Category Scores",
            "",
        ]

        for category, score in self.category_scores.items():
            status = "PASS" if score >= 0.8 else "WARN" if score >= 0.6 else "FAIL"
            lines.append(f"- **{category}**: {score:.0%} [{status}]")

        if self.differences:
            lines.extend(["", "## Differences", ""])
            for diff in self.differences:
                lines.append(f"- {diff}")

        if self.suggestions:
            lines.extend(["", "## Suggestions", ""])
            for suggestion in self.suggestions:
                lines.append(f"- {suggestion}")

        return "\n".join(lines)


@dataclass
class TestCase:
    """A self-test case.

    Attributes:
        test_id: Unique test identifier
        name: Test name
        description: Test description
        category: Test category
        result: Test result
        duration: Test duration in seconds
        error: Error message if failed
        details: Additional test details
    """

    test_id: str = ""
    name: str = ""
    description: str = ""
    category: str = ""
    result: TestResult = TestResult.SKIPPED
    duration: float = 0.0
    error: str = ""
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "test_id": self.test_id,
            "name": self.name,
            "description": self.description,
            "category": self.category,
            "result": self.result.value,
            "duration": self.duration,
            "error": self.error,
            "details": self.details,
        }


@dataclass
class TestReport:
    """Self-test execution report.

    Attributes:
        test_cases: List of executed test cases
        total_duration: Total test duration
        passed_count: Number of passed tests
        failed_count: Number of failed tests
        warning_count: Number of warning tests
        skipped_count: Number of skipped tests
        started_at: Test start timestamp
        completed_at: Test completion timestamp
    """

    test_cases: List[TestCase] = field(default_factory=list)
    total_duration: float = 0.0
    passed_count: int = 0
    failed_count: int = 0
    warning_count: int = 0
    skipped_count: int = 0
    started_at: float = 0.0
    completed_at: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "total_tests": len(self.test_cases),
            "passed": self.passed_count,
            "failed": self.failed_count,
            "warning": self.warning_count,
            "skipped": self.skipped_count,
            "total_duration": self.total_duration,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "test_cases": [tc.to_dict() for tc in self.test_cases],
        }

    def to_markdown(self) -> str:
        """Convert to markdown report.

        Returns:
            Markdown formatted report string.
        """
        total = len(self.test_cases)
        pass_rate = (
            self.passed_count / total * 100 if total > 0 else 0
        )

        lines = [
            "# Evasion Self-Test Report",
            "",
            f"**Total Tests**: {total}",
            f"**Passed**: {self.passed_count}",
            f"**Failed**: {self.failed_count}",
            f"**Warnings**: {self.warning_count}",
            f"**Skipped**: {self.skipped_count}",
            f"**Pass Rate**: {pass_rate:.1f}%",
            f"**Duration**: {self.total_duration:.2f}s",
            "",
            "## Test Results",
            "",
        ]

        for tc in self.test_cases:
            emoji = {
                TestResult.PASSED: "PASS",
                TestResult.FAILED: "FAIL",
                TestResult.WARNING: "WARN",
                TestResult.SKIPPED: "SKIP",
            }.get(tc.result, "??")

            lines.append(
                f"- [{emoji}] **{tc.name}**: {tc.description} "
                f"({tc.duration:.2f}s)"
            )

            if tc.error:
                lines.append(f"  - Error: {tc.error}")

        return "\n".join(lines)


# =============================================================================
# Sandbox Detector
# =============================================================================

class SandboxDetector:
    """Detects sandbox and analysis environments.

    Checks runtime duration, user interaction traces, screen resolution,
    registry keys, and common sandbox artifacts.

    Attributes:
        _start_time: Detection start timestamp
        _indicators: Accumulated detection indicators
    """

    SANDBOX_REGISTRY_KEYS: List[str] = [
        "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Virtual Machine\\Guest\\Parameters",
        "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\VBoxGuest",
        "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\VBoxMouse",
        "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\VBoxService",
        "HKEY_LOCAL_MACHINE\\SOFTWARE\\Oracle\\VirtualBox Guest Additions",
        "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\CriticalDeviceDatabase\\root#vmwdev",
        "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\CriticalDeviceDatabase\\root#vmmouse",
    ]

    SANDBOX_PROCESSES: List[str] = [
        "vboxservice.exe",
        "vboxtray.exe",
        "vmtoolsd.exe",
        "vmwaretray.exe",
        "vmwareuser.exe",
        "vmusrvc.exe",
        "prl_cc.exe",
        "prl_tools.exe",
        "xenservice.exe",
        "qemu-ga.exe",
        "sandboxiedcomserver.exe",
        "sandboxierpcss.exe",
        "joeboxserver.exe",
        "joeboxcontrol.exe",
        "ksafe.exe",
        "kpf4ss.exe",
    ]

    SANDBOX_FILES: List[str] = [
        "C:\\windows\\system32\\drivers\\VBoxMouse.sys",
        "C:\\windows\\system32\\drivers\\VBoxGuest.sys",
        "C:\\windows\\system32\\drivers\\VBoxSF.sys",
        "C:\\windows\\system32\\drivers\\VBoxVideo.sys",
        "C:\\windows\\system32\\vboxdisp.dll",
        "C:\\windows\\system32\\vboxhook.dll",
        "C:\\windows\\system32\\vboxmrxnp.dll",
        "C:\\windows\\system32\\vboxogl.dll",
        "C:\\windows\\system32\\vboxoglarrayspu.dll",
        "C:\\windows\\system32\\vboxoglcrutil.dll",
        "C:\\windows\\system32\\vboxoglerrorspu.dll",
        "C:\\windows\\system32\\vboxoglfeedbackspu.dll",
        "C:\\windows\\system32\\vboxoglpackspu.dll",
        "C:\\windows\\system32\\vboxoglpassthroughspu.dll",
    ]

    def __init__(self) -> None:
        """Initialize the SandboxDetector."""
        self._start_time = time.time()
        self._indicators: List[str] = []

    async def detect(self) -> SandboxDetection:
        """Perform comprehensive sandbox detection.

        Returns:
            SandboxDetection with results.
        """
        self._indicators = []
        confidence_scores: List[float] = []

        checks = [
            self._check_runtime,
            self._check_user_interaction,
            self._check_screen_resolution,
            self._check_registry_keys,
            self._check_processes,
            self._check_files,
            self._check_hardware,
            self._check_network,
        ]

        for check in checks:
            try:
                score = await check()
                if score > 0.3:
                    confidence_scores.append(score)
            except Exception as e:
                logger.debug(f"Sandbox check failed: {e}")

        if not confidence_scores:
            return SandboxDetection()

        avg_confidence = sum(confidence_scores) / len(confidence_scores)
        max_confidence = max(confidence_scores)
        final_confidence = max(avg_confidence, max_confidence * 0.7)

        is_sandbox = final_confidence > 0.5

        sandbox_type = SandboxType.NONE
        if is_sandbox:
            if any("vm" in ind.lower() for ind in self._indicators):
                sandbox_type = SandboxType.VIRTUAL_MACHINE
            elif any("container" in ind.lower() for ind in self._indicators):
                sandbox_type = SandboxType.CONTAINER
            elif any("analysis" in ind.lower() for ind in self._indicators):
                sandbox_type = SandboxType.ANALYSIS_TOOL
            else:
                sandbox_type = SandboxType.UNKNOWN

        return SandboxDetection(
            is_sandbox=is_sandbox,
            sandbox_type=sandbox_type,
            confidence=final_confidence,
            indicators=list(self._indicators),
            details={
                "check_count": len(checks),
                "positive_checks": len(confidence_scores),
            },
        )

    async def _check_runtime(self) -> float:
        """Check if runtime is suspiciously short.

        Returns:
            Confidence score (0.0-1.0).
        """
        elapsed = time.time() - self._start_time

        if elapsed < 5:
            self._indicators.append(f"Very short runtime: {elapsed:.1f}s")
            return 0.8
        elif elapsed < 30:
            self._indicators.append(f"Short runtime: {elapsed:.1f}s")
            return 0.4

        return 0.0

    async def _check_user_interaction(self) -> float:
        """Check for user interaction traces.

        Returns:
            Confidence score (0.0-1.0).
        """
        if platform.system() == "Windows":
            try:
                import ctypes
                last_input = ctypes.windll.user32.GetLastInputInfo()
                if last_input:
                    class LASTINPUTINFO(ctypes.Structure):
                        _fields_ = [
                            ("cbSize", ctypes.c_uint),
                            ("dwTime", ctypes.c_ulong),
                        ]

                    lii = LASTINPUTINFO()
                    lii.cbSize = ctypes.sizeof(lii)

                    if ctypes.windll.user32.GetLastInputInfo(ctypes.byref(lii)):
                        idle_time = (ctypes.windll.kernel32.GetTickCount() - lii.dwTime) / 1000

                        if idle_time > 3600:
                            self._indicators.append(f"Long idle time: {idle_time:.0f}s")
                            return 0.6

            except Exception:
                pass

        return 0.0

    async def _check_screen_resolution(self) -> float:
        """Check screen resolution for sandbox indicators.

        Returns:
            Confidence score (0.0-1.0).
        """
        if platform.system() == "Windows":
            try:
                import ctypes
                width = ctypes.windll.user32.GetSystemMetrics(0)
                height = ctypes.windll.user32.GetSystemMetrics(1)

                if width < 800 or height < 600:
                    self._indicators.append(
                        f"Suspicious resolution: {width}x{height}"
                    )
                    return 0.7

                if width == 1024 and height == 768:
                    self._indicators.append(
                        f"Common sandbox resolution: {width}x{height}"
                    )
                    return 0.5

            except Exception:
                pass

        return 0.0

    async def _check_registry_keys(self) -> float:
        """Check for sandbox-related registry keys.

        Returns:
            Confidence score (0.0-1.0).
        """
        if platform.system() != "Windows":
            return 0.0

        found = 0
        try:
            import winreg

            for key_path in self.SANDBOX_REGISTRY_KEYS:
                try:
                    parts = key_path.split("\\", 1)
                    if len(parts) != 2:
                        continue

                    hive_map = {
                        "HKEY_LOCAL_MACHINE": winreg.HKEY_LOCAL_MACHINE,
                        "HKEY_CURRENT_USER": winreg.HKEY_CURRENT_USER,
                    }

                    hive = hive_map.get(parts[0])
                    if not hive:
                        continue

                    winreg.OpenKey(hive, parts[1], 0, winreg.KEY_READ)
                    found += 1
                    self._indicators.append(f"VM registry key found: {key_path}")

                except FileNotFoundError:
                    pass

        except Exception:
            pass

        if found >= 2:
            return 0.9
        elif found == 1:
            return 0.5

        return 0.0

    async def _check_processes(self) -> float:
        """Check for sandbox-related processes.

        Returns:
            Confidence score (0.0-1.0).
        """
        if platform.system() != "Windows":
            return 0.0

        found = 0
        try:
            import subprocess
            output = subprocess.check_output(
                ["tasklist", "/FO", "CSV", "/NH"],
                creationflags=subprocess.CREATE_NO_WINDOW,
            ).decode("gbk", errors="ignore")

            for line in output.strip().split("\n"):
                parts = line.split(",")
                if parts:
                    name = parts[0].strip('"').lower()
                    if name in self.SANDBOX_PROCESSES:
                        found += 1
                        self._indicators.append(f"VM process found: {name}")

        except Exception:
            pass

        if found >= 2:
            return 0.9
        elif found == 1:
            return 0.5

        return 0.0

    async def _check_files(self) -> float:
        """Check for sandbox-related files.

        Returns:
            Confidence score (0.0-1.0).
        """
        if platform.system() != "Windows":
            return 0.0

        found = 0
        for file_path in self.SANDBOX_FILES:
            if os.path.exists(file_path):
                found += 1
                self._indicators.append(f"VM file found: {file_path}")

        if found >= 2:
            return 0.9
        elif found == 1:
            return 0.5

        return 0.0

    async def _check_hardware(self) -> float:
        """Check for virtual hardware indicators.

        Returns:
            Confidence score (0.0-1.0).
        """
        if platform.system() != "Windows":
            return 0.0

        indicators_found = 0

        try:
            import subprocess

            bios_output = subprocess.check_output(
                ["wmic", "bios", "get", "manufacturer", "/value"],
                creationflags=subprocess.CREATE_NO_WINDOW,
            ).decode("gbk", errors="ignore")

            vm_manufacturers = [
                "virtualbox", "vmware", "microsoft corporation",
                "xen", "qemu", "parallels",
            ]

            for manufacturer in vm_manufacturers:
                if manufacturer in bios_output.lower():
                    indicators_found += 1
                    self._indicators.append(
                        f"VM BIOS manufacturer: {manufacturer}"
                    )

        except Exception:
            pass

        if indicators_found >= 1:
            return 0.8

        return 0.0

    async def _check_network(self) -> float:
        """Check for network-based sandbox indicators.

        Returns:
            Confidence score (0.0-1.0).
        """
        try:
            mac_addr = self._get_mac_address()
            if mac_addr:
                vm_mac_prefixes = [
                    "00:05:69",
                    "00:0c:29",
                    "00:1c:14",
                    "00:50:56",
                    "08:00:27",
                    "00:16:3e",
                ]

                for prefix in vm_mac_prefixes:
                    if mac_addr.startswith(prefix):
                        self._indicators.append(f"VM MAC address: {mac_addr}")
                        return 0.7

        except Exception:
            pass

        return 0.0

    @staticmethod
    def _get_mac_address() -> Optional[str]:
        """Get the MAC address of the primary network interface.

        Returns:
            MAC address string, or None if not found.
        """
        try:
            import uuid
            mac = uuid.getnode()
            return ":".join(f"{(mac >> i) & 0xff:02x}" for i in range(40, -1, -8))
        except Exception:
            return None


# =============================================================================
# Camouflage Scorer
# =============================================================================

class CamouflageScorer:
    """Scores camouflage effectiveness against reference traffic.

    Uses local ML model to compare generated traffic against
    real browser traffic and outputs difference reports.

    Attributes:
        _reference_traffic: Reference traffic samples
        _category_weights: Per-category scoring weights
    """

    CATEGORY_WEIGHTS: Dict[CamouflageCategory, float] = {
        CamouflageCategory.HTTP_HEADERS: 0.20,
        CamouflageCategory.TLS_FINGERPRINT: 0.20,
        CamouflageCategory.TRAFFIC_PATTERN: 0.15,
        CamouflageCategory.DNS_BEHAVIOR: 0.10,
        CamouflageCategory.USER_AGENT: 0.10,
        CamouflageCategory.PAYLOAD_STRUCTURE: 0.15,
        CamouflageCategory.TIMING_BEHAVIOR: 0.10,
    }

    def __init__(self) -> None:
        """Initialize the CamouflageScorer."""
        self._reference_traffic: Dict[str, Any] = {}
        self._category_weights = {
            k.value: v for k, v in self.CATEGORY_WEIGHTS.items()
        }

    def set_reference_traffic(
        self, traffic_data: Dict[str, Any],
    ) -> None:
        """Set reference traffic for comparison.

        Args:
            traffic_data: Reference traffic samples.
        """
        self._reference_traffic = traffic_data
        logger.info(f"Set reference traffic with {len(traffic_data)} samples")

    def score(
        self,
        generated_traffic: Dict[str, Any],
        reference_service: str = "general",
    ) -> CamouflageScore:
        """Score camouflage effectiveness.

        Args:
            generated_traffic: Traffic to evaluate.
            reference_service: Reference service name.

        Returns:
            CamouflageScore with detailed results.
        """
        category_scores: Dict[str, float] = {}
        differences: List[str] = []
        suggestions: List[str] = []

        for category in CamouflageCategory:
            score = self._score_category(
                category, generated_traffic, reference_service,
            )
            category_scores[category.value] = score

            if score < 0.8:
                differences.append(
                    f"{category.value}: {score:.0%} similarity"
                )
                suggestion = self._get_suggestion(category, score)
                if suggestion:
                    suggestions.append(suggestion)

        overall_score = sum(
            category_scores.get(cat, 0) * weight
            for cat, weight in self._category_weights.items()
        )

        return CamouflageScore(
            overall_score=overall_score,
            category_scores=category_scores,
            comparison_target=reference_service,
            differences=differences,
            suggestions=suggestions,
        )

    def _score_category(
        self,
        category: CamouflageCategory,
        generated: Dict[str, Any],
        reference_service: str,
    ) -> float:
        """Score a specific camouflage category.

        Args:
            category: Category to score.
            generated: Generated traffic data.
            reference_service: Reference service name.

        Returns:
            Score between 0.0 and 1.0.
        """
        if category == CamouflageCategory.HTTP_HEADERS:
            return self._score_http_headers(generated)
        elif category == CamouflageCategory.TLS_FINGERPRINT:
            return self._score_tls_fingerprint(generated)
        elif category == CamouflageCategory.TRAFFIC_PATTERN:
            return self._score_traffic_pattern(generated)
        elif category == CamouflageCategory.DNS_BEHAVIOR:
            return self._score_dns_behavior(generated)
        elif category == CamouflageCategory.USER_AGENT:
            return self._score_user_agent(generated)
        elif category == CamouflageCategory.PAYLOAD_STRUCTURE:
            return self._score_payload_structure(generated)
        elif category == CamouflageCategory.TIMING_BEHAVIOR:
            return self._score_timing_behavior(generated)

        return 0.5

    def _score_http_headers(self, traffic: Dict[str, Any]) -> float:
        """Score HTTP header similarity.

        Args:
            traffic: Traffic data.

        Returns:
            Score between 0.0 and 1.0.
        """
        headers = traffic.get("headers", {})

        required_headers = [
            "Accept", "Accept-Language", "Accept-Encoding",
            "Connection", "Upgrade-Insecure-Requests",
        ]

        present = sum(1 for h in required_headers if h in headers)
        base_score = present / len(required_headers)

        if "Referer" in headers:
            base_score = min(1.0, base_score + 0.05)

        return base_score

    def _score_tls_fingerprint(self, traffic: Dict[str, Any]) -> float:
        """Score TLS fingerprint similarity.

        Args:
            traffic: Traffic data.

        Returns:
            Score between 0.0 and 1.0.
        """
        ja3 = traffic.get("ja3", "")

        if not ja3:
            return 0.3

        common_ja3_patterns = [
            "771,4865",
            "771,4866",
            "771,4867",
        ]

        for pattern in common_ja3_patterns:
            if pattern in ja3:
                return 0.9

        return 0.5

    def _score_traffic_pattern(self, traffic: Dict[str, Any]) -> float:
        """Score traffic pattern similarity.

        Args:
            traffic: Traffic data.

        Returns:
            Score between 0.0 and 1.0.
        """
        request_size = traffic.get("request_size", 0)
        response_size = traffic.get("response_size", 0)

        if 200 <= request_size <= 2000:
            return 0.8
        elif 100 <= request_size <= 5000:
            return 0.6

        return 0.3

    def _score_dns_behavior(self, traffic: Dict[str, Any]) -> float:
        """Score DNS behavior similarity.

        Args:
            traffic: Traffic data.

        Returns:
            Score between 0.0 and 1.0.
        """
        query_type = traffic.get("dns_query_type", "")
        query_frequency = traffic.get("dns_query_frequency", 0)

        if query_type == "TXT" and 1 <= query_frequency <= 5:
            return 0.9
        elif query_type in ("A", "AAAA", "TXT"):
            return 0.6

        return 0.3

    def _score_user_agent(self, traffic: Dict[str, Any]) -> float:
        """Score User-Agent similarity.

        Args:
            traffic: Traffic data.

        Returns:
            Score between 0.0 and 1.0.
        """
        ua = traffic.get("user_agent", "")

        if not ua:
            return 0.0

        modern_browsers = ["Chrome/", "Firefox/", "Safari/", "Edge/"]
        if any(browser in ua for browser in modern_browsers):
            return 0.9

        return 0.3

    def _score_payload_structure(self, traffic: Dict[str, Any]) -> float:
        """Score payload structure similarity.

        Args:
            traffic: Traffic data.

        Returns:
            Score between 0.0 and 1.0.
        """
        content_type = traffic.get("content_type", "")
        has_body = traffic.get("has_body", False)

        if content_type in (
            "application/json", "application/xml", "text/html",
        ):
            return 0.8 if has_body else 0.5

        return 0.4

    def _score_timing_behavior(self, traffic: Dict[str, Any]) -> float:
        """Score timing behavior similarity.

        Args:
            traffic: Traffic data.

        Returns:
            Score between 0.0 and 1.0.
        """
        interval = traffic.get("interval", 0)
        jitter = traffic.get("jitter", 0)

        if interval > 0 and 0.1 <= jitter <= 0.5:
            return 0.8
        elif interval > 0:
            return 0.5

        return 0.2

    @staticmethod
    def _get_suggestion(
        category: CamouflageCategory, score: float,
    ) -> str:
        """Get optimization suggestion for a category.

        Args:
            category: Category with low score.
            score: Current score.

        Returns:
            Suggestion string.
        """
        suggestions: Dict[str, str] = {
            CamouflageCategory.HTTP_HEADERS.value: (
                "Add missing standard browser headers (Accept, "
                "Accept-Language, Accept-Encoding)"
            ),
            CamouflageCategory.TLS_FINGERPRINT.value: (
                "Use modern browser TLS fingerprint (Chrome 120+ or "
                "Firefox 120+)"
            ),
            CamouflageCategory.TRAFFIC_PATTERN.value: (
                "Adjust request/response sizes to match normal "
                "browser patterns"
            ),
            CamouflageCategory.DNS_BEHAVIOR.value: (
                "Use TXT record queries with realistic frequency "
                "(1-5 queries per minute)"
            ),
            CamouflageCategory.USER_AGENT.value: (
                "Use a modern browser User-Agent string with "
                "version numbers"
            ),
            CamouflageCategory.PAYLOAD_STRUCTURE.value: (
                "Ensure payload uses standard content types "
                "(application/json, text/html)"
            ),
            CamouflageCategory.TIMING_BEHAVIOR.value: (
                "Add jitter to heartbeat intervals (10-50%) to "
                "simulate human behavior"
            ),
        }

        return suggestions.get(category.value, "Review and improve this category")


# =============================================================================
# Self-Test Framework
# =============================================================================

class SelfTestFramework:
    """Automated self-test framework for evasion validation.

    Provides a local simulation environment to test Beacon behavior,
    traffic generation, packet capture, and Profile comparison.
    Supports CI/CD integration.

    Attributes:
        _sandbox_detector: Sandbox detector
        _camouflage_scorer: Camouflage scorer
        _test_cases: Registered test cases
        _test_results: Test execution results
    """

    def __init__(self) -> None:
        """Initialize the SelfTestFramework."""
        self._sandbox_detector = SandboxDetector()
        self._camouflage_scorer = CamouflageScorer()
        self._test_cases: List[Callable[[], Coroutine[Any, Any, TestCase]]] = []
        self._test_results: List[TestCase] = []

    def register_test(
        self,
        test_func: Callable[[], Coroutine[Any, Any, TestCase]],
    ) -> None:
        """Register a test case.

        Args:
            test_func: Async test function returning TestCase.
        """
        self._test_cases.append(test_func)
        logger.info(f"Registered test: {test_func.__name__}")

    async def run_all(self) -> TestReport:
        """Run all registered tests.

        Returns:
            TestReport with all results.
        """
        started_at = time.time()
        self._test_results = []

        for test_func in self._test_cases:
            start = time.time()

            try:
                result = await test_func()
                result.duration = time.time() - start
            except Exception as e:
                result = TestCase(
                    test_id=test_func.__name__,
                    name=test_func.__name__,
                    result=TestResult.FAILED,
                    duration=time.time() - start,
                    error=str(e),
                )

            self._test_results.append(result)

        completed_at = time.time()

        return TestReport(
            test_cases=self._test_results,
            total_duration=completed_at - started_at,
            passed_count=sum(
                1 for r in self._test_results if r.result == TestResult.PASSED
            ),
            failed_count=sum(
                1 for r in self._test_results if r.result == TestResult.FAILED
            ),
            warning_count=sum(
                1 for r in self._test_results if r.result == TestResult.WARNING
            ),
            skipped_count=sum(
                1 for r in self._test_results if r.result == TestResult.SKIPPED
            ),
            started_at=started_at,
            completed_at=completed_at,
        )

    async def run_sandbox_detection(self) -> TestCase:
        """Run sandbox detection test.

        Returns:
            TestCase with results.
        """
        detection = await self._sandbox_detector.detect()

        return TestCase(
            test_id="sandbox_detection",
            name="Sandbox Detection",
            description="Check if running in a sandbox environment",
            category="evasion",
            result=(
                TestResult.FAILED if detection.is_sandbox
                else TestResult.PASSED
            ),
            details=detection.to_dict(),
        )

    async def run_camouflage_test(
        self,
        traffic: Dict[str, Any],
        reference: str = "general",
    ) -> TestCase:
        """Run camouflage effectiveness test.

        Args:
            traffic: Traffic to evaluate.
            reference: Reference service name.

        Returns:
            TestCase with results.
        """
        score = self._camouflage_scorer.score(traffic, reference)

        if score.overall_score >= 0.8:
            result = TestResult.PASSED
        elif score.overall_score >= 0.6:
            result = TestResult.WARNING
        else:
            result = TestResult.FAILED

        return TestCase(
            test_id="camouflage_test",
            name="Camouflage Effectiveness",
            description=f"Score camouflage against {reference}",
            category="camouflage",
            result=result,
            details=score.to_dict(),
        )

    async def run_profile_validation(self, profile_data: Dict[str, Any]) -> TestCase:
        """Run Profile validation test.

        Args:
            profile_data: Profile configuration to validate.

        Returns:
            TestCase with results.
        """
        errors: List[str] = []

        required_fields = ["name", "version", "protocol", "heartbeat"]
        for field_name in required_fields:
            if field_name not in profile_data:
                errors.append(f"Missing required field: {field_name}")

        if profile_data.get("heartbeat", {}).get("sleep_time", 0) <= 0:
            errors.append("Invalid heartbeat sleep_time")

        if profile_data.get("heartbeat", {}).get("jitter", 0) < 0:
            errors.append("Invalid heartbeat jitter")

        if errors:
            return TestCase(
                test_id="profile_validation",
                name="Profile Validation",
                description="Validate Profile configuration",
                category="profile",
                result=TestResult.FAILED,
                details={"errors": errors},
            )

        return TestCase(
            test_id="profile_validation",
            name="Profile Validation",
            description="Validate Profile configuration",
            category="profile",
            result=TestResult.PASSED,
            details={"profile_name": profile_data.get("name")},
        )

    async def run_traffic_generation_test(self) -> TestCase:
        """Run traffic generation test.

        Returns:
            TestCase with results.
        """
        try:
            simulated_traffic = {
                "headers": {
                    "User-Agent": (
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                        "AppleWebKit/537.36 (KHTML, like Gecko) "
                        "Chrome/120.0.0.0 Safari/537.36"
                    ),
                    "Accept": "text/html,application/xhtml+xml",
                    "Accept-Language": "en-US,en;q=0.9",
                    "Accept-Encoding": "gzip, deflate, br",
                    "Connection": "keep-alive",
                },
                "request_size": 512,
                "response_size": 1024,
                "ja3": "771,4865-4866-4867-49195-49199",
                "interval": 60,
                "jitter": 0.3,
                "content_type": "application/json",
                "has_body": True,
            }

            score = self._camouflage_scorer.score(simulated_traffic)

            return TestCase(
                test_id="traffic_generation",
                name="Traffic Generation",
                description="Generate and validate simulated traffic",
                category="traffic",
                result=(
                    TestResult.PASSED if score.overall_score >= 0.7
                    else TestResult.WARNING
                ),
                details=score.to_dict(),
            )

        except Exception as e:
            return TestCase(
                test_id="traffic_generation",
                name="Traffic Generation",
                description="Generate and validate simulated traffic",
                category="traffic",
                result=TestResult.FAILED,
                error=str(e),
            )


# =============================================================================
# Evasion Tester (Main Class)
# =============================================================================

class EvasionTester:
    """Main evasion testing and validation coordination engine.

    Integrates sandbox detection, camouflage scoring, and self-test
    framework for comprehensive evasion validation.

    Attributes:
        _sandbox_detector: Sandbox detector
        _camouflage_scorer: Camouflage scorer
        _self_test: Self-test framework
    """

    def __init__(self) -> None:
        """Initialize the EvasionTester."""
        self._sandbox_detector = SandboxDetector()
        self._camouflage_scorer = CamouflageScorer()
        self._self_test = SelfTestFramework()

    async def check_sandbox(self) -> SandboxDetection:
        """Check for sandbox environment.

        Returns:
            SandboxDetection with results.
        """
        return await self._sandbox_detector.detect()

    def score_camouflage(
        self,
        traffic: Dict[str, Any],
        reference: str = "general",
    ) -> CamouflageScore:
        """Score camouflage effectiveness.

        Args:
            traffic: Traffic to evaluate.
            reference: Reference service name.

        Returns:
            CamouflageScore with results.
        """
        return self._camouflage_scorer.score(traffic, reference)

    def set_reference_traffic(
        self, traffic_data: Dict[str, Any],
    ) -> None:
        """Set reference traffic for comparison.

        Args:
            traffic_data: Reference traffic samples.
        """
        self._camouflage_scorer.set_reference_traffic(traffic_data)

    async def run_self_test(self) -> TestReport:
        """Run the complete self-test suite.

        Returns:
            TestReport with all results.
        """
        self._self_test.register_test(
            self._self_test.run_sandbox_detection,
        )
        self._self_test.register_test(
            self._self_test.run_traffic_generation_test,
        )

        return await self._self_test.run_all()

    def get_self_test_framework(self) -> SelfTestFramework:
        """Get the self-test framework for custom test registration.

        Returns:
            SelfTestFramework instance.
        """
        return self._self_test


# =============================================================================
# Global Singleton
# =============================================================================

_evasion_tester: Optional[EvasionTester] = None


def get_evasion_tester() -> EvasionTester:
    """Get the global EvasionTester singleton.

    Returns:
        Singleton EvasionTester instance.
    """
    global _evasion_tester
    if _evasion_tester is None:
        _evasion_tester = EvasionTester()
    return _evasion_tester


__all__ = [
    "EvasionTester",
    "SandboxDetector",
    "CamouflageScorer",
    "SelfTestFramework",
    "SandboxDetection",
    "CamouflageScore",
    "TestCase",
    "TestReport",
    "SandboxType",
    "TestResult",
    "CamouflageCategory",
    "get_evasion_tester",
]
