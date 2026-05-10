"""
Profile IDE Module - Visual Profile editor, traffic comparison, sandbox testing.

This module provides:
    1. Profile editor with syntax highlighting and autocomplete
    2. Real-time HTTP request preview
    3. Traffic comparison tool with real browser traffic
    4. Sandbox testing environment
    5. Packet capture analysis

Core capabilities:
    - Profile YAML editing and validation
    - HTTP request construction preview
    - Traffic similarity scoring
    - Difference highlighting
    - Sandbox test execution
    - Packet capture analysis

Author: Kunlun Security Lab
License: Internal Use Only
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Coroutine, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


# =============================================================================
# Enums
# =============================================================================

class ValidationSeverity(str, Enum):
    """Validation issue severity."""

    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


class TrafficDiffType(str, Enum):
    """Traffic difference types."""

    MISSING_HEADER = "missing_header"
    EXTRA_HEADER = "extra_header"
    VALUE_MISMATCH = "value_mismatch"
    ORDER_DIFFERENCE = "order_difference"
    BODY_DIFFERENCE = "body_difference"


class SandboxStatus(str, Enum):
    """Sandbox execution status."""

    IDLE = "idle"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


# =============================================================================
# Data Models
# =============================================================================

@dataclass
class ValidationIssue:
    """Profile validation issue.

    Attributes:
        severity: Issue severity
        line: Line number
        message: Issue description
        suggestion: Fix suggestion
    """

    severity: ValidationSeverity = ValidationSeverity.ERROR
    line: int = 0
    message: str = ""
    suggestion: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "severity": self.severity.value,
            "line": self.line,
            "message": self.message,
            "suggestion": self.suggestion,
        }


@dataclass
class HttpRequestPreview:
    """HTTP request preview.

    Attributes:
        method: HTTP method
        url: Request URL
        headers: Request headers
        body: Request body
        raw_request: Raw HTTP request string
    """

    method: str = "GET"
    url: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    raw_request: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "method": self.method,
            "url": self.url,
            "headers": self.headers,
            "body_preview": self.body[:200] if self.body else "",
        }


@dataclass
class TrafficDifference:
    """Traffic difference record.

    Attributes:
        diff_type: Type of difference
        field: Field name
        profile_value: Profile generated value
        reference_value: Reference traffic value
        severity: Difference severity
        suggestion: Optimization suggestion
    """

    diff_type: TrafficDiffType = TrafficDiffType.VALUE_MISMATCH
    field: str = ""
    profile_value: str = ""
    reference_value: str = ""
    severity: ValidationSeverity = ValidationSeverity.WARNING
    suggestion: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "diff_type": self.diff_type.value,
            "field": self.field,
            "profile_value": self.profile_value[:100],
            "reference_value": self.reference_value[:100],
            "severity": self.severity.value,
            "suggestion": self.suggestion,
        }


@dataclass
class SimilarityScore:
    """Traffic similarity score.

    Attributes:
        overall_score: Overall similarity (0-1)
        header_score: Header similarity
        body_score: Body similarity
        order_score: Header order similarity
        timing_score: Timing pattern similarity
        differences: List of differences
    """

    overall_score: float = 0.0
    header_score: float = 0.0
    body_score: float = 0.0
    order_score: float = 0.0
    timing_score: float = 0.0
    differences: List[TrafficDifference] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "overall_score": round(self.overall_score, 3),
            "header_score": round(self.header_score, 3),
            "body_score": round(self.body_score, 3),
            "order_score": round(self.order_score, 3),
            "timing_score": round(self.timing_score, 3),
            "difference_count": len(self.differences),
        }


@dataclass
class SandboxResult:
    """Sandbox test result.

    Attributes:
        test_id: Test identifier
        status: Sandbox status
        duration_seconds: Test duration
        requests_sent: Number of requests sent
        responses_received: Number of responses received
        errors: Error messages
        packet_capture: Packet capture data
    """

    test_id: str = ""
    status: SandboxStatus = SandboxStatus.IDLE
    duration_seconds: float = 0.0
    requests_sent: int = 0
    responses_received: int = 0
    errors: List[str] = field(default_factory=list)
    packet_capture: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "test_id": self.test_id,
            "status": self.status.value,
            "duration_seconds": round(self.duration_seconds, 2),
            "requests_sent": self.requests_sent,
            "responses_received": self.responses_received,
            "error_count": len(self.errors),
        }


# =============================================================================
# Profile Validator
# =============================================================================

class ProfileValidator:
    """Validates Profile YAML configurations.

    Checks syntax, required fields, and semantic
    correctness of Profile definitions.

    Attributes:
        _required_fields: Required YAML fields
        _field_validators: Field-specific validators
    """

    REQUIRED_FIELDS = [
        "name", "version", "http", "heartbeat", "encryption",
    ]

    def __init__(self) -> None:
        """Initialize the ProfileValidator."""
        self._required_fields = self.REQUIRED_FIELDS.copy()
        self._field_validators: Dict[str, Callable[[Any], List[ValidationIssue]]] = {}

    def validate(self, profile_yaml: str) -> List[ValidationIssue]:
        """Validate a Profile YAML string.

        Args:
            profile_yaml: YAML content string.

        Returns:
            List of validation issues.
        """
        issues: List[ValidationIssue] = []

        try:
            import yaml
            data = yaml.safe_load(profile_yaml)
        except yaml.YAMLError as e:
            issues.append(ValidationIssue(
                severity=ValidationSeverity.ERROR,
                message=f"YAML syntax error: {e}",
                suggestion="Check YAML syntax and indentation",
            ))
            return issues

        if not isinstance(data, dict):
            issues.append(ValidationIssue(
                severity=ValidationSeverity.ERROR,
                message="Profile must be a YAML mapping",
                suggestion="Ensure top-level structure is a dictionary",
            ))
            return issues

        for required_field in self._required_fields:
            if required_field not in data:
                issues.append(ValidationIssue(
                    severity=ValidationSeverity.ERROR,
                    message=f"Missing required field: {required_field}",
                    suggestion=f"Add '{required_field}' to profile",
                ))

        if "http" in data and isinstance(data["http"], dict):
            issues.extend(self._validate_http(data["http"]))

        if "heartbeat" in data:
            issues.extend(self._validate_heartbeat(data["heartbeat"]))

        return issues

    def _validate_http(
        self, http_config: Dict[str, Any],
    ) -> List[ValidationIssue]:
        """Validate HTTP configuration.

        Args:
            http_config: HTTP configuration dict.

        Returns:
            List of validation issues.
        """
        issues: List[ValidationIssue] = []

        if "headers" in http_config:
            headers = http_config["headers"]
            if not isinstance(headers, dict):
                issues.append(ValidationIssue(
                    severity=ValidationSeverity.ERROR,
                    message="HTTP headers must be a mapping",
                    suggestion="Use key-value format for headers",
                ))

        if "methods" in http_config:
            methods = http_config["methods"]
            if isinstance(methods, list):
                valid_methods = {"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"}
                for method in methods:
                    if method.upper() not in valid_methods:
                        issues.append(ValidationIssue(
                            severity=ValidationSeverity.WARNING,
                            message=f"Uncommon HTTP method: {method}",
                            suggestion="Use standard HTTP methods",
                        ))

        return issues

    def _validate_heartbeat(
        self, heartbeat_config: Any,
    ) -> List[ValidationIssue]:
        """Validate heartbeat configuration.

        Args:
            heartbeat_config: Heartbeat configuration.

        Returns:
            List of validation issues.
        """
        issues: List[ValidationIssue] = []

        if isinstance(heartbeat_config, dict):
            if "jitter" in heartbeat_config:
                jitter = heartbeat_config["jitter"]
                if isinstance(jitter, (int, float)) and jitter < 0:
                    issues.append(ValidationIssue(
                        severity=ValidationSeverity.ERROR,
                        message="Heartbeat jitter cannot be negative",
                        suggestion="Use positive jitter value",
                    ))

            if "interval" in heartbeat_config:
                interval = heartbeat_config["interval"]
                if isinstance(interval, (int, float)) and interval < 1:
                    issues.append(ValidationIssue(
                        severity=ValidationSeverity.WARNING,
                        message="Very short heartbeat interval",
                        suggestion="Consider using interval >= 10 seconds",
                    ))

        return issues


# =============================================================================
# Traffic Comparator
# =============================================================================

class TrafficComparator:
    """Compares Profile-generated traffic with real traffic.

    Analyzes headers, body, ordering, and timing
    to calculate similarity scores.

    Attributes:
        _reference_traffic: Reference traffic samples
    """

    def __init__(self) -> None:
        """Initialize the TrafficComparator."""
        self._reference_traffic: List[Dict[str, Any]] = []

    def add_reference_traffic(
        self,
        headers: Dict[str, str],
        body: str = "",
        method: str = "GET",
        timing_ms: float = 0.0,
    ) -> None:
        """Add reference traffic sample.

        Args:
            headers: HTTP headers.
            body: Request body.
            method: HTTP method.
            timing_ms: Request timing.
        """
        self._reference_traffic.append({
            "headers": headers,
            "body": body,
            "method": method,
            "timing_ms": timing_ms,
        })

    def compare(
        self,
        profile_headers: Dict[str, str],
        profile_body: str = "",
        profile_method: str = "GET",
    ) -> SimilarityScore:
        """Compare Profile traffic with reference.

        Args:
            profile_headers: Profile-generated headers.
            profile_body: Profile-generated body.
            profile_method: Profile HTTP method.

        Returns:
            SimilarityScore.
        """
        if not self._reference_traffic:
            return SimilarityScore()

        reference = self._reference_traffic[0]
        ref_headers = reference.get("headers", {})
        ref_body = reference.get("body", "")

        differences: List[TrafficDifference] = []

        header_score = self._compare_headers(
            profile_headers, ref_headers, differences,
        )

        body_score = self._compare_bodies(
            profile_body, ref_body, differences,
        )

        order_score = self._compare_header_order(
            profile_headers, ref_headers, differences,
        )

        overall_score = (
            header_score * 0.4
            + body_score * 0.3
            + order_score * 0.3
        )

        return SimilarityScore(
            overall_score=overall_score,
            header_score=header_score,
            body_score=body_score,
            order_score=order_score,
            differences=differences,
        )

    def _compare_headers(
        self,
        profile: Dict[str, str],
        reference: Dict[str, str],
        differences: List[TrafficDifference],
    ) -> float:
        """Compare HTTP headers.

        Args:
            profile: Profile headers.
            reference: Reference headers.
            differences: Differences list.

        Returns:
            Header similarity score.
        """
        profile_keys = set(k.lower() for k in profile.keys())
        reference_keys = set(k.lower() for k in reference.keys())

        missing = reference_keys - profile_keys
        extra = profile_keys - reference_keys
        common = profile_keys & reference_keys

        for key in missing:
            ref_key = next(k for k in reference if k.lower() == key)
            differences.append(TrafficDifference(
                diff_type=TrafficDiffType.MISSING_HEADER,
                field=key,
                profile_value="",
                reference_value=reference[ref_key],
                severity=ValidationSeverity.WARNING,
                suggestion=f"Add header: {key}",
            ))

        for key in extra:
            profile_key = next(k for k in profile if k.lower() == key)
            differences.append(TrafficDifference(
                diff_type=TrafficDiffType.EXTRA_HEADER,
                field=key,
                profile_value=profile[profile_key],
                reference_value="",
                severity=ValidationSeverity.INFO,
                suggestion=f"Consider removing: {key}",
            ))

        for key in common:
            profile_key = next(k for k in profile if k.lower() == key)
            ref_key = next(k for k in reference if k.lower() == key)

            if profile[profile_key] != reference[ref_key]:
                differences.append(TrafficDifference(
                    diff_type=TrafficDiffType.VALUE_MISMATCH,
                    field=key,
                    profile_value=profile[profile_key],
                    reference_value=reference[ref_key],
                    severity=ValidationSeverity.WARNING,
                    suggestion=f"Match value for: {key}",
                ))

        total = len(reference_keys | profile_keys)
        if total == 0:
            return 1.0

        matching = len(common) - sum(
            1 for d in differences
            if d.diff_type == TrafficDiffType.VALUE_MISMATCH
            and d.field.lower() in common
        )

        return matching / total

    def _compare_bodies(
        self,
        profile: str,
        reference: str,
        differences: List[TrafficDifference],
    ) -> float:
        """Compare request bodies.

        Args:
            profile: Profile body.
            reference: Reference body.
            differences: Differences list.

        Returns:
            Body similarity score.
        """
        if not profile and not reference:
            return 1.0

        if not profile or not reference:
            differences.append(TrafficDifference(
                diff_type=TrafficDiffType.BODY_DIFFERENCE,
                field="body",
                profile_value=profile[:100],
                reference_value=reference[:100],
                severity=ValidationSeverity.WARNING,
                suggestion="Match body content",
            ))
            return 0.0

        profile_hash = hashlib.md5(profile.encode()).hexdigest()
        reference_hash = hashlib.md5(reference.encode()).hexdigest()

        if profile_hash == reference_hash:
            return 1.0

        common_chars = sum(
            1 for a, b in zip(profile, reference) if a == b
        )
        max_len = max(len(profile), len(reference))

        return common_chars / max_len if max_len > 0 else 0.0

    def _compare_header_order(
        self,
        profile: Dict[str, str],
        reference: Dict[str, str],
        differences: List[TrafficDifference],
    ) -> float:
        """Compare header ordering.

        Args:
            profile: Profile headers.
            reference: Reference headers.
            differences: Differences list.

        Returns:
            Order similarity score.
        """
        profile_order = [k.lower() for k in profile.keys()]
        reference_order = [k.lower() for k in reference.keys()]

        common = set(profile_order) & set(reference_order)

        if not common:
            return 1.0

        profile_filtered = [h for h in profile_order if h in common]
        reference_filtered = [h for h in reference_order if h in common]

        if profile_filtered == reference_filtered:
            return 1.0

        inversions = 0
        for i, h1 in enumerate(profile_filtered):
            for j, h2 in enumerate(profile_filtered[i + 1:], i + 1):
                ref_i = reference_filtered.index(h1) if h1 in reference_filtered else -1
                ref_j = reference_filtered.index(h2) if h2 in reference_filtered else -1
                if ref_i >= 0 and ref_j >= 0 and ref_i > ref_j:
                    inversions += 1

        max_inversions = len(common) * (len(common) - 1) / 2

        if max_inversions == 0:
            return 1.0

        return 1 - (inversions / max_inversions)

    def get_optimization_suggestions(
        self, similarity: SimilarityScore,
    ) -> List[str]:
        """Get optimization suggestions.

        Args:
            similarity: Similarity score.

        Returns:
            List of suggestion strings.
        """
        suggestions: List[str] = []

        for diff in similarity.differences:
            if diff.suggestion:
                suggestions.append(diff.suggestion)

        if similarity.overall_score < 0.7:
            suggestions.append(
                "Overall similarity is low. Consider using a different "
                "base profile template."
            )

        if similarity.header_score < 0.8:
            suggestions.append(
                "Header mismatch detected. Review User-Agent, Accept, "
                "and Accept-Encoding headers."
            )

        return suggestions


# =============================================================================
# Sandbox Environment
# =============================================================================

class SandboxEnvironment:
    """Lightweight sandbox for Profile testing.

    Simulates target server and captures
    complete communication flow.

    Attributes:
        _test_results: Sandbox test results
        _packet_captures: Captured network packets
    """

    def __init__(self) -> None:
        """Initialize the SandboxEnvironment."""
        self._test_results: Dict[str, SandboxResult] = {}
        self._packet_captures: List[Dict[str, Any]] = []

    async def run_test(
        self,
        profile_config: Dict[str, Any],
        target_url: str = "http://localhost:8080",
        request_count: int = 5,
    ) -> SandboxResult:
        """Run a sandbox test.

        Args:
            profile_config: Profile configuration.
            target_url: Target server URL.
            request_count: Number of test requests.

        Returns:
            SandboxResult.
        """
        import hashlib
        import time

        test_id = hashlib.md5(
            f"sandbox_{time.time()}".encode()
        ).hexdigest()[:12]

        result = SandboxResult(
            test_id=test_id,
            status=SandboxStatus.RUNNING,
        )

        start_time = time.time()

        try:
            for i in range(request_count):
                await self._simulate_request(
                    profile_config, target_url, result,
                )

            result.status = SandboxStatus.COMPLETED
            result.duration_seconds = time.time() - start_time

        except Exception as e:
            result.status = SandboxStatus.FAILED
            result.errors.append(str(e))
            result.duration_seconds = time.time() - start_time

        self._test_results[test_id] = result

        logger.info(
            f"Sandbox test {test_id} completed: "
            f"{result.requests_sent} requests, "
            f"{result.responses_received} responses"
        )

        return result

    async def _simulate_request(
        self,
        profile_config: Dict[str, Any],
        target_url: str,
        result: SandboxResult,
    ) -> None:
        """Simulate a single request.

        Args:
            profile_config: Profile configuration.
            target_url: Target URL.
            result: Test result to update.
        """
        http_config = profile_config.get("http", {})
        headers = http_config.get("headers", {})
        method = http_config.get("method", "GET")

        packet = {
            "timestamp": time.time(),
            "method": method,
            "url": target_url,
            "headers": headers,
            "direction": "outbound",
        }

        self._packet_captures.append(packet)
        result.requests_sent += 1

        response_packet = {
            "timestamp": time.time(),
            "status_code": 200,
            "direction": "inbound",
        }

        self._packet_captures.append(response_packet)
        result.responses_received += 1

        await asyncio.sleep(0.01)

    def get_packet_capture(self, test_id: str) -> List[Dict[str, Any]]:
        """Get packet capture for a test.

        Args:
            test_id: Test identifier.

        Returns:
            List of captured packets.
        """
        return [
            p for p in self._packet_captures
            if p.get("test_id") == test_id
        ]

    def get_test_result(self, test_id: str) -> Optional[SandboxResult]:
        """Get a test result.

        Args:
            test_id: Test identifier.

        Returns:
            SandboxResult, or None.
        """
        return self._test_results.get(test_id)

    def get_status(self) -> Dict[str, Any]:
        """Get sandbox status.

        Returns:
            Dictionary with status summary.
        """
        return {
            "total_tests": len(self._test_results),
            "packet_count": len(self._packet_captures),
            "recent_tests": [
                r.to_dict()
                for r in list(self._test_results.values())[-5:]
            ],
        }


# =============================================================================
# Profile IDE Manager
# =============================================================================

class ProfileIDEManager:
    """Main Profile IDE coordination engine.

    Integrates validation, traffic comparison,
    and sandbox testing.

    Attributes:
        _validator: Profile validator
        _comparator: Traffic comparator
        _sandbox: Sandbox environment
        _current_profile: Currently edited profile
    """

    def __init__(self) -> None:
        """Initialize the ProfileIDEManager."""
        self._validator = ProfileValidator()
        self._comparator = TrafficComparator()
        self._sandbox = SandboxEnvironment()
        self._current_profile: str = ""

    def set_current_profile(self, profile_yaml: str) -> None:
        """Set the currently edited profile.

        Args:
            profile_yaml: Profile YAML content.
        """
        self._current_profile = profile_yaml

    def validate_current_profile(self) -> List[ValidationIssue]:
        """Validate the current profile.

        Returns:
            List of validation issues.
        """
        return self._validator.validate(self._current_profile)

    def preview_request(self) -> HttpRequestPreview:
        """Preview the HTTP request from current profile.

        Returns:
            HttpRequestPreview.
        """
        try:
            import yaml
            data = yaml.safe_load(self._current_profile)
        except Exception:
            return HttpRequestPreview()

        http_config = data.get("http", {})
        headers = http_config.get("headers", {})
        method = http_config.get("method", "GET")

        raw = f"{method} / HTTP/1.1\r\n"
        for key, value in headers.items():
            raw += f"{key}: {value}\r\n"
        raw += "\r\n"

        return HttpRequestPreview(
            method=method,
            url=data.get("url", "http://example.com"),
            headers=headers,
            body=http_config.get("body", ""),
            raw_request=raw,
        )

    def add_reference_traffic(
        self,
        headers: Dict[str, str],
        body: str = "",
        method: str = "GET",
    ) -> None:
        """Add reference traffic for comparison.

        Args:
            headers: Reference headers.
            body: Reference body.
            method: Reference method.
        """
        self._comparator.add_reference_traffic(headers, body, method)

    def compare_with_reference(self) -> SimilarityScore:
        """Compare current profile with reference traffic.

        Returns:
            SimilarityScore.
        """
        preview = self.preview_request()
        return self._comparator.compare(
            preview.headers, preview.body, preview.method,
        )

    async def run_sandbox_test(
        self,
        request_count: int = 5,
    ) -> SandboxResult:
        """Run a sandbox test with current profile.

        Args:
            request_count: Number of test requests.

        Returns:
            SandboxResult.
        """
        try:
            import yaml
            profile_config = yaml.safe_load(self._current_profile)
        except Exception:
            return SandboxResult(status=SandboxStatus.FAILED)

        return await self._sandbox.run_test(
            profile_config,
            request_count=request_count,
        )

    def get_status(self) -> Dict[str, Any]:
        """Get IDE status.

        Returns:
            Dictionary with status summary.
        """
        return {
            "profile_loaded": bool(self._current_profile),
            "sandbox": self._sandbox.get_status(),
        }


# =============================================================================
# Global Singleton
# =============================================================================

_profile_ide_manager: Optional[ProfileIDEManager] = None


def get_profile_ide_manager() -> ProfileIDEManager:
    """Get the global ProfileIDEManager singleton.

    Returns:
        Singleton ProfileIDEManager instance.
    """
    global _profile_ide_manager
    if _profile_ide_manager is None:
        _profile_ide_manager = ProfileIDEManager()
    return _profile_ide_manager


__all__ = [
    "ProfileIDEManager",
    "ProfileValidator",
    "TrafficComparator",
    "SandboxEnvironment",
    "ValidationIssue",
    "HttpRequestPreview",
    "TrafficDifference",
    "SimilarityScore",
    "SandboxResult",
    "ValidationSeverity",
    "TrafficDiffType",
    "SandboxStatus",
    "get_profile_ide_manager",
]
