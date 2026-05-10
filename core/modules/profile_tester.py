"""
Profile Tester Module - Profile camouflage effectiveness testing and similarity scoring.

This module provides a testing suite for Malleable C2 Profiles that simulates
traffic generation without deploying an actual Beacon, compares generated traffic
against real browser traffic, and outputs camouflage similarity scores with
optimization recommendations.

Core capabilities:
    1. Profile traffic simulation without actual Beacon deployment
    2. Comparison between generated traffic and real browser traffic
    3. Camouflage similarity scoring across multiple dimensions
    4. Optimization suggestions for improving profile stealth
    5. Batch testing of multiple profiles

Author: Kunlun Security Lab
License: Internal Use Only
"""

from __future__ import annotations

import asyncio
import json
import logging
import random
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Coroutine, Dict, List, Optional, Tuple
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


# =============================================================================
# Enums
# =============================================================================

class TestDimension(str, Enum):
    """Traffic comparison dimensions."""

    USER_AGENT = "user_agent"
    HEADERS = "headers"
    URL_PATTERN = "url_pattern"
    BODY_FORMAT = "body_format"
    TIMING = "timing"
    TLS_FINGERPRINT = "tls_fingerprint"
    HTTP2_FINGERPRINT = "http2_fingerprint"
    OVERALL = "overall"


class TestSeverity(str, Enum):
    """Test result severity levels."""

    PASS = "pass"
    WARNING = "warning"
    FAIL = "fail"
    CRITICAL = "critical"


# =============================================================================
# Data Models
# =============================================================================

@dataclass
class TestResult:
    """Result of a single profile test dimension.

    Attributes:
        dimension: Test dimension
        score: Similarity score (0.0-1.0)
        severity: Test severity level
        details: Detailed test findings
        suggestions: Optimization suggestions
    """

    dimension: TestDimension = TestDimension.OVERALL
    score: float = 0.0
    severity: TestSeverity = TestSeverity.PASS
    details: str = ""
    suggestions: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "dimension": self.dimension.value,
            "score": round(self.score, 3),
            "severity": self.severity.value,
            "details": self.details,
            "suggestions": self.suggestions,
        }


@dataclass
class ProfileTestReport:
    """Complete test report for a profile.

    Attributes:
        profile_name: Tested profile name
        overall_score: Overall similarity score
        results: Individual dimension test results
        total_issues: Total number of issues found
        critical_issues: Number of critical issues
        warning_issues: Number of warnings
        test_duration_ms: Total test duration
        timestamp: Test execution timestamp
        recommendations: Top-level recommendations
    """

    profile_name: str = ""
    overall_score: float = 0.0
    results: List[TestResult] = field(default_factory=list)
    total_issues: int = 0
    critical_issues: int = 0
    warning_issues: int = 0
    test_duration_ms: float = 0.0
    timestamp: str = ""
    recommendations: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "profile_name": self.profile_name,
            "overall_score": round(self.overall_score, 3),
            "results": [r.to_dict() for r in self.results],
            "total_issues": self.total_issues,
            "critical_issues": self.critical_issues,
            "warning_issues": self.warning_issues,
            "test_duration_ms": round(self.test_duration_ms, 2),
            "timestamp": self.timestamp,
            "recommendations": self.recommendations,
        }

    def to_markdown(self) -> str:
        """Generate a markdown-formatted test report.

        Returns:
            Markdown string of the test report.
        """
        lines = [
            f"# Profile Test Report: {self.profile_name}",
            f"",
            f"**Overall Score**: {self.overall_score:.1%}",
            f"**Test Duration**: {self.test_duration_ms:.0f}ms",
            f"**Issues**: {self.critical_issues} critical, {self.warning_issues} warnings",
            f"",
            f"## Dimension Results",
            f"",
            f"| Dimension | Score | Severity |",
            f"|-----------|-------|----------|",
        ]

        for r in self.results:
            emoji = {
                TestSeverity.PASS: "✅",
                TestSeverity.WARNING: "⚠️",
                TestSeverity.FAIL: "❌",
                TestSeverity.CRITICAL: "🚨",
            }.get(r.severity, "")

            lines.append(
                f"| {r.dimension.value} | {r.score:.1%} | {emoji} {r.severity.value} |"
            )

        if self.recommendations:
            lines.extend([
                f"",
                f"## Recommendations",
                f"",
            ])
            for rec in self.recommendations:
                lines.append(f"- {rec}")

        return "\n".join(lines)


@dataclass
class SimulatedRequest:
    """A simulated request generated from a profile.

    Attributes:
        method: HTTP method
        url: Generated URL
        headers: Generated headers
        body: Generated body
        timing_ms: Time to construct the request
    """

    method: str = "GET"
    url: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    timing_ms: float = 0.0


@dataclass
class ReferenceTraffic:
    """Reference real browser traffic for comparison.

    Attributes:
        user_agents: Known real User-Agent strings
        headers: Known real header patterns
        url_patterns: Known real URL patterns
        body_samples: Known real body samples
        timing_samples: Known real timing samples
        source: Source of the reference data
    """

    user_agents: List[str] = field(default_factory=list)
    headers: Dict[str, List[str]] = field(default_factory=dict)
    url_patterns: List[str] = field(default_factory=list)
    body_samples: List[str] = field(default_factory=list)
    timing_samples: List[float] = field(default_factory=list)
    source: str = "manual"


# =============================================================================
# Built-in Reference Traffic Library
# =============================================================================

class ReferenceTrafficLibrary:
    """Built-in reference traffic data for common services.

    Provides known-good traffic patterns for popular services
    to use as comparison baselines.
    """

    @classmethod
    def get_jquery_reference(cls) -> ReferenceTraffic:
        """Get reference traffic for jQuery CDN requests.

        Returns:
            ReferenceTraffic for jQuery CDN patterns.
        """
        return ReferenceTraffic(
            user_agents=[
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            ],
            headers={
                "Accept": [
                    "application/javascript, */*;q=0.8",
                    "*/*",
                ],
                "Accept-Encoding": ["gzip, deflate, br"],
                "Accept-Language": ["en-US,en;q=0.9"],
                "Cache-Control": ["no-cache"],
                "Referer": ["https://example.com/index.html"],
            },
            url_patterns=[
                r"/js/jquery-[\w]+\.min\.js\?ts=\d+",
                r"/js/jquery-\d+\.\d+\.\d+\.min\.js",
            ],
            source="jquery_cdn",
        )

    @classmethod
    def get_google_analytics_reference(cls) -> ReferenceTraffic:
        """Get reference traffic for Google Analytics requests.

        Returns:
            ReferenceTraffic for Google Analytics patterns.
        """
        return ReferenceTraffic(
            user_agents=[
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            ],
            headers={
                "Accept": ["image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, */*"],
                "Accept-Encoding": ["gzip, deflate"],
                "Content-Type": ["application/x-www-form-urlencoded"],
                "Origin": ["https://example.com"],
            },
            url_patterns=[
                r"/collect\?v=1&t=pageview&tid=UA-\d+-\d+&cid=[\w-]+",
                r"/collect\?.*v=1.*",
            ],
            body_samples=[
                "v=1&t=pageview&tid=UA-123456-1&cid=abc123&dl=https%3A%2F%2Fexample.com",
            ],
            source="google_analytics",
        )

    @classmethod
    def get_reference(cls, service: str) -> Optional[ReferenceTraffic]:
        """Get reference traffic for a service.

        Args:
            service: Service name.

        Returns:
            ReferenceTraffic, or None if not found.
        """
        references: Dict[str, Callable[..., ReferenceTraffic]] = {
            "jquery": cls.get_jquery_reference,
            "google_analytics": cls.get_google_analytics_reference,
        }

        factory = references.get(service)
        return factory() if factory else None


# =============================================================================
# Profile Traffic Simulator
# =============================================================================

class ProfileTrafficSimulator:
    """Simulates traffic generation from a profile without deploying a Beacon.

    Generates sample requests based on profile configuration to test
    the profile's output without actual C2 communication.

    Attributes:
        _variable_resolver: Variable resolver for template substitution
    """

    def __init__(self) -> None:
        """Initialize the ProfileTrafficSimulator."""
        self._variable_resolver = self._create_variable_resolver()

    def simulate_requests(
        self,
        profile_dict: Dict[str, Any],
        count: int = 5,
    ) -> List[SimulatedRequest]:
        """Simulate multiple requests from a profile.

        Args:
            profile_dict: Profile configuration dictionary.
            count: Number of requests to simulate.

        Returns:
            List of SimulatedRequest instances.
        """
        requests: List[SimulatedRequest] = []

        http_config = profile_dict.get("http", {})
        method = http_config.get("http_method", "GET")
        uri_template = http_config.get("http_uri", "/")
        headers_template = http_config.get("headers", {})
        user_agents = http_config.get("user_agent", [])
        body_format = http_config.get("body_format", "plain")
        body_template = http_config.get("body_template", "")
        referer = http_config.get("referer", "")
        cookie = http_config.get("cookie", "")

        for i in range(count):
            start_time = time.monotonic()

            url = self._resolve_variables(uri_template)

            headers: Dict[str, str] = {}
            for key, value in headers_template.items():
                if isinstance(value, list):
                    headers[key] = random.choice(value)
                else:
                    headers[key] = self._resolve_variables(value)

            if user_agents:
                headers["User-Agent"] = random.choice(user_agents)

            if referer:
                headers["Referer"] = self._resolve_variables(referer)

            if cookie:
                headers["Cookie"] = self._resolve_variables(cookie)

            body = ""
            if body_template and method != "GET":
                body = self._resolve_variables(body_template)

            elapsed_ms = (time.monotonic() - start_time) * 1000

            requests.append(SimulatedRequest(
                method=method,
                url=url,
                headers=headers,
                body=body,
                timing_ms=elapsed_ms,
            ))

        return requests

    def _resolve_variables(self, template: str) -> str:
        """Resolve template variables.

        Args:
            template: Template string with {{variable}} patterns.

        Returns:
            Resolved string.
        """
        import re

        def _replace(match: re.Match[str]) -> str:
            var_name = match.group(1)
            replacements = {
                "timestamp": str(int(time.time())),
                "random_string": "".join(
                    random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=12)
                ),
                "random_int": str(random.randint(100000, 999999)),
                "random_hex": "".join(
                    random.choices("0123456789abcdef", k=16)
                ),
                "hostname": "example.com",
                "beacon_id": "test-beacon-001",
                "task_id": "test-task",
                "date_iso": time.strftime("%Y-%m-%dT%H:%M:%S"),
                "payload": "test-payload-data",
            }
            return str(replacements.get(var_name, match.group(0)))

        return re.sub(r"\{\{(\w+)\}\}", _replace, template)

    @staticmethod
    def _create_variable_resolver() -> Any:
        """Create a variable resolver placeholder."""
        return None


# =============================================================================
# Similarity Scorer
# =============================================================================

class SimilarityScorer:
    """Computes similarity scores between generated and reference traffic.

    Evaluates multiple dimensions including User-Agent, headers, URL patterns,
    body format, and timing to produce an overall camouflage score.

    Attributes:
        _dimension_weights: Weights for each test dimension
    """

    DIMENSION_WEIGHTS: Dict[TestDimension, float] = {
        TestDimension.USER_AGENT: 0.20,
        TestDimension.HEADERS: 0.25,
        TestDimension.URL_PATTERN: 0.20,
        TestDimension.BODY_FORMAT: 0.10,
        TestDimension.TIMING: 0.10,
        TestDimension.TLS_FINGERPRINT: 0.10,
        TestDimension.HTTP2_FINGERPRINT: 0.05,
    }

    def score_user_agent(
        self,
        simulated_agents: List[str],
        reference_agents: List[str],
    ) -> TestResult:
        """Score User-Agent similarity.

        Args:
            simulated_agents: User-Agents from simulated traffic.
            reference_agents: Reference User-Agents.

        Returns:
            TestResult with UA similarity score.
        """
        if not reference_agents:
            return TestResult(
                dimension=TestDimension.USER_AGENT,
                score=0.5,
                severity=TestSeverity.WARNING,
                details="No reference User-Agents provided for comparison",
                suggestions=["Provide reference User-Agent strings for accurate scoring"],
            )

        if not simulated_agents:
            return TestResult(
                dimension=TestDimension.USER_AGENT,
                score=0.0,
                severity=TestSeverity.CRITICAL,
                details="No User-Agent in simulated traffic",
                suggestions=["Add User-Agent to profile configuration"],
            )

        best_score = 0.0
        for sim_ua in simulated_agents:
            for ref_ua in reference_agents:
                score = self._string_similarity(sim_ua, ref_ua)
                best_score = max(best_score, score)

        severity = TestSeverity.PASS
        suggestions: List[str] = []

        if best_score < 0.5:
            severity = TestSeverity.CRITICAL
            suggestions.append("User-Agent does not match reference; use a real browser UA")
        elif best_score < 0.8:
            severity = TestSeverity.WARNING
            suggestions.append("User-Agent partially matches; consider using exact reference UA")

        return TestResult(
            dimension=TestDimension.USER_AGENT,
            score=best_score,
            severity=severity,
            details=f"Best UA similarity: {best_score:.1%}",
            suggestions=suggestions,
        )

    def score_headers(
        self,
        simulated_headers: Dict[str, str],
        reference_headers: Dict[str, List[str]],
    ) -> TestResult:
        """Score header similarity.

        Args:
            simulated_headers: Headers from simulated traffic.
            reference_headers: Reference header patterns.

        Returns:
            TestResult with header similarity score.
        """
        if not reference_headers:
            return TestResult(
                dimension=TestDimension.HEADERS,
                score=0.5,
                severity=TestSeverity.WARNING,
                details="No reference headers provided",
            )

        total_score = 0.0
        total_count = 0
        missing_headers: List[str] = []
        mismatched_headers: List[str] = []

        for ref_key, ref_values in reference_headers.items():
            total_count += 1

            sim_value = simulated_headers.get(ref_key)
            if not sim_value:
                missing_headers.append(ref_key)
                continue

            best_match = max(
                self._string_similarity(sim_value, rv) for rv in ref_values
            )
            total_score += best_match

            if best_match < 0.7:
                mismatched_headers.append(ref_key)

        score = total_score / total_count if total_count > 0 else 0.0

        severity = TestSeverity.PASS
        suggestions: List[str] = []

        if missing_headers:
            severity = TestSeverity.WARNING
            suggestions.append(
                f"Missing headers: {', '.join(missing_headers[:5])}"
            )

        if mismatched_headers:
            suggestions.append(
                f"Header values differ from reference: {', '.join(mismatched_headers[:5])}"
            )

        if score < 0.5:
            severity = TestSeverity.CRITICAL

        return TestResult(
            dimension=TestDimension.HEADERS,
            score=score,
            severity=severity,
            details=f"Header match: {score:.1%} ({len(missing_headers)} missing, "
                    f"{len(mismatched_headers)} mismatched)",
            suggestions=suggestions,
        )

    def score_url_pattern(
        self,
        simulated_urls: List[str],
        reference_patterns: List[str],
    ) -> TestResult:
        """Score URL pattern similarity.

        Args:
            simulated_urls: URLs from simulated traffic.
            reference_patterns: Reference URL regex patterns.

        Returns:
            TestResult with URL pattern similarity score.
        """
        import re

        if not reference_patterns:
            return TestResult(
                dimension=TestDimension.URL_PATTERN,
                score=0.5,
                severity=TestSeverity.WARNING,
                details="No reference URL patterns provided",
            )

        if not simulated_urls:
            return TestResult(
                dimension=TestDimension.URL_PATTERN,
                score=0.0,
                severity=TestSeverity.CRITICAL,
                details="No URLs in simulated traffic",
            )

        match_count = 0
        for url in simulated_urls:
            for pattern in reference_patterns:
                try:
                    if re.search(pattern, url):
                        match_count += 1
                        break
                except re.error:
                    continue

        score = match_count / len(simulated_urls) if simulated_urls else 0.0

        severity = TestSeverity.PASS if score >= 0.8 else TestSeverity.WARNING
        if score < 0.5:
            severity = TestSeverity.CRITICAL

        return TestResult(
            dimension=TestDimension.URL_PATTERN,
            score=score,
            severity=severity,
            details=f"URL pattern match rate: {score:.1%} ({match_count}/{len(simulated_urls)})",
            suggestions=[] if score >= 0.8 else [
                "URL pattern does not match reference; adjust URI template",
            ],
        )

    def score_body_format(
        self,
        simulated_bodies: List[str],
        reference_bodies: List[str],
        expected_format: str = "plain",
    ) -> TestResult:
        """Score body format similarity.

        Args:
            simulated_bodies: Bodies from simulated traffic.
            reference_bodies: Reference body samples.
            expected_format: Expected body format.

        Returns:
            TestResult with body format similarity score.
        """
        if not reference_bodies:
            return TestResult(
                dimension=TestDimension.BODY_FORMAT,
                score=0.5,
                severity=TestSeverity.WARNING,
                details="No reference body samples provided",
            )

        if not simulated_bodies:
            return TestResult(
                dimension=TestDimension.BODY_FORMAT,
                score=0.5,
                severity=TestSeverity.PASS,
                details="No body in simulated traffic (GET request)",
            )

        best_score = 0.0
        for sim_body in simulated_bodies:
            for ref_body in reference_bodies:
                score = self._string_similarity(sim_body, ref_body)
                best_score = max(best_score, score)

        severity = TestSeverity.PASS if best_score >= 0.3 else TestSeverity.WARNING

        return TestResult(
            dimension=TestDimension.BODY_FORMAT,
            score=best_score,
            severity=severity,
            details=f"Body similarity: {best_score:.1%}",
            suggestions=[] if best_score >= 0.3 else [
                "Body content differs significantly from reference",
            ],
        )

    def score_timing(
        self,
        simulated_timings: List[float],
        reference_timings: List[float],
    ) -> TestResult:
        """Score timing similarity.

        Args:
            simulated_timings: Request construction timings.
            reference_timings: Reference timing samples.

        Returns:
            TestResult with timing similarity score.
        """
        if not reference_timings:
            return TestResult(
                dimension=TestDimension.TIMING,
                score=0.5,
                severity=TestSeverity.WARNING,
                details="No reference timing samples provided",
            )

        if not simulated_timings:
            return TestResult(
                dimension=TestDimension.TIMING,
                score=0.0,
                severity=TestSeverity.FAIL,
                details="No timing data from simulation",
            )

        sim_avg = sum(simulated_timings) / len(simulated_timings)
        ref_avg = sum(reference_timings) / len(reference_timings)

        if ref_avg == 0:
            score = 1.0 if sim_avg == 0 else 0.0
        else:
            ratio = min(sim_avg, ref_avg) / max(sim_avg, ref_avg)
            score = ratio

        severity = TestSeverity.PASS if score >= 0.8 else TestSeverity.WARNING

        return TestResult(
            dimension=TestDimension.TIMING,
            score=score,
            severity=severity,
            details=f"Timing ratio: {score:.1%} (sim: {sim_avg:.2f}ms, ref: {ref_avg:.2f}ms)",
            suggestions=[] if score >= 0.8 else [
                "Request construction time differs from reference",
            ],
        )

    def compute_overall_score(self, results: List[TestResult]) -> float:
        """Compute weighted overall score from dimension results.

        Args:
            results: List of dimension TestResults.

        Returns:
            Weighted overall score (0.0-1.0).
        """
        if not results:
            return 0.0

        total_weight = 0.0
        weighted_score = 0.0

        for result in results:
            weight = self.DIMENSION_WEIGHTS.get(result.dimension, 0.1)
            weighted_score += result.score * weight
            total_weight += weight

        return weighted_score / total_weight if total_weight > 0 else 0.0

    @staticmethod
    def _string_similarity(s1: str, s2: str) -> float:
        """Compute similarity between two strings.

        Uses a simple character-level similarity metric.

        Args:
            s1: First string.
            s2: Second string.

        Returns:
            Similarity score (0.0-1.0).
        """
        if not s1 and not s2:
            return 1.0
        if not s1 or not s2:
            return 0.0

        s1_lower = s1.lower()
        s2_lower = s2.lower()

        if s1_lower == s2_lower:
            return 1.0

        longer = s1_lower if len(s1_lower) > len(s2_lower) else s2_lower
        shorter = s2_lower if len(s1_lower) > len(s2_lower) else s1_lower

        if not longer:
            return 1.0

        matches = 0
        for i in range(len(shorter)):
            if shorter[i] == longer[i]:
                matches += 1

        base_score = matches / len(longer)

        len_ratio = len(shorter) / len(longer) if longer else 0

        return base_score * 0.6 + len_ratio * 0.4


# =============================================================================
# Profile Tester (Main Class)
# =============================================================================

class ProfileTester:
    """Main profile testing engine.

    Coordinates traffic simulation, similarity scoring, and report
    generation to evaluate profile camouflage effectiveness.

    Attributes:
        _simulator: Traffic simulator instance
        _scorer: Similarity scorer instance
        _reference_library: Reference traffic library
        _test_history: History of test reports
    """

    def __init__(self) -> None:
        """Initialize the ProfileTester."""
        self._simulator = ProfileTrafficSimulator()
        self._scorer = SimilarityScorer()
        self._reference_library = ReferenceTrafficLibrary()
        self._test_history: List[ProfileTestReport] = []

    def test_profile(
        self,
        profile_dict: Dict[str, Any],
        reference: Optional[ReferenceTraffic] = None,
        simulation_count: int = 5,
    ) -> ProfileTestReport:
        """Test a profile's camouflage effectiveness.

        Args:
            profile_dict: Profile configuration dictionary.
            reference: Reference traffic for comparison.
            simulation_count: Number of requests to simulate.

        Returns:
            ProfileTestReport with test results.
        """
        start_time = time.monotonic()
        profile_name = profile_dict.get("name", "unknown")

        simulated = self._simulator.simulate_requests(
            profile_dict, simulation_count,
        )

        results: List[TestResult] = []

        if reference:
            sim_uas = list(set(
                s.headers.get("User-Agent", "") for s in simulated
            ))
            results.append(self._scorer.score_user_agent(
                sim_uas, reference.user_agents,
            ))

            sim_headers = simulated[0].headers if simulated else {}
            results.append(self._scorer.score_headers(
                sim_headers, reference.headers,
            ))

            sim_urls = [s.url for s in simulated]
            results.append(self._scorer.score_url_pattern(
                sim_urls, reference.url_patterns,
            ))

            sim_bodies = [s.body for s in simulated if s.body]
            results.append(self._scorer.score_body_format(
                sim_bodies, reference.body_samples,
            ))

            sim_timings = [s.timing_ms for s in simulated]
            results.append(self._scorer.score_timing(
                sim_timings, reference.timing_samples,
            ))
        else:
            results.append(TestResult(
                dimension=TestDimension.USER_AGENT,
                score=0.5,
                severity=TestSeverity.WARNING,
                details="No reference traffic provided; limited scoring available",
                suggestions=["Provide reference traffic for comprehensive testing"],
            ))

        overall = self._scorer.compute_overall_score(results)

        elapsed_ms = (time.monotonic() - start_time) * 1000

        critical = sum(1 for r in results if r.severity == TestSeverity.CRITICAL)
        warnings = sum(1 for r in results if r.severity == TestSeverity.WARNING)

        recommendations = self._generate_recommendations(results, overall)

        report = ProfileTestReport(
            profile_name=profile_name,
            overall_score=overall,
            results=results,
            total_issues=critical + warnings,
            critical_issues=critical,
            warning_issues=warnings,
            test_duration_ms=elapsed_ms,
            timestamp=time.strftime("%Y-%m-%dT%H:%M:%S"),
            recommendations=recommendations,
        )

        self._test_history.append(report)

        logger.info(
            f"Profile test complete: {profile_name} "
            f"(score: {overall:.1%}, {critical} critical, {warnings} warnings)"
        )

        return report

    def test_profile_from_yaml(
        self,
        yaml_content: str,
        reference_service: str = "",
        simulation_count: int = 5,
    ) -> ProfileTestReport:
        """Test a profile from YAML content.

        Args:
            yaml_content: YAML profile string.
            reference_service: Reference service name.
            simulation_count: Number of requests to simulate.

        Returns:
            ProfileTestReport with test results.
        """
        import yaml

        try:
            profile_dict = yaml.safe_load(yaml_content)
        except yaml.YAMLError as e:
            return ProfileTestReport(
                profile_name="parse_error",
                overall_score=0.0,
                recommendations=[f"YAML parse error: {e}"],
            )

        reference = None
        if reference_service:
            reference = self._reference_library.get_reference(reference_service)

        return self.test_profile(profile_dict, reference, simulation_count)

    def batch_test_profiles(
        self,
        profiles: List[Dict[str, Any]],
        reference: Optional[ReferenceTraffic] = None,
    ) -> List[ProfileTestReport]:
        """Test multiple profiles in batch.

        Args:
            profiles: List of profile dictionaries.
            reference: Reference traffic for comparison.

        Returns:
            List of ProfileTestReport instances.
        """
        reports: List[ProfileTestReport] = []

        for profile in profiles:
            report = self.test_profile(profile, reference)
            reports.append(report)

        reports.sort(key=lambda r: r.overall_score, reverse=True)
        return reports

    def get_test_history(self) -> List[ProfileTestReport]:
        """Get all test reports.

        Returns:
            List of ProfileTestReport instances.
        """
        return list(self._test_history)

    def _generate_recommendations(
        self, results: List[TestResult], overall_score: float,
    ) -> List[str]:
        """Generate top-level recommendations.

        Args:
            results: Dimension test results.
            overall_score: Overall similarity score.

        Returns:
            List of recommendation strings.
        """
        recommendations: List[str] = []

        if overall_score >= 0.9:
            recommendations.append(
                "Excellent camouflage! Profile closely matches reference traffic.",
            )
        elif overall_score >= 0.7:
            recommendations.append(
                "Good camouflage with minor improvements needed.",
            )
        elif overall_score >= 0.5:
            recommendations.append(
                "Moderate camouflage; significant improvements recommended before use.",
            )
        else:
            recommendations.append(
                "Poor camouflage; profile is likely to be detected. "
                "Major revisions needed.",
            )

        for result in results:
            if result.severity == TestSeverity.CRITICAL:
                recommendations.extend(result.suggestions)

        return recommendations


# =============================================================================
# Global Singleton
# =============================================================================

_profile_tester: Optional[ProfileTester] = None


def get_profile_tester() -> ProfileTester:
    """Get the global ProfileTester singleton.

    Returns:
        Singleton ProfileTester instance.
    """
    global _profile_tester
    if _profile_tester is None:
        _profile_tester = ProfileTester()
    return _profile_tester


__all__ = [
    "ProfileTester",
    "ProfileTrafficSimulator",
    "SimilarityScorer",
    "ReferenceTrafficLibrary",
    "ProfileTestReport",
    "TestResult",
    "SimulatedRequest",
    "ReferenceTraffic",
    "TestDimension",
    "TestSeverity",
    "get_profile_tester",
]
