"""
JWT Information Leak Module - Key leakage detection, timing side-channel,
and error message differential analysis.

This module provides:
    1. JWT key and credential leak detection in proxy history
    2. JavaScript file scanning for hardcoded secrets
    3. Timing side-channel attacks for signature verification
    4. Error message differential analysis for library fingerprinting
    5. Automatic vulnerability database matching

Integration points:
    - MITM proxy traffic capture
    - JavaScript asset scanning
    - Error message analysis
    - Timing measurement infrastructure

Author: Kunlun Security Lab
License: Internal Use Only
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import logging
import re
import statistics
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

import aiohttp

logger = logging.getLogger(__name__)


# =============================================================================
# Enums
# =============================================================================

class LeakType(str, Enum):
    """Types of information leaks."""

    JWT_SECRET = "jwt_secret"
    JWKS_PRIVATE_KEY = "jwks_private_key"
    OAUTH_CLIENT_SECRET = "oauth_client_secret"
    HARD_CODED_KEY = "hardcoded_key"
    ERROR_STACK_TRACE = "error_stack_trace"
    DEBUG_INFO = "debug_info"


class Severity(str, Enum):
    """Vulnerability severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class TimingAttackPhase(str, Enum):
    """Timing attack phases."""

    BASELINE = "baseline"
    MEASUREMENT = "measurement"
    ANALYSIS = "analysis"


# =============================================================================
# Data Classes
# =============================================================================

@dataclass
class LeakFinding:
    """Information leak finding.

    Attributes:
        leak_type: Type of leak detected
        severity: Finding severity
        source_url: URL where leak was found
        source_file: File containing the leak
        leaked_value: The leaked value (masked)
        context: Surrounding context
        line_number: Line number in source file
        timestamp: Detection timestamp
    """

    leak_type: LeakType = LeakType.JWT_SECRET
    severity: Severity = Severity.INFO
    source_url: str = ""
    source_file: str = ""
    leaked_value: str = ""
    context: str = ""
    line_number: int = 0
    timestamp: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary.

        Returns:
            Dictionary representation.
        """
        return {
            "leak_type": self.leak_type.value,
            "severity": self.severity.value,
            "source_url": self.source_url,
            "source_file": self.source_file,
            "leaked_value": self._mask_value(self.leaked_value),
            "context": self.context,
            "line_number": self.line_number,
            "timestamp": self.timestamp,
        }

    @staticmethod
    def _mask_value(value: str) -> str:
        """Mask sensitive value for safe display.

        Args:
            value: Original value.

        Returns:
            Masked value.
        """
        if len(value) <= 8:
            return value[:2] + "*" * (len(value) - 2)
        return value[:4] + "*" * (len(value) - 8) + value[-4:]


@dataclass
class TimingMeasurement:
    """Timing measurement result.

    Attributes:
        test_case: Test case identifier
        samples: List of timing samples in milliseconds
        mean_ms: Mean response time
        median_ms: Median response time
        std_dev_ms: Standard deviation
        min_ms: Minimum response time
        max_ms: Maximum response time
    """

    test_case: str = ""
    samples: List[float] = field(default_factory=list)
    mean_ms: float = 0.0
    median_ms: float = 0.0
    std_dev_ms: float = 0.0
    min_ms: float = 0.0
    max_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary.

        Returns:
            Dictionary representation.
        """
        return {
            "test_case": self.test_case,
            "sample_count": len(self.samples),
            "mean_ms": self.mean_ms,
            "median_ms": self.median_ms,
            "std_dev_ms": self.std_dev_ms,
            "min_ms": self.min_ms,
            "max_ms": self.max_ms,
        }

    def calculate_stats(self) -> None:
        """Calculate statistical measures from samples."""
        if not self.samples:
            return

        self.mean_ms = statistics.mean(self.samples)
        self.median_ms = statistics.median(self.samples)
        self.std_dev_ms = statistics.stdev(self.samples) if len(self.samples) > 1 else 0.0
        self.min_ms = min(self.samples)
        self.max_ms = max(self.samples)


@dataclass
class TimingAttackResult:
    """Timing side-channel attack result.

    Attributes:
        success: Whether timing difference was detected
        severity: Result severity
        valid_key_timing: Timing for valid key
        invalid_key_timing: Timing for invalid key
        time_difference_ms: Time difference in milliseconds
        statistically_significant: Whether difference is significant
        inferred_key_bytes: Inferred key bytes (if any)
        measurements: All timing measurements
    """

    success: bool = False
    severity: Severity = Severity.INFO
    valid_key_timing: TimingMeasurement = field(default_factory=TimingMeasurement)
    invalid_key_timing: TimingMeasurement = field(default_factory=TimingMeasurement)
    time_difference_ms: float = 0.0
    statistically_significant: bool = False
    inferred_key_bytes: List[int] = field(default_factory=list)
    measurements: List[TimingMeasurement] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary.

        Returns:
            Dictionary representation.
        """
        return {
            "success": self.success,
            "severity": self.severity.value,
            "valid_key_timing": self.valid_key_timing.to_dict(),
            "invalid_key_timing": self.invalid_key_timing.to_dict(),
            "time_difference_ms": self.time_difference_ms,
            "statistically_significant": self.statistically_significant,
            "inferred_key_bytes_length": len(self.inferred_key_bytes),
            "measurements": [m.to_dict() for m in self.measurements],
        }


@dataclass
class ErrorMessageFinding:
    """Error message analysis finding.

    Attributes:
        error_type: Type of error
        error_message: Full error message
        library_detected: Detected JWT library
        version_detected: Detected version
        severity: Finding severity
        unique_patterns: Unique patterns found
        timestamp: Analysis timestamp
    """

    error_type: str = ""
    error_message: str = ""
    library_detected: str = ""
    version_detected: str = ""
    severity: Severity = Severity.INFO
    unique_patterns: List[str] = field(default_factory=list)
    timestamp: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary.

        Returns:
            Dictionary representation.
        """
        return {
            "error_type": self.error_type,
            "error_message": self.error_message,
            "library_detected": self.library_detected,
            "version_detected": self.version_detected,
            "severity": self.severity.value,
            "unique_patterns": self.unique_patterns,
            "timestamp": self.timestamp,
        }


# =============================================================================
# Key and Credential Leak Detector
# =============================================================================

class KeyLeakDetector:
    """Detects JWT keys and credentials in proxy history and source files.

    Scans for:
    - Hardcoded JWT secrets in JavaScript files
    - JWKS private keys in responses
    - OAuth client secrets in configuration
    - Error stack traces revealing keys
    """

    SECRET_PATTERNS: List[Tuple[str, LeakType, Severity]] = [
        (r'(?:secret|jwt_secret|jwtSecret)\s*[:=]\s*["\']([^"\']{8,})["\']', LeakType.JWT_SECRET, Severity.CRITICAL),
        (r'(?:SECRET_KEY|JWT_SECRET)\s*=\s*["\']([^"\']{8,})["\']', LeakType.JWT_SECRET, Severity.CRITICAL),
        (r'"k"\s*:\s*"([^"]{50,})"', LeakType.JWKS_PRIVATE_KEY, Severity.CRITICAL),
        (r'"d"\s*:\s*"([^"]{50,})"', LeakType.JWKS_PRIVATE_KEY, Severity.CRITICAL),
        (r'(?:client_secret|clientSecret)\s*[:=]\s*["\']([^"\']{8,})["\']', LeakType.OAUTH_CLIENT_SECRET, Severity.HIGH),
        (r'(?:api_key|apiKey)\s*[:=]\s*["\']([^"\']{8,})["\']', LeakType.HARD_CODED_KEY, Severity.HIGH),
        (r'(?:password|passwd)\s*[:=]\s*["\']([^"\']{4,})["\']', LeakType.HARD_CODED_KEY, Severity.HIGH),
        (r'-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----', LeakType.JWKS_PRIVATE_KEY, Severity.CRITICAL),
        (r'-----BEGIN\s+EC\s+PRIVATE\s+KEY-----', LeakType.JWKS_PRIVATE_KEY, Severity.CRITICAL),
    ]

    ERROR_PATTERNS: List[Tuple[str, LeakType, Severity]] = [
        (r'Traceback\s+\(most\s+recent\s+call\s+last\)', LeakType.ERROR_STACK_TRACE, Severity.MEDIUM),
        (r'at\s+\w+\.\w+\s+\([^)]+:\d+:\d+\)', LeakType.ERROR_STACK_TRACE, Severity.MEDIUM),
        (r'Exception:\s+.*(?:secret|key|token)', LeakType.DEBUG_INFO, Severity.MEDIUM),
        (r'DEBUG.*(?:secret|key|token)', LeakType.DEBUG_INFO, Severity.HIGH),
    ]

    def __init__(self) -> None:
        """Initialize the key leak detector."""
        self.findings: List[LeakFinding] = []

    def scan_response_body(
        self,
        body: str,
        source_url: str = "",
        source_file: str = "",
    ) -> List[LeakFinding]:
        """Scan response body for leaked secrets.

        Args:
            body: Response body content.
            source_url: Source URL.
            source_file: Source file name.

        Returns:
            List of LeakFinding objects.
        """
        findings: List[LeakFinding] = []

        for pattern, leak_type, severity in self.SECRET_PATTERNS + self.ERROR_PATTERNS:
            matches = re.finditer(pattern, body, re.IGNORECASE | re.MULTILINE)

            for match in matches:
                line_number = body[:match.start()].count("\n") + 1
                context_start = max(0, match.start() - 50)
                context_end = min(len(body), match.end() + 50)
                context = body[context_start:context_end].replace("\n", " ")

                finding = LeakFinding(
                    leak_type=leak_type,
                    severity=severity,
                    source_url=source_url,
                    source_file=source_file,
                    leaked_value=match.group(1) if match.lastindex else match.group(0),
                    context=context,
                    line_number=line_number,
                    timestamp=time.time(),
                )

                findings.append(finding)
                self.findings.append(finding)

        return findings

    def scan_javascript_files(
        self,
        js_content: str,
        source_url: str = "",
    ) -> List[LeakFinding]:
        """Scan JavaScript files for hardcoded secrets.

        Args:
            js_content: JavaScript file content.
            source_url: Source URL.

        Returns:
            List of LeakFinding objects.
        """
        js_patterns: List[Tuple[str, LeakType, Severity]] = [
            (r'const\s+(?:SECRET|JWT_SECRET|API_KEY)\s*=\s*["\']([^"\']{8,})["\']', LeakType.JWT_SECRET, Severity.CRITICAL),
            (r'process\.env\.(?:SECRET|JWT_SECRET)\s*\|\|\s*["\']([^"\']{8,})["\']', LeakType.JWT_SECRET, Severity.HIGH),
            (r'config\.(?:secret|jwtSecret)\s*=\s*["\']([^"\']{8,})["\']', LeakType.JWT_SECRET, Severity.CRITICAL),
            (r'window\.(?:SECRET|JWT_SECRET)\s*=\s*["\']([^"\']{8,})["\']', LeakType.JWT_SECRET, Severity.CRITICAL),
        ]

        findings: List[LeakFinding] = []

        for pattern, leak_type, severity in js_patterns:
            matches = re.finditer(pattern, js_content, re.IGNORECASE)

            for match in matches:
                line_number = js_content[:match.start()].count("\n") + 1
                context_start = max(0, match.start() - 50)
                context_end = min(len(js_content), match.end() + 50)
                context = js_content[context_start:context_end].replace("\n", " ")

                finding = LeakFinding(
                    leak_type=leak_type,
                    severity=severity,
                    source_url=source_url,
                    source_file=source_url.split("/")[-1] if source_url else "",
                    leaked_value=match.group(1),
                    context=context,
                    line_number=line_number,
                    timestamp=time.time(),
                )

                findings.append(finding)
                self.findings.append(finding)

        return findings

    def scan_proxy_history(
        self,
        requests: List[Dict[str, Any]],
    ) -> List[LeakFinding]:
        """Scan proxy history for leaked secrets.

        Args:
            requests: List of proxy request/response dictionaries.

        Returns:
            List of LeakFinding objects.
        """
        findings: List[LeakFinding] = []

        for req in requests:
            url = req.get("url", "")
            response_body = req.get("response_body", "")
            response_headers = req.get("response_headers", {})

            content_type = response_headers.get("Content-Type", "")

            if "javascript" in content_type.lower():
                js_findings = self.scan_javascript_files(response_body, url)
                findings.extend(js_findings)
            else:
                body_findings = self.scan_response_body(response_body, url)
                findings.extend(body_findings)

        return findings


# =============================================================================
# Timing Side-Channel Attacker
# =============================================================================

class TimingSideChannelAttacker:
    """Timing side-channel attack engine for JWT signature verification.

    Measures response time differences between valid and invalid signatures
    to infer key information through timing analysis.
    """

    SAMPLE_COUNT = 20
    SIGNIFICANCE_THRESHOLD = 2.0

    def __init__(self, base_url: str, original_token: str) -> None:
        """Initialize the timing side-channel attacker.

        Args:
            base_url: Target base URL.
            original_token: Original JWT token for comparison.
        """
        self.base_url = base_url
        self.original_token = original_token
        self.measurements: List[TimingMeasurement] = []

    async def measure_timing_difference(
        self,
        test_url: str,
        headers: Optional[Dict[str, str]] = None,
        sample_count: int = SAMPLE_COUNT,
        timeout: int = 10,
    ) -> TimingAttackResult:
        """Measure timing difference between valid and invalid tokens.

        Args:
            test_url: URL to test.
            headers: Additional headers.
            sample_count: Number of samples to collect.
            timeout: Request timeout in seconds.

        Returns:
            TimingAttackResult with analysis.
        """
        valid_timing = await self._collect_timing_samples(
            test_url, self.original_token, headers, sample_count, timeout
        )

        invalid_token = self._create_invalid_token()
        invalid_timing = await self._collect_timing_samples(
            test_url, invalid_token, headers, sample_count, timeout
        )

        time_diff = abs(valid_timing.mean_ms - invalid_timing.mean_ms)

        pooled_std = (
            (valid_timing.std_dev_ms ** 2 + invalid_timing.std_dev_ms ** 2) ** 0.5
        )

        is_significant = False
        if pooled_std > 0:
            t_statistic = time_diff / pooled_std
            is_significant = t_statistic > self.SIGNIFICANCE_THRESHOLD

        result = TimingAttackResult(
            success=is_significant,
            severity=Severity.HIGH if is_significant else Severity.INFO,
            valid_key_timing=valid_timing,
            invalid_key_timing=invalid_timing,
            time_difference_ms=time_diff,
            statistically_significant=is_significant,
            measurements=[valid_timing, invalid_timing],
        )

        return result

    async def byte_by_byte_key_inference(
        self,
        test_url: str,
        token_prefix: str = "",
        headers: Optional[Dict[str, str]] = None,
        timeout: int = 10,
    ) -> TimingAttackResult:
        """Attempt byte-by-byte key inference through timing.

        Args:
            test_url: URL to test.
            token_prefix: Known token prefix.
            headers: Additional headers.
            timeout: Request timeout in seconds.

        Returns:
            TimingAttackResult with inferred bytes.
        """
        inferred_bytes: List[int] = []
        all_measurements: List[TimingMeasurement] = []

        for byte_position in range(32):
            best_byte = 0
            max_time = 0.0

            for test_byte in range(256):
                test_token = self._create_token_with_byte(
                    token_prefix, byte_position, test_byte
                )

                timing = await self._collect_timing_samples(
                    test_url, test_token, headers, 5, timeout
                )

                all_measurements.append(timing)

                if timing.mean_ms > max_time:
                    max_time = timing.mean_ms
                    best_byte = test_byte

            inferred_bytes.append(best_byte)

        result = TimingAttackResult(
            success=len(inferred_bytes) > 0,
            severity=Severity.CRITICAL,
            inferred_key_bytes=inferred_bytes,
            measurements=all_measurements,
        )

        return result

    async def _collect_timing_samples(
        self,
        test_url: str,
        token: str,
        headers: Optional[Dict[str, str]],
        sample_count: int,
        timeout: int,
    ) -> TimingMeasurement:
        """Collect timing samples for a given token.

        Args:
            test_url: URL to test.
            token: JWT token to test.
            headers: Additional headers.
            sample_count: Number of samples.
            timeout: Request timeout.

        Returns:
            TimingMeasurement with statistics.
        """
        samples: List[float] = []

        request_headers = {
            "Authorization": f"Bearer {token}",
            **(headers or {}),
        }

        async with aiohttp.ClientSession() as session:
            for _ in range(sample_count):
                try:
                    start_time = time.perf_counter()

                    async with session.get(
                        test_url, headers=request_headers, timeout=timeout
                    ) as response:
                        await response.text()

                    end_time = time.perf_counter()
                    elapsed_ms = (end_time - start_time) * 1000

                    samples.append(elapsed_ms)

                    await asyncio.sleep(0.1)

                except Exception as e:
                    logger.error(f"Timing sample collection failed: {e}")

        measurement = TimingMeasurement(
            test_case=token[:20] + "...",
            samples=samples,
        )
        measurement.calculate_stats()

        self.measurements.append(measurement)

        return measurement

    def _create_invalid_token(self) -> str:
        """Create an invalid JWT token for timing comparison.

        Returns:
            Invalid JWT token string.
        """
        parts = self.original_token.split(".")
        if len(parts) != 3:
            return "invalid.token.here"

        header_b64 = parts[0]
        payload_b64 = parts[1]

        invalid_signature = base64.urlsafe_b64encode(
            b"invalid_signature_data"
        ).decode().rstrip("=")

        return f"{header_b64}.{payload_b64}.{invalid_signature}"

    def _create_token_with_byte(
        self, prefix: str, position: int, byte_value: int
    ) -> str:
        """Create a token with specific byte at position.

        Args:
            prefix: Token prefix.
            position: Byte position.
            byte_value: Byte value to insert.

        Returns:
            Modified token string.
        """
        parts = self.original_token.split(".")
        if len(parts) != 3:
            return self.original_token

        signature_b64 = parts[2]
        padding = 4 - len(signature_b64) % 4
        if padding != 4:
            signature_b64 += "=" * padding

        try:
            signature_bytes = bytearray(base64.urlsafe_b64decode(signature_b64))

            if position < len(signature_bytes):
                signature_bytes[position] = byte_value

                new_signature = base64.urlsafe_b64encode(
                    bytes(signature_bytes)
                ).decode().rstrip("=")

                return f"{parts[0]}.{parts[1]}.{new_signature}"

        except Exception:
            pass

        return self.original_token


# =============================================================================
# Error Message Differential Analyzer
# =============================================================================

class ErrorMessageDifferentialAnalyzer:
    """Analyzes error message differences to fingerprint JWT libraries.

    Sends various malformed tokens and compares error responses
    to identify the JWT library and version.
    """

    ERROR_TEST_CASES: List[Tuple[str, str]] = [
        ("valid_expired", "expired_token"),
        ("invalid_signature", "tampered_signature"),
        ("invalid_format", "not_a_jwt"),
        ("missing_parts", "only_two_parts"),
        ("empty_token", "empty_string"),
        ("alg_none", "algorithm_none"),
        ("alg_invalid", "invalid_algorithm"),
    ]

    LIBRARY_SIGNATURES: Dict[str, List[str]] = {
        "PyJWT": [
            "InvalidSignatureError",
            "ExpiredSignatureError",
            "jwt.exceptions",
        ],
        "jsonwebtoken": [
            "JsonWebTokenError",
            "TokenExpiredError",
            "invalid algorithm",
        ],
        "jwt-go": [
            "token is malformed",
            "token is unverifiable",
            "token is expired",
        ],
        "jose4j": [
            "InvalidJwtException",
            "UnresolvableKeyException",
            "org.jose4j",
        ],
        "nimbus-jose": [
            "JOSEException",
            "BadJWSException",
            "com.nimbusds",
        ],
    }

    def __init__(self, base_url: str) -> None:
        """Initialize the error message analyzer.

        Args:
            base_url: Target base URL.
        """
        self.base_url = base_url
        self.findings: List[ErrorMessageFinding] = []

    async def analyze_error_messages(
        self,
        test_url: str,
        original_token: str,
        headers: Optional[Dict[str, str]] = None,
        timeout: int = 10,
    ) -> Dict[str, Any]:
        """Analyze error messages from various test cases.

        Args:
            test_url: URL to test.
            original_token: Original JWT token.
            headers: Additional headers.
            timeout: Request timeout in seconds.

        Returns:
            Dictionary with analysis results.
        """
        error_responses: Dict[str, str] = {}

        for test_case, description in self.ERROR_TEST_CASES:
            test_token = self._generate_test_token(test_case, original_token)

            request_headers = {
                "Authorization": f"Bearer {test_token}",
                **(headers or {}),
            }

            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(
                        test_url, headers=request_headers, timeout=timeout
                    ) as response:
                        body = await response.text()
                        error_responses[test_case] = body

            except Exception as e:
                logger.error(f"Error message test failed for {test_case}: {e}")
                error_responses[test_case] = f"Error: {str(e)}"

        library_votes: Dict[str, int] = {}
        unique_patterns: List[str] = []

        for test_case, response_body in error_responses.items():
            error_msg = self._extract_error_message(response_body)

            for library, signatures in self.LIBRARY_SIGNATURES.items():
                for signature in signatures:
                    if signature.lower() in response_body.lower():
                        library_votes[library] = library_votes.get(library, 0) + 1
                        if signature not in unique_patterns:
                            unique_patterns.append(signature)

            finding = ErrorMessageFinding(
                error_type=test_case,
                error_message=error_msg,
                severity=Severity.INFO,
                timestamp=time.time(),
            )
            self.findings.append(finding)

        detected_library = ""
        if library_votes:
            detected_library = max(library_votes, key=lambda k: library_votes[k])

        result = {
            "error_responses": {k: v[:500] for k, v in error_responses.items()},
            "detected_library": detected_library,
            "library_votes": library_votes,
            "unique_patterns": unique_patterns,
            "confidence": len(unique_patterns) / 5.0 if unique_patterns else 0.0,
        }

        return result

    def _generate_test_token(self, test_case: str, original_token: str) -> str:
        """Generate test token for specific test case.

        Args:
            test_case: Test case identifier.
            original_token: Original JWT token.

        Returns:
            Test token string.
        """
        if test_case == "valid_expired":
            parts = original_token.split(".")
            if len(parts) == 3:
                payload_b64 = parts[1]
                padding = 4 - len(payload_b64) % 4
                if padding != 4:
                    payload_b64 += "=" * padding

                try:
                    payload = json.loads(base64.urlsafe_b64decode(payload_b64))
                    payload["exp"] = int(time.time()) - 3600
                    payload["iat"] = int(time.time()) - 7200

                    new_payload_b64 = base64.urlsafe_b64encode(
                        json.dumps(payload).encode()
                    ).decode().rstrip("=")

                    return f"{parts[0]}.{new_payload_b64}.{parts[2]}"
                except Exception:
                    pass

        elif test_case == "invalid_signature":
            parts = original_token.split(".")
            if len(parts) == 3:
                return f"{parts[0]}.{parts[1]}.invalidsignature"

        elif test_case == "invalid_format":
            return "not_a_jwt_token"

        elif test_case == "missing_parts":
            parts = original_token.split(".")
            if len(parts) >= 2:
                return f"{parts[0]}.{parts[1]}"

        elif test_case == "empty_token":
            return ""

        elif test_case == "alg_none":
            header = {"alg": "none", "typ": "JWT"}
            payload = {"sub": "test", "iat": int(time.time())}

            header_b64 = base64.urlsafe_b64encode(
                json.dumps(header).encode()
            ).decode().rstrip("=")
            payload_b64 = base64.urlsafe_b64encode(
                json.dumps(payload).encode()
            ).decode().rstrip("=")

            return f"{header_b64}.{payload_b64}."

        elif test_case == "alg_invalid":
            header = {"alg": "invalid_alg", "typ": "JWT"}
            payload = {"sub": "test", "iat": int(time.time())}

            header_b64 = base64.urlsafe_b64encode(
                json.dumps(header).encode()
            ).decode().rstrip("=")
            payload_b64 = base64.urlsafe_b64encode(
                json.dumps(payload).encode()
            ).decode().rstrip("=")

            return f"{header_b64}.{payload_b64}.fakesig"

        return original_token

    def _extract_error_message(self, response_body: str) -> str:
        """Extract error message from response body.

        Args:
            response_body: Response body content.

        Returns:
            Extracted error message.
        """
        error_patterns = [
            r'"message"\s*:\s*"([^"]+)"',
            r'"error"\s*:\s*"([^"]+)"',
            r'"error_description"\s*:\s*"([^"]+)"',
            r"<message>([^<]+)</message>",
            r"Error[:\s]+([^\n]+)",
        ]

        for pattern in error_patterns:
            match = re.search(pattern, response_body)
            if match:
                return match.group(1)

        return response_body[:200]


# =============================================================================
# Main Information Leak Manager
# =============================================================================

class JWTInfoLeakManager:
    """Main JWT information leak coordination engine.

    Integrates key leak detection, timing side-channel attacks,
    and error message differential analysis.

    Attributes:
        base_url: Target base URL
        leak_detector: Key leak detector
        timing_attacker: Timing side-channel attacker
        error_analyzer: Error message analyzer
    """

    def __init__(self, base_url: str, original_token: str = "") -> None:
        """Initialize the JWT info leak manager.

        Args:
            base_url: Target base URL.
            original_token: Original JWT token for testing.
        """
        self.base_url = base_url
        self.original_token = original_token
        self.leak_detector = KeyLeakDetector()
        self.timing_attacker = TimingSideChannelAttacker(base_url, original_token)
        self.error_analyzer = ErrorMessageDifferentialAnalyzer(base_url)

    async def run_full_leak_analysis(
        self,
        test_url: str,
        proxy_history: Optional[List[Dict[str, Any]]] = None,
        js_files: Optional[List[Dict[str, str]]] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """Run full information leak analysis suite.

        Args:
            test_url: URL to test.
            proxy_history: Proxy history to scan.
            js_files: JavaScript files to scan.
            headers: Additional headers.

        Returns:
            Dictionary with all analysis results.
        """
        results: Dict[str, Any] = {
            "key_leaks": [],
            "timing_analysis": {},
            "error_analysis": {},
        }

        if proxy_history:
            leak_findings = self.leak_detector.scan_proxy_history(proxy_history)
            results["key_leaks"] = [f.to_dict() for f in leak_findings]

        if js_files:
            for js_file in js_files:
                content = js_file.get("content", "")
                url = js_file.get("url", "")
                js_findings = self.leak_detector.scan_javascript_files(content, url)
                results["key_leaks"].extend([f.to_dict() for f in js_findings])

        if self.original_token:
            timing_result = await self.timing_attacker.measure_timing_difference(
                test_url, headers
            )
            results["timing_analysis"] = timing_result.to_dict()

            error_result = await self.error_analyzer.analyze_error_messages(
                test_url, self.original_token, headers
            )
            results["error_analysis"] = error_result

        return results
