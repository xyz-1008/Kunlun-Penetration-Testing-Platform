"""
OAuth Analyzer Module - OAuth 2.0 / OpenID Connect flow identification,
attack detection, and visualization.

This module provides:
    1. OAuth flow auto-detection and visualization
    2. CSRF and state parameter analysis
    3. Redirect URI bypass testing
    4. Authorization code and token replay testing
    5. PKCE and client authentication testing
    6. Scope and access control testing

Integration points:
    - MITM proxy traffic capture
    - Fuzzer module for redirect URI testing
    - Reverse callback platform for redirect testing
    - Report module for vulnerability output

Author: Kunlun Security Lab
License: Internal Use Only
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import random
import re
import string
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Coroutine, Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

logger = logging.getLogger(__name__)


# =============================================================================
# Enums
# =============================================================================

class OAuthFlowType(str, Enum):
    """OAuth 2.0 flow types."""

    AUTHORIZATION_CODE = "authorization_code"
    IMPLICIT = "implicit"
    RESOURCE_OWNER_PASSWORD = "resource_owner_password"
    CLIENT_CREDENTIALS = "client_credentials"
    DEVICE_CODE = "device_code"
    REFRESH_TOKEN = "refresh_token"
    UNKNOWN = "unknown"


class OAuthVulnerability(str, Enum):
    """OAuth vulnerability types."""

    MISSING_STATE = "missing_state"
    WEAK_STATE = "weak_state"
    REDIRECT_URI_BYPASS = "redirect_uri_bypass"
    CODE_REPLAY = "code_replay"
    PKCE_MISSING = "pkce_missing"
    SCOPE_ESCALATION = "scope_escalation"
    TOKEN_REPLAY = "token_replay"
    RACE_CONDITION = "race_condition"
    WEAK_CLIENT_SECRET = "weak_client_secret"
    OPEN_REDIRECT = "open_redirect"


class Severity(str, Enum):
    """Vulnerability severity levels."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class OAuthStep(str, Enum):
    """OAuth flow steps."""

    AUTHORIZE_REQUEST = "authorize_request"
    AUTHORIZE_RESPONSE = "authorize_response"
    TOKEN_REQUEST = "token_request"
    TOKEN_RESPONSE = "token_response"
    RESOURCE_REQUEST = "resource_request"
    RESOURCE_RESPONSE = "resource_response"


# =============================================================================
# Data Models
# =============================================================================

@dataclass
class OAuthRequest:
    """OAuth request representation.

    Attributes:
        url: Request URL
        method: HTTP method
        headers: Request headers
        body: Request body
        params: Query parameters
        timestamp: Request timestamp
        source_request_id: Source MITM request ID
    """

    url: str = ""
    method: str = "GET"
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    params: Dict[str, str] = field(default_factory=dict)
    timestamp: float = 0.0
    source_request_id: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary.

        Returns:
            Dictionary representation.
        """
        return {
            "url": self.url,
            "method": self.method,
            "params": self.params,
            "timestamp": self.timestamp,
        }


@dataclass
class OAuthResponse:
    """OAuth response representation.

    Attributes:
        status_code: HTTP status code
        headers: Response headers
        body: Response body
        timestamp: Response timestamp
    """

    status_code: int = 0
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    timestamp: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary.

        Returns:
            Dictionary representation.
        """
        return {
            "status_code": self.status_code,
            "timestamp": self.timestamp,
        }


@dataclass
class OAuthFlow:
    """Complete OAuth flow representation.

    Attributes:
        flow_id: Unique flow identifier
        flow_type: Detected flow type
        client_id: OAuth client ID
        redirect_uri: Redirect URI
        scope: Requested scope
        state: State parameter
        code_challenge: PKCE code challenge
        code_verifier: PKCE code verifier
        authorization_code: Captured authorization code
        access_token: Captured access token
        refresh_token: Captured refresh token
        steps: Flow steps
        vulnerabilities: Detected vulnerabilities
    """

    flow_id: str = ""
    flow_type: OAuthFlowType = OAuthFlowType.UNKNOWN
    client_id: str = ""
    redirect_uri: str = ""
    scope: str = ""
    state: str = ""
    code_challenge: str = ""
    code_verifier: str = ""
    authorization_code: str = ""
    access_token: str = ""
    refresh_token: str = ""
    steps: List[Tuple[OAuthStep, OAuthRequest, Optional[OAuthResponse]]] = field(
        default_factory=list,
    )
    vulnerabilities: List["OAuthVulnerabilityFinding"] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary.

        Returns:
            Dictionary representation.
        """
        return {
            "flow_id": self.flow_id,
            "flow_type": self.flow_type.value,
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "scope": self.scope,
            "has_state": bool(self.state),
            "has_pkce": bool(self.code_challenge),
            "has_auth_code": bool(self.authorization_code),
            "has_access_token": bool(self.access_token),
            "has_refresh_token": bool(self.refresh_token),
            "step_count": len(self.steps),
            "vulnerability_count": len(self.vulnerabilities),
        }


@dataclass
class OAuthVulnerabilityFinding:
    """OAuth vulnerability finding.

    Attributes:
        vuln_id: Unique vulnerability ID
        vuln_type: Vulnerability type
        severity: Severity level
        description: Vulnerability description
        evidence: Evidence details
        mitre_id: MITRE ATT&CK technique ID
        recommendation: Remediation recommendation
        step: Flow step where found
    """

    vuln_type: OAuthVulnerability
    severity: Severity
    vuln_id: str = ""
    description: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)
    mitre_id: str = ""
    recommendation: str = ""
    step: OAuthStep = OAuthStep.AUTHORIZE_REQUEST

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary.

        Returns:
            Dictionary representation.
        """
        return {
            "vuln_id": self.vuln_id,
            "vuln_type": self.vuln_type.value,
            "severity": self.severity.value,
            "description": self.description,
            "mitre_id": self.mitre_id,
            "recommendation": self.recommendation,
            "step": self.step.value,
        }


@dataclass
class RedirectTestResult:
    """Redirect URI test result.

    Attributes:
        test_uri: Tested redirect URI
        bypass_successful: Whether bypass succeeded
        technique: Bypass technique used
        response_details: Response details
    """

    test_uri: str = ""
    bypass_successful: bool = False
    technique: str = ""
    response_details: Dict[str, Any] = field(default_factory=dict)


# =============================================================================
# OAuth Flow Detector
# =============================================================================

class OAuthFlowDetector:
    """Detects OAuth 2.0 flows from HTTP traffic.

    Analyzes URLs, parameters, and response bodies
    to identify OAuth authorization and token endpoints.

    Attributes:
        _auth_endpoint_patterns: Patterns for auth endpoints
        _token_endpoint_patterns: Patterns for token endpoints
    """

    def __init__(self) -> None:
        """Initialize the OAuthFlowDetector."""
        self._auth_endpoint_patterns = [
            "/authorize",
            "/oauth/authorize",
            "/oauth2/authorize",
            "/auth/oauth",
            "/openid/authorize",
            "/oidc/authorize",
        ]

        self._token_endpoint_patterns = [
            "/token",
            "/oauth/token",
            "/oauth2/token",
            "/auth/token",
            "/openid/token",
            "/oidc/token",
        ]

    def detect_flow_type(self, url: str, params: Dict[str, str]) -> OAuthFlowType:
        """Detect OAuth flow type from URL and parameters.

        Args:
            url: Request URL.
            params: Query parameters.

        Returns:
            Detected OAuthFlowType.
        """
        response_type = params.get("response_type", "")
        grant_type = params.get("grant_type", "")

        if response_type == "code":
            return OAuthFlowType.AUTHORIZATION_CODE
        elif response_type == "token":
            return OAuthFlowType.IMPLICIT
        elif response_type == "id_token":
            return OAuthFlowType.IMPLICIT
        elif grant_type == "password":
            return OAuthFlowType.RESOURCE_OWNER_PASSWORD
        elif grant_type == "client_credentials":
            return OAuthFlowType.CLIENT_CREDENTIALS
        elif grant_type == "refresh_token":
            return OAuthFlowType.REFRESH_TOKEN
        elif grant_type == "urn:ietf:params:oauth:grant-type:device_code":
            return OAuthFlowType.DEVICE_CODE

        if any(p in url.lower() for p in self._auth_endpoint_patterns):
            return OAuthFlowType.AUTHORIZATION_CODE
        elif any(p in url.lower() for p in self._token_endpoint_patterns):
            return OAuthFlowType.UNKNOWN

        return OAuthFlowType.UNKNOWN

    def is_oauth_request(self, url: str, params: Dict[str, str]) -> bool:
        """Check if a request is an OAuth request.

        Args:
            url: Request URL.
            params: Query parameters.

        Returns:
            True if OAuth request detected.
        """
        oauth_params = {"client_id", "response_type", "redirect_uri", "scope", "state"}
        if oauth_params.intersection(params.keys()):
            return True

        url_lower = url.lower()
        if any(p in url_lower for p in self._auth_endpoint_patterns):
            return True
        if any(p in url_lower for p in self._token_endpoint_patterns):
            return True

        return False

    def extract_oauth_params(self, url: str, params: Dict[str, str]) -> Dict[str, str]:
        """Extract OAuth parameters from request.

        Args:
            url: Request URL.
            params: Query parameters.

        Returns:
            Dictionary of OAuth parameters.
        """
        oauth_keys = {
            "client_id", "client_secret", "response_type", "redirect_uri",
            "scope", "state", "code", "code_challenge", "code_challenge_method",
            "code_verifier", "grant_type", "access_token", "refresh_token",
            "token_type", "expires_in", "id_token",
        }
        return {k: v for k, v in params.items() if k in oauth_keys}


# =============================================================================
# OAuth Vulnerability Scanner
# =============================================================================

class OAuthVulnerabilityScanner:
    """Scans OAuth flows for common vulnerabilities.

    Checks for missing state, weak PKCE, redirect URI bypass,
    code replay, scope escalation, and other issues.

    Attributes:
        _vuln_counter: Vulnerability counter for ID generation
    """

    def __init__(self) -> None:
        """Initialize the OAuthVulnerabilityScanner."""
        self._vuln_counter = 0

    def scan_flow(self, flow: OAuthFlow) -> List[OAuthVulnerabilityFinding]:
        """Scan an OAuth flow for vulnerabilities.

        Args:
            flow: OAuthFlow to scan.

        Returns:
            List of OAuthVulnerabilityFinding.
        """
        findings: List[OAuthVulnerabilityFinding] = []

        findings.extend(self._check_state_parameter(flow))
        findings.extend(self._check_pkce(flow))
        findings.extend(self._check_redirect_uri(flow))
        findings.extend(self._check_scope(flow))
        findings.extend(self._check_client_secret(flow))

        flow.vulnerabilities = findings
        return findings

    def _check_state_parameter(
        self, flow: OAuthFlow,
    ) -> List[OAuthVulnerabilityFinding]:
        """Check for state parameter issues.

        Args:
            flow: OAuthFlow to check.

        Returns:
            List of findings.
        """
        findings: List[OAuthVulnerabilityFinding] = []

        if not flow.state:
            findings.append(OAuthVulnerabilityFinding(
                vuln_id=self._next_vuln_id(),
                vuln_type=OAuthVulnerability.MISSING_STATE,
                severity=Severity.HIGH,
                description="OAuth授权请求缺少state参数，存在CSRF攻击风险",
                evidence={"client_id": flow.client_id, "redirect_uri": flow.redirect_uri},
                mitre_id="T1550.001",
                recommendation="授权请求必须包含随机且不可预测的state参数",
            ))
        elif len(flow.state) < 16:
            findings.append(OAuthVulnerabilityFinding(
                vuln_id=self._next_vuln_id(),
                vuln_type=OAuthVulnerability.WEAK_STATE,
                severity=Severity.MEDIUM,
                description="state参数长度过短，可能被预测",
                evidence={"state_length": len(flow.state)},
                mitre_id="T1550.001",
                recommendation="state参数应至少16个字符，使用加密安全的随机数生成器",
            ))
        elif not self._is_random_string(flow.state):
            findings.append(OAuthVulnerabilityFinding(
                vuln_id=self._next_vuln_id(),
                vuln_type=OAuthVulnerability.WEAK_STATE,
                severity=Severity.MEDIUM,
                description="state参数可能不是随机生成的",
                evidence={"state": flow.state},
                mitre_id="T1550.001",
                recommendation="state参数应使用加密安全的随机数生成器",
            ))

        return findings

    def _check_pkce(self, flow: OAuthFlow) -> List[OAuthVulnerabilityFinding]:
        """Check for PKCE issues.

        Args:
            flow: OAuthFlow to check.

        Returns:
            List of findings.
        """
        findings: List[OAuthVulnerabilityFinding] = []

        if flow.flow_type == OAuthFlowType.AUTHORIZATION_CODE:
            if not flow.code_challenge:
                findings.append(OAuthVulnerabilityFinding(
                    vuln_id=self._next_vuln_id(),
                    vuln_type=OAuthVulnerability.PKCE_MISSING,
                    severity=Severity.HIGH,
                    description="授权码流程未启用PKCE，存在授权码拦截攻击风险",
                    evidence={"client_id": flow.client_id},
                    mitre_id="T1550.001",
                    recommendation="公共客户端必须启用PKCE（RFC 7636）",
                ))
            elif flow.code_challenge_method and flow.code_challenge_method.upper() != "S256":
                findings.append(OAuthVulnerabilityFinding(
                    vuln_id=self._next_vuln_id(),
                    vuln_type=OAuthVulnerability.PKCE_MISSING,
                    severity=Severity.MEDIUM,
                    description="PKCE使用了弱挑战方法，建议使用S256",
                    evidence={"method": flow.code_challenge_method},
                    mitre_id="T1550.001",
                    recommendation="PKCE应使用S256挑战方法",
                ))

        return findings

    def _check_redirect_uri(
        self, flow: OAuthFlow,
    ) -> List[OAuthVulnerabilityFinding]:
        """Check for redirect URI issues.

        Args:
            flow: OAuthFlow to check.

        Returns:
            List of findings.
        """
        findings: List[OAuthVulnerabilityFinding] = []

        if not flow.redirect_uri:
            return findings

        redirect = flow.redirect_uri.lower()

        if "http://" in redirect and "localhost" not in redirect:
            findings.append(OAuthVulnerabilityFinding(
                vuln_id=self._next_vuln_id(),
                vuln_type=OAuthVulnerability.REDIRECT_URI_BYPASS,
                severity=Severity.MEDIUM,
                description="redirect_uri使用HTTP而非HTTPS，存在令牌泄露风险",
                evidence={"redirect_uri": flow.redirect_uri},
                mitre_id="T1550.001",
                recommendation="redirect_uri应使用HTTPS协议",
            ))

        if redirect.endswith("/"):
            findings.append(OAuthVulnerabilityFinding(
                vuln_id=self._next_vuln_id(),
                vuln_type=OAuthVulnerability.REDIRECT_URI_BYPASS,
                severity=Severity.LOW,
                description="redirect_uri以斜杠结尾，可能存在路径绕过风险",
                evidence={"redirect_uri": flow.redirect_uri},
                mitre_id="T1550.001",
                recommendation="redirect_uri应精确匹配，避免使用通配符",
            ))

        return findings

    def _check_scope(self, flow: OAuthFlow) -> List[OAuthVulnerabilityFinding]:
        """Check for scope issues.

        Args:
            flow: OAuthFlow to check.

        Returns:
            List of findings.
        """
        findings: List[OAuthVulnerabilityFinding] = []

        if not flow.scope:
            return findings

        scopes = flow.scope.split()
        dangerous_scopes = {"admin", "offline_access", "full_access", "root", "superuser"}

        dangerous_found = dangerous_scopes.intersection(set(scopes))
        if dangerous_found:
            findings.append(OAuthVulnerabilityFinding(
                vuln_id=self._next_vuln_id(),
                vuln_type=OAuthVulnerability.SCOPE_ESCALATION,
                severity=Severity.HIGH,
                description=f"请求包含高权限作用域: {', '.join(dangerous_found)}",
                evidence={"scopes": scopes, "dangerous": list(dangerous_found)},
                mitre_id="T1550.001",
                recommendation="限制客户端可请求的作用域范围，避免过度授权",
            ))

        return findings

    def _check_client_secret(
        self, flow: OAuthFlow,
    ) -> List[OAuthVulnerabilityFinding]:
        """Check for client secret issues.

        Args:
            flow: OAuthFlow to check.

        Returns:
            List of findings.
        """
        findings: List[OAuthVulnerabilityFinding] = []

        for step_type, req, resp in flow.steps:
            secret = req.params.get("client_secret", "") or req.body
            if "client_secret=" in req.body:
                import re as _re
                match = _re.search(r"client_secret=([^&]+)", req.body)
                if match:
                    secret = match.group(1)

            if secret and len(secret) < 16:
                findings.append(OAuthVulnerabilityFinding(
                    vuln_id=self._next_vuln_id(),
                    vuln_type=OAuthVulnerability.WEAK_CLIENT_SECRET,
                    severity=Severity.HIGH,
                    description="客户端密钥长度过短，容易被爆破",
                    evidence={"secret_length": len(secret)},
                    mitre_id="T1550.001",
                    recommendation="客户端密钥应至少32个字符，使用加密安全的随机数生成器",
                ))

        return findings

    def _is_random_string(self, s: str) -> bool:
        """Check if a string appears to be randomly generated.

        Args:
            s: String to check.

        Returns:
            True if string appears random.
        """
        if len(s) < 8:
            return False

        char_types = {"upper": 0, "lower": 0, "digit": 0, "special": 0}
        for c in s:
            if c.isupper():
                char_types["upper"] += 1
            elif c.islower():
                char_types["lower"] += 1
            elif c.isdigit():
                char_types["digit"] += 1
            else:
                char_types["special"] += 1

        non_zero = sum(1 for v in char_types.values() if v > 0)
        return non_zero >= 2

    def _next_vuln_id(self) -> str:
        """Generate next vulnerability ID.

        Returns:
            Unique vulnerability ID.
        """
        self._vuln_counter += 1
        return f"OAUTH-VULN-{self._vuln_counter:04d}"


# =============================================================================
# Redirect URI Tester
# =============================================================================

class RedirectURITester:
    """Tests redirect URI bypass techniques.

    Generates and tests various redirect URI manipulation
    techniques including path traversal, subdomain takeover,
    and open redirect chaining.

    Attributes:
        _original_uri: Original redirect URI
        _test_results: Test results
    """

    def __init__(self) -> None:
        """Initialize the RedirectURITester."""
        self._original_uri: str = ""
        self._test_results: List[RedirectTestResult] = []

    def generate_test_uris(self, original_uri: str) -> List[RedirectTestResult]:
        """Generate redirect URI test cases.

        Args:
            original_uri: Original redirect URI.

        Returns:
            List of RedirectTestResult with test URIs.
        """
        self._original_uri = original_uri
        self._test_results = []

        parsed = urlparse(original_uri)
        domain = parsed.hostname or ""
        path = parsed.path or ""
        scheme = parsed.scheme or "https"

        self._test_results.extend(self._path_traversal_tests(domain, path, scheme))
        self._test_results.extend(self._subdomain_tests(domain, path, scheme))
        self._test_results.extend(self._encoding_tests(domain, path, scheme))
        self._test_results.extend(self._parameter_pollution_tests(domain, path, scheme))

        return self._test_results

    def _path_traversal_tests(
        self, domain: str, path: str, scheme: str,
    ) -> List[RedirectTestResult]:
        """Generate path traversal test URIs.

        Args:
            domain: Target domain.
            path: Original path.
            scheme: URL scheme.

        Returns:
            List of RedirectTestResult.
        """
        results: List[RedirectTestResult] = []

        test_cases = [
            (f"{scheme}://{domain}/callback/../evil.com", "path_traversal_dotdot"),
            (f"{scheme}://{domain}/callback%2F..%2Fevil.com", "encoded_path_traversal"),
            (f"{scheme}://{domain}/callback/..\\evil.com", "backslash_traversal"),
            (f"{scheme}://{domain}//evil.com", "double_slash"),
            (f"{scheme}://{domain}/callback%00.evil.com", "null_byte"),
            (f"{scheme}://{domain}/.evil.com", "dot_prefix"),
        ]

        for uri, technique in test_cases:
            results.append(RedirectTestResult(
                test_uri=uri,
                technique=technique,
            ))

        return results

    def _subdomain_tests(
        self, domain: str, path: str, scheme: str,
    ) -> List[RedirectTestResult]:
        """Generate subdomain manipulation test URIs.

        Args:
            domain: Target domain.
            path: Original path.
            scheme: URL scheme.

        Returns:
            List of RedirectTestResult.
        """
        results: List[RedirectTestResult] = []

        parts = domain.split(".")
        if len(parts) >= 2:
            base_domain = ".".join(parts[-2:])

            test_cases = [
                (f"{scheme}://evil.{base_domain}{path}", "subdomain_prefix"),
                (f"{scheme}://{domain}.evil.com{path}", "subdomain_suffix"),
                (f"{scheme}://{domain}%2F.evil.com{path}", "subdomain_encoding"),
            ]

            for uri, technique in test_cases:
                results.append(RedirectTestResult(
                    test_uri=uri,
                    technique=technique,
                ))

        return results

    def _encoding_tests(
        self, domain: str, path: str, scheme: str,
    ) -> List[RedirectTestResult]:
        """Generate encoding-based test URIs.

        Args:
            domain: Target domain.
            path: Original path.
            scheme: URL scheme.

        Returns:
            List of RedirectTestResult.
        """
        results: List[RedirectTestResult] = []

        encoded_domain = domain.replace(".", "%2E")
        encoded_path = path.replace("/", "%2F")

        test_cases = [
            (f"{scheme}://{encoded_domain}{encoded_path}", "full_encoding"),
            (f"{scheme}://{domain}{path.replace('/', '%2f')}", "path_encoding"),
            (f"{scheme}://{domain}{path.replace('/', '/%2e%2e%2f')}", "double_encoding"),
        ]

        for uri, technique in test_cases:
            results.append(RedirectTestResult(
                test_uri=uri,
                technique=technique,
            ))

        return results

    def _parameter_pollution_tests(
        self, domain: str, path: str, scheme: str,
    ) -> List[RedirectTestResult]:
        """Generate parameter pollution test URIs.

        Args:
            domain: Target domain.
            path: Original path.
            scheme: URL scheme.

        Returns:
            List of RedirectTestResult.
        """
        results: List[RedirectTestResult] = []

        base = f"{scheme}://{domain}{path}"
        test_cases = [
            (f"{base}?redirect_uri={base}&redirect_uri=https://evil.com", "duplicate_param"),
            (f"{base}&redirect_uri=https://evil.com", "param_injection"),
            (f"{base}?redirect_uri=https://evil.com&callback={base}", "param_override"),
        ]

        for uri, technique in test_cases:
            results.append(RedirectTestResult(
                test_uri=uri,
                technique=technique,
            ))

        return results

    def get_results(self) -> List[RedirectTestResult]:
        """Get test results.

        Returns:
            List of RedirectTestResult.
        """
        return self._test_results.copy()


# =============================================================================
# Token Replay Tester
# =============================================================================

class TokenReplayTester:
    """Tests authorization code and token replay vulnerabilities.

    Tests for code replay, refresh token race conditions,
    and token reuse across clients.

    Attributes:
        _replay_results: Replay test results
    """

    def __init__(self) -> None:
        """Initialize the TokenReplayTester."""
        self._replay_results: List[Dict[str, Any]] = []

    async def test_code_replay(
        self,
        authorization_code: str,
        token_endpoint: str,
        client_id: str,
        redirect_uri: str,
        max_retries: int = 5,
    ) -> Dict[str, Any]:
        """Test authorization code replay.

        Args:
            authorization_code: Authorization code.
            token_endpoint: Token endpoint URL.
            client_id: OAuth client ID.
            redirect_uri: Redirect URI.
            max_retries: Maximum retry attempts.

        Returns:
            Dictionary with replay test results.
        """
        results: List[Dict[str, Any]] = []

        for i in range(max_retries):
            result = {
                "attempt": i + 1,
                "timestamp": time.time(),
                "code": authorization_code[:8] + "...",
            }

            try:
                import aiohttp

                async with aiohttp.ClientSession() as session:
                    async with session.post(
                        token_endpoint,
                        data={
                            "grant_type": "authorization_code",
                            "code": authorization_code,
                            "client_id": client_id,
                            "redirect_uri": redirect_uri,
                        },
                    ) as resp:
                        result["status_code"] = resp.status
                        result["response"] = await resp.text()

                        if resp.status == 200:
                            result["replay_successful"] = True
                        else:
                            result["replay_successful"] = False

            except Exception as e:
                result["error"] = str(e)
                result["replay_successful"] = False

            results.append(result)

        replay_count = sum(1 for r in results if r.get("replay_successful"))

        self._replay_results.append({
            "code": authorization_code[:8] + "...",
            "total_attempts": max_retries,
            "successful_replays": replay_count,
            "details": results,
        })

        return {
            "code": authorization_code[:8] + "...",
            "total_attempts": max_retries,
            "successful_replays": replay_count,
            "is_vulnerable": replay_count > 1,
            "details": results,
        }

    async def test_refresh_token_race(
        self,
        refresh_token: str,
        token_endpoint: str,
        client_id: str,
        concurrent_requests: int = 10,
    ) -> Dict[str, Any]:
        """Test refresh token race condition.

        Args:
            refresh_token: Refresh token.
            token_endpoint: Token endpoint URL.
            client_id: OAuth client ID.
            concurrent_requests: Number of concurrent requests.

        Returns:
            Dictionary with race condition test results.
        """
        semaphore = asyncio.Semaphore(concurrent_requests)

        async def refresh_attempt() -> Dict[str, Any]:
            async with semaphore:
                try:
                    import aiohttp

                    async with aiohttp.ClientSession() as session:
                        async with session.post(
                            token_endpoint,
                            data={
                                "grant_type": "refresh_token",
                                "refresh_token": refresh_token,
                                "client_id": client_id,
                            },
                        ) as resp:
                            return {
                                "status_code": resp.status,
                                "response": await resp.text(),
                                "success": resp.status == 200,
                            }
                except Exception as e:
                    return {"error": str(e), "success": False}

        tasks = [refresh_attempt() for _ in range(concurrent_requests)]
        results = await asyncio.gather(*tasks)

        success_count = sum(1 for r in results if r.get("success"))

        return {
            "concurrent_requests": concurrent_requests,
            "successful_refreshes": success_count,
            "is_vulnerable": success_count > 1,
            "details": results,
        }


# =============================================================================
# Scope Escalation Tester
# =============================================================================

class ScopeEscalationTester:
    """Tests OAuth scope escalation vulnerabilities.

    Attempts to add privileged scopes to requests
    and observes if the server grants elevated permissions.

    Attributes:
        _escalation_results: Escalation test results
    """

    def __init__(self) -> None:
        """Initialize the ScopeEscalationTester."""
        self._escalation_results: List[Dict[str, Any]] = []

    def generate_escalation_scopes(
        self, original_scopes: str,
    ) -> List[str]:
        """Generate scope escalation test cases.

        Args:
            original_scopes: Original scope string.

        Returns:
            List of test scope strings.
        """
        base_scopes = set(original_scopes.split()) if original_scopes else set()

        escalation_scopes = {
            "admin", "administrator", "superadmin", "root",
            "offline_access", "full_access", "read_write",
            "manage_users", "manage_groups", "manage_roles",
            "profile", "email", "phone", "address",
            "openid", "api", "api.read", "api.write",
            "user.read", "user.write", "user.delete",
        }

        test_cases: List[str] = []

        for escalation in escalation_scopes:
            combined = base_scopes | {escalation}
            test_cases.append(" ".join(sorted(combined)))

        return test_cases

    async def test_escalation(
        self,
        authorize_url: str,
        client_id: str,
        original_scope: str,
        escalation_scopes: Optional[List[str]] = None,
    ) -> List[Dict[str, Any]]:
        """Test scope escalation.

        Args:
            authorize_url: Authorization URL.
            client_id: OAuth client ID.
            original_scope: Original scope.
            escalation_scopes: Custom escalation scopes.

        Returns:
            List of test results.
        """
        if escalation_scopes is None:
            escalation_scopes = self.generate_escalation_scopes(original_scope)

        results: List[Dict[str, Any]] = []

        for test_scope in escalation_scopes:
            result = {
                "original_scope": original_scope,
                "test_scope": test_scope,
                "timestamp": time.time(),
            }

            try:
                import aiohttp

                params = {
                    "client_id": client_id,
                    "response_type": "code",
                    "scope": test_scope,
                    "redirect_uri": "http://localhost/callback",
                }

                async with aiohttp.ClientSession() as session:
                    async with session.get(
                        authorize_url,
                        params=params,
                        allow_redirects=False,
                    ) as resp:
                        result["status_code"] = resp.status
                        result["location"] = resp.headers.get("Location", "")
                        result["escalation_possible"] = resp.status in (301, 302, 303, 307, 308)

            except Exception as e:
                result["error"] = str(e)
                result["escalation_possible"] = False

            results.append(result)

        self._escalation_results.extend(results)
        return results


# =============================================================================
# OAuth Analyzer Manager
# =============================================================================

class OAuthAnalyzerManager:
    """Main OAuth analyzer coordination engine.

    Integrates flow detection, vulnerability scanning,
    redirect URI testing, and token replay testing.

    Attributes:
        _detector: OAuth flow detector
        _scanner: Vulnerability scanner
        _redirect_tester: Redirect URI tester
        _replay_tester: Token replay tester
        _scope_tester: Scope escalation tester
        _active_flows: Active OAuth flows
    """

    def __init__(self) -> None:
        """Initialize the OAuthAnalyzerManager."""
        self._detector = OAuthFlowDetector()
        self._scanner = OAuthVulnerabilityScanner()
        self._redirect_tester = RedirectURITester()
        self._replay_tester = TokenReplayTester()
        self._scope_tester = ScopeEscalationTester()
        self._active_flows: Dict[str, OAuthFlow] = {}

    def process_request(
        self,
        url: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        body: str = "",
        request_id: str = "",
    ) -> Optional[OAuthFlow]:
        """Process an HTTP request for OAuth detection.

        Args:
            url: Request URL.
            method: HTTP method.
            headers: Request headers.
            body: Request body.
            request_id: Source request ID.

        Returns:
            OAuthFlow if detected, or None.
        """
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        flat_params = {k: v[0] if v else "" for k, v in params.items()}

        if not self._detector.is_oauth_request(url, flat_params):
            return None

        flow_type = self._detector.detect_flow_type(url, flat_params)
        flow_id = hashlib.md5(f"{url}{time.time()}".encode()).hexdigest()[:12]

        flow = OAuthFlow(
            flow_id=flow_id,
            flow_type=flow_type,
            client_id=flat_params.get("client_id", ""),
            redirect_uri=flat_params.get("redirect_uri", ""),
            scope=flat_params.get("scope", ""),
            state=flat_params.get("state", ""),
            code_challenge=flat_params.get("code_challenge", ""),
            code_verifier=flat_params.get("code_verifier", ""),
        )

        request = OAuthRequest(
            url=url,
            method=method,
            headers=headers or {},
            body=body,
            params=flat_params,
            timestamp=time.time(),
            source_request_id=request_id,
        )

        if any(p in url.lower() for p in self._detector._auth_endpoint_patterns):
            flow.steps.append((OAuthStep.AUTHORIZE_REQUEST, request, None))
        elif any(p in url.lower() for p in self._detector._token_endpoint_patterns):
            flow.steps.append((OAuthStep.TOKEN_REQUEST, request, None))

        self._active_flows[flow_id] = flow

        return flow

    def process_response(
        self,
        flow_id: str,
        status_code: int,
        headers: Optional[Dict[str, str]] = None,
        body: str = "",
    ) -> Optional[OAuthFlow]:
        """Process an HTTP response for OAuth flow tracking.

        Args:
            flow_id: OAuth flow ID.
            status_code: HTTP status code.
            headers: Response headers.
            body: Response body.

        Returns:
            Updated OAuthFlow, or None.
        """
        flow = self._active_flows.get(flow_id)
        if not flow:
            return None

        response = OAuthResponse(
            status_code=status_code,
            headers=headers or {},
            body=body,
            timestamp=time.time(),
        )

        if flow.steps:
            last_step = flow.steps[-1]
            step_type, request, _ = last_step

            if step_type == OAuthStep.AUTHORIZE_REQUEST:
                flow.steps[-1] = (OAuthStep.AUTHORIZE_RESPONSE, request, response)

                auth_code = self._extract_auth_code(body, headers or {})
                if auth_code:
                    flow.authorization_code = auth_code

            elif step_type == OAuthStep.TOKEN_REQUEST:
                flow.steps[-1] = (OAuthStep.TOKEN_RESPONSE, request, response)

                tokens = self._extract_tokens(body)
                flow.access_token = tokens.get("access_token", "")
                flow.refresh_token = tokens.get("refresh_token", "")

        return flow

    def scan_flow(self, flow_id: str) -> List[OAuthVulnerabilityFinding]:
        """Scan an OAuth flow for vulnerabilities.

        Args:
            flow_id: OAuth flow ID.

        Returns:
            List of OAuthVulnerabilityFinding.
        """
        flow = self._active_flows.get(flow_id)
        if not flow:
            return []

        return self._scanner.scan_flow(flow)

    def generate_redirect_tests(self, redirect_uri: str) -> List[RedirectTestResult]:
        """Generate redirect URI test cases.

        Args:
            redirect_uri: Original redirect URI.

        Returns:
            List of RedirectTestResult.
        """
        return self._redirect_tester.generate_test_uris(redirect_uri)

    async def test_code_replay(
        self,
        authorization_code: str,
        token_endpoint: str,
        client_id: str,
        redirect_uri: str,
    ) -> Dict[str, Any]:
        """Test authorization code replay.

        Args:
            authorization_code: Authorization code.
            token_endpoint: Token endpoint URL.
            client_id: OAuth client ID.
            redirect_uri: Redirect URI.

        Returns:
            Dictionary with replay test results.
        """
        return await self._replay_tester.test_code_replay(
            authorization_code, token_endpoint, client_id, redirect_uri,
        )

    async def test_refresh_token_race(
        self,
        refresh_token: str,
        token_endpoint: str,
        client_id: str,
    ) -> Dict[str, Any]:
        """Test refresh token race condition.

        Args:
            refresh_token: Refresh token.
            token_endpoint: Token endpoint URL.
            client_id: OAuth client ID.

        Returns:
            Dictionary with race condition test results.
        """
        return await self._replay_tester.test_refresh_token_race(
            refresh_token, token_endpoint, client_id,
        )

    def generate_escalation_scopes(self, original_scope: str) -> List[str]:
        """Generate scope escalationation test cases.

        Args:
            original_scope: Original scope.

        Returns:
            List of test scope strings.
        """
        return self._scope_tester.generate_escalation_scopes(original_scope)

    async def test_scope_escalation(
        self,
        authorize_url: str,
        client_id: str,
        original_scope: str,
    ) -> List[Dict[str, Any]]:
        """Test scope escalation.

        Args:
            authorize_url: Authorization URL.
            client_id: OAuth client ID.
            original_scope: Original scope.

        Returns:
            List of test results.
        """
        return await self._scope_tester.test_escalation(
            authorize_url, client_id, original_scope,
        )

    def get_active_flows(self) -> Dict[str, OAuthFlow]:
        """Get all active flows.

        Returns:
            Dictionary of active OAuthFlow.
        """
        return self._active_flows.copy()

    def get_flow(self, flow_id: str) -> Optional[OAuthFlow]:
        """Get a specific flow.

        Args:
            flow_id: Flow ID.

        Returns:
            OAuthFlow, or None.
        """
        return self._active_flows.get(flow_id)

    def _extract_auth_code(
        self, body: str, headers: Dict[str, str],
    ) -> str:
        """Extract authorization code from response.

        Args:
            body: Response body.
            headers: Response headers.

        Returns:
            Authorization code, or empty string.
        """
        location = headers.get("Location", "")
        if "code=" in location:
            parsed = urlparse(location)
            params = parse_qs(parsed.query)
            return params.get("code", [""])[0]

        import re as _re
        match = _re.search(r'"code"\s*:\s*"([^"]+)"', body)
        if match:
            return match.group(1)

        match = _re.search(r"code=([^&]+)", body)
        if match:
            return match.group(1)

        return ""

    def _extract_tokens(self, body: str) -> Dict[str, str]:
        """Extract tokens from response body.

        Args:
            body: Response body.

        Returns:
            Dictionary of tokens.
        """
        tokens: Dict[str, str] = {}

        try:
            import json
            data = json.loads(body)
            tokens["access_token"] = data.get("access_token", "")
            tokens["refresh_token"] = data.get("refresh_token", "")
            tokens["id_token"] = data.get("id_token", "")
            tokens["token_type"] = data.get("token_type", "")
        except Exception:
            import re as _re
            for key in ("access_token", "refresh_token", "id_token"):
                match = _re.search(rf'"{key}"\s*:\s*"([^"]+)"', body)
                if match:
                    tokens[key] = match.group(1)

        return tokens

    def generate_timeline(self, flow_id: str) -> List[Dict[str, Any]]:
        """Generate OAuth flow timeline.

        Args:
            flow_id: Flow ID.

        Returns:
            List of timeline entries.
        """
        flow = self._active_flows.get(flow_id)
        if not flow:
            return []

        timeline: List[Dict[str, Any]] = []

        for step_type, request, response in flow.steps:
            entry: Dict[str, Any] = {
                "step": step_type.value,
                "url": request.url,
                "method": request.method,
                "timestamp": request.timestamp,
            }
            if response:
                entry["status_code"] = response.status_code
                entry["response_timestamp"] = response.timestamp

            timeline.append(entry)

        return timeline

    def get_status(self) -> Dict[str, Any]:
        """Get analyzer status.

        Returns:
            Dictionary with status summary.
        """
        vuln_count = sum(len(f.vulnerabilities) for f in self._active_flows.values())

        return {
            "active_flows": len(self._active_flows),
            "total_vulnerabilities": vuln_count,
            "flow_types": {
                ft.value: sum(1 for f in self._active_flows.values() if f.flow_type == ft)
                for ft in OAuthFlowType
            },
        }


# =============================================================================
# Global Singleton
# =============================================================================

_oauth_analyzer_manager: Optional[OAuthAnalyzerManager] = None


def get_oauth_analyzer_manager() -> OAuthAnalyzerManager:
    """Get the global OAuthAnalyzerManager singleton.

    Returns:
        Singleton OAuthAnalyzerManager instance.
    """
    global _oauth_analyzer_manager
    if _oauth_analyzer_manager is None:
        _oauth_analyzer_manager = OAuthAnalyzerManager()
    return _oauth_analyzer_manager


__all__ = [
    "OAuthAnalyzerManager",
    "OAuthFlowDetector",
    "OAuthVulnerabilityScanner",
    "RedirectURITester",
    "TokenReplayTester",
    "ScopeEscalationTester",
    "OAuthFlow",
    "OAuthRequest",
    "OAuthResponse",
    "OAuthVulnerabilityFinding",
    "RedirectTestResult",
    "OAuthFlowType",
    "OAuthVulnerability",
    "OAuthStep",
    "Severity",
    "get_oauth_analyzer_manager",
]
