"""
Session & MFA Bypass Module - MFA bypass testing, token binding
tests, and session fixation exploitation.

This module provides:
    1. Multi-factor authentication (MFA) bypass testing
    2. Token binding validation testing (IP, device, platform)
    3. Session fixation and injection attacks
    4. Post-logout token invalidation testing
    5. AMR (Authentication Method References) claim analysis

Integration points:
    - JWT Editor module
    - OAuth Analyzer module
    - MITM proxy traffic capture
    - Report generation engine

Author: Kunlun Security Lab
License: Internal Use Only
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qs, urlencode, urlparse

import aiohttp

logger = logging.getLogger(__name__)


# =============================================================================
# Enums
# =============================================================================

class MFABypassType(str, Enum):
    """MFA bypass types."""

    PARTIAL_AUTH = "partial_auth"
    API_BYPASS = "api_bypass"
    AMR_TAMPERING = "amr_tampering"
    STEP_UP_BYPASS = "step_up_bypass"
    RECOVERY_BYPASS = "recovery_bypass"


class SessionAttackType(str, Enum):
    """Session attack types."""

    SESSION_FIXATION = "session_fixation"
    TOKEN_REUSE = "token_reuse"
    LOGOUT_BYPASS = "logout_bypass"
    SESSION_INJECTION = "session_injection"


class Severity(str, Enum):
    """Vulnerability severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# =============================================================================
# Data Classes
# =============================================================================

@dataclass
class MFABypassResult:
    """MFA bypass test result.

    Attributes:
        bypass_type: Type of MFA bypass tested
        success: Whether bypass was successful
        severity: Result severity
        description: Bypass description
        evidence: Evidence of bypass
        affected_resource: Resource that was accessed
        timestamp: Result timestamp
    """

    bypass_type: MFABypassType = MFABypassType.PARTIAL_AUTH
    success: bool = False
    severity: Severity = Severity.INFO
    description: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)
    affected_resource: str = ""
    timestamp: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary.

        Returns:
            Dictionary representation.
        """
        return {
            "bypass_type": self.bypass_type.value,
            "success": self.success,
            "severity": self.severity.value,
            "description": self.description,
            "evidence": self.evidence,
            "affected_resource": self.affected_resource,
            "timestamp": self.timestamp,
        }


@dataclass
class SessionAttackResult:
    """Session attack test result.

    Attributes:
        attack_type: Type of session attack
        success: Whether attack was successful
        severity: Result severity
        description: Attack description
        evidence: Evidence of attack
        token_valid_after_logout: Whether token remained valid
        timestamp: Result timestamp
    """

    attack_type: SessionAttackType = SessionAttackType.SESSION_FIXATION
    success: bool = False
    severity: Severity = Severity.INFO
    description: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)
    token_valid_after_logout: bool = False
    timestamp: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary.

        Returns:
            Dictionary representation.
        """
        return {
            "attack_type": self.attack_type.value,
            "success": self.success,
            "severity": self.severity.value,
            "description": self.description,
            "evidence": self.evidence,
            "token_valid_after_logout": self.token_valid_after_logout,
            "timestamp": self.timestamp,
        }


@dataclass
class TokenBindingResult:
    """Token binding test result.

    Attributes:
        binding_type: Type of binding tested
        is_bound: Whether token is properly bound
        bypass_possible: Whether binding can be bypassed
        severity: Result severity
        evidence: Evidence of binding status
        timestamp: Result timestamp
    """

    binding_type: str = ""
    is_bound: bool = False
    bypass_possible: bool = False
    severity: Severity = Severity.INFO
    evidence: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary.

        Returns:
            Dictionary representation.
        """
        return {
            "binding_type": self.binding_type,
            "is_bound": self.is_bound,
            "bypass_possible": self.bypass_possible,
            "severity": self.severity.value,
            "evidence": self.evidence,
            "timestamp": self.timestamp,
        }


# =============================================================================
# MFA Bypass Tester
# =============================================================================

class MFABypassTester:
    """Tests multi-factor authentication bypass vulnerabilities.

    Tests:
    - Partial authentication token usage
    - API endpoint MFA policy differences
    - AMR claim tampering
    - Step-up authentication bypass
    - Recovery code bypass
    """

    def __init__(
        self,
        base_url: str,
        first_factor_token: str = "",
        full_auth_token: str = "",
    ) -> None:
        """Initialize the MFA bypass tester.

        Args:
            base_url: Target base URL.
            first_factor_token: Token after first factor only.
            full_auth_token: Token after complete MFA.
        """
        self.base_url = base_url
        self.first_factor_token = first_factor_token
        self.full_auth_token = full_auth_token
        self.results: List[MFABypassResult] = []

    async def test_partial_auth_access(
        self,
        protected_resources: List[str],
        timeout: int = 10,
    ) -> List[MFABypassResult]:
        """Test if partial auth tokens can access protected resources.

        Args:
            protected_resources: List of protected resource URLs.
            timeout: Request timeout in seconds.

        Returns:
            List of MFABypassResult.
        """
        results: List[MFABypassResult] = []

        if not self.first_factor_token:
            return results

        for resource_url in protected_resources:
            result = MFABypassResult(
                bypass_type=MFABypassType.PARTIAL_AUTH,
                description=(
                    "使用仅完成第一因素认证的令牌访问受保护资源，"
                    "测试是否可以在未完成 MFA 的情况下访问资源。"
                ),
                affected_resource=resource_url,
                timestamp=time.time(),
            )

            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(
                        resource_url,
                        headers={
                            "Authorization": f"Bearer {self.first_factor_token}"
                        },
                        timeout=timeout,
                    ) as response:
                        body = await response.text()
                        result.evidence["status_code"] = response.status
                        result.evidence["body_preview"] = body[:500]

                        if response.status == 200:
                            result.success = True
                            result.severity = Severity.CRITICAL
                            logger.warning(
                                f"MFA bypass via partial auth: {resource_url}"
                            )

            except Exception as e:
                result.evidence["error"] = str(e)

            results.append(result)
            self.results.append(result)

        return results

    async def test_api_mfa_policy_difference(
        self,
        api_endpoints: List[str],
        timeout: int = 10,
    ) -> List[MFABypassResult]:
        """Test if API endpoints have different MFA policies.

        Args:
            api_endpoints: List of API endpoint URLs.
            timeout: Request timeout in seconds.

        Returns:
            List of MFABypassResult.
        """
        results: List[MFABypassResult] = []

        if not self.first_factor_token:
            return results

        for endpoint in api_endpoints:
            result = MFABypassResult(
                bypass_type=MFABypassType.API_BYPASS,
                description=(
                    "测试不同 API 路径的 MFA 策略配置是否一致。"
                    "某些 API 路径可能未正确配置 MFA 要求。"
                ),
                affected_resource=endpoint,
                timestamp=time.time(),
            )

            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(
                        endpoint,
                        headers={
                            "Authorization": f"Bearer {self.first_factor_token}"
                        },
                        timeout=timeout,
                    ) as response:
                        result.evidence["status_code"] = response.status

                        if response.status == 200:
                            result.success = True
                            result.severity = Severity.HIGH

            except Exception as e:
                result.evidence["error"] = str(e)

            results.append(result)
            self.results.append(result)

        return results

    async def test_amr_claim_tampering(
        self,
        resource_url: str,
        timeout: int = 10,
    ) -> MFABypassResult:
        """Test if AMR claims can be tampered with.

        Args:
            resource_url: Protected resource URL.
            timeout: Request timeout in seconds.

        Returns:
            MFABypassResult with test results.
        """
        result = MFABypassResult(
            bypass_type=MFABypassType.AMR_TAMPERING,
            description=(
                "篡改 JWT 中的 amr（Authentication Method References）声明，"
                "测试服务器是否验证该声明的真实性。"
            ),
            affected_resource=resource_url,
            timestamp=time.time(),
        )

        if not self.first_factor_token:
            result.evidence["error"] = "No first factor token available"
            return result

        try:
            parts = self.first_factor_token.split(".")
            if len(parts) != 3:
                result.evidence["error"] = "Invalid JWT format"
                return result

            payload_b64 = parts[1]
            padding = 4 - len(payload_b64) % 4
            if padding != 4:
                payload_b64 += "=" * padding

            payload = json.loads(base64.urlsafe_b64decode(payload_b64))

            original_amr = payload.get("amr", [])
            payload["amr"] = ["pwd", "mfa", "hwk", "user"]

            new_payload_b64 = base64.urlsafe_b64encode(
                json.dumps(payload).encode()
            ).decode().rstrip("=")

            tampered_token = f"{parts[0]}.{new_payload_b64}.{parts[2]}"

            async with aiohttp.ClientSession() as session:
                async with session.get(
                    resource_url,
                    headers={"Authorization": f"Bearer {tampered_token}"},
                    timeout=timeout,
                ) as response:
                    body = await response.text()
                    result.evidence["status_code"] = response.status
                    result.evidence["original_amr"] = original_amr
                    result.evidence["tampered_amr"] = payload["amr"]
                    result.evidence["body_preview"] = body[:500]

                    if response.status == 200:
                        result.success = True
                        result.severity = Severity.CRITICAL

        except Exception as e:
            result.evidence["error"] = str(e)

        self.results.append(result)
        return result

    async def test_step_up_bypass(
        self,
        sensitive_endpoint: str,
        normal_endpoint: str,
        timeout: int = 10,
    ) -> MFABypassResult:
        """Test step-up authentication bypass.

        Args:
            sensitive_endpoint: Sensitive operation endpoint.
            normal_endpoint: Normal operation endpoint.
            timeout: Request timeout in seconds.

        Returns:
            MFABypassResult with test results.
        """
        result = MFABypassResult(
            bypass_type=MFABypassType.STEP_UP_BYPASS,
            description=(
                "测试敏感操作是否需要逐步升级认证（step-up authentication）。"
                "如果普通令牌可以执行敏感操作，则存在绕过漏洞。"
            ),
            affected_resource=sensitive_endpoint,
            timestamp=time.time(),
        )

        if not self.full_auth_token:
            result.evidence["error"] = "No full auth token available"
            return result

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    sensitive_endpoint,
                    headers={
                        "Authorization": f"Bearer {self.full_auth_token}"
                    },
                    timeout=timeout,
                ) as response:
                    body = await response.text()
                    result.evidence["status_code"] = response.status
                    result.evidence["body_preview"] = body[:500]

                    if response.status == 200:
                        result.success = True
                        result.severity = Severity.HIGH

        except Exception as e:
            result.evidence["error"] = str(e)

        self.results.append(result)
        return result


# =============================================================================
# Session Fixation Tester
# =============================================================================

class SessionFixationTester:
    """Tests session fixation and token reuse vulnerabilities.

    Tests:
    - Session fixation in OAuth flow
    - Post-logout token reuse
    - Token blacklisting verification
    - Session injection attacks
    """

    def __init__(
        self,
        auth_server_url: str,
        resource_url: str,
    ) -> None:
        """Initialize the session fixation tester.

        Args:
            auth_server_url: Authorization server URL.
            resource_url: Protected resource URL.
        """
        self.auth_server_url = auth_server_url
        self.resource_url = resource_url
        self.results: List[SessionAttackResult] = []

    async def test_session_fixation(
        self,
        authorize_url: str = "",
        timeout: int = 10,
    ) -> SessionAttackResult:
        """Test session fixation in OAuth flow.

        Args:
            authorize_url: Authorization endpoint URL.
            timeout: Request timeout in seconds.

        Returns:
            SessionAttackResult with test results.
        """
        auth_url = authorize_url or f"{self.auth_server_url}/authorize"

        result = SessionAttackResult(
            attack_type=SessionAttackType.SESSION_FIXATION,
            description=(
                "在 OAuth 授权流程中注入已知的 state 或 nonce 值，"
                "测试攻击者是否可以预先获取授权码并诱使受害者使用。"
            ),
            timestamp=time.time(),
        )

        fixed_state = "attacker_controlled_state_12345"
        fixed_nonce = "attacker_controlled_nonce_67890"

        params = {
            "response_type": "code",
            "client_id": "test_client",
            "redirect_uri": "https://example.com/callback",
            "scope": "openid profile email",
            "state": fixed_state,
            "nonce": fixed_nonce,
        }

        test_url = f"{auth_url}?{urlencode(params)}"

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    test_url, timeout=timeout, allow_redirects=False
                ) as response:
                    result.evidence["status_code"] = response.status
                    result.evidence["fixed_state"] = fixed_state
                    result.evidence["fixed_nonce"] = fixed_nonce

                    if response.status in (301, 302, 303, 307, 308):
                        location = response.headers.get("Location", "")
                        if fixed_state in location:
                            result.success = True
                            result.severity = Severity.HIGH
                            result.evidence["redirect_location"] = location

        except Exception as e:
            result.evidence["error"] = str(e)

        self.results.append(result)
        return result

    async def test_post_logout_token_reuse(
        self,
        logout_url: str = "",
        access_token: str = "",
        timeout: int = 10,
    ) -> SessionAttackResult:
        """Test if tokens remain valid after logout.

        Args:
            logout_url: Logout endpoint URL.
            access_token: Access token to test.
            timeout: Request timeout in seconds.

        Returns:
            SessionAttackResult with test results.
        """
        result = SessionAttackResult(
            attack_type=SessionAttackType.LOGOUT_BYPASS,
            description=(
                "测试登出后令牌是否被服务端真正列入黑名单。"
                "如果仅依赖客户端删除令牌，攻击者仍可重用截获的令牌。"
            ),
            timestamp=time.time(),
        )

        if not access_token:
            result.evidence["error"] = "No access token provided"
            return result

        try:
            async with aiohttp.ClientSession() as session:
                response_before = await session.get(
                    self.resource_url,
                    headers={"Authorization": f"Bearer {access_token}"},
                    timeout=timeout,
                )

                result.evidence["status_before_logout"] = response_before.status

                if logout_url:
                    async with session.get(logout_url, timeout=timeout) as logout_resp:
                        result.evidence["logout_status"] = logout_resp.status

                await asyncio.sleep(2)

                response_after = await session.get(
                    self.resource_url,
                    headers={"Authorization": f"Bearer {access_token}"},
                    timeout=timeout,
                )

                result.evidence["status_after_logout"] = response_after.status

                if response_after.status == 200:
                    result.token_valid_after_logout = True
                    result.success = True
                    result.severity = Severity.CRITICAL
                    logger.warning("Token still valid after logout!")

        except Exception as e:
            result.evidence["error"] = str(e)

        self.results.append(result)
        return result

    async def test_token_reuse_across_sessions(
        self,
        access_token: str = "",
        timeout: int = 10,
    ) -> SessionAttackResult:
        """Test if tokens can be reused across different sessions.

        Args:
            access_token: Access token to test.
            timeout: Request timeout in seconds.

        Returns:
            SessionAttackResult with test results.
        """
        result = SessionAttackResult(
            attack_type=SessionAttackType.TOKEN_REUSE,
            description=(
                "测试令牌是否可在不同会话、不同 IP 或不同设备间重用。"
                "如果令牌未绑定到特定会话，攻击者可在截获后重用。"
            ),
            timestamp=time.time(),
        )

        if not access_token:
            result.evidence["error"] = "No access token provided"
            return result

        try:
            async with aiohttp.ClientSession() as session:
                headers = {
                    "Authorization": f"Bearer {access_token}",
                    "X-Forwarded-For": "192.168.1.100",
                    "User-Agent": "Mozilla/5.0 (attacker)",
                }

                async with session.get(
                    self.resource_url, headers=headers, timeout=timeout
                ) as response:
                    body = await response.text()
                    result.evidence["status_code"] = response.status
                    result.evidence["body_preview"] = body[:500]

                    if response.status == 200:
                        result.success = True
                        result.severity = Severity.HIGH

        except Exception as e:
            result.evidence["error"] = str(e)

        self.results.append(result)
        return result


# =============================================================================
# Token Binding Tester
# =============================================================================

class TokenBindingTester:
    """Tests token binding to IP, device, and platform.

    Tests:
    - IP address binding
    - Device identifier binding
    - Platform binding (mobile vs web)
    - Certificate binding (mTLS)
    """

    def __init__(
        self,
        resource_url: str,
        access_token: str,
    ) -> None:
        """Initialize the token binding tester.

        Args:
            resource_url: Protected resource URL.
            access_token: Access token to test.
        """
        self.resource_url = resource_url
        self.access_token = access_token
        self.results: List[TokenBindingResult] = []

    async def test_ip_binding(
        self,
        timeout: int = 10,
    ) -> TokenBindingResult:
        """Test if token is bound to IP address.

        Args:
            timeout: Request timeout in seconds.

        Returns:
            TokenBindingResult with test results.
        """
        result = TokenBindingResult(
            binding_type="ip_address",
            timestamp=time.time(),
        )

        test_ips = [
            "10.0.0.1",
            "192.168.1.100",
            "172.16.0.1",
            "203.0.113.1",
        ]

        bypassed = False

        try:
            async with aiohttp.ClientSession() as session:
                for ip in test_ips:
                    headers = {
                        "Authorization": f"Bearer {self.access_token}",
                        "X-Forwarded-For": ip,
                        "X-Real-IP": ip,
                    }

                    async with session.get(
                        self.resource_url, headers=headers, timeout=timeout
                    ) as response:
                        if response.status == 200:
                            bypassed = True
                            result.evidence[f"ip_{ip}"] = "accepted"

            result.is_bound = not bypassed
            result.bypass_possible = bypassed

            if bypassed:
                result.severity = Severity.HIGH

        except Exception as e:
            result.evidence["error"] = str(e)

        self.results.append(result)
        return result

    async def test_device_binding(
        self,
        timeout: int = 10,
    ) -> TokenBindingResult:
        """Test if token is bound to device identifier.

        Args:
            timeout: Request timeout in seconds.

        Returns:
            TokenBindingResult with test results.
        """
        result = TokenBindingResult(
            binding_type="device_id",
            timestamp=time.time(),
        )

        test_user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X)",
            "Mozilla/5.0 (Linux; Android 13; Pixel 7)",
            "curl/7.88.1",
        ]

        bypassed = False

        try:
            async with aiohttp.ClientSession() as session:
                for ua in test_user_agents:
                    headers = {
                        "Authorization": f"Bearer {self.access_token}",
                        "User-Agent": ua,
                    }

                    async with session.get(
                        self.resource_url, headers=headers, timeout=timeout
                    ) as response:
                        if response.status == 200:
                            bypassed = True
                            result.evidence[f"ua_{ua[:30]}"] = "accepted"

            result.is_bound = not bypassed
            result.bypass_possible = bypassed

            if bypassed:
                result.severity = Severity.MEDIUM

        except Exception as e:
            result.evidence["error"] = str(e)

        self.results.append(result)
        return result

    async def test_platform_binding(
        self,
        timeout: int = 10,
    ) -> TokenBindingResult:
        """Test if token is bound to platform (mobile vs web).

        Args:
            timeout: Request timeout in seconds.

        Returns:
            TokenBindingResult with test results.
        """
        result = TokenBindingResult(
            binding_type="platform",
            timestamp=time.time(),
        )

        platform_headers = {
            "mobile": {
                "X-Platform": "mobile",
                "X-App-Version": "2.0.0",
            },
            "web": {
                "X-Platform": "web",
                "X-App-Version": "1.0.0",
            },
            "desktop": {
                "X-Platform": "desktop",
                "X-App-Version": "3.0.0",
            },
        }

        cross_platform_access = False

        try:
            async with aiohttp.ClientSession() as session:
                for platform, headers in platform_headers.items():
                    full_headers = {
                        "Authorization": f"Bearer {self.access_token}",
                        **headers,
                    }

                    async with session.get(
                        self.resource_url,
                        headers=full_headers,
                        timeout=timeout,
                    ) as response:
                        if response.status == 200:
                            cross_platform_access = True
                            result.evidence[platform] = "accepted"

            result.is_bound = not cross_platform_access
            result.bypass_possible = cross_platform_access

            if cross_platform_access:
                result.severity = Severity.MEDIUM

        except Exception as e:
            result.evidence["error"] = str(e)

        self.results.append(result)
        return result


# =============================================================================
# Main Session & MFA Bypass Manager
# =============================================================================

class SessionMFABypassManager:
    """Main session and MFA bypass testing coordination engine.

    Integrates MFA bypass testing, session fixation testing,
    and token binding validation.

    Attributes:
        base_url: Target base URL
        auth_server_url: Authorization server URL
        resource_url: Protected resource URL
    """

    def __init__(
        self,
        base_url: str,
        auth_server_url: str = "",
        resource_url: str = "",
    ) -> None:
        """Initialize the session and MFA bypass manager.

        Args:
            base_url: Target base URL.
            auth_server_url: Authorization server URL.
            resource_url: Protected resource URL.
        """
        self.base_url = base_url
        self.auth_server_url = auth_server_url or base_url
        self.resource_url = resource_url or f"{base_url}/api/user"

    async def run_full_mfa_bypass_suite(
        self,
        first_factor_token: str = "",
        full_auth_token: str = "",
        protected_resources: Optional[List[str]] = None,
        timeout: int = 10,
    ) -> Dict[str, Any]:
        """Run full MFA bypass test suite.

        Args:
            first_factor_token: Token after first factor only.
            full_auth_token: Token after complete MFA.
            protected_resources: List of protected resource URLs.
            timeout: Request timeout in seconds.

        Returns:
            Dictionary with test results.
        """
        mfa_tester = MFABypassTester(
            self.base_url, first_factor_token, full_auth_token
        )

        default_resources = [
            f"{self.base_url}/api/user/profile",
            f"{self.base_url}/api/user/settings",
            f"{self.base_url}/api/admin/dashboard",
        ]

        resources = protected_resources or default_resources

        all_results: Dict[str, Any] = {
            "partial_auth_tests": [],
            "api_policy_tests": [],
            "amr_tampering": None,
            "step_up_bypass": None,
        }

        all_results["partial_auth_tests"] = [
            r.to_dict()
            for r in await mfa_tester.test_partial_auth_access(
                resources, timeout
            )
        ]

        all_results["api_policy_tests"] = [
            r.to_dict()
            for r in await mfa_tester.test_api_mfa_policy_difference(
                resources, timeout
            )
        ]

        amr_result = await mfa_tester.test_amr_claim_tampering(
            resources[0], timeout
        )
        all_results["amr_tampering"] = amr_result.to_dict()

        step_up_result = await mfa_tester.test_step_up_bypass(
            f"{self.base_url}/api/admin/sensitive-operation",
            resources[0],
            timeout,
        )
        all_results["step_up_bypass"] = step_up_result.to_dict()

        return all_results

    async def run_full_session_attack_suite(
        self,
        access_token: str = "",
        logout_url: str = "",
        timeout: int = 10,
    ) -> Dict[str, Any]:
        """Run full session attack test suite.

        Args:
            access_token: Access token to test.
            logout_url: Logout endpoint URL.
            timeout: Request timeout in seconds.

        Returns:
            Dictionary with test results.
        """
        session_tester = SessionFixationTester(
            self.auth_server_url, self.resource_url
        )

        all_results: Dict[str, Any] = {
            "session_fixation": None,
            "post_logout_reuse": None,
            "token_reuse": None,
        }

        fixation_result = await session_tester.test_session_fixation(timeout=timeout)
        all_results["session_fixation"] = fixation_result.to_dict()

        if access_token:
            logout_result = await session_tester.test_post_logout_token_reuse(
                logout_url, access_token, timeout
            )
            all_results["post_logout_reuse"] = logout_result.to_dict()

            reuse_result = await session_tester.test_token_reuse_across_sessions(
                access_token, timeout
            )
            all_results["token_reuse"] = reuse_result.to_dict()

        return all_results

    async def run_full_token_binding_suite(
        self,
        access_token: str = "",
        timeout: int = 10,
    ) -> Dict[str, Any]:
        """Run full token binding test suite.

        Args:
            access_token: Access token to test.
            timeout: Request timeout in seconds.

        Returns:
            Dictionary with test results.
        """
        if not access_token:
            return {"error": "No access token provided"}

        binding_tester = TokenBindingTester(self.resource_url, access_token)

        all_results: Dict[str, Any] = {
            "ip_binding": None,
            "device_binding": None,
            "platform_binding": None,
        }

        ip_result = await binding_tester.test_ip_binding(timeout)
        all_results["ip_binding"] = ip_result.to_dict()

        device_result = await binding_tester.test_device_binding(timeout)
        all_results["device_binding"] = device_result.to_dict()

        platform_result = await binding_tester.test_platform_binding(timeout)
        all_results["platform_binding"] = platform_result.to_dict()

        return all_results
