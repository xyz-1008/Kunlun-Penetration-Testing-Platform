"""
OIDC Analyzer Module - ID Token tampering, UserInfo leakage, OIDC Discovery security.

This module provides:
    1. ID Token tampering and claim manipulation
    2. UserInfo endpoint information leakage detection
    3. OIDC Discovery endpoint security analysis
    4. OIDC configuration comparison and anomaly detection

Integration points:
    - MITM proxy traffic capture
    - JWT Editor module
    - OAuth Analyzer module
    - Report generation engine

Author: Kunlun Security Lab
License: Internal Use Only
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


# =============================================================================
# Enums
# =============================================================================

class OIDCTestType(str, Enum):
    """OIDC test types."""

    ID_TOKEN_TAMPERING = "id_token_tampering"
    USERINFO_LEAKAGE = "userinfo_leakage"
    DISCOVERY_SECURITY = "discovery_security"
    CONFIG_ANOMALY = "config_anomaly"
    CLAIM_VALIDATION = "claim_validation"


class OIDCSecurityLevel(str, Enum):
    """OIDC security levels."""

    SECURE = "secure"
    WEAK = "weak"
    VULNERABLE = "vulnerable"
    UNKNOWN = "unknown"


# =============================================================================
# Data Classes
# =============================================================================

@dataclass
class IDTokenClaim:
    """ID Token claim representation.

    Attributes:
        name: Claim name
        value: Claim value
        is_standard: Whether it's a standard OIDC claim
        is_sensitive: Whether the claim is sensitive
        tamper_result: Result after tampering
    """

    name: str = ""
    value: Any = None
    is_standard: bool = False
    is_sensitive: bool = False
    tamper_result: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary.

        Returns:
            Dictionary representation.
        """
        return {
            "name": self.name,
            "value": self.value,
            "is_standard": self.is_standard,
            "is_sensitive": self.is_sensitive,
            "tamper_result": self.tamper_result,
        }


@dataclass
class IDTokenTamperResult:
    """ID Token tampering test result.

    Attributes:
        test_id: Unique test ID
        original_token: Original ID token
        tampered_token: Tampered ID token
        modified_claims: Claims that were modified
        server_accepted: Whether server accepted tampered token
        severity: Finding severity
        description: Test description
        recommendation: Remediation recommendation
    """

    test_id: str = ""
    original_token: str = ""
    tampered_token: str = ""
    modified_claims: Dict[str, Any] = field(default_factory=dict)
    server_accepted: bool = False
    severity: str = "low"
    description: str = ""
    recommendation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary.

        Returns:
            Dictionary representation.
        """
        return {
            "test_id": self.test_id,
            "original_token": self.original_token[:50] + "..." if len(self.original_token) > 50 else self.original_token,
            "tampered_token": self.tampered_token[:50] + "..." if len(self.tampered_token) > 50 else self.tampered_token,
            "modified_claims": self.modified_claims,
            "server_accepted": self.server_accepted,
            "severity": self.severity,
            "description": self.description,
            "recommendation": self.recommendation,
        }


@dataclass
class UserInfoFinding:
    """UserInfo endpoint information leakage finding.

    Attributes:
        finding_id: Unique finding ID
        test_type: Test type performed
        returned_claims: Claims returned by UserInfo
        excessive_claims: Claims beyond necessary scope
        cross_user_access: Whether cross-user access was possible
        severity: Finding severity
        description: Finding description
        recommendation: Remediation recommendation
    """

    finding_id: str = ""
    test_type: OIDCTestType = OIDCTestType.USERINFO_LEAKAGE
    returned_claims: List[str] = field(default_factory=list)
    excessive_claims: List[str] = field(default_factory=list)
    cross_user_access: bool = False
    severity: str = "low"
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
            "returned_claims": self.returned_claims,
            "excessive_claims": self.excessive_claims,
            "cross_user_access": self.cross_user_access,
            "severity": self.severity,
            "description": self.description,
            "recommendation": self.recommendation,
        }


@dataclass
class OIDCDiscoveryFinding:
    """OIDC Discovery endpoint security finding.

    Attributes:
        finding_id: Unique finding ID
        test_type: Test type performed
        discovery_url: OIDC Discovery URL
        uses_http: Whether HTTP is used instead of HTTPS
        supports_none_alg: Whether none algorithm is supported
        exposes_internal_endpoints: Whether internal endpoints are exposed
        supported_algorithms: List of supported algorithms
        security_level: Overall security level
        anomalies: Detected anomalies
        severity: Finding severity
        description: Finding description
        recommendation: Remediation recommendation
    """

    finding_id: str = ""
    test_type: OIDCTestType = OIDCTestType.DISCOVERY_SECURITY
    discovery_url: str = ""
    uses_http: bool = False
    supports_none_alg: bool = False
    exposes_internal_endpoints: bool = False
    supported_algorithms: List[str] = field(default_factory=list)
    security_level: OIDCSecurityLevel = OIDCSecurityLevel.UNKNOWN
    anomalies: List[str] = field(default_factory=list)
    severity: str = "low"
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
            "discovery_url": self.discovery_url,
            "uses_http": self.uses_http,
            "supports_none_alg": self.supports_none_alg,
            "exposes_internal_endpoints": self.exposes_internal_endpoints,
            "supported_algorithms": self.supported_algorithms,
            "security_level": self.security_level.value,
            "anomalies": self.anomalies,
            "severity": self.severity,
            "description": self.description,
            "recommendation": self.recommendation,
        }


# =============================================================================
# ID Token Tampering Tester
# =============================================================================

class IDTokenTamperTester:
    """Tests ID Token tampering vulnerabilities.

    Extracts ID Tokens from OIDC flows, decodes claims,
    and tests whether modified tokens are accepted.

    Attributes:
        _results: Tampering test results
        _result_counter: Result counter
    """

    STANDARD_CLAIMS = {
        "sub", "iss", "aud", "exp", "nbf", "iat", "auth_time",
        "nonce", "acr", "amr", "azp", "at_hash", "c_hash",
        "name", "given_name", "family_name", "middle_name",
        "nickname", "preferred_username", "profile", "picture",
        "website", "email", "email_verified", "gender",
        "birthdate", "zoneinfo", "locale", "phone_number",
        "phone_number_verified", "address", "updated_at",
    }

    SENSITIVE_CLAIMS = {
        "sub", "email", "email_verified", "phone_number",
        "phone_number_verified", "role", "admin", "scope",
    }

    def __init__(self) -> None:
        """Initialize the IDTokenTamperTester."""
        self._results: List[IDTokenTamperResult] = []
        self._result_counter = 0

    def decode_id_token(self, token: str) -> Dict[str, Any]:
        """Decode an ID Token and extract claims.

        Args:
            token: ID Token to decode.

        Returns:
            Dictionary of claims.
        """
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return {}

            payload_json = self._base64url_decode(parts[1])
            return json.loads(payload_json)
        except Exception as e:
            logger.error(f"Failed to decode ID token: {e}")
            return {}

    def extract_claims(self, token: str) -> List[IDTokenClaim]:
        """Extract claims from an ID Token.

        Args:
            token: ID Token to extract from.

        Returns:
            List of IDTokenClaim objects.
        """
        claims_dict = self.decode_id_token(token)
        claims: List[IDTokenClaim] = []

        for name, value in claims_dict.items():
            claim = IDTokenClaim(
                name=name,
                value=value,
                is_standard=name in self.STANDARD_CLAIMS,
                is_sensitive=name in self.SENSITIVE_CLAIMS,
            )
            claims.append(claim)

        return claims

    async def test_claim_tampering(
        self,
        id_token: str,
        resource_url: str,
        claim_modifications: Dict[str, Any],
        headers_template: Optional[Dict[str, str]] = None,
    ) -> IDTokenTamperResult:
        """Test if modified ID Token claims are accepted by the server.

        Args:
            id_token: Original ID Token.
            resource_url: Resource URL to test against.
            claim_modifications: Claims to modify.
            headers_template: Base headers template.

        Returns:
            IDTokenTamperResult with test results.
        """
        self._result_counter += 1
        result = IDTokenTamperResult(
            test_id=f"ID-TOKEN-TAMPER-{self._result_counter:04d}",
            original_token=id_token,
            modified_claims=claim_modifications,
        )

        tampered_token = self._tamper_id_token(id_token, claim_modifications)
        result.tampered_token = tampered_token

        if not tampered_token:
            result.severity = "low"
            result.description = "ID Token篡改失败，无法构造有效令牌。"
            result.recommendation = ""
            self._results.append(result)
            return result

        accepted = await self._test_token_acceptance(
            token=tampered_token,
            resource_url=resource_url,
            headers=headers_template,
        )

        result.server_accepted = accepted

        if accepted:
            result.severity = "critical"
            result.description = (
                f"服务器接受了篡改后的ID Token，修改的声明: {', '.join(claim_modifications.keys())}。"
                f"资源服务器未正确验证ID Token的完整性。"
            )
            result.recommendation = (
                "资源服务器必须验证ID Token的签名和完整性，"
                "不能仅依赖令牌中的声明而不进行独立校验。"
            )
        else:
            result.severity = "low"
            result.description = "服务器正确拒绝了篡改后的ID Token。"
            result.recommendation = ""

        self._results.append(result)
        return result

    def _tamper_id_token(
        self, token: str, modifications: Dict[str, Any],
    ) -> Optional[str]:
        """Tamper with ID Token claims.

        Args:
            token: Original ID Token.
            modifications: Claims to modify.

        Returns:
            Tampered ID Token, or None.
        """
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return None

            payload_json = self._base64url_decode(parts[1])
            payload = json.loads(payload_json)

            payload.update(modifications)

            new_payload_json = json.dumps(payload)
            new_payload_b64 = self._base64url_encode(new_payload_json)

            return f"{parts[0]}.{new_payload_b64}.{parts[2]}"
        except Exception as e:
            logger.error(f"Failed to tamper ID token: {e}")
            return None

    async def _test_token_acceptance(
        self,
        token: str,
        resource_url: str,
        headers: Optional[Dict[str, str]] = None,
    ) -> bool:
        """Test if a tampered token is accepted by the server.

        Args:
            token: Token to test.
            resource_url: Resource URL.
            headers: Base headers.

        Returns:
            True if token is accepted.
        """
        try:
            import aiohttp

            request_headers = headers.copy() if headers else {}
            request_headers["Authorization"] = f"Bearer {token}"

            async with aiohttp.ClientSession() as session:
                async with session.get(
                    resource_url,
                    headers=request_headers,
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as resp:
                    return resp.status == 200
        except Exception as e:
            logger.error(f"Token acceptance test failed: {e}")
            return False

    def _base64url_decode(self, data: str) -> str:
        """Decode base64url-encoded data.

        Args:
            data: Base64url-encoded string.

        Returns:
            Decoded string.
        """
        padding = 4 - len(data) % 4
        if padding != 4:
            data += "=" * padding
        return base64.urlsafe_b64decode(data).decode("utf-8")

    def _base64url_encode(self, data: str) -> str:
        """Encode data to base64url.

        Args:
            data: String to encode.

        Returns:
            Base64url-encoded string.
        """
        return base64.urlsafe_b64encode(data.encode("utf-8")).rstrip(b"=").decode("utf-8")

    def get_results(self) -> List[IDTokenTamperResult]:
        """Get all tampering test results.

        Returns:
            List of IDTokenTamperResult.
        """
        return self._results.copy()


# =============================================================================
# UserInfo Endpoint Leakage Tester
# =============================================================================

class UserInfoLeakageTester:
    """Tests UserInfo endpoint for information leakage.

    Checks whether the endpoint returns excessive data
    or allows cross-user access with modified tokens.

    Attributes:
        _findings: Test findings
        _finding_counter: Finding counter
    """

    NECESSARY_CLAIMS_BY_SCOPE = {
        "profile": {"name", "given_name", "family_name", "nickname", "preferred_username", "profile", "picture", "website", "gender", "birthdate", "zoneinfo", "locale", "updated_at"},
        "email": {"email", "email_verified"},
        "phone": {"phone_number", "phone_number_verified"},
        "address": {"address"},
    }

    def __init__(self) -> None:
        """Initialize the UserInfoLeakageTester."""
        self._findings: List[UserInfoFinding] = []
        self._finding_counter = 0

    async def test_userinfo_leakage(
        self,
        userinfo_endpoint: str,
        access_token: str,
        requested_scopes: Optional[List[str]] = None,
    ) -> UserInfoFinding:
        """Test UserInfo endpoint for information leakage.

        Args:
            userinfo_endpoint: UserInfo endpoint URL.
            access_token: Access token to use.
            requested_scopes: Scopes that were requested.

        Returns:
            UserInfoFinding with test results.
        """
        self._finding_counter += 1
        finding = UserInfoFinding(
            finding_id=f"USERINFO-LEAK-{self._finding_counter:04d}",
            test_type=OIDCTestType.USERINFO_LEAKAGE,
        )

        userinfo_data = await self._fetch_userinfo(
            userinfo_endpoint=userinfo_endpoint,
            access_token=access_token,
        )

        if not userinfo_data:
            finding.severity = "low"
            finding.description = "无法访问UserInfo端点。"
            finding.recommendation = ""
            self._findings.append(finding)
            return finding

        returned_claims = list(userinfo_data.keys())
        finding.returned_claims = returned_claims

        excessive = self._find_excessive_claims(
            returned_claims=returned_claims,
            requested_scopes=requested_scopes or [],
        )
        finding.excessive_claims = excessive

        if excessive:
            finding.severity = "medium"
            finding.description = (
                f"UserInfo端点返回了超出请求范围的声明: {', '.join(excessive)}。"
                f"应遵循最小权限原则，只返回必要的用户信息。"
            )
            finding.recommendation = (
                "UserInfo端点应只返回与请求scope对应的声明，"
                "避免返回超出授权范围的用户信息。"
            )
        else:
            finding.severity = "low"
            finding.description = "UserInfo端点返回的声明与请求scope匹配。"
            finding.recommendation = ""

        self._findings.append(finding)
        return finding

    async def test_cross_user_access(
        self,
        userinfo_endpoint: str,
        access_token: str,
        target_user_sub: str = "",
    ) -> UserInfoFinding:
        """Test if access token can access other users' UserInfo.

        Args:
            userinfo_endpoint: UserInfo endpoint URL.
            access_token: Access token to use.
            target_user_sub: Target user's sub claim.

        Returns:
            UserInfoFinding with test results.
        """
        self._finding_counter += 1
        finding = UserInfoFinding(
            finding_id=f"USERINFO-CROSS-{self._finding_counter:04d}",
            test_type=OIDCTestType.USERINFO_LEAKAGE,
        )

        userinfo_data = await self._fetch_userinfo(
            userinfo_endpoint=userinfo_endpoint,
            access_token=access_token,
        )

        if not userinfo_data:
            finding.severity = "low"
            finding.description = "无法访问UserInfo端点。"
            finding.recommendation = ""
            self._findings.append(finding)
            return finding

        returned_sub = userinfo_data.get("sub", "")

        if target_user_sub and returned_sub == target_user_sub:
            finding.cross_user_access = True
            finding.severity = "critical"
            finding.description = (
                f"Access Token可以访问其他用户（sub={target_user_sub}）的UserInfo。"
                f"存在严重的越权访问漏洞。"
            )
            finding.recommendation = (
                "UserInfo端点必须严格验证Access Token与用户身份的绑定，"
                "确保令牌只能访问对应令牌所有者的信息。"
            )
        else:
            finding.severity = "low"
            finding.description = "Access Token正确绑定到令牌所有者，无法跨用户访问。"
            finding.recommendation = ""

        self._findings.append(finding)
        return finding

    async def _fetch_userinfo(
        self,
        userinfo_endpoint: str,
        access_token: str,
    ) -> Optional[Dict[str, Any]]:
        """Fetch UserInfo from the endpoint.

        Args:
            userinfo_endpoint: UserInfo endpoint URL.
            access_token: Access token to use.

        Returns:
            UserInfo data dictionary, or None.
        """
        try:
            import aiohttp

            headers = {"Authorization": f"Bearer {access_token}"}

            async with aiohttp.ClientSession() as session:
                async with session.get(
                    userinfo_endpoint,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as resp:
                    if resp.status == 200:
                        return await resp.json()
                    return None
        except Exception as e:
            logger.error(f"Failed to fetch UserInfo: {e}")
            return None

    def _find_excessive_claims(
        self,
        returned_claims: List[str],
        requested_scopes: List[str],
    ) -> List[str]:
        """Find claims that exceed the requested scopes.

        Args:
            returned_claims: Claims returned by UserInfo.
            requested_scopes: Scopes that were requested.

        Returns:
            List of excessive claims.
        """
        allowed_claims: Set[str] = {"sub", "iss", "aud", "exp", "iat"}

        for scope in requested_scopes:
            if scope in self.NECESSARY_CLAIMS_BY_SCOPE:
                allowed_claims.update(self.NECESSARY_CLAIMS_BY_SCOPE[scope])

        excessive = []
        for claim in returned_claims:
            if claim not in allowed_claims:
                excessive.append(claim)

        return excessive

    def get_findings(self) -> List[UserInfoFinding]:
        """Get all UserInfo leakage findings.

        Returns:
            List of UserInfoFinding.
        """
        return self._findings.copy()


# =============================================================================
# OIDC Discovery Security Tester
# =============================================================================

class OIDCDiscoverySecurityTester:
    """Tests OIDC Discovery endpoint for security issues.

    Analyzes the configuration returned by the discovery endpoint
    for security risks and anomalies.

    Attributes:
        _findings: Test findings
        _finding_counter: Finding counter
    """

    def __init__(self) -> None:
        """Initialize the OIDCDiscoverySecurityTester."""
        self._findings: List[OIDCDiscoveryFinding] = []
        self._finding_counter = 0

    async def test_discovery_security(
        self,
        issuer_url: str,
    ) -> OIDCDiscoveryFinding:
        """Test OIDC Discovery endpoint security.

        Args:
            issuer_url: OIDC issuer URL.

        Returns:
            OIDCDiscoveryFinding with test results.
        """
        self._finding_counter += 1
        finding = OIDCDiscoveryFinding(
            finding_id=f"OIDC-DISCOVERY-{self._finding_counter:04d}",
            test_type=OIDCTestType.DISCOVERY_SECURITY,
        )

        discovery_url = self._build_discovery_url(issuer_url)
        finding.discovery_url = discovery_url

        config = await self._fetch_discovery_config(discovery_url)

        if not config:
            finding.severity = "low"
            finding.description = "无法获取OIDC Discovery配置。"
            finding.recommendation = ""
            finding.security_level = OIDCSecurityLevel.UNKNOWN
            self._findings.append(finding)
            return finding

        anomalies: List[str] = []

        uses_http = self._check_http_usage(config)
        finding.uses_http = uses_http
        if uses_http:
            anomalies.append("使用HTTP而非HTTPS，存在配置泄露风险")

        supports_none = self._check_none_algorithm(config)
        finding.supports_none_alg = supports_none
        if supports_none:
            anomalies.append("支持none算法，存在JWT签名绕过风险")

        exposes_internal = self._check_internal_endpoints(config)
        finding.exposes_internal_endpoints = exposes_internal
        if exposes_internal:
            anomalies.append("暴露了内部端点地址，可能泄露内部架构")

        finding.supported_algorithms = config.get("id_token_signing_alg_values_supported", [])
        finding.anomalies = anomalies

        if len(anomalies) >= 2:
            finding.security_level = OIDCSecurityLevel.VULNERABLE
            finding.severity = "high"
        elif len(anomalies) == 1:
            finding.security_level = OIDCSecurityLevel.WEAK
            finding.severity = "medium"
        else:
            finding.security_level = OIDCSecurityLevel.SECURE
            finding.severity = "low"

        if anomalies:
            finding.description = (
                f"OIDC Discovery配置存在{len(anomalies)}个安全问题: "
                + "; ".join(anomalies)
            )
            finding.recommendation = (
                "使用HTTPS协议，禁用none算法，"
                "避免在配置中暴露内部端点地址。"
            )
        else:
            finding.description = "OIDC Discovery配置安全，未检测到明显问题。"
            finding.recommendation = ""

        self._findings.append(finding)
        return finding

    def _build_discovery_url(self, issuer_url: str) -> str:
        """Build OIDC Discovery URL from issuer.

        Args:
            issuer_url: Issuer URL.

        Returns:
            Discovery URL.
        """
        if issuer_url.endswith("/"):
            issuer_url = issuer_url[:-1]

        return f"{issuer_url}/.well-known/openid-configuration"

    async def _fetch_discovery_config(
        self, discovery_url: str,
    ) -> Optional[Dict[str, Any]]:
        """Fetch OIDC Discovery configuration.

        Args:
            discovery_url: Discovery URL.

        Returns:
            Configuration dictionary, or None.
        """
        try:
            import aiohttp

            async with aiohttp.ClientSession() as session:
                async with session.get(
                    discovery_url,
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as resp:
                    if resp.status == 200:
                        return await resp.json()
                    return None
        except Exception as e:
            logger.error(f"Failed to fetch discovery config: {e}")
            return None

    def _check_http_usage(self, config: Dict[str, Any]) -> bool:
        """Check if configuration uses HTTP instead of HTTPS.

        Args:
            config: Discovery configuration.

        Returns:
            True if HTTP is used.
        """
        http_fields = [
            "issuer", "authorization_endpoint", "token_endpoint",
            "userinfo_endpoint", "jwks_uri", "registration_endpoint",
        ]

        for field in http_fields:
            value = config.get(field, "")
            if value and value.startswith("http://"):
                return True

        return False

    def _check_none_algorithm(self, config: Dict[str, Any]) -> bool:
        """Check if none algorithm is supported.

        Args:
            config: Discovery configuration.

        Returns:
            True if none algorithm is supported.
        """
        algorithms = config.get("id_token_signing_alg_values_supported", [])
        return "none" in algorithms

    def _check_internal_endpoints(self, config: Dict[str, Any]) -> bool:
        """Check if internal endpoints are exposed.

        Args:
            config: Discovery configuration.

        Returns:
            True if internal endpoints are exposed.
        """
        internal_indicators = [
            "localhost", "127.0.0.1", "192.168.", "10.",
            "172.16.", "172.17.", "172.18.", "172.19.",
            "172.20.", "172.21.", "172.22.", "172.23.",
            "172.24.", "172.25.", "172.26.", "172.27.",
            "172.28.", "172.29.", "172.30.", "172.31.",
            "internal", "private", "intranet",
        ]

        all_values = json.dumps(config).lower()

        return any(indicator in all_values for indicator in internal_indicators)

    def get_findings(self) -> List[OIDCDiscoveryFinding]:
        """Get all discovery security findings.

        Returns:
            List of OIDCDiscoveryFinding.
        """
        return self._findings.copy()


# =============================================================================
# Main OIDC Analyzer Manager
# =============================================================================

class OIDCAnalyzerManager:
    """Main OIDC analyzer coordination engine.

    Integrates ID Token tampering, UserInfo leakage detection,
    and OIDC Discovery security testing.

    Attributes:
        _id_token_tester: ID Token tamper tester
        _userinfo_tester: UserInfo leakage tester
        _discovery_tester: OIDC Discovery security tester
    """

    def __init__(self) -> None:
        """Initialize the OIDCAnalyzerManager."""
        self._id_token_tester = IDTokenTamperTester()
        self._userinfo_tester = UserInfoLeakageTester()
        self._discovery_tester = OIDCDiscoverySecurityTester()

    @property
    def id_token(self) -> IDTokenTamperTester:
        """Get ID Token tester.

        Returns:
            IDTokenTamperTester instance.
        """
        return self._id_token_tester

    @property
    def userinfo(self) -> UserInfoLeakageTester:
        """Get UserInfo tester.

        Returns:
            UserInfoLeakageTester instance.
        """
        return self._userinfo_tester

    @property
    def discovery(self) -> OIDCDiscoverySecurityTester:
        """Get Discovery tester.

        Returns:
            OIDCDiscoverySecurityTester instance.
        """
        return self._discovery_tester

    async def run_full_oidc_suite(
        self,
        id_token: str = "",
        access_token: str = "",
        issuer_url: str = "",
        userinfo_endpoint: str = "",
        resource_url: str = "",
        requested_scopes: Optional[List[str]] = None,
        claim_modifications: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Run the full OIDC test suite.

        Args:
            id_token: ID Token to test.
            access_token: Access token to use.
            issuer_url: OIDC issuer URL.
            userinfo_endpoint: UserInfo endpoint URL.
            resource_url: Resource URL for token testing.
            requested_scopes: Scopes that were requested.
            claim_modifications: Claims to modify for tampering test.

        Returns:
            Dictionary with all test results.
        """
        results: Dict[str, Any] = {
            "id_token_tampering": {},
            "userinfo_leakage": {},
            "discovery_security": {},
        }

        if id_token and resource_url and claim_modifications:
            tamper_result = await self._id_token_tester.test_claim_tampering(
                id_token=id_token,
                resource_url=resource_url,
                claim_modifications=claim_modifications,
            )
            results["id_token_tampering"] = tamper_result.to_dict()

        if access_token and userinfo_endpoint:
            leakage_result = await self._userinfo_tester.test_userinfo_leakage(
                userinfo_endpoint=userinfo_endpoint,
                access_token=access_token,
                requested_scopes=requested_scopes,
            )
            results["userinfo_leakage"] = leakage_result.to_dict()

        if issuer_url:
            discovery_result = await self._discovery_tester.test_discovery_security(
                issuer_url=issuer_url,
            )
            results["discovery_security"] = discovery_result.to_dict()

        return results
