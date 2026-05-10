"""
OAuth 2.1 Audit Module - Security baseline detection and authorization
server configuration audit.

This module provides:
    1. OAuth 2.1 compliance detection (PKCE enforcement, implicit flow ban)
    2. Authorization server security configuration audit
    3. Client metadata exposure detection
    4. CORS configuration analysis
    5. Rate limiting detection

Integration points:
    - OAuth Analyzer module
    - MITM proxy traffic capture
    - Report generation engine
    - Knowledge base integration

Author: Kunlun Security Lab
License: Internal Use Only
"""

from __future__ import annotations

import asyncio
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

class ComplianceLevel(str, Enum):
    """OAuth 2.1 compliance levels."""

    COMPLIANT = "compliant"
    PARTIAL = "partial"
    NON_COMPLIANT = "non_compliant"


class AuditCategory(str, Enum):
    """Audit check categories."""

    OAUTH21_BASELINE = "oauth21_baseline"
    SERVER_CONFIG = "server_config"
    CLIENT_METADATA = "client_metadata"
    CORS_CONFIG = "cors_config"
    RATE_LIMITING = "rate_limiting"


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
class AuditFinding:
    """Individual audit finding.

    Attributes:
        finding_id: Unique finding identifier
        category: Audit category
        severity: Finding severity
        title: Finding title
        description: Detailed description
        evidence: Evidence supporting the finding
        recommendation: Remediation recommendation
        oauth21_requirement: Related OAuth 2.1 requirement
        compliance_impact: Impact on OAuth 2.1 compliance
        timestamp: Finding timestamp
    """

    finding_id: str = ""
    category: AuditCategory = AuditCategory.OAUTH21_BASELINE
    severity: Severity = Severity.INFO
    title: str = ""
    description: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)
    recommendation: str = ""
    oauth21_requirement: str = ""
    compliance_impact: str = ""
    timestamp: float = 0.0
    success: bool = False

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary.

        Returns:
            Dictionary representation.
        """
        return {
            "finding_id": self.finding_id,
            "category": self.category.value,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
            "oauth21_requirement": self.oauth21_requirement,
            "compliance_impact": self.compliance_impact,
            "timestamp": self.timestamp,
        }


@dataclass
class OAuth21ComplianceReport:
    """OAuth 2.1 compliance report.

    Attributes:
        target_url: Target authorization server URL
        compliance_level: Overall compliance level
        compliance_score: Score from 0-100
        findings: List of audit findings
        passed_checks: Number of passed checks
        failed_checks: Number of failed checks
        total_checks: Total number of checks
        timestamp: Report timestamp
    """

    target_url: str = ""
    compliance_level: ComplianceLevel = ComplianceLevel.NON_COMPLIANT
    compliance_score: float = 0.0
    findings: List[AuditFinding] = field(default_factory=list)
    passed_checks: int = 0
    failed_checks: int = 0
    total_checks: int = 0
    timestamp: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary.

        Returns:
            Dictionary representation.
        """
        return {
            "target_url": self.target_url,
            "compliance_level": self.compliance_level.value,
            "compliance_score": self.compliance_score,
            "findings": [f.to_dict() for f in self.findings],
            "passed_checks": self.passed_checks,
            "failed_checks": self.failed_checks,
            "total_checks": self.total_checks,
            "timestamp": self.timestamp,
        }


# =============================================================================
# OAuth 2.1 Baseline Checker
# =============================================================================

class OAuth21BaselineChecker:
    """Checks OAuth 2.1 compliance requirements.

    OAuth 2.1 mandates:
    - PKCE must be enforced for all clients
    - Implicit flow is prohibited
    - Exact redirect URI matching required
    - response_mode=query is prohibited for token transmission
    """

    def __init__(self, auth_server_url: str) -> None:
        """Initialize the OAuth 2.1 baseline checker.

        Args:
            auth_server_url: Authorization server base URL.
        """
        self.auth_server_url = auth_server_url
        self.findings: List[AuditFinding] = []
        self.finding_counter = 0

    def _next_finding_id(self) -> str:
        """Generate next finding ID.

        Returns:
            Finding ID string.
        """
        self.finding_counter += 1
        return f"OAUTH21-{self.finding_counter:03d}"

    async def check_implicit_flow_disabled(
        self,
        authorize_url: str = "",
        timeout: int = 10,
    ) -> AuditFinding:
        """Check if implicit flow is disabled.

        OAuth 2.1 prohibits implicit flow (response_type=token).

        Args:
            authorize_url: Authorization endpoint URL.
            timeout: Request timeout in seconds.

        Returns:
            AuditFinding with check results.
        """
        auth_url = authorize_url or f"{self.auth_server_url}/authorize"

        params = {
            "response_type": "token",
            "client_id": "test_client",
            "redirect_uri": "https://example.com/callback",
            "scope": "openid",
        }

        test_url = f"{auth_url}?{urlencode(params)}"

        finding = AuditFinding(
            finding_id=self._next_finding_id(),
            category=AuditCategory.OAUTH21_BASELINE,
            severity=Severity.HIGH,
            title="隐式流未禁用",
            description=(
                "OAuth 2.1 明确禁止隐式流（response_type=token）。"
                "检测到授权端点仍接受隐式流请求。"
            ),
            recommendation=(
                "禁用隐式流，改用授权码流程配合 PKCE。"
                "在授权端点拒绝 response_type=token 的请求。"
            ),
            oauth21_requirement="Section 2.1: Implicit flow is prohibited",
            compliance_impact="不符合 OAuth 2.1 安全基线",
            evidence={"test_url": test_url, "response_type": "token"},
            timestamp=time.time(),
        )

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(test_url, timeout=timeout, allow_redirects=False) as response:
                    finding.evidence["status_code"] = response.status
                    finding.evidence["location"] = response.headers.get("Location", "")

                    if response.status in (301, 302, 303, 307, 308):
                        location = response.headers.get("Location", "")
                        if "access_token" in location or "token" in location:
                            finding.success = True
                            logger.warning("Implicit flow is enabled!")
                    else:
                        finding.severity = Severity.INFO
                        finding.title = "隐式流已禁用"
                        finding.description = "授权端点正确拒绝了隐式流请求。"
                        finding.compliance_impact = "符合 OAuth 2.1 要求"

        except Exception as e:
            finding.evidence["error"] = str(e)

        self.findings.append(finding)
        return finding

    async def check_pkce_enforced(
        self,
        authorize_url: str = "",
        timeout: int = 10,
    ) -> AuditFinding:
        """Check if PKCE is enforced for all clients.

        OAuth 2.1 requires PKCE for all clients.

        Args:
            authorize_url: Authorization endpoint URL.
            timeout: Request timeout in seconds.

        Returns:
            AuditFinding with check results.
        """
        auth_url = authorize_url or f"{self.auth_server_url}/authorize"

        params = {
            "response_type": "code",
            "client_id": "test_client",
            "redirect_uri": "https://example.com/callback",
            "scope": "openid",
        }

        test_url = f"{auth_url}?{urlencode(params)}"

        finding = AuditFinding(
            finding_id=self._next_finding_id(),
            category=AuditCategory.OAUTH21_BASELINE,
            severity=Severity.HIGH,
            title="PKCE 未强制启用",
            description=(
                "OAuth 2.1 要求所有客户端必须使用 PKCE。"
                "检测到授权端点接受不包含 code_challenge 的请求。"
            ),
            recommendation=(
                "强制所有授权请求必须包含 code_challenge 和 code_challenge_method 参数。"
                "拒绝缺少 PKCE 参数的授权请求。"
            ),
            oauth21_requirement="Section 2.2: PKCE is required for all clients",
            compliance_impact="不符合 OAuth 2.1 安全基线",
            evidence={"test_url": test_url, "missing": "code_challenge"},
            timestamp=time.time(),
        )

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(test_url, timeout=timeout, allow_redirects=False) as response:
                    finding.evidence["status_code"] = response.status

                    if response.status in (301, 302, 303, 307, 308):
                        location = response.headers.get("Location", "")
                        if "code=" in location:
                            finding.success = True
                            logger.warning("PKCE is not enforced!")
                    else:
                        finding.severity = Severity.INFO
                        finding.title = "PKCE 已强制启用"
                        finding.description = "授权端点正确拒绝了缺少 PKCE 参数的请求。"
                        finding.compliance_impact = "符合 OAuth 2.1 要求"

        except Exception as e:
            finding.evidence["error"] = str(e)

        self.findings.append(finding)
        return finding

    async def check_exact_redirect_uri_matching(
        self,
        authorize_url: str = "",
        registered_uri: str = "https://example.com/callback",
        timeout: int = 10,
    ) -> AuditFinding:
        """Check if exact redirect URI matching is enforced.

        OAuth 2.1 requires exact redirect URI matching.

        Args:
            authorize_url: Authorization endpoint URL.
            registered_uri: Registered redirect URI.
            timeout: Request timeout in seconds.

        Returns:
            AuditFinding with check results.
        """
        auth_url = authorize_url or f"{self.auth_server_url}/authorize"

        bypass_variants = [
            f"{registered_uri}.evil.com",
            f"{registered_uri}/evil",
            f"https://evil.com?redirect={registered_uri}",
            f"{registered_uri}%2F.evil.com",
            f"{registered_uri}%40evil.com",
        ]

        finding = AuditFinding(
            finding_id=self._next_finding_id(),
            category=AuditCategory.OAUTH21_BASELINE,
            severity=Severity.HIGH,
            title="重定向 URI 未精确匹配",
            description=(
                "OAuth 2.1 要求重定向 URI 必须精确匹配注册值。"
                "检测到授权端点接受变形的重定向 URI。"
            ),
            recommendation=(
                "使用精确字符串匹配验证重定向 URI。"
                "禁止使用前缀匹配、后缀匹配或正则表达式匹配。"
            ),
            oauth21_requirement="Section 2.3: Exact redirect URI matching required",
            compliance_impact="不符合 OAuth 2.1 安全基线",
            evidence={"registered_uri": registered_uri, "tested_variants": bypass_variants},
            timestamp=time.time(),
        )

        bypassed_uris: List[str] = []

        try:
            async with aiohttp.ClientSession() as session:
                for variant in bypass_variants:
                    params = {
                        "response_type": "code",
                        "client_id": "test_client",
                        "redirect_uri": variant,
                        "scope": "openid",
                        "code_challenge": "test_challenge",
                        "code_challenge_method": "S256",
                    }

                    test_url = f"{auth_url}?{urlencode(params)}"

                    async with session.get(test_url, timeout=timeout, allow_redirects=False) as response:
                        if response.status in (301, 302, 303, 307, 308):
                            location = response.headers.get("Location", "")
                            if variant in location or "code=" in location:
                                bypassed_uris.append(variant)

        except Exception as e:
            finding.evidence["error"] = str(e)

        if bypassed_uris:
            finding.evidence["bypassed_uris"] = bypassed_uris
            finding.success = True
            logger.warning(f"Redirect URI bypass detected: {bypassed_uris}")
        else:
            finding.severity = Severity.INFO
            finding.title = "重定向 URI 精确匹配已启用"
            finding.description = "授权端点正确拒绝了变形的重定向 URI。"
            finding.compliance_impact = "符合 OAuth 2.1 要求"

        self.findings.append(finding)
        return finding

    async def check_response_mode_query_prohibited(
        self,
        authorize_url: str = "",
        timeout: int = 10,
    ) -> AuditFinding:
        """Check if response_mode=query is prohibited for token transmission.

        OAuth 2.1 prohibits response_mode=query for token responses.

        Args:
            authorize_url: Authorization endpoint URL.
            timeout: Request timeout in seconds.

        Returns:
            AuditFinding with check results.
        """
        auth_url = authorize_url or f"{self.auth_server_url}/authorize"

        params = {
            "response_type": "token",
            "client_id": "test_client",
            "redirect_uri": "https://example.com/callback",
            "scope": "openid",
            "response_mode": "query",
        }

        test_url = f"{auth_url}?{urlencode(params)}"

        finding = AuditFinding(
            finding_id=self._next_finding_id(),
            category=AuditCategory.OAUTH21_BASELINE,
            severity=Severity.MEDIUM,
            title="response_mode=query 未禁止",
            description=(
                "OAuth 2.1 禁止使用 response_mode=query 传输令牌，"
                "因为会导致令牌暴露在 URL 查询参数中，可能被日志记录或 Referer 头泄露。"
            ),
            recommendation=(
                "禁止 response_mode=query 用于令牌传输。"
                "仅允许 response_mode=fragment 或 response_mode=form_post。"
            ),
            oauth21_requirement="Section 2.4: response_mode=query prohibited for tokens",
            compliance_impact="不符合 OAuth 2.1 安全基线",
            evidence={"test_url": test_url, "response_mode": "query"},
            timestamp=time.time(),
        )

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(test_url, timeout=timeout, allow_redirects=False) as response:
                    finding.evidence["status_code"] = response.status

                    if response.status in (301, 302, 303, 307, 308):
                        location = response.headers.get("Location", "")
                        if "access_token" in location and "?" in location:
                            finding.success = True
                            logger.warning("response_mode=query is allowed for tokens!")
                    else:
                        finding.severity = Severity.INFO
                        finding.title = "response_mode=query 已禁止"
                        finding.description = "授权端点正确拒绝了 response_mode=query 的令牌请求。"
                        finding.compliance_impact = "符合 OAuth 2.1 要求"

        except Exception as e:
            finding.evidence["error"] = str(e)

        self.findings.append(finding)
        return finding


# =============================================================================
# Authorization Server Security Auditor
# =============================================================================

class AuthServerSecurityAuditor:
    """Audits authorization server security configuration.

    Checks:
    - CORS configuration
    - HTTP method restrictions
    - Rate limiting
    - Security headers
    """

    def __init__(self, auth_server_url: str) -> None:
        """Initialize the authorization server security auditor.

        Args:
            auth_server_url: Authorization server base URL.
        """
        self.auth_server_url = auth_server_url
        self.findings: List[AuditFinding] = []
        self.finding_counter = 0

    def _next_finding_id(self) -> str:
        """Generate next finding ID.

        Returns:
            Finding ID string.
        """
        self.finding_counter += 1
        return f"SERVER-{self.finding_counter:03d}"

    async def check_cors_configuration(
        self,
        endpoint: str = "",
        timeout: int = 10,
    ) -> AuditFinding:
        """Check CORS configuration for overly permissive settings.

        Args:
            endpoint: Endpoint to test.
            timeout: Request timeout in seconds.

        Returns:
            AuditFinding with check results.
        """
        test_endpoint = endpoint or f"{self.auth_server_url}/authorize"

        finding = AuditFinding(
            finding_id=self._next_finding_id(),
            category=AuditCategory.CORS_CONFIG,
            severity=Severity.MEDIUM,
            title="CORS 配置过于宽松",
            description=(
                "授权服务器的 CORS 配置允许任意来源访问，"
                "可能导致恶意网站跨域读取敏感信息。"
            ),
            recommendation=(
                "限制 access-control-allow-origin 为可信域名。"
                "禁止使用通配符 '*' 作为允许的来源。"
            ),
            oauth21_requirement="CORS Security Best Practices",
            compliance_impact="安全风险",
            evidence={"endpoint": test_endpoint},
            timestamp=time.time(),
        )

        test_origins = [
            "https://evil.com",
            "null",
            "https://attacker.example.com",
        ]

        permissive_origins: List[str] = []

        try:
            async with aiohttp.ClientSession() as session:
                for origin in test_origins:
                    headers = {"Origin": origin}

                    async with session.options(
                        test_endpoint, headers=headers, timeout=timeout
                    ) as response:
                        acao = response.headers.get("Access-Control-Allow-Origin", "")
                        acac = response.headers.get("Access-Control-Allow-Credentials", "")

                        if acao == "*" or acao == origin:
                            permissive_origins.append(origin)
                            finding.evidence[f"origin_{origin}"] = {
                                "allow_origin": acao,
                                "allow_credentials": acac,
                            }

        except Exception as e:
            finding.evidence["error"] = str(e)

        if permissive_origins:
            finding.evidence["permissive_origins"] = permissive_origins
            finding.success = True
            logger.warning(f"Permissive CORS detected: {permissive_origins}")
        else:
            finding.severity = Severity.INFO
            finding.title = "CORS 配置正确"
            finding.description = "授权服务器的 CORS 配置限制了访问来源。"
            finding.compliance_impact = "符合安全最佳实践"

        self.findings.append(finding)
        return finding

    async def check_http_method_restrictions(
        self,
        timeout: int = 10,
    ) -> List[AuditFinding]:
        """Check HTTP method restrictions on OAuth endpoints.

        Args:
            timeout: Request timeout in seconds.

        Returns:
            List of AuditFinding.
        """
        findings: List[AuditFinding] = []

        endpoints_to_check: List[Dict[str, Any]] = [
            {
                "url": f"{self.auth_server_url}/authorize",
                "name": "授权端点",
                "allowed_methods": ["GET", "POST"],
            },
            {
                "url": f"{self.auth_server_url}/token",
                "name": "令牌端点",
                "allowed_methods": ["POST"],
            },
            {
                "url": f"{self.auth_server_url}/revoke",
                "name": "撤销端点",
                "allowed_methods": ["POST"],
            },
        ]

        for ep in endpoints_to_check:
            ep_url: str = ep["url"]
            ep_name: str = ep["name"]
            ep_methods: List[str] = ep["allowed_methods"]

            finding = AuditFinding(
                finding_id=self._next_finding_id(),
                category=AuditCategory.SERVER_CONFIG,
                severity=Severity.MEDIUM,
                title=f"{ep_name} HTTP 方法限制不足",
                description=(
                    f"{ep_name} 应仅允许 {ep_methods} 方法。"
                    "检测到其他方法也被接受。"
                ),
                recommendation=(
                    f"配置 Web 服务器仅允许 {ep_methods} 方法访问该端点。"
                    "拒绝其他所有 HTTP 方法。"
                ),
                oauth21_requirement="HTTP Method Restrictions",
                compliance_impact="安全风险",
                evidence={"endpoint": ep_url, "allowed_methods": ep_methods},
                timestamp=time.time(),
            )

            disallowed_methods = ["DELETE", "PUT", "PATCH", "OPTIONS"]

            try:
                async with aiohttp.ClientSession() as session:
                    for method in disallowed_methods:
                        async with session.request(
                            method, ep_url, timeout=timeout, allow_redirects=False
                        ) as response:
                            if response.status not in (405, 501):
                                finding.evidence[f"method_{method}"] = response.status

            except Exception as e:
                finding.evidence["error"] = str(e)

            findings.append(finding)
            self.findings.append(finding)

        return findings

    async def check_rate_limiting(
        self,
        endpoint: str = "",
        test_count: int = 20,
        timeout: int = 10,
    ) -> AuditFinding:
        """Check if rate limiting is implemented.

        Args:
            endpoint: Endpoint to test.
            test_count: Number of requests to send.
            timeout: Request timeout in seconds.

        Returns:
            AuditFinding with check results.
        """
        test_endpoint = endpoint or f"{self.auth_server_url}/token"

        finding = AuditFinding(
            finding_id=self._next_finding_id(),
            category=AuditCategory.RATE_LIMITING,
            severity=Severity.MEDIUM,
            title="未实施速率限制",
            description=(
                "令牌端点未实施速率限制，攻击者可暴力破解授权码或客户端密钥。"
            ),
            recommendation=(
                "实施速率限制，限制同一 IP 或客户端的请求频率。"
                "在连续失败后临时锁定账户或 IP。"
            ),
            oauth21_requirement="Rate Limiting Best Practices",
            compliance_impact="安全风险",
            evidence={"endpoint": test_endpoint, "test_count": test_count},
            timestamp=time.time(),
        )

        rate_limited_count = 0
        status_codes: List[int] = []

        try:
            async with aiohttp.ClientSession() as session:
                for i in range(test_count):
                    data = {
                        "grant_type": "authorization_code",
                        "code": f"invalid_code_{i}",
                        "client_id": "test_client",
                        "client_secret": f"invalid_secret_{i}",
                        "redirect_uri": "https://example.com/callback",
                    }

                    async with session.post(
                        test_endpoint, data=data, timeout=timeout
                    ) as response:
                        status_codes.append(response.status)
                        if response.status == 429:
                            rate_limited_count += 1

        except Exception as e:
            finding.evidence["error"] = str(e)

        finding.evidence["status_codes"] = status_codes
        finding.evidence["rate_limited_count"] = rate_limited_count

        if rate_limited_count > 0:
            finding.severity = Severity.INFO
            finding.title = "速率限制已启用"
            finding.description = "令牌端点实施了速率限制。"
            finding.compliance_impact = "符合安全最佳实践"
        else:
            finding.success = True
            logger.warning("No rate limiting detected!")

        self.findings.append(finding)
        return finding


# =============================================================================
# Client Metadata Exposure Checker
# =============================================================================

class ClientMetadataExposureChecker:
    """Checks for client metadata exposure vulnerabilities.

    Checks:
    - OAuth authorization server metadata exposure
    - Client registration information leakage
    - Sensitive information in well-known endpoints
    """

    def __init__(self, auth_server_url: str) -> None:
        """Initialize the client metadata exposure checker.

        Args:
            auth_server_url: Authorization server base URL.
        """
        self.auth_server_url = auth_server_url
        self.findings: List[AuditFinding] = []
        self.finding_counter = 0

    def _next_finding_id(self) -> str:
        """Generate next finding ID.

        Returns:
            Finding ID string.
        """
        self.finding_counter += 1
        return f"METADATA-{self.finding_counter:03d}"

    async def check_well_known_exposure(
        self,
        timeout: int = 10,
    ) -> AuditFinding:
        """Check well-known endpoint for sensitive information exposure.

        Args:
            timeout: Request timeout in seconds.

        Returns:
            AuditFinding with check results.
        """
        well_known_urls = [
            f"{self.auth_server_url}/.well-known/oauth-authorization-server",
            f"{self.auth_server_url}/.well-known/openid-configuration",
        ]

        finding = AuditFinding(
            finding_id=self._next_finding_id(),
            category=AuditCategory.CLIENT_METADATA,
            severity=Severity.LOW,
            title="客户端元数据暴露",
            description=(
                "授权服务器的元数据端点暴露了敏感的客户端信息，"
                "包括重定向 URI 列表、支持的算法等。"
            ),
            recommendation=(
                "限制元数据端点的访问权限。"
                "不要在公开元数据中包含客户端密钥或敏感配置。"
            ),
            oauth21_requirement="Client Metadata Protection",
            compliance_impact="信息泄露风险",
            evidence={"tested_urls": well_known_urls},
            timestamp=time.time(),
        )

        sensitive_fields = [
            "client_secret",
            "registration_access_token",
            "token_endpoint_auth_methods_supported",
            "redirect_uris",
        ]

        exposed_fields: List[str] = []

        try:
            async with aiohttp.ClientSession() as session:
                for url in well_known_urls:
                    async with session.get(url, timeout=timeout) as response:
                        if response.status == 200:
                            body = await response.text()
                            try:
                                data = json.loads(body)
                                for field in sensitive_fields:
                                    if field in data:
                                        exposed_fields.append(field)
                                        finding.evidence[field] = str(data[field])[:200]
                            except json.JSONDecodeError:
                                pass

        except Exception as e:
            finding.evidence["error"] = str(e)

        if exposed_fields:
            finding.evidence["exposed_fields"] = exposed_fields
            finding.success = True
            logger.warning(f"Sensitive metadata exposed: {exposed_fields}")
        else:
            finding.severity = Severity.INFO
            finding.title = "客户端元数据保护良好"
            finding.description = "未发现敏感的客户端信息暴露。"
            finding.compliance_impact = "符合安全最佳实践"

        self.findings.append(finding)
        return finding


# =============================================================================
# Main OAuth 2.1 Audit Manager
# =============================================================================

class OAuth21AuditManager:
    """Main OAuth 2.1 audit coordination engine.

    Integrates baseline checking, server security auditing,
    and client metadata exposure detection.

    Attributes:
        auth_server_url: Authorization server URL
        baseline_checker: OAuth 2.1 baseline checker
        server_auditor: Server security auditor
        metadata_checker: Client metadata exposure checker
    """

    def __init__(self, auth_server_url: str) -> None:
        """Initialize the OAuth 2.1 audit manager.

        Args:
            auth_server_url: Authorization server base URL.
        """
        self.auth_server_url = auth_server_url
        self.baseline_checker = OAuth21BaselineChecker(auth_server_url)
        self.server_auditor = AuthServerSecurityAuditor(auth_server_url)
        self.metadata_checker = ClientMetadataExposureChecker(auth_server_url)

    async def run_full_audit(
        self,
        authorize_url: str = "",
        timeout: int = 10,
    ) -> OAuth21ComplianceReport:
        """Run full OAuth 2.1 compliance audit.

        Args:
            authorize_url: Authorization endpoint URL.
            timeout: Request timeout in seconds.

        Returns:
            OAuth21ComplianceReport with audit results.
        """
        start_time = time.time()

        all_findings: List[AuditFinding] = []

        baseline_findings = await self._run_baseline_checks(authorize_url, timeout)
        all_findings.extend(baseline_findings)

        server_findings = await self._run_server_audits(timeout)
        all_findings.extend(server_findings)

        metadata_findings = await self._run_metadata_checks(timeout)
        all_findings.extend(metadata_findings)

        passed = len([f for f in all_findings if f.severity == Severity.INFO])
        failed = len([f for f in all_findings if f.severity != Severity.INFO])
        total = len(all_findings)

        score = (passed / total * 100) if total > 0 else 0

        if score >= 90:
            level = ComplianceLevel.COMPLIANT
        elif score >= 60:
            level = ComplianceLevel.PARTIAL
        else:
            level = ComplianceLevel.NON_COMPLIANT

        return OAuth21ComplianceReport(
            target_url=self.auth_server_url,
            compliance_level=level,
            compliance_score=score,
            findings=all_findings,
            passed_checks=passed,
            failed_checks=failed,
            total_checks=total,
            timestamp=time.time(),
        )

    async def _run_baseline_checks(
        self,
        authorize_url: str,
        timeout: int,
    ) -> List[AuditFinding]:
        """Run OAuth 2.1 baseline checks.

        Args:
            authorize_url: Authorization endpoint URL.
            timeout: Request timeout in seconds.

        Returns:
            List of AuditFinding.
        """
        findings: List[AuditFinding] = []

        findings.append(
            await self.baseline_checker.check_implicit_flow_disabled(authorize_url, timeout)
        )
        findings.append(
            await self.baseline_checker.check_pkce_enforced(authorize_url, timeout)
        )
        findings.append(
            await self.baseline_checker.check_exact_redirect_uri_matching(authorize_url, timeout=timeout)
        )
        findings.append(
            await self.baseline_checker.check_response_mode_query_prohibited(authorize_url, timeout)
        )

        return findings

    async def _run_server_audits(
        self,
        timeout: int,
    ) -> List[AuditFinding]:
        """Run server security audits.

        Args:
            timeout: Request timeout in seconds.

        Returns:
            List of AuditFinding.
        """
        findings: List[AuditFinding] = []

        findings.append(
            await self.server_auditor.check_cors_configuration(timeout=timeout)
        )
        findings.extend(
            await self.server_auditor.check_http_method_restrictions(timeout)
        )
        findings.append(
            await self.server_auditor.check_rate_limiting(timeout=timeout)
        )

        return findings

    async def _run_metadata_checks(
        self,
        timeout: int,
    ) -> List[AuditFinding]:
        """Run client metadata exposure checks.

        Args:
            timeout: Request timeout in seconds.

        Returns:
            List of AuditFinding.
        """
        findings: List[AuditFinding] = []

        findings.append(
            await self.metadata_checker.check_well_known_exposure(timeout)
        )

        return findings
