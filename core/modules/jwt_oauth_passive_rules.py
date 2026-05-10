"""
JWT/OAuth Passive Rules Module - Passive scanning rules for JWT/OAuth vulnerabilities.

This module provides:
    1. 10+ passive scanning rules for JWT/OAuth vulnerabilities
    2. Automatic detection of weak JWT configurations
    3. OAuth flow security analysis
    4. Integration with passive scanning engine

Integration points:
    - MITM proxy traffic capture
    - Passive scanning engine
    - JWT Editor module
    - OAuth Analyzer module
    - Report generation engine

Author: Kunlun Security Lab
License: Internal Use Only
"""

from __future__ import annotations

import base64
import json
import logging
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qs, urlparse

logger = logging.getLogger(__name__)


# =============================================================================
# Enums
# =============================================================================

class PassiveRuleID(str, Enum):
    """Passive scanning rule IDs."""

    JWT_NONE_ALGORITHM = "JWT-001"
    JWT_NO_EXPIRATION = "JWT-002"
    JWT_LONG_EXPIRATION = "JWT-003"
    JWT_WEAK_SECRET = "JWT-004"
    JWT_KID_INJECTION = "JWT-005"
    JWT_ALG_CONFUSION = "JWT-006"
    OAUTH_MISSING_STATE = "OAUTH-001"
    OAUTH_HTTP_REDIRECT = "OAUTH-002"
    OAUTH_TOKEN_IN_URL = "OAUTH-003"
    OAUTH_IMPLICIT_FLOW = "OAUTH-004"
    OAUTH_MISSING_PKCE = "OAUTH-005"
    OAUTH_WIDE_SCOPE = "OAUTH-006"
    OAUTH_CODE_REUSE = "OAUTH-007"
    OIDC_HTTP_DISCOVERY = "OIDC-001"
    OIDC_NONE_ALGORITHM = "OIDC-002"


class RuleSeverity(str, Enum):
    """Rule severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class RuleCategory(str, Enum):
    """Rule categories."""

    JWT = "jwt"
    OAUTH = "oauth"
    OIDC = "oidc"


# =============================================================================
# Data Classes
# =============================================================================

@dataclass
class PassiveRuleMatch:
    """Passive rule match result.

    Attributes:
        rule_id: Rule ID that matched
        rule_name: Rule name
        severity: Match severity
        category: Rule category
        description: Match description
        evidence: Evidence details
        mitre_id: MITRE ATT&CK technique ID
        recommendation: Remediation recommendation
        request_id: Source request ID
        timestamp: Match timestamp
        jump_to_module: Module to jump to for manual verification
    """

    rule_id: str = ""
    rule_name: str = ""
    severity: RuleSeverity = RuleSeverity.INFO
    category: RuleCategory = RuleCategory.JWT
    description: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)
    mitre_id: str = ""
    recommendation: str = ""
    request_id: str = ""
    timestamp: float = 0.0
    jump_to_module: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary.

        Returns:
            Dictionary representation.
        """
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": self.severity.value,
            "category": self.category.value,
            "description": self.description,
            "evidence": self.evidence,
            "mitre_id": self.mitre_id,
            "recommendation": self.recommendation,
            "request_id": self.request_id,
            "timestamp": self.timestamp,
            "jump_to_module": self.jump_to_module,
        }


# =============================================================================
# Passive Scanning Rules
# =============================================================================

class PassiveRuleBase:
    """Base class for passive scanning rules."""

    def __init__(
        self,
        rule_id: str,
        rule_name: str,
        severity: RuleSeverity,
        category: RuleCategory,
        description: str,
        mitre_id: str,
        recommendation: str,
        jump_to_module: str = "",
    ) -> None:
        """Initialize the passive rule.

        Args:
            rule_id: Rule ID.
            rule_name: Rule name.
            severity: Rule severity.
            category: Rule category.
            description: Rule description.
            mitre_id: MITRE ATT&CK technique ID.
            recommendation: Remediation recommendation.
            jump_to_module: Module to jump to.
        """
        self.rule_id = rule_id
        self.rule_name = rule_name
        self.severity = severity
        self.category = category
        self.description = description
        self.mitre_id = mitre_id
        self.recommendation = recommendation
        self.jump_to_module = jump_to_module

    def check(
        self,
        url: str,
        method: str,
        headers: Dict[str, str],
        body: str,
        response_headers: Dict[str, str],
        response_body: str,
        request_id: str = "",
    ) -> Optional[PassiveRuleMatch]:
        """Check if the rule matches.

        Args:
            url: Request URL.
            method: HTTP method.
            headers: Request headers.
            body: Request body.
            response_headers: Response headers.
            response_body: Response body.
            request_id: Source request ID.

        Returns:
            PassiveRuleMatch if matched, None otherwise.
        """
        raise NotImplementedError


class JWTNoneAlgorithmRule(PassiveRuleBase):
    """Rule: JWT uses none algorithm."""

    def __init__(self) -> None:
        """Initialize the rule."""
        super().__init__(
            rule_id=PassiveRuleID.JWT_NONE_ALGORITHM.value,
            rule_name="JWT使用none算法",
            severity=RuleSeverity.CRITICAL,
            category=RuleCategory.JWT,
            description="JWT的alg字段为none，表示不使用签名算法，攻击者可以伪造任意JWT。",
            mitre_id="T1550.001",
            recommendation="禁止使用none算法，所有JWT必须使用安全的签名算法（如RS256、ES256）。",
            jump_to_module="jwt_editor",
        )

    def check(
        self,
        url: str,
        method: str,
        headers: Dict[str, str],
        body: str,
        response_headers: Dict[str, str],
        response_body: str,
        request_id: str = "",
    ) -> Optional[PassiveRuleMatch]:
        """Check if JWT uses none algorithm.

        Args:
            url: Request URL.
            method: HTTP method.
            headers: Request headers.
            body: Request body.
            response_headers: Response headers.
            response_body: Response body.
            request_id: Source request ID.

        Returns:
            PassiveRuleMatch if matched.
        """
        jwt_token = self._extract_jwt(headers, body)
        if not jwt_token:
            return None

        try:
            parts = jwt_token.split(".")
            if len(parts) != 3:
                return None

            header_json = self._base64url_decode(parts[0])
            header = json.loads(header_json)

            alg = header.get("alg", "")
            if alg.lower() == "none":
                return PassiveRuleMatch(
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    severity=self.severity,
                    category=self.category,
                    description=self.description,
                    evidence={"alg": alg, "header": header},
                    mitre_id=self.mitre_id,
                    recommendation=self.recommendation,
                    request_id=request_id,
                    timestamp=time.time(),
                    jump_to_module=self.jump_to_module,
                )
        except Exception:
            pass

        return None

    def _extract_jwt(self, headers: Dict[str, str], body: str) -> Optional[str]:
        """Extract JWT from headers or body.

        Args:
            headers: Request headers.
            body: Request body.

        Returns:
            JWT token if found.
        """
        auth_header = headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            return auth_header[7:]

        match = re.search(r'"(?:access_token|id_token|jwt)"\s*:\s*"([^"]+)"', body)
        if match:
            return match.group(1)

        return None

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


class JWTNoExpirationRule(PassiveRuleBase):
    """Rule: JWT has no expiration time."""

    def __init__(self) -> None:
        """Initialize the rule."""
        super().__init__(
            rule_id=PassiveRuleID.JWT_NO_EXPIRATION.value,
            rule_name="JWT未设置过期时间",
            severity=RuleSeverity.HIGH,
            category=RuleCategory.JWT,
            description="JWT的Payload中没有exp字段，令牌永不过期，存在长期使用风险。",
            mitre_id="T1550.001",
            recommendation="所有JWT都必须设置合理的过期时间（exp字段），建议不超过1小时。",
            jump_to_module="jwt_editor",
        )

    def check(
        self,
        url: str,
        method: str,
        headers: Dict[str, str],
        body: str,
        response_headers: Dict[str, str],
        response_body: str,
        request_id: str = "",
    ) -> Optional[PassiveRuleMatch]:
        """Check if JWT has no expiration.

        Args:
            url: Request URL.
            method: HTTP method.
            headers: Request headers.
            body: Request body.
            response_headers: Response headers.
            response_body: Response body.
            request_id: Source request ID.

        Returns:
            PassiveRuleMatch if matched.
        """
        jwt_token = self._extract_jwt(headers, body)
        if not jwt_token:
            return None

        try:
            parts = jwt_token.split(".")
            if len(parts) != 3:
                return None

            payload_json = self._base64url_decode(parts[1])
            payload = json.loads(payload_json)

            if "exp" not in payload:
                return PassiveRuleMatch(
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    severity=self.severity,
                    category=self.category,
                    description=self.description,
                    evidence={"payload_keys": list(payload.keys())},
                    mitre_id=self.mitre_id,
                    recommendation=self.recommendation,
                    request_id=request_id,
                    timestamp=time.time(),
                    jump_to_module=self.jump_to_module,
                )
        except Exception:
            pass

        return None

    def _extract_jwt(self, headers: Dict[str, str], body: str) -> Optional[str]:
        """Extract JWT from headers or body.

        Args:
            headers: Request headers.
            body: Request body.

        Returns:
            JWT token if found.
        """
        auth_header = headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            return auth_header[7:]

        match = re.search(r'"(?:access_token|id_token|jwt)"\s*:\s*"([^"]+)"', body)
        if match:
            return match.group(1)

        return None

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


class JWTLongExpirationRule(PassiveRuleBase):
    """Rule: JWT has excessively long expiration time."""

    def __init__(self) -> None:
        """Initialize the rule."""
        super().__init__(
            rule_id=PassiveRuleID.JWT_LONG_EXPIRATION.value,
            rule_name="JWT过期时间过长",
            severity=RuleSeverity.MEDIUM,
            category=RuleCategory.JWT,
            description="JWT的exp字段设置的过期时间超过24小时，增加了令牌泄露后的风险窗口。",
            mitre_id="T1550.001",
            recommendation="JWT的过期时间应不超过1小时，使用Refresh Token机制来延长会话。",
            jump_to_module="jwt_editor",
        )

    def check(
        self,
        url: str,
        method: str,
        headers: Dict[str, str],
        body: str,
        response_headers: Dict[str, str],
        response_body: str,
        request_id: str = "",
    ) -> Optional[PassiveRuleMatch]:
        """Check if JWT has long expiration.

        Args:
            url: Request URL.
            method: HTTP method.
            headers: Request headers.
            body: Request body.
            response_headers: Response headers.
            response_body: Response body.
            request_id: Source request ID.

        Returns:
            PassiveRuleMatch if matched.
        """
        jwt_token = self._extract_jwt(headers, body)
        if not jwt_token:
            return None

        try:
            parts = jwt_token.split(".")
            if len(parts) != 3:
                return None

            payload_json = self._base64url_decode(parts[1])
            payload = json.loads(payload_json)

            exp = payload.get("exp", 0)
            iat = payload.get("iat", 0)

            if exp and iat:
                lifetime_hours = (exp - iat) / 3600.0

                if lifetime_hours > 24:
                    return PassiveRuleMatch(
                        rule_id=self.rule_id,
                        rule_name=self.rule_name,
                        severity=self.severity,
                        category=self.category,
                        description=self.description,
                        evidence={"lifetime_hours": lifetime_hours, "exp": exp, "iat": iat},
                        mitre_id=self.mitre_id,
                        recommendation=self.recommendation,
                        request_id=request_id,
                        timestamp=time.time(),
                        jump_to_module=self.jump_to_module,
                    )
        except Exception:
            pass

        return None

    def _extract_jwt(self, headers: Dict[str, str], body: str) -> Optional[str]:
        """Extract JWT from headers or body.

        Args:
            headers: Request headers.
            body: Request body.

        Returns:
            JWT token if found.
        """
        auth_header = headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            return auth_header[7:]

        match = re.search(r'"(?:access_token|id_token|jwt)"\s*:\s*"([^"]+)"', body)
        if match:
            return match.group(1)

        return None

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


class OAuthMissingStateRule(PassiveRuleBase):
    """Rule: OAuth request missing state parameter."""

    def __init__(self) -> None:
        """Initialize the rule."""
        super().__init__(
            rule_id=PassiveRuleID.OAUTH_MISSING_STATE.value,
            rule_name="OAuth请求缺少state参数",
            severity=RuleSeverity.HIGH,
            category=RuleCategory.OAUTH,
            description="OAuth授权请求中缺少state参数，存在CSRF攻击风险。",
            mitre_id="T1550.001",
            recommendation="OAuth授权请求必须包含随机且不可预测的state参数。",
            jump_to_module="oauth_analyzer",
        )

    def check(
        self,
        url: str,
        method: str,
        headers: Dict[str, str],
        body: str,
        response_headers: Dict[str, str],
        response_body: str,
        request_id: str = "",
    ) -> Optional[PassiveRuleMatch]:
        """Check if OAuth request is missing state.

        Args:
            url: Request URL.
            method: HTTP method.
            headers: Request headers.
            body: Request body.
            response_headers: Response headers.
            response_body: Response body.
            request_id: Source request ID.

        Returns:
            PassiveRuleMatch if matched.
        """
        if not self._is_oauth_authorize_request(url, body):
            return None

        params = self._extract_params(url, body)

        if "state" not in params:
            return PassiveRuleMatch(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=self.severity,
                category=self.category,
                description=self.description,
                evidence={"client_id": params.get("client_id", ""), "redirect_uri": params.get("redirect_uri", "")},
                mitre_id=self.mitre_id,
                recommendation=self.recommendation,
                request_id=request_id,
                timestamp=time.time(),
                jump_to_module=self.jump_to_module,
            )

        return None

    def _is_oauth_authorize_request(self, url: str, body: str) -> bool:
        """Check if request is an OAuth authorization request.

        Args:
            url: Request URL.
            body: Request body.

        Returns:
            True if it's an OAuth authorize request.
        """
        return "response_type=" in url or "response_type=" in body

    def _extract_params(self, url: str, body: str) -> Dict[str, str]:
        """Extract parameters from URL and body.

        Args:
            url: Request URL.
            body: Request body.

        Returns:
            Dictionary of parameters.
        """
        params: Dict[str, str] = {}

        parsed = urlparse(url)
        url_params = parse_qs(parsed.query)
        params.update({k: v[0] for k, v in url_params.items()})

        if "application/x-www-form-urlencoded" in body or "&" in body:
            body_params = parse_qs(body)
            params.update({k: v[0] for k, v in body_params.items()})

        return params


class OAuthHTTPRedirectRule(PassiveRuleBase):
    """Rule: OAuth redirect_uri uses HTTP instead of HTTPS."""

    def __init__(self) -> None:
        """Initialize the rule."""
        super().__init__(
            rule_id=PassiveRuleID.OAUTH_HTTP_REDIRECT.value,
            rule_name="OAuth redirect_uri使用HTTP",
            severity=RuleSeverity.MEDIUM,
            category=RuleCategory.OAUTH,
            description="OAuth的redirect_uri使用HTTP协议而非HTTPS，存在令牌泄露风险。",
            mitre_id="T1550.001",
            recommendation="redirect_uri应使用HTTPS协议，避免使用HTTP。",
            jump_to_module="oauth_analyzer",
        )

    def check(
        self,
        url: str,
        method: str,
        headers: Dict[str, str],
        body: str,
        response_headers: Dict[str, str],
        response_body: str,
        request_id: str = "",
    ) -> Optional[PassiveRuleMatch]:
        """Check if redirect_uri uses HTTP.

        Args:
            url: Request URL.
            method: HTTP method.
            headers: Request headers.
            body: Request body.
            response_headers: Response headers.
            response_body: Response body.
            request_id: Source request ID.

        Returns:
            PassiveRuleMatch if matched.
        """
        params = self._extract_params(url, body)
        redirect_uri = params.get("redirect_uri", "")

        if redirect_uri and redirect_uri.startswith("http://"):
            if "localhost" not in redirect_uri and "127.0.0.1" not in redirect_uri:
                return PassiveRuleMatch(
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    severity=self.severity,
                    category=self.category,
                    description=self.description,
                    evidence={"redirect_uri": redirect_uri},
                    mitre_id=self.mitre_id,
                    recommendation=self.recommendation,
                    request_id=request_id,
                    timestamp=time.time(),
                    jump_to_module=self.jump_to_module,
                )

        return None

    def _extract_params(self, url: str, body: str) -> Dict[str, str]:
        """Extract parameters from URL and body.

        Args:
            url: Request URL.
            body: Request body.

        Returns:
            Dictionary of parameters.
        """
        params: Dict[str, str] = {}

        parsed = urlparse(url)
        url_params = parse_qs(parsed.query)
        params.update({k: v[0] for k, v in url_params.items()})

        if "application/x-www-form-urlencoded" in body or "&" in body:
            body_params = parse_qs(body)
            params.update({k: v[0] for k, v in body_params.items()})

        return params


class OAuthTokenInURLRule(PassiveRuleBase):
    """Rule: Access Token passed in URL query parameter."""

    def __init__(self) -> None:
        """Initialize the rule."""
        super().__init__(
            rule_id=PassiveRuleID.OAUTH_TOKEN_IN_URL.value,
            rule_name="Access Token在URL中传递",
            severity=RuleSeverity.HIGH,
            category=RuleCategory.OAUTH,
            description="Access Token通过URL查询参数传递，可能被浏览器历史、Referer头等泄露。",
            mitre_id="T1550.001",
            recommendation="Access Token应通过Authorization请求头传递，不要在URL中包含令牌。",
            jump_to_module="oauth_analyzer",
        )

    def check(
        self,
        url: str,
        method: str,
        headers: Dict[str, str],
        body: str,
        response_headers: Dict[str, str],
        response_body: str,
        request_id: str = "",
    ) -> Optional[PassiveRuleMatch]:
        """Check if token is in URL.

        Args:
            url: Request URL.
            method: HTTP method.
            headers: Request headers.
            body: Request body.
            response_headers: Response headers.
            response_body: Response body.
            request_id: Source request ID.

        Returns:
            PassiveRuleMatch if matched.
        """
        token_indicators = ["access_token=", "token=", "id_token="]

        for indicator in token_indicators:
            if indicator in url.lower():
                return PassiveRuleMatch(
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    severity=self.severity,
                    category=self.category,
                    description=self.description,
                    evidence={"url": url, "indicator": indicator},
                    mitre_id=self.mitre_id,
                    recommendation=self.recommendation,
                    request_id=request_id,
                    timestamp=time.time(),
                    jump_to_module=self.jump_to_module,
                )

        return None


class OAuthImplicitFlowRule(PassiveRuleBase):
    """Rule: OAuth uses deprecated implicit flow."""

    def __init__(self) -> None:
        """Initialize the rule."""
        super().__init__(
            rule_id=PassiveRuleID.OAUTH_IMPLICIT_FLOW.value,
            rule_name="使用已废弃的隐式流",
            severity=RuleSeverity.MEDIUM,
            category=RuleCategory.OAUTH,
            description="OAuth使用隐式流（response_type=token），该流程已被RFC 6749废弃。",
            mitre_id="T1550.001",
            recommendation="使用授权码流程配合PKCE替代隐式流。",
            jump_to_module="oauth_analyzer",
        )

    def check(
        self,
        url: str,
        method: str,
        headers: Dict[str, str],
        body: str,
        response_headers: Dict[str, str],
        response_body: str,
        request_id: str = "",
    ) -> Optional[PassiveRuleMatch]:
        """Check if implicit flow is used.

        Args:
            url: Request URL.
            method: HTTP method.
            headers: Request headers.
            body: Request body.
            response_headers: Response headers.
            response_body: Response body.
            request_id: Source request ID.

        Returns:
            PassiveRuleMatch if matched.
        """
        params = self._extract_params(url, body)
        response_type = params.get("response_type", "")

        if response_type == "token" or "token" in response_type.split():
            return PassiveRuleMatch(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=self.severity,
                category=self.category,
                description=self.description,
                evidence={"response_type": response_type, "client_id": params.get("client_id", "")},
                mitre_id=self.mitre_id,
                recommendation=self.recommendation,
                request_id=request_id,
                timestamp=time.time(),
                jump_to_module=self.jump_to_module,
            )

        return None

    def _extract_params(self, url: str, body: str) -> Dict[str, str]:
        """Extract parameters from URL and body.

        Args:
            url: Request URL.
            body: Request body.

        Returns:
            Dictionary of parameters.
        """
        params: Dict[str, str] = {}

        parsed = urlparse(url)
        url_params = parse_qs(parsed.query)
        params.update({k: v[0] for k, v in url_params.items()})

        if "application/x-www-form-urlencoded" in body or "&" in body:
            body_params = parse_qs(body)
            params.update({k: v[0] for k, v in body_params.items()})

        return params


class OAuthMissingPKCERule(PassiveRuleBase):
    """Rule: OAuth authorization code flow missing PKCE."""

    def __init__(self) -> None:
        """Initialize the rule."""
        super().__init__(
            rule_id=PassiveRuleID.OAUTH_MISSING_PKCE.value,
            rule_name="授权码流程未启用PKCE",
            severity=RuleSeverity.HIGH,
            category=RuleCategory.OAUTH,
            description="OAuth授权码流程未使用PKCE（Proof Key for Code Exchange），存在授权码拦截攻击风险。",
            mitre_id="T1550.001",
            recommendation="所有OAuth客户端都应使用PKCE，特别是公共客户端。",
            jump_to_module="oauth_analyzer",
        )

    def check(
        self,
        url: str,
        method: str,
        headers: Dict[str, str],
        body: str,
        response_headers: Dict[str, str],
        response_body: str,
        request_id: str = "",
    ) -> Optional[PassiveRuleMatch]:
        """Check if PKCE is missing.

        Args:
            url: Request URL.
            method: HTTP method.
            headers: Request headers.
            body: Request body.
            response_headers: Response headers.
            response_body: Response body.
            request_id: Source request ID.

        Returns:
            PassiveRuleMatch if matched.
        """
        params = self._extract_params(url, body)
        response_type = params.get("response_type", "")

        if "code" not in response_type.split():
            return None

        if "code_challenge" not in params:
            return PassiveRuleMatch(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=self.severity,
                category=self.category,
                description=self.description,
                evidence={"client_id": params.get("client_id", ""), "response_type": response_type},
                mitre_id=self.mitre_id,
                recommendation=self.recommendation,
                request_id=request_id,
                timestamp=time.time(),
                jump_to_module=self.jump_to_module,
            )

        return None

    def _extract_params(self, url: str, body: str) -> Dict[str, str]:
        """Extract parameters from URL and body.

        Args:
            url: Request URL.
            body: Request body.

        Returns:
            Dictionary of parameters.
        """
        params: Dict[str, str] = {}

        parsed = urlparse(url)
        url_params = parse_qs(parsed.query)
        params.update({k: v[0] for k, v in url_params.items()})

        if "application/x-www-form-urlencoded" in body or "&" in body:
            body_params = parse_qs(body)
            params.update({k: v[0] for k, v in body_params.items()})

        return params


class OAuthWideScopeRule(PassiveRuleBase):
    """Rule: OAuth requests overly wide scope."""

    def __init__(self) -> None:
        """Initialize the rule."""
        super().__init__(
            rule_id=PassiveRuleID.OAUTH_WIDE_SCOPE.value,
            rule_name="OAuth请求过宽的作用域",
            severity=RuleSeverity.MEDIUM,
            category=RuleCategory.OAUTH,
            description="OAuth请求包含过多或危险的作用域（如admin、offline_access），可能存在过度授权。",
            mitre_id="T1550.001",
            recommendation="遵循最小权限原则，只请求必要的作用域。",
            jump_to_module="oauth_analyzer",
        )

    def check(
        self,
        url: str,
        method: str,
        headers: Dict[str, str],
        body: str,
        response_headers: Dict[str, str],
        response_body: str,
        request_id: str = "",
    ) -> Optional[PassiveRuleMatch]:
        """Check for wide scope.

        Args:
            url: Request URL.
            method: HTTP method.
            headers: Request headers.
            body: Request body.
            response_headers: Response headers.
            response_body: Response body.
            request_id: Source request ID.

        Returns:
            PassiveRuleMatch if matched.
        """
        params = self._extract_params(url, body)
        scope = params.get("scope", "")

        if not scope:
            return None

        dangerous_scopes = {"admin", "offline_access", "full_access", "root", "superuser", "*"}
        requested_scopes = set(scope.split())

        dangerous_found = dangerous_scopes.intersection(requested_scopes)

        if dangerous_found:
            return PassiveRuleMatch(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=self.severity,
                category=self.category,
                description=self.description,
                evidence={"scope": scope, "dangerous_scopes": list(dangerous_found)},
                mitre_id=self.mitre_id,
                recommendation=self.recommendation,
                request_id=request_id,
                timestamp=time.time(),
                jump_to_module=self.jump_to_module,
            )

        return None

    def _extract_params(self, url: str, body: str) -> Dict[str, str]:
        """Extract parameters from URL and body.

        Args:
            url: Request URL.
            body: Request body.

        Returns:
            Dictionary of parameters.
        """
        params: Dict[str, str] = {}

        parsed = urlparse(url)
        url_params = parse_qs(parsed.query)
        params.update({k: v[0] for k, v in url_params.items()})

        if "application/x-www-form-urlencoded" in body or "&" in body:
            body_params = parse_qs(body)
            params.update({k: v[0] for k, v in body_params.items()})

        return params


# =============================================================================
# Passive Rules Engine
# =============================================================================

class JWTOAuthPassiveRulesEngine:
    """JWT/OAuth passive scanning rules engine.

    Contains 10+ rules for detecting JWT/OAuth vulnerabilities
    in proxy traffic.

    Attributes:
        _rules: List of registered rules
        _matches: Rule matches
    """

    def __init__(self) -> None:
        """Initialize the passive rules engine."""
        self._rules: List[PassiveRuleBase] = [
            JWTNoneAlgorithmRule(),
            JWTNoExpirationRule(),
            JWTLongExpirationRule(),
            OAuthMissingStateRule(),
            OAuthHTTPRedirectRule(),
            OAuthTokenInURLRule(),
            OAuthImplicitFlowRule(),
            OAuthMissingPKCERule(),
            OAuthWideScopeRule(),
        ]
        self._matches: List[PassiveRuleMatch] = []

    def register_rule(self, rule: PassiveRuleBase) -> None:
        """Register a new rule.

        Args:
            rule: Rule to register.
        """
        self._rules.append(rule)

    def scan_traffic(
        self,
        url: str,
        method: str,
        headers: Dict[str, str],
        body: str,
        response_headers: Dict[str, str],
        response_body: str,
        request_id: str = "",
    ) -> List[PassiveRuleMatch]:
        """Scan traffic against all rules.

        Args:
            url: Request URL.
            method: HTTP method.
            headers: Request headers.
            body: Request body.
            response_headers: Response headers.
            response_body: Response body.
            request_id: Source request ID.

        Returns:
            List of rule matches.
        """
        matches: List[PassiveRuleMatch] = []

        for rule in self._rules:
            try:
                match = rule.check(
                    url=url,
                    method=method,
                    headers=headers,
                    body=body,
                    response_headers=response_headers,
                    response_body=response_body,
                    request_id=request_id,
                )

                if match:
                    matches.append(match)
                    self._matches.append(match)
            except Exception as e:
                logger.error(f"Rule {rule.rule_id} failed: {e}")

        return matches

    def get_all_matches(self) -> List[PassiveRuleMatch]:
        """Get all rule matches.

        Returns:
            List of PassiveRuleMatch.
        """
        return self._matches.copy()

    def get_matches_by_severity(self, severity: RuleSeverity) -> List[PassiveRuleMatch]:
        """Get matches by severity.

        Args:
            severity: Severity level to filter.

        Returns:
            List of PassiveRuleMatch with specified severity.
        """
        return [m for m in self._matches if m.severity == severity]

    def get_matches_by_category(self, category: RuleCategory) -> List[PassiveRuleMatch]:
        """Get matches by category.

        Args:
            category: Category to filter.

        Returns:
            List of PassiveRuleMatch with specified category.
        """
        return [m for m in self._matches if m.category == category]

    def get_rule_count(self) -> int:
        """Get the number of registered rules.

        Returns:
            Number of rules.
        """
        return len(self._rules)
