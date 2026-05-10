"""
JWT/OAuth Integration Module - Integration layer with MITM proxy, Fuzzer,
reverse callback platform, and report modules.

This module provides:
    1. MITM proxy联动 - Auto-detection, highlighting, one-click sending to editors
    2. Fuzzer联动 - Fuzztag generation, dictionary rotation
    3. 反连平台联动 - JWKS spoofing, OAuth redirect testing with callback
    4. 报告模块联动 - Structured vulnerability reports with MITRE ATT&CK mapping

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
from typing import Any, Callable, Coroutine, Dict, List, Optional, Set, Tuple

from .jwt_editor import (
    AttackResult,
    AttackType,
    JWTToken,
    JWTEditorManager,
    Severity as JWTSeverity,
    get_jwt_editor_manager,
)
from .oauth_analyzer import (
    OAuthAnalyzerManager,
    OAuthFlow,
    OAuthFlowType,
    OAuthVulnerabilityFinding,
    RedirectTestResult,
    Severity as OAuthSeverity,
    get_oauth_analyzer_manager,
)

logger = logging.getLogger(__name__)


# =============================================================================
# Enums
# =============================================================================

class IntegrationEventType(str, Enum):
    """Integration event types."""

    JWT_DETECTED = "jwt_detected"
    OAUTH_FLOW_DETECTED = "oauth_flow_detected"
    VULNERABILITY_FOUND = "vulnerability_found"
    ATTACK_COMPLETED = "attack_completed"
    CALLBACK_RECEIVED = "callback_received"
    REPORT_GENERATED = "report_generated"


class CallbackType(str, Enum):
    """Reverse callback types."""

    JWKS_SPOOFING = "jwks_spoofing"
    OAUTH_REDIRECT = "oauth_redirect"
    OAUTH_TOKEN = "oauth_token"
    CUSTOM = "custom"


# =============================================================================
# Data Models
# =============================================================================

@dataclass
class IntegrationEvent:
    """Integration event for cross-module communication.

    Attributes:
        event_type: Event type
        timestamp: Event timestamp
        data: Event data
        source_module: Source module name
    """

    event_type: IntegrationEventType
    timestamp: float = 0.0
    data: Dict[str, Any] = field(default_factory=dict)
    source_module: str = "jwt_oauth_integration"

    def __post_init__(self) -> None:
        """Set timestamp if not provided."""
        if self.timestamp == 0.0:
            self.timestamp = time.time()

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary.

        Returns:
            Dictionary representation.
        """
        return {
            "event_type": self.event_type.value,
            "timestamp": self.timestamp,
            "data": self.data,
            "source_module": self.source_module,
        }


@dataclass
class VulnerabilityReport:
    """Structured vulnerability report.

    Attributes:
        vuln_id: Unique vulnerability ID
        vuln_type: Vulnerability type
        severity: Severity level
        title: Vulnerability title
        description: Detailed description
        evidence: Evidence data
        mitre_id: MITRE ATT&CK technique ID
        recommendation: Remediation recommendation
        affected_url: Affected URL
        affected_request: Affected request
        timestamp: Discovery timestamp
        module_source: Source module
    """

    vuln_id: str = ""
    vuln_type: str = ""
    severity: str = ""
    title: str = ""
    description: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)
    mitre_id: str = ""
    recommendation: str = ""
    affected_url: str = ""
    affected_request: str = ""
    timestamp: float = 0.0
    module_source: str = "jwt_oauth"

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary.

        Returns:
            Dictionary representation.
        """
        return {
            "vuln_id": self.vuln_id,
            "vuln_type": self.vuln_type,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "evidence": self.evidence,
            "mitre_id": self.mitre_id,
            "recommendation": self.recommendation,
            "affected_url": self.affected_url,
            "timestamp": self.timestamp,
            "module_source": self.module_source,
        }


@dataclass
class FuzztagDefinition:
    """Fuzztag definition for Fuzzer integration.

    Attributes:
        tag_name: Fuzztag name
        description: Tag description
        generator: Generator function
        attack_type: Associated attack type
    """

    tag_name: str
    description: str
    generator: Callable[..., str]
    attack_type: AttackType


@dataclass
class CallbackEndpoint:
    """Reverse callback endpoint.

    Attributes:
        endpoint_id: Endpoint identifier
        callback_type: Callback type
        url: Callback URL
        is_active: Whether endpoint is active
        received_callbacks: Received callback count
        created_at: Creation timestamp
    """

    endpoint_id: str = ""
    callback_type: CallbackType = CallbackType.CUSTOM
    url: str = ""
    is_active: bool = False
    received_callbacks: int = 0
    created_at: float = 0.0


# =============================================================================
# MITM Proxy Integration
# =============================================================================

class MITMProxyIntegration:
    """Integration with MITM proxy for auto-detection and highlighting.

    Monitors proxy traffic, detects JWT tokens and OAuth flows,
    and provides one-click sending to editors.

    Attributes:
        _jwt_manager: JWT editor manager
        _oauth_manager: OAuth analyzer manager
        _event_callbacks: Registered event callbacks
        _detected_tokens: Detected JWT tokens
        _detected_flows: Detected OAuth flows
    """

    def __init__(
        self,
        jwt_manager: Optional[JWTEditorManager] = None,
        oauth_manager: Optional[OAuthAnalyzerManager] = None,
    ) -> None:
        """Initialize the MITMProxyIntegration.

        Args:
            jwt_manager: JWT editor manager.
            oauth_manager: OAuth analyzer manager.
        """
        self._jwt_manager = jwt_manager or get_jwt_editor_manager()
        self._oauth_manager = oauth_manager or get_oauth_analyzer_manager()
        self._event_callbacks: Dict[IntegrationEventType, List[Callable]] = {}
        self._detected_tokens: List[JWTToken] = []
        self._detected_flows: List[OAuthFlow] = []

    def process_proxy_request(
        self,
        url: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        body: Optional[str] = None,
        request_id: str = "",
    ) -> Dict[str, Any]:
        """Process a proxy request for JWT/OAuth detection.

        Args:
            url: Request URL.
            method: HTTP method.
            headers: Request headers.
            cookies: Cookie dictionary.
            body: Request body.
            request_id: Source request ID.

        Returns:
            Dictionary with detection results.
        """
        result: Dict[str, Any] = {
            "request_id": request_id,
            "jwt_detected": [],
            "oauth_detected": None,
            "highlight": False,
        }

        headers = headers or {}

        jwt_tokens = self._jwt_manager.detect_from_request(
            headers=headers,
            cookies=cookies,
            body=body,
            url=url,
            request_id=request_id,
        )

        if jwt_tokens:
            result["jwt_detected"] = [t.to_dict() for t in jwt_tokens]
            result["highlight"] = True
            self._detected_tokens.extend(jwt_tokens)

            self._emit_event(
                IntegrationEventType.JWT_DETECTED,
                {
                    "request_id": request_id,
                    "token_count": len(jwt_tokens),
                    "tokens": [t.to_dict() for t in jwt_tokens],
                },
            )

        oauth_flow = self._oauth_manager.process_request(
            url=url,
            method=method,
            headers=headers,
            body=body or "",
            request_id=request_id,
        )

        if oauth_flow:
            result["oauth_detected"] = oauth_flow.to_dict()
            result["highlight"] = True
            self._detected_flows.append(oauth_flow)

            self._emit_event(
                IntegrationEventType.OAUTH_FLOW_DETECTED,
                {
                    "request_id": request_id,
                    "flow_id": oauth_flow.flow_id,
                    "flow_type": oauth_flow.flow_type.value,
                },
            )

        return result

    def process_proxy_response(
        self,
        flow_id: str,
        status_code: int,
        headers: Optional[Dict[str, str]] = None,
        body: str = "",
    ) -> Optional[Dict[str, Any]]:
        """Process a proxy response for OAuth flow tracking.

        Args:
            flow_id: OAuth flow ID.
            status_code: HTTP status code.
            headers: Response headers.
            body: Response body.

        Returns:
            Dictionary with response processing results, or None.
        """
        flow = self._oauth_manager.process_response(
            flow_id=flow_id,
            status_code=status_code,
            headers=headers,
            body=body,
        )

        if flow:
            findings = self._oauth_manager.scan_flow(flow_id)

            if findings:
                self._emit_event(
                    IntegrationEventType.VULNERABILITY_FOUND,
                    {
                        "flow_id": flow_id,
                        "finding_count": len(findings),
                        "findings": [f.to_dict() for f in findings],
                    },
                )

            return flow.to_dict()

        return None

    def send_to_jwt_editor(self, token: str, source: str = "proxy") -> Optional[JWTToken]:
        """Send a JWT token to the JWT editor.

        Args:
            token: Raw JWT string.
            source: Token source.

        Returns:
            JWTToken, or None.
        """
        return self._jwt_manager.load_token(token, source)

    def send_to_oauth_analyzer(self, flow_id: str) -> Optional[Dict[str, Any]]:
        """Send an OAuth flow to the analyzer.

        Args:
            flow_id: OAuth flow ID.

        Returns:
            Dictionary with analysis results, or None.
        """
        flow = self._oauth_manager.get_flow(flow_id)
        if not flow:
            return None

        findings = self._oauth_manager.scan_flow(flow_id)
        timeline = self._oauth_manager.generate_timeline(flow_id)

        return {
            "flow": flow.to_dict(),
            "findings": [f.to_dict() for f in findings],
            "timeline": timeline,
        }

    def register_callback(
        self,
        event_type: IntegrationEventType,
        callback: Callable[[IntegrationEvent], None],
    ) -> None:
        """Register an event callback.

        Args:
            event_type: Event type to subscribe to.
            callback: Callback function.
        """
        if event_type not in self._event_callbacks:
            self._event_callbacks[event_type] = []
        self._event_callbacks[event_type].append(callback)

    def _emit_event(
        self,
        event_type: IntegrationEventType,
        data: Dict[str, Any],
    ) -> None:
        """Emit an integration event.

        Args:
            event_type: Event type.
            data: Event data.
        """
        event = IntegrationEvent(
            event_type=event_type,
            data=data,
        )

        callbacks = self._event_callbacks.get(event_type, [])
        for callback in callbacks:
            try:
                callback(event)
            except Exception as e:
                logger.error(f"Event callback failed: {e}")

    def get_detected_tokens(self) -> List[JWTToken]:
        """Get all detected JWT tokens.

        Returns:
            List of JWTToken.
        """
        return self._detected_tokens.copy()

    def get_detected_flows(self) -> List[OAuthFlow]:
        """Get all detected OAuth flows.

        Returns:
            List of OAuthFlow.
        """
        return self._detected_flows.copy()

    def get_status(self) -> Dict[str, Any]:
        """Get integration status.

        Returns:
            Dictionary with status summary.
        """
        return {
            "detected_tokens": len(self._detected_tokens),
            "detected_flows": len(self._detected_flows),
            "jwt_editor": self._jwt_manager.get_status(),
            "oauth_analyzer": self._oauth_manager.get_status(),
        }


# =============================================================================
# Fuzzer Integration
# =============================================================================

class FuzzerIntegration:
    """Integration with Fuzzer for fuzztag generation and dictionary rotation.

    Generates Fuzztags for JWT attacks and OAuth redirect URI testing,
    and provides dictionary rotation capabilities.

    Attributes:
        _jwt_manager: JWT editor manager
        _fuzztags: Registered fuzztags
    """

    def __init__(
        self,
        jwt_manager: Optional[JWTEditorManager] = None,
    ) -> None:
        """Initialize the FuzzerIntegration.

        Args:
            jwt_manager: JWT editor manager.
        """
        self._jwt_manager = jwt_manager or get_jwt_editor_manager()
        self._fuzztags: Dict[str, FuzztagDefinition] = {}
        self._register_default_fuzztags()

    def _register_default_fuzztags(self) -> None:
        """Register default fuzztags."""
        fuzztags = [
            FuzztagDefinition(
                tag_name="jwt_none",
                description="Replace JWT with alg=none variant",
                generator=lambda t: self._jwt_manager.attack_none(t).modified_token,
                attack_type=AttackType.ALG_NONE,
            ),
            FuzztagDefinition(
                tag_name="jwt_alg_confusion",
                description="Replace JWT with algorithm confusion variant",
                generator=lambda t: self._jwt_manager.attack_alg_confusion(
                    t, "public_key_placeholder"
                ).modified_token,
                attack_type=AttackType.ALG_CONFUSION,
            ),
            FuzztagDefinition(
                tag_name="jwt_kid_injection",
                description="Replace JWT with kid path traversal injection",
                generator=lambda t: self._jwt_manager.attack_kid_injection(
                    t, "../../../../etc/passwd"
                ).modified_token,
                attack_type=AttackType.KID_INJECTION,
            ),
            FuzztagDefinition(
                tag_name="jwt_jwks_spoofing",
                description="Replace JWT with JWKS spoofing variant",
                generator=lambda t: self._jwt_manager.attack_jwks_spoofing(
                    t, "http://attacker.com/jwks.json"
                ).modified_token,
                attack_type=AttackType.JWKS_SPOOFING,
            ),
            FuzztagDefinition(
                tag_name="jwt_weak_secret",
                description="Mark JWT for weak secret brute-force",
                generator=lambda t: t,
                attack_type=AttackType.WEAK_SECRET,
            ),
            FuzztagDefinition(
                tag_name="jwt_claim_tamper",
                description="Replace JWT with tampered claims (admin=true)",
                generator=lambda t: self._jwt_manager.attack_claim_tampering(
                    t, {"admin": True, "role": "admin"}
                ).modified_token,
                attack_type=AttackType.CLAIM_TAMPERING,
            ),
            FuzztagDefinition(
                tag_name="jwt_b64_confusion",
                description="Replace JWT with Base64 encoding confusion variant",
                generator=lambda t: self._jwt_manager.attack_b64_confusion(t).modified_token,
                attack_type=AttackType.B64_CONFUSION,
            ),
            FuzztagDefinition(
                tag_name="jwt_nested",
                description="Replace JWT with nested JWT variant",
                generator=lambda t: self._jwt_manager.attack_nested_jwt(
                    t, "nested_token_placeholder"
                ).modified_token,
                attack_type=AttackType.NESTED_JWT,
            ),
        ]

        for ft in fuzztags:
            self._fuzztags[ft.tag_name] = ft

    def generate_fuzztag(self, tag_name: str, token: str) -> Optional[str]:
        """Generate a fuzztag replacement.

        Args:
            tag_name: Fuzztag name.
            token: JWT token to transform.

        Returns:
            Transformed token, or None.
        """
        fuzztag = self._fuzztags.get(tag_name)
        if not fuzztag:
            return None

        try:
            return fuzztag.generator(token)
        except Exception as e:
            logger.error(f"Fuzztag generation failed: {e}")
            return None

    def get_available_fuzztags(self) -> List[Dict[str, str]]:
        """Get all available fuzztags.

        Returns:
            List of fuzztag definitions.
        """
        return [
            {
                "tag_name": ft.tag_name,
                "description": ft.description,
                "attack_type": ft.attack_type.value,
            }
            for ft in self._fuzztags.values()
        ]

    def generate_redirect_fuzztags(self, redirect_uri: str) -> List[Dict[str, str]]:
        """Generate redirect URI fuzztags.

        Args:
            redirect_uri: Original redirect URI.

        Returns:
            List of redirect test cases.
        """
        from .oauth_analyzer import RedirectURITester

        tester = RedirectURITester()
        results = tester.generate_test_uris(redirect_uri)

        return [
            {
                "test_uri": r.test_uri,
                "technique": r.technique,
                "tag": f"{{{{redirect_{r.technique}}}}}",
            }
            for r in results
        ]

    def process_request_with_fuzztags(
        self,
        request_body: str,
        token: str,
    ) -> List[Dict[str, str]]:
        """Process a request with all fuzztags.

        Args:
            request_body: Original request body.
            token: JWT token to fuzz.

        Returns:
            List of modified request bodies.
        """
        results: List[Dict[str, str]] = []

        for tag_name, fuzztag in self._fuzztags.items():
            try:
                modified_token = fuzztag.generator(token)
                modified_body = request_body.replace(token, modified_token)
                results.append({
                    "tag": tag_name,
                    "body": modified_body,
                })
            except Exception as e:
                logger.error(f"Fuzztag {tag_name} failed: {e}")

        return results


# =============================================================================
# Reverse Callback Platform Integration
# =============================================================================

class ReverseCallbackIntegration:
    """Integration with reverse callback platform for JWKS spoofing
    and OAuth redirect testing.

    Manages callback endpoints, receives callbacks,
    and updates vulnerability status.

    Attributes:
        _endpoints: Active callback endpoints
        _callback_history: Received callback history
        _callback_server: Callback server instance
    """

    def __init__(self) -> None:
        """Initialize the ReverseCallbackIntegration."""
        self._endpoints: Dict[str, CallbackEndpoint] = {}
        self._callback_history: List[Dict[str, Any]] = []
        self._callback_server: Optional[Any] = None

    def create_callback_endpoint(
        self,
        callback_type: CallbackType,
        custom_url: str = "",
    ) -> CallbackEndpoint:
        """Create a new callback endpoint.

        Args:
            callback_type: Callback type.
            custom_url: Custom callback URL.

        Returns:
            Created CallbackEndpoint.
        """
        import hashlib

        endpoint_id = hashlib.md5(
            f"{callback_type.value}{time.time()}".encode()
        ).hexdigest()[:12]

        url = custom_url or f"http://callback.example.com/{endpoint_id}"

        endpoint = CallbackEndpoint(
            endpoint_id=endpoint_id,
            callback_type=callback_type,
            url=url,
            is_active=True,
            created_at=time.time(),
        )

        self._endpoints[endpoint_id] = endpoint

        logger.info(f"Created callback endpoint: {endpoint_id} ({url})")

        return endpoint

    def create_jwks_callback(
        self,
        public_key: str = "",
        private_key: str = "",
    ) -> CallbackEndpoint:
        """Create a JWKS spoofing callback endpoint.

        Args:
            public_key: Public key to serve.
            private_key: Private key for signing.

        Returns:
            Created CallbackEndpoint.
        """
        endpoint = self.create_callback_endpoint(CallbackType.JWKS_SPOOFING)

        jwks_response = self._generate_jwks_response(public_key)
        endpoint.url = f"{endpoint.url}/jwks.json"

        logger.info(f"JWKS callback endpoint ready: {endpoint.url}")

        return endpoint

    def create_oauth_redirect_callback(self) -> CallbackEndpoint:
        """Create an OAuth redirect callback endpoint.

        Returns:
            Created CallbackEndpoint.
        """
        endpoint = self.create_callback_endpoint(CallbackType.OAUTH_REDIRECT)
        endpoint.url = f"{endpoint.url}/callback"

        logger.info(f"OAuth redirect callback ready: {endpoint.url}")

        return endpoint

    def process_callback(
        self,
        endpoint_id: str,
        callback_data: Dict[str, Any],
    ) -> None:
        """Process a received callback.

        Args:
            endpoint_id: Endpoint ID.
            callback_data: Callback data.
        """
        endpoint = self._endpoints.get(endpoint_id)
        if not endpoint:
            logger.warning(f"Unknown callback endpoint: {endpoint_id}")
            return

        endpoint.received_callbacks += 1

        callback_record = {
            "endpoint_id": endpoint_id,
            "callback_type": endpoint.callback_type.value,
            "timestamp": time.time(),
            "data": callback_data,
        }

        self._callback_history.append(callback_record)

        logger.info(
            f"Received callback on {endpoint_id}: "
            f"{endpoint.callback_type.value}"
        )

    def get_callback_history(
        self,
        endpoint_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Get callback history.

        Args:
            endpoint_id: Filter by endpoint ID.

        Returns:
            List of callback records.
        """
        if endpoint_id:
            return [
                c for c in self._callback_history
                if c["endpoint_id"] == endpoint_id
            ]
        return self._callback_history.copy()

    def get_active_endpoints(self) -> List[CallbackEndpoint]:
        """Get all active endpoints.

        Returns:
            List of active CallbackEndpoint.
        """
        return [e for e in self._endpoints.values() if e.is_active]

    def _generate_jwks_response(self, public_key: str = "") -> Dict[str, Any]:
        """Generate a JWK Set response.

        Args:
            public_key: Public key to include.

        Returns:
            JWK Set dictionary.
        """
        import base64

        n = base64.urlsafe_b64encode(b"fake_modulus").decode().rstrip("=")
        e = base64.urlsafe_b64encode(b"AQAB").decode().rstrip("=")

        return {
            "keys": [
                {
                    "kty": "RSA",
                    "kid": "attacker-key-1",
                    "use": "sig",
                    "alg": "RS256",
                    "n": n,
                    "e": e,
                }
            ]
        }

    def get_status(self) -> Dict[str, Any]:
        """Get callback integration status.

        Returns:
            Dictionary with status summary.
        """
        return {
            "active_endpoints": len(self.get_active_endpoints()),
            "total_callbacks": len(self._callback_history),
            "endpoints": [
                {
                    "id": e.endpoint_id,
                    "type": e.callback_type.value,
                    "url": e.url,
                    "callbacks": e.received_callbacks,
                }
                for e in self._endpoints.values()
            ],
        }


# =============================================================================
# Report Integration
# =============================================================================

class ReportIntegration:
    """Integration with report module for structured vulnerability output.

    Converts JWT/OAuth findings into structured reports with
    MITRE ATT&CK mapping and remediation recommendations.

    Attributes:
        _reports: Generated reports
    """

    def __init__(self) -> None:
        """Initialize the ReportIntegration."""
        self._reports: List[VulnerabilityReport] = []

    def create_jwt_report(
        self,
        attack_result: AttackResult,
        affected_url: str = "",
        affected_request: str = "",
    ) -> VulnerabilityReport:
        """Create a vulnerability report from a JWT attack result.

        Args:
            attack_result: JWT attack result.
            affected_url: Affected URL.
            affected_request: Affected request.

        Returns:
            Generated VulnerabilityReport.
        """
        import hashlib

        vuln_id = hashlib.md5(
            f"{attack_result.attack_type.value}{time.time()}".encode()
        ).hexdigest()[:12]

        severity_map = {
            JWTSeverity.LOW: "low",
            JWTSeverity.MEDIUM: "medium",
            JWTSeverity.HIGH: "high",
            JWTSeverity.CRITICAL: "critical",
        }

        report = VulnerabilityReport(
            vuln_id=f"JWT-{vuln_id.upper()}",
            vuln_type=attack_result.attack_type.value,
            severity=severity_map.get(attack_result.severity, "medium"),
            title=f"JWT {attack_result.attack_type.value} 漏洞",
            description=self._get_jwt_description(attack_result.attack_type),
            evidence=attack_result.details,
            mitre_id=attack_result.mitre_id,
            recommendation=attack_result.recommendation,
            affected_url=affected_url,
            affected_request=affected_request,
            timestamp=time.time(),
        )

        self._reports.append(report)
        return report

    def create_oauth_report(
        self,
        finding: OAuthVulnerabilityFinding,
        affected_url: str = "",
        affected_request: str = "",
    ) -> VulnerabilityReport:
        """Create a vulnerability report from an OAuth finding.

        Args:
            finding: OAuth vulnerability finding.
            affected_url: Affected URL.
            affected_request: Affected request.

        Returns:
            Generated VulnerabilityReport.
        """
        import hashlib

        vuln_id = hashlib.md5(
            f"{finding.vuln_type.value}{time.time()}".encode()
        ).hexdigest()[:12]

        severity_map = {
            OAuthSeverity.LOW: "low",
            OAuthSeverity.MEDIUM: "medium",
            OAuthSeverity.HIGH: "high",
            OAuthSeverity.CRITICAL: "critical",
        }

        report = VulnerabilityReport(
            vuln_id=f"OAUTH-{vuln_id.upper()}",
            vuln_type=finding.vuln_type.value,
            severity=severity_map.get(finding.severity, "medium"),
            title=f"OAuth {finding.vuln_type.value} 漏洞",
            description=finding.description,
            evidence=finding.evidence,
            mitre_id=finding.mitre_id,
            recommendation=finding.recommendation,
            affected_url=affected_url,
            affected_request=affected_request,
            timestamp=time.time(),
        )

        self._reports.append(report)
        return report

    def get_reports(
        self,
        vuln_type: Optional[str] = None,
        severity: Optional[str] = None,
    ) -> List[VulnerabilityReport]:
        """Get vulnerability reports.

        Args:
            vuln_type: Filter by vulnerability type.
            severity: Filter by severity.

        Returns:
            List of VulnerabilityReport.
        """
        reports = self._reports

        if vuln_type:
            reports = [r for r in reports if r.vuln_type == vuln_type]

        if severity:
            reports = [r for r in reports if r.severity == severity]

        return reports

    def export_reports(self, format: str = "json") -> str:
        """Export reports in specified format.

        Args:
            format: Export format (json, csv).

        Returns:
            Exported report string.
        """
        if format == "json":
            return json.dumps(
                [r.to_dict() for r in self._reports],
                indent=2,
                ensure_ascii=False,
            )
        elif format == "csv":
            headers = [
                "vuln_id", "vuln_type", "severity", "title",
                "mitre_id", "affected_url", "timestamp",
            ]
            lines = [",".join(headers)]
            for r in self._reports:
                row = [
                    r.vuln_id, r.vuln_type, r.severity,
                    r.title, r.mitre_id, r.affected_url,
                    str(r.timestamp),
                ]
                lines.append(",".join(row))
            return "\n".join(lines)

        return ""

    def _get_jwt_description(self, attack_type: AttackType) -> str:
        """Get description for JWT attack type.

        Args:
            attack_type: Attack type.

        Returns:
            Description string.
        """
        descriptions = {
            AttackType.ALG_NONE: "JWT alg=none攻击允许攻击者绕过签名验证，通过设置算法为none来伪造任意JWT。",
            AttackType.ALG_CONFUSION: "JWT算法混淆攻击利用服务器对非对称算法和对称算法的处理差异，使用公钥作为HMAC密钥伪造JWT。",
            AttackType.KID_INJECTION: "JWT kid参数注入攻击通过修改密钥ID字段实施路径遍历或SQL注入，可能导致服务器加载恶意密钥。",
            AttackType.JWKS_SPOOFING: "JWT JWKS欺骗攻击通过控制jku/x5u字段让服务器从攻击者控制的URL加载JWK，从而伪造有效JWT。",
            AttackType.WEAK_SECRET: "JWT弱密钥爆破攻击通过字典攻击破解HMAC签名密钥，成功后可伪造任意JWT。",
            AttackType.CLAIM_TAMPERING: "JWT声明篡改攻击通过修改Payload中的权限声明（如role、admin）实现越权访问。",
            AttackType.CROSS_SERVICE: "JWT跨服务中继攻击检测同一个JWT是否被多个服务接受，可能存在权限差异。",
            AttackType.B64_CONFUSION: "JWT Base64混淆攻击测试目标解析器是否正确处理标准Base64与URL-safe Base64的差异。",
            AttackType.NESTED_JWT: "JWT嵌套攻击通过cty字段声明嵌套JWT，测试服务器是否正确递归验证内层令牌。",
        }
        return descriptions.get(attack_type, "JWT安全漏洞")


# =============================================================================
# JWT/OAuth Integration Manager
# =============================================================================

class JWTOAuthIntegrationManager:
    """Main JWT/OAuth integration coordination engine.

    Integrates MITM proxy, Fuzzer, reverse callback platform,
    and report modules for comprehensive JWT/OAuth testing.

    Attributes:
        _mitm_integration: MITM proxy integration
        _fuzzer_integration: Fuzzer integration
        _callback_integration: Reverse callback integration
        _report_integration: Report integration
    """

    def __init__(self) -> None:
        """Initialize the JWTOAuthIntegrationManager."""
        self._mitm_integration = MITMProxyIntegration()
        self._fuzzer_integration = FuzzerIntegration()
        self._callback_integration = ReverseCallbackIntegration()
        self._report_integration = ReportIntegration()

    @property
    def mitm(self) -> MITMProxyIntegration:
        """Get MITM proxy integration.

        Returns:
            MITMProxyIntegration instance.
        """
        return self._mitm_integration

    @property
    def fuzzer(self) -> FuzzerIntegration:
        """Get Fuzzer integration.

        Returns:
            FuzzerIntegration instance.
        """
        return self._fuzzer_integration

    @property
    def callback(self) -> ReverseCallbackIntegration:
        """Get reverse callback integration.

        Returns:
            ReverseCallbackIntegration instance.
        """
        return self._callback_integration

    @property
    def report(self) -> ReportIntegration:
        """Get report integration.

        Returns:
            ReportIntegration instance.
        """
        return self._report_integration

    def process_proxy_traffic(
        self,
        url: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        body: Optional[str] = None,
        request_id: str = "",
    ) -> Dict[str, Any]:
        """Process proxy traffic for JWT/OAuth detection.

        Args:
            url: Request URL.
            method: HTTP method.
            headers: Request headers.
            cookies: Cookie dictionary.
            body: Request body.
            request_id: Source request ID.

        Returns:
            Dictionary with detection results.
        """
        return self._mitm_integration.process_proxy_request(
            url=url,
            method=method,
            headers=headers,
            cookies=cookies,
            body=body,
            request_id=request_id,
        )

    def generate_fuzztags(self, token: str) -> List[Dict[str, str]]:
        """Generate all available fuzztags for a token.

        Args:
            token: JWT token.

        Returns:
            List of fuzztag definitions.
        """
        return self._fuzzer_integration.get_available_fuzztags()

    def create_callback_endpoint(
        self,
        callback_type: CallbackType,
    ) -> CallbackEndpoint:
        """Create a reverse callback endpoint.

        Args:
            callback_type: Callback type.

        Returns:
            Created CallbackEndpoint.
        """
        return self._callback_integration.create_callback_endpoint(callback_type)

    def generate_report(
        self,
        attack_result: Optional[AttackResult] = None,
        oauth_finding: Optional[OAuthVulnerabilityFinding] = None,
        affected_url: str = "",
        affected_request: str = "",
    ) -> Optional[VulnerabilityReport]:
        """Generate a vulnerability report.

        Args:
            attack_result: JWT attack result.
            oauth_finding: OAuth vulnerability finding.
            affected_url: Affected URL.
            affected_request: Affected request.

        Returns:
            Generated VulnerabilityReport, or None.
        """
        if attack_result:
            return self._report_integration.create_jwt_report(
                attack_result, affected_url, affected_request,
            )
        elif oauth_finding:
            return self._report_integration.create_oauth_report(
                oauth_finding, affected_url, affected_request,
            )
        return None

    def get_status(self) -> Dict[str, Any]:
        """Get integration status.

        Returns:
            Dictionary with status summary.
        """
        return {
            "mitm": self._mitm_integration.get_status(),
            "fuzzer": {
                "available_fuzztags": len(
                    self._fuzzer_integration.get_available_fuzztags()
                ),
            },
            "callback": self._callback_integration.get_status(),
            "reports": len(self._report_integration.get_reports()),
        }


# =============================================================================
# Global Singleton
# =============================================================================

_integration_manager: Optional[JWTOAuthIntegrationManager] = None


def get_integration_manager() -> JWTOAuthIntegrationManager:
    """Get the global JWTOAuthIntegrationManager singleton.

    Returns:
        Singleton JWTOAuthIntegrationManager instance.
    """
    global _integration_manager
    if _integration_manager is None:
        _integration_manager = JWTOAuthIntegrationManager()
    return _integration_manager


__all__ = [
    "JWTOAuthIntegrationManager",
    "MITMProxyIntegration",
    "FuzzerIntegration",
    "ReverseCallbackIntegration",
    "ReportIntegration",
    "IntegrationEvent",
    "VulnerabilityReport",
    "FuzztagDefinition",
    "CallbackEndpoint",
    "IntegrationEventType",
    "CallbackType",
    "get_integration_manager",
]
