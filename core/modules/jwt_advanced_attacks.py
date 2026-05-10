"""
JWT Advanced Attacks Module - Cross-service confusion, nested JWT, SAML/OIDC hybrid exploitation.

This module provides:
    1. Cross-service token confusion detection
    2. Nested JWT parsing and manipulation
    3. JWT/SAML/OIDC hybrid exploitation
    4. Token chain analysis and attack graph generation

Integration points:
    - MITM proxy traffic capture
    - JWT Editor module
    - OAuth Analyzer module
    - PoC verification engine

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

class AdvancedAttackType(str, Enum):
    """Advanced JWT attack types."""

    CROSS_SERVICE = "cross_service"
    NESTED_JWT = "nested_jwt"
    SAML_JWT_HYBRID = "saml_jwt_hybrid"
    TOKEN_CHAIN = "token_chain"
    PERMISSION_CONFUSION = "permission_confusion"


class ServiceRole(str, Enum):
    """Service role classification."""

    ADMIN = "admin"
    USER = "user"
    SERVICE = "service"
    UNKNOWN = "unknown"


class TokenChainStep(str, Enum):
    """Token chain step types."""

    AUTHORIZATION_CODE = "authorization_code"
    ACCESS_TOKEN = "access_token"
    REFRESH_TOKEN = "refresh_token"
    NEW_ACCESS_TOKEN = "new_access_token"
    RESOURCE_ACCESS = "resource_access"


# =============================================================================
# Data Classes
# =============================================================================

@dataclass
class ServiceEndpoint:
    """Service endpoint representation.

    Attributes:
        url: Service URL
        name: Service name
        domain: Service domain
        role_in_response: Detected role from response
        response_status: HTTP response status
        response_headers: Response headers
        timestamp: Detection timestamp
    """

    url: str = ""
    name: str = ""
    domain: str = ""
    role_in_response: str = ""
    response_status: int = 0
    response_headers: Dict[str, str] = field(default_factory=dict)
    timestamp: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary.

        Returns:
            Dictionary representation.
        """
        return {
            "url": self.url,
            "name": self.name,
            "domain": self.domain,
            "role": self.role_in_response,
            "status": self.response_status,
            "timestamp": self.timestamp,
        }


@dataclass
class CrossServiceFinding:
    """Cross-service token confusion finding.

    Attributes:
        finding_id: Unique finding ID
        jwt_token: Original JWT token
        services_tested: List of tested services
        permission_differences: Permission differences detected
        severity: Finding severity
        description: Finding description
        recommendation: Remediation recommendation
    """

    finding_id: str = ""
    jwt_token: str = ""
    services_tested: List[ServiceEndpoint] = field(default_factory=list)
    permission_differences: List[Dict[str, Any]] = field(default_factory=list)
    severity: str = "high"
    description: str = ""
    recommendation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary.

        Returns:
            Dictionary representation.
        """
        return {
            "finding_id": self.finding_id,
            "jwt_token": self.jwt_token[:50] + "..." if len(self.jwt_token) > 50 else self.jwt_token,
            "services_tested": [s.to_dict() for s in self.services_tested],
            "permission_differences": self.permission_differences,
            "severity": self.severity,
            "description": self.description,
            "recommendation": self.recommendation,
        }


@dataclass
class NestedJWTLayer:
    """Nested JWT layer representation.

    Attributes:
        layer_index: Layer index (0 = outermost)
        header: JWT header dictionary
        payload: JWT payload dictionary
        signature: JWT signature
        raw_token: Raw JWT token string
        children: Child nested JWTs
    """

    layer_index: int = 0
    header: Dict[str, Any] = field(default_factory=dict)
    payload: Dict[str, Any] = field(default_factory=dict)
    signature: str = ""
    raw_token: str = ""
    children: List[NestedJWTLayer] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary.

        Returns:
            Dictionary representation.
        """
        return {
            "layer_index": self.layer_index,
            "header": self.header,
            "payload": self.payload,
            "signature": self.signature[:20] + "..." if len(self.signature) > 20 else self.signature,
            "children": [c.to_dict() for c in self.children],
        }


@dataclass
class TokenChainNode:
    """Token chain node representation.

    Attributes:
        step_type: Chain step type
        token_value: Token value at this step
        timestamp: Step timestamp
        service_url: Service URL
        response_data: Response data
        can_skip: Whether this step can be skipped
        can_replay: Whether this step can be replayed
    """

    step_type: TokenChainStep = TokenChainStep.AUTHORIZATION_CODE
    token_value: str = ""
    timestamp: float = 0.0
    service_url: str = ""
    response_data: Dict[str, Any] = field(default_factory=dict)
    can_skip: bool = False
    can_replay: bool = False

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary.

        Returns:
            Dictionary representation.
        """
        return {
            "step_type": self.step_type.value,
            "token_value": self.token_value[:50] + "..." if len(self.token_value) > 50 else self.token_value,
            "timestamp": self.timestamp,
            "service_url": self.service_url,
            "can_skip": self.can_skip,
            "can_replay": self.can_replay,
        }


@dataclass
class TokenChainGraph:
    """Token chain attack graph.

    Attributes:
        chain_id: Unique chain ID
        nodes: Chain nodes
        edges: Chain edges (from_index, to_index, attack_type)
        vulnerabilities: Detected vulnerabilities
        attack_paths: Possible attack paths
    """

    chain_id: str = ""
    nodes: List[TokenChainNode] = field(default_factory=list)
    edges: List[Tuple[int, int, str]] = field(default_factory=list)
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    attack_paths: List[List[int]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary.

        Returns:
            Dictionary representation.
        """
        return {
            "chain_id": self.chain_id,
            "nodes": [n.to_dict() for n in self.nodes],
            "edges": [{"from": e[0], "to": e[1], "type": e[2]} for e in self.edges],
            "vulnerabilities": self.vulnerabilities,
            "attack_paths": self.attack_paths,
        }


# =============================================================================
# Cross-Service Token Confusion Detector
# =============================================================================

class CrossServiceDetector:
    """Detects cross-service JWT token confusion.

    Tests whether the same JWT is accepted by multiple
    different services with varying permission levels.

    Attributes:
        _tested_tokens: Tokens that have been tested
        _findings: Detected findings
        _service_cache: Cached service endpoints
    """

    def __init__(self) -> None:
        """Initialize the CrossServiceDetector."""
        self._tested_tokens: Set[str] = set()
        self._findings: List[CrossServiceFinding] = []
        self._service_cache: Dict[str, ServiceEndpoint] = {}
        self._finding_counter = 0

    async def test_token_across_services(
        self,
        jwt_token: str,
        service_urls: List[str],
        headers_template: Optional[Dict[str, str]] = None,
    ) -> CrossServiceFinding:
        """Test a JWT token across multiple services.

        Args:
            jwt_token: JWT token to test.
            service_urls: List of service URLs to test.
            headers_template: Base headers template.

        Returns:
            CrossServiceFinding with test results.
        """
        self._tested_tokens.add(jwt_token)
        self._finding_counter += 1

        finding = CrossServiceFinding(
            finding_id=f"CROSS-SVC-{self._finding_counter:04d}",
            jwt_token=jwt_token,
        )

        services_tested: List[ServiceEndpoint] = []
        permission_map: Dict[str, Any] = {}

        async def test_single_service(url: str) -> Optional[ServiceEndpoint]:
            """Test token against a single service.

            Args:
                url: Service URL to test.

            Returns:
                ServiceEndpoint if tested, None otherwise.
            """
            try:
                import aiohttp

                headers = headers_template.copy() if headers_template else {}
                headers["Authorization"] = f"Bearer {jwt_token}"

                async with aiohttp.ClientSession() as session:
                    async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                        body = await resp.text()
                        endpoint = ServiceEndpoint(
                            url=url,
                            name=urlparse(url).hostname or "",
                            domain=urlparse(url).hostname or "",
                            response_status=resp.status,
                            response_headers=dict(resp.headers),
                            timestamp=time.time(),
                        )

                        role = self._extract_role_from_response(body, dict(resp.headers))
                        endpoint.role_in_response = role
                        permission_map[url] = {
                            "role": role,
                            "status": resp.status,
                            "permissions": self._extract_permissions(body),
                        }

                        return endpoint
            except Exception as e:
                logger.error(f"Failed to test service {url}: {e}")
                return None

        tasks = [test_single_service(url) for url in service_urls]
        results = await asyncio.gather(*tasks)

        for result in results:
            if result:
                services_tested.append(result)

        finding.services_tested = services_tested

        permission_diffs = self._analyze_permission_differences(permission_map)
        finding.permission_differences = permission_diffs

        if permission_diffs:
            finding.severity = "critical"
            finding.description = (
                f"JWT被多个服务接受且权限不同，存在跨服务权限混淆漏洞。"
                f"发现{len(permission_diffs)}个权限差异。"
            )
            finding.recommendation = (
                "各服务应独立验证JWT的权限声明，避免依赖单一令牌。"
                "实施服务间权限隔离和最小权限原则。"
            )
        else:
            finding.severity = "low"
            finding.description = "JWT在多个服务中权限一致，未发现跨服务混淆。"
            finding.recommendation = ""

        self._findings.append(finding)
        return finding

    def _extract_role_from_response(
        self, body: str, headers: Dict[str, str],
    ) -> str:
        """Extract role information from response.

        Args:
            body: Response body.
            headers: Response headers.

        Returns:
            Extracted role string.
        """
        body_lower = body.lower()

        role_indicators = {
            "admin": ["admin", "administrator", "superuser", "root"],
            "user": ["user", "member", "customer"],
            "service": ["service", "api", "system"],
        }

        for role, keywords in role_indicators.items():
            if any(kw in body_lower for kw in keywords):
                return role

        return ServiceRole.UNKNOWN.value

    def _extract_permissions(self, body: str) -> List[str]:
        """Extract permissions from response body.

        Args:
            body: Response body.

        Returns:
            List of permission strings.
        """
        permissions: List[str] = []

        try:
            data = json.loads(body)
            if isinstance(data, dict):
                for key in ["permissions", "scopes", "roles", "access"]:
                    if key in data:
                        value = data[key]
                        if isinstance(value, list):
                            permissions.extend([str(v) for v in value])
                        elif isinstance(value, str):
                            permissions.append(value)
        except (json.JSONDecodeError, TypeError):
            pass

        return permissions

    def _analyze_permission_differences(
        self, permission_map: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """Analyze permission differences across services.

        Args:
            permission_map: Map of URL to permission data.

        Returns:
            List of permission differences.
        """
        differences: List[Dict[str, Any]] = []

        if len(permission_map) < 2:
            return differences

        urls = list(permission_map.keys())
        for i in range(len(urls)):
            for j in range(i + 1, len(urls)):
                url_a = urls[i]
                url_b = urls[j]

                role_a = permission_map[url_a].get("role", "")
                role_b = permission_map[url_b].get("role", "")

                if role_a != role_b:
                    differences.append({
                        "service_a": url_a,
                        "service_b": url_b,
                        "role_a": role_a,
                        "role_b": role_b,
                        "type": "role_mismatch",
                    })

                perms_a = set(permission_map[url_a].get("permissions", []))
                perms_b = set(permission_map[url_b].get("permissions", []))

                if perms_a != perms_b:
                    only_in_a = perms_a - perms_b
                    only_in_b = perms_b - perms_a

                    if only_in_a or only_in_b:
                        differences.append({
                            "service_a": url_a,
                            "service_b": url_b,
                            "only_in_a": list(only_in_a),
                            "only_in_b": list(only_in_b),
                            "type": "permission_mismatch",
                        })

        return differences

    def get_findings(self) -> List[CrossServiceFinding]:
        """Get all cross-service findings.

        Returns:
            List of CrossServiceFinding.
        """
        return self._findings.copy()


# =============================================================================
# Nested JWT Parser and Manipulator
# =============================================================================

class NestedJWTHandler:
    """Handles nested JWT parsing and manipulation.

    Supports multi-layer JWT structures where JWT payloads
    contain other JWT tokens.

    Attributes:
        _parsed_trees: Parsed JWT trees
        _modification_history: Modification history
    """

    def __init__(self) -> None:
        """Initialize the NestedJWTHandler."""
        self._parsed_trees: List[NestedJWTLayer] = []
        self._modification_history: List[Dict[str, Any]] = []

    def parse_nested_jwt(self, token: str, max_depth: int = 5) -> Optional[NestedJWTLayer]:
        """Parse a potentially nested JWT structure.

        Args:
            token: JWT token to parse.
            max_depth: Maximum nesting depth to parse.

        Returns:
            NestedJWTLayer tree, or None if parsing fails.
        """
        try:
            return self._parse_layer(token, 0, max_depth)
        except Exception as e:
            logger.error(f"Failed to parse nested JWT: {e}")
            return None

    def _parse_layer(
        self, token: str, current_depth: int, max_depth: int,
    ) -> Optional[NestedJWTLayer]:
        """Parse a single JWT layer.

        Args:
            token: JWT token string.
            current_depth: Current nesting depth.
            max_depth: Maximum allowed depth.

        Returns:
            NestedJWTLayer or None.
        """
        if current_depth >= max_depth:
            return None

        parts = token.split(".")
        if len(parts) != 3:
            return None

        try:
            header_json = self._base64url_decode(parts[0])
            payload_json = self._base64url_decode(parts[1])

            header = json.loads(header_json)
            payload = json.loads(payload_json)

            layer = NestedJWTLayer(
                layer_index=current_depth,
                header=header,
                payload=payload,
                signature=parts[2],
                raw_token=token,
            )

            for key, value in payload.items():
                if isinstance(value, str) and self._looks_like_jwt(value):
                    child = self._parse_layer(value, current_depth + 1, max_depth)
                    if child:
                        layer.children.append(child)

            if current_depth == 0:
                self._parsed_trees.append(layer)

            return layer
        except Exception as e:
            logger.error(f"Failed to parse JWT layer {current_depth}: {e}")
            return None

    def modify_layer(
        self,
        tree: NestedJWTLayer,
        layer_index: int,
        modifications: Dict[str, Any],
    ) -> Optional[str]:
        """Modify a specific layer in the JWT tree.

        Args:
            tree: JWT tree to modify.
            layer_index: Index of layer to modify.
            modifications: Payload modifications.

        Returns:
            Reconstructed JWT token, or None.
        """
        target_layer = self._find_layer(tree, layer_index)
        if not target_layer:
            return None

        target_layer.payload.update(modifications)

        self._modification_history.append({
            "layer_index": layer_index,
            "modifications": modifications,
            "timestamp": time.time(),
        })

        return self._rebuild_jwt(tree)

    def _find_layer(
        self, tree: NestedJWTLayer, target_index: int,
    ) -> Optional[NestedJWTLayer]:
        """Find a layer by index in the tree.

        Args:
            tree: Root of the JWT tree.
            target_index: Target layer index.

        Returns:
            NestedJWTLayer if found, None otherwise.
        """
        if tree.layer_index == target_index:
            return tree

        for child in tree.children:
            found = self._find_layer(child, target_index)
            if found:
                return found

        return None

    def _rebuild_jwt(self, tree: NestedJWTLayer) -> Optional[str]:
        """Rebuild JWT from tree structure.

        Args:
            tree: JWT tree to rebuild.

        Returns:
            Rebuilt JWT token, or None.
        """
        try:
            header_b64 = self._base64url_encode(json.dumps(tree.header))
            payload_b64 = self._base64url_encode(json.dumps(tree.payload))

            signature = tree.signature
            if not signature:
                signature = ""

            return f"{header_b64}.{payload_b64}.{signature}"
        except Exception as e:
            logger.error(f"Failed to rebuild JWT: {e}")
            return None

    def _looks_like_jwt(self, value: str) -> bool:
        """Check if a string looks like a JWT.

        Args:
            value: String to check.

        Returns:
            True if string appears to be a JWT.
        """
        parts = value.split(".")
        if len(parts) != 3:
            return False

        try:
            for part in parts[:2]:
                decoded = self._base64url_decode(part)
                json.loads(decoded)
            return True
        except Exception:
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

    def get_parsed_trees(self) -> List[NestedJWTLayer]:
        """Get all parsed JWT trees.

        Returns:
            List of NestedJWTLayer trees.
        """
        return self._parsed_trees.copy()


# =============================================================================
# SAML/OIDC Hybrid Exploitation
# =============================================================================

class SAMLOIDCHybridTester:
    """Tests JWT/SAML/OIDC hybrid exploitation scenarios.

    Analyzes trust boundaries between different authentication
    mechanisms and tests for privilege escalation opportunities.

    Attributes:
        _test_results: Test results
        _trust_boundaries: Detected trust boundaries
    """

    def __init__(self) -> None:
        """Initialize the SAMLOIDCHybridTester."""
        self._test_results: List[Dict[str, Any]] = []
        self._trust_boundaries: List[Dict[str, Any]] = []

    async def test_saml_to_jwt_escalation(
        self,
        saml_assertion: str,
        jwt_endpoint: str,
        headers: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """Test if a low-privilege SAML assertion can obtain a high-privilege JWT.

        Args:
            saml_assertion: SAML assertion to test.
            jwt_endpoint: JWT token endpoint.
            headers: Additional headers.

        Returns:
            Test result dictionary.
        """
        result: Dict[str, Any] = {
            "test_type": "saml_to_jwt_escalation",
            "success": False,
            "details": {},
            "timestamp": time.time(),
        }

        try:
            import aiohttp

            request_headers = headers.copy() if headers else {}
            request_headers["Content-Type"] = "application/x-www-form-urlencoded"

            payload = f"grant_type=urn:ietf:params:oauth:grant-type:saml2-bearer&assertion={saml_assertion}"

            async with aiohttp.ClientSession() as session:
                async with session.post(
                    jwt_endpoint,
                    headers=request_headers,
                    data=payload,
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as resp:
                    body = await resp.text()
                    result["status_code"] = resp.status
                    result["response"] = body

                    if resp.status == 200:
                        try:
                            token_data = json.loads(body)
                            if "access_token" in token_data:
                                result["success"] = True
                                result["details"] = {
                                    "token_type": token_data.get("token_type", ""),
                                    "scope": token_data.get("scope", ""),
                                    "expires_in": token_data.get("expires_in", 0),
                                }
                        except json.JSONDecodeError:
                            pass
        except Exception as e:
            logger.error(f"SAML to JWT escalation test failed: {e}")
            result["error"] = str(e)

        self._test_results.append(result)
        return result

    async def test_jwt_to_saml_escalation(
        self,
        jwt_token: str,
        saml_endpoint: str,
        headers: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """Test if a JWT can be exchanged for a SAML assertion.

        Args:
            jwt_token: JWT token to test.
            saml_endpoint: SAML token endpoint.
            headers: Additional headers.

        Returns:
            Test result dictionary.
        """
        result: Dict[str, Any] = {
            "test_type": "jwt_to_saml_escalation",
            "success": False,
            "details": {},
            "timestamp": time.time(),
        }

        try:
            import aiohttp

            request_headers = headers.copy() if headers else {}
            request_headers["Authorization"] = f"Bearer {jwt_token}"
            request_headers["Content-Type"] = "application/x-www-form-urlencoded"

            payload = "grant_type=urn:ietf:params:oauth:grant-type:token-exchange&subject_token_type=urn:ietf:params:oauth:token-type:jwt"

            async with aiohttp.ClientSession() as session:
                async with session.post(
                    saml_endpoint,
                    headers=request_headers,
                    data=payload,
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as resp:
                    body = await resp.text()
                    result["status_code"] = resp.status
                    result["response"] = body

                    if resp.status == 200:
                        try:
                            token_data = json.loads(body)
                            if "issued_token_type" in token_data:
                                result["success"] = True
                                result["details"] = token_data
                        except json.JSONDecodeError:
                            pass
        except Exception as e:
            logger.error(f"JWT to SAML escalation test failed: {e}")
            result["error"] = str(e)

        self._test_results.append(result)
        return result

    def analyze_trust_boundaries(
        self,
        services: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """Analyze trust boundaries between services.

        Args:
            services: List of service configurations.

        Returns:
            List of trust boundary findings.
        """
        boundaries: List[Dict[str, Any]] = []

        auth_methods: Dict[str, List[str]] = {}
        for service in services:
            name = service.get("name", "")
            methods = service.get("auth_methods", [])

            for method in methods:
                if method not in auth_methods:
                    auth_methods[method] = []
                auth_methods[method].append(name)

        for method, service_names in auth_methods.items():
            if len(service_names) > 1:
                boundaries.append({
                    "auth_method": method,
                    "shared_services": service_names,
                    "risk": "high" if method in ["jwt", "saml"] else "medium",
                    "description": f"多个服务共享{method}认证，存在信任边界风险",
                })

        self._trust_boundaries = boundaries
        return boundaries

    def get_test_results(self) -> List[Dict[str, Any]]:
        """Get all test results.

        Returns:
            List of test result dictionaries.
        """
        return self._test_results.copy()

    def get_trust_boundaries(self) -> List[Dict[str, Any]]:
        """Get all trust boundary findings.

        Returns:
            List of trust boundary dictionaries.
        """
        return self._trust_boundaries.copy()


# =============================================================================
# Token Chain Analyzer
# =============================================================================

class TokenChainAnalyzer:
    """Analyzes complete token chains and generates attack graphs.

    Tracks the full lifecycle from initial login to resource
    access, identifying weak points in the chain.

    Attributes:
        _chains: Detected token chains
        _attack_graphs: Generated attack graphs
    """

    def __init__(self) -> None:
        """Initialize the TokenChainAnalyzer."""
        self._chains: List[TokenChainGraph] = []
        self._attack_graphs: List[Dict[str, Any]] = []
        self._chain_counter = 0

    def build_chain_from_traffic(
        self,
        traffic_entries: List[Dict[str, Any]],
    ) -> TokenChainGraph:
        """Build a token chain from captured traffic.

        Args:
            traffic_entries: List of traffic entries.

        Returns:
            TokenChainGraph representing the chain.
        """
        self._chain_counter += 1
        chain = TokenChainGraph(chain_id=f"CHAIN-{self._chain_counter:04d}")

        nodes: List[TokenChainNode] = []

        for entry in traffic_entries:
            node = self._extract_chain_node(entry)
            if node:
                nodes.append(node)

        chain.nodes = nodes

        for i in range(len(nodes) - 1):
            chain.edges.append((i, i + 1, "sequential"))

        vulnerabilities = self._analyze_chain_vulnerabilities(chain)
        chain.vulnerabilities = vulnerabilities

        attack_paths = self._find_attack_paths(chain)
        chain.attack_paths = attack_paths

        self._chains.append(chain)
        return chain

    def _extract_chain_node(self, entry: Dict[str, Any]) -> Optional[TokenChainNode]:
        """Extract a chain node from a traffic entry.

        Args:
            entry: Traffic entry dictionary.

        Returns:
            TokenChainNode or None.
        """
        url = entry.get("url", "")
        body = entry.get("body", "")
        response = entry.get("response", "")

        step_type = self._classify_step(url, body, response)
        if not step_type:
            return None

        token = self._extract_token(body, response)

        return TokenChainNode(
            step_type=step_type,
            token_value=token,
            timestamp=entry.get("timestamp", time.time()),
            service_url=url,
            response_data={"status": entry.get("status", 0)},
        )

    def _classify_step(
        self, url: str, body: str, response: str,
    ) -> Optional[TokenChainStep]:
        """Classify a traffic entry as a chain step.

        Args:
            url: Request URL.
            body: Request body.
            response: Response body.

        Returns:
            TokenChainStep or None.
        """
        url_lower = url.lower()
        body_lower = body.lower()
        response_lower = response.lower()

        if "/authorize" in url_lower and "response_type=code" in body_lower:
            return TokenChainStep.AUTHORIZATION_CODE

        if "/token" in url_lower and "grant_type=authorization_code" in body_lower:
            return TokenChainStep.ACCESS_TOKEN

        if "/token" in url_lower and "grant_type=refresh_token" in body_lower:
            return TokenChainStep.NEW_ACCESS_TOKEN

        if "refresh_token" in response_lower:
            return TokenChainStep.REFRESH_TOKEN

        if "access_token" in response_lower:
            return TokenChainStep.ACCESS_TOKEN

        return None

    def _extract_token(self, body: str, response: str) -> str:
        """Extract token from body or response.

        Args:
            body: Request body.
            response: Response body.

        Returns:
            Extracted token string.
        """
        import re

        for text in [body, response]:
            match = re.search(r'"access_token"\s*:\s*"([^"]+)"', text)
            if match:
                return match.group(1)

            match = re.search(r'"refresh_token"\s*:\s*"([^"]+)"', text)
            if match:
                return match.group(1)

            match = re.search(r"code=([^&]+)", text)
            if match:
                return match.group(1)

        return ""

    def _analyze_chain_vulnerabilities(
        self, chain: TokenChainGraph,
    ) -> List[Dict[str, Any]]:
        """Analyze vulnerabilities in a token chain.

        Args:
            chain: Token chain to analyze.

        Returns:
            List of vulnerability dictionaries.
        """
        vulnerabilities: List[Dict[str, Any]] = []

        for i, node in enumerate(chain.nodes):
            if node.step_type == TokenChainStep.AUTHORIZATION_CODE:
                if not node.can_skip:
                    vulnerabilities.append({
                        "node_index": i,
                        "type": "authorization_code_replay",
                        "severity": "high",
                        "description": "授权码可被重放，应一次性使用",
                    })

            if node.step_type == TokenChainStep.REFRESH_TOKEN:
                if node.can_replay:
                    vulnerabilities.append({
                        "node_index": i,
                        "type": "refresh_token_reuse",
                        "severity": "critical",
                        "description": "Refresh Token可重复使用，存在令牌链滥用风险",
                    })

        return vulnerabilities

    def _find_attack_paths(self, chain: TokenChainGraph) -> List[List[int]]:
        """Find possible attack paths in the chain.

        Args:
            chain: Token chain to analyze.

        Returns:
            List of attack paths (node index sequences).
        """
        paths: List[List[int]] = []

        for i, node in enumerate(chain.nodes):
            if node.can_skip:
                path = list(range(len(chain.nodes)))
                path.pop(i)
                paths.append(path)

        if not paths:
            paths.append(list(range(len(chain.nodes))))

        return paths

    def get_chains(self) -> List[TokenChainGraph]:
        """Get all analyzed token chains.

        Returns:
            List of TokenChainGraph.
        """
        return self._chains.copy()


# =============================================================================
# Main Advanced Attacks Manager
# =============================================================================

class JWTAdvancedAttacksManager:
    """Main JWT advanced attacks coordination engine.

    Integrates cross-service detection, nested JWT handling,
    SAML/OIDC hybrid testing, and token chain analysis.

    Attributes:
        _cross_service_detector: Cross-service detector
        _nested_jwt_handler: Nested JWT handler
        _saml_oidc_tester: SAML/OIDC hybrid tester
        _chain_analyzer: Token chain analyzer
    """

    def __init__(self) -> None:
        """Initialize the JWTAdvancedAttacksManager."""
        self._cross_service_detector = CrossServiceDetector()
        self._nested_jwt_handler = NestedJWTHandler()
        self._saml_oidc_tester = SAMLOIDCHybridTester()
        self._chain_analyzer = TokenChainAnalyzer()

    @property
    def cross_service(self) -> CrossServiceDetector:
        """Get cross-service detector.

        Returns:
            CrossServiceDetector instance.
        """
        return self._cross_service_detector

    @property
    def nested_jwt(self) -> NestedJWTHandler:
        """Get nested JWT handler.

        Returns:
            NestedJWTHandler instance.
        """
        return self._nested_jwt_handler

    @property
    def saml_oidc(self) -> SAMLOIDCHybridTester:
        """Get SAML/OIDC hybrid tester.

        Returns:
            SAMLOIDCHybridTester instance.
        """
        return self._saml_oidc_tester

    @property
    def chain_analyzer(self) -> TokenChainAnalyzer:
        """Get token chain analyzer.

        Returns:
            TokenChainAnalyzer instance.
        """
        return self._chain_analyzer

    async def run_full_advanced_suite(
        self,
        jwt_token: str,
        service_urls: List[str],
        saml_assertion: Optional[str] = None,
        traffic_entries: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Run the full advanced attack suite.

        Args:
            jwt_token: JWT token to test.
            service_urls: List of service URLs.
            saml_assertion: Optional SAML assertion.
            traffic_entries: Optional traffic entries for chain analysis.

        Returns:
            Dictionary with all test results.
        """
        results: Dict[str, Any] = {
            "cross_service": {},
            "nested_jwt": {},
            "saml_oidc": {},
            "token_chain": {},
        }

        cross_finding = await self._cross_service_detector.test_token_across_services(
            jwt_token=jwt_token,
            service_urls=service_urls,
        )
        results["cross_service"] = cross_finding.to_dict()

        nested_tree = self._nested_jwt_handler.parse_nested_jwt(jwt_token)
        if nested_tree:
            results["nested_jwt"] = nested_tree.to_dict()

        if saml_assertion:
            saml_result = await self._saml_oidc_tester.test_saml_to_jwt_escalation(
                saml_assertion=saml_assertion,
                jwt_endpoint=service_urls[0] if service_urls else "",
            )
            results["saml_oidc"] = saml_result

        if traffic_entries:
            chain = self._chain_analyzer.build_chain_from_traffic(traffic_entries)
            results["token_chain"] = chain.to_dict()

        return results
