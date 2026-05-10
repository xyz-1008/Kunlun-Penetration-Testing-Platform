"""
OAuth Cross-Client Module - Multi-client permission cross-testing,
scope escalation, and token binding bypass.

This module provides:
    1. Cross-client permission testing (Client A token accessing Client B resources)
    2. Scope escalation and stacking attacks
    3. Token binding bypass testing (IP, device, platform)
    4. Client ID extraction from proxy history
    5. Cross-client test matrix generation

Integration points:
    - MITM proxy traffic capture
    - OAuth Analyzer module
    - Token lifecycle testing
    - Report generation

Author: Kunlun Security Lab
License: Internal Use Only
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import random
import re
import string
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

class CrossClientAttackType(str, Enum):
    """Cross-client attack types."""

    TOKEN_CROSS_CLIENT = "token_cross_client"
    CODE_CROSS_CLIENT = "code_cross_client"
    REFRESH_CROSS_CLIENT = "refresh_cross_client"
    SCOPE_ESCALATION = "scope_escalation"
    SCOPE_STACKING = "scope_stacking"
    SCOPE_CASE_CONFUSION = "scope_case_confusion"
    TOKEN_BINDING_BYPASS = "token_binding_bypass"
    PLATFORM_CROSS_USAGE = "platform_cross_usage"


class Severity(str, Enum):
    """Vulnerability severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class TokenType(str, Enum):
    """OAuth token types."""

    ACCESS_TOKEN = "access_token"
    REFRESH_TOKEN = "refresh_token"
    AUTHORIZATION_CODE = "authorization_code"
    ID_TOKEN = "id_token"


# =============================================================================
# Data Classes
# =============================================================================

@dataclass
class OAuthClient:
    """OAuth client representation.

    Attributes:
        client_id: Client identifier
        client_secret: Client secret (if known)
        redirect_uris: Registered redirect URIs
        scopes: Allowed scopes
        grant_types: Supported grant types
        platform: Client platform (web, mobile, desktop)
        source_request_id: Source request ID where detected
    """

    client_id: str = ""
    client_secret: str = ""
    redirect_uris: List[str] = field(default_factory=list)
    scopes: List[str] = field(default_factory=list)
    grant_types: List[str] = field(default_factory=list)
    platform: str = "unknown"
    source_request_id: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary.

        Returns:
            Dictionary representation.
        """
        return {
            "client_id": self.client_id,
            "redirect_uris": self.redirect_uris,
            "scopes": self.scopes,
            "grant_types": self.grant_types,
            "platform": self.platform,
        }


@dataclass
class CrossClientTestResult:
    """Cross-client test result.

    Attributes:
        attack_type: Type of cross-client attack tested
        source_client_id: Source client ID
        target_client_id: Target client ID
        token_type: Type of token tested
        success: Whether cross-client access succeeded
        severity: Result severity
        response_status: HTTP response status
        response_body: Response body content
        details: Additional details
        timestamp: Test timestamp
    """

    attack_type: CrossClientAttackType = CrossClientAttackType.TOKEN_CROSS_CLIENT
    source_client_id: str = ""
    target_client_id: str = ""
    token_type: TokenType = TokenType.ACCESS_TOKEN
    success: bool = False
    severity: Severity = Severity.INFO
    response_status: int = 0
    response_body: str = ""
    details: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary.

        Returns:
            Dictionary representation.
        """
        return {
            "attack_type": self.attack_type.value,
            "source_client_id": self.source_client_id,
            "target_client_id": self.target_client_id,
            "token_type": self.token_type.value,
            "success": self.success,
            "severity": self.severity.value,
            "response_status": self.response_status,
            "response_body": self.response_body[:500],
            "details": self.details,
            "timestamp": self.timestamp,
        }


@dataclass
class ScopeEscalationResult:
    """Scope escalation test result.

    Attributes:
        original_scopes: Original requested scopes
        escalated_scopes: Escalated scopes attempted
        success: Whether escalation succeeded
        severity: Result severity
        granted_scopes: Actually granted scopes
        response_body: Response body content
        timestamp: Test timestamp
    """

    original_scopes: List[str] = field(default_factory=list)
    escalated_scopes: List[str] = field(default_factory=list)
    success: bool = False
    severity: Severity = Severity.INFO
    granted_scopes: List[str] = field(default_factory=list)
    response_body: str = ""
    timestamp: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary.

        Returns:
            Dictionary representation.
        """
        return {
            "original_scopes": self.original_scopes,
            "escalated_scopes": self.escalated_scopes,
            "success": self.success,
            "severity": self.severity.value,
            "granted_scopes": self.granted_scopes,
            "response_body": self.response_body[:500],
            "timestamp": self.timestamp,
        }


@dataclass
class TokenBindingResult:
    """Token binding bypass test result.

    Attributes:
        token_type: Type of token tested
        binding_type: Type of binding tested (ip, device, platform)
        success: Whether binding was bypassed
        severity: Result severity
        original_context: Original token context
        test_context: Test context
        response_status: HTTP response status
        timestamp: Test timestamp
    """

    token_type: TokenType = TokenType.ACCESS_TOKEN
    binding_type: str = ""
    success: bool = False
    severity: Severity = Severity.INFO
    original_context: Dict[str, Any] = field(default_factory=dict)
    test_context: Dict[str, Any] = field(default_factory=dict)
    response_status: int = 0
    timestamp: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary.

        Returns:
            Dictionary representation.
        """
        return {
            "token_type": self.token_type.value,
            "binding_type": self.binding_type,
            "success": self.success,
            "severity": self.severity.value,
            "original_context": self.original_context,
            "test_context": self.test_context,
            "response_status": self.response_status,
            "timestamp": self.timestamp,
        }


# =============================================================================
# Client Discovery
# =============================================================================

class ClientDiscovery:
    """Discovers OAuth clients from proxy history.

    Extracts client IDs, redirect URIs, and scopes from
    captured OAuth traffic.
    """

    def __init__(self) -> None:
        """Initialize the client discovery engine."""
        self.clients: Dict[str, OAuthClient] = {}

    def extract_clients_from_proxy_history(
        self,
        requests: List[Dict[str, Any]],
    ) -> Dict[str, OAuthClient]:
        """Extract OAuth clients from proxy history.

        Args:
            requests: List of proxy request/response dictionaries.

        Returns:
            Dictionary of client_id to OAuthClient.
        """
        for req in requests:
            url = req.get("url", "")
            body = req.get("body", "")
            headers = req.get("headers", {})

            self._extract_from_url(url, req.get("request_id", ""))
            self._extract_from_body(body, req.get("request_id", ""))

        return self.clients

    def _extract_from_url(self, url: str, request_id: str) -> None:
        """Extract client info from URL.

        Args:
            url: Request URL.
            request_id: Source request ID.
        """
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        client_id = params.get("client_id", [None])[0]
        if client_id:
            if client_id not in self.clients:
                self.clients[client_id] = OAuthClient(
                    client_id=client_id,
                    source_request_id=request_id,
                )

            redirect_uri = params.get("redirect_uri", [None])[0]
            if redirect_uri and redirect_uri not in self.clients[client_id].redirect_uris:
                self.clients[client_id].redirect_uris.append(redirect_uri)

            scope = params.get("scope", [None])[0]
            if scope:
                scopes = scope.split()
                for s in scopes:
                    if s not in self.clients[client_id].scopes:
                        self.clients[client_id].scopes.append(s)

    def _extract_from_body(self, body: str, request_id: str) -> None:
        """Extract client info from request body.

        Args:
            body: Request body.
            request_id: Source request ID.
        """
        params = parse_qs(body)

        client_id = params.get("client_id", [None])[0]
        if client_id:
            if client_id not in self.clients:
                self.clients[client_id] = OAuthClient(
                    client_id=client_id,
                    source_request_id=request_id,
                )

            grant_type = params.get("grant_type", [None])[0]
            if grant_type and grant_type not in self.clients[client_id].grant_types:
                self.clients[client_id].grant_types.append(grant_type)

            scope = params.get("scope", [None])[0]
            if scope:
                scopes = scope.split()
                for s in scopes:
                    if s not in self.clients[client_id].scopes:
                        self.clients[client_id].scopes.append(s)

    def generate_cross_client_matrix(self) -> List[Tuple[str, str]]:
        """Generate cross-client test matrix.

        Returns:
            List of (source_client_id, target_client_id) pairs.
        """
        client_ids = list(self.clients.keys())
        matrix: List[Tuple[str, str]] = []

        for i, source_id in enumerate(client_ids):
            for j, target_id in enumerate(client_ids):
                if i != j:
                    matrix.append((source_id, target_id))

        return matrix


# =============================================================================
# Cross-Client Permission Tester
# =============================================================================

class CrossClientPermissionTester:
    """Tests cross-client permission vulnerabilities.

    Tests whether tokens, codes, or refresh tokens from one client
    can be used with another client.
    """

    def __init__(
        self,
        token_endpoint: str,
        resource_url: str,
        clients: Dict[str, OAuthClient],
    ) -> None:
        """Initialize the cross-client permission tester.

        Args:
            token_endpoint: OAuth token endpoint URL.
            resource_url: Protected resource URL.
            clients: Dictionary of discovered clients.
        """
        self.token_endpoint = token_endpoint
        self.resource_url = resource_url
        self.clients = clients
        self.results: List[CrossClientTestResult] = []

    async def test_token_cross_client(
        self,
        source_client_id: str,
        target_client_id: str,
        access_token: str,
        timeout: int = 10,
    ) -> CrossClientTestResult:
        """Test if Client A's access token works with Client B.

        Args:
            source_client_id: Source client ID.
            target_client_id: Target client ID.
            access_token: Access token from source client.
            timeout: Request timeout in seconds.

        Returns:
            CrossClientTestResult with test results.
        """
        try:
            headers = {
                "Authorization": f"Bearer {access_token}",
                "X-Client-ID": target_client_id,
            }

            async with aiohttp.ClientSession() as session:
                async with session.get(
                    self.resource_url, headers=headers, timeout=timeout
                ) as response:
                    body = await response.text()

                    result = CrossClientTestResult(
                        attack_type=CrossClientAttackType.TOKEN_CROSS_CLIENT,
                        source_client_id=source_client_id,
                        target_client_id=target_client_id,
                        token_type=TokenType.ACCESS_TOKEN,
                        success=response.status == 200,
                        severity=Severity.CRITICAL if response.status == 200 else Severity.INFO,
                        response_status=response.status,
                        response_body=body,
                        timestamp=time.time(),
                    )

                    self.results.append(result)
                    return result

        except Exception as e:
            logger.error(f"Cross-client token test failed: {e}")

            return CrossClientTestResult(
                attack_type=CrossClientAttackType.TOKEN_CROSS_CLIENT,
                source_client_id=source_client_id,
                target_client_id=target_client_id,
                token_type=TokenType.ACCESS_TOKEN,
                success=False,
                severity=Severity.INFO,
                details={"error": str(e)},
                timestamp=time.time(),
            )

    async def test_code_cross_client(
        self,
        source_client_id: str,
        target_client_id: str,
        authorization_code: str,
        redirect_uri: str = "",
        timeout: int = 10,
    ) -> CrossClientTestResult:
        """Test if Client A's auth code can be exchanged by Client B.

        Args:
            source_client_id: Source client ID.
            target_client_id: Target client ID.
            authorization_code: Authorization code from source client.
            redirect_uri: Redirect URI.
            timeout: Request timeout in seconds.

        Returns:
            CrossClientTestResult with test results.
        """
        try:
            target_client = self.clients.get(target_client_id)
            client_secret = target_client.client_secret if target_client else ""

            data = {
                "grant_type": "authorization_code",
                "code": authorization_code,
                "client_id": target_client_id,
                "redirect_uri": redirect_uri or (
                    target_client.redirect_uris[0] if target_client and target_client.redirect_uris else ""
                ),
            }

            if client_secret:
                data["client_secret"] = client_secret

            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self.token_endpoint, data=data, timeout=timeout
                ) as response:
                    body = await response.text()

                    result = CrossClientTestResult(
                        attack_type=CrossClientAttackType.CODE_CROSS_CLIENT,
                        source_client_id=source_client_id,
                        target_client_id=target_client_id,
                        token_type=TokenType.AUTHORIZATION_CODE,
                        success=response.status == 200,
                        severity=Severity.CRITICAL if response.status == 200 else Severity.INFO,
                        response_status=response.status,
                        response_body=body,
                        timestamp=time.time(),
                    )

                    self.results.append(result)
                    return result

        except Exception as e:
            logger.error(f"Cross-client code test failed: {e}")

            return CrossClientTestResult(
                attack_type=CrossClientAttackType.CODE_CROSS_CLIENT,
                source_client_id=source_client_id,
                target_client_id=target_client_id,
                token_type=TokenType.AUTHORIZATION_CODE,
                success=False,
                severity=Severity.INFO,
                details={"error": str(e)},
                timestamp=time.time(),
            )

    async def test_refresh_cross_client(
        self,
        source_client_id: str,
        target_client_id: str,
        refresh_token: str,
        timeout: int = 10,
    ) -> CrossClientTestResult:
        """Test if Client A's refresh token works with Client B.

        Args:
            source_client_id: Source client ID.
            target_client_id: Target client ID.
            refresh_token: Refresh token from source client.
            timeout: Request timeout in seconds.

        Returns:
            CrossClientTestResult with test results.
        """
        try:
            target_client = self.clients.get(target_client_id)
            client_secret = target_client.client_secret if target_client else ""

            data = {
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
                "client_id": target_client_id,
            }

            if client_secret:
                data["client_secret"] = client_secret

            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self.token_endpoint, data=data, timeout=timeout
                ) as response:
                    body = await response.text()

                    result = CrossClientTestResult(
                        attack_type=CrossClientAttackType.REFRESH_CROSS_CLIENT,
                        source_client_id=source_client_id,
                        target_client_id=target_client_id,
                        token_type=TokenType.REFRESH_TOKEN,
                        success=response.status == 200,
                        severity=Severity.HIGH if response.status == 200 else Severity.INFO,
                        response_status=response.status,
                        response_body=body,
                        timestamp=time.time(),
                    )

                    self.results.append(result)
                    return result

        except Exception as e:
            logger.error(f"Cross-client refresh test failed: {e}")

            return CrossClientTestResult(
                attack_type=CrossClientAttackType.REFRESH_CROSS_CLIENT,
                source_client_id=source_client_id,
                target_client_id=target_client_id,
                token_type=TokenType.REFRESH_TOKEN,
                success=False,
                severity=Severity.INFO,
                details={"error": str(e)},
                timestamp=time.time(),
            )

    async def run_full_cross_client_suite(
        self,
        test_tokens: Dict[str, Dict[str, str]],
        timeout: int = 10,
    ) -> List[CrossClientTestResult]:
        """Run full cross-client test suite.

        Args:
            test_tokens: Dictionary of client_id to tokens.
            timeout: Request timeout in seconds.

        Returns:
            List of all test results.
        """
        all_results: List[CrossClientTestResult] = []

        matrix = ClientDiscovery().generate_cross_client_matrix() if len(self.clients) > 1 else []

        for source_id, target_id in matrix:
            source_tokens = test_tokens.get(source_id, {})

            if "access_token" in source_tokens:
                result = await self.test_token_cross_client(
                    source_id, target_id, source_tokens["access_token"], timeout
                )
                all_results.append(result)

            if "authorization_code" in source_tokens:
                result = await self.test_code_cross_client(
                    source_id,
                    target_id,
                    source_tokens["authorization_code"],
                    timeout=timeout,
                )
                all_results.append(result)

            if "refresh_token" in source_tokens:
                result = await self.test_refresh_cross_client(
                    source_id, target_id, source_tokens["refresh_token"], timeout
                )
                all_results.append(result)

        return all_results


# =============================================================================
# Scope Escalation Tester
# =============================================================================

class ScopeEscalationTester:
    """Tests OAuth scope escalation vulnerabilities.

    Tests adding extra scopes, scope stacking, and case confusion.
    """

    DANGEROUS_SCOPES: List[str] = [
        "admin",
        "Admin",
        "ADMIN",
        "superuser",
        "root",
        "full_access",
        "offline_access",
        "openid",
        "profile",
        "email",
        "phone",
        "address",
        "*",
        "read:all",
        "write:all",
        "delete:all",
    ]

    def __init__(
        self,
        authorize_url: str,
        client_id: str,
        redirect_uri: str,
        original_scopes: List[str],
    ) -> None:
        """Initialize the scope escalation tester.

        Args:
            authorize_url: OAuth authorize URL.
            client_id: Client ID.
            redirect_uri: Redirect URI.
            original_scopes: Original scopes.
        """
        self.authorize_url = authorize_url
        self.client_id = client_id
        self.redirect_uri = redirect_uri
        self.original_scopes = original_scopes
        self.results: List[ScopeEscalationResult] = []

    async def test_scope_addition(
        self,
        additional_scope: str,
        timeout: int = 10,
    ) -> ScopeEscalationResult:
        """Test adding an extra scope to authorization request.

        Args:
            additional_scope: Additional scope to test.
            timeout: Request timeout in seconds.

        Returns:
            ScopeEscalationResult with test results.
        """
        all_scopes = self.original_scopes + [additional_scope]
        scope_string = " ".join(all_scopes)

        params = {
            "response_type": "code",
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "scope": scope_string,
            "state": hashlib.md5(str(time.time()).encode()).hexdigest()[:12],
        }

        test_url = f"{self.authorize_url}?{urlencode(params)}"

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(test_url, timeout=timeout, allow_redirects=False) as response:
                    body = await response.text()

                    granted_scopes = self._extract_granted_scopes(body)

                    result = ScopeEscalationResult(
                        original_scopes=self.original_scopes,
                        escalated_scopes=[additional_scope],
                        success=additional_scope in granted_scopes,
                        severity=Severity.HIGH if additional_scope in granted_scopes else Severity.INFO,
                        granted_scopes=granted_scopes,
                        response_body=body,
                        timestamp=time.time(),
                    )

                    self.results.append(result)
                    return result

        except Exception as e:
            logger.error(f"Scope addition test failed: {e}")

            return ScopeEscalationResult(
                original_scopes=self.original_scopes,
                escalated_scopes=[additional_scope],
                success=False,
                severity=Severity.INFO,
                timestamp=time.time(),
            )

    async def test_scope_stacking(
        self,
        iterations: int = 3,
        timeout: int = 10,
    ) -> List[ScopeEscalationResult]:
        """Test scope stacking through multiple authorizations.

        Args:
            iterations: Number of authorization iterations.
            timeout: Request timeout in seconds.

        Returns:
            List of ScopeEscalationResult for each iteration.
        """
        results: List[ScopeEscalationResult] = []
        accumulated_scopes = list(self.original_scopes)

        for i in range(iterations):
            new_scope = self.DANGEROUS_SCOPES[i % len(self.DANGEROUS_SCOPES)]

            if new_scope not in accumulated_scopes:
                accumulated_scopes.append(new_scope)

            scope_string = " ".join(accumulated_scopes)

            params = {
                "response_type": "code",
                "client_id": self.client_id,
                "redirect_uri": self.redirect_uri,
                "scope": scope_string,
                "state": hashlib.md5(f"{time.time()}{i}".encode()).hexdigest()[:12],
            }

            test_url = f"{self.authorize_url}?{urlencode(params)}"

            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(test_url, timeout=timeout, allow_redirects=False) as response:
                        body = await response.text()
                        granted_scopes = self._extract_granted_scopes(body)

                        result = ScopeEscalationResult(
                            original_scopes=self.original_scopes,
                            escalated_scopes=[new_scope],
                            success=new_scope in granted_scopes,
                            severity=Severity.HIGH if new_scope in granted_scopes else Severity.INFO,
                            granted_scopes=granted_scopes,
                            response_body=body,
                            timestamp=time.time(),
                        )

                        results.append(result)
                        self.results.append(result)

            except Exception as e:
                logger.error(f"Scope stacking test failed at iteration {i}: {e}")

        return results

    async def test_scope_case_confusion(
        self,
        base_scope: str = "admin",
        timeout: int = 10,
    ) -> List[ScopeEscalationResult]:
        """Test scope case confusion attacks.

        Args:
            base_scope: Base scope to test case variations.
            timeout: Request timeout in seconds.

        Returns:
            List of ScopeEscalationResult for each case variant.
        """
        case_variants = [
            base_scope.lower(),
            base_scope.upper(),
            base_scope.capitalize(),
            base_scope.swapcase(),
        ]

        results: List[ScopeEscalationResult] = []

        for variant in case_variants:
            if variant in self.original_scopes:
                continue

            all_scopes = self.original_scopes + [variant]
            scope_string = " ".join(all_scopes)

            params = {
                "response_type": "code",
                "client_id": self.client_id,
                "redirect_uri": self.redirect_uri,
                "scope": scope_string,
                "state": hashlib.md5(f"{time.time()}{variant}".encode()).hexdigest()[:12],
            }

            test_url = f"{self.authorize_url}?{urlencode(params)}"

            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(test_url, timeout=timeout, allow_redirects=False) as response:
                        body = await response.text()
                        granted_scopes = self._extract_granted_scopes(body)

                        result = ScopeEscalationResult(
                            original_scopes=self.original_scopes,
                            escalated_scopes=[variant],
                            success=variant in granted_scopes,
                            severity=Severity.MEDIUM if variant in granted_scopes else Severity.INFO,
                            granted_scopes=granted_scopes,
                            response_body=body,
                            timestamp=time.time(),
                        )

                        results.append(result)
                        self.results.append(result)

            except Exception as e:
                logger.error(f"Scope case confusion test failed for {variant}: {e}")

        return results

    def _extract_granted_scopes(self, response_body: str) -> List[str]:
        """Extract granted scopes from response.

        Args:
            response_body: Response body content.

        Returns:
            List of granted scopes.
        """
        scope_patterns = [
            r'"scope"\s*:\s*"([^"]*)"',
            r'"granted_scopes"\s*:\s*\[([^\]]*)\]',
            r"scope=([^&\s]+)",
        ]

        for pattern in scope_patterns:
            match = re.search(pattern, response_body)
            if match:
                scope_value: str = match.group(1)
                return scope_value.split()

        return []


# =============================================================================
# Token Binding Bypass Tester
# =============================================================================

class TokenBindingBypassTester:
    """Tests OAuth token binding bypass vulnerabilities.

    Tests whether tokens are properly bound to IP, device, or platform.
    """

    def __init__(
        self,
        resource_url: str,
        access_token: str,
    ) -> None:
        """Initialize the token binding bypass tester.

        Args:
            resource_url: Protected resource URL.
            access_token: Access token to test.
        """
        self.resource_url = resource_url
        self.access_token = access_token
        self.results: List[TokenBindingResult] = []

    async def test_ip_binding_bypass(
        self,
        original_ip: str = "",
        test_proxies: Optional[List[str]] = None,
        timeout: int = 10,
    ) -> TokenBindingResult:
        """Test if token is bound to specific IP.

        Args:
            original_ip: Original IP address.
            test_proxies: List of proxy URLs to test through.
            timeout: Request timeout in seconds.

        Returns:
            TokenBindingResult with test results.
        """
        test_proxies = test_proxies or [
            "http://proxy1:8080",
            "http://proxy2:8080",
        ]

        for proxy in test_proxies:
            try:
                connector = aiohttp.TCPConnector()

                async with aiohttp.ClientSession(connector=connector) as session:
                    headers = {
                        "Authorization": f"Bearer {self.access_token}",
                        "X-Forwarded-For": "1.2.3.4",
                        "X-Real-IP": "1.2.3.4",
                    }

                    async with session.get(
                        self.resource_url,
                        headers=headers,
                        timeout=timeout,
                    ) as response:
                        await response.text()

                        result = TokenBindingResult(
                            token_type=TokenType.ACCESS_TOKEN,
                            binding_type="ip",
                            success=response.status == 200,
                            severity=Severity.HIGH if response.status == 200 else Severity.INFO,
                            original_context={"ip": original_ip},
                            test_context={"proxy": proxy, "spoofed_ip": "1.2.3.4"},
                            response_status=response.status,
                            timestamp=time.time(),
                        )

                        self.results.append(result)
                        return result

            except Exception as e:
                logger.error(f"IP binding bypass test failed: {e}")

        return TokenBindingResult(
            token_type=TokenType.ACCESS_TOKEN,
            binding_type="ip",
            success=False,
            severity=Severity.INFO,
            timestamp=time.time(),
        )

    async def test_platform_cross_usage(
        self,
        original_platform: str = "mobile",
        target_platform: str = "web",
        timeout: int = 10,
    ) -> TokenBindingResult:
        """Test if mobile token can be used on web (or vice versa).

        Args:
            original_platform: Original platform.
            target_platform: Target platform.
            timeout: Request timeout in seconds.

        Returns:
            TokenBindingResult with test results.
        """
        platform_headers: Dict[str, Dict[str, str]] = {
            "web": {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                "X-Platform": "web",
            },
            "mobile": {
                "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X)",
                "X-Platform": "mobile",
            },
            "desktop": {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                "X-Platform": "desktop",
            },
        }

        try:
            headers = {
                "Authorization": f"Bearer {self.access_token}",
                **platform_headers.get(target_platform, {}),
            }

            async with aiohttp.ClientSession() as session:
                async with session.get(
                    self.resource_url, headers=headers, timeout=timeout
                ) as response:
                    body = await response.text()

                    result = TokenBindingResult(
                        token_type=TokenType.ACCESS_TOKEN,
                        binding_type="platform",
                        success=response.status == 200,
                        severity=Severity.MEDIUM if response.status == 200 else Severity.INFO,
                        original_context={"platform": original_platform},
                        test_context={"platform": target_platform},
                        response_status=response.status,
                        timestamp=time.time(),
                    )

                    self.results.append(result)
                    return result

        except Exception as e:
            logger.error(f"Platform cross-usage test failed: {e}")

            return TokenBindingResult(
                token_type=TokenType.ACCESS_TOKEN,
                binding_type="platform",
                success=False,
                severity=Severity.INFO,
                timestamp=time.time(),
            )

    async def test_device_binding_bypass(
        self,
        original_device_id: str = "",
        timeout: int = 10,
    ) -> TokenBindingResult:
        """Test if token is bound to specific device.

        Args:
            original_device_id: Original device ID.
            timeout: Request timeout in seconds.

        Returns:
            TokenBindingResult with test results.
        """
        device_headers = [
            {"X-Device-ID": "test_device_123"},
            {"X-Device-ID": ""},
            {"X-Device-ID": hashlib.md5(str(time.time()).encode()).hexdigest()},
        ]

        for headers in device_headers:
            try:
                request_headers = {
                    "Authorization": f"Bearer {self.access_token}",
                    **headers,
                }

                async with aiohttp.ClientSession() as session:
                    async with session.get(
                        self.resource_url, headers=request_headers, timeout=timeout
                    ) as response:
                        await response.text()

                        result = TokenBindingResult(
                            token_type=TokenType.ACCESS_TOKEN,
                            binding_type="device",
                            success=response.status == 200,
                            severity=Severity.HIGH if response.status == 200 else Severity.INFO,
                            original_context={"device_id": original_device_id},
                            test_context=headers,
                            response_status=response.status,
                            timestamp=time.time(),
                        )

                        self.results.append(result)

                        if response.status == 200:
                            return result

            except Exception as e:
                logger.error(f"Device binding bypass test failed: {e}")

        return TokenBindingResult(
            token_type=TokenType.ACCESS_TOKEN,
            binding_type="device",
            success=False,
            severity=Severity.INFO,
            timestamp=time.time(),
        )


# =============================================================================
# Main Cross-Client Manager
# =============================================================================

class OAuthCrossClientManager:
    """Main OAuth cross-client coordination engine.

    Integrates client discovery, cross-client permission testing,
    scope escalation, and token binding bypass.

    Attributes:
        token_endpoint: OAuth token endpoint
        authorize_url: OAuth authorize URL
        resource_url: Protected resource URL
        client_discovery: Client discovery engine
    """

    def __init__(
        self,
        token_endpoint: str,
        authorize_url: str,
        resource_url: str,
    ) -> None:
        """Initialize the OAuth cross-client manager.

        Args:
            token_endpoint: OAuth token endpoint URL.
            authorize_url: OAuth authorize URL.
            resource_url: Protected resource URL.
        """
        self.token_endpoint = token_endpoint
        self.authorize_url = authorize_url
        self.resource_url = resource_url
        self.client_discovery = ClientDiscovery()

    async def run_full_cross_client_analysis(
        self,
        proxy_history: List[Dict[str, Any]],
        test_tokens: Dict[str, Dict[str, str]],
        access_token: str = "",
        original_scopes: Optional[List[str]] = None,
        client_id: str = "",
        redirect_uri: str = "",
    ) -> Dict[str, Any]:
        """Run full cross-client analysis suite.

        Args:
            proxy_history: Proxy history to analyze.
            test_tokens: Dictionary of client tokens.
            access_token: Access token for binding tests.
            original_scopes: Original scopes.
            client_id: Client ID for scope tests.
            redirect_uri: Redirect URI for scope tests.

        Returns:
            Dictionary with all analysis results.
        """
        results: Dict[str, Any] = {
            "discovered_clients": {},
            "cross_client_matrix": [],
            "cross_client_results": [],
            "scope_escalation_results": [],
            "token_binding_results": [],
        }

        clients = self.client_discovery.extract_clients_from_proxy_history(
            proxy_history
        )
        results["discovered_clients"] = {
            cid: c.to_dict() for cid, c in clients.items()
        }

        if len(clients) > 1:
            tester = CrossClientPermissionTester(
                self.token_endpoint, self.resource_url, clients
            )
            cross_results = await tester.run_full_cross_client_suite(
                test_tokens
            )
            results["cross_client_results"] = [
                r.to_dict() for r in cross_results
            ]

        if original_scopes and client_id and redirect_uri:
            scope_tester = ScopeEscalationTester(
                self.authorize_url, client_id, redirect_uri, original_scopes
            )

            for dangerous_scope in ["admin", "superuser", "full_access"]:
                esc_result = await scope_tester.test_scope_addition(
                    dangerous_scope
                )
                results["scope_escalation_results"].append(esc_result.to_dict())

            stacking_results = await scope_tester.test_scope_stacking()
            results["scope_escalation_results"].extend(
                [r.to_dict() for r in stacking_results]
            )

        if access_token:
            binding_tester = TokenBindingBypassTester(
                self.resource_url, access_token
            )

            ip_result = await binding_tester.test_ip_binding_bypass()
            results["token_binding_results"].append(ip_result.to_dict())

            platform_result = await binding_tester.test_platform_cross_usage()
            results["token_binding_results"].append(platform_result.to_dict())

            device_result = await binding_tester.test_device_binding_bypass()
            results["token_binding_results"].append(device_result.to_dict())

        return results
