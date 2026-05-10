"""
Cross-Protocol Token Utilization Module - Cross-protocol token conversion,
WebSocket token reuse, and mobile-web interoperability testing.

This module provides:
    1. OAuth token to other protocol credential conversion
    2. WebSocket authentication token reuse testing
    3. Mobile and web platform token interoperability testing
    4. Alternative authentication method discovery

Integration points:
    - JWT Attack Orchestration module
    - OAuth 2.1 Audit module
    - Session MFA Bypass module
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
from typing import Any, Dict, List, Optional

import aiohttp

logger = logging.getLogger(__name__)


# =============================================================================
# Enums
# =============================================================================

class ProtocolType(str, Enum):
    """Authentication protocol types."""

    BEARER_TOKEN = "bearer_token"
    BASIC_AUTH = "basic_auth"
    API_KEY = "api_key"
    COOKIE = "cookie"
    OAUTH2 = "oauth2"
    WEBSOCKET = "websocket"


class ConversionResult(str, Enum):
    """Token conversion test result."""

    SUCCESS = "success"
    FAILED = "failed"
    PARTIAL = "partial"
    UNTESTED = "untested"


class PlatformType(str, Enum):
    """Client platform types."""

    WEB = "web"
    MOBILE_IOS = "mobile_ios"
    MOBILE_ANDROID = "mobile_android"
    DESKTOP = "desktop"
    API = "api"


# =============================================================================
# Data Classes
# =============================================================================

@dataclass
class TokenConversionResult:
    """Result of a token conversion test.

    Attributes:
        source_protocol: Original protocol type
        target_protocol: Converted protocol type
        result: Conversion test result
        evidence: Test evidence
        description: Test description
        timestamp: Test timestamp
    """

    source_protocol: ProtocolType = ProtocolType.BEARER_TOKEN
    target_protocol: ProtocolType = ProtocolType.BASIC_AUTH
    result: ConversionResult = ConversionResult.UNTESTED
    evidence: Dict[str, Any] = field(default_factory=dict)
    description: str = ""
    timestamp: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary.

        Returns:
            Dictionary representation.
        """
        return {
            "source_protocol": self.source_protocol.value,
            "target_protocol": self.target_protocol.value,
            "result": self.result.value,
            "evidence": self.evidence,
            "description": self.description,
            "timestamp": self.timestamp,
        }


@dataclass
class WebSocketTestResult:
    """WebSocket token reuse test result.

    Attributes:
        ws_url: WebSocket URL tested
        token_used: Token used for connection
        connection_established: Whether connection was established
        token_validated: Whether server validated token
        connection_maintained_after_expiry: Whether connection persists after token expiry
        evidence: Test evidence
        timestamp: Test timestamp
    """

    ws_url: str = ""
    token_used: str = ""
    connection_established: bool = False
    token_validated: bool = False
    connection_maintained_after_expiry: bool = False
    evidence: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary.

        Returns:
            Dictionary representation.
        """
        return {
            "ws_url": self.ws_url,
            "token_used": self.token_used[:30] + "...",
            "connection_established": self.connection_established,
            "token_validated": self.token_validated,
            "connection_maintained_after_expiry": self.connection_maintained_after_expiry,
            "evidence": self.evidence,
            "timestamp": self.timestamp,
        }


@dataclass
class PlatformInteroperabilityResult:
    """Cross-platform token interoperability test result.

    Attributes:
        source_platform: Source platform type
        target_platform: Target platform type
        token_interoperable: Whether token works across platforms
        permission_differences: Permission differences found
        evidence: Test evidence
        timestamp: Test timestamp
    """

    source_platform: PlatformType = PlatformType.WEB
    target_platform: PlatformType = PlatformType.MOBILE_IOS
    token_interoperable: bool = False
    permission_differences: List[str] = field(default_factory=list)
    evidence: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary.

        Returns:
            Dictionary representation.
        """
        return {
            "source_platform": self.source_platform.value,
            "target_platform": self.target_platform.value,
            "token_interoperable": self.token_interoperable,
            "permission_differences": self.permission_differences,
            "evidence": self.evidence,
            "timestamp": self.timestamp,
        }


# =============================================================================
# Token Conversion Tester
# =============================================================================

class TokenConversionTester:
    """Tests OAuth token conversion to other authentication protocols.

    Tests:
    - Bearer token to Basic Auth conversion
    - Bearer token to API Key conversion
    - Bearer token to Cookie conversion
    - Alternative authentication method discovery
    """

    def __init__(
        self,
        target_url: str,
        bearer_token: str,
    ) -> None:
        """Initialize the token conversion tester.

        Args:
            target_url: Target API URL for testing.
            bearer_token: OAuth Bearer token to convert.
        """
        self.target_url = target_url
        self.bearer_token = bearer_token
        self.results: List[TokenConversionResult] = []

    async def test_basic_auth_conversion(
        self,
        username: str = "user",
        timeout: int = 10,
    ) -> TokenConversionResult:
        """Test converting Bearer token to Basic Auth.

        Tests if the API accepts `user:token` as Basic Auth credentials.

        Args:
            username: Username for Basic Auth.
            timeout: Request timeout in seconds.

        Returns:
            TokenConversionResult with test results.
        """
        token_prefix = self.bearer_token[:20] + "..."

        result = TokenConversionResult(
            source_protocol=ProtocolType.BEARER_TOKEN,
            target_protocol=ProtocolType.BASIC_AUTH,
            description=(
                f"测试是否可将 Bearer Token 转换为 Basic Auth 认证。"
                f"使用格式: {username}:{token_prefix}"
            ),
            timestamp=time.time(),
        )

        credentials = f"{username}:{self.bearer_token}"
        encoded_credentials = base64.b64encode(
            credentials.encode()
        ).decode()

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    self.target_url,
                    headers={
                        "Authorization": f"Basic {encoded_credentials}",
                    },
                    timeout=timeout,
                ) as response:
                    body = await response.text()
                    result.evidence["status_code"] = response.status
                    result.evidence["body_preview"] = body[:500]

                    if response.status == 200:
                        result.result = ConversionResult.SUCCESS
                    elif response.status == 401:
                        result.result = ConversionResult.FAILED
                    else:
                        result.result = ConversionResult.PARTIAL

        except Exception as e:
            result.evidence["error"] = str(e)
            result.result = ConversionResult.FAILED

        self.results.append(result)
        return result

    async def test_api_key_conversion(
        self,
        header_name: str = "X-API-Key",
        timeout: int = 10,
    ) -> TokenConversionResult:
        """Test converting Bearer token to API Key.

        Tests if the API accepts the token as an API Key header.

        Args:
            header_name: API Key header name.
            timeout: Request timeout in seconds.

        Returns:
            TokenConversionResult with test results.
        """
        result = TokenConversionResult(
            source_protocol=ProtocolType.BEARER_TOKEN,
            target_protocol=ProtocolType.API_KEY,
            description=(
                f"测试是否可将 Bearer Token 作为 API Key 使用。"
                f"Header: {header_name}"
            ),
            timestamp=time.time(),
        )

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    self.target_url,
                    headers={
                        header_name: self.bearer_token,
                    },
                    timeout=timeout,
                ) as response:
                    body = await response.text()
                    result.evidence["status_code"] = response.status
                    result.evidence["body_preview"] = body[:500]

                    if response.status == 200:
                        result.result = ConversionResult.SUCCESS
                    elif response.status == 401:
                        result.result = ConversionResult.FAILED
                    else:
                        result.result = ConversionResult.PARTIAL

        except Exception as e:
            result.evidence["error"] = str(e)
            result.result = ConversionResult.FAILED

        self.results.append(result)
        return result

    async def test_cookie_conversion(
        self,
        cookie_name: str = "session",
        timeout: int = 10,
    ) -> TokenConversionResult:
        """Test converting Bearer token to Cookie.

        Tests if the API accepts the token as a session cookie.

        Args:
            cookie_name: Cookie name to use.
            timeout: Request timeout in seconds.

        Returns:
            TokenConversionResult with test results.
        """
        result = TokenConversionResult(
            source_protocol=ProtocolType.BEARER_TOKEN,
            target_protocol=ProtocolType.COOKIE,
            description=(
                f"测试是否可将 Bearer Token 转换为 Cookie 认证。"
                f"Cookie 名称: {cookie_name}"
            ),
            timestamp=time.time(),
        )

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    self.target_url,
                    headers={
                        "Cookie": f"{cookie_name}={self.bearer_token}",
                    },
                    timeout=timeout,
                ) as response:
                    body = await response.text()
                    result.evidence["status_code"] = response.status
                    result.evidence["body_preview"] = body[:500]

                    if response.status == 200:
                        result.result = ConversionResult.SUCCESS
                    elif response.status == 401:
                        result.result = ConversionResult.FAILED
                    else:
                        result.result = ConversionResult.PARTIAL

        except Exception as e:
            result.evidence["error"] = str(e)
            result.result = ConversionResult.FAILED

        self.results.append(result)
        return result

    async def test_all_conversions(
        self,
        timeout: int = 10,
    ) -> List[TokenConversionResult]:
        """Test all token conversion methods.

        Args:
            timeout: Request timeout in seconds.

        Returns:
            List of all conversion test results.
        """
        results = []

        results.append(await self.test_basic_auth_conversion(timeout=timeout))
        results.append(await self.test_api_key_conversion(timeout=timeout))
        results.append(await self.test_cookie_conversion(timeout=timeout))

        return results


# =============================================================================
# WebSocket Token Tester
# =============================================================================

class WebSocketTokenTester:
    """Tests WebSocket authentication token reuse.

    Tests:
    - WebSocket connection with HTTP API token
    - Token validation on WebSocket connection
    - Connection persistence after token expiry
    """

    def __init__(
        self,
        ws_url: str,
        http_token: str,
        http_api_url: str = "",
    ) -> None:
        """Initialize the WebSocket token tester.

        Args:
            ws_url: WebSocket URL for testing.
            http_token: HTTP API token to test.
            http_api_url: HTTP API URL for comparison.
        """
        self.ws_url = ws_url
        self.http_token = http_token
        self.http_api_url = http_api_url
        self.results: List[WebSocketTestResult] = []

    async def test_token_interoperability(
        self,
        timeout: int = 10,
    ) -> WebSocketTestResult:
        """Test if HTTP API token works for WebSocket connection.

        Args:
            timeout: Connection timeout in seconds.

        Returns:
            WebSocketTestResult with test results.
        """
        result = WebSocketTestResult(
            ws_url=self.ws_url,
            token_used=self.http_token,
            timestamp=time.time(),
        )

        try:
            async with aiohttp.ClientSession() as session:
                async with session.ws_connect(
                    self.ws_url,
                    headers={"Authorization": f"Bearer {self.http_token}"},
                ) as ws:
                    result.connection_established = True

                    async for msg in ws:
                        if msg.type == aiohttp.WSMsgType.TEXT:
                            data = json.loads(msg.data) if msg.data else {}
                            if "error" not in data:
                                result.token_validated = True
                            break
                        elif msg.type in (
                            aiohttp.WSMsgType.CLOSE,
                            aiohttp.WSMsgType.CLOSED,
                            aiohttp.WSMsgType.ERROR,
                        ):
                            break

        except Exception as e:
            result.evidence["error"] = str(e)
            result.connection_established = False

        self.results.append(result)
        return result

    async def test_connection_persistence_after_expiry(
        self,
        short_lived_token: str = "",
        wait_seconds: int = 5,
        timeout: int = 10,
    ) -> WebSocketTestResult:
        """Test if WebSocket connection persists after token expiry.

        Args:
            short_lived_token: Token with short expiry.
            wait_seconds: Seconds to wait for token expiry.
            timeout: Connection timeout in seconds.

        Returns:
            WebSocketTestResult with test results.
        """
        result = WebSocketTestResult(
            ws_url=self.ws_url,
            token_used=short_lived_token or self.http_token,
            timestamp=time.time(),
        )

        token_to_use = short_lived_token or self.http_token

        try:
            async with aiohttp.ClientSession() as session:
                async with session.ws_connect(
                    self.ws_url,
                    headers={"Authorization": f"Bearer {token_to_use}"},
                ) as ws:
                    result.connection_established = True

                    await asyncio.sleep(wait_seconds)

                    try:
                        await ws.send_str('{"action": "ping"}')
                        response = await asyncio.wait_for(
                            ws.receive(), timeout=5
                        )

                        if response.type == aiohttp.WSMsgType.TEXT:
                            result.connection_maintained_after_expiry = True
                            result.evidence["response"] = response.data

                    except asyncio.TimeoutError:
                        result.evidence["error"] = "No response after token expiry"

        except Exception as e:
            result.evidence["error"] = str(e)
            result.connection_established = False

        self.results.append(result)
        return result

    async def test_all_ws_scenarios(
        self,
        timeout: int = 10,
    ) -> List[WebSocketTestResult]:
        """Test all WebSocket token scenarios.

        Args:
            timeout: Request timeout in seconds.

        Returns:
            List of all WebSocket test results.
        """
        results = []

        results.append(await self.test_token_interoperability(timeout=timeout))

        return results


# =============================================================================
# Platform Interoperability Tester
# =============================================================================

class PlatformInteroperabilityTester:
    """Tests cross-platform token interoperability.

    Tests:
    - Mobile token usage on Web API
    - Web token usage on Mobile API
    - Permission differences across platforms
    """

    def __init__(
        self,
        web_api_url: str,
        mobile_api_url: str,
    ) -> None:
        """Initialize the platform interoperability tester.

        Args:
            web_api_url: Web API base URL.
            mobile_api_url: Mobile API base URL.
        """
        self.web_api_url = web_api_url
        self.mobile_api_url = mobile_api_url
        self.results: List[PlatformInteroperabilityResult] = []

    async def test_mobile_token_on_web(
        self,
        mobile_token: str,
        test_endpoint: str = "/api/user",
        timeout: int = 10,
    ) -> PlatformInteroperabilityResult:
        """Test if mobile token works on Web API.

        Args:
            mobile_token: Token from mobile platform.
            test_endpoint: API endpoint to test.
            timeout: Request timeout in seconds.

        Returns:
            PlatformInteroperabilityResult with test results.
        """
        result = PlatformInteroperabilityResult(
            source_platform=PlatformType.MOBILE_IOS,
            target_platform=PlatformType.WEB,
            timestamp=time.time(),
        )

        web_url = f"{self.web_api_url}{test_endpoint}"

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    web_url,
                    headers={"Authorization": f"Bearer {mobile_token}"},
                    timeout=timeout,
                ) as response:
                    body = await response.text()
                    result.evidence["web_status"] = response.status
                    result.evidence["web_body_preview"] = body[:500]

                    if response.status == 200:
                        result.token_interoperable = True
                        web_data = json.loads(body) if body else {}
                        result.evidence["web_permissions"] = web_data.get(
                            "permissions", []
                        )

        except Exception as e:
            result.evidence["web_error"] = str(e)

        self.results.append(result)
        return result

    async def test_web_token_on_mobile(
        self,
        web_token: str,
        test_endpoint: str = "/api/user",
        timeout: int = 10,
    ) -> PlatformInteroperabilityResult:
        """Test if web token works on Mobile API.

        Args:
            web_token: Token from web platform.
            test_endpoint: API endpoint to test.
            timeout: Request timeout in seconds.

        Returns:
            PlatformInteroperabilityResult with test results.
        """
        result = PlatformInteroperabilityResult(
            source_platform=PlatformType.WEB,
            target_platform=PlatformType.MOBILE_IOS,
            timestamp=time.time(),
        )

        mobile_url = f"{self.mobile_api_url}{test_endpoint}"

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    mobile_url,
                    headers={"Authorization": f"Bearer {web_token}"},
                    timeout=timeout,
                ) as response:
                    body = await response.text()
                    result.evidence["mobile_status"] = response.status
                    result.evidence["mobile_body_preview"] = body[:500]

                    if response.status == 200:
                        result.token_interoperable = True
                        mobile_data = json.loads(body) if body else {}
                        result.evidence["mobile_permissions"] = mobile_data.get(
                            "permissions", []
                        )

        except Exception as e:
            result.evidence["mobile_error"] = str(e)

        self.results.append(result)
        return result

    async def compare_permissions(
        self,
        web_token: str,
        mobile_token: str,
        test_endpoint: str = "/api/user",
        timeout: int = 10,
    ) -> PlatformInteroperabilityResult:
        """Compare permissions between web and mobile tokens.

        Args:
            web_token: Web platform token.
            mobile_token: Mobile platform token.
            test_endpoint: API endpoint to test.
            timeout: Request timeout in seconds.

        Returns:
            PlatformInteroperabilityResult with comparison results.
        """
        result = PlatformInteroperabilityResult(
            source_platform=PlatformType.WEB,
            target_platform=PlatformType.MOBILE_IOS,
            timestamp=time.time(),
        )

        web_permissions: List[str] = []
        mobile_permissions: List[str] = []

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"{self.web_api_url}{test_endpoint}",
                    headers={"Authorization": f"Bearer {web_token}"},
                    timeout=timeout,
                ) as web_response:
                    if web_response.status == 200:
                        web_body = await web_response.text()
                        web_data = json.loads(web_body) if web_body else {}
                        web_permissions = web_data.get("permissions", [])

                async with session.get(
                    f"{self.mobile_api_url}{test_endpoint}",
                    headers={"Authorization": f"Bearer {mobile_token}"},
                    timeout=timeout,
                ) as mobile_response:
                    if mobile_response.status == 200:
                        mobile_body = await mobile_response.text()
                        mobile_data = json.loads(mobile_body) if mobile_body else {}
                        mobile_permissions = mobile_data.get("permissions", [])

            web_set = set(web_permissions)
            mobile_set = set(mobile_permissions)

            only_web = web_set - mobile_set
            only_mobile = mobile_set - web_set

            if only_web:
                result.permission_differences.append(
                    f"Web 独有权限: {list(only_web)}"
                )

            if only_mobile:
                result.permission_differences.append(
                    f"Mobile 独有权限: {list(only_mobile)}"
                )

            result.evidence["web_permissions"] = web_permissions
            result.evidence["mobile_permissions"] = mobile_permissions

        except Exception as e:
            result.evidence["error"] = str(e)

        self.results.append(result)
        return result

    async def test_all_platform_scenarios(
        self,
        web_token: str,
        mobile_token: str,
        test_endpoint: str = "/api/user",
        timeout: int = 10,
    ) -> List[PlatformInteroperabilityResult]:
        """Test all cross-platform scenarios.

        Args:
            web_token: Web platform token.
            mobile_token: Mobile platform token.
            test_endpoint: API endpoint to test.
            timeout: Request timeout in seconds.

        Returns:
            List of all platform test results.
        """
        results = []

        results.append(
            await self.test_mobile_token_on_web(
                mobile_token, test_endpoint, timeout
            )
        )

        results.append(
            await self.test_web_token_on_mobile(
                web_token, test_endpoint, timeout
            )
        )

        results.append(
            await self.compare_permissions(
                web_token, mobile_token, test_endpoint, timeout
            )
        )

        return results


# =============================================================================
# Main Cross-Protocol Token Manager
# =============================================================================

class CrossProtocolTokenManager:
    """Main cross-protocol token testing coordination engine.

    Integrates:
    - Token conversion testing
    - WebSocket token reuse testing
    - Platform interoperability testing
    """

    def __init__(
        self,
        target_url: str,
        bearer_token: str,
    ) -> None:
        """Initialize the cross-protocol token manager.

        Args:
            target_url: Target API URL.
            bearer_token: OAuth Bearer token.
        """
        self.target_url = target_url
        self.bearer_token = bearer_token
        self.conversion_tester = TokenConversionTester(
            target_url, bearer_token
        )
        self.results: Dict[str, Any] = {}

    async def test_all_token_conversions(
        self,
        timeout: int = 10,
    ) -> List[TokenConversionResult]:
        """Test all token conversion methods.

        Args:
            timeout: Request timeout in seconds.

        Returns:
            List of conversion test results.
        """
        results = await self.conversion_tester.test_all_conversions(
            timeout=timeout
        )

        self.results["conversions"] = [r.to_dict() for r in results]

        return results

    async def test_websocket_reuse(
        self,
        ws_url: str,
        timeout: int = 10,
    ) -> List[WebSocketTestResult]:
        """Test WebSocket token reuse.

        Args:
            ws_url: WebSocket URL to test.
            timeout: Connection timeout in seconds.

        Returns:
            List of WebSocket test results.
        """
        ws_tester = WebSocketTokenTester(
            ws_url=ws_url,
            http_token=self.bearer_token,
            http_api_url=self.target_url,
        )

        results = await ws_tester.test_all_ws_scenarios(timeout=timeout)

        self.results["websocket"] = [r.to_dict() for r in results]

        return results

    async def test_platform_interoperability(
        self,
        web_api_url: str,
        mobile_api_url: str,
        web_token: str,
        mobile_token: str,
        test_endpoint: str = "/api/user",
        timeout: int = 10,
    ) -> List[PlatformInteroperabilityResult]:
        """Test cross-platform token interoperability.

        Args:
            web_api_url: Web API base URL.
            mobile_api_url: Mobile API base URL.
            web_token: Web platform token.
            mobile_token: Mobile platform token.
            test_endpoint: API endpoint to test.
            timeout: Request timeout in seconds.

        Returns:
            List of platform test results.
        """
        platform_tester = PlatformInteroperabilityTester(
            web_api_url=web_api_url,
            mobile_api_url=mobile_api_url,
        )

        results = await platform_tester.test_all_platform_scenarios(
            web_token=web_token,
            mobile_token=mobile_token,
            test_endpoint=test_endpoint,
            timeout=timeout,
        )

        self.results["platform"] = [r.to_dict() for r in results]

        return results

    async def run_full_suite(
        self,
        ws_url: str = "",
        web_api_url: str = "",
        mobile_api_url: str = "",
        web_token: str = "",
        mobile_token: str = "",
        timeout: int = 10,
    ) -> Dict[str, Any]:
        """Run full cross-protocol token test suite.

        Args:
            ws_url: WebSocket URL to test.
            web_api_url: Web API base URL.
            mobile_api_url: Mobile API base URL.
            web_token: Web platform token.
            mobile_token: Mobile platform token.
            timeout: Request timeout in seconds.

        Returns:
            Dictionary with all test results.
        """
        results: Dict[str, Any] = {}

        results["conversions"] = [
            r.to_dict()
            for r in await self.test_all_token_conversions(timeout=timeout)
        ]

        if ws_url:
            results["websocket"] = [
                r.to_dict()
                for r in await self.test_websocket_reuse(ws_url, timeout)
            ]

        if web_api_url and mobile_api_url and web_token and mobile_token:
            results["platform"] = [
                r.to_dict()
                for r in await self.test_platform_interoperability(
                    web_api_url,
                    mobile_api_url,
                    web_token,
                    mobile_token,
                    timeout=timeout,
                )
            ]

        self.results = results

        return results

    def get_successful_conversions(self) -> List[TokenConversionResult]:
        """Get successful token conversions.

        Returns:
            List of successful conversion results.
        """
        return [
            r for r in self.conversion_tester.results
            if r.result == ConversionResult.SUCCESS
        ]

    def export_report(self) -> Dict[str, Any]:
        """Export cross-protocol token test report.

        Returns:
            Dictionary with full report.
        """
        return {
            "target_url": self.target_url,
            "test_timestamp": time.time(),
            "results": self.results,
            "successful_conversions": [
                r.to_dict() for r in self.get_successful_conversions()
            ],
        }
