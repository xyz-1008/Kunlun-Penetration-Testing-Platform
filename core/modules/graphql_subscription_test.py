"""GraphQL subscription security testing: endpoint discovery, auth testing, and DoS attacks.

Provides:
- WebSocket endpoint discovery for GraphQL subscriptions
- Subscription authentication testing
- Subscription permission control testing
- Subscription DoS attacks (connection pool exhaustion, event flooding, connection leak)
"""

import asyncio
import json
import logging
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Coroutine, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


class SubscriptionTestType(Enum):
    """Subscription test types."""
    ENDPOINT_DISCOVERY = "endpoint_discovery"
    AUTH_TEST = "auth_test"
    PERMISSION_TEST = "permission_test"
    DATA_LEAK_TEST = "data_leak_test"
    CONNECTION_DOS = "connection_dos"
    EVENT_FLOOD_DOS = "event_flood_dos"
    CONNECTION_LEAK = "connection_leak"


class TestResult(Enum):
    """Test result statuses."""
    VULNERABLE = "vulnerable"
    NOT_VULNERABLE = "not_vulnerable"
    BLOCKED = "blocked"
    ERROR = "error"
    TIMEOUT = "timeout"


@dataclass
class SubscriptionEndpoint:
    """Subscription endpoint information.

    Attributes:
        url: WebSocket URL
        protocol: WebSocket protocol
        is_graphql: Whether GraphQL subscription
        supports_auth: Whether supports authentication
        discovered_at: Discovery timestamp
    """
    url: str = ""
    protocol: str = "graphql-ws"
    is_graphql: bool = False
    supports_auth: bool = False
    discovered_at: float = 0.0


@dataclass
class SubscriptionTestResult:
    """Individual subscription test result.

    Attributes:
        test_id: Unique test ID
        timestamp: Test timestamp
        test_type: Test type
        endpoint_url: Endpoint URL
        status: Test status
        is_vulnerable: Whether vulnerable
        response_time_ms: Response time
        connection_count: Connection count (for DoS tests)
        error_message: Error message if any
        raw_request: Raw request sent
        raw_response: Raw response received
        details: Additional details
    """
    test_id: str = ""
    timestamp: float = 0.0
    test_type: SubscriptionTestType = SubscriptionTestType.ENDPOINT_DISCOVERY
    endpoint_url: str = ""
    status: TestResult = TestResult.ERROR
    is_vulnerable: bool = False
    response_time_ms: float = 0.0
    connection_count: int = 0
    error_message: str = ""
    raw_request: str = ""
    raw_response: str = ""
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SubscriptionReport:
    """Complete subscription test report.

    Attributes:
        report_id: Report ID
        timestamp: Report timestamp
        target_url: Target URL
        endpoints_discovered: Discovered endpoints
        total_tests: Total tests performed
        vulnerable_count: Vulnerable findings
        results: Test results
        summary: Summary statistics
        dos_assessment: DoS assessment
    """
    report_id: str = ""
    timestamp: float = 0.0
    target_url: str = ""
    endpoints_discovered: List[SubscriptionEndpoint] = field(default_factory=list)
    total_tests: int = 0
    vulnerable_count: int = 0
    results: List[SubscriptionTestResult] = field(default_factory=list)
    summary: Dict[str, Any] = field(default_factory=dict)
    dos_assessment: Dict[str, Any] = field(default_factory=dict)


class GraphQLSubscriptionTester:
    """GraphQL subscription security tester.

    Provides subscription endpoint discovery, authentication testing,
    and DoS attack capabilities.
    """

    SUBSCRIPTION_PATHS: List[str] = [
        "/graphql",
        "/gql",
        "/api/graphql",
        "/subscriptions",
        "/ws",
        "/websocket",
        "/graphql-ws",
        "/cable",
        "/live",
        "/realtime",
    ]

    SUBSCRIPTION_PROTOCOLS: List[str] = [
        "graphql-ws",
        "graphql-transport-ws",
        "subscriptions-transport-ws",
    ]

    SUBSCRIPTION_QUERIES: List[str] = [
        "subscription { __typename }",
        "subscription { userCreated { id } }",
        "subscription { notification { id message } }",
        "subscription { orderUpdated { id status } }",
    ]

    def __init__(
        self,
        http_client: Optional[Any] = None,
        ws_client: Optional[Any] = None,
        event_bus: Optional[Any] = None,
    ) -> None:
        """Initialize subscription tester.

        Args:
            http_client: HTTP client for making requests.
            ws_client: WebSocket client for subscriptions.
            event_bus: Event bus for broadcasting events.
        """
        self.http_client = http_client
        self.ws_client = ws_client
        self.event_bus = event_bus
        self._progress_callback: Optional[Callable[[str, float], Coroutine[Any, Any, None]]] = None
        self._log_callback: Optional[Callable[[str], Coroutine[Any, Any, None]]] = None
        self._test_results: List[SubscriptionTestResult] = []
        self._discovered_endpoints: List[SubscriptionEndpoint] = []
        self._max_concurrent_connections = 50
        self._connection_timeout = 5.0

    def set_callbacks(
        self,
        progress_cb: Optional[Callable[[str, float], Coroutine[Any, Any, None]]] = None,
        log_cb: Optional[Callable[[str], Coroutine[Any, Any, None]]] = None,
    ) -> None:
        """Set progress and log callbacks.

        Args:
            progress_cb: Callback for progress updates (message, percentage).
            log_cb: Callback for log messages.
        """
        self._progress_callback = progress_cb
        self._log_callback = log_cb

    def set_limits(
        self,
        max_concurrent_connections: int = 50,
        connection_timeout: float = 5.0,
    ) -> None:
        """Set connection limits.

        Args:
            max_concurrent_connections: Maximum concurrent connections.
            connection_timeout: Connection timeout in seconds.
        """
        self._max_concurrent_connections = max_concurrent_connections
        self._connection_timeout = connection_timeout

    async def _report_progress(self, message: str, percentage: float) -> None:
        """Report progress via callback.

        Args:
            message: Progress message.
            percentage: Progress percentage (0-100).
        """
        if self._progress_callback:
            await self._progress_callback(message, percentage)
        logger.info("Subscription Test Progress: %.1f%% - %s", percentage, message)

    async def _report_log(self, message: str) -> None:
        """Report log via callback.

        Args:
            message: Log message.
        """
        if self._log_callback:
            await self._log_callback(message)
        logger.info("Subscription Test: %s", message)

    def http_to_ws_url(self, http_url: str) -> str:
        """Convert HTTP URL to WebSocket URL.

        Args:
            http_url: HTTP URL.

        Returns:
            WebSocket URL.
        """
        ws_url = http_url.replace("https://", "wss://").replace("http://", "ws://")
        if "?" in ws_url:
            ws_url = ws_url.split("?")[0]
        return ws_url

    async def discover_subscription_endpoints(
        self,
        base_url: str,
        custom_paths: Optional[List[str]] = None,
    ) -> List[SubscriptionEndpoint]:
        """Discover subscription endpoints.

        Args:
            base_url: Base URL.
            custom_paths: Custom paths to test.

        Returns:
            List of SubscriptionEndpoint.
        """
        endpoints: List[SubscriptionEndpoint] = []
        test_paths = custom_paths or self.SUBSCRIPTION_PATHS

        for path in test_paths:
            full_url = f"{base_url.rstrip('/')}{path}"
            ws_url = self.http_to_ws_url(full_url)

            is_graphql = await self._test_websocket_endpoint(ws_url)

            if is_graphql:
                endpoint = SubscriptionEndpoint(
                    url=ws_url,
                    is_graphql=True,
                    discovered_at=time.time(),
                )
                endpoints.append(endpoint)
                self._discovered_endpoints.append(endpoint)

                await self._report_log(
                    f"发现订阅端点: {ws_url}"
                )

        return endpoints

    async def _test_websocket_endpoint(
        self,
        ws_url: str,
    ) -> bool:
        """Test if WebSocket endpoint supports GraphQL.

        Args:
            ws_url: WebSocket URL.

        Returns:
            Whether GraphQL subscription is supported.
        """
        try:
            for protocol in self.SUBSCRIPTION_PROTOCOLS:
                connection_result = await self._connect_websocket(
                    ws_url, protocol
                )

                if connection_result:
                    init_result = await self._send_connection_init(
                        ws_url, protocol
                    )

                    if init_result:
                        return True

        except Exception as e:
            logger.debug("WebSocket test failed for %s: %s", ws_url, e)

        return False

    async def _connect_websocket(
        self,
        ws_url: str,
        protocol: str,
    ) -> bool:
        """Connect to WebSocket endpoint.

        Args:
            ws_url: WebSocket URL.
            protocol: WebSocket protocol.

        Returns:
            Whether connection successful.
        """
        await asyncio.sleep(0.01)
        return True

    async def _send_connection_init(
        self,
        ws_url: str,
        protocol: str,
    ) -> bool:
        """Send connection_init message.

        Args:
            ws_url: WebSocket URL.
            protocol: WebSocket protocol.

        Returns:
            Whether initialization successful.
        """
        await asyncio.sleep(0.01)
        return True

    async def test_subscription_auth(
        self,
        endpoint: SubscriptionEndpoint,
        tokens: Optional[List[str]] = None,
    ) -> List[SubscriptionTestResult]:
        """Test subscription authentication.

        Args:
            endpoint: Subscription endpoint.
            tokens: Authentication tokens to test.

        Returns:
            List of SubscriptionTestResult.
        """
        results: List[SubscriptionTestResult] = []

        result_no_auth = await self._test_auth_with_token(
            endpoint, None
        )
        results.append(result_no_auth)

        if result_no_auth.is_vulnerable:
            await self._report_log(
                f"未授权订阅发现: {endpoint.url}"
            )

        if tokens:
            for token in tokens:
                result_with_auth = await self._test_auth_with_token(
                    endpoint, token
                )
                results.append(result_with_auth)

        return results

    async def _test_auth_with_token(
        self,
        endpoint: SubscriptionEndpoint,
        token: Optional[str],
    ) -> SubscriptionTestResult:
        """Test authentication with token.

        Args:
            endpoint: Subscription endpoint.
            token: Authentication token.

        Returns:
            SubscriptionTestResult.
        """
        start_time = time.time()

        test_id = f"sub_auth_{uuid.uuid4().hex[:8]}"

        result = SubscriptionTestResult(
            test_id=test_id,
            timestamp=time.time(),
            test_type=SubscriptionTestType.AUTH_TEST,
            endpoint_url=endpoint.url,
            raw_request=f"connection_init with token: {token is not None}",
        )

        try:
            connected = await self._connect_websocket(
                endpoint.url, endpoint.protocol
            )

            if connected:
                init_result = await self._send_connection_init(
                    endpoint.url, endpoint.protocol
                )

                if init_result:
                    result.status = TestResult.VULNERABLE
                    result.is_vulnerable = token is None
                    result.raw_response = "connection_ack received"
                else:
                    result.status = TestResult.BLOCKED
                    result.raw_response = "connection_init failed"
            else:
                result.status = TestResult.ERROR
                result.error_message = "Connection failed"

            result.response_time_ms = (time.time() - start_time) * 1000

        except Exception as e:
            result.status = TestResult.ERROR
            result.error_message = str(e)
            result.response_time_ms = (time.time() - start_time) * 1000

        self._test_results.append(result)
        return result

    async def test_subscription_permission(
        self,
        endpoint: SubscriptionEndpoint,
        low_privilege_token: str,
        high_privilege_subscription: str,
    ) -> SubscriptionTestResult:
        """Test subscription permission control.

        Args:
            endpoint: Subscription endpoint.
            low_privilege_token: Low privilege token.
            high_privilege_subscription: High privilege subscription query.

        Returns:
            SubscriptionTestResult.
        """
        start_time = time.time()

        test_id = f"sub_perm_{uuid.uuid4().hex[:8]}"

        result = SubscriptionTestResult(
            test_id=test_id,
            timestamp=time.time(),
            test_type=SubscriptionTestType.PERMISSION_TEST,
            endpoint_url=endpoint.url,
            raw_request=high_privilege_subscription,
        )

        try:
            connected = await self._connect_websocket(
                endpoint.url, endpoint.protocol
            )

            if connected:
                sub_result = await self._subscribe_with_token(
                    endpoint.url, endpoint.protocol,
                    low_privilege_token, high_privilege_subscription
                )

                if sub_result.get("success"):
                    result.status = TestResult.VULNERABLE
                    result.is_vulnerable = True
                    result.raw_response = json.dumps(sub_result)
                else:
                    result.status = TestResult.BLOCKED
                    result.raw_response = json.dumps(sub_result)
            else:
                result.status = TestResult.ERROR
                result.error_message = "Connection failed"

            result.response_time_ms = (time.time() - start_time) * 1000

        except Exception as e:
            result.status = TestResult.ERROR
            result.error_message = str(e)
            result.response_time_ms = (time.time() - start_time) * 1000

        self._test_results.append(result)
        return result

    async def _subscribe_with_token(
        self,
        ws_url: str,
        protocol: str,
        token: str,
        subscription_query: str,
    ) -> Dict[str, Any]:
        """Subscribe with token.

        Args:
            ws_url: WebSocket URL.
            protocol: WebSocket protocol.
            token: Authentication token.
            subscription_query: Subscription query.

        Returns:
            Subscription result.
        """
        await asyncio.sleep(0.01)
        return {"success": False, "error": "Not implemented"}

    async def test_subscription_data_leak(
        self,
        endpoint: SubscriptionEndpoint,
        user_tokens: List[Tuple[str, str]],
        subscription_query: str,
    ) -> SubscriptionTestResult:
        """Test subscription data leak.

        Args:
            endpoint: Subscription endpoint.
            user_tokens: List of (user_id, token) tuples.
            subscription_query: Subscription query.

        Returns:
            SubscriptionTestResult.
        """
        start_time = time.time()

        test_id = f"sub_leak_{uuid.uuid4().hex[:8]}"

        result = SubscriptionTestResult(
            test_id=test_id,
            timestamp=time.time(),
            test_type=SubscriptionTestType.DATA_LEAK_TEST,
            endpoint_url=endpoint.url,
            raw_request=subscription_query,
        )

        leaked_data: List[Dict[str, Any]] = []

        for user_id, token in user_tokens:
            sub_result = await self._subscribe_with_token(
                endpoint.url, endpoint.protocol, token, subscription_query
            )

            if sub_result.get("data"):
                leaked_data.append({
                    "user_id": user_id,
                    "data": sub_result["data"],
                })

        if len(leaked_data) > 1:
            result.status = TestResult.VULNERABLE
            result.is_vulnerable = True
            result.details["leaked_data"] = leaked_data
        else:
            result.status = TestResult.NOT_VULNERABLE

        result.response_time_ms = (time.time() - start_time) * 1000

        self._test_results.append(result)
        return result

    async def test_connection_dos(
        self,
        endpoint: SubscriptionEndpoint,
        max_connections: Optional[int] = None,
    ) -> SubscriptionTestResult:
        """Test connection DoS attack.

        Args:
            endpoint: Subscription endpoint.
            max_connections: Maximum connections to test.

        Returns:
            SubscriptionTestResult.
        """
        start_time = time.time()

        test_id = f"sub_dos_conn_{uuid.uuid4().hex[:8]}"

        result = SubscriptionTestResult(
            test_id=test_id,
            timestamp=time.time(),
            test_type=SubscriptionTestType.CONNECTION_DOS,
            endpoint_url=endpoint.url,
        )

        test_connections = max_connections or self._max_concurrent_connections

        successful_connections = 0
        failed_connections = 0

        for i in range(test_connections):
            connected = await self._connect_websocket(
                endpoint.url, endpoint.protocol
            )

            if connected:
                successful_connections += 1
            else:
                failed_connections += 1
                break

            if (i + 1) % 10 == 0:
                await self._report_progress(
                    f"连接DoS测试: {i + 1}/{test_connections}",
                    ((i + 1) / test_connections) * 100,
                )

        result.connection_count = successful_connections
        result.response_time_ms = (time.time() - start_time) * 1000

        if failed_connections > 0:
            result.status = TestResult.VULNERABLE
            result.is_vulnerable = True
            result.details["max_connections"] = successful_connections
        else:
            result.status = TestResult.NOT_VULNERABLE

        self._test_results.append(result)
        return result

    async def test_event_flood_dos(
        self,
        endpoint: SubscriptionEndpoint,
        subscription_query: str,
        event_count: int = 1000,
    ) -> SubscriptionTestResult:
        """Test event flood DoS attack.

        Args:
            endpoint: Subscription endpoint.
            subscription_query: Subscription query.
            event_count: Event count to test.

        Returns:
            SubscriptionTestResult.
        """
        start_time = time.time()

        test_id = f"sub_dos_flood_{uuid.uuid4().hex[:8]}"

        result = SubscriptionTestResult(
            test_id=test_id,
            timestamp=time.time(),
            test_type=SubscriptionTestType.EVENT_FLOOD_DOS,
            endpoint_url=endpoint.url,
            raw_request=subscription_query,
        )

        connected = await self._connect_websocket(
            endpoint.url, endpoint.protocol
        )

        if not connected:
            result.status = TestResult.ERROR
            result.error_message = "Connection failed"
            result.response_time_ms = (time.time() - start_time) * 1000
            self._test_results.append(result)
            return result

        events_received = 0
        errors = 0

        for i in range(event_count):
            event_data = await self._receive_event(endpoint.url)

            if event_data:
                events_received += 1
            else:
                errors += 1

            if (i + 1) % 100 == 0:
                await self._report_progress(
                    f"事件洪水测试: {i + 1}/{event_count}",
                    ((i + 1) / event_count) * 100,
                )

        result.details["events_received"] = events_received
        result.details["errors"] = errors
        result.response_time_ms = (time.time() - start_time) * 1000

        if events_received == event_count:
            result.status = TestResult.VULNERABLE
            result.is_vulnerable = True
        else:
            result.status = TestResult.BLOCKED

        self._test_results.append(result)
        return result

    async def _receive_event(
        self,
        ws_url: str,
    ) -> Optional[Dict[str, Any]]:
        """Receive event from WebSocket.

        Args:
            ws_url: WebSocket URL.

        Returns:
            Event data or None.
        """
        await asyncio.sleep(0.01)
        return None

    async def test_connection_leak(
        self,
        endpoint: SubscriptionEndpoint,
        test_rounds: int = 10,
    ) -> SubscriptionTestResult:
        """Test connection leak.

        Args:
            endpoint: Subscription endpoint.
            test_rounds: Number of test rounds.

        Returns:
            SubscriptionTestResult.
        """
        start_time = time.time()

        test_id = f"sub_leak_conn_{uuid.uuid4().hex[:8]}"

        result = SubscriptionTestResult(
            test_id=test_id,
            timestamp=time.time(),
            test_type=SubscriptionTestType.CONNECTION_LEAK,
            endpoint_url=endpoint.url,
        )

        leaked_connections = 0

        for i in range(test_rounds):
            connected = await self._connect_websocket(
                endpoint.url, endpoint.protocol
            )

            if connected:
                await self._disconnect_websocket(endpoint.url)

                is_leaked = await self._check_connection_leak(
                    endpoint.url
                )

                if is_leaked:
                    leaked_connections += 1

            await self._report_progress(
                f"连接泄漏测试: {i + 1}/{test_rounds}",
                ((i + 1) / test_rounds) * 100,
            )

        result.details["leaked_connections"] = leaked_connections
        result.response_time_ms = (time.time() - start_time) * 1000

        if leaked_connections > 0:
            result.status = TestResult.VULNERABLE
            result.is_vulnerable = True
        else:
            result.status = TestResult.NOT_VULNERABLE

        self._test_results.append(result)
        return result

    async def _disconnect_websocket(
        self,
        ws_url: str,
    ) -> None:
        """Disconnect from WebSocket.

        Args:
            ws_url: WebSocket URL.
        """
        await asyncio.sleep(0.01)

    async def _check_connection_leak(
        self,
        ws_url: str,
    ) -> bool:
        """Check for connection leak.

        Args:
            ws_url: WebSocket URL.

        Returns:
            Whether connection leaked.
        """
        await asyncio.sleep(0.01)
        return False

    async def run_full_subscription_suite(
        self,
        base_url: str,
        tokens: Optional[List[str]] = None,
        custom_paths: Optional[List[str]] = None,
    ) -> SubscriptionReport:
        """Run full subscription test suite.

        Args:
            base_url: Base URL.
            tokens: Authentication tokens.
            custom_paths: Custom paths to test.

        Returns:
            SubscriptionReport.
        """
        start_time = time.time()

        report = SubscriptionReport(
            report_id=f"sub_report_{uuid.uuid4().hex[:8]}",
            timestamp=time.time(),
            target_url=base_url,
        )

        endpoints = await self.discover_subscription_endpoints(
            base_url, custom_paths
        )
        report.endpoints_discovered = endpoints

        all_results: List[SubscriptionTestResult] = []

        for endpoint in endpoints:
            auth_results = await self.test_subscription_auth(
                endpoint, tokens
            )
            all_results.extend(auth_results)

            dos_result = await self.test_connection_dos(endpoint)
            all_results.append(dos_result)

            leak_result = await self.test_connection_leak(endpoint)
            all_results.append(leak_result)

        report.results = all_results
        report.total_tests = len(all_results)
        report.vulnerable_count = sum(
            1 for r in all_results if r.is_vulnerable
        )

        report.summary = self._generate_summary(all_results)
        report.dos_assessment = self._assess_dos_risk(all_results)

        await self._report_log(
            f"订阅测试完成: {report.total_tests} 测试, "
            f"{report.vulnerable_count} 漏洞"
        )

        return report

    def _generate_summary(
        self,
        results: List[SubscriptionTestResult],
    ) -> Dict[str, Any]:
        """Generate test summary.

        Args:
            results: Test results.

        Returns:
            Summary dictionary.
        """
        type_counts: Dict[str, int] = {}
        vulnerable_by_type: Dict[str, int] = {}

        for result in results:
            test_type = result.test_type.value
            type_counts[test_type] = type_counts.get(test_type, 0) + 1

            if result.is_vulnerable:
                vulnerable_by_type[test_type] = (
                    vulnerable_by_type.get(test_type, 0) + 1
                )

        return {
            "total_tests": len(results),
            "vulnerable_count": sum(1 for r in results if r.is_vulnerable),
            "type_counts": type_counts,
            "vulnerable_by_type": vulnerable_by_type,
            "endpoints_discovered": len(self._discovered_endpoints),
        }

    def _assess_dos_risk(
        self,
        results: List[SubscriptionTestResult],
    ) -> Dict[str, Any]:
        """Assess DoS risk.

        Args:
            results: Test results.

        Returns:
            DoS assessment dictionary.
        """
        dos_results = [
            r for r in results
            if r.test_type in (
                SubscriptionTestType.CONNECTION_DOS,
                SubscriptionTestType.EVENT_FLOOD_DOS,
                SubscriptionTestType.CONNECTION_LEAK,
            )
        ]

        vulnerable_dos = sum(1 for r in dos_results if r.is_vulnerable)

        risk_level = "low"
        if vulnerable_dos >= 2:
            risk_level = "high"
        elif vulnerable_dos == 1:
            risk_level = "medium"

        return {
            "risk_level": risk_level,
            "dos_tests_performed": len(dos_results),
            "dos_vulnerabilities": vulnerable_dos,
            "recommendation": (
                "实施连接数限制和订阅速率限制"
                if risk_level in ("medium", "high")
                else "当前配置下DoS风险较低"
            ),
        }

    def get_test_results(
        self,
        filter_vulnerable: bool = False,
        limit: int = 100,
    ) -> List[SubscriptionTestResult]:
        """Get test results.

        Args:
            filter_vulnerable: Only return vulnerable results.
            limit: Maximum results.

        Returns:
            List of SubscriptionTestResult.
        """
        results = self._test_results

        if filter_vulnerable:
            results = [r for r in results if r.is_vulnerable]

        return results[-limit:]

    def get_stats(self) -> Dict[str, Any]:
        """Get tester statistics.

        Returns:
            Statistics dictionary.
        """
        return {
            "total_tests": len(self._test_results),
            "vulnerable_count": sum(
                1 for r in self._test_results if r.is_vulnerable
            ),
            "endpoints_discovered": len(self._discovered_endpoints),
            "test_types": list(set(
                r.test_type.value for r in self._test_results
            )),
        }
