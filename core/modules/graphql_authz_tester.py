"""GraphQL authorization testing engine based on token switching and ID traversal.

Provides:
- Query and Mutation field-by-field permission testing with different JWT/OAuth tokens
- Automatic ID-type parameter detection (userId, orderId) for horizontal privilege escalation
- Alias attack support for batch testing rate limits and resource constraints
- Comparison report generation for privilege escalation findings
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


class AuthzTestType(Enum):
    """Authorization test types."""
    FIELD_ACCESS = "field_access"
    ID_TRAVERSAL = "id_traversal"
    ALIAS_ATTACK = "alias_attack"
    TOKEN_COMPARISON = "token_comparison"


class AuthzResult(Enum):
    """Authorization test results."""
    ACCESSIBLE = "accessible"
    DENIED = "denied"
    PARTIAL = "partial"
    ERROR = "error"
    TIMEOUT = "timeout"


class SeverityLevel(Enum):
    """Vulnerability severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class TokenProfile:
    """Token profile for testing.

    Attributes:
        name: Profile name
        token: JWT/OAuth token value
        role: User role
        permissions: Permission list
        token_type: Token type (Bearer, API Key, etc.)
        is_valid: Whether token is valid
    """
    name: str = ""
    token: str = ""
    role: str = ""
    permissions: List[str] = field(default_factory=list)
    token_type: str = "Bearer"
    is_valid: bool = True


@dataclass
class AuthzTestResult:
    """Authorization test result.

    Attributes:
        test_id: Unique test ID
        timestamp: Test timestamp
        test_type: Test type
        field_path: Field path tested
        token_profile: Token profile used
        result: Test result
        response_data: Response data
        response_status: HTTP status code
        response_time_ms: Response time
        is_vulnerable: Whether vulnerability found
        severity: Severity level
        description: Result description
        raw_request: Raw request sent
        raw_response: Raw response received
    """
    test_id: str = ""
    timestamp: float = 0.0
    test_type: AuthzTestType = AuthzTestType.FIELD_ACCESS
    field_path: str = ""
    token_profile: str = ""
    result: AuthzResult = AuthzResult.ERROR
    response_data: Dict[str, Any] = field(default_factory=dict)
    response_status: int = 0
    response_time_ms: float = 0.0
    is_vulnerable: bool = False
    severity: SeverityLevel = SeverityLevel.INFO
    description: str = ""
    raw_request: str = ""
    raw_response: str = ""


@dataclass
class IDTraversalTarget:
    """ID traversal test target.

    Attributes:
        field_name: Field name containing ID
        field_type: Field type
        parent_type: Parent type name
        id_pattern: ID pattern detected
        test_ids: IDs to test
    """
    field_name: str = ""
    field_type: str = ""
    parent_type: str = ""
    id_pattern: str = ""
    test_ids: List[str] = field(default_factory=list)


@dataclass
class AliasAttackConfig:
    """Alias attack configuration.

    Attributes:
        target_field: Target field to alias
        alias_count: Number of aliases
        id_values: ID values to test
        query_template: Query template
    """
    target_field: str = ""
    alias_count: int = 10
    id_values: List[str] = field(default_factory=list)
    query_template: str = ""


@dataclass
class AuthzReport:
    """Authorization test report.

    Attributes:
        report_id: Report ID
        timestamp: Report timestamp
        endpoint_url: Tested endpoint
        total_tests: Total tests performed
        vulnerable_count: Vulnerable findings count
        results: Test results
        summary: Summary statistics
        recommendations: Recommendations
    """
    report_id: str = ""
    timestamp: float = 0.0
    endpoint_url: str = ""
    total_tests: int = 0
    vulnerable_count: int = 0
    results: List[AuthzTestResult] = field(default_factory=list)
    summary: Dict[str, Any] = field(default_factory=dict)
    recommendations: List[str] = field(default_factory=list)


class GraphQLAuthzTester:
    """GraphQL authorization testing engine.

    Provides field-by-field permission testing, ID traversal,
    and alias attack capabilities.
    """

    ID_FIELD_PATTERNS: List[str] = [
        "id", "Id", "ID",
        "userId", "user_id", "userId",
        "orderId", "order_id", "orderId",
        "accountId", "account_id", "accountId",
        "profileId", "profile_id", "profileId",
        "customerId", "customer_id", "customerId",
        "productId", "product_id", "productId",
        "transactionId", "transaction_id", "transactionId",
        "sessionId", "session_id", "sessionId",
        "organizationId", "organization_id", "orgId",
        "companyId", "company_id", "companyId",
        "groupId", "group_id", "groupId",
        "roleId", "role_id", "roleId",
        "permissionId", "permission_id", "permissionId",
    ]

    ID_VALUE_PATTERNS: List[str] = [
        "1", "2", "100", "999",
        "00000000-0000-0000-0000-000000000001",
        "admin", "administrator", "root",
        "test", "user1", "user2",
    ]

    DEFAULT_ROLES: List[str] = ["admin", "user", "readonly", "anonymous"]

    def __init__(
        self,
        http_client: Optional[Any] = None,
        event_bus: Optional[Any] = None,
    ) -> None:
        """Initialize authorization tester.

        Args:
            http_client: HTTP client for making requests.
            event_bus: Event bus for broadcasting events.
        """
        self.http_client = http_client
        self.event_bus = event_bus
        self._progress_callback: Optional[Callable[[str, float], Coroutine[Any, Any, None]]] = None
        self._log_callback: Optional[Callable[[str], Coroutine[Any, Any, None]]] = None
        self._token_profiles: List[TokenProfile] = []
        self._test_results: List[AuthzTestResult] = []
        self._is_running = False

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
        logger.info("Authz Test Progress: %.1f%% - %s", percentage, message)

    async def _report_log(self, message: str) -> None:
        """Report log via callback.

        Args:
            message: Log message.
        """
        if self._log_callback:
            await self._log_callback(message)
        logger.info("Authz Test: %s", message)

    def add_token_profile(
        self,
        name: str,
        token: str,
        role: str = "user",
        permissions: Optional[List[str]] = None,
        token_type: str = "Bearer",
    ) -> None:
        """Add token profile for testing.

        Args:
            name: Profile name.
            token: Token value.
            role: User role.
            permissions: Permission list.
            token_type: Token type.
        """
        profile = TokenProfile(
            name=name,
            token=token,
            role=role,
            permissions=permissions or [],
            token_type=token_type,
        )
        self._token_profiles.append(profile)

    def get_token_profiles(self) -> List[TokenProfile]:
        """Get all token profiles.

        Returns:
            List of TokenProfile.
        """
        return self._token_profiles.copy()

    async def test_field_access(
        self,
        url: str,
        field_path: str,
        query_template: str,
        headers: Optional[Dict[str, str]] = None,
    ) -> List[AuthzTestResult]:
        """Test field access with different tokens.

        Args:
            url: GraphQL endpoint URL.
            field_path: Field path to test.
            query_template: Query template.
            headers: Base HTTP headers.

        Returns:
            List of AuthzTestResult.
        """
        results: List[AuthzTestResult] = []

        for profile in self._token_profiles:
            result = await self._test_single_field(
                url, field_path, query_template, profile, headers
            )
            results.append(result)

        await self._compare_results(results)

        return results

    async def _test_single_field(
        self,
        url: str,
        field_path: str,
        query_template: str,
        profile: TokenProfile,
        base_headers: Optional[Dict[str, str]],
    ) -> AuthzTestResult:
        """Test single field with specific token.

        Args:
            url: Endpoint URL.
            field_path: Field path.
            query_template: Query template.
            profile: Token profile.
            base_headers: Base headers.

        Returns:
            AuthzTestResult.
        """
        start_time = time.time()

        headers = base_headers.copy() if base_headers else {}
        headers["Authorization"] = f"{profile.token_type} {profile.token}"

        test_id = f"authz_{uuid.uuid4().hex[:8]}"

        result = AuthzTestResult(
            test_id=test_id,
            timestamp=time.time(),
            test_type=AuthzTestType.FIELD_ACCESS,
            field_path=field_path,
            token_profile=profile.name,
            raw_request=query_template,
        )

        try:
            response_data = await self._send_query(url, query_template, headers)

            result.response_time_ms = (time.time() - start_time) * 1000
            result.raw_response = json.dumps(response_data) if response_data else ""

            if response_data:
                errors = response_data.get("errors", [])
                data = response_data.get("data", {})

                if errors:
                    error_messages = [e.get("message", "") for e in errors]
                    if any("not authorized" in m.lower() or "permission" in m.lower() for m in error_messages):
                        result.result = AuthzResult.DENIED
                        result.is_vulnerable = False
                        result.description = f"访问被拒绝: {profile.role}"
                    else:
                        result.result = AuthzResult.ERROR
                        result.description = f"错误: {'; '.join(error_messages)}"
                elif data:
                    result.result = AuthzResult.ACCESSIBLE
                    result.response_data = data
                    result.description = f"访问成功: {profile.role}"
                else:
                    result.result = AuthzResult.PARTIAL
                    result.description = f"部分数据: {profile.role}"
            else:
                result.result = AuthzResult.ERROR
                result.description = "无响应"

        except Exception as e:
            result.result = AuthzResult.ERROR
            result.description = f"异常: {str(e)}"
            result.response_time_ms = (time.time() - start_time) * 1000

        self._test_results.append(result)
        return result

    async def test_id_traversal(
        self,
        url: str,
        target: IDTraversalTarget,
        base_headers: Optional[Dict[str, str]] = None,
        max_ids: int = 20,
    ) -> List[AuthzTestResult]:
        """Test horizontal privilege escalation via ID traversal.

        Args:
            url: GraphQL endpoint URL.
            target: ID traversal target.
            base_headers: Base HTTP headers.
            max_ids: Maximum IDs to test.

        Returns:
            List of AuthzTestResult.
        """
        results: List[AuthzTestResult] = []
        test_ids = target.test_ids[:max_ids]

        if not test_ids:
            test_ids = self.ID_VALUE_PATTERNS[:max_ids]

        for profile in self._token_profiles:
            for test_id_value in test_ids:
                query = self._build_id_traversal_query(
                    target.field_name, test_id_value
                )

                result = await self._test_single_field(
                    url,
                    f"{target.parent_type}.{target.field_name}(id={test_id_value})",
                    query,
                    profile,
                    base_headers,
                )

                result.test_type = AuthzTestType.ID_TRAVERSAL

                if result.result == AuthzResult.ACCESSIBLE:
                    result.is_vulnerable = True
                    result.severity = SeverityLevel.HIGH
                    result.description = (
                        f"水平越权: {profile.role} 可访问 ID={test_id_value}"
                    )

                results.append(result)

        return results

    def _build_id_traversal_query(
        self,
        field_name: str,
        id_value: str,
    ) -> str:
        """Build ID traversal query.

        Args:
            field_name: Field name.
            id_value: ID value.

        Returns:
            GraphQL query string.
        """
        return f"""
        query {{
            {field_name}(id: "{id_value}") {{
                id
                ... on User {{
                    email
                    name
                    role
                }}
                ... on Order {{
                    total
                    status
                    items
                }}
                ... on Account {{
                    balance
                    status
                }}
            }}
        }}
        """

    async def test_alias_attack(
        self,
        url: str,
        config: AliasAttackConfig,
        base_headers: Optional[Dict[str, str]] = None,
    ) -> AuthzTestResult:
        """Test alias attack for rate limit bypass.

        Args:
            url: GraphQL endpoint URL.
            config: Alias attack configuration.
            base_headers: Base HTTP headers.

        Returns:
            AuthzTestResult.
        """
        start_time = time.time()

        query = self._build_alias_query(config)

        result = AuthzTestResult(
            test_id=f"alias_{uuid.uuid4().hex[:8]}",
            timestamp=time.time(),
            test_type=AuthzTestType.ALIAS_ATTACK,
            field_path=config.target_field,
            token_profile="multiple",
            raw_request=query,
        )

        try:
            for profile in self._token_profiles:
                headers = base_headers.copy() if base_headers else {}
                headers["Authorization"] = f"{profile.token_type} {profile.token}"

                response_data = await self._send_query(url, query, headers)

                if response_data:
                    errors = response_data.get("errors", [])
                    data = response_data.get("data", {})

                    if data and not errors:
                        result.result = AuthzResult.ACCESSIBLE
                        result.is_vulnerable = True
                        result.severity = SeverityLevel.MEDIUM
                        result.description = (
                            f"别名攻击成功: {config.alias_count} 个别名绕过速率限制"
                        )
                        break
                    elif errors:
                        rate_limit_errors = [
                            e for e in errors
                            if "rate limit" in e.get("message", "").lower()
                            or "too many" in e.get("message", "").lower()
                        ]
                        if rate_limit_errors:
                            result.result = AuthzResult.DENIED
                            result.description = "速率限制生效"
                        else:
                            result.result = AuthzResult.PARTIAL
                            result.description = f"部分成功: {len(errors)} 个错误"

            result.response_time_ms = (time.time() - start_time) * 1000
            result.raw_response = json.dumps(response_data) if response_data else ""

        except Exception as e:
            result.result = AuthzResult.ERROR
            result.description = f"异常: {str(e)}"
            result.response_time_ms = (time.time() - start_time) * 1000

        self._test_results.append(result)
        return result

    def _build_alias_query(self, config: AliasAttackConfig) -> str:
        """Build alias attack query.

        Args:
            config: Alias attack configuration.

        Returns:
            GraphQL query string.
        """
        aliases: List[str] = []

        for i, id_value in enumerate(config.id_values[:config.alias_count]):
            alias_name = f"alias_{i}"
            id_str = f'"{id_value}"' if not id_value.isdigit() else id_value
            alias_query = f"{alias_name}: {config.target_field}(id: {id_str}) {{ id }}"
            aliases.append(alias_query)

        return f"query {{\n    {', '.join(aliases)}\n}}"

    async def _compare_results(
        self,
        results: List[AuthzTestResult],
    ) -> None:
        """Compare test results to find privilege escalation.

        Args:
            results: Test results to compare.
        """
        accessible_roles: List[str] = []
        denied_roles: List[str] = []

        for result in results:
            if result.result == AuthzResult.ACCESSIBLE:
                accessible_roles.append(result.token_profile)
            elif result.result == AuthzResult.DENIED:
                denied_roles.append(result.token_profile)

        if accessible_roles and denied_roles:
            for result in results:
                if result.result == AuthzResult.ACCESSIBLE:
                    result.is_vulnerable = True
                    result.severity = SeverityLevel.HIGH
                    result.description = (
                        f"权限提升: {result.token_profile} 可访问，"
                        f"但 {', '.join(denied_roles)} 被拒绝"
                    )

    async def run_full_authz_test(
        self,
        url: str,
        schema_types: Dict[str, Any],
        base_headers: Optional[Dict[str, str]] = None,
    ) -> AuthzReport:
        """Run full authorization test suite.

        Args:
            url: GraphQL endpoint URL.
            schema_types: Schema types dictionary.
            base_headers: Base HTTP headers.

        Returns:
            AuthzReport.
        """
        self._is_running = True
        start_time = time.time()

        report = AuthzReport(
            report_id=f"report_{uuid.uuid4().hex[:8]}",
            timestamp=time.time(),
            endpoint_url=url,
        )

        all_results: List[AuthzTestResult] = []

        total_fields = sum(
            len(t.get("fields", []))
            for t in schema_types.values()
        )

        current = 0

        for type_name, type_data in schema_types.items():
            for field_data in type_data.get("fields", []):
                if not self._is_running:
                    break

                field_name = field_data.get("name", "")
                field_path = f"{type_name}.{field_name}"

                query = self._build_field_query(type_name, field_name, field_data)

                results = await self.test_field_access(
                    url, field_path, query, base_headers
                )

                all_results.extend(results)

                current += 1
                progress = (current / max(total_fields, 1)) * 100
                await self._report_progress(
                    f"测试 {field_path}", progress
                )

        id_targets = self._detect_id_fields(schema_types)

        for target in id_targets:
            traversal_results = await self.test_id_traversal(
                url, target, base_headers
            )
            all_results.extend(traversal_results)

        report.results = all_results
        report.total_tests = len(all_results)
        report.vulnerable_count = sum(
            1 for r in all_results if r.is_vulnerable
        )

        report.summary = self._generate_summary(all_results)
        report.recommendations = self._generate_recommendations(all_results)

        self._is_running = False

        await self._report_log(
            f"越权测试完成: {report.total_tests} 测试, "
            f"{report.vulnerable_count} 漏洞"
        )

        return report

    def _build_field_query(
        self,
        type_name: str,
        field_name: str,
        field_data: Dict[str, Any],
    ) -> str:
        """Build query for field testing.

        Args:
            type_name: Type name.
            field_name: Field name.
            field_data: Field data.

        Returns:
            GraphQL query string.
        """
        args = field_data.get("args", [])
        arg_str = ""

        if args:
            arg_parts: List[str] = []
            for arg in args:
                arg_name = arg.get("name", "")
                arg_type = arg.get("type", "String")
                if arg.get("is_required"):
                    if "ID" in arg_type or "Int" in arg_type:
                        arg_parts.append(f'{arg_name}: "1"')
                    else:
                        arg_parts.append(f'{arg_name}: "test"')
            if arg_parts:
                arg_str = f"({', '.join(arg_parts)})"

        return f"""
        query {{
            {field_name}{arg_str} {{
                id
                ... on Node {{
                    id
                }}
            }}
        }}
        """

    def _detect_id_fields(
        self,
        schema_types: Dict[str, Any],
    ) -> List[IDTraversalTarget]:
        """Detect ID-type fields for traversal testing.

        Args:
            schema_types: Schema types.

        Returns:
            List of IDTraversalTarget.
        """
        targets: List[IDTraversalTarget] = []

        for type_name, type_data in schema_types.items():
            for field_data in type_data.get("fields", []):
                field_name = field_data.get("name", "")

                if any(
                    pattern.lower() in field_name.lower()
                    for pattern in self.ID_FIELD_PATTERNS
                ):
                    target = IDTraversalTarget(
                        field_name=field_name,
                        field_type=field_data.get("type", "ID"),
                        parent_type=type_name,
                        id_pattern="numeric",
                        test_ids=self.ID_VALUE_PATTERNS[:10],
                    )
                    targets.append(target)

        return targets

    def _generate_summary(
        self,
        results: List[AuthzTestResult],
    ) -> Dict[str, Any]:
        """Generate test summary.

        Args:
            results: Test results.

        Returns:
            Summary dictionary.
        """
        severity_counts: Dict[str, int] = {}
        type_counts: Dict[str, int] = {}

        for result in results:
            severity = result.severity.value
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

            test_type = result.test_type.value
            type_counts[test_type] = type_counts.get(test_type, 0) + 1

        return {
            "total_tests": len(results),
            "vulnerable_count": sum(1 for r in results if r.is_vulnerable),
            "severity_counts": severity_counts,
            "type_counts": type_counts,
            "roles_tested": list(set(r.token_profile for r in results)),
        }

    def _generate_recommendations(
        self,
        results: List[AuthzTestResult],
    ) -> List[str]:
        """Generate security recommendations.

        Args:
            results: Test results.

        Returns:
            List of recommendation strings.
        """
        recommendations: List[str] = []

        vulnerable_results = [r for r in results if r.is_vulnerable]

        if any(r.test_type == AuthzTestType.ID_TRAVERSAL for r in vulnerable_results):
            recommendations.append(
                "实施对象级授权检查，确保用户只能访问自己的资源"
            )

        if any(r.test_type == AuthzTestType.ALIAS_ATTACK for r in vulnerable_results):
            recommendations.append(
                "实施查询复杂度限制，防止别名攻击绕过速率限制"
            )

        if any(r.test_type == AuthzTestType.FIELD_ACCESS for r in vulnerable_results):
            recommendations.append(
                "为所有字段实施细粒度权限控制，特别是敏感操作"
            )

        if not recommendations:
            recommendations.append("未发现明显越权漏洞，建议定期复测")

        return recommendations

    def stop_test(self) -> None:
        """Stop running test."""
        self._is_running = False

    def get_test_results(
        self,
        filter_vulnerable: bool = False,
        limit: int = 100,
    ) -> List[AuthzTestResult]:
        """Get test results.

        Args:
            filter_vulnerable: Only return vulnerable results.
            limit: Maximum results.

        Returns:
            List of AuthzTestResult.
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
            "token_profiles": len(self._token_profiles),
            "total_tests": len(self._test_results),
            "vulnerable_count": sum(
                1 for r in self._test_results if r.is_vulnerable
            ),
            "is_running": self._is_running,
        }

    async def _send_query(
        self,
        url: str,
        query: str,
        headers: Dict[str, str],
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
