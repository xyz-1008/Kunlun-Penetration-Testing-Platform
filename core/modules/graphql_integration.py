"""GraphQL integration layer with proxy, Fuzzer, JWT module, and passive scanning engine.

Provides:
- Automatic GraphQL request identification and marking in proxy traffic
- Protocol-based traffic filtering
- Protobuf decoding structure display in detail panel
- Passive scanning engine with GraphQL-specific rules
- Asset recognition for GraphQL services and methods
- Integration with Web Fuzzer for automated attack testing
- JWT/OAuth module联动 for privilege escalation testing
"""

import asyncio
import json
import logging
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Coroutine, Dict, List, Optional, Set, Tuple

from core.modules.graphql_detector import (
    GraphQLDetector,
    GraphQLMethod,
    GraphQLRequest,
    GraphQLEndpoint,
)
from core.modules.graphql_introspector import (
    GraphQLIntrospector,
    GraphQLSchema,
    GraphQLType,
    GraphQLTypeKind,
)
from core.modules.graphql_authz_tester import (
    GraphQLAuthzTester,
    AuthzTestResult,
    AuthzReport,
    TokenProfile,
)
from core.modules.graphql_attacks import (
    GraphQLAttacks,
    AttackResult,
    AttackReport,
    AttackType,
)

logger = logging.getLogger(__name__)


class ScanRuleID(Enum):
    """GraphQL passive scan rule IDs."""
    GRAPHQL_001 = "graphql-001"
    GRAPHQL_002 = "graphql-002"
    GRAPHQL_003 = "graphql-003"
    GRAPHQL_004 = "graphql-004"
    GRAPHQL_005 = "graphql-005"
    GRAPHQL_006 = "graphql-006"


class SeverityLevel(Enum):
    """Vulnerability severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class ScanRule:
    """Passive scan rule definition.

    Attributes:
        rule_id: Rule ID
        name: Rule name
        description: Rule description
        severity: Rule severity
        is_enabled: Whether rule is enabled
        category: Rule category
    """
    rule_id: str = ""
    name: str = ""
    description: str = ""
    severity: SeverityLevel = SeverityLevel.INFO
    is_enabled: bool = True
    category: str = ""


@dataclass
class PassiveFinding:
    """Passive scan finding.

    Attributes:
        finding_id: Finding ID
        timestamp: Finding timestamp
        rule_id: Triggered rule ID
        severity: Finding severity
        title: Finding title
        description: Finding description
        request_url: Request URL
        request_data: Request data
        response_data: Response data
        remediation: Remediation advice
        mitre_mapping: MITRE ATT&CK mapping
    """
    finding_id: str = ""
    timestamp: float = 0.0
    rule_id: str = ""
    severity: SeverityLevel = SeverityLevel.INFO
    title: str = ""
    description: str = ""
    request_url: str = ""
    request_data: Dict[str, Any] = field(default_factory=dict)
    response_data: Dict[str, Any] = field(default_factory=dict)
    remediation: str = ""
    mitre_mapping: Dict[str, str] = field(default_factory=dict)


@dataclass
class GraphQLAsset:
    """GraphQL asset definition.

    Attributes:
        asset_id: Asset ID
        endpoint_url: Endpoint URL
        schema: GraphQL schema
        discovered_at: Discovery timestamp
        last_seen: Last seen timestamp
        is_active: Whether asset is active
        tags: Asset tags
        methods_count: Number of methods
        fields_count: Number of fields
        sensitive_fields_count: Number of sensitive fields
    """
    asset_id: str = ""
    endpoint_url: str = ""
    schema: Optional[GraphQLSchema] = None
    discovered_at: float = 0.0
    last_seen: float = 0.0
    is_active: bool = True
    tags: List[str] = field(default_factory=list)
    methods_count: int = 0
    fields_count: int = 0
    sensitive_fields_count: int = 0


@dataclass
class FuzzTask:
    """Fuzz task definition.

    Attributes:
        task_id: Task ID
        endpoint_url: Target endpoint
        target_field: Target field
        fuzz_payloads: Fuzz payloads
        status: Task status
        progress: Task progress
        results: Task results
        created_at: Creation timestamp
        completed_at: Completion timestamp
    """
    task_id: str = ""
    endpoint_url: str = ""
    target_field: str = ""
    fuzz_payloads: List[str] = field(default_factory=list)
    status: str = "pending"
    progress: float = 0.0
    results: List[Dict[str, Any]] = field(default_factory=list)
    created_at: float = 0.0
    completed_at: float = 0.0


class GraphQLIntegration:
    """GraphQL integration layer.

    Provides integration with proxy, passive scanning, asset recognition,
    Web Fuzzer, and JWT/OAuth modules.
    """

    DEFAULT_SCAN_RULES: List[ScanRule] = [
        ScanRule(
            rule_id=ScanRuleID.GRAPHQL_001.value,
            name="GraphQL 内省启用",
            description="GraphQL 端点启用了内省查询，可能暴露敏感Schema信息",
            severity=SeverityLevel.MEDIUM,
            is_enabled=True,
            category="信息泄露",
        ),
        ScanRule(
            rule_id=ScanRuleID.GRAPHQL_002.value,
            name="GraphQL 敏感字段暴露",
            description="响应中包含敏感字段（password, token, apiKey等）",
            severity=SeverityLevel.HIGH,
            is_enabled=True,
            category="敏感信息泄露",
        ),
        ScanRule(
            rule_id=ScanRuleID.GRAPHQL_003.value,
            name="GraphQL 错误信息泄露",
            description="响应中包含详细错误信息，可能泄露内部实现细节",
            severity=SeverityLevel.MEDIUM,
            is_enabled=True,
            category="信息泄露",
        ),
        ScanRule(
            rule_id=ScanRuleID.GRAPHQL_004.value,
            name="GraphQL 未授权访问",
            description="GraphQL 端点未实施访问控制，允许未授权查询",
            severity=SeverityLevel.HIGH,
            is_enabled=True,
            category="未授权访问",
        ),
        ScanRule(
            rule_id=ScanRuleID.GRAPHQL_005.value,
            name="GraphQL 批量查询风险",
            description="允许批量查询，可能被用于数据枚举攻击",
            severity=SeverityLevel.MEDIUM,
            is_enabled=True,
            category="业务逻辑",
        ),
        ScanRule(
            rule_id=ScanRuleID.GRAPHQL_006.value,
            name="GraphQL 调试接口暴露",
            description="GraphQL 调试接口（GraphiQL/Playground）在生产环境暴露",
            severity=SeverityLevel.LOW,
            is_enabled=True,
            category="配置错误",
        ),
    ]

    def __init__(
        self,
        event_bus: Optional[Any] = None,
        proxy_module: Optional[Any] = None,
        scanner_module: Optional[Any] = None,
        asset_module: Optional[Any] = None,
        fuzzer_module: Optional[Any] = None,
        jwt_module: Optional[Any] = None,
    ) -> None:
        """Initialize GraphQL integration layer.

        Args:
            event_bus: Event bus for broadcasting events.
            proxy_module: Proxy module reference.
            scanner_module: Passive scanner module reference.
            asset_module: Asset recognition module reference.
            fuzzer_module: Web Fuzzer module reference.
            jwt_module: JWT/OAuth module reference.
        """
        self.event_bus = event_bus
        self.proxy_module = proxy_module
        self.scanner_module = scanner_module
        self.asset_module = asset_module
        self.fuzzer_module = fuzzer_module
        self.jwt_module = jwt_module

        self.detector = GraphQLDetector(event_bus=event_bus)
        self.introspector = GraphQLIntrospector(event_bus=event_bus)
        self.authz_tester = GraphQLAuthzTester(event_bus=event_bus)
        self.attacks = GraphQLAttacks(event_bus=event_bus)

        self._progress_callback: Optional[Callable[[str, float], Coroutine[Any, Any, None]]] = None
        self._log_callback: Optional[Callable[[str], Coroutine[Any, Any, None]]] = None
        self._vulnerability_callback: Optional[Callable[[Dict[str, Any]], Coroutine[Any, Any, None]]] = None

        self._scan_rules: Dict[str, ScanRule] = {
            rule.rule_id: rule for rule in self.DEFAULT_SCAN_RULES
        }

        self._passive_findings: List[PassiveFinding] = []
        self._assets: Dict[str, GraphQLAsset] = {}
        self._fuzz_tasks: Dict[str, FuzzTask] = {}

    def set_callbacks(
        self,
        progress_cb: Optional[Callable[[str, float], Coroutine[Any, Any, None]]] = None,
        log_cb: Optional[Callable[[str], Coroutine[Any, Any, None]]] = None,
        vuln_cb: Optional[Callable[[Dict[str, Any]], Coroutine[Any, Any, None]]] = None,
    ) -> None:
        """Set integration callbacks.

        Args:
            progress_cb: Progress callback (message, percentage).
            log_cb: Log callback.
            vuln_cb: Vulnerability callback for reporting findings.
        """
        self._progress_callback = progress_cb
        self._log_callback = log_cb
        self._vulnerability_callback = vuln_cb

        self.detector.set_callbacks(progress_cb, log_cb)
        self.introspector.set_callbacks(progress_cb, log_cb)
        self.authz_tester.set_callbacks(progress_cb, log_cb)
        self.attacks.set_callbacks(progress_cb, log_cb)

    async def _report_progress(self, message: str, percentage: float) -> None:
        """Report progress via callback.

        Args:
            message: Progress message.
            percentage: Progress percentage (0-100).
        """
        if self._progress_callback:
            await self._progress_callback(message, percentage)
        logger.info("GraphQL Integration Progress: %.1f%% - %s", percentage, message)

    async def _report_log(self, message: str) -> None:
        """Report log via callback.

        Args:
            message: Log message.
        """
        if self._log_callback:
            await self._log_callback(message)
        logger.info("GraphQL Integration: %s", message)

    async def _report_vulnerability(self, finding: PassiveFinding) -> None:
        """Report vulnerability finding.

        Args:
            finding: PassiveFinding to report.
        """
        if self._vulnerability_callback:
            await self._vulnerability_callback({
                "finding_id": finding.finding_id,
                "rule_id": finding.rule_id,
                "severity": finding.severity.value,
                "title": finding.title,
                "description": finding.description,
                "url": finding.request_url,
                "mitre_mapping": finding.mitre_mapping,
            })

    async def process_proxy_request(
        self,
        method: str,
        url: str,
        headers: Dict[str, str],
        body: bytes,
        response_headers: Optional[Dict[str, str]] = None,
        response_body: Optional[bytes] = None,
    ) -> Optional[GraphQLRequest]:
        """Process proxy request for GraphQL detection.

        Args:
            method: HTTP method.
            url: Request URL.
            headers: HTTP headers.
            body: Request body.
            response_headers: Response headers.
            response_body: Response body.

        Returns:
            GraphQLRequest if detected, None otherwise.
        """
        content_type = headers.get("content-type", "")

        is_graphql_content = self.detector.is_graphql_content_type(content_type)
        has_graphql_keywords = self.detector.has_graphql_keywords(
            body.decode("utf-8", errors="replace")
        )

        if is_graphql_content or has_graphql_keywords:
            request = await self.detector.parse_graphql_request(
                method, url, headers, body
            )

            if request:
                await self._run_passive_scan(
                    request, response_headers, response_body
                )

                await self._register_asset(url, request)

                return request

        return None

    async def _run_passive_scan(
        self,
        request: GraphQLRequest,
        response_headers: Optional[Dict[str, str]],
        response_body: Optional[bytes],
    ) -> List[PassiveFinding]:
        """Run passive scan rules on GraphQL request/response.

        Args:
            request: GraphQL request.
            response_headers: Response headers.
            response_body: Response body.

        Returns:
            List of PassiveFinding.
        """
        findings: List[PassiveFinding] = []

        response_str = response_body.decode("utf-8", errors="replace") if response_body else ""

        try:
            response_data = json.loads(response_str) if response_str else {}
        except json.JSONDecodeError:
            response_data = {}

        for rule_id, rule in self._scan_rules.items():
            if not rule.is_enabled:
                continue

            finding = await self._evaluate_rule(
                rule, request, response_headers, response_data
            )

            if finding:
                findings.append(finding)
                self._passive_findings.append(finding)
                await self._report_vulnerability(finding)

        return findings

    async def _evaluate_rule(
        self,
        rule: ScanRule,
        request: GraphQLRequest,
        response_headers: Optional[Dict[str, str]],
        response_data: Dict[str, Any],
    ) -> Optional[PassiveFinding]:
        """Evaluate single scan rule.

        Args:
            rule: Scan rule.
            request: GraphQL request.
            response_headers: Response headers.
            response_data: Response data.

        Returns:
            PassiveFinding if rule triggered, None otherwise.
        """
        if rule.rule_id == ScanRuleID.GRAPHQL_001.value:
            return await self._check_introspection_enabled(rule, request, response_data)
        elif rule.rule_id == ScanRuleID.GRAPHQL_002.value:
            return await self._check_sensitive_fields(rule, request, response_data)
        elif rule.rule_id == ScanRuleID.GRAPHQL_003.value:
            return await self._check_error_disclosure(rule, request, response_data)
        elif rule.rule_id == ScanRuleID.GRAPHQL_004.value:
            return await self._check_unauthorized_access(rule, request, response_data)
        elif rule.rule_id == ScanRuleID.GRAPHQL_005.value:
            return await self._check_batch_query(rule, request, response_data)
        elif rule.rule_id == ScanRuleID.GRAPHQL_006.value:
            return await self._check_debug_interface(rule, request, response_data)

        return None

    async def _check_introspection_enabled(
        self,
        rule: ScanRule,
        request: GraphQLRequest,
        response_data: Dict[str, Any],
    ) -> Optional[PassiveFinding]:
        """Check if introspection is enabled.

        Args:
            rule: Scan rule.
            request: GraphQL request.
            response_data: Response data.

        Returns:
            PassiveFinding if triggered.
        """
        if "__schema" in request.query.lower():
            data = response_data.get("data", {})
            if "__schema" in data:
                return PassiveFinding(
                    finding_id=f"finding_{uuid.uuid4().hex[:8]}",
                    timestamp=time.time(),
                    rule_id=rule.rule_id,
                    severity=rule.severity,
                    title="GraphQL 内省查询已启用",
                    description="目标GraphQL端点允许内省查询，攻击者可获取完整Schema信息",
                    request_url=request.url,
                    request_data={"query": request.query},
                    response_data=response_data,
                    remediation="在生产环境禁用内省查询，或使用 persisted queries",
                    mitre_mapping={
                        "technique_id": "T1082",
                        "technique_name": "System Information Discovery",
                        "tactic": "Discovery",
                    },
                )
        return None

    async def _check_sensitive_fields(
        self,
        rule: ScanRule,
        request: GraphQLRequest,
        response_data: Dict[str, Any],
    ) -> Optional[PassiveFinding]:
        """Check for sensitive field exposure.

        Args:
            rule: Scan rule.
            request: GraphQL request.
            response_data: Response data.

        Returns:
            PassiveFinding if triggered.
        """
        sensitive_patterns = [
            "password", "token", "secret", "apiKey", "creditCard",
            "ssn", "privateKey", "authorization",
        ]

        response_str = json.dumps(response_data).lower()

        for pattern in sensitive_patterns:
            if pattern.lower() in response_str:
                return PassiveFinding(
                    finding_id=f"finding_{uuid.uuid4().hex[:8]}",
                    timestamp=time.time(),
                    rule_id=rule.rule_id,
                    severity=rule.severity,
                    title=f"敏感字段暴露: {pattern}",
                    description=f"响应中包含敏感字段 '{pattern}'，可能导致信息泄露",
                    request_url=request.url,
                    request_data={"query": request.query},
                    response_data=response_data,
                    remediation="从响应中移除敏感字段，或使用字段级权限控制",
                    mitre_mapping={
                        "technique_id": "T1005",
                        "technique_name": "Data from Local System",
                        "tactic": "Collection",
                    },
                )

        return None

    async def _check_error_disclosure(
        self,
        rule: ScanRule,
        request: GraphQLRequest,
        response_data: Dict[str, Any],
    ) -> Optional[PassiveFinding]:
        """Check for error information disclosure.

        Args:
            rule: Scan rule.
            request: GraphQL request.
            response_data: Response data.

        Returns:
            PassiveFinding if triggered.
        """
        errors = response_data.get("errors", [])

        if errors:
            for error in errors:
                message = error.get("message", "")
                if any(
                    keyword in message.lower()
                    for keyword in ["stack trace", "traceback", "internal", "sql", "query"]
                ):
                    return PassiveFinding(
                        finding_id=f"finding_{uuid.uuid4().hex[:8]}",
                        timestamp=time.time(),
                        rule_id=rule.rule_id,
                        severity=rule.severity,
                        title="GraphQL 错误信息泄露",
                        description=f"响应包含详细错误信息: {message[:100]}",
                        request_url=request.url,
                        request_data={"query": request.query},
                        response_data=response_data,
                        remediation="实施通用错误响应，不泄露内部实现细节",
                        mitre_mapping={
                            "technique_id": "T2005",
                            "technique_name": "Error Message Analysis",
                            "tactic": "Discovery",
                        },
                    )

        return None

    async def _check_unauthorized_access(
        self,
        rule: ScanRule,
        request: GraphQLRequest,
        response_data: Dict[str, Any],
    ) -> Optional[PassiveFinding]:
        """Check for unauthorized access.

        Args:
            rule: Scan rule.
            request: GraphQL request.
            response_data: Response data.

        Returns:
            PassiveFinding if triggered.
        """
        auth_headers = [
            "authorization", "x-api-key", "x-auth-token",
            "cookie", "x-csrf-token",
        ]

        has_auth = any(
            header in request.headers
            for header in auth_headers
        )

        if not has_auth:
            data = response_data.get("data", {})
            if data:
                return PassiveFinding(
                    finding_id=f"finding_{uuid.uuid4().hex[:8]}",
                    timestamp=time.time(),
                    rule_id=rule.rule_id,
                    severity=rule.severity,
                    title="GraphQL 未授权访问",
                    description="GraphQL端点无需认证即可访问，允许未授权查询",
                    request_url=request.url,
                    request_data={"query": request.query},
                    response_data=response_data,
                    remediation="实施认证和授权控制，验证所有请求的身份",
                    mitre_mapping={
                        "technique_id": "T1078",
                        "technique_name": "Valid Accounts",
                        "tactic": "Defense Evasion",
                    },
                )

        return None

    async def _check_batch_query(
        self,
        rule: ScanRule,
        request: GraphQLRequest,
        response_data: Dict[str, Any],
    ) -> Optional[PassiveFinding]:
        """Check for batch query risk.

        Args:
            rule: Scan rule.
            request: GraphQL request.
            response_data: Response data.

        Returns:
            PassiveFinding if triggered.
        """
        if request.is_batch and request.batch_count > 5:
            return PassiveFinding(
                finding_id=f"finding_{uuid.uuid4().hex[:8]}",
                timestamp=time.time(),
                rule_id=rule.rule_id,
                severity=rule.severity,
                title="GraphQL 批量查询风险",
                description=f"请求包含 {request.batch_count} 个批量操作，可能被用于数据枚举",
                request_url=request.url,
                request_data={"query": request.query, "batch_count": request.batch_count},
                response_data=response_data,
                remediation="限制批量查询数量，实施查询复杂度限制",
                mitre_mapping={
                    "technique_id": "T1110",
                    "technique_name": "Brute Force",
                    "tactic": "Credential Access",
                },
            )

        return None

    async def _check_debug_interface(
        self,
        rule: ScanRule,
        request: GraphQLRequest,
        response_data: Dict[str, Any],
    ) -> Optional[PassiveFinding]:
        """Check for debug interface exposure.

        Args:
            rule: Scan rule.
            request: GraphQL request.
            response_data: Response data.

        Returns:
            PassiveFinding if triggered.
        """
        debug_paths = ["/graphiql", "/playground", "/altair", "/graphql/console"]

        for path in debug_paths:
            if path in request.url.lower():
                return PassiveFinding(
                    finding_id=f"finding_{uuid.uuid4().hex[:8]}",
                    timestamp=time.time(),
                    rule_id=rule.rule_id,
                    severity=rule.severity,
                    title="GraphQL 调试接口暴露",
                    description=f"GraphQL调试接口在 {path} 暴露，可能被用于交互式攻击",
                    request_url=request.url,
                    request_data={"query": request.query},
                    response_data=response_data,
                    remediation="在生产环境禁用调试接口",
                    mitre_mapping={
                        "technique_id": "T1082",
                        "technique_name": "System Information Discovery",
                        "tactic": "Discovery",
                    },
                )

        return None

    async def _register_asset(
        self,
        url: str,
        request: GraphQLRequest,
    ) -> None:
        """Register GraphQL asset.

        Args:
            url: Endpoint URL.
            request: GraphQL request.
        """
        if url not in self._assets:
            asset = GraphQLAsset(
                asset_id=f"asset_{uuid.uuid4().hex[:8]}",
                endpoint_url=url,
                discovered_at=time.time(),
                last_seen=time.time(),
                tags=["graphql", "auto_discovered"],
            )
            self._assets[url] = asset
        else:
            self._assets[url].last_seen = time.time()

        if request.operation_name:
            self._assets[url].tags.append(request.operation_name)

    async def introspect_endpoint(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
    ) -> Optional[GraphQLSchema]:
        """Introspect GraphQL endpoint and register asset.

        Args:
            url: Endpoint URL.
            headers: HTTP headers.

        Returns:
            GraphQLSchema or None.
        """
        schema = await self.introspector.introspect(url, headers)

        if schema and url in self._assets:
            self._assets[url].schema = schema
            self._assets[url].methods_count = (
                len(schema.types.get(schema.query_type, GraphQLType()).fields)
                + len(schema.types.get(schema.mutation_type, GraphQLType()).fields)
            )
            self._assets[url].fields_count = sum(
                len(t.fields) for t in schema.types.values()
            )
            self._assets[url].sensitive_fields_count = len(schema.sensitive_fields)

        return schema

    async def run_authz_test(
        self,
        url: str,
        token_profiles: List[TokenProfile],
        headers: Optional[Dict[str, str]] = None,
    ) -> Optional[AuthzReport]:
        """Run authorization test with token switching.

        Args:
            url: Endpoint URL.
            token_profiles: Token profiles for testing.
            headers: Base HTTP headers.

        Returns:
            AuthzReport or None.
        """
        for profile in token_profiles:
            self.authz_tester.add_token_profile(
                profile.name, profile.token, profile.role, profile.permissions
            )

        schema = self.introspector.get_schema(url)
        if not schema:
            schema = await self.introspect_endpoint(url, headers)

        if not schema:
            await self._report_log(f"无法获取Schema，跳过越权测试: {url}")
            return None

        schema_types: Dict[str, Any] = {}
        for type_name, graphql_type in schema.types.items():
            schema_types[type_name] = {
                "name": graphql_type.name,
                "kind": graphql_type.kind.value,
                "fields": [
                    {
                        "name": f.name,
                        "type": f.field_type,
                        "args": [
                            {
                                "name": a.name,
                                "type": a.arg_type,
                                "is_required": a.is_required,
                            }
                            for a in f.args
                        ],
                    }
                    for f in graphql_type.fields
                ],
            }

        report = await self.authz_tester.run_full_authz_test(
            url, schema_types, headers
        )

        return report

    async def run_attack_suite(
        self,
        url: str,
        target_fields: List[str],
        query_templates: Optional[Dict[str, str]] = None,
        headers: Optional[Dict[str, str]] = None,
        attack_types: Optional[List[AttackType]] = None,
    ) -> Optional[AttackReport]:
        """Run attack suite on GraphQL endpoint.

        Args:
            url: Endpoint URL.
            target_fields: Target fields.
            query_templates: Query templates.
            headers: HTTP headers.
            attack_types: Attack types to run.

        Returns:
            AttackReport or None.
        """
        templates = query_templates or {}
        for field_name in target_fields:
            if field_name not in templates:
                templates[field_name] = f"query {{ {field_name} {{ id }} }}"

        report = await self.attacks.run_full_attack_suite(
            url, target_fields, templates, headers, attack_types
        )

        return report

    async def send_to_fuzzer(
        self,
        url: str,
        query: str,
        fuzz_payloads: Optional[List[str]] = None,
    ) -> Optional[FuzzTask]:
        """Send GraphQL query to Web Fuzzer.

        Args:
            url: Endpoint URL.
            query: GraphQL query.
            fuzz_payloads: Fuzz payloads.

        Returns:
            FuzzTask or None.
        """
        if not self.fuzzer_module:
            await self._report_log("Web Fuzzer模块未加载")
            return None

        task = FuzzTask(
            task_id=f"fuzz_{uuid.uuid4().hex[:8]}",
            endpoint_url=url,
            target_field="query",
            fuzz_payloads=fuzz_payloads or [],
            status="pending",
            created_at=time.time(),
        )

        self._fuzz_tasks[task.task_id] = task

        await self._report_log(f"GraphQL查询已发送到Fuzzer: {task.task_id}")

        return task

    def get_scan_rules(self) -> List[ScanRule]:
        """Get all scan rules.

        Returns:
            List of ScanRule.
        """
        return list(self._scan_rules.values())

    def toggle_scan_rule(self, rule_id: str, enabled: bool) -> bool:
        """Toggle scan rule.

        Args:
            rule_id: Rule ID.
            enabled: Whether to enable.

        Returns:
            Whether rule was found and toggled.
        """
        if rule_id in self._scan_rules:
            self._scan_rules[rule_id].is_enabled = enabled
            return True
        return False

    def get_passive_findings(
        self,
        limit: int = 100,
        severity_filter: Optional[SeverityLevel] = None,
    ) -> List[PassiveFinding]:
        """Get passive scan findings.

        Args:
            limit: Maximum findings.
            severity_filter: Filter by severity.

        Returns:
            List of PassiveFinding.
        """
        findings = self._passive_findings

        if severity_filter:
            findings = [f for f in findings if f.severity == severity_filter]

        return findings[-limit:]

    def get_assets(self) -> List[GraphQLAsset]:
        """Get all GraphQL assets.

        Returns:
            List of GraphQLAsset.
        """
        return list(self._assets.values())

    def get_asset(self, url: str) -> Optional[GraphQLAsset]:
        """Get GraphQL asset by URL.

        Args:
            url: Endpoint URL.

        Returns:
            GraphQLAsset or None.
        """
        return self._assets.get(url)

    def get_fuzz_tasks(self) -> List[FuzzTask]:
        """Get all fuzz tasks.

        Returns:
            List of FuzzTask.
        """
        return list(self._fuzz_tasks.values())

    def get_stats(self) -> Dict[str, Any]:
        """Get integration statistics.

        Returns:
            Statistics dictionary.
        """
        return {
            "detector": self.detector.get_stats(),
            "introspector": self.introspector.get_stats(),
            "authz_tester": self.authz_tester.get_stats(),
            "attacks": self.attacks.get_stats(),
            "assets": len(self._assets),
            "passive_findings": len(self._passive_findings),
            "fuzz_tasks": len(self._fuzz_tasks),
            "scan_rules_enabled": sum(
                1 for r in self._scan_rules.values() if r.is_enabled
            ),
        }
