"""GraphQL enterprise features: schema version comparison, multi-endpoint management, and federation visualization.

Provides:
- Schema version comparison with change detection (add/delete/modify types, fields, parameters)
- Multi-endpoint management for simultaneous introspection results
- Cross-endpoint schema comparison with shared types and differences
- GraphQL Federation visualization for microservice architectures
- Change report with potential security risk highlighting
"""

import json
import logging
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Coroutine, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


class ChangeType(Enum):
    """Schema change types."""
    ADDED = "added"
    REMOVED = "removed"
    MODIFIED = "modified"
    RENAMED = "renamed"
    DEPRECATED = "deprecated"
    UNDEPRECATED = "undeprecated"


class ChangeSeverity(Enum):
    """Change severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class EndpointStatus(Enum):
    """Endpoint status."""
    ACTIVE = "active"
    INACTIVE = "inactive"
    ERROR = "error"
    PENDING = "pending"


@dataclass
class SchemaChange:
    """Schema change record.

    Attributes:
        change_id: Change ID
        timestamp: Change timestamp
        change_type: Change type
        severity: Change severity
        target_type: Target type name
        target_field: Target field name
        old_value: Old value
        new_value: New value
        description: Change description
        security_risk: Security risk description
    """
    change_id: str = ""
    timestamp: float = 0.0
    change_type: ChangeType = ChangeType.ADDED
    severity: ChangeSeverity = ChangeSeverity.INFO
    target_type: str = ""
    target_field: str = ""
    old_value: str = ""
    new_value: str = ""
    description: str = ""
    security_risk: str = ""


@dataclass
class SchemaVersion:
    """Schema version snapshot.

    Attributes:
        version_id: Version ID
        timestamp: Version timestamp
        endpoint_url: Endpoint URL
        schema_data: Schema data
        type_count: Type count
        field_count: Field count
        query_count: Query count
        mutation_count: Mutation count
    """
    version_id: str = ""
    timestamp: float = 0.0
    endpoint_url: str = ""
    schema_data: Dict[str, Any] = field(default_factory=dict)
    type_count: int = 0
    field_count: int = 0
    query_count: int = 0
    mutation_count: int = 0


@dataclass
class SchemaComparison:
    """Schema comparison result.

    Attributes:
        comparison_id: Comparison ID
        timestamp: Comparison timestamp
        old_version_id: Old version ID
        new_version_id: New version ID
        total_changes: Total changes
        changes: Schema changes
        summary: Summary statistics
        security_risks: Security risks identified
    """
    comparison_id: str = ""
    timestamp: float = 0.0
    old_version_id: str = ""
    new_version_id: str = ""
    total_changes: int = 0
    changes: List[SchemaChange] = field(default_factory=list)
    summary: Dict[str, Any] = field(default_factory=dict)
    security_risks: List[str] = field(default_factory=list)


@dataclass
class GraphQLEndpoint:
    """GraphQL endpoint information.

    Attributes:
        endpoint_id: Endpoint ID
        url: Endpoint URL
        name: Endpoint name
        status: Endpoint status
        last_introspected: Last introspection timestamp
        schema_version_id: Current schema version ID
        type_count: Type count
        field_count: Field count
        tags: Endpoint tags
    """
    endpoint_id: str = ""
    url: str = ""
    name: str = ""
    status: EndpointStatus = EndpointStatus.PENDING
    last_introspected: float = 0.0
    schema_version_id: str = ""
    type_count: int = 0
    field_count: int = 0
    tags: List[str] = field(default_factory=list)


@dataclass
class FederationInfo:
    """GraphQL Federation information.

    Attributes:
        federation_id: Federation ID
        name: Federation name
        services: Service list
        shared_types: Shared types across services
        unique_types: Unique types per service
        cross_service_dependencies: Cross-service dependencies
    """
    federation_id: str = ""
    name: str = ""
    services: List[Dict[str, Any]] = field(default_factory=list)
    shared_types: List[str] = field(default_factory=list)
    unique_types: Dict[str, List[str]] = field(default_factory=dict)
    cross_service_dependencies: List[Dict[str, Any]] = field(default_factory=list)


class GraphQLEnterprise:
    """GraphQL enterprise features module.

    Provides schema version comparison, multi-endpoint management,
    and federation visualization capabilities.
    """

    SENSITIVE_FIELD_PATTERNS: List[str] = [
        "password", "token", "secret", "apiKey", "creditCard",
        "ssn", "socialSecurity", "bankAccount", "cvv", "pin",
        "privateKey", "authToken", "refreshToken", "accessToken",
    ]

    HIGH_RISK_OPERATION_PATTERNS: List[str] = [
        "delete", "drop", "truncate", "execute", "impersonate",
        "resetPassword", "changeEmail", "transfer", "withdraw",
        "grantAccess", "revokeAccess", "admin", "sudo",
    ]

    def __init__(
        self,
        introspector: Optional[Any] = None,
        event_bus: Optional[Any] = None,
    ) -> None:
        """Initialize enterprise module.

        Args:
            introspector: GraphQL introspector module.
            event_bus: Event bus for broadcasting events.
        """
        self.introspector = introspector
        self.event_bus = event_bus

        self._schema_versions: Dict[str, SchemaVersion] = {}
        self._endpoint_registry: Dict[str, GraphQLEndpoint] = {}
        self._federation_registry: Dict[str, FederationInfo] = {}
        self._comparison_history: List[SchemaComparison] = []

        self._progress_callback: Optional[Callable[[str, float], Coroutine[Any, Any, None]]] = None
        self._log_callback: Optional[Callable[[str], Coroutine[Any, Any, None]]] = None

    def set_callbacks(
        self,
        progress_cb: Optional[Callable[[str, float], Coroutine[Any, Any, None]]] = None,
        log_cb: Optional[Callable[[str], Coroutine[Any, Any, None]]] = None,
    ) -> None:
        """Set progress and log callbacks.

        Args:
            progress_cb: Callback for progress updates.
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
        logger.info("Enterprise Progress: %.1f%% - %s", percentage, message)

    async def _report_log(self, message: str) -> None:
        """Report log via callback.

        Args:
            message: Log message.
        """
        if self._log_callback:
            await self._log_callback(message)
        logger.info("Enterprise: %s", message)

    def save_schema_version(
        self,
        endpoint_url: str,
        schema_data: Dict[str, Any],
    ) -> SchemaVersion:
        """Save schema version snapshot.

        Args:
            endpoint_url: Endpoint URL.
            schema_data: Schema data.

        Returns:
            SchemaVersion.
        """
        version_id = f"schema_{uuid.uuid4().hex[:8]}"

        types = schema_data.get("types", {})
        type_count = len(types)

        field_count = 0
        query_count = 0
        mutation_count = 0

        for type_name, type_data in types.items():
            fields = type_data.get("fields", [])
            field_count += len(fields)

            if type_name == "Query":
                query_count = len(fields)
            elif type_name == "Mutation":
                mutation_count = len(fields)

        version = SchemaVersion(
            version_id=version_id,
            timestamp=time.time(),
            endpoint_url=endpoint_url,
            schema_data=schema_data,
            type_count=type_count,
            field_count=field_count,
            query_count=query_count,
            mutation_count=mutation_count,
        )

        self._schema_versions[version_id] = version

        return version

    def compare_schema_versions(
        self,
        old_version_id: str,
        new_version_id: str,
    ) -> SchemaComparison:
        """Compare two schema versions.

        Args:
            old_version_id: Old version ID.
            new_version_id: New version ID.

        Returns:
            SchemaComparison.
        """
        old_version = self._schema_versions.get(old_version_id)
        new_version = self._schema_versions.get(new_version_id)

        if not old_version or not new_version:
            raise ValueError("Schema version not found")

        comparison = SchemaComparison(
            comparison_id=f"compare_{uuid.uuid4().hex[:8]}",
            timestamp=time.time(),
            old_version_id=old_version_id,
            new_version_id=new_version_id,
        )

        changes = self._diff_schemas(
            old_version.schema_data, new_version.schema_data
        )

        comparison.changes = changes
        comparison.total_changes = len(changes)
        comparison.summary = self._generate_comparison_summary(changes)
        comparison.security_risks = self._identify_security_risks(changes)

        self._comparison_history.append(comparison)

        return comparison

    def _diff_schemas(
        self,
        old_schema: Dict[str, Any],
        new_schema: Dict[str, Any],
    ) -> List[SchemaChange]:
        """Diff two schemas.

        Args:
            old_schema: Old schema data.
            new_schema: New schema data.

        Returns:
            List of SchemaChange.
        """
        changes: List[SchemaChange] = []

        old_types = old_schema.get("types", {})
        new_types = new_schema.get("types", {})

        old_type_names = set(old_types.keys())
        new_type_names = set(new_types.keys())

        added_types = new_type_names - old_type_names
        removed_types = old_type_names - new_type_names
        common_types = old_type_names & new_type_names

        for type_name in added_types:
            change = SchemaChange(
                change_id=f"change_{uuid.uuid4().hex[:8]}",
                timestamp=time.time(),
                change_type=ChangeType.ADDED,
                severity=self._assess_type_severity(type_name, ChangeType.ADDED),
                target_type=type_name,
                description=f"Type added: {type_name}",
                security_risk=self._assess_type_security_risk(type_name, ChangeType.ADDED),
            )
            changes.append(change)

        for type_name in removed_types:
            change = SchemaChange(
                change_id=f"change_{uuid.uuid4().hex[:8]}",
                timestamp=time.time(),
                change_type=ChangeType.REMOVED,
                severity=self._assess_type_severity(type_name, ChangeType.REMOVED),
                target_type=type_name,
                description=f"Type removed: {type_name}",
                security_risk=self._assess_type_security_risk(type_name, ChangeType.REMOVED),
            )
            changes.append(change)

        for type_name in common_types:
            type_changes = self._diff_type_fields(
                type_name,
                old_types[type_name],
                new_types[type_name],
            )
            changes.extend(type_changes)

        return changes

    def _diff_type_fields(
        self,
        type_name: str,
        old_type_data: Dict[str, Any],
        new_type_data: Dict[str, Any],
    ) -> List[SchemaChange]:
        """Diff type fields.

        Args:
            type_name: Type name.
            old_type_data: Old type data.
            new_type_data: New type data.

        Returns:
            List of SchemaChange.
        """
        changes: List[SchemaChange] = []

        old_fields = {f["name"]: f for f in old_type_data.get("fields", [])}
        new_fields = {f["name"]: f for f in new_type_data.get("fields", [])}

        old_field_names = set(old_fields.keys())
        new_field_names = set(new_fields.keys())

        added_fields = new_field_names - old_field_names
        removed_fields = old_field_names - new_field_names
        common_fields = old_field_names & new_field_names

        for field_name in added_fields:
            field_data = new_fields[field_name]
            change = SchemaChange(
                change_id=f"change_{uuid.uuid4().hex[:8]}",
                timestamp=time.time(),
                change_type=ChangeType.ADDED,
                severity=self._assess_field_severity(type_name, field_name, ChangeType.ADDED),
                target_type=type_name,
                target_field=field_name,
                new_value=json.dumps(field_data),
                description=f"Field added: {type_name}.{field_name}",
                security_risk=self._assess_field_security_risk(type_name, field_name, ChangeType.ADDED),
            )
            changes.append(change)

        for field_name in removed_fields:
            field_data = old_fields[field_name]
            change = SchemaChange(
                change_id=f"change_{uuid.uuid4().hex[:8]}",
                timestamp=time.time(),
                change_type=ChangeType.REMOVED,
                severity=self._assess_field_severity(type_name, field_name, ChangeType.REMOVED),
                target_type=type_name,
                target_field=field_name,
                old_value=json.dumps(field_data),
                description=f"Field removed: {type_name}.{field_name}",
                security_risk=self._assess_field_security_risk(type_name, field_name, ChangeType.REMOVED),
            )
            changes.append(change)

        for field_name in common_fields:
            old_field = old_fields[field_name]
            new_field = new_fields[field_name]

            if old_field != new_field:
                change = SchemaChange(
                    change_id=f"change_{uuid.uuid4().hex[:8]}",
                    timestamp=time.time(),
                    change_type=ChangeType.MODIFIED,
                    severity=self._assess_field_severity(type_name, field_name, ChangeType.MODIFIED),
                    target_type=type_name,
                    target_field=field_name,
                    old_value=json.dumps(old_field),
                    new_value=json.dumps(new_field),
                    description=f"Field modified: {type_name}.{field_name}",
                    security_risk=self._assess_field_security_risk(type_name, field_name, ChangeType.MODIFIED),
                )
                changes.append(change)

                old_deprecated = old_field.get("isDeprecated", False)
                new_deprecated = new_field.get("isDeprecated", False)

                if not old_deprecated and new_deprecated:
                    dep_change = SchemaChange(
                        change_id=f"change_{uuid.uuid4().hex[:8]}",
                        timestamp=time.time(),
                        change_type=ChangeType.DEPRECATED,
                        severity=ChangeSeverity.LOW,
                        target_type=type_name,
                        target_field=field_name,
                        description=f"Field deprecated: {type_name}.{field_name}",
                    )
                    changes.append(dep_change)
                elif old_deprecated and not new_deprecated:
                    undep_change = SchemaChange(
                        change_id=f"change_{uuid.uuid4().hex[:8]}",
                        timestamp=time.time(),
                        change_type=ChangeType.UNDEPRECATED,
                        severity=ChangeSeverity.INFO,
                        target_type=type_name,
                        target_field=field_name,
                        description=f"Field undeprecated: {type_name}.{field_name}",
                    )
                    changes.append(undep_change)

        return changes

    def _assess_type_severity(
        self,
        type_name: str,
        change_type: ChangeType,
    ) -> ChangeSeverity:
        """Assess type change severity.

        Args:
            type_name: Type name.
            change_type: Change type.

        Returns:
            ChangeSeverity.
        """
        type_lower = type_name.lower()

        if change_type == ChangeType.ADDED:
            if any(p in type_lower for p in ["admin", "auth", "security", "config"]):
                return ChangeSeverity.HIGH
            return ChangeSeverity.MEDIUM
        elif change_type == ChangeType.REMOVED:
            return ChangeSeverity.HIGH
        else:
            return ChangeSeverity.INFO

    def _assess_field_severity(
        self,
        type_name: str,
        field_name: str,
        change_type: ChangeType,
    ) -> ChangeSeverity:
        """Assess field change severity.

        Args:
            type_name: Type name.
            field_name: Field name.
            change_type: Change type.

        Returns:
            ChangeSeverity.
        """
        field_lower = field_name.lower()

        if change_type == ChangeType.ADDED:
            if any(p in field_lower for p in self.SENSITIVE_FIELD_PATTERNS):
                return ChangeSeverity.CRITICAL
            if any(p in field_lower for p in self.HIGH_RISK_OPERATION_PATTERNS):
                return ChangeSeverity.HIGH
            return ChangeSeverity.MEDIUM
        elif change_type == ChangeType.REMOVED:
            return ChangeSeverity.MEDIUM
        else:
            return ChangeSeverity.LOW

    def _assess_type_security_risk(
        self,
        type_name: str,
        change_type: ChangeType,
    ) -> str:
        """Assess type security risk.

        Args:
            type_name: Type name.
            change_type: Change type.

        Returns:
            Security risk description.
        """
        type_lower = type_name.lower()

        if change_type == ChangeType.ADDED:
            if any(p in type_lower for p in ["admin", "auth", "security"]):
                return "新增敏感类型，可能引入权限控制问题"
            return "新增类型，需评估访问控制"
        elif change_type == ChangeType.REMOVED:
            return "类型删除，需确认无依赖断裂"
        else:
            return ""

    def _assess_field_security_risk(
        self,
        type_name: str,
        field_name: str,
        change_type: ChangeType,
    ) -> str:
        """Assess field security risk.

        Args:
            type_name: Type name.
            field_name: Field name.
            change_type: Change type.

        Returns:
            Security risk description.
        """
        field_lower = field_name.lower()

        if change_type == ChangeType.ADDED:
            if any(p in field_lower for p in self.SENSITIVE_FIELD_PATTERNS):
                return "新增敏感字段，可能存在信息泄露风险"
            if any(p in field_lower for p in self.HIGH_RISK_OPERATION_PATTERNS):
                return "新增高风险操作，需验证权限控制"
            return "新增字段，需评估数据暴露风险"
        elif change_type == ChangeType.REMOVED:
            return "字段删除，需确认客户端兼容性"
        elif change_type == ChangeType.MODIFIED:
            return "字段修改，需验证类型兼容性"
        else:
            return ""

    def _generate_comparison_summary(
        self,
        changes: List[SchemaChange],
    ) -> Dict[str, Any]:
        """Generate comparison summary.

        Args:
            changes: Schema changes.

        Returns:
            Summary dictionary.
        """
        type_counts: Dict[str, int] = {}
        severity_counts: Dict[str, int] = {}

        for change in changes:
            change_type = change.change_type.value
            type_counts[change_type] = type_counts.get(change_type, 0) + 1

            severity = change.severity.value
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        return {
            "total_changes": len(changes),
            "type_counts": type_counts,
            "severity_counts": severity_counts,
            "critical_changes": severity_counts.get("critical", 0),
            "high_changes": severity_counts.get("high", 0),
        }

    def _identify_security_risks(
        self,
        changes: List[SchemaChange],
    ) -> List[str]:
        """Identify security risks from changes.

        Args:
            changes: Schema changes.

        Returns:
            List of security risk descriptions.
        """
        risks: List[str] = []

        for change in changes:
            if change.security_risk:
                risks.append(
                    f"[{change.severity.value.upper()}] {change.description}: "
                    f"{change.security_risk}"
                )

        return risks

    def register_endpoint(
        self,
        url: str,
        name: str,
        tags: Optional[List[str]] = None,
    ) -> GraphQLEndpoint:
        """Register GraphQL endpoint.

        Args:
            url: Endpoint URL.
            name: Endpoint name.
            tags: Endpoint tags.

        Returns:
            GraphQLEndpoint.
        """
        endpoint_id = f"endpoint_{uuid.uuid4().hex[:8]}"

        endpoint = GraphQLEndpoint(
            endpoint_id=endpoint_id,
            url=url,
            name=name,
            tags=tags or [],
        )

        self._endpoint_registry[endpoint_id] = endpoint

        return endpoint

    async def introspect_endpoint(
        self,
        endpoint_id: str,
    ) -> Optional[SchemaVersion]:
        """Introspect registered endpoint.

        Args:
            endpoint_id: Endpoint ID.

        Returns:
            SchemaVersion or None.
        """
        endpoint = self._endpoint_registry.get(endpoint_id)

        if not endpoint:
            return None

        if not self.introspector:
            return None

        schema_data = await self.introspector.introspect(endpoint.url)

        version = self.save_schema_version(endpoint.url, schema_data)

        endpoint.last_introspected = time.time()
        endpoint.schema_version_id = version.version_id
        endpoint.type_count = version.type_count
        endpoint.field_count = version.field_count
        endpoint.status = EndpointStatus.ACTIVE

        return version

    def compare_endpoints(
        self,
        endpoint_id_a: str,
        endpoint_id_b: str,
    ) -> Dict[str, Any]:
        """Compare two endpoints.

        Args:
            endpoint_id_a: First endpoint ID.
            endpoint_id_b: Second endpoint ID.

        Returns:
            Comparison dictionary.
        """
        endpoint_a = self._endpoint_registry.get(endpoint_id_a)
        endpoint_b = self._endpoint_registry.get(endpoint_id_b)

        if not endpoint_a or not endpoint_b:
            raise ValueError("Endpoint not found")

        version_a = self._schema_versions.get(endpoint_a.schema_version_id)
        version_b = self._schema_versions.get(endpoint_b.schema_version_id)

        if not version_a or not version_b:
            raise ValueError("Schema version not found")

        comparison = self.compare_schema_versions(
            version_a.version_id, version_b.version_id
        )

        return {
            "endpoint_a": endpoint_a.name,
            "endpoint_b": endpoint_b.name,
            "comparison": comparison,
        }

    def create_federation(
        self,
        name: str,
        service_endpoint_ids: List[str],
    ) -> FederationInfo:
        """Create federation from services.

        Args:
            name: Federation name.
            service_endpoint_ids: Service endpoint IDs.

        Returns:
            FederationInfo.
        """
        federation_id = f"federation_{uuid.uuid4().hex[:8]}"

        services: List[Dict[str, Any]] = []
        all_types: Dict[str, List[str]] = {}

        for endpoint_id in service_endpoint_ids:
            endpoint = self._endpoint_registry.get(endpoint_id)

            if endpoint:
                services.append({
                    "endpoint_id": endpoint_id,
                    "name": endpoint.name,
                    "url": endpoint.url,
                })

                version = self._schema_versions.get(endpoint.schema_version_id)

                if version:
                    types = version.schema_data.get("types", {})
                    for type_name in types:
                        if type_name not in all_types:
                            all_types[type_name] = []
                        all_types[type_name].append(endpoint.name)

        shared_types = [
            type_name for type_name, services_list in all_types.items()
            if len(services_list) > 1
        ]

        unique_types: Dict[str, List[str]] = {}
        for type_name, services_list in all_types.items():
            if len(services_list) == 1:
                service_name = services_list[0]
                if service_name not in unique_types:
                    unique_types[service_name] = []
                unique_types[service_name].append(type_name)

        cross_service_dependencies = self._find_cross_service_dependencies(
            all_types, service_endpoint_ids
        )

        federation = FederationInfo(
            federation_id=federation_id,
            name=name,
            services=services,
            shared_types=shared_types,
            unique_types=unique_types,
            cross_service_dependencies=cross_service_dependencies,
        )

        self._federation_registry[federation_id] = federation

        return federation

    def _find_cross_service_dependencies(
        self,
        all_types: Dict[str, List[str]],
        service_endpoint_ids: List[str],
    ) -> List[Dict[str, Any]]:
        """Find cross-service dependencies.

        Args:
            all_types: All types dictionary.
            service_endpoint_ids: Service endpoint IDs.

        Returns:
            List of cross-service dependencies.
        """
        dependencies: List[Dict[str, Any]] = []

        for type_name, services_list in all_types.items():
            if len(services_list) > 1:
                dependencies.append({
                    "type": type_name,
                    "services": services_list,
                    "dependency_type": "shared_type",
                })

        return dependencies

    def get_endpoint_registry(
        self,
        status_filter: Optional[EndpointStatus] = None,
    ) -> List[GraphQLEndpoint]:
        """Get endpoint registry.

        Args:
            status_filter: Filter by status.

        Returns:
            List of GraphQLEndpoint.
        """
        endpoints = list(self._endpoint_registry.values())

        if status_filter:
            endpoints = [e for e in endpoints if e.status == status_filter]

        return endpoints

    def get_federation_registry(
        self,
    ) -> List[FederationInfo]:
        """Get federation registry.

        Returns:
            List of FederationInfo.
        """
        return list(self._federation_registry.values())

    def get_schema_versions(
        self,
        endpoint_url: Optional[str] = None,
        limit: int = 10,
    ) -> List[SchemaVersion]:
        """Get schema versions.

        Args:
            endpoint_url: Filter by endpoint URL.
            limit: Maximum versions.

        Returns:
            List of SchemaVersion.
        """
        versions = list(self._schema_versions.values())

        if endpoint_url:
            versions = [v for v in versions if v.endpoint_url == endpoint_url]

        versions.sort(key=lambda v: v.timestamp, reverse=True)

        return versions[:limit]

    def get_comparison_history(
        self,
        limit: int = 10,
    ) -> List[SchemaComparison]:
        """Get comparison history.

        Args:
            limit: Maximum comparisons.

        Returns:
            List of SchemaComparison.
        """
        return self._comparison_history[-limit:]

    def get_stats(self) -> Dict[str, Any]:
        """Get enterprise module statistics.

        Returns:
            Statistics dictionary.
        """
        return {
            "schema_versions": len(self._schema_versions),
            "endpoints": len(self._endpoint_registry),
            "active_endpoints": sum(
                1 for e in self._endpoint_registry.values()
                if e.status == EndpointStatus.ACTIVE
            ),
            "federations": len(self._federation_registry),
            "comparisons": len(self._comparison_history),
        }
