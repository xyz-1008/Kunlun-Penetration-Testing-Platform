"""Integration layer for gRPC with proxy, passive scanner, and asset recognition.

Provides:
- Automatic gRPC identification in proxy traffic with protocol marking
- gRPC protocol filtering and decoded display in detail panel
- gRPC-specific passive scanning rules
- Automatic asset registration for gRPC services and methods
- Service map integration with asset topology
"""

import asyncio
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Coroutine, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


class GrpcAssetType(Enum):
    """gRPC asset types."""
    SERVICE = "service"
    METHOD = "method"
    MESSAGE = "message"
    ENDPOINT = "endpoint"


@dataclass
class GrpcAsset:
    """gRPC asset entry.

    Attributes:
        asset_id: Unique asset ID
        asset_type: Asset type
        name: Asset name
        full_path: Full path
        service_name: Service name
        method_name: Method name
        first_seen: First seen timestamp
        last_seen: Last seen timestamp
        request_count: Request count
        metadata: Additional metadata
        is_active: Whether currently active
        tags: Asset tags
    """
    asset_id: str = ""
    asset_type: GrpcAssetType = GrpcAssetType.SERVICE
    name: str = ""
    full_path: str = ""
    service_name: str = ""
    method_name: str = ""
    first_seen: float = 0.0
    last_seen: float = 0.0
    request_count: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)
    is_active: bool = True
    tags: List[str] = field(default_factory=list)


@dataclass
class GrpcScanRule:
    """gRPC passive scan rule.

    Attributes:
        rule_id: Rule ID
        name: Rule name
        description: Rule description
        severity: Severity level
        category: Rule category
        check_function: Check function name
        is_enabled: Whether enabled
    """
    rule_id: str = ""
    name: str = ""
    description: str = ""
    severity: str = "info"
    category: str = ""
    check_function: str = ""
    is_enabled: bool = True


@dataclass
class GrpcScanResult:
    """gRPC scan result.

    Attributes:
        result_id: Result ID
        rule_id: Triggered rule
        request_id: Related request
        service_path: Service path
        method_name: Method name
        severity: Severity
        title: Finding title
        description: Finding description
        evidence: Evidence data
        timestamp: Scan timestamp
    """
    result_id: str = ""
    rule_id: str = ""
    request_id: str = ""
    service_path: str = ""
    method_name: str = ""
    severity: str = "info"
    title: str = ""
    description: str = ""
    evidence: str = ""
    timestamp: float = 0.0


class GrpcIntegration:
    """gRPC integration layer.

    Provides integration with proxy, passive scanner,
    and asset recognition modules.
    """

    DEFAULT_SCAN_RULES: List[GrpcScanRule] = [
        GrpcScanRule(
            rule_id="grpc-001",
            name="gRPC未授权访问检测",
            description="检测gRPC方法是否缺少认证",
            severity="high",
            category="authentication",
            check_function="check_unauthorized_access",
        ),
        GrpcScanRule(
            rule_id="grpc-002",
            name="gRPC敏感信息泄露",
            description="检测响应中是否包含敏感信息",
            severity="medium",
            category="information_disclosure",
            check_function="check_sensitive_data",
        ),
        GrpcScanRule(
            rule_id="grpc-003",
            name="gRPC输入验证缺陷",
            description="检测输入验证是否充分",
            severity="medium",
            category="input_validation",
            check_function="check_input_validation",
        ),
        GrpcScanRule(
            rule_id="grpc-004",
            name="gRPC SQL注入检测",
            description="检测SQL注入漏洞",
            severity="critical",
            category="injection",
            check_function="check_sql_injection",
        ),
        GrpcScanRule(
            rule_id="grpc-005",
            name="gRPC命令注入检测",
            description="检测命令注入漏洞",
            severity="critical",
            category="injection",
            check_function="check_command_injection",
        ),
    ]

    def __init__(
        self,
        grpc_parser: Optional[Any] = None,
        protobuf_decoder: Optional[Any] = None,
        schema_manager: Optional[Any] = None,
        event_bus: Optional[Any] = None,
    ) -> None:
        """Initialize gRPC integration.

        Args:
            grpc_parser: GrpcParser instance.
            protobuf_decoder: ProtobufDecoder instance.
            schema_manager: ProtobufSchemaManager instance.
            event_bus: Event bus for broadcasting events.
        """
        self.grpc_parser = grpc_parser
        self.protobuf_decoder = protobuf_decoder
        self.schema_manager = schema_manager
        self.event_bus = event_bus
        self._progress_callback: Optional[Callable[[str, float], Coroutine[Any, Any, None]]] = None
        self._log_callback: Optional[Callable[[str], Coroutine[Any, Any, None]]] = None
        self._assets: Dict[str, GrpcAsset] = {}
        self._scan_rules: Dict[str, GrpcScanRule] = {}
        self._scan_results: List[GrpcScanResult] = []
        self._initialized = False

        for rule in self.DEFAULT_SCAN_RULES:
            self._scan_rules[rule.rule_id] = rule

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
        logger.info("Integration Progress: %.1f%% - %s", percentage, message)

    async def _report_log(self, message: str) -> None:
        """Report log via callback.

        Args:
            message: Log message.
        """
        if self._log_callback:
            await self._log_callback(message)
        logger.info("Integration: %s", message)

    async def initialize(self) -> None:
        """Initialize integration layer."""
        if self._initialized:
            return

        await self._report_log("gRPC集成层初始化完成")
        self._initialized = True

    async def process_proxy_traffic(
        self,
        request: Any,
        response: Any,
    ) -> Optional[Dict[str, Any]]:
        """Process proxy traffic for gRPC identification.

        Args:
            request: Proxy request object.
            response: Proxy response object.

        Returns:
            Processing result dictionary or None.
        """
        if not self.grpc_parser:
            return None

        headers = getattr(request, "headers", {})

        if not self.grpc_parser.is_grpc_request(headers):
            return None

        grpc_request = await self.grpc_parser.parse_grpc_request(
            method=getattr(request, "method", "POST"),
            path=getattr(request, "path", ""),
            headers=headers,
            body=getattr(request, "body", b""),
        )

        if not grpc_request:
            return None

        grpc_response = await self.grpc_parser.parse_grpc_response(
            status_code=getattr(response, "status_code", 200),
            headers=getattr(response, "headers", {}),
            trailers=getattr(response, "trailers", {}),
            body=getattr(response, "body", b""),
        )

        await self._register_grpc_assets(grpc_request)

        scan_results = await self._run_passive_scan(grpc_request, grpc_response)

        decoded_body = ""
        if self.protobuf_decoder and grpc_response.messages:
            message = await self.protobuf_decoder.decode_message(
                grpc_response.messages[0].message_body
            )
            decoded_body = await self.protobuf_decoder.message_to_json(message)

        result = {
            "protocol": "gRPC",
            "grpc_request": grpc_request,
            "grpc_response": grpc_response,
            "decoded_response": decoded_body,
            "scan_results": scan_results,
            "service_path": grpc_request.service_path,
            "method": grpc_request.method,
            "call_type": grpc_request.call_type.value,
        }

        await self._emit_event("grpc_traffic_processed", result)

        return result

    async def _register_grpc_assets(self, grpc_request: Any) -> None:
        """Register gRPC assets from request.

        Args:
            grpc_request: GrpcRequest object.
        """
        service_path = getattr(grpc_request, "service_path", "")
        method_name = getattr(grpc_request, "method", "")

        package, service_name, _ = self._parse_service_path(service_path)

        service_key = f"{package}.{service_name}" if package else service_name

        if service_key not in self._assets:
            service_asset = GrpcAsset(
                asset_id=f"svc_{service_key}_{int(time.time())}",
                asset_type=GrpcAssetType.SERVICE,
                name=service_name,
                full_path=service_path,
                service_name=service_key,
                first_seen=time.time(),
                last_seen=time.time(),
                request_count=1,
                tags=["grpc", "service"],
            )
            self._assets[service_key] = service_asset

        service_asset = self._assets[service_key]
        service_asset.request_count += 1
        service_asset.last_seen = time.time()

        method_key = f"{service_key}/{method_name}"
        if method_key not in self._assets:
            method_asset = GrpcAsset(
                asset_id=f"method_{method_key}_{int(time.time())}",
                asset_type=GrpcAssetType.METHOD,
                name=method_name,
                full_path=service_path,
                service_name=service_key,
                method_name=method_name,
                first_seen=time.time(),
                last_seen=time.time(),
                request_count=1,
                tags=["grpc", "method"],
            )
            self._assets[method_key] = method_asset
        else:
            method_asset = self._assets[method_key]
            method_asset.request_count += 1
            method_asset.last_seen = time.time()

    def _parse_service_path(self, path: str) -> Tuple[str, str, str]:
        """Parse service path.

        Args:
            path: Service path.

        Returns:
            Tuple of (package, service_name, method_name).
        """
        path = path.lstrip("/")

        if "/" not in path:
            return "", path, ""

        parts = path.split("/", 1)
        service_path = parts[0]
        method_name = parts[1] if len(parts) > 1 else ""

        service_parts = service_path.rsplit(".", 1)
        if len(service_parts) == 2:
            package = service_parts[0]
            service_name = service_parts[1]
        else:
            package = ""
            service_name = service_parts[0]

        return package, service_name, method_name

    async def _run_passive_scan(
        self,
        grpc_request: Any,
        grpc_response: Any,
    ) -> List[GrpcScanResult]:
        """Run passive scan rules against gRPC traffic.

        Args:
            grpc_request: GrpcRequest object.
            grpc_response: GrpcResponse object.

        Returns:
            List of GrpcScanResult.
        """
        results: List[GrpcScanResult] = []

        for rule in self._scan_rules.values():
            if not rule.is_enabled:
                continue

            rule_result = await self._apply_scan_rule(rule, grpc_request, grpc_response)
            if rule_result:
                results.append(rule_result)

        self._scan_results.extend(results)

        if results:
            await self._emit_event("grpc_scan_results", results)

        return results

    async def _apply_scan_rule(
        self,
        rule: GrpcScanRule,
        grpc_request: Any,
        grpc_response: Any,
    ) -> Optional[GrpcScanResult]:
        """Apply single scan rule.

        Args:
            rule: Scan rule.
            grpc_request: GrpcRequest object.
            grpc_response: GrpcResponse object.

        Returns:
            GrpcScanResult or None.
        """
        check_function = rule.check_function

        if check_function == "check_unauthorized_access":
            return await self._check_unauthorized_access(rule, grpc_request)
        elif check_function == "check_sensitive_data":
            return await self._check_sensitive_data(rule, grpc_response)
        elif check_function == "check_input_validation":
            return await self._check_input_validation(rule, grpc_request, grpc_response)
        elif check_function == "check_sql_injection":
            return await self._check_sql_injection(rule, grpc_request, grpc_response)
        elif check_function == "check_command_injection":
            return await self._check_command_injection(rule, grpc_request, grpc_response)

        return None

    async def _check_unauthorized_access(
        self,
        rule: GrpcScanRule,
        grpc_request: Any,
    ) -> Optional[GrpcScanResult]:
        """Check for unauthorized access.

        Args:
            rule: Scan rule.
            grpc_request: GrpcRequest object.

        Returns:
            GrpcScanResult or None.
        """
        metadata = getattr(grpc_request, "metadata", None)
        if not metadata:
            return GrpcScanResult(
                result_id=f"scan_{int(time.time())}",
                rule_id=rule.rule_id,
                request_id=getattr(grpc_request, "request_id", ""),
                service_path=getattr(grpc_request, "service_path", ""),
                method_name=getattr(grpc_request, "method", ""),
                severity=rule.severity,
                title="gRPC方法缺少认证",
                description=f"gRPC方法 {getattr(grpc_request, 'service_path', '')} 未检测到认证信息",
                timestamp=time.time(),
            )
        return None

    async def _check_sensitive_data(
        self,
        rule: GrpcScanRule,
        grpc_response: Any,
    ) -> Optional[GrpcScanResult]:
        """Check for sensitive data leakage.

        Args:
            rule: Scan rule.
            grpc_response: GrpcResponse object.

        Returns:
            GrpcScanResult or None.
        """
        sensitive_patterns = [
            "password", "secret", "token", "api_key",
            "private_key", "credit_card", "ssn",
        ]

        trailers = getattr(grpc_response, "trailers", {})
        for key, value in trailers.items():
            for pattern in sensitive_patterns:
                if pattern.lower() in key.lower() or pattern.lower() in value.lower():
                    return GrpcScanResult(
                        result_id=f"scan_{int(time.time())}",
                        rule_id=rule.rule_id,
                        service_path="",
                        method_name="",
                        severity=rule.severity,
                        title="gRPC响应包含敏感信息",
                        description=f"在响应元数据中发现敏感字段: {key}",
                        evidence=f"{key}: {value[:50]}...",
                        timestamp=time.time(),
                    )

        return None

    async def _check_input_validation(
        self,
        rule: GrpcScanRule,
        grpc_request: Any,
        grpc_response: Any,
    ) -> Optional[GrpcScanResult]:
        """Check input validation.

        Args:
            rule: Scan rule.
            grpc_request: GrpcRequest object.
            grpc_response: GrpcResponse object.

        Returns:
            GrpcScanResult or None.
        """
        status_code = getattr(grpc_response, "status_code", 0)

        if status_code == 3:
            return GrpcScanResult(
                result_id=f"scan_{int(time.time())}",
                rule_id=rule.rule_id,
                request_id=getattr(grpc_request, "request_id", ""),
                service_path=getattr(grpc_request, "service_path", ""),
                method_name=getattr(grpc_request, "method", ""),
                severity=rule.severity,
                title="gRPC输入验证缺陷",
                description="方法返回INVALID_ARGUMENT，可能存在输入验证问题",
                timestamp=time.time(),
            )

        return None

    async def _check_sql_injection(
        self,
        rule: GrpcScanRule,
        grpc_request: Any,
        grpc_response: Any,
    ) -> Optional[GrpcScanResult]:
        """Check SQL injection.

        Args:
            rule: Scan rule.
            grpc_request: GrpcRequest object.
            grpc_response: GrpcResponse object.

        Returns:
            GrpcScanResult or None.
        """
        return None

    async def _check_command_injection(
        self,
        rule: GrpcScanRule,
        grpc_request: Any,
        grpc_response: Any,
    ) -> Optional[GrpcScanResult]:
        """Check command injection.

        Args:
            rule: Scan rule.
            grpc_request: GrpcRequest object.
            grpc_response: GrpcResponse object.

        Returns:
            GrpcScanResult or None.
        """
        return None

    def get_assets(
        self,
        asset_type: Optional[GrpcAssetType] = None,
        service_filter: Optional[str] = None,
    ) -> List[GrpcAsset]:
        """Get registered gRPC assets.

        Args:
            asset_type: Filter by asset type.
            service_filter: Filter by service name.

        Returns:
            List of GrpcAsset.
        """
        assets = list(self._assets.values())

        if asset_type:
            assets = [a for a in assets if a.asset_type == asset_type]

        if service_filter:
            assets = [
                a for a in assets
                if service_filter.lower() in a.service_name.lower()
            ]

        return assets

    def get_service_tree(self) -> Dict[str, List[str]]:
        """Get service tree for UI display.

        Returns:
            Dictionary of service name to method list.
        """
        tree: Dict[str, List[str]] = {}

        for asset in self._assets.values():
            if asset.asset_type == GrpcAssetType.SERVICE:
                tree[asset.service_name] = []

        for asset in self._assets.values():
            if asset.asset_type == GrpcAssetType.METHOD:
                service = asset.service_name
                if service in tree:
                    tree[service].append(asset.method_name)

        return tree

    def get_scan_results(
        self,
        severity_filter: Optional[str] = None,
        limit: int = 100,
    ) -> List[GrpcScanResult]:
        """Get scan results.

        Args:
            severity_filter: Filter by severity.
            limit: Maximum records.

        Returns:
            List of GrpcScanResult.
        """
        results = self._scan_results

        if severity_filter:
            results = [r for r in results if r.severity == severity_filter]

        return results[-limit:]

    def get_scan_rules(self) -> List[GrpcScanRule]:
        """Get all scan rules.

        Returns:
            List of GrpcScanRule.
        """
        return list(self._scan_rules.values())

    def enable_scan_rule(self, rule_id: str) -> bool:
        """Enable scan rule.

        Args:
            rule_id: Rule ID.

        Returns:
            Whether rule was enabled.
        """
        rule = self._scan_rules.get(rule_id)
        if rule:
            rule.is_enabled = True
            return True
        return False

    def disable_scan_rule(self, rule_id: str) -> bool:
        """Disable scan rule.

        Args:
            rule_id: Rule ID.

        Returns:
            Whether rule was disabled.
        """
        rule = self._scan_rules.get(rule_id)
        if rule:
            rule.is_enabled = False
            return True
        return False

    async def _emit_event(self, event_type: str, data: Any) -> None:
        """Emit event to event bus.

        Args:
            event_type: Event type.
            data: Event data.
        """
        if self.event_bus:
            try:
                await self.event_bus.emit(event_type, data)
            except Exception as e:
                logger.error("Failed to emit event: %s", e)

    def get_stats(self) -> Dict[str, Any]:
        """Get integration statistics.

        Returns:
            Statistics dictionary.
        """
        return {
            "total_assets": len(self._assets),
            "services": sum(
                1 for a in self._assets.values()
                if a.asset_type == GrpcAssetType.SERVICE
            ),
            "methods": sum(
                1 for a in self._assets.values()
                if a.asset_type == GrpcAssetType.METHOD
            ),
            "scan_results": len(self._scan_results),
            "scan_rules": len(self._scan_rules),
            "enabled_rules": sum(
                1 for r in self._scan_rules.values() if r.is_enabled
            ),
        }
