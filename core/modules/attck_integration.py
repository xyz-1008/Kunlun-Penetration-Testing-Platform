"""ATT&CK integration layer for Kunlun penetration testing platform.

Provides:
- Event bus subscription for automatic operation monitoring
- Integration with C2 framework, PoC engine, and report module
- Real-time mapping trigger on operation events
- Report template data generation
"""

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Any, Callable, Coroutine, Dict, List, Optional

from .attck_mapper import AttckMapper, AttckTimelineEntry, AttckVersion, MappingResult
from .attck_visualizer import AttckVisualizer

logger = logging.getLogger(__name__)


@dataclass
class OperationEvent:
    """Operation event from the event bus.

    Attributes:
        event_id: Unique event identifier
        operation_type: Type of operation (poc_execute, pth, wmi, etc.)
        operation_description: Human-readable description
        target_host: Target host/IP
        operation_id: Associated operation ID
        parameters: Operation parameters
        result: Operation result status
        timestamp: Event timestamp
        source_module: Module that generated the event
        metadata: Additional metadata
    """
    event_id: str = ""
    operation_type: str = ""
    operation_description: str = ""
    target_host: str = ""
    operation_id: str = ""
    parameters: Dict[str, Any] = field(default_factory=dict)
    result: str = "success"
    timestamp: float = 0.0
    source_module: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class IntegrationConfig:
    """Configuration for ATT&CK integration.

    Attributes:
        enabled: Whether ATT&CK integration is active
        auto_map: Whether to automatically map operations
        include_in_reports: Whether to include in reports
        heatmap_color_theme: Color theme for heatmaps
        detail_level: Level of detail in reports (summary/full)
        custom_rules_path: Path to custom rules YAML
        attck_version: ATT&CK framework version
        max_events: Maximum events to store in memory
    """
    enabled: bool = True
    auto_map: bool = True
    include_in_reports: bool = True
    heatmap_color_theme: str = "default"
    detail_level: str = "full"
    custom_rules_path: Optional[str] = None
    attck_version: str = "v14"
    max_events: int = 10000


class AttckIntegration:
    """Integration layer connecting ATT&CK mapper with Kunlun platform modules.

    Subscribes to event bus, processes operations, and generates report data.
    """

    def __init__(
        self,
        config: Optional[IntegrationConfig] = None,
        event_bus: Optional[Any] = None,
    ) -> None:
        """Initialize the integration layer.

        Args:
            config: Integration configuration.
            event_bus: Event bus instance for subscription.
        """
        self.config = config or IntegrationConfig()
        self.event_bus = event_bus
        self.mapper = AttckMapper(
            rules_path=self.config.custom_rules_path,
            version=AttckVersion(self.config.attck_version),
        )
        self.visualizer = AttckVisualizer()
        self.event_history: List[OperationEvent] = []
        self.mapping_results: List[MappingResult] = []
        self._event_handlers: Dict[str, Callable[..., Coroutine[Any, Any, None]]] = {}
        self._running = False
        self._listener_task: Optional[asyncio.Task[None]] = None
        self._register_default_handlers()

    def _register_default_handlers(self) -> None:
        """Register default event handlers for operation types."""
        self._event_handlers["poc_execute"] = self._handle_poc_execute
        self._event_handlers["c2_command"] = self._handle_c2_command
        self._event_handlers["lateral_movement"] = self._handle_lateral_movement
        self._event_handlers["privilege_escalation"] = self._handle_privilege_escalation
        self._event_handlers["persistence"] = self._handle_persistence
        self._event_handlers["credential_access"] = self._handle_credential_access
        self._event_handlers["discovery"] = self._handle_discovery
        self._event_handlers["exfiltration"] = self._handle_exfiltration
        self._event_handlers["impact"] = self._handle_impact
        self._event_handlers["defense_evasion"] = self._handle_defense_evasion

    async def _handle_poc_execute(self, event: OperationEvent) -> None:
        """Handle PoC execution events.

        Args:
            event: Operation event.
        """
        cve = event.parameters.get("cve", "")
        template_info = event.parameters.get("template_info", {})
        attck_id = template_info.get("classification", {}).get("attck-id", "")

        if attck_id:
            technique = self.mapper.get_technique(attck_id)
            if technique:
                result = MappingResult(
                    technique=technique,
                    operation_type=event.operation_type,
                    operation_description=event.operation_description,
                    target_host=event.target_host,
                    timestamp=event.timestamp,
                    evidence={"cve": cve, "template": template_info.get("name", "")},
                )
                self.mapping_results.append(result)
                return

        self._auto_map_event(event)

    async def _handle_c2_command(self, event: OperationEvent) -> None:
        """Handle C2 command execution events.

        Args:
            event: Operation event.
        """
        command_type = event.parameters.get("command_type", "")
        command = event.parameters.get("command", "")
        desc = f"{command_type}: {command}" if command else command_type
        event.operation_description = event.operation_description or desc
        self._auto_map_event(event)

    async def _handle_lateral_movement(self, event: OperationEvent) -> None:
        """Handle lateral movement events.

        Args:
            event: Operation event.
        """
        method = event.parameters.get("method", "")
        target = event.parameters.get("target", "")
        desc = f"横向移动 ({method}) -> {target}" if target else f"横向移动 ({method})"
        event.operation_description = event.operation_description or desc
        self._auto_map_event(event)

    async def _handle_privilege_escalation(self, event: OperationEvent) -> None:
        """Handle privilege escalation events.

        Args:
            event: Operation event.
        """
        method = event.parameters.get("method", "")
        desc = f"提权 ({method})" if method else "提权"
        event.operation_description = event.operation_description or desc
        self._auto_map_event(event)

    async def _handle_persistence(self, event: OperationEvent) -> None:
        """Handle persistence events.

        Args:
            event: Operation event.
        """
        method = event.parameters.get("method", "")
        desc = f"持久化 ({method})" if method else "持久化"
        event.operation_description = event.operation_description or desc
        self._auto_map_event(event)

    async def _handle_credential_access(self, event: OperationEvent) -> None:
        """Handle credential access events.

        Args:
            event: Operation event.
        """
        method = event.parameters.get("method", "")
        desc = f"凭据访问 ({method})" if method else "凭据访问"
        event.operation_description = event.operation_description or desc
        self._auto_map_event(event)

    async def _handle_discovery(self, event: OperationEvent) -> None:
        """Handle discovery events.

        Args:
            event: Operation event.
        """
        method = event.parameters.get("method", "")
        desc = f"发现 ({method})" if method else "发现"
        event.operation_description = event.operation_description or desc
        self._auto_map_event(event)

    async def _handle_exfiltration(self, event: OperationEvent) -> None:
        """Handle data exfiltration events.

        Args:
            event: Operation event.
        """
        method = event.parameters.get("method", "")
        desc = f"数据渗出 ({method})" if method else "数据渗出"
        event.operation_description = event.operation_description or desc
        self._auto_map_event(event)

    async def _handle_impact(self, event: OperationEvent) -> None:
        """Handle impact events.

        Args:
            event: Operation event.
        """
        method = event.parameters.get("method", "")
        desc = f"影响 ({method})" if method else "影响"
        event.operation_description = event.operation_description or desc
        self._auto_map_event(event)

    async def _handle_defense_evasion(self, event: OperationEvent) -> None:
        """Handle defense evasion events.

        Args:
            event: Operation event.
        """
        method = event.parameters.get("method", "")
        desc = f"防御规避 ({method})" if method else "防御规避"
        event.operation_description = event.operation_description or desc
        self._auto_map_event(event)

    def _auto_map_event(self, event: OperationEvent) -> None:
        """Automatically map an event to ATT&CK technique.

        Args:
            event: Operation event to map.
        """
        if not self.config.auto_map:
            return
        result = self.mapper.map_operation(
            operation_type=event.operation_type,
            operation_description=event.operation_description,
            target_host=event.target_host,
            operation_id=event.operation_id,
            evidence={
                "source_module": event.source_module,
                "parameters": event.parameters,
                "result": event.result,
            },
        )
        if result:
            self.mapping_results.append(result)
            logger.debug(
                "Mapped %s -> %s (%s)",
                event.operation_type,
                result.technique.technique_id,
                result.confidence.value,
            )

    async def process_event(self, event: OperationEvent) -> None:
        """Process a single operation event.

        Args:
            event: Operation event to process.
        """
        if not self.config.enabled:
            return
        self.event_history.append(event)
        if len(self.event_history) > self.config.max_events:
            self.event_history = self.event_history[-self.config.max_events:]

        handler = self._event_handlers.get(event.operation_type)
        if handler:
            await handler(event)
        else:
            self._auto_map_event(event)

    async def process_events_batch(self, events: List[OperationEvent]) -> None:
        """Process multiple events concurrently.

        Args:
            events: List of operation events.
        """
        tasks = [self.process_event(event) for event in events]
        await asyncio.gather(*tasks, return_exceptions=True)

    def subscribe_to_event_bus(self) -> None:
        """Subscribe to the platform event bus for real-time monitoring."""
        if not self.event_bus:
            logger.warning("No event bus available for subscription")
            return
        try:
            self.event_bus.subscribe("operation", self._on_event_bus_event)
            logger.info("Subscribed to event bus for ATT&CK mapping")
        except Exception as e:
            logger.error("Failed to subscribe to event bus: %s", e)

    async def _on_event_bus_event(self, event_data: Dict[str, Any]) -> None:
        """Handle event from the event bus.

        Args:
            event_data: Event data dictionary.
        """
        import time
        event = OperationEvent(
            event_id=event_data.get("event_id", ""),
            operation_type=event_data.get("operation_type", ""),
            operation_description=event_data.get("description", ""),
            target_host=event_data.get("target_host", ""),
            operation_id=event_data.get("operation_id", ""),
            parameters=event_data.get("parameters", {}),
            result=event_data.get("result", "success"),
            timestamp=event_data.get("timestamp", time.time()),
            source_module=event_data.get("source_module", ""),
            metadata=event_data.get("metadata", {}),
        )
        await self.process_event(event)

    def generate_report_data(self) -> Dict[str, Any]:
        """Generate complete ATT&CK report data.

        Returns:
            Dictionary with all report-ready ATT&CK data.
        """
        if not self.config.include_in_reports:
            return {"enabled": False}

        all_techniques = self.mapper.get_all_techniques()
        timeline_entries = self.mapper.get_attack_chain_timeline()

        report_data = self.visualizer.get_report_data(
            mapping_results=self.mapping_results,
            all_techniques=all_techniques,
            timeline_entries=timeline_entries,
        )
        report_data["enabled"] = True
        report_data["config"] = {
            "version": self.config.attck_version,
            "detail_level": self.config.detail_level,
            "color_theme": self.config.heatmap_color_theme,
        }
        report_data["statistics"] = self.mapper.get_statistics()
        return report_data

    def export_report_assets(
        self,
        output_dir: str,
        title: str = "ATT&CK Attack Matrix Report",
    ) -> Dict[str, str]:
        """Export all report assets (HTML heatmap, technique list, timeline).

        Args:
            output_dir: Output directory for assets.
            title: Report title.

        Returns:
            Dictionary mapping asset type to file path.
        """
        import os
        os.makedirs(output_dir, exist_ok=True)

        all_techniques = self.mapper.get_all_techniques()
        timeline_entries = self.mapper.get_attack_chain_timeline()

        heatmap = self.visualizer.generate_heatmap(self.mapping_results, all_techniques)
        details = self.visualizer.generate_technique_details(self.mapping_results)
        timeline_data = self.visualizer.generate_timeline(timeline_entries)

        heatmap_path = os.path.join(output_dir, "attck_heatmap.html")
        details_path = os.path.join(output_dir, "attck_techniques.html")
        timeline_path = os.path.join(output_dir, "attck_timeline.html")

        self.visualizer.export_html_heatmap(
            heatmap,
            heatmap_path,
            title=f"{title} - Heatmap",
            color_theme=self.config.heatmap_color_theme,
        )
        self.visualizer.export_technique_list_html(
            details,
            details_path,
            title=f"{title} - Technique Details",
        )
        self.visualizer.export_timeline_html(
            timeline_data,
            timeline_path,
            title=f"{title} - Attack Chain Timeline",
        )

        return {
            "heatmap": heatmap_path,
            "techniques": details_path,
            "timeline": timeline_path,
        }

    async def start(self) -> None:
        """Start the integration layer and event listener."""
        self._running = True
        self.subscribe_to_event_bus()
        logger.info("ATT&CK integration started")

    async def stop(self) -> None:
        """Stop the integration layer."""
        self._running = False
        if self._listener_task:
            self._listener_task.cancel()
            try:
                await self._listener_task
            except asyncio.CancelledError:
                pass
        logger.info("ATT&CK integration stopped")

    def get_summary(self) -> Dict[str, Any]:
        """Get a summary of ATT&CK mapping status.

        Returns:
            Dictionary with mapping summary.
        """
        stats = self.mapper.get_statistics()
        return {
            "enabled": self.config.enabled,
            "auto_map": self.config.auto_map,
            "total_events": len(self.event_history),
            "total_mappings": stats["total_mappings"],
            "unique_techniques": stats["unique_techniques"],
            "tactics_covered": stats["tactic_distribution"],
            "severity_distribution": stats["severity_distribution"],
        }
