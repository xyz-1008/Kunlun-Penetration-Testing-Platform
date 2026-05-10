"""Export Integration: Deep integration with proxy, report, and task management modules.

Provides:
- Proxy module integration: traffic list multi-select export, preview, progress
- Report module integration: automatic HAR/PCAP attachment, traffic statistics
- Task management integration: automated export rules, file archiving
- Event bus integration for real-time export status updates
- Vulnerability detail page "export related traffic" quick button
"""

import asyncio
import json
import logging
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum, auto
from typing import Any, Callable, Coroutine, Dict, List, Optional, Set, Tuple

from .export_manager import (
    ExportFilter,
    ExportFormat,
    ExportManager,
    ExportPreview,
    ExportStatus,
    ExportTask,
    HARExportOptions,
    PCAPExportOptions,
)
from .har_exporter import HARExporter
from .pcap_exporter import PCAPExporter

logger = logging.getLogger(__name__)


class IntegrationEventType(Enum):
    """Integration event types."""
    EXPORT_STARTED = "export_started"
    EXPORT_PROGRESS = "export_progress"
    EXPORT_COMPLETED = "export_completed"
    EXPORT_FAILED = "export_failed"
    TRAFFIC_PREVIEW = "traffic_preview"
    AUTO_EXPORT_TRIGGERED = "auto_export_triggered"


@dataclass
class IntegrationEvent:
    """Integration event for event bus.

    Attributes:
        event_type: Event type
        timestamp: Event timestamp
        data: Event data dictionary
    """
    event_type: IntegrationEventType = IntegrationEventType.EXPORT_STARTED
    timestamp: float = 0.0
    data: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TrafficEvidenceConfig:
    """Traffic evidence configuration for report integration.

    Attributes:
        include_har: Whether to include HAR export
        include_pcap: Whether to include PCAP export
        filter: Export filter for evidence
        har_options: HAR export options
        pcap_options: PCAP export options
        output_dir: Output directory for evidence files
    """
    include_har: bool = True
    include_pcap: bool = False
    filter: ExportFilter = field(default_factory=ExportFilter)
    har_options: HARExportOptions = field(default_factory=HARExportOptions)
    pcap_options: PCAPExportOptions = field(default_factory=PCAPExportOptions)
    output_dir: str = ""


@dataclass
class AutoExportRule:
    """Automatic export rule configuration.

    Attributes:
        rule_id: Unique rule identifier
        name: Rule name
        enabled: Whether rule is enabled
        trigger: Trigger condition (scan_complete, interval, manual)
        format: Export format
        filter: Export filter
        har_options: HAR export options
        pcap_options: PCAP export options
        output_dir: Output directory
        archive: Whether to archive to project directory
        interval_seconds: Interval for time-based triggers
    """
    rule_id: str = ""
    name: str = ""
    enabled: bool = True
    trigger: str = "scan_complete"
    format: ExportFormat = ExportFormat.HAR
    filter: ExportFilter = field(default_factory=ExportFilter)
    har_options: HARExportOptions = field(default_factory=HARExportOptions)
    pcap_options: PCAPExportOptions = field(default_factory=PCAPExportOptions)
    output_dir: str = ""
    archive: bool = True
    interval_seconds: int = 3600


@dataclass
class TrafficStatistics:
    """Traffic statistics summary for reports.

    Attributes:
        total_requests: Total number of requests
        total_responses: Total number of responses
        unique_domains: Number of unique domains
        unique_urls: Number of unique URLs
        methods_distribution: HTTP methods distribution
        status_codes_distribution: Status codes distribution
        total_request_bytes: Total request body size
        total_response_bytes: Total response body size
        avg_response_time_ms: Average response time
        websocket_connections: Number of WebSocket connections
        time_range_start: Start of time range
        time_range_end: End of time range
    """
    total_requests: int = 0
    total_responses: int = 0
    unique_domains: int = 0
    unique_urls: int = 0
    methods_distribution: Dict[str, int] = field(default_factory=dict)
    status_codes_distribution: Dict[int, int] = field(default_factory=dict)
    total_request_bytes: int = 0
    total_response_bytes: int = 0
    avg_response_time_ms: float = 0.0
    websocket_connections: int = 0
    time_range_start: Optional[float] = None
    time_range_end: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation.

        Returns:
            Dictionary with statistics data.
        """
        return {
            "total_requests": self.total_requests,
            "total_responses": self.total_responses,
            "unique_domains": self.unique_domains,
            "unique_urls": self.unique_urls,
            "methods_distribution": self.methods_distribution,
            "status_codes_distribution": self.status_codes_distribution,
            "total_request_bytes": self.total_request_bytes,
            "total_response_bytes": self.total_response_bytes,
            "avg_response_time_ms": round(self.avg_response_time_ms, 2),
            "websocket_connections": self.websocket_connections,
            "time_range_start": self.time_range_start,
            "time_range_end": self.time_range_end,
        }


class ExportIntegration:
    """Integration layer for export functionality with platform modules.

    Coordinates export operations with proxy, report, and task management
    modules through event bus and direct API calls.

    Attributes:
        export_manager: Export manager instance
        _event_bus: Optional event bus for event publishing
        _auto_export_rules: Dictionary of auto export rules
        _proxy_traffic: Reference to proxy traffic records
    """

    def __init__(
        self,
        export_manager: Optional[ExportManager] = None,
        event_bus: Optional[Any] = None,
    ) -> None:
        """Initialize export integration.

        Args:
            export_manager: Export manager instance. Creates new if None.
            event_bus: Optional event bus for publishing events.
        """
        self.export_manager = export_manager or ExportManager()
        self._event_bus = event_bus
        self._auto_export_rules: Dict[str, AutoExportRule] = {}
        self._proxy_traffic: List[Dict[str, Any]] = []

    async def _publish_event(self, event: IntegrationEvent) -> None:
        """Publish event to event bus.

        Args:
            event: Integration event to publish.
        """
        if self._event_bus:
            try:
                await self._event_bus.publish(event)
            except Exception as e:
                logger.error(f"Failed to publish event: {e}")

    def set_proxy_traffic(self, traffic_records: List[Dict[str, Any]]) -> None:
        """Set proxy traffic records reference.

        Args:
            traffic_records: List of traffic record dictionaries.
        """
        self._proxy_traffic = traffic_records

    def get_traffic_preview(
        self,
        selected_indices: Optional[List[int]] = None,
        export_filter: Optional[ExportFilter] = None,
    ) -> ExportPreview:
        """Get traffic preview for selected or filtered records.

        Args:
            selected_indices: Optional list of selected record indices.
            export_filter: Optional export filter.

        Returns:
            ExportPreview with summary information.
        """
        if selected_indices:
            records = [
                self._proxy_traffic[i]
                for i in selected_indices
                if 0 <= i < len(self._proxy_traffic)
            ]
            return self.export_manager.generate_preview(records, export_filter)
        else:
            return self.export_manager.generate_preview(
                self._proxy_traffic, export_filter
            )

    async def export_selected_traffic(
        self,
        selected_indices: List[int],
        format: ExportFormat,
        output_path: str,
        har_options: Optional[HARExportOptions] = None,
        pcap_options: Optional[PCAPExportOptions] = None,
    ) -> str:
        """Export selected traffic records.

        Args:
            selected_indices: List of selected record indices.
            format: Export format (HAR or PCAP).
            output_path: Output file path.
            har_options: HAR-specific options.
            pcap_options: PCAP-specific options.

        Returns:
            Task ID for tracking.
        """
        records = [
            self._proxy_traffic[i]
            for i in selected_indices
            if 0 <= i < len(self._proxy_traffic)
        ]

        task_id = f"export_{int(time.time())}"

        await self._publish_event(IntegrationEvent(
            event_type=IntegrationEventType.EXPORT_STARTED,
            timestamp=time.time(),
            data={
                "task_id": task_id,
                "format": format.value,
                "record_count": len(records),
                "output_path": output_path,
            },
        ))

        try:
            if format == ExportFormat.HAR:
                await self.export_manager.export_har(
                    traffic_records=records,
                    output_path=output_path,
                    har_options=har_options,
                    task_id=task_id,
                )
            else:
                await self.export_manager.export_pcap(
                    traffic_records=records,
                    output_path=output_path,
                    pcap_options=pcap_options,
                    task_id=task_id,
                )

            await self._publish_event(IntegrationEvent(
                event_type=IntegrationEventType.EXPORT_COMPLETED,
                timestamp=time.time(),
                data={
                    "task_id": task_id,
                    "format": format.value,
                    "output_path": output_path,
                },
            ))

            return task_id

        except Exception as e:
            await self._publish_event(IntegrationEvent(
                event_type=IntegrationEventType.EXPORT_FAILED,
                timestamp=time.time(),
                data={
                    "task_id": task_id,
                    "error": str(e),
                },
            ))
            raise

    async def export_all_traffic(
        self,
        format: ExportFormat,
        output_path: str,
        export_filter: Optional[ExportFilter] = None,
        har_options: Optional[HARExportOptions] = None,
        pcap_options: Optional[PCAPExportOptions] = None,
    ) -> str:
        """Export all proxy traffic.

        Args:
            format: Export format (HAR or PCAP).
            output_path: Output file path.
            export_filter: Optional export filter.
            har_options: HAR-specific options.
            pcap_options: PCAP-specific options.

        Returns:
            Task ID for tracking.
        """
        task_id = f"export_all_{int(time.time())}"

        await self._publish_event(IntegrationEvent(
            event_type=IntegrationEventType.EXPORT_STARTED,
            timestamp=time.time(),
            data={
                "task_id": task_id,
                "format": format.value,
                "record_count": len(self._proxy_traffic),
                "output_path": output_path,
            },
        ))

        try:
            if format == ExportFormat.HAR:
                await self.export_manager.export_har(
                    traffic_records=self._proxy_traffic,
                    output_path=output_path,
                    export_filter=export_filter,
                    har_options=har_options,
                    task_id=task_id,
                )
            else:
                await self.export_manager.export_pcap(
                    traffic_records=self._proxy_traffic,
                    output_path=output_path,
                    export_filter=export_filter,
                    pcap_options=pcap_options,
                    task_id=task_id,
                )

            await self._publish_event(IntegrationEvent(
                event_type=IntegrationEventType.EXPORT_COMPLETED,
                timestamp=time.time(),
                data={
                    "task_id": task_id,
                    "format": format.value,
                    "output_path": output_path,
                },
            ))

            return task_id

        except Exception as e:
            await self._publish_event(IntegrationEvent(
                event_type=IntegrationEventType.EXPORT_FAILED,
                timestamp=time.time(),
                data={
                    "task_id": task_id,
                    "error": str(e),
                },
            ))
            raise

    def calculate_traffic_statistics(
        self,
        traffic_records: Optional[List[Dict[str, Any]]] = None,
    ) -> TrafficStatistics:
        """Calculate traffic statistics for report integration.

        Args:
            traffic_records: Optional list of traffic records. Uses proxy traffic if None.

        Returns:
            TrafficStatistics with summary data.
        """
        records = traffic_records or self._proxy_traffic

        stats = TrafficStatistics()
        domains_set: Set[str] = set()
        urls_set: Set[str] = set()
        methods_dist: Dict[str, int] = {}
        status_dist: Dict[int, int] = {}
        total_req_bytes = 0
        total_resp_bytes = 0
        total_response_time = 0.0
        response_time_count = 0
        ws_connections = 0
        min_ts: Optional[float] = None
        max_ts: Optional[float] = None

        for record in records:
            request_data = record.get("request", {})
            response_data = record.get("response", {})
            is_websocket = record.get("is_websocket", False)

            stats.total_requests += 1
            if response_data.get("status_code"):
                stats.total_responses += 1

            domain = request_data.get("host", "")
            url = request_data.get("url", "")
            method = request_data.get("method", "GET")
            status = response_data.get("status_code", 0)
            timestamp = request_data.get("timestamp", 0)
            response_time = response_data.get("response_time", 0.0)

            if isinstance(timestamp, datetime):
                timestamp = timestamp.timestamp()

            if domain:
                domains_set.add(domain)
            if url:
                urls_set.add(url)

            methods_dist[method] = methods_dist.get(method, 0) + 1
            if status > 0:
                status_dist[status] = status_dist.get(status, 0) + 1

            req_body = request_data.get("body", b"")
            resp_body = response_data.get("body", b"")
            if isinstance(req_body, str):
                req_body = req_body.encode("utf-8")
            if isinstance(resp_body, str):
                resp_body = resp_body.encode("utf-8")
            total_req_bytes += len(req_body)
            total_resp_bytes += len(resp_body)

            if response_time > 0:
                total_response_time += response_time
                response_time_count += 1

            if is_websocket:
                ws_connections += 1

            if timestamp > 0:
                if min_ts is None or timestamp < min_ts:
                    min_ts = timestamp
                if max_ts is None or timestamp > max_ts:
                    max_ts = timestamp

        stats.unique_domains = len(domains_set)
        stats.unique_urls = len(urls_set)
        stats.methods_distribution = methods_dist
        stats.status_codes_distribution = status_dist
        stats.total_request_bytes = total_req_bytes
        stats.total_response_bytes = total_resp_bytes
        stats.avg_response_time_ms = (
            total_response_time / response_time_count if response_time_count > 0 else 0.0
        )
        stats.websocket_connections = ws_connections
        stats.time_range_start = min_ts
        stats.time_range_end = max_ts

        return stats

    async def export_traffic_evidence(
        self,
        evidence_config: TrafficEvidenceConfig,
        report_id: str,
        related_urls: Optional[List[str]] = None,
    ) -> Dict[str, str]:
        """Export traffic evidence for report attachment.

        Args:
            evidence_config: Evidence export configuration.
            report_id: Report identifier for file naming.
            related_urls: Optional list of related URLs to filter.

        Returns:
            Dictionary of format to output file path.
        """
        output_files: Dict[str, str] = {}

        if not evidence_config.output_dir:
            evidence_config.output_dir = os.path.join(
                "exports", "evidence", report_id
            )

        os.makedirs(evidence_config.output_dir, exist_ok=True)

        filter_config = evidence_config.filter
        if related_urls:
            filter_config.url_patterns = related_urls

        timestamp = int(time.time())

        if evidence_config.include_har:
            har_path = os.path.join(
                evidence_config.output_dir,
                f"evidence_{report_id}_{timestamp}.har",
            )
            await self.export_manager.export_har(
                traffic_records=self._proxy_traffic,
                output_path=har_path,
                export_filter=filter_config,
                har_options=evidence_config.har_options,
                task_id=f"evidence_har_{report_id}",
            )
            output_files["har"] = har_path

        if evidence_config.include_pcap:
            pcap_path = os.path.join(
                evidence_config.output_dir,
                f"evidence_{report_id}_{timestamp}.pcap",
            )
            await self.export_manager.export_pcap(
                traffic_records=self._proxy_traffic,
                output_path=pcap_path,
                export_filter=filter_config,
                pcap_options=evidence_config.pcap_options,
                task_id=f"evidence_pcap_{report_id}",
            )
            output_files["pcap"] = pcap_path

        return output_files

    def add_auto_export_rule(self, rule: AutoExportRule) -> None:
        """Add automatic export rule.

        Args:
            rule: Auto export rule configuration.
        """
        self._auto_export_rules[rule.rule_id] = rule
        logger.info(f"Added auto export rule: {rule.name}")

    def remove_auto_export_rule(self, rule_id: str) -> None:
        """Remove automatic export rule.

        Args:
            rule_id: Rule identifier.
        """
        if rule_id in self._auto_export_rules:
            del self._auto_export_rules[rule_id]
            logger.info(f"Removed auto export rule: {rule_id}")

    async def trigger_scan_complete_export(self) -> List[str]:
        """Trigger export on scan completion.

        Returns:
            List of output file paths created.
        """
        output_paths: List[str] = []

        for rule_id, rule in self._auto_export_rules.items():
            if not rule.enabled or rule.trigger != "scan_complete":
                continue

            try:
                timestamp = int(time.time())
                output_dir = rule.output_dir or os.path.join(
                    "exports", "auto", rule.rule_id
                )
                os.makedirs(output_dir, exist_ok=True)

                if rule.format == ExportFormat.HAR:
                    output_path = os.path.join(
                        output_dir, f"scan_{timestamp}.har"
                    )
                    await self.export_manager.export_har(
                        traffic_records=self._proxy_traffic,
                        output_path=output_path,
                        export_filter=rule.filter,
                        har_options=rule.har_options,
                        task_id=f"auto_har_{rule_id}_{timestamp}",
                    )
                else:
                    output_path = os.path.join(
                        output_dir, f"scan_{timestamp}.pcap"
                    )
                    await self.export_manager.export_pcap(
                        traffic_records=self._proxy_traffic,
                        output_path=output_path,
                        export_filter=rule.filter,
                        pcap_options=rule.pcap_options,
                        task_id=f"auto_pcap_{rule_id}_{timestamp}",
                    )

                if rule.archive:
                    logger.info(f"Auto export archived: {output_path}")

                output_paths.append(output_path)

            except Exception as e:
                logger.error(f"Auto export rule {rule_id} failed: {e}")

        return output_paths

    async def export_vulnerability_traffic(
        self,
        vulnerability_id: str,
        related_urls: List[str],
        output_dir: str,
        format: ExportFormat = ExportFormat.HAR,
    ) -> str:
        """Export traffic related to a specific vulnerability.

        Args:
            vulnerability_id: Vulnerability identifier.
            related_urls: List of URLs related to the vulnerability.
            output_dir: Output directory for export file.
            format: Export format.

        Returns:
            Output file path.
        """
        os.makedirs(output_dir, exist_ok=True)

        timestamp = int(time.time())
        filename = f"vuln_{vulnerability_id}_{timestamp}"

        if format == ExportFormat.HAR:
            output_path = os.path.join(output_dir, f"{filename}.har")
            export_filter = ExportFilter(url_patterns=related_urls)
            await self.export_manager.export_har(
                traffic_records=self._proxy_traffic,
                output_path=output_path,
                export_filter=export_filter,
                task_id=f"vuln_har_{vulnerability_id}",
            )
        else:
            output_path = os.path.join(output_dir, f"{filename}.pcap")
            export_filter = ExportFilter(url_patterns=related_urls)
            await self.export_manager.export_pcap(
                traffic_records=self._proxy_traffic,
                output_path=output_path,
                export_filter=export_filter,
                task_id=f"vuln_pcap_{vulnerability_id}",
            )

        return output_path
