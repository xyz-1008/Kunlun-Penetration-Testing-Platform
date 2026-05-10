"""Export Manager: Traffic export configuration, filtering, and CLI commands.

Provides:
- Export options panel configuration for HAR and PCAP
- Filter condition management (domain, URL, time range, method, status code)
- Export progress callback and real-time status display
- CLI command interface for har/pcap export
- Export preview with traffic summary
- Post-export validation for HAR and PCAP files
"""

import argparse
import asyncio
import json
import logging
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum, auto
from typing import Any, Callable, Coroutine, Dict, List, Optional, Set, Tuple

from .har_exporter import HARExportConfig, HARExporter
from .pcap_exporter import PCAPExporter, PCAPLinkType

logger = logging.getLogger(__name__)


class ExportFormat(Enum):
    """Export format options."""
    HAR = "har"
    PCAP = "pcap"
    PCAPNG = "pcapng"


class ExportStatus(Enum):
    """Export operation status."""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class ExportFilter:
    """Export filter configuration.

    Attributes:
        domains: List of domains to include (empty = all)
        url_patterns: List of URL patterns to include (empty = all)
        methods: List of HTTP methods to include (empty = all)
        status_codes: List of status codes to include (empty = all)
        time_start: Start timestamp for time range filter
        time_end: End timestamp for time range filter
        include_websocket: Whether to include WebSocket traffic
        exclude_private_ips: Whether to exclude private IP addresses
    """
    domains: List[str] = field(default_factory=list)
    url_patterns: List[str] = field(default_factory=list)
    methods: List[str] = field(default_factory=list)
    status_codes: List[int] = field(default_factory=list)
    time_start: Optional[float] = None
    time_end: Optional[float] = None
    include_websocket: bool = True
    exclude_private_ips: bool = False


@dataclass
class HARExportOptions:
    """HAR export specific options.

    Attributes:
        include_websocket_messages: Whether to include WebSocket messages
        base64_encode_bodies: Whether to Base64 encode response bodies
        body_size_limit: Maximum body size before truncation (bytes)
        include_private_ips: Whether to include private IP addresses
        include_meta: Whether to include _meta extension field
        normalize_http_version: Whether to normalize HTTP/2/3 to HTTP/1.1
    """
    include_websocket_messages: bool = True
    base64_encode_bodies: bool = True
    body_size_limit: int = 10 * 1024 * 1024
    include_private_ips: bool = True
    include_meta: bool = True
    normalize_http_version: bool = True


@dataclass
class PCAPExportOptions:
    """PCAP export specific options.

    Attributes:
        mss: Maximum Segment Size for TCP segmentation
        preserve_tls: Whether to preserve original TLS records
        src_mac: Source MAC address template (6 bytes)
        dst_mac: Destination MAC address template (6 bytes)
        link_type: PCAP link type
    """
    mss: int = 1460
    preserve_tls: bool = False
    src_mac: Optional[bytes] = None
    dst_mac: Optional[bytes] = None
    link_type: PCAPLinkType = PCAPLinkType.ETHERNET


@dataclass
class ExportTask:
    """Export task tracking information.

    Attributes:
        task_id: Unique task identifier
        format: Export format
        output_path: Output file path
        filter: Export filter configuration
        har_options: HAR-specific options
        pcap_options: PCAP-specific options
        status: Current task status
        progress: Progress percentage (0-100)
        started_at: Task start time
        completed_at: Task completion time
        error_message: Error message if failed
        record_count: Number of records to export
        packet_count: Number of packets written (PCAP only)
    """
    task_id: str = ""
    format: ExportFormat = ExportFormat.HAR
    output_path: str = ""
    filter: ExportFilter = field(default_factory=ExportFilter)
    har_options: HARExportOptions = field(default_factory=HARExportOptions)
    pcap_options: PCAPExportOptions = field(default_factory=PCAPExportOptions)
    status: ExportStatus = ExportStatus.PENDING
    progress: float = 0.0
    started_at: Optional[float] = None
    completed_at: Optional[float] = None
    error_message: str = ""
    record_count: int = 0
    packet_count: int = 0


@dataclass
class ExportPreview:
    """Export preview information.

    Attributes:
        total_records: Total number of records matching filter
        domains: Unique domains in filtered records
        methods: HTTP methods distribution
        status_codes: Status code distribution
        total_request_size: Total request body size
        total_response_size: Total response body size
        time_range: Time range of filtered records
        websocket_count: Number of WebSocket records
    """
    total_records: int = 0
    domains: List[str] = field(default_factory=list)
    methods: Dict[str, int] = field(default_factory=dict)
    status_codes: Dict[int, int] = field(default_factory=dict)
    total_request_size: int = 0
    total_response_size: int = 0
    time_range: Tuple[Optional[float], Optional[float]] = (None, None)
    websocket_count: int = 0


class ExportManager:
    """Traffic export manager with configuration, filtering, and progress tracking.

    Coordinates HAR and PCAP export operations with unified interface,
    filter management, and progress reporting.

    Attributes:
        _active_tasks: Dictionary of active export tasks
        _progress_callback: Global progress callback
    """

    def __init__(
        self,
        progress_callback: Optional[Callable[[str, float], Coroutine[Any, Any, None]]] = None,
    ) -> None:
        """Initialize export manager.

        Args:
            progress_callback: Global async progress callback.
        """
        self._active_tasks: Dict[str, ExportTask] = {}
        self._progress_callback = progress_callback

    async def _report_progress(
        self,
        task_id: str,
        message: str,
        percentage: float,
    ) -> None:
        """Report export progress for a task.

        Args:
            task_id: Task identifier.
            message: Progress message.
            percentage: Progress percentage (0-100).
        """
        if task_id in self._active_tasks:
            self._active_tasks[task_id].progress = percentage

        if self._progress_callback:
            await self._progress_callback(message, percentage)

    def _apply_filter(
        self,
        traffic_records: List[Dict[str, Any]],
        export_filter: ExportFilter,
    ) -> List[Dict[str, Any]]:
        """Apply export filter to traffic records.

        Args:
            traffic_records: Full list of traffic records.
            export_filter: Filter configuration.

        Returns:
            Filtered list of traffic records.
        """
        filtered: List[Dict[str, Any]] = []

        for record in traffic_records:
            request_data = record.get("request", {})
            response_data = record.get("response", {})
            is_websocket = record.get("is_websocket", False)

            if not export_filter.include_websocket and is_websocket:
                continue

            url = request_data.get("url", "")
            domain = request_data.get("host", "")
            method = request_data.get("method", "")
            status = response_data.get("status_code", 0)
            timestamp = request_data.get("timestamp", 0)

            if isinstance(timestamp, datetime):
                timestamp = timestamp.timestamp()

            if export_filter.domains and domain not in export_filter.domains:
                continue

            if export_filter.url_patterns:
                if not any(pattern in url for pattern in export_filter.url_patterns):
                    continue

            if export_filter.methods and method not in export_filter.methods:
                continue

            if export_filter.status_codes and status not in export_filter.status_codes:
                continue

            if export_filter.time_start and timestamp < export_filter.time_start:
                continue

            if export_filter.time_end and timestamp > export_filter.time_end:
                continue

            if export_filter.exclude_private_ips:
                server_ip = request_data.get("server_ip", "")
                if server_ip.startswith(("10.", "192.168.", "172.16.")):
                    continue

            filtered.append(record)

        return filtered

    def generate_preview(
        self,
        traffic_records: List[Dict[str, Any]],
        export_filter: Optional[ExportFilter] = None,
    ) -> ExportPreview:
        """Generate export preview with traffic summary.

        Args:
            traffic_records: Full list of traffic records.
            export_filter: Optional filter to apply.

        Returns:
            ExportPreview with summary information.
        """
        if export_filter:
            records = self._apply_filter(traffic_records, export_filter)
        else:
            records = traffic_records

        preview = ExportPreview(total_records=len(records))

        domains_set: Set[str] = set()
        methods_dist: Dict[str, int] = {}
        status_dist: Dict[int, int] = {}
        total_req_size = 0
        total_resp_size = 0
        ws_count = 0
        min_ts: Optional[float] = None
        max_ts: Optional[float] = None

        for record in records:
            request_data = record.get("request", {})
            response_data = record.get("response", {})
            is_websocket = record.get("is_websocket", False)

            domain = request_data.get("host", "")
            method = request_data.get("method", "GET")
            status = response_data.get("status_code", 0)
            timestamp = request_data.get("timestamp", 0)

            if isinstance(timestamp, datetime):
                timestamp = timestamp.timestamp()

            if domain:
                domains_set.add(domain)

            methods_dist[method] = methods_dist.get(method, 0) + 1
            if status > 0:
                status_dist[status] = status_dist.get(status, 0) + 1

            req_body = request_data.get("body", b"")
            resp_body = response_data.get("body", b"")
            if isinstance(req_body, str):
                req_body = req_body.encode("utf-8")
            if isinstance(resp_body, str):
                resp_body = resp_body.encode("utf-8")
            total_req_size += len(req_body)
            total_resp_size += len(resp_body)

            if is_websocket:
                ws_count += 1

            if timestamp > 0:
                if min_ts is None or timestamp < min_ts:
                    min_ts = timestamp
                if max_ts is None or timestamp > max_ts:
                    max_ts = timestamp

        preview.domains = sorted(list(domains_set))
        preview.methods = methods_dist
        preview.status_codes = status_dist
        preview.total_request_size = total_req_size
        preview.total_response_size = total_resp_size
        preview.time_range = (min_ts, max_ts)
        preview.websocket_count = ws_count

        return preview

    async def export_har(
        self,
        traffic_records: List[Dict[str, Any]],
        output_path: str,
        export_filter: Optional[ExportFilter] = None,
        har_options: Optional[HARExportOptions] = None,
        task_id: Optional[str] = None,
    ) -> str:
        """Export traffic to HAR format.

        Args:
            traffic_records: Full list of traffic records.
            output_path: Output HAR file path.
            export_filter: Optional filter to apply.
            har_options: HAR-specific export options.
            task_id: Optional task ID for tracking.

        Returns:
            HAR JSON string.
        """
        tid = task_id or f"har_{int(time.time())}"

        task = ExportTask(
            task_id=tid,
            format=ExportFormat.HAR,
            output_path=output_path,
            filter=export_filter or ExportFilter(),
            har_options=har_options or HARExportOptions(),
            status=ExportStatus.IN_PROGRESS,
            started_at=time.time(),
        )
        self._active_tasks[tid] = task

        try:
            if export_filter:
                records = self._apply_filter(traffic_records, export_filter)
            else:
                records = traffic_records

            task.record_count = len(records)

            har_config = HARExportConfig(
                include_websocket_messages=task.har_options.include_websocket_messages,
                base64_encode_bodies=task.har_options.base64_encode_bodies,
                body_size_limit=task.har_options.body_size_limit,
                include_private_ips=task.har_options.include_private_ips,
                include_meta=task.har_options.include_meta,
                normalize_http_version=task.har_options.normalize_http_version,
            )

            async def progress_cb(message: str, percentage: float) -> None:
                await self._report_progress(tid, message, percentage)

            exporter = HARExporter(config=har_config, progress_callback=progress_cb)
            har_json = await exporter.export_to_har(records, output_path)

            task.status = ExportStatus.COMPLETED
            task.progress = 100.0
            task.completed_at = time.time()

            await self._report_progress(tid, "HAR export completed", 100.0)

            return har_json

        except Exception as e:
            task.status = ExportStatus.FAILED
            task.error_message = str(e)
            task.completed_at = time.time()
            logger.error(f"HAR export failed: {e}")
            raise

    async def export_pcap(
        self,
        traffic_records: List[Dict[str, Any]],
        output_path: str,
        export_filter: Optional[ExportFilter] = None,
        pcap_options: Optional[PCAPExportOptions] = None,
        task_id: Optional[str] = None,
    ) -> int:
        """Export traffic to PCAP format.

        Args:
            traffic_records: Full list of traffic records.
            output_path: Output PCAP file path.
            export_filter: Optional filter to apply.
            pcap_options: PCAP-specific export options.
            task_id: Optional task ID for tracking.

        Returns:
            Number of packets written.
        """
        tid = task_id or f"pcap_{int(time.time())}"

        task = ExportTask(
            task_id=tid,
            format=ExportFormat.PCAP,
            output_path=output_path,
            filter=export_filter or ExportFilter(),
            pcap_options=pcap_options or PCAPExportOptions(),
            status=ExportStatus.IN_PROGRESS,
            started_at=time.time(),
        )
        self._active_tasks[tid] = task

        try:
            if export_filter:
                records = self._apply_filter(traffic_records, export_filter)
            else:
                records = traffic_records

            task.record_count = len(records)

            opts = task.pcap_options

            async def progress_cb(message: str, percentage: float) -> None:
                await self._report_progress(tid, message, percentage)

            exporter = PCAPExporter(
                mss=opts.mss,
                preserve_tls=opts.preserve_tls,
                src_mac=opts.src_mac,
                dst_mac=opts.dst_mac,
                link_type=opts.link_type,
                progress_callback=progress_cb,
            )

            if export_filter:
                packet_count = await exporter.export_filtered_traffic(
                    traffic_records=records,
                    output_path=output_path,
                    domain_filter=export_filter.domains if export_filter.domains else None,
                    url_filter=export_filter.url_patterns if export_filter.url_patterns else None,
                    method_filter=export_filter.methods if export_filter.methods else None,
                    status_filter=export_filter.status_codes if export_filter.status_codes else None,
                    time_start=export_filter.time_start,
                    time_end=export_filter.time_end,
                )
            else:
                packet_count = await exporter.export_to_pcap(records, output_path)

            task.status = ExportStatus.COMPLETED
            task.progress = 100.0
            task.packet_count = packet_count
            task.completed_at = time.time()

            await self._report_progress(tid, "PCAP export completed", 100.0)

            return packet_count

        except Exception as e:
            task.status = ExportStatus.FAILED
            task.error_message = str(e)
            task.completed_at = time.time()
            logger.error(f"PCAP export failed: {e}")
            raise

    def get_task_status(self, task_id: str) -> Optional[ExportTask]:
        """Get export task status.

        Args:
            task_id: Task identifier.

        Returns:
            ExportTask object or None if not found.
        """
        return self._active_tasks.get(task_id)

    def get_all_tasks(self) -> Dict[str, ExportTask]:
        """Get all export tasks.

        Returns:
            Dictionary of task ID to ExportTask.
        """
        return self._active_tasks.copy()

    def validate_har_file(self, file_path: str) -> Tuple[bool, str]:
        """Validate HAR file can be opened by Chrome DevTools.

        Args:
            file_path: Path to HAR file.

        Returns:
            Tuple of (is_valid, message).
        """
        try:
            if not os.path.exists(file_path):
                return False, f"File not found: {file_path}"

            with open(file_path, "r", encoding="utf-8") as f:
                har_data = json.load(f)

            if "log" not in har_data:
                return False, "Missing 'log' root element"

            log_data = har_data["log"]

            if "version" not in log_data:
                return False, "Missing 'version' in log"

            if "creator" not in log_data:
                return False, "Missing 'creator' in log"

            if "entries" not in log_data:
                return False, "Missing 'entries' in log"

            entries = log_data["entries"]
            if not isinstance(entries, list):
                return False, "'entries' must be a list"

            for i, entry in enumerate(entries):
                if "request" not in entry:
                    return False, f"Entry {i} missing 'request'"
                if "response" not in entry:
                    return False, f"Entry {i} missing 'response'"
                if "startedDateTime" not in entry:
                    return False, f"Entry {i} missing 'startedDateTime'"
                if "timings" not in entry:
                    return False, f"Entry {i} missing 'timings'"

            return True, f"Valid HAR file with {len(entries)} entries"

        except json.JSONDecodeError as e:
            return False, f"Invalid JSON: {e}"
        except Exception as e:
            return False, f"Validation error: {e}"

    def validate_pcap_file(self, file_path: str) -> Tuple[bool, str]:
        """Validate PCAP file can be opened by Wireshark.

        Args:
            file_path: Path to PCAP file.

        Returns:
            Tuple of (is_valid, message).
        """
        try:
            if not os.path.exists(file_path):
                return False, f"File not found: {file_path}"

            file_size = os.path.getsize(file_path)
            if file_size < 24:
                return False, "File too small to be valid PCAP"

            with open(file_path, "rb") as f:
                magic = f.read(4)

            magic_value = int.from_bytes(magic, byteorder="big")
            if magic_value == 0xA1B2C3D4:
                return True, "Valid PCAP file (big-endian)"
            elif magic_value == 0xD4C3B2A1:
                return True, "Valid PCAP file (little-endian)"
            else:
                return False, f"Invalid PCAP magic: {magic.hex()}"

        except Exception as e:
            return False, f"Validation error: {e}"

    def build_cli_parser(self) -> argparse.ArgumentParser:
        """Build CLI argument parser for export commands.

        Returns:
            Configured ArgumentParser.
        """
        parser = argparse.ArgumentParser(
            description="Kunlun Traffic Export CLI",
            prog="kunlun export",
        )

        subparsers = parser.add_subparsers(dest="command", help="Export command")

        har_parser = subparsers.add_parser("har", help="Export traffic to HAR format")
        har_parser.add_argument(
            "--output", "-o",
            required=True,
            help="Output HAR file path",
        )
        har_parser.add_argument(
            "--filter-domain",
            action="append",
            dest="domains",
            help="Filter by domain (can be specified multiple times)",
        )
        har_parser.add_argument(
            "--filter-url",
            action="append",
            dest="url_patterns",
            help="Filter by URL pattern (can be specified multiple times)",
        )
        har_parser.add_argument(
            "--filter-method",
            action="append",
            dest="methods",
            help="Filter by HTTP method (can be specified multiple times)",
        )
        har_parser.add_argument(
            "--filter-status",
            action="append",
            type=int,
            dest="status_codes",
            help="Filter by status code (can be specified multiple times)",
        )
        har_parser.add_argument(
            "--no-websocket",
            action="store_true",
            help="Exclude WebSocket traffic",
        )
        har_parser.add_argument(
            "--no-base64",
            action="store_true",
            help="Disable Base64 encoding for bodies",
        )
        har_parser.add_argument(
            "--body-limit",
            type=int,
            default=10 * 1024 * 1024,
            help="Body size limit in bytes (default: 10MB)",
        )

        pcap_parser = subparsers.add_parser("pcap", help="Export traffic to PCAP format")
        pcap_parser.add_argument(
            "--output", "-o",
            required=True,
            help="Output PCAP file path",
        )
        pcap_parser.add_argument(
            "--filter-domain",
            action="append",
            dest="domains",
            help="Filter by domain (can be specified multiple times)",
        )
        pcap_parser.add_argument(
            "--filter-url",
            action="append",
            dest="url_patterns",
            help="Filter by URL pattern (can be specified multiple times)",
        )
        pcap_parser.add_argument(
            "--filter-method",
            action="append",
            dest="methods",
            help="Filter by HTTP method (can be specified multiple times)",
        )
        pcap_parser.add_argument(
            "--filter-status",
            action="append",
            type=int,
            dest="status_codes",
            help="Filter by status code (can be specified multiple times)",
        )
        pcap_parser.add_argument(
            "--mss",
            type=int,
            default=1460,
            help="TCP Maximum Segment Size (default: 1460)",
        )
        pcap_parser.add_argument(
            "--preserve-tls",
            action="store_true",
            help="Preserve original TLS records",
        )

        return parser
