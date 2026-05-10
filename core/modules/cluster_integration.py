"""Cluster Integration: Integration with asset discovery, vulnerability scanning, passive scanning, and reporting modules.

Provides:
- Asset discovery integration: Large-scale scan tasks automatically split into distributed sub-tasks, results aggregated into asset panel, same-subnet assets auto-associated
- Vulnerability scanning integration: PoC verification tasks distributed to multiple nodes for parallel execution, nodes filter executable tasks based on installed PoC libraries, vulnerability results deduplicated
- Passive scanning integration: MITM proxy traffic from multiple nodes aggregated to master for unified analysis, passive scanning rules managed on master and auto-synced to all workers
- Reporting integration: Distributed scan results automatically汇总 to report generation workflow, reports annotate scanning nodes and time ranges
"""

import asyncio
import json
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Coroutine, Dict, List, Optional, Set, Tuple

from core.modules.cluster_master import (
    ClusterMaster,
    ScanTask,
    SubTask,
    TaskPriority,
    TaskStatus,
)
from core.modules.cluster_manager import ClusterManager
from core.modules.cluster_worker import ClusterWorker, ScanResult, WorkerConfig
from core.modules.cluster_communication import ClusterMessage, MessageType

logger = logging.getLogger(__name__)


@dataclass
class AssetRecord:
    """Asset record from distributed scanning.

    Attributes:
        asset_id: Unique asset identifier
        ip: IP address
        port: Port number
        protocol: Protocol detected
        service: Service name
        fingerprint: Service fingerprint
        hostname: Hostname
        os: Operating system detected
        discovering_nodes: List of nodes that discovered this asset
        first_discovered: First discovery timestamp
        last_updated: Last update timestamp
        subnet: Subnet association
    """
    asset_id: str = ""
    ip: str = ""
    port: int = 0
    protocol: str = ""
    service: str = ""
    fingerprint: str = ""
    hostname: str = ""
    os: str = ""
    discovering_nodes: List[str] = field(default_factory=list)
    first_discovered: float = 0.0
    last_updated: float = 0.0
    subnet: str = ""


@dataclass
class VulnerabilityRecord:
    """Vulnerability record from distributed scanning.

    Attributes:
        vuln_id: Unique vulnerability identifier
        asset_id: Associated asset ID
        cve_id: CVE identifier
        title: Vulnerability title
        severity: Severity level
        description: Vulnerability description
        proof: Proof of concept
        discovering_nodes: List of nodes that discovered this vuln
        first_discovered: First discovery timestamp
        task_id: Associated task ID
    """
    vuln_id: str = ""
    asset_id: str = ""
    cve_id: str = ""
    title: str = ""
    severity: str = ""
    description: str = ""
    proof: str = ""
    discovering_nodes: List[str] = field(default_factory=list)
    first_discovered: float = 0.0
    task_id: str = ""


@dataclass
class PassiveScanRule:
    """Passive scanning rule.

    Attributes:
        rule_id: Unique rule identifier
        name: Rule name
        description: Rule description
        pattern: Detection pattern
        severity: Severity level
        enabled: Whether rule is enabled
        version: Rule version
    """
    rule_id: str = ""
    name: str = ""
    description: str = ""
    pattern: str = ""
    severity: str = ""
    enabled: bool = True
    version: str = "1.0.0"


@dataclass
class ReportData:
    """Report data from distributed scanning.

    Attributes:
        report_id: Unique report identifier
        task_id: Associated task ID
        title: Report title
        created_at: Creation timestamp
        scan_start: Scan start timestamp
        scan_end: Scan end timestamp
        scanning_nodes: List of nodes that participated
        total_assets: Total assets discovered
        total_vulnerabilities: Total vulnerabilities found
        assets: List of asset records
        vulnerabilities: List of vulnerability records
        summary: Report summary
    """
    report_id: str = ""
    task_id: str = ""
    title: str = ""
    created_at: float = 0.0
    scan_start: float = 0.0
    scan_end: float = 0.0
    scanning_nodes: List[str] = field(default_factory=list)
    total_assets: int = 0
    total_vulnerabilities: int = 0
    assets: List[AssetRecord] = field(default_factory=list)
    vulnerabilities: List[VulnerabilityRecord] = field(default_factory=list)
    summary: str = ""


class AssetDiscoveryIntegration:
    """Integrates distributed scanning with asset discovery module.

    Handles automatic task splitting, result aggregation, and subnet association.
    """

    def __init__(self, master: ClusterMaster) -> None:
        """Initialize asset discovery integration.

        Args:
            master: ClusterMaster instance.
        """
        self.master = master
        self._assets: Dict[str, AssetRecord] = {}
        self._asset_callbacks: List[Callable[[List[AssetRecord]], Coroutine[Any, Any, None]]] = []

    def register_asset_callback(
        self,
        callback: Callable[[List[AssetRecord]], Coroutine[Any, Any, None]],
    ) -> None:
        """Register callback for new asset discovery.

        Args:
            callback: Async callback function.
        """
        self._asset_callbacks.append(callback)

    async def submit_asset_discovery_task(
        self,
        targets: List[str],
        ports: Optional[List[int]] = None,
        name: str = "",
        priority: TaskPriority = TaskPriority.NORMAL,
    ) -> str:
        """Submit asset discovery task to cluster.

        Args:
            targets: List of target IPs/domains.
            ports: List of ports to scan.
            name: Task name.
            priority: Task priority.

        Returns:
            Task ID.
        """
        task = ScanTask(
            name=name or f"Asset Discovery - {time.strftime('%Y-%m-%d %H:%M:%S')}",
            targets=targets,
            ports=ports or [80, 443, 8080, 8443, 22, 3389],
            modules=["port_scan", "service_detection", "asset_discovery"],
            priority=priority,
        )

        task_id = await self.master.submit_task(task)

        return task_id

    async def process_aggregated_results(self, task_id: str) -> List[AssetRecord]:
        """Process aggregated results and update asset database.

        Args:
            task_id: Task identifier.

        Returns:
            List of new AssetRecord objects.
        """
        results = self.master.aggregator.get_results_for_task(task_id)

        new_assets: List[AssetRecord] = []

        for result in results:
            asset_key = result.asset_key

            if asset_key in self._assets:
                existing = self._assets[asset_key]

                for node in result.discovering_nodes:
                    if node not in existing.discovering_nodes:
                        existing.discovering_nodes.append(node)

                existing.last_updated = time.time()
            else:
                asset = AssetRecord(
                    asset_id=f"asset_{asset_key}",
                    ip=result.asset_data.get("ip", ""),
                    port=result.asset_data.get("port", 0),
                    protocol=result.asset_data.get("protocol", ""),
                    service=result.asset_data.get("service", ""),
                    fingerprint=result.asset_data.get("fingerprint", ""),
                    hostname=result.asset_data.get("hostname", ""),
                    os=result.asset_data.get("os", ""),
                    discovering_nodes=list(result.discovering_nodes),
                    first_discovered=result.first_discovered,
                    last_updated=result.last_updated,
                    subnet=self._extract_subnet(result.asset_data.get("ip", "")),
                )

                self._assets[asset_key] = asset
                new_assets.append(asset)

        if new_assets and self._asset_callbacks:
            for callback in self._asset_callbacks:
                try:
                    await callback(new_assets)
                except Exception as e:
                    logger.error(f"Asset callback error: {e}")

        return new_assets

    def get_assets_by_subnet(self, subnet: str) -> List[AssetRecord]:
        """Get assets by subnet.

        Args:
            subnet: Subnet CIDR.

        Returns:
            List of AssetRecord objects.
        """
        return [
            asset for asset in self._assets.values()
            if asset.subnet == subnet
        ]

    def get_all_assets(self) -> List[AssetRecord]:
        """Get all discovered assets.

        Returns:
            List of AssetRecord objects.
        """
        return list(self._assets.values())

    @staticmethod
    def _extract_subnet(ip: str) -> str:
        """Extract subnet from IP address.

        Args:
            ip: IP address.

        Returns:
            Subnet CIDR.
        """
        if not ip:
            return ""

        parts = ip.split(".")
        if len(parts) == 4:
            return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"

        return ""


class VulnerabilityScanIntegration:
    """Integrates distributed scanning with vulnerability scanning module.

    Handles PoC verification distribution, node filtering, and result deduplication.
    """

    def __init__(self, master: ClusterMaster) -> None:
        """Initialize vulnerability scan integration.

        Args:
            master: ClusterMaster instance.
        """
        self.master = master
        self._vulnerabilities: Dict[str, VulnerabilityRecord] = {}
        self._poc_libraries: Dict[str, List[str]] = {}
        self._vuln_callbacks: List[Callable[[List[VulnerabilityRecord]], Coroutine[Any, Any, None]]] = []

    def register_poc_library(self, node_id: str, poc_ids: List[str]) -> None:
        """Register PoC library for a node.

        Args:
            node_id: Node identifier.
            poc_ids: List of PoC IDs available on node.
        """
        self._poc_libraries[node_id] = poc_ids

    def register_vuln_callback(
        self,
        callback: Callable[[List[VulnerabilityRecord]], Coroutine[Any, Any, None]],
    ) -> None:
        """Register callback for new vulnerability discovery.

        Args:
            callback: Async callback function.
        """
        self._vuln_callbacks.append(callback)

    async def submit_vulnerability_scan(
        self,
        targets: List[str],
        cve_ids: Optional[List[str]] = None,
        name: str = "",
        priority: TaskPriority = TaskPriority.HIGH,
    ) -> str:
        """Submit vulnerability scan task to cluster.

        Args:
            targets: List of target IPs/domains.
            cve_ids: List of CVE IDs to verify.
            name: Task name.
            priority: Task priority.

        Returns:
            Task ID.
        """
        task = ScanTask(
            name=name or f"Vulnerability Scan - {time.strftime('%Y-%m-%d %H:%M:%S')}",
            targets=targets,
            ports=[],
            modules=["vulnerability_scan", "poc_verify"],
            priority=priority,
            parameters={"cve_ids": cve_ids or []},
        )

        task_id = await self.master.submit_task(task)

        return task_id

    async def process_vulnerability_results(self, task_id: str) -> List[VulnerabilityRecord]:
        """Process vulnerability results and deduplicate.

        Args:
            task_id: Task identifier.

        Returns:
            List of new VulnerabilityRecord objects.
        """
        results = self.master.aggregator.get_results_for_task(task_id)

        new_vulns: List[VulnerabilityRecord] = []

        for result in results:
            for vuln_data in result.asset_data.get("vulnerabilities", []):
                vuln_key = f"{result.asset_data.get('ip', '')}:{result.asset_data.get('port', 0)}:{vuln_data.get('cve_id', '')}"

                if vuln_key in self._vulnerabilities:
                    existing = self._vulnerabilities[vuln_key]

                    for node in result.discovering_nodes:
                        if node not in existing.discovering_nodes:
                            existing.discovering_nodes.append(node)
                else:
                    vuln = VulnerabilityRecord(
                        vuln_id=f"vuln_{vuln_key}",
                        asset_id=f"asset_{result.asset_key}",
                        cve_id=vuln_data.get("cve_id", ""),
                        title=vuln_data.get("title", ""),
                        severity=vuln_data.get("severity", ""),
                        description=vuln_data.get("description", ""),
                        proof=vuln_data.get("proof", ""),
                        discovering_nodes=list(result.discovering_nodes),
                        first_discovered=result.first_discovered,
                        task_id=task_id,
                    )

                    self._vulnerabilities[vuln_key] = vuln
                    new_vulns.append(vuln)

        if new_vulns and self._vuln_callbacks:
            for callback in self._vuln_callbacks:
                try:
                    await callback(new_vulns)
                except Exception as e:
                    logger.error(f"Vuln callback error: {e}")

        return new_vulns

    def get_vulnerabilities_by_severity(self, severity: str) -> List[VulnerabilityRecord]:
        """Get vulnerabilities by severity.

        Args:
            severity: Severity level.

        Returns:
            List of VulnerabilityRecord objects.
        """
        return [
            vuln for vuln in self._vulnerabilities.values()
            if vuln.severity == severity
        ]

    def get_all_vulnerabilities(self) -> List[VulnerabilityRecord]:
        """Get all discovered vulnerabilities.

        Returns:
            List of VulnerabilityRecord objects.
        """
        return list(self._vulnerabilities.values())


class PassiveScanIntegration:
    """Integrates distributed scanning with passive scanning module.

    Handles MITM proxy traffic aggregation, rule management, and rule sync.
    """

    def __init__(self, master: ClusterMaster) -> None:
        """Initialize passive scan integration.

        Args:
            master: ClusterMaster instance.
        """
        self.master = master
        self._rules: Dict[str, PassiveScanRule] = {}
        self._traffic_buffer: List[Dict[str, Any]] = []

    def add_rule(self, rule: PassiveScanRule) -> None:
        """Add passive scanning rule.

        Args:
            rule: PassiveScanRule object.
        """
        self._rules[rule.rule_id] = rule

    def remove_rule(self, rule_id: str) -> bool:
        """Remove passive scanning rule.

        Args:
            rule_id: Rule identifier.

        Returns:
            True if removed successfully.
        """
        if rule_id in self._rules:
            del self._rules[rule_id]
            return True

        return False

    def get_rules(self) -> List[PassiveScanRule]:
        """Get all passive scanning rules.

        Returns:
            List of PassiveScanRule objects.
        """
        return list(self._rules.values())

    async def sync_rules_to_workers(self) -> Dict[str, bool]:
        """Sync rules to all worker nodes.

        Returns:
            Dict of worker_id to sync success.
        """
        rules_data = [
            {
                "rule_id": rule.rule_id,
                "name": rule.name,
                "description": rule.description,
                "pattern": rule.pattern,
                "severity": rule.severity,
                "enabled": rule.enabled,
                "version": rule.version,
            }
            for rule in self._rules.values()
        ]

        return await self.master.comm_manager.broadcast(
            ClusterMessage(
                message_type=MessageType.CONFIG_UPDATE,
                sender_id=self.master.node_id,
                payload={
                    "type": "passive_scan_rules",
                    "rules": rules_data,
                },
            ),
        )

    def aggregate_traffic(self, traffic_data: Dict[str, Any]) -> None:
        """Aggregate traffic data from worker nodes.

        Args:
            traffic_data: Traffic data dict.
        """
        self._traffic_buffer.append(traffic_data)

        if len(self._traffic_buffer) > 10000:
            self._traffic_buffer = self._traffic_buffer[-5000:]

    def get_aggregated_traffic(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get aggregated traffic data.

        Args:
            limit: Maximum traffic entries.

        Returns:
            List of traffic data dicts.
        """
        return self._traffic_buffer[-limit:]


class ReportIntegration:
    """Integrates distributed scanning with report generation module.

    Handles automatic result aggregation for reports, node annotation, and time range tracking.
    """

    def __init__(
        self,
        master: ClusterMaster,
        asset_integration: AssetDiscoveryIntegration,
        vuln_integration: VulnerabilityScanIntegration,
    ) -> None:
        """Initialize report integration.

        Args:
            master: ClusterMaster instance.
            asset_integration: AssetDiscoveryIntegration instance.
            vuln_integration: VulnerabilityScanIntegration instance.
        """
        self.master = master
        self.asset_integration = asset_integration
        self.vuln_integration = vuln_integration
        self._reports: Dict[str, ReportData] = {}

    async def generate_report(
        self,
        task_id: str,
        title: str = "",
    ) -> ReportData:
        """Generate report for a distributed scan task.

        Args:
            task_id: Task identifier.
            title: Report title.

        Returns:
            ReportData object.
        """
        task = self.master._tasks.get(task_id)
        if not task:
            raise ValueError(f"Task not found: {task_id}")

        assets = self.asset_integration.get_all_assets()
        vulnerabilities = self.vuln_integration.get_all_vulnerabilities()

        scanning_nodes = self._get_task_scanning_nodes(task_id)

        report_id = f"report_{task_id}_{int(time.time())}"

        report = ReportData(
            report_id=report_id,
            task_id=task_id,
            title=title or f"Scan Report - {task.name}",
            created_at=time.time(),
            scan_start=task.started_at or task.created_at,
            scan_end=task.completed_at or time.time(),
            scanning_nodes=scanning_nodes,
            total_assets=len(assets),
            total_vulnerabilities=len(vulnerabilities),
            assets=assets,
            vulnerabilities=vulnerabilities,
            summary=self._generate_summary(task, assets, vulnerabilities),
        )

        self._reports[report_id] = report

        return report

    def get_report(self, report_id: str) -> Optional[ReportData]:
        """Get report by ID.

        Args:
            report_id: Report identifier.

        Returns:
            ReportData or None.
        """
        return self._reports.get(report_id)

    def get_all_reports(self) -> List[ReportData]:
        """Get all reports.

        Returns:
            List of ReportData objects.
        """
        return list(self._reports.values())

    def export_report_json(self, report_id: str) -> str:
        """Export report as JSON string.

        Args:
            report_id: Report identifier.

        Returns:
            JSON string.
        """
        report = self._reports.get(report_id)
        if not report:
            return ""

        report_dict = {
            "report_id": report.report_id,
            "task_id": report.task_id,
            "title": report.title,
            "created_at": report.created_at,
            "scan_start": report.scan_start,
            "scan_end": report.scan_end,
            "scanning_nodes": report.scanning_nodes,
            "total_assets": report.total_assets,
            "total_vulnerabilities": report.total_vulnerabilities,
            "assets": [
                {
                    "asset_id": a.asset_id,
                    "ip": a.ip,
                    "port": a.port,
                    "protocol": a.protocol,
                    "service": a.service,
                    "fingerprint": a.fingerprint,
                    "hostname": a.hostname,
                    "os": a.os,
                    "discovering_nodes": a.discovering_nodes,
                    "subnet": a.subnet,
                }
                for a in report.assets
            ],
            "vulnerabilities": [
                {
                    "vuln_id": v.vuln_id,
                    "asset_id": v.asset_id,
                    "cve_id": v.cve_id,
                    "title": v.title,
                    "severity": v.severity,
                    "description": v.description,
                    "proof": v.proof,
                    "discovering_nodes": v.discovering_nodes,
                }
                for v in report.vulnerabilities
            ],
            "summary": report.summary,
        }

        return json.dumps(report_dict, ensure_ascii=False, indent=2)

    def _get_task_scanning_nodes(self, task_id: str) -> List[str]:
        """Get list of nodes that participated in a task.

        Args:
            task_id: Task identifier.

        Returns:
            List of node IDs.
        """
        nodes: Set[str] = set()

        for sub_task in self.master._sub_tasks.values():
            if sub_task.task_id == task_id and sub_task.worker_id:
                nodes.add(sub_task.worker_id)

        return list(nodes)

    @staticmethod
    def _generate_summary(
        task: ScanTask,
        assets: List[AssetRecord],
        vulnerabilities: List[VulnerabilityRecord],
    ) -> str:
        """Generate report summary.

        Args:
            task: Scan task.
            assets: List of discovered assets.
            vulnerabilities: List of discovered vulnerabilities.

        Returns:
            Summary string.
        """
        high_severity = sum(1 for v in vulnerabilities if v.severity in ("high", "critical"))
        medium_severity = sum(1 for v in vulnerabilities if v.severity == "medium")
        low_severity = sum(1 for v in vulnerabilities if v.severity == "low")

        summary = (
            f"Scan task '{task.name}' completed.\n"
            f"Discovered {len(assets)} assets.\n"
            f"Found {len(vulnerabilities)} vulnerabilities: "
            f"{high_severity} high/critical, {medium_severity} medium, {low_severity} low."
        )

        return summary


class ClusterIntegration:
    """Main integration class that ties all cluster integrations together.

    Provides a unified interface for integrating distributed scanning
    with existing Kunlun platform modules.
    """

    def __init__(self, master: ClusterMaster, storage_path: str = "") -> None:
        """Initialize cluster integration.

        Args:
            master: ClusterMaster instance.
            storage_path: Path for integration data storage.
        """
        self.master = master
        self.storage_path = storage_path

        self.asset_integration = AssetDiscoveryIntegration(master)
        self.vuln_integration = VulnerabilityScanIntegration(master)
        self.passive_integration = PassiveScanIntegration(master)
        self.report_integration = ReportIntegration(
            master,
            self.asset_integration,
            self.vuln_integration,
        )

        self._task_completion_handlers: List[Callable[[str], Coroutine[Any, Any, None]]] = []

    def register_task_completion_handler(
        self,
        handler: Callable[[str], Coroutine[Any, Any, None]],
    ) -> None:
        """Register handler for task completion.

        Args:
            handler: Async callback function.
        """
        self._task_completion_handlers.append(handler)

    async def on_task_complete(self, task_id: str) -> None:
        """Handle task completion.

        Args:
            task_id: Task identifier.
        """
        await self.asset_integration.process_aggregated_results(task_id)
        await self.vuln_integration.process_vulnerability_results(task_id)

        for handler in self._task_completion_handlers:
            try:
                await handler(task_id)
            except Exception as e:
                logger.error(f"Task completion handler error: {e}")

    async def create_full_scan_task(
        self,
        targets: List[str],
        ports: Optional[List[int]] = None,
        name: str = "",
        priority: TaskPriority = TaskPriority.NORMAL,
        include_vulnerability_scan: bool = True,
    ) -> str:
        """Create a full scan task with asset discovery and vulnerability scanning.

        Args:
            targets: List of target IPs/domains.
            ports: List of ports to scan.
            name: Task name.
            priority: Task priority.
            include_vulnerability_scan: Whether to include vulnerability scanning.

        Returns:
            Task ID.
        """
        modules = ["port_scan", "service_detection", "asset_discovery"]

        if include_vulnerability_scan:
            modules.extend(["vulnerability_scan", "poc_verify"])

        task = ScanTask(
            name=name or f"Full Scan - {time.strftime('%Y-%m-%d %H:%M:%S')}",
            targets=targets,
            ports=ports or [80, 443, 8080, 8443, 22, 3389, 3306, 5432, 6379, 27017],
            modules=modules,
            priority=priority,
        )

        task_id = await self.master.submit_task(task)

        return task_id

    async def sync_all_rules(self) -> Dict[str, bool]:
        """Sync all rules to worker nodes.

        Returns:
            Dict of worker_id to sync success.
        """
        return await self.passive_integration.sync_rules_to_workers()
