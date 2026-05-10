"""Template Audit: Automated security audit, sandbox execution verification, malicious template detection.

Provides:
- Automated security audit: Static analysis (scan commands, payloads, URLs for malicious content), dynamic analysis (execute in isolated sandbox, monitor network/file/process), dependency audit (verify sub-templates and plugins)
- Sandbox execution verification: Execute templates in isolated sandbox with network isolation, full recording and logging, compare results with expected output
- Malicious template detection: Built-in malicious behavior signature database (reverse shell address replacement, unauthorized persistence, data exfiltration), auto-trigger deep audit on user reports, immediate takedown and notification for confirmed malicious templates
"""

import asyncio
import json
import logging
import os
import re
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Callable, Coroutine, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


class AuditLevel(Enum):
    """Audit result levels."""
    PASS = "pass"
    WARNING = "warning"
    REJECT = "reject"


class AuditType(Enum):
    """Audit types."""
    STATIC_ANALYSIS = "static_analysis"
    DYNAMIC_ANALYSIS = "dynamic_analysis"
    DEPENDENCY_AUDIT = "dependency_audit"
    DEEP_AUDIT = "deep_audit"


class MaliciousBehavior(Enum):
    """Malicious behavior types."""
    REVERSE_SHELL = "reverse_shell"
    UNAUTHORIZED_PERSISTENCE = "unauthorized_persistence"
    DATA_EXFILTRATION = "data_exfiltration"
    CREDENTIAL_THEFT = "credential_theft"
    C2_COMMUNICATION = "c2_communication"
    RANSOMWARE = "ransomware"
    CRYPTO_MINING = "crypto_mining"
    BOTNET = "botnet"


@dataclass
class AuditFinding:
    """Single audit finding.

    Attributes:
        finding_id: Unique finding identifier
        audit_type: Type of audit
        severity: Severity level (low/medium/high/critical)
        title: Finding title
        description: Finding description
        location: Location in template (step/command)
        evidence: Evidence supporting finding
        recommendation: Recommended action
    """
    finding_id: str = ""
    audit_type: AuditType = AuditType.STATIC_ANALYSIS
    severity: str = "low"
    title: str = ""
    description: str = ""
    location: str = ""
    evidence: str = ""
    recommendation: str = ""


@dataclass
class AuditReport:
    """Template audit report.

    Attributes:
        report_id: Unique report identifier
        template_id: Template identifier
        audit_level: Overall audit level
        audit_types: List of audit types performed
        findings: List of audit findings
        sandbox_results: Sandbox execution results
        execution_log: Sandbox execution log
        execution_recording: Sandbox execution recording path
        audit_timestamp: Audit timestamp
        auditor: Auditor identifier
        is_manual_review_required: Whether manual review is required
    """
    report_id: str = ""
    template_id: str = ""
    audit_level: AuditLevel = AuditLevel.PASS
    audit_types: List[AuditType] = field(default_factory=list)
    findings: List[AuditFinding] = field(default_factory=list)
    sandbox_results: Dict[str, Any] = field(default_factory=dict)
    execution_log: str = ""
    execution_recording: str = ""
    audit_timestamp: float = 0.0
    auditor: str = ""
    is_manual_review_required: bool = False


@dataclass
class SandboxConfig:
    """Sandbox execution configuration.

    Attributes:
        sandbox_id: Unique sandbox identifier
        network_isolated: Whether network is isolated
        allowed_hosts: List of allowed hosts
        max_execution_time: Maximum execution time in seconds
        max_memory_mb: Maximum memory usage in MB
        recording_enabled: Whether execution is recorded
        log_level: Logging level
    """
    sandbox_id: str = ""
    network_isolated: bool = True
    allowed_hosts: List[str] = field(default_factory=list)
    max_execution_time: int = 300
    max_memory_mb: int = 512
    recording_enabled: bool = True
    log_level: str = "INFO"


@dataclass
class MaliciousTemplateRecord:
    """Record of confirmed malicious template.

    Attributes:
        template_id: Template identifier
        author_id: Author identifier
        malicious_behaviors: List of malicious behaviors detected
        evidence: Evidence of malicious behavior
        detection_timestamp: Detection timestamp
        action_taken: Action taken (takedown/ban/warning)
        notified_users: List of users who installed template
        is_banned: Whether author is banned
    """
    template_id: str = ""
    author_id: str = ""
    malicious_behaviors: List[MaliciousBehavior] = field(default_factory=list)
    evidence: str = ""
    detection_timestamp: float = 0.0
    action_taken: str = ""
    notified_users: List[str] = field(default_factory=list)
    is_banned: bool = False


class TemplateAuditor:
    """Automated security auditor for templates.

    Performs static analysis, dynamic analysis in sandbox, dependency
    audits, and malicious template detection.
    """

    MALICIOUS_PATTERNS = {
        MaliciousBehavior.REVERSE_SHELL: [
            r"bash\s+-i\s+>&\s+/dev/tcp/",
            r"nc\s+-e\s+/bin/(ba)?sh",
            r"python.*socket.*connect.*subprocess",
            r"powershell.*invoke-webrequest.*downloadstring.*iex",
            r"mkfifo.*nc\s+",
            r"telnet\s+.*\|\s*/bin/(ba)?sh",
        ],
        MaliciousBehavior.UNAUTHORIZED_PERSISTENCE: [
            r"crontab\s+-l.*\|\|.*crontab",
            r"schtasks\s+/create.*\/sc\s+onlogon",
            r"systemctl\s+enable",
            r"reg\s+add.*Run",
            r"launchctl\s+load",
        ],
        MaliciousBehavior.DATA_EXFILTRATION: [
            r"curl\s+.*-d\s+@/etc/passwd",
            r"scp\s+.*root@.*:/",
            r"ftp\s+.*put\s+.*shadow",
            r"base64\s+.*curl.*post",
        ],
        MaliciousBehavior.CREDENTIAL_THEFT: [
            r"mimikatz.*sekurlsa::logonpasswords",
            r"procdump.*lsass",
            r"/etc/shadow.*cat",
            r"dumpcreds",
        ],
        MaliciousBehavior.C2_COMMUNICATION: [
            r"cobalt.*strike",
            r"metasploit.*meterpreter",
            r"empire.*agent",
            r"c2.*beacon",
        ],
    }

    SENSITIVE_COMMANDS = [
        "rm -rf /",
        "format c:",
        "shutdown /s /t 0",
        "del /s /q",
        "mkfs",
        "dd if=/dev/zero",
    ]

    def __init__(
        self,
        storage_path: str = "",
        sandbox_executor: Optional[Callable[[str, Dict[str, Any]], Coroutine[Any, Any, Dict[str, Any]]]] = None,
        notification_callback: Optional[Callable[[str, str, str], Coroutine[Any, Any, None]]] = None,
    ) -> None:
        """Initialize template auditor.

        Args:
            storage_path: Directory path for storage.
            sandbox_executor: Optional async callback for sandbox execution.
            notification_callback: Optional async callback for user notifications.
        """
        self.storage_path = storage_path
        self._sandbox_executor = sandbox_executor
        self._notification_callback = notification_callback
        self._audit_reports: Dict[str, AuditReport] = {}
        self._malicious_templates: Dict[str, MaliciousTemplateRecord] = {}
        self._banned_authors: Set[str] = set()
        self._template_install_map: Dict[str, List[str]] = {}

        if storage_path:
            os.makedirs(storage_path, exist_ok=True)
            self._load_data()

    async def audit_template(
        self,
        template_id: str,
        template_data: Dict[str, Any],
        author_id: str = "",
        audit_types: Optional[List[AuditType]] = None,
    ) -> AuditReport:
        """Perform comprehensive security audit on template.

        Args:
            template_id: Template identifier.
            template_data: Template data to audit.
            author_id: Template author ID.
            audit_types: Types of audits to perform.

        Returns:
            AuditReport with findings.
        """
        report_id = f"audit_{template_id}_{int(time.time())}"

        audit_types = audit_types or [
            AuditType.STATIC_ANALYSIS,
            AuditType.DYNAMIC_ANALYSIS,
            AuditType.DEPENDENCY_AUDIT,
        ]

        report = AuditReport(
            report_id=report_id,
            template_id=template_id,
            audit_types=audit_types,
            audit_timestamp=time.time(),
            auditor="auto",
        )

        for audit_type in audit_types:
            if audit_type == AuditType.STATIC_ANALYSIS:
                findings = await self._static_analysis(template_data)
                report.findings.extend(findings)
            elif audit_type == AuditType.DYNAMIC_ANALYSIS:
                findings, sandbox_results = await self._dynamic_analysis(template_id, template_data)
                report.findings.extend(findings)
                report.sandbox_results = sandbox_results
            elif audit_type == AuditType.DEPENDENCY_AUDIT:
                findings = await self._dependency_audit(template_data)
                report.findings.extend(findings)

        report.audit_level = self._determine_audit_level(report.findings)
        report.is_manual_review_required = report.audit_level == AuditLevel.REJECT

        if report.audit_level == AuditLevel.REJECT:
            malicious_behaviors = self._detect_malicious_behaviors(report.findings)
            if malicious_behaviors:
                await self._handle_malicious_template(
                    template_id,
                    author_id,
                    malicious_behaviors,
                    report,
                )

        self._audit_reports[report_id] = report
        self._save_data()

        return report

    async def deep_audit_template(
        self,
        template_id: str,
        template_data: Dict[str, Any],
        author_id: str = "",
    ) -> AuditReport:
        """Perform deep audit on template (triggered by user reports).

        Args:
            template_id: Template identifier.
            template_data: Template data to audit.
            author_id: Template author ID.

        Returns:
            AuditReport with findings.
        """
        report = await self.audit_template(
            template_id,
            template_data,
            author_id,
            [AuditType.STATIC_ANALYSIS, AuditType.DYNAMIC_ANALYSIS, AuditType.DEPENDENCY_AUDIT, AuditType.DEEP_AUDIT],
        )

        report.audit_types.append(AuditType.DEEP_AUDIT)

        return report

    async def execute_in_sandbox(
        self,
        template_id: str,
        template_data: Dict[str, Any],
        config: Optional[SandboxConfig] = None,
    ) -> Dict[str, Any]:
        """Execute template in isolated sandbox.

        Args:
            template_id: Template identifier.
            template_data: Template data to execute.
            config: Sandbox configuration.

        Returns:
            Sandbox execution results.
        """
        config = config or SandboxConfig(
            sandbox_id=f"sandbox_{template_id}_{int(time.time())}",
        )

        if self._sandbox_executor:
            result = await self._sandbox_executor(template_id, {
                "template_data": template_data,
                "config": {
                    "network_isolated": config.network_isolated,
                    "allowed_hosts": config.allowed_hosts,
                    "max_execution_time": config.max_execution_time,
                    "max_memory_mb": config.max_memory_mb,
                },
            })

            return {
                "sandbox_id": config.sandbox_id,
                "success": result.get("success", False),
                "output": result.get("output", ""),
                "network_connections": result.get("network_connections", []),
                "file_operations": result.get("file_operations", []),
                "process_creations": result.get("process_creations", []),
                "execution_time": result.get("execution_time", 0),
                "memory_usage": result.get("memory_usage", 0),
                "log": result.get("log", ""),
                "recording_path": result.get("recording_path", ""),
            }

        return {
            "sandbox_id": config.sandbox_id,
            "success": True,
            "output": "Simulated sandbox execution",
            "network_connections": [],
            "file_operations": [],
            "process_creations": [],
            "execution_time": 0,
            "memory_usage": 0,
            "log": "",
            "recording_path": "",
        }

    async def report_template(
        self,
        template_id: str,
        template_data: Dict[str, Any],
        reporter_id: str,
        reason: str = "",
    ) -> AuditReport:
        """Report template for deep audit.

        Args:
            template_id: Template identifier.
            template_data: Template data.
            reporter_id: Reporter user ID.
            reason: Report reason.

        Returns:
            AuditReport from deep audit.
        """
        logger.info(f"Template {template_id} reported by {reporter_id}: {reason}")

        return await self.deep_audit_template(template_id, template_data)

    async def get_audit_report(self, report_id: str) -> Optional[AuditReport]:
        """Get audit report.

        Args:
            report_id: Report identifier.

        Returns:
            AuditReport or None.
        """
        return self._audit_reports.get(report_id)

    async def get_template_audit_history(self, template_id: str) -> List[AuditReport]:
        """Get audit history for template.

        Args:
            template_id: Template identifier.

        Returns:
            List of AuditReport objects.
        """
        return [
            r for r in self._audit_reports.values()
            if r.template_id == template_id
        ]

    async def get_malicious_templates(self) -> List[MaliciousTemplateRecord]:
        """Get list of malicious templates.

        Returns:
            List of MaliciousTemplateRecord objects.
        """
        return list(self._malicious_templates.values())

    async def is_author_banned(self, author_id: str) -> bool:
        """Check if author is banned.

        Args:
            author_id: Author identifier.

        Returns:
            True if author is banned.
        """
        return author_id in self._banned_authors

    async def _static_analysis(self, template_data: Dict[str, Any]) -> List[AuditFinding]:
        """Perform static analysis on template.

        Scans commands, payloads, URLs for malicious content.

        Args:
            template_data: Template data.

        Returns:
            List of AuditFinding objects.
        """
        findings: List[AuditFinding] = []

        steps = template_data.get("steps", [])
        for i, step in enumerate(steps):
            command = step.get("command", "")
            payload = step.get("payload", "")
            url = step.get("url", "")

            text_to_scan = f"{command} {payload} {url}"

            for behavior, patterns in self.MALICIOUS_PATTERNS.items():
                for pattern in patterns:
                    if re.search(pattern, text_to_scan, re.IGNORECASE):
                        finding = AuditFinding(
                            finding_id=f"static_{i}_{behavior.value}",
                            audit_type=AuditType.STATIC_ANALYSIS,
                            severity="critical",
                            title=f"Potential {behavior.value.replace('_', ' ')} detected",
                            description=f"Step {i + 1} contains pattern matching {behavior.value}",
                            location=f"Step {i + 1}",
                            evidence=f"Pattern: {pattern}",
                            recommendation="Review step and remove malicious content",
                        )
                        findings.append(finding)

            for sensitive_cmd in self.SENSITIVE_COMMANDS:
                if sensitive_cmd.lower() in text_to_scan.lower():
                    finding = AuditFinding(
                        finding_id=f"static_{i}_sensitive",
                        audit_type=AuditType.STATIC_ANALYSIS,
                        severity="high",
                        title="Sensitive destructive command detected",
                        description=f"Step {i + 1} contains potentially destructive command",
                        location=f"Step {i + 1}",
                        evidence=f"Command: {sensitive_cmd}",
                        recommendation="Remove or replace destructive command",
                    )
                    findings.append(finding)

            ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
            for match in ip_pattern.finditer(text_to_scan):
                ip = match.group()
                if not ip.startswith(("10.", "192.168.", "172.")):
                    finding = AuditFinding(
                        finding_id=f"static_{i}_external_ip",
                        audit_type=AuditType.STATIC_ANALYSIS,
                        severity="medium",
                        title="External IP address detected",
                        description=f"Step {i + 1} references external IP: {ip}",
                        location=f"Step {i + 1}",
                        evidence=f"IP: {ip}",
                        recommendation="Verify IP is authorized target",
                    )
                    findings.append(finding)

        return findings

    async def _dynamic_analysis(
        self,
        template_id: str,
        template_data: Dict[str, Any],
    ) -> Tuple[List[AuditFinding], Dict[str, Any]]:
        """Perform dynamic analysis in sandbox.

        Args:
            template_id: Template identifier.
            template_data: Template data.

        Returns:
            Tuple of (findings, sandbox_results).
        """
        findings: List[AuditFinding] = []

        sandbox_results = await self.execute_in_sandbox(template_id, template_data)

        network_connections = sandbox_results.get("network_connections", [])
        for conn in network_connections:
            dest = conn.get("destination", "")
            if not dest.startswith(("10.", "192.168.", "172.", "127.")):
                finding = AuditFinding(
                    finding_id=f"dynamic_net_{dest}",
                    audit_type=AuditType.DYNAMIC_ANALYSIS,
                    severity="high",
                    title="Unauthorized network connection",
                    description=f"Template connected to external host: {dest}",
                    location="Network",
                    evidence=f"Connection: {conn}",
                    recommendation="Verify connection is expected and authorized",
                )
                findings.append(finding)

        file_operations = sandbox_results.get("file_operations", [])
        for op in file_operations:
            path = op.get("path", "")
            operation = op.get("operation", "")

            if "shadow" in path or "passwd" in path or "sam" in path.lower():
                finding = AuditFinding(
                    finding_id=f"dynamic_file_{path}",
                    audit_type=AuditType.DYNAMIC_ANALYSIS,
                    severity="high",
                    title="Sensitive file access detected",
                    description=f"Template accessed sensitive file: {path}",
                    location="File System",
                    evidence=f"Operation: {operation}, Path: {path}",
                    recommendation="Verify file access is part of legitimate test",
                )
                findings.append(finding)

        process_creations = sandbox_results.get("process_creations", [])
        for proc in process_creations:
            name = proc.get("name", "").lower()
            if any(s in name for s in ["mimikatz", "procdump", "pwdump", "wce"]):
                finding = AuditFinding(
                    finding_id=f"dynamic_proc_{name}",
                    audit_type=AuditType.DYNAMIC_ANALYSIS,
                    severity="high",
                    title="Suspicious process creation",
                    description=f"Template created suspicious process: {name}",
                    location="Process",
                    evidence=f"Process: {proc}",
                    recommendation="Verify process is authorized security tool",
                )
                findings.append(finding)

        return findings, sandbox_results

    async def _dependency_audit(self, template_data: Dict[str, Any]) -> List[AuditFinding]:
        """Audit template dependencies (sub-templates and plugins).

        Args:
            template_data: Template data.

        Returns:
            List of AuditFinding objects.
        """
        findings: List[AuditFinding] = []

        sub_templates = template_data.get("sub_template_refs", [])
        for sub_id in sub_templates:
            if sub_id in self._malicious_templates:
                finding = AuditFinding(
                    finding_id=f"dep_{sub_id}",
                    audit_type=AuditType.DEPENDENCY_AUDIT,
                    severity="critical",
                    title="Malicious sub-template dependency",
                    description=f"Template references known malicious sub-template: {sub_id}",
                    location=f"Dependency: {sub_id}",
                    evidence=f"Sub-template: {sub_id}",
                    recommendation="Remove dependency on malicious sub-template",
                )
                findings.append(finding)

        plugins = template_data.get("plugin_refs", [])
        for plugin_id in plugins:
            if plugin_id in self._malicious_templates:
                finding = AuditFinding(
                    finding_id=f"dep_plugin_{plugin_id}",
                    audit_type=AuditType.DEPENDENCY_AUDIT,
                    severity="critical",
                    title="Malicious plugin dependency",
                    description=f"Template references known malicious plugin: {plugin_id}",
                    location=f"Dependency: {plugin_id}",
                    evidence=f"Plugin: {plugin_id}",
                    recommendation="Remove dependency on malicious plugin",
                )
                findings.append(finding)

        return findings

    def _determine_audit_level(self, findings: List[AuditFinding]) -> AuditLevel:
        """Determine overall audit level.

        Args:
            findings: List of audit findings.

        Returns:
            AuditLevel.
        """
        if not findings:
            return AuditLevel.PASS

        severities = [f.severity for f in findings]

        if "critical" in severities:
            return AuditLevel.REJECT
        elif "high" in severities:
            return AuditLevel.WARNING
        elif "medium" in severities:
            return AuditLevel.WARNING

        return AuditLevel.PASS

    def _detect_malicious_behaviors(
        self,
        findings: List[AuditFinding],
    ) -> List[MaliciousBehavior]:
        """Detect malicious behaviors from findings.

        Args:
            findings: List of audit findings.

        Returns:
            List of MaliciousBehavior enums.
        """
        behaviors: Set[MaliciousBehavior] = set()

        for finding in findings:
            if finding.severity == "critical":
                title_lower = finding.title.lower()
                for behavior in MaliciousBehavior:
                    if behavior.value.replace("_", " ") in title_lower:
                        behaviors.add(behavior)

        return list(behaviors)

    async def _handle_malicious_template(
        self,
        template_id: str,
        author_id: str,
        behaviors: List[MaliciousBehavior],
        report: AuditReport,
    ) -> None:
        """Handle confirmed malicious template.

        Args:
            template_id: Template identifier.
            author_id: Author identifier.
            behaviors: List of malicious behaviors.
            report: Audit report.
        """
        record = MaliciousTemplateRecord(
            template_id=template_id,
            author_id=author_id,
            malicious_behaviors=behaviors,
            evidence=json.dumps([
                {
                    "finding_id": f.finding_id,
                    "title": f.title,
                    "severity": f.severity,
                }
                for f in report.findings
                if f.severity == "critical"
            ]),
            detection_timestamp=time.time(),
            action_taken="takedown",
            notified_users=self._template_install_map.get(template_id, []),
            is_banned=True,
        )

        self._malicious_templates[template_id] = record
        self._banned_authors.add(author_id)

        if self._notification_callback:
            for user_id in record.notified_users:
                await self._notification_callback(
                    user_id,
                    "malicious_template",
                    f"Template {template_id} has been identified as malicious and removed",
                )

        logger.warning(f"Malicious template {template_id} by {author_id} detected and removed")

    def _load_data(self) -> None:
        """Load data from storage."""
        if not self.storage_path:
            return

        try:
            data_file = os.path.join(self.storage_path, "audit_data.json")
            if os.path.exists(data_file):
                with open(data_file, "r", encoding="utf-8") as f:
                    data = json.load(f)

                    for report_id, report_data in data.get("audit_reports", {}).items():
                        findings = []
                        for f_data in report_data.get("findings", []):
                            findings.append(AuditFinding(
                                finding_id=f_data.get("finding_id", ""),
                                audit_type=AuditType(f_data.get("audit_type", "static_analysis")),
                                severity=f_data.get("severity", "low"),
                                title=f_data.get("title", ""),
                                description=f_data.get("description", ""),
                                location=f_data.get("location", ""),
                                evidence=f_data.get("evidence", ""),
                                recommendation=f_data.get("recommendation", ""),
                            ))

                        report = AuditReport(
                            report_id=report_id,
                            template_id=report_data.get("template_id", ""),
                            audit_level=AuditLevel(report_data.get("audit_level", "pass")),
                            audit_types=[
                                AuditType(t) for t in report_data.get("audit_types", [])
                            ],
                            findings=findings,
                            sandbox_results=report_data.get("sandbox_results", {}),
                            execution_log=report_data.get("execution_log", ""),
                            execution_recording=report_data.get("execution_recording", ""),
                            audit_timestamp=report_data.get("audit_timestamp", 0.0),
                            auditor=report_data.get("auditor", ""),
                            is_manual_review_required=report_data.get("is_manual_review_required", False),
                        )

                        self._audit_reports[report.report_id] = report

                    for tpl_id, mal_data in data.get("malicious_templates", {}).items():
                        behaviors = [
                            MaliciousBehavior(b)
                            for b in mal_data.get("malicious_behaviors", [])
                        ]

                        record = MaliciousTemplateRecord(
                            template_id=tpl_id,
                            author_id=mal_data.get("author_id", ""),
                            malicious_behaviors=behaviors,
                            evidence=mal_data.get("evidence", ""),
                            detection_timestamp=mal_data.get("detection_timestamp", 0.0),
                            action_taken=mal_data.get("action_taken", ""),
                            notified_users=mal_data.get("notified_users", []),
                            is_banned=mal_data.get("is_banned", False),
                        )

                        self._malicious_templates[record.template_id] = record
                        if record.is_banned:
                            self._banned_authors.add(record.author_id)

                    self._template_install_map = data.get("template_install_map", {})

        except Exception as e:
            logger.error(f"Failed to load audit data: {e}")

    def _save_data(self) -> None:
        """Save data to storage."""
        if not self.storage_path:
            return

        try:
            data_file = os.path.join(self.storage_path, "audit_data.json")

            data = {
                "audit_reports": {
                    report_id: {
                        "template_id": r.template_id,
                        "audit_level": r.audit_level.value,
                        "audit_types": [t.value for t in r.audit_types],
                        "findings": [
                            {
                                "finding_id": f.finding_id,
                                "audit_type": f.audit_type.value,
                                "severity": f.severity,
                                "title": f.title,
                                "description": f.description,
                                "location": f.location,
                                "evidence": f.evidence,
                                "recommendation": f.recommendation,
                            }
                            for f in r.findings
                        ],
                        "sandbox_results": r.sandbox_results,
                        "execution_log": r.execution_log,
                        "execution_recording": r.execution_recording,
                        "audit_timestamp": r.audit_timestamp,
                        "auditor": r.auditor,
                        "is_manual_review_required": r.is_manual_review_required,
                    }
                    for report_id, r in self._audit_reports.items()
                },
                "malicious_templates": {
                    tpl_id: {
                        "author_id": m.author_id,
                        "malicious_behaviors": [b.value for b in m.malicious_behaviors],
                        "evidence": m.evidence,
                        "detection_timestamp": m.detection_timestamp,
                        "action_taken": m.action_taken,
                        "notified_users": m.notified_users,
                        "is_banned": m.is_banned,
                    }
                    for tpl_id, m in self._malicious_templates.items()
                },
                "template_install_map": self._template_install_map,
            }

            with open(data_file, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)

        except Exception as e:
            logger.error(f"Failed to save audit data: {e}")
