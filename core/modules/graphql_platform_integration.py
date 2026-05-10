"""GraphQL platform integration: deep integration with passive scanning, PoC engine, and report module.

Provides:
- GraphQL-specific passive scanning rules
- Automatic GraphQL traffic analysis through proxy
- GraphQL endpoint auto-registration as assets
- PoC script generation for advanced attacks
- Nuclei template format support
- MITRE ATT&CK mapping
- GraphQL security assessment report generation
"""

import json
import logging
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Coroutine, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


class IntegrationType(Enum):
    """Platform integration types."""
    PASSIVE_SCANNING = "passive_scanning"
    POC_ENGINE = "poc_engine"
    REPORT_MODULE = "report_module"
    ASSET_REGISTRY = "asset_registry"
    EVENT_BUS = "event_bus"


class SeverityLevel(Enum):
    """Vulnerability severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class PassiveRule:
    """Passive scanning rule definition.

    Attributes:
        rule_id: Rule ID
        name: Rule name
        description: Rule description
        severity: Severity level
        mitre_attack_id: MITRE ATT&CK technique ID
        pattern: Detection pattern
        enabled: Whether enabled
    """
    rule_id: str = ""
    name: str = ""
    description: str = ""
    severity: SeverityLevel = SeverityLevel.INFO
    mitre_attack_id: str = ""
    pattern: str = ""
    enabled: bool = True


@dataclass
class PassiveFinding:
    """Passive scanning finding.

    Attributes:
        finding_id: Finding ID
        timestamp: Finding timestamp
        rule_id: Triggered rule ID
        rule_name: Rule name
        severity: Severity level
        target_url: Target URL
        evidence: Evidence data
        mitre_attack_id: MITRE ATT&CK technique ID
        raw_request: Raw request
        raw_response: Raw response
    """
    finding_id: str = ""
    timestamp: float = 0.0
    rule_id: str = ""
    rule_name: str = ""
    severity: SeverityLevel = SeverityLevel.INFO
    target_url: str = ""
    evidence: str = ""
    mitre_attack_id: str = ""
    raw_request: str = ""
    raw_response: str = ""


@dataclass
class PoCScript:
    """PoC script definition.

    Attributes:
        poc_id: PoC ID
        name: PoC name
        description: PoC description
        attack_type: Attack type
        severity: Severity level
        mitre_attack_id: MITRE ATT&CK technique ID
        script: PoC script content
        nuclei_template: Nuclei template YAML
        verified: Whether verified
    """
    poc_id: str = ""
    name: str = ""
    description: str = ""
    attack_type: str = ""
    severity: SeverityLevel = SeverityLevel.INFO
    mitre_attack_id: str = ""
    script: str = ""
    nuclei_template: str = ""
    verified: bool = False


@dataclass
class ReportSection:
    """Report section definition.

    Attributes:
        section_id: Section ID
        title: Section title
        content: Section content
        data: Section data
        mitre_mapping: MITRE ATT&CK mapping
    """
    section_id: str = ""
    title: str = ""
    content: str = ""
    data: Dict[str, Any] = field(default_factory=dict)
    mitre_mapping: Dict[str, str] = field(default_factory=dict)


@dataclass
class AssetRecord:
    """Asset registry record.

    Attributes:
        asset_id: Asset ID
        url: Asset URL
        asset_type: Asset type
        discovered_at: Discovery timestamp
        metadata: Asset metadata
        tags: Asset tags
    """
    asset_id: str = ""
    url: str = ""
    asset_type: str = "graphql_endpoint"
    discovered_at: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)


class GraphQLPlatformIntegration:
    """GraphQL platform integration module.

    Provides deep integration with passive scanning, PoC engine,
    and report module capabilities.
    """

    MITRE_ATTACK_MAPPING: Dict[str, str] = {
        "information_disclosure": "T1083",
        "unauthorized_access": "T1078",
        "dos_attack": "T1498",
        "injection": "T1190",
        "privilege_escalation": "T1078",
        "credential_access": "T1552",
        "discovery": "T1580",
    }

    PASSIVE_RULES: List[PassiveRule] = [
        PassiveRule(
            rule_id="graphql-passive-001",
            name="GraphQL Introspection Enabled",
            description="Detects when GraphQL introspection is enabled, allowing full schema discovery",
            severity=SeverityLevel.MEDIUM,
            mitre_attack_id="T1580",
            pattern="__schema",
            enabled=True,
        ),
        PassiveRule(
            rule_id="graphql-passive-002",
            name="Sensitive Field Exposure",
            description="Detects sensitive fields (password, token, secret) in GraphQL responses",
            severity=SeverityLevel.HIGH,
            mitre_attack_id="T1083",
            pattern="password|token|secret|apiKey",
            enabled=True,
        ),
        PassiveRule(
            rule_id="graphql-passive-003",
            name="Error Information Leakage",
            description="Detects verbose error messages that may leak internal information",
            severity=SeverityLevel.MEDIUM,
            mitre_attack_id="T1083",
            pattern="stack trace|internal error|debug",
            enabled=True,
        ),
        PassiveRule(
            rule_id="graphql-passive-004",
            name="Unauthorized Query Access",
            description="Detects successful queries without authentication",
            severity=SeverityLevel.HIGH,
            mitre_attack_id="T1078",
            pattern="unauthorized|forbidden",
            enabled=True,
        ),
        PassiveRule(
            rule_id="graphql-passive-005",
            name="Batch Query Risk",
            description="Detects batch queries that may bypass rate limiting",
            severity=SeverityLevel.MEDIUM,
            mitre_attack_id="T1498",
            pattern="\\[.*query.*\\]",
            enabled=True,
        ),
        PassiveRule(
            rule_id="graphql-passive-006",
            name="Debug Interface Exposure",
            description="Detects GraphQL debug interfaces (GraphiQL, Playground) exposed",
            severity=SeverityLevel.LOW,
            mitre_attack_id="T1580",
            pattern="graphiql|playground|altair",
            enabled=True,
        ),
    ]

    def __init__(
        self,
        passive_scanner: Optional[Any] = None,
        poc_engine: Optional[Any] = None,
        report_module: Optional[Any] = None,
        asset_registry: Optional[Any] = None,
        event_bus: Optional[Any] = None,
    ) -> None:
        """Initialize platform integration.

        Args:
            passive_scanner: Passive scanning engine.
            poc_engine: PoC verification engine.
            report_module: Report generation module.
            asset_registry: Asset registry module.
            event_bus: Event bus for broadcasting events.
        """
        self.passive_scanner = passive_scanner
        self.poc_engine = poc_engine
        self.report_module = report_module
        self.asset_registry = asset_registry
        self.event_bus = event_bus

        self._passive_findings: List[PassiveFinding] = []
        self._poc_scripts: List[PoCScript] = []
        self._report_sections: List[ReportSection] = []
        self._asset_records: List[AssetRecord] = []

        self._progress_callback: Optional[Callable[[str, float], Coroutine[Any, Any, None]]] = None
        self._log_callback: Optional[Callable[[str], Coroutine[Any, Any, None]]] = None
        self._vulnerability_callback: Optional[Callable[[Dict[str, Any]], Coroutine[Any, Any, None]]] = None

    def set_callbacks(
        self,
        progress_cb: Optional[Callable[[str, float], Coroutine[Any, Any, None]]] = None,
        log_cb: Optional[Callable[[str], Coroutine[Any, Any, None]]] = None,
        vuln_cb: Optional[Callable[[Dict[str, Any]], Coroutine[Any, Any, None]]] = None,
    ) -> None:
        """Set integration callbacks.

        Args:
            progress_cb: Callback for progress updates.
            log_cb: Callback for log messages.
            vuln_cb: Callback for vulnerability reports.
        """
        self._progress_callback = progress_cb
        self._log_callback = log_cb
        self._vulnerability_callback = vuln_cb

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

    async def _report_vulnerability(self, vuln_data: Dict[str, Any]) -> None:
        """Report vulnerability via callback.

        Args:
            vuln_data: Vulnerability data.
        """
        if self._vulnerability_callback:
            await self._vulnerability_callback(vuln_data)
        logger.info("Integration Vulnerability: %s", json.dumps(vuln_data))

    async def analyze_proxy_traffic(
        self,
        request_data: Dict[str, Any],
        response_data: Dict[str, Any],
    ) -> List[PassiveFinding]:
        """Analyze proxy traffic for GraphQL findings.

        Args:
            request_data: Request data from proxy.
            response_data: Response data from proxy.

        Returns:
            List of PassiveFinding.
        """
        findings: List[PassiveFinding] = []

        is_graphql = self._is_graphql_traffic(request_data, response_data)

        if not is_graphql:
            return findings

        for rule in self.PASSIVE_RULES:
            if not rule.enabled:
                continue

            if self._check_rule_match(rule, request_data, response_data):
                finding = PassiveFinding(
                    finding_id=f"finding_{uuid.uuid4().hex[:8]}",
                    timestamp=time.time(),
                    rule_id=rule.rule_id,
                    rule_name=rule.name,
                    severity=rule.severity,
                    target_url=request_data.get("url", ""),
                    evidence=rule.pattern,
                    mitre_attack_id=rule.mitre_attack_id,
                    raw_request=json.dumps(request_data),
                    raw_response=json.dumps(response_data),
                )
                findings.append(finding)
                self._passive_findings.append(finding)

                await self._report_vulnerability({
                    "type": "passive_finding",
                    "rule": rule.name,
                    "severity": rule.severity.value,
                    "url": request_data.get("url", ""),
                    "mitre_attack_id": rule.mitre_attack_id,
                })

        if findings:
            await self._report_log(
                f"被动扫描发现 {len(findings)} 条GraphQL安全问题"
            )

        return findings

    def _is_graphql_traffic(
        self,
        request_data: Dict[str, Any],
        response_data: Dict[str, Any],
    ) -> bool:
        """Check if traffic is GraphQL.

        Args:
            request_data: Request data.
            response_data: Response data.

        Returns:
            Whether traffic is GraphQL.
        """
        content_type = request_data.get("headers", {}).get("Content-Type", "")

        if "graphql" in content_type.lower():
            return True

        body = request_data.get("body", "")

        if isinstance(body, str):
            graphql_keywords = ["query", "mutation", "subscription", "__schema", "__type"]
            return any(kw in body.lower() for kw in graphql_keywords)
        elif isinstance(body, dict):
            return any(k in body for k in ["query", "mutation", "subscription"])

        return False

    def _check_rule_match(
        self,
        rule: PassiveRule,
        request_data: Dict[str, Any],
        response_data: Dict[str, Any],
    ) -> bool:
        """Check if rule matches traffic.

        Args:
            rule: Passive rule.
            request_data: Request data.
            response_data: Response data.

        Returns:
            Whether rule matches.
        """
        import re

        request_str = json.dumps(request_data).lower()
        response_str = json.dumps(response_data).lower()

        try:
            pattern = re.compile(rule.pattern, re.IGNORECASE)
            return bool(pattern.search(request_str) or pattern.search(response_str))
        except re.error:
            return rule.pattern.lower() in request_str or rule.pattern.lower() in response_str

    def register_graphql_asset(
        self,
        url: str,
        metadata: Optional[Dict[str, Any]] = None,
        tags: Optional[List[str]] = None,
    ) -> AssetRecord:
        """Register GraphQL endpoint as asset.

        Args:
            url: Endpoint URL.
            metadata: Asset metadata.
            tags: Asset tags.

        Returns:
            AssetRecord.
        """
        asset = AssetRecord(
            asset_id=f"asset_{uuid.uuid4().hex[:8]}",
            url=url,
            discovered_at=time.time(),
            metadata=metadata or {},
            tags=tags or ["graphql", "api"],
        )

        self._asset_records.append(asset)

        if self.asset_registry:
            self.asset_registry.register(asset)

        return asset

    def generate_poc_script(
        self,
        attack_type: str,
        target_url: str,
        severity: SeverityLevel,
        description: str,
        payload: str,
        mitre_attack_id: Optional[str] = None,
    ) -> PoCScript:
        """Generate PoC script for attack.

        Args:
            attack_type: Attack type.
            target_url: Target URL.
            severity: Severity level.
            description: PoC description.
            payload: Attack payload.
            mitre_attack_id: MITRE ATT&CK technique ID.

        Returns:
            PoCScript.
        """
        poc_id = f"poc_{uuid.uuid4().hex[:8]}"

        script = self._generate_python_poc(
            attack_type, target_url, payload
        )

        nuclei_template = self._generate_nuclei_template(
            attack_type, target_url, severity, description, payload
        )

        poc = PoCScript(
            poc_id=poc_id,
            name=f"GraphQL {attack_type.title()} PoC",
            description=description,
            attack_type=attack_type,
            severity=severity,
            mitre_attack_id=mitre_attack_id or self.MITRE_ATTACK_MAPPING.get(attack_type, ""),
            script=script,
            nuclei_template=nuclei_template,
            verified=False,
        )

        self._poc_scripts.append(poc)

        return poc

    def _generate_python_poc(
        self,
        attack_type: str,
        target_url: str,
        payload: str,
    ) -> str:
        """Generate Python PoC script.

        Args:
            attack_type: Attack type.
            target_url: Target URL.
            payload: Attack payload.

        Returns:
            Python PoC script.
        """
        return f'''"""GraphQL {attack_type.title()} PoC

Auto-generated PoC for GraphQL {attack_type} attack.
Target: {target_url}
"""

import requests
import json

TARGET_URL = "{target_url}"

def run_poc():
    """Execute the PoC."""
    headers = {{
        "Content-Type": "application/json",
    }}

    payload = {{
        "query": {json.dumps(payload)}
    }}

    response = requests.post(TARGET_URL, json=payload, headers=headers)

    if response.status_code == 200:
        data = response.json()
        if "errors" in data:
            print(f"[!] Vulnerable: {{data['errors']}}")
            return True
        elif "data" in data:
            print(f"[+] Successful response: {{data['data']}}")
            return True

    print("[-] Not vulnerable")
    return False

if __name__ == "__main__":
    run_poc()
'''

    def _generate_nuclei_template(
        self,
        attack_type: str,
        target_url: str,
        severity: SeverityLevel,
        description: str,
        payload: str,
    ) -> str:
        """Generate Nuclei template YAML.

        Args:
            attack_type: Attack type.
            target_url: Target URL.
            severity: Severity level.
            description: PoC description.
            payload: Attack payload.

        Returns:
            Nuclei template YAML.
        """
        return f'''id: graphql-{attack_type.lower()}

info:
  name: GraphQL {attack_type.title()} Detection
  author: kunlun-platform
  severity: {severity.value}
  description: {description}
  tags: graphql,{attack_type.lower()}
  metadata:
    max-request: 1

http:
  - raw:
      - |
        POST /graphql HTTP/1.1
        Host: {{Hostname}}
        Content-Type: application/json

        {{"query": {json.dumps(payload)}}}

    matchers-condition: and
    matchers:
      - type: word
        words:
          - "data"
        part: body

      - type: status
        status:
          - 200
'''

    def generate_report_section(
        self,
        section_type: str,
        data: Dict[str, Any],
    ) -> ReportSection:
        """Generate report section.

        Args:
            section_type: Section type.
            data: Section data.

        Returns:
            ReportSection.
        """
        section_id = f"section_{uuid.uuid4().hex[:8]}"

        title = self._get_section_title(section_type)
        content = self._generate_section_content(section_type, data)
        mitre_mapping = self._get_mitre_mapping(section_type, data)

        section = ReportSection(
            section_id=section_id,
            title=title,
            content=content,
            data=data,
            mitre_mapping=mitre_mapping,
        )

        self._report_sections.append(section)

        return section

    def _get_section_title(
        self,
        section_type: str,
    ) -> str:
        """Get section title.

        Args:
            section_type: Section type.

        Returns:
            Section title.
        """
        titles = {
            "schema_summary": "GraphQL Schema Analysis Summary",
            "sensitive_fields": "Sensitive Field Inventory",
            "authz_results": "Authorization Testing Results",
            "injection_results": "Injection Testing Results",
            "dos_results": "DoS Testing Results",
            "subscription_results": "Subscription Testing Results",
            "recommendations": "Remediation Recommendations",
        }

        return titles.get(section_type, section_type.title())

    def _generate_section_content(
        self,
        section_type: str,
        data: Dict[str, Any],
    ) -> str:
        """Generate section content.

        Args:
            section_type: Section type.
            data: Section data.

        Returns:
            Section content.
        """
        if section_type == "schema_summary":
            return (
                f"Schema contains {data.get('type_count', 0)} types, "
                f"{data.get('field_count', 0)} fields, "
                f"{data.get('query_count', 0)} queries, "
                f"{data.get('mutation_count', 0)} mutations."
            )
        elif section_type == "sensitive_fields":
            sensitive_fields = data.get("sensitive_fields", [])
            return (
                f"Found {len(sensitive_fields)} sensitive fields: "
                f"{', '.join(sensitive_fields[:10])}"
            )
        elif section_type == "authz_results":
            vuln_count = data.get("vulnerable_count", 0)
            return (
                f"Authorization testing found {vuln_count} "
                f"privilege escalation vulnerabilities."
            )
        elif section_type == "injection_results":
            vuln_count = data.get("vulnerable_count", 0)
            return (
                f"Injection testing found {vuln_count} "
                f"injection vulnerabilities."
            )
        elif section_type == "dos_results":
            risk_level = data.get("risk_level", "unknown")
            return f"DoS testing assessed risk level as {risk_level}."
        elif section_type == "subscription_results":
            vuln_count = data.get("vulnerable_count", 0)
            return (
                f"Subscription testing found {vuln_count} "
                f"subscription-related vulnerabilities."
            )
        elif section_type == "recommendations":
            recommendations = data.get("recommendations", [])
            return (
                "Recommendations:\n" +
                "\n".join(f"- {r}" for r in recommendations)
            )

        return ""

    def _get_mitre_mapping(
        self,
        section_type: str,
        data: Dict[str, Any],
    ) -> Dict[str, str]:
        """Get MITRE ATT&CK mapping for section.

        Args:
            section_type: Section type.
            data: Section data.

        Returns:
            MITRE ATT&CK mapping dictionary.
        """
        mapping: Dict[str, str] = {}

        if section_type in ("schema_summary", "sensitive_fields"):
            mapping["Discovery"] = "T1580"
            mapping["File and Directory Discovery"] = "T1083"
        elif section_type == "authz_results":
            mapping["Valid Accounts"] = "T1078"
            mapping["Privilege Escalation"] = "T1078"
        elif section_type == "injection_results":
            mapping["Exploit Public-Facing Application"] = "T1190"
        elif section_type == "dos_results":
            mapping["Network Denial of Service"] = "T1498"
        elif section_type == "subscription_results":
            mapping["Exploit Public-Facing Application"] = "T1190"

        return mapping

    async def run_full_integration(
        self,
        target_url: str,
        scan_results: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Run full platform integration.

        Args:
            target_url: Target URL.
            scan_results: Scan results to integrate.

        Returns:
            Integration result dictionary.
        """
        await self._report_log(f"开始平台集成: {target_url}")

        asset = self.register_graphql_asset(target_url)

        findings: List[PassiveFinding] = []
        poc_scripts: List[PoCScript] = []
        report_sections: List[ReportSection] = []

        if "passive_findings" in scan_results:
            for finding_data in scan_results["passive_findings"]:
                finding = PassiveFinding(**finding_data)
                findings.append(finding)

        if "vulnerabilities" in scan_results:
            for vuln in scan_results["vulnerabilities"]:
                poc = self.generate_poc_script(
                    attack_type=vuln.get("type", "unknown"),
                    target_url=target_url,
                    severity=SeverityLevel(vuln.get("severity", "medium")),
                    description=vuln.get("description", ""),
                    payload=vuln.get("payload", ""),
                    mitre_attack_id=vuln.get("mitre_attack_id"),
                )
                poc_scripts.append(poc)

        for section_type in [
            "schema_summary", "sensitive_fields", "authz_results",
            "injection_results", "dos_results", "subscription_results",
            "recommendations",
        ]:
            if section_type in scan_results:
                section = self.generate_report_section(
                    section_type, scan_results[section_type]
                )
                report_sections.append(section)

        await self._report_log(
            f"平台集成完成: {len(findings)} 被动发现, "
            f"{len(poc_scripts)} PoC脚本, "
            f"{len(report_sections)} 报告章节"
        )

        return {
            "asset": asset,
            "passive_findings": findings,
            "poc_scripts": poc_scripts,
            "report_sections": report_sections,
        }

    def get_passive_findings(
        self,
        severity_filter: Optional[SeverityLevel] = None,
        limit: int = 100,
    ) -> List[PassiveFinding]:
        """Get passive findings.

        Args:
            severity_filter: Filter by severity.
            limit: Maximum findings.

        Returns:
            List of PassiveFinding.
        """
        findings = self._passive_findings

        if severity_filter:
            findings = [f for f in findings if f.severity == severity_filter]

        return findings[-limit:]

    def get_poc_scripts(
        self,
        attack_type_filter: Optional[str] = None,
    ) -> List[PoCScript]:
        """Get PoC scripts.

        Args:
            attack_type_filter: Filter by attack type.

        Returns:
            List of PoCScript.
        """
        scripts = self._poc_scripts

        if attack_type_filter:
            scripts = [s for s in scripts if s.attack_type == attack_type_filter]

        return scripts

    def get_report_sections(
        self,
    ) -> List[ReportSection]:
        """Get report sections.

        Returns:
            List of ReportSection.
        """
        return self._report_sections

    def get_asset_records(
        self,
    ) -> List[AssetRecord]:
        """Get asset records.

        Returns:
            List of AssetRecord.
        """
        return self._asset_records

    def get_stats(self) -> Dict[str, Any]:
        """Get integration statistics.

        Returns:
            Statistics dictionary.
        """
        return {
            "passive_findings": len(self._passive_findings),
            "critical_findings": sum(
                1 for f in self._passive_findings
                if f.severity == SeverityLevel.CRITICAL
            ),
            "high_findings": sum(
                1 for f in self._passive_findings
                if f.severity == SeverityLevel.HIGH
            ),
            "poc_scripts": len(self._poc_scripts),
            "report_sections": len(self._report_sections),
            "assets_registered": len(self._asset_records),
        }
