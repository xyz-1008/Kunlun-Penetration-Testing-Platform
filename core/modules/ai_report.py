"""AI Report: Natural language report generation, attack chain analysis, and MITRE ATT&CK automatic mapping.

Provides:
- Natural language report generation: One-command report creation from project data
- Multi-style reports: Executive summary, technical findings, risk assessment, remediation recommendations
- Attack chain automatic梳理: AI analyzes operation logs to build complete attack chain timeline
- MITRE ATT&CK automatic mapping: Each step mapped to corresponding technique IDs
- Attack chain visualization: Mermaid flowchart generation with success/failure status
- Critical node highlighting with technical details
"""

import asyncio
import json
import logging
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum, auto
from typing import Any, Callable, Coroutine, Dict, List, Optional, Set, Tuple

from .ai_engine import AIEngine, AIResponse, ChatMessage, ModelCapability, PromptTemplate

logger = logging.getLogger(__name__)


class ReportStyle(Enum):
    """Report style options."""
    EXECUTIVE = "executive"
    TECHNICAL = "technical"
    MANAGEMENT = "management"
    DETAILED = "detailed"
    CONCISE = "concise"


class ReportLanguage(Enum):
    """Report language options."""
    ENGLISH = "en"
    CHINESE = "zh"


class AttackChainStatus(Enum):
    """Attack chain step status."""
    SUCCESS = "success"
    FAILED = "failed"
    PARTIAL = "partial"
    PENDING = "pending"


@dataclass
class MITREAttackTechnique:
    """MITRE ATT&CK technique mapping.

    Attributes:
        technique_id: MITRE technique ID (e.g., T1190)
        technique_name: Technique name
        tactic: ATT&CK tactic
        sub_technique: Sub-technique ID if applicable
        description: Technique description
        url: MITRE reference URL
    """
    technique_id: str = ""
    technique_name: str = ""
    tactic: str = ""
    sub_technique: str = ""
    description: str = ""
    url: str = ""


@dataclass
class AttackChainStep:
    """Single step in attack chain.

    Attributes:
        step_number: Step number in chain
        timestamp: Step timestamp
        action: Action performed
        target: Target of action
        result: Result of action
        status: Step status
        mitre_techniques: Associated MITRE ATT&CK techniques
        technical_details: Technical details of the step
        evidence: Evidence supporting the step
    """
    step_number: int = 0
    timestamp: float = 0.0
    action: str = ""
    target: str = ""
    result: str = ""
    status: AttackChainStatus = AttackChainStatus.PENDING
    mitre_techniques: List[MITREAttackTechnique] = field(default_factory=list)
    technical_details: str = ""
    evidence: List[str] = field(default_factory=list)


@dataclass
class AttackChain:
    """Complete attack chain.

    Attributes:
        chain_id: Chain identifier
        target: Target of attack chain
        steps: Chain steps
        start_time: Chain start time
        end_time: Chain end time
        success_rate: Overall success rate
        mermaid_diagram: Mermaid flowchart representation
        critical_nodes: Critical nodes in chain
    """
    chain_id: str = ""
    target: str = ""
    steps: List[AttackChainStep] = field(default_factory=list)
    start_time: float = 0.0
    end_time: float = 0.0
    success_rate: float = 0.0
    mermaid_diagram: str = ""
    critical_nodes: List[int] = field(default_factory=list)


@dataclass
class ReportSection:
    """Report section.

    Attributes:
        title: Section title
        content: Section content
        subsections: Nested subsections
        metadata: Section metadata
    """
    title: str = ""
    content: str = ""
    subsections: List["ReportSection"] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PenetrationTestReport:
    """Complete penetration test report.

    Attributes:
        report_id: Report identifier
        target: Target of penetration test
        scope: Test scope
        style: Report style
        language: Report language
        sections: Report sections
        executive_summary: Executive summary
        technical_findings: Technical findings
        risk_assessment: Risk assessment
        remediation_recommendations: Remediation recommendations
        attack_chain: Associated attack chain
        statistics: Report statistics
        created_at: Report creation time
        generated_by: AI model that generated the report
    """
    report_id: str = ""
    target: str = ""
    scope: str = ""
    style: ReportStyle = ReportStyle.DETAILED
    language: ReportLanguage = ReportLanguage.ENGLISH
    sections: List[ReportSection] = field(default_factory=list)
    executive_summary: str = ""
    technical_findings: List[Dict[str, Any]] = field(default_factory=list)
    risk_assessment: str = ""
    remediation_recommendations: List[str] = field(default_factory=list)
    attack_chain: Optional[AttackChain] = None
    statistics: Dict[str, Any] = field(default_factory=dict)
    created_at: float = 0.0
    generated_by: str = ""


class MITREATTCKMapper:
    """MITRE ATT&CK technique mapper.

    Maps penetration testing actions to MITRE ATT&CK framework techniques.
    """

    TECHNIQUE_DATABASE: Dict[str, MITREAttackTechnique] = {
        "T1190": MITREAttackTechnique(
            technique_id="T1190",
            technique_name="Exploit Public-Facing Application",
            tactic="Initial Access",
            description="Adversaries may attempt to exploit a weakness in an Internet-facing host or system to initially access a network.",
            url="https://attack.mitre.org/techniques/T1190/",
        ),
        "T1133": MITREAttackTechnique(
            technique_id="T1133",
            technique_name="External Remote Services",
            tactic="Initial Access",
            description="Adversaries may leverage external-facing remote services to initially access a network.",
            url="https://attack.mitre.org/techniques/T1133/",
        ),
        "T1566": MITREAttackTechnique(
            technique_id="T1566",
            technique_name="Phishing",
            tactic="Initial Access",
            description="Adversaries may send phishing messages to gain access to victim systems.",
            url="https://attack.mitre.org/techniques/T1566/",
        ),
        "T1078": MITREAttackTechnique(
            technique_id="T1078",
            technique_name="Valid Accounts",
            tactic="Persistence",
            description="Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion.",
            url="https://attack.mitre.org/techniques/T1078/",
        ),
        "T1068": MITREAttackTechnique(
            technique_id="T1068",
            technique_name="Exploitation for Privilege Escalation",
            tactic="Privilege Escalation",
            description="Adversaries may exploit software vulnerabilities in an attempt to collect elevate privileges.",
            url="https://attack.mitre.org/techniques/T1068/",
        ),
        "T1055": MITREAttackTechnique(
            technique_id="T1055",
            technique_name="Process Injection",
            tactic="Privilege Escalation",
            description="Adversaries may inject code into processes in order to evade process-based defenses as well as possibly elevate privileges.",
            url="https://attack.mitre.org/techniques/T1055/",
        ),
        "T1021": MITREAttackTechnique(
            technique_id="T1021",
            technique_name="Remote Services",
            tactic="Lateral Movement",
            description="Adversaries may use legitimate credentials to log into remote services.",
            url="https://attack.mitre.org/techniques/T1021/",
        ),
        "T1021.002": MITREAttackTechnique(
            technique_id="T1021.002",
            technique_name="SMB/Windows Admin Shares",
            tactic="Lateral Movement",
            description="Adversaries may use Valid Accounts to interact with a remote network share using Server Message Block (SMB).",
            url="https://attack.mitre.org/techniques/T1021/002/",
        ),
        "T1047": MITREAttackTechnique(
            technique_id="T1047",
            technique_name="Windows Management Instrumentation",
            tactic="Execution",
            description="Adversaries may use Windows Management Instrumentation (WMI) to execute malicious commands.",
            url="https://attack.mitre.org/techniques/T1047/",
        ),
        "T1059": MITREAttackTechnique(
            technique_id="T1059",
            technique_name="Command and Scripting Interpreter",
            tactic="Execution",
            description="Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries.",
            url="https://attack.mitre.org/techniques/T1059/",
        ),
        "T1005": MITREAttackTechnique(
            technique_id="T1005",
            technique_name="Data from Local System",
            tactic="Collection",
            description="Adversaries may search local system sources, such as file systems and configuration files, to find files of interest.",
            url="https://attack.mitre.org/techniques/T1005/",
        ),
        "T1041": MITREAttackTechnique(
            technique_id="T1041",
            technique_name="Exfiltration Over C2 Channel",
            tactic="Exfiltration",
            description="Adversaries may steal data by exfiltrating it over an existing command and control channel.",
            url="https://attack.mitre.org/techniques/T1041/",
        ),
        "T1562": MITREAttackTechnique(
            technique_id="T1562",
            technique_name="Impair Defenses",
            tactic="Defense Evasion",
            description="Adversaries may maliciously modify components of a victim environment to evade or disable defenses.",
            url="https://attack.mitre.org/techniques/T1562/",
        ),
        "T1070": MITREAttackTechnique(
            technique_id="T1070",
            technique_name="Indicator Removal",
            tactic="Defense Evasion",
            description="Adversaries may remove indicators/logs from a system to hide evidence of malicious activity.",
            url="https://attack.mitre.org/techniques/T1070/",
        ),
        "T1110": MITREAttackTechnique(
            technique_id="T1110",
            technique_name="Brute Force",
            tactic="Credential Access",
            description="Adversaries may use brute force techniques to gain access to accounts when passwords are unknown or when password hashes are obtained.",
            url="https://attack.mitre.org/techniques/T1110/",
        ),
        "T1190": MITREAttackTechnique(
            technique_id="T1190",
            technique_name="SQL Injection",
            tactic="Initial Access",
            description="Adversaries may exploit SQL injection vulnerabilities to gain access to backend databases.",
            url="https://attack.mitre.org/techniques/T1190/",
        ),
    }

    ACTION_TO_TECHNIQUE: Dict[str, List[str]] = {
        "sql injection": ["T1190"],
        "xss": ["T1190"],
        "rce": ["T1190", "T1059"],
        "remote code execution": ["T1190", "T1059"],
        "file upload": ["T1190"],
        "ssrf": ["T1190"],
        "idor": ["T1078"],
        "privilege escalation": ["T1068", "T1055"],
        "lateral movement": ["T1021", "T1021.002"],
        "password": ["T1110"],
        "brute force": ["T1110"],
        "credential": ["T1078", "T1110"],
        "wmi": ["T1047"],
        "process injection": ["T1055"],
        "disable antivirus": ["T1562"],
        "clear logs": ["T1070"],
        "data exfiltration": ["T1041"],
        "data collection": ["T1005"],
    }

    @classmethod
    def map_action_to_techniques(cls, action: str) -> List[MITREAttackTechnique]:
        """Map action string to MITRE ATT&CK techniques.

        Args:
            action: Action description string.

        Returns:
            List of matching MITREAttackTechnique objects.
        """
        action_lower = action.lower()
        technique_ids: Set[str] = set()

        for keyword, tech_ids in cls.ACTION_TO_TECHNIQUE.items():
            if keyword in action_lower:
                technique_ids.update(tech_ids)

        return [
            cls.TECHNIQUE_DATABASE[tid]
            for tid in technique_ids
            if tid in cls.TECHNIQUE_DATABASE
        ]

    @classmethod
    def get_technique_by_id(cls, technique_id: str) -> Optional[MITREAttackTechnique]:
        """Get technique by MITRE ID.

        Args:
            technique_id: MITRE technique ID.

        Returns:
            MITREAttackTechnique or None if not found.
        """
        return cls.TECHNIQUE_DATABASE.get(technique_id)

    @classmethod
    def get_all_tactics(cls) -> List[str]:
        """Get all unique ATT&CK tactics.

        Returns:
            List of unique tactic names.
        """
        return list(set(tech.tactic for tech in cls.TECHNIQUE_DATABASE.values()))


class AIReportGenerator:
    """AI-powered penetration test report generator.

    Generates comprehensive reports from project data using AI models.
    Supports multiple styles, languages, and automatic attack chain analysis.

    Attributes:
        ai_engine: AI engine instance
        project_id: Current project identifier
        mitre_mapper: MITRE ATT&CK mapper instance
        _report_callback: Optional report generation progress callback
    """

    def __init__(
        self,
        ai_engine: AIEngine,
        project_id: str = "",
        report_callback: Optional[Callable[[str, float], Coroutine[Any, Any, None]]] = None,
    ) -> None:
        """Initialize AI report generator.

        Args:
            ai_engine: AI engine instance.
            project_id: Current project identifier.
            report_callback: Optional async callback for report progress.
        """
        self.ai_engine = ai_engine
        self.project_id = project_id
        self.mitre_mapper = MITREATTCKMapper()
        self._report_callback = report_callback

    async def _report_progress(self, message: str, percentage: float) -> None:
        """Report report generation progress.

        Args:
            message: Progress message.
            percentage: Progress percentage (0-100).
        """
        if self._report_callback:
            await self._report_callback(message, percentage)

    async def generate_report(
        self,
        target: str,
        scope: str,
        findings: List[Dict[str, Any]],
        attack_chain_data: Optional[List[Dict[str, Any]]] = None,
        style: ReportStyle = ReportStyle.DETAILED,
        language: ReportLanguage = ReportLanguage.ENGLISH,
        audience: str = "technical",
    ) -> PenetrationTestReport:
        """Generate comprehensive penetration test report.

        Args:
            target: Target of penetration test.
            scope: Test scope description.
            findings: List of vulnerability findings.
            attack_chain_data: Optional attack chain data.
            style: Report style.
            language: Report language.
            audience: Target audience.

        Returns:
            Complete PenetrationTestReport.
        """
        await self._report_progress("Starting report generation...", 5.0)

        template = self.ai_engine.get_prompt_template("report_generation")
        if not template:
            raise ValueError("Report generation template not found")

        findings_str = json.dumps(findings, indent=2, ensure_ascii=False)
        attack_chain_str = json.dumps(attack_chain_data, indent=2, ensure_ascii=False) if attack_chain_data else "N/A"

        system_prompt, user_prompt = template.render(
            target=target,
            scope=scope,
            findings=findings_str,
            attack_chain=attack_chain_str,
            report_style=style.value,
            audience=audience,
        )

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ]

        await self._report_progress("Generating report content...", 30.0)

        response = await self.ai_engine.chat_completion(
            messages=messages,
            project_id=self.project_id,
        )

        await self._report_progress("Parsing report sections...", 60.0)

        report = self._parse_report_response(
            response.content,
            target=target,
            scope=scope,
            findings=findings,
            style=style,
            language=language,
        )
        report.generated_by = response.model
        report.created_at = time.time()

        if attack_chain_data:
            await self._report_progress("Analyzing attack chain...", 75.0)
            report.attack_chain = await self.analyze_attack_chain(attack_chain_data)

        await self._report_progress("Report generation completed", 100.0)

        return report

    async def analyze_attack_chain(
        self,
        attack_steps: List[Dict[str, Any]],
        timeline: Optional[List[Dict[str, Any]]] = None,
    ) -> AttackChain:
        """Analyze and document complete attack chain with MITRE ATT&CK mapping.

        Args:
            attack_steps: List of attack step dictionaries.
            timeline: Optional timeline data.

        Returns:
            Complete AttackChain with MITRE mapping.
        """
        await self._report_progress("Starting attack chain analysis...", 10.0)

        chain = AttackChain(
            chain_id=f"chain_{int(time.time())}",
            target=attack_steps[0].get("target", "") if attack_steps else "",
            start_time=attack_steps[0].get("timestamp", time.time()) if attack_steps else time.time(),
            end_time=attack_steps[-1].get("timestamp", time.time()) if attack_steps else time.time(),
        )

        for i, step_data in enumerate(attack_steps):
            step = AttackChainStep(
                step_number=i + 1,
                timestamp=step_data.get("timestamp", time.time()),
                action=step_data.get("action", ""),
                target=step_data.get("target", ""),
                result=step_data.get("result", ""),
                status=AttackChainStatus(step_data.get("status", "pending")),
                technical_details=step_data.get("details", ""),
                evidence=step_data.get("evidence", []),
            )

            step.mitre_techniques = self.mitre_mapper.map_action_to_techniques(step.action)

            chain.steps.append(step)

        successful_steps = sum(1 for s in chain.steps if s.status == AttackChainStatus.SUCCESS)
        chain.success_rate = successful_steps / len(chain.steps) if chain.steps else 0.0

        chain.critical_nodes = [
            s.step_number for s in chain.steps
            if s.status == AttackChainStatus.SUCCESS and len(s.mitre_techniques) > 0
        ]

        await self._report_progress("Generating Mermaid diagram...", 60.0)

        chain.mermaid_diagram = self._generate_mermaid_diagram(chain)

        await self._report_progress("Attack chain analysis completed", 100.0)

        return chain

    async def generate_attack_chain_from_natural_language(
        self,
        target: str,
        operation_log: str,
    ) -> AttackChain:
        """Generate attack chain from natural language operation log.

        Args:
            target: Target identifier.
            operation_log: Operation log string.

        Returns:
            Generated AttackChain.
        """
        await self._report_progress("Analyzing operation log...", 20.0)

        template = self.ai_engine.get_prompt_template("attack_chain_analysis")
        if not template:
            raise ValueError("Attack chain analysis template not found")

        system_prompt, user_prompt = template.render(
            target=target,
            attack_steps=operation_log,
            timeline="",
        )

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ]

        response = await self.ai_engine.chat_completion(
            messages=messages,
            project_id=self.project_id,
        )

        steps = self._parse_attack_chain_steps(response.content)

        chain = await self.analyze_attack_chain(steps)
        chain.target = target

        return chain

    def _parse_report_response(
        self,
        ai_response: str,
        target: str,
        scope: str,
        findings: List[Dict[str, Any]],
        style: ReportStyle,
        language: ReportLanguage,
    ) -> PenetrationTestReport:
        """Parse AI report generation response.

        Args:
            ai_response: AI response text.
            target: Target identifier.
            scope: Test scope.
            findings: Vulnerability findings.
            style: Report style.
            language: Report language.

        Returns:
            Parsed PenetrationTestReport.
        """
        report = PenetrationTestReport(
            report_id=f"report_{int(time.time())}",
            target=target,
            scope=scope,
            style=style,
            language=language,
            created_at=time.time(),
        )

        sections = re.split(r"#{1,3}\s+", ai_response)

        for section_text in sections:
            section_text = section_text.strip()
            if not section_text:
                continue

            lines = section_text.split("\n")
            title = lines[0].strip() if lines else "Untitled"
            content = "\n".join(lines[1:]).strip()

            section = ReportSection(title=title, content=content)
            report.sections.append(section)

            if "executive" in title.lower() or "summary" in title.lower():
                report.executive_summary = content
            elif "finding" in title.lower() or "technical" in title.lower():
                report.technical_findings.append({"title": title, "content": content})
            elif "risk" in title.lower():
                report.risk_assessment = content
            elif "remediation" in title.lower() or "recommendation" in title.lower():
                for line in content.split("\n"):
                    line = line.strip()
                    if line.startswith("-") or line.startswith("*") or line.startswith("1."):
                        report.remediation_recommendations.append(line.lstrip("-*1234567890. "))

        report.statistics = {
            "total_findings": len(findings),
            "high_severity": sum(1 for f in findings if f.get("severity") == "high"),
            "medium_severity": sum(1 for f in findings if f.get("severity") == "medium"),
            "low_severity": sum(1 for f in findings if f.get("severity") == "low"),
        }

        return report

    def _parse_attack_chain_steps(self, ai_response: str) -> List[Dict[str, Any]]:
        """Parse AI attack chain analysis response.

        Args:
            ai_response: AI response text.

        Returns:
            List of attack step dictionaries.
        """
        steps: List[Dict[str, Any]] = []

        lines = ai_response.split("\n")
        current_step: Dict[str, Any] = {}

        for line in lines:
            line = line.strip()
            if not line:
                if current_step:
                    steps.append(current_step)
                    current_step = {}
                continue

            if line.startswith("step") or line.startswith("- step"):
                if current_step:
                    steps.append(current_step)
                current_step = {"action": line, "timestamp": time.time()}
            elif line.startswith("-") or line.startswith("*"):
                content = line[1:].strip()
                if "target" in content.lower():
                    current_step["target"] = content
                elif "result" in content.lower():
                    current_step["result"] = content
                elif "status" in content.lower():
                    current_step["status"] = content.lower().replace("status:", "").strip()

        if current_step:
            steps.append(current_step)

        return steps

    def _generate_mermaid_diagram(self, chain: AttackChain) -> str:
        """Generate Mermaid flowchart for attack chain.

        Args:
            chain: AttackChain to visualize.

        Returns:
            Mermaid diagram string.
        """
        lines = ["graph TD"]

        for step in chain.steps:
            node_id = f"step{step.step_number}"

            status_color = {
                AttackChainStatus.SUCCESS: "#90EE90",
                AttackChainStatus.FAILED: "#FFB6C1",
                AttackChainStatus.PARTIAL: "#FFD700",
                AttackChainStatus.PENDING: "#D3D3D3",
            }

            color = status_color.get(step.status, "#D3D3D3")

            action_short = step.action[:50] + "..." if len(step.action) > 50 else step.action

            lines.append(f'    {node_id}["{action_short}"]')
            lines.append(f'    style {node_id} fill:{color}')

            if step.step_number > 1:
                prev_id = f"step{step.step_number - 1}"
                lines.append(f"    {prev_id} --> {node_id}")

        if chain.critical_nodes:
            lines.append("")
            lines.append("    classDef critical fill:#FF6347,stroke:#333,stroke-width:2px")
            for node_num in chain.critical_nodes:
                lines.append(f"    class step{node_num} critical")

        return "\n".join(lines)

    def export_report_to_markdown(self, report: PenetrationTestReport) -> str:
        """Export report to Markdown format.

        Args:
            report: PenetrationTestReport to export.

        Returns:
            Markdown string representation.
        """
        lines = [
            f"# Penetration Test Report: {report.target}",
            "",
            f"**Report ID:** {report.report_id}",
            f"**Generated:** {datetime.fromtimestamp(report.created_at, tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
            f"**Style:** {report.style.value}",
            f"**Language:** {report.language.value}",
            f"**Generated by:** {report.generated_by}",
            "",
            "## Executive Summary",
            "",
            report.executive_summary,
            "",
            "## Technical Findings",
            "",
        ]

        for finding in report.technical_findings:
            lines.append(f"### {finding.get('title', 'Finding')}")
            lines.append("")
            lines.append(finding.get("content", ""))
            lines.append("")

        lines.extend([
            "## Risk Assessment",
            "",
            report.risk_assessment,
            "",
            "## Remediation Recommendations",
            "",
        ])

        for rec in report.remediation_recommendations:
            lines.append(f"- {rec}")

        lines.extend([
            "",
            "## Statistics",
            "",
            f"- Total Findings: {report.statistics.get('total_findings', 0)}",
            f"- High Severity: {report.statistics.get('high_severity', 0)}",
            f"- Medium Severity: {report.statistics.get('medium_severity', 0)}",
            f"- Low Severity: {report.statistics.get('low_severity', 0)}",
        ])

        if report.attack_chain:
            lines.extend([
                "",
                "## Attack Chain",
                "",
                f"**Success Rate:** {report.attack_chain.success_rate:.1%}",
                "",
                "```mermaid",
                report.attack_chain.mermaid_diagram,
                "```",
                "",
            ])

        return "\n".join(lines)

    def export_report_to_html(self, report: PenetrationTestReport) -> str:
        """Export report to HTML format.

        Args:
            report: PenetrationTestReport to export.

        Returns:
            HTML string representation.
        """
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Penetration Test Report: {report.target}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; line-height: 1.6; }}
        h1 {{ color: #333; border-bottom: 2px solid #333; padding-bottom: 10px; }}
        h2 {{ color: #555; margin-top: 30px; }}
        .meta {{ color: #777; font-size: 0.9em; }}
        .finding {{ background: #f9f9f9; padding: 15px; margin: 10px 0; border-left: 4px solid #007bff; }}
        .critical {{ border-left-color: #dc3545; }}
        .high {{ border-left-color: #fd7e14; }}
        .medium {{ border-left-color: #ffc107; }}
        .low {{ border-left-color: #28a745; }}
        .stats {{ display: flex; gap: 20px; margin: 20px 0; }}
        .stat {{ background: #f0f0f0; padding: 15px; border-radius: 5px; text-align: center; }}
        .stat-number {{ font-size: 2em; font-weight: bold; }}
        pre {{ background: #f5f5f5; padding: 15px; overflow-x: auto; }}
    </style>
</head>
<body>
    <h1>Penetration Test Report: {report.target}</h1>
    <div class="meta">
        <p><strong>Report ID:</strong> {report.report_id}</p>
        <p><strong>Generated:</strong> {datetime.fromtimestamp(report.created_at, tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
        <p><strong>Style:</strong> {report.style.value}</p>
        <p><strong>Generated by:</strong> {report.generated_by}</p>
    </div>

    <h2>Executive Summary</h2>
    <p>{report.executive_summary}</p>

    <h2>Technical Findings</h2>
"""

        for finding in report.technical_findings:
            severity = finding.get("severity", "medium")
            html += f'<div class="finding {severity}">\n'
            html += f'<h3>{finding.get("title", "Finding")}</h3>\n'
            html += f"<p>{finding.get('content', '')}</p>\n"
            html += "</div>\n"

        html += """
    <h2>Risk Assessment</h2>
    <p>{risk}</p>

    <h2>Remediation Recommendations</h2>
    <ul>
""".format(risk=report.risk_assessment)

        for rec in report.remediation_recommendations:
            html += f"        <li>{rec}</li>\n"

        html += f"""
    </ul>

    <h2>Statistics</h2>
    <div class="stats">
        <div class="stat">
            <div class="stat-number">{report.statistics.get('total_findings', 0)}</div>
            <div>Total Findings</div>
        </div>
        <div class="stat">
            <div class="stat-number" style="color: #dc3545;">{report.statistics.get('high_severity', 0)}</div>
            <div>High Severity</div>
        </div>
        <div class="stat">
            <div class="stat-number" style="color: #ffc107;">{report.statistics.get('medium_severity', 0)}</div>
            <div>Medium Severity</div>
        </div>
        <div class="stat">
            <div class="stat-number" style="color: #28a745;">{report.statistics.get('low_severity', 0)}</div>
            <div>Low Severity</div>
        </div>
    </div>
"""

        if report.attack_chain:
            html += f"""
    <h2>Attack Chain</h2>
    <p><strong>Success Rate:</strong> {report.attack_chain.success_rate:.1%}</p>
    <pre class="mermaid">
{report.attack_chain.mermaid_diagram}
    </pre>
"""

        html += """
</body>
</html>"""

        return html
