"""Deserialization exploitation reporting module.

Provides:
- Evidence chain recording
- Reproduction script generation (Python format)
- Attack chain visualization with timeline
- Remediation recommendations with MITRE ATT&CK mapping
"""

import asyncio
import json
import logging
import secrets
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Coroutine, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class ReportType(Enum):
    """Report types."""
    EVIDENCE_CHAIN = "evidence_chain"
    REPRODUCTION_SCRIPT = "reproduction_script"
    ATTACK_TIMELINE = "attack_timeline"
    REMEDIATION = "remediation"
    FULL_REPORT = "full_report"


class Severity(Enum):
    """Vulnerability severity."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class EvidenceItem:
    """Evidence chain item.

    Attributes:
        evidence_id: Unique evidence identifier
        timestamp: Evidence timestamp
        stage: Exploitation stage
        request_data: Request data
        response_data: Response data
        payload: Exploitation payload
        payload_base64: Base64 encoded payload
        success: Whether stage succeeded
        notes: Evidence notes
    """
    evidence_id: str = ""
    timestamp: float = 0.0
    stage: str = ""
    request_data: Dict[str, Any] = field(default_factory=dict)
    response_data: Dict[str, Any] = field(default_factory=dict)
    payload: str = ""
    payload_base64: str = ""
    success: bool = False
    notes: str = ""


@dataclass
class RemediationItem:
    """Remediation recommendation.

    Attributes:
        recommendation_id: Unique recommendation identifier
        gadget_chain: Affected gadget chain
        severity: Vulnerability severity
        description: Vulnerability description
        upgrade_advice: Upgrade recommendations
        config_changes: Configuration modifications
        waf_rules: WAF rules
        monitoring_rules: Monitoring rules
        mitre_technique: MITRE ATT&CK technique ID
        references: Reference links
    """
    recommendation_id: str = ""
    gadget_chain: str = ""
    severity: Severity = Severity.HIGH
    description: str = ""
    upgrade_advice: str = ""
    config_changes: List[str] = field(default_factory=list)
    waf_rules: List[str] = field(default_factory=list)
    monitoring_rules: List[str] = field(default_factory=list)
    mitre_technique: str = ""
    references: List[str] = field(default_factory=list)


@dataclass
class DeserReport:
    """Deserialization exploitation report.

    Attributes:
        report_id: Unique report identifier
        report_type: Report type
        target: Target information
        evidence_chain: Evidence chain items
        remediation_items: Remediation recommendations
        reproduction_script: Generated reproduction script
        attack_timeline: Attack timeline data
        severity: Overall severity
        summary: Report summary
        created_at: Report creation timestamp
        metadata: Additional metadata
    """
    report_id: str = ""
    report_type: ReportType = ReportType.FULL_REPORT
    target: Dict[str, Any] = field(default_factory=dict)
    evidence_chain: List[EvidenceItem] = field(default_factory=list)
    remediation_items: List[RemediationItem] = field(default_factory=list)
    reproduction_script: str = ""
    attack_timeline: List[Dict[str, Any]] = field(default_factory=list)
    severity: Severity = Severity.HIGH
    summary: str = ""
    created_at: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "report_id": self.report_id,
            "report_type": self.report_type.value,
            "target": self.target,
            "evidence_count": len(self.evidence_chain),
            "remediation_count": len(self.remediation_items),
            "severity": self.severity.value,
            "summary": self.summary,
            "created_at": self.created_at,
            "metadata": self.metadata,
        }


class DeserReportGenerator:
    """Deserialization exploitation report generator.

    Provides evidence chain recording, reproduction script generation,
    attack timeline visualization, and remediation recommendations.
    """

    REMEDIATION_DB: Dict[str, RemediationItem] = {
        "commons_collections1": RemediationItem(
            recommendation_id="rem_cc1",
            gadget_chain="CommonsCollections1",
            severity=Severity.CRITICAL,
            description="Apache Commons Collections反序列化漏洞，攻击者可构造恶意序列化数据执行任意代码。",
            upgrade_advice="升级commons-collections到4.x版本，或使用commons-collections 3.2.2+（已修复部分链）。",
            config_changes=[
                "禁用ObjectInputStream的反序列化功能",
                "使用白名单机制限制可反序列化的类",
                "启用Java序列化过滤（JEP 290）",
            ],
            waf_rules=[
                "检测HTTP请求中的\\xac\\xed\\x00\\x05魔数",
                "拦截包含InvokerTransformer、LazyMap等关键字的请求",
                "限制Content-Type为application/x-java-serialized-object的请求",
            ],
            monitoring_rules=[
                "监控JVM进程异常子进程创建",
                "监控Runtime.exec()调用",
                "监控异常类加载行为",
            ],
            mitre_technique="T1566.001",
            references=[
                "https://frohoff.github.io/appseccali-il-2015-marshalling-pickles/",
                "https://github.com/frohoff/ysoserial",
            ],
        ),
        "commons_collections5": RemediationItem(
            recommendation_id="rem_cc5",
            gadget_chain="CommonsCollections5",
            severity=Severity.CRITICAL,
            description="Apache Commons Collections 5反序列化漏洞，利用BadAttributeValueExpException触发命令执行。",
            upgrade_advice="升级commons-collections到4.x版本，或升级到3.2.2+。",
            config_changes=[
                "实施Java序列化白名单",
                "使用JEP 290序列化过滤",
                "禁用不必要的反序列化端点",
            ],
            waf_rules=[
                "检测BadAttributeValueExpException相关序列化数据",
                "拦截包含TiedMapEntry的请求",
            ],
            monitoring_rules=[
                "监控异常异常抛出行为",
                "监控toString()方法异常调用",
            ],
            mitre_technique="T1566.001",
            references=[
                "https://github.com/frohoff/ysoserial",
            ],
        ),
        "jdk7u21": RemediationItem(
            recommendation_id="rem_jdk7u21",
            gadget_chain="Jdk7u21",
            severity=Severity.HIGH,
            description="JDK 7u21反序列化漏洞，利用AnnotationInvocationHandler触发命令执行。",
            upgrade_advice="升级JDK到8u121+版本，或应用最新安全补丁。",
            config_changes=[
                "启用JEP 290序列化过滤",
                "限制可反序列化的类范围",
            ],
            waf_rules=[
                "检测AnnotationInvocationHandler相关序列化数据",
            ],
            monitoring_rules=[
                "监控Annotation相关异常行为",
            ],
            mitre_technique="T1566.001",
            references=[
                "https://github.com/frohoff/ysoserial",
            ],
        ),
        "shiro_rememberme": RemediationItem(
            recommendation_id="rem_shiro",
            gadget_chain="Shiro RememberMe",
            severity=Severity.CRITICAL,
            description="Apache Shiro RememberMe反序列化漏洞，使用固定密钥加密序列化数据。",
            upgrade_advice="升级Shiro到1.2.5+版本，或修改默认密钥。",
            config_changes=[
                "修改shiro.ini中的cipherKey配置",
                "使用强随机密钥替代默认密钥",
                "禁用RememberMe功能（如不需要）",
            ],
            waf_rules=[
                "检测rememberMe Cookie中的Base64编码序列化数据",
                "拦截包含\\xac\\xed\\x00\\x05的Cookie值",
            ],
            monitoring_rules=[
                "监控Shiro认证失败异常",
                "监控RememberMe Cookie解密失败",
            ],
            mitre_technique="T1566.001",
            references=[
                "https://github.com/apache/shiro",
            ],
        ),
        "weblogic_t3": RemediationItem(
            recommendation_id="rem_wl_t3",
            gadget_chain="WebLogic T3",
            severity=Severity.CRITICAL,
            description="Oracle WebLogic T3协议反序列化漏洞，攻击者可通过T3协议发送恶意序列化数据。",
            upgrade_advice="升级WebLogic到最新补丁版本，应用CPU补丁。",
            config_changes=[
                "禁用T3协议（如不需要）",
                "配置连接过滤器限制T3访问",
                "启用WebLogic安全日志",
            ],
            waf_rules=[
                "检测T3协议握手特征",
                "拦截异常T3协议数据包",
            ],
            monitoring_rules=[
                "监控T3协议连接异常",
                "监控WebLogic反序列化异常",
            ],
            mitre_technique="T1566.001",
            references=[
                "https://www.oracle.com/security-alerts/",
            ],
        ),
    }

    def __init__(
        self,
        event_bus: Optional[Any] = None,
    ) -> None:
        """Initialize deserialization report generator.

        Args:
            event_bus: Event bus for broadcasting events.
        """
        self.event_bus = event_bus
        self._progress_callback: Optional[Callable[[str, float], Coroutine[Any, Any, None]]] = None
        self._log_callback: Optional[Callable[[str], Coroutine[Any, Any, None]]] = None
        self._report_history: List[DeserReport] = []

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
        logger.info("Report Progress: %.1f%% - %s", percentage, message)

    async def _report_log(self, message: str) -> None:
        """Report log via callback.

        Args:
            message: Log message.
        """
        if self._log_callback:
            await self._log_callback(message)
        logger.info("Report: %s", message)

    async def generate_evidence_chain(
        self,
        exploit_results: List[Dict[str, Any]],
        target: Dict[str, Any],
    ) -> DeserReport:
        """Generate evidence chain report.

        Args:
            exploit_results: List of exploitation results.
            target: Target information.

        Returns:
            DeserReport with evidence chain.
        """
        report = DeserReport(
            report_id=f"evidence_{int(time.time())}_{secrets.token_hex(4)}",
            report_type=ReportType.EVIDENCE_CHAIN,
            target=target,
            created_at=time.time(),
        )

        try:
            await self._report_progress("生成证据链", 10)

            for i, result in enumerate(exploit_results):
                evidence = EvidenceItem(
                    evidence_id=f"evidence_{i}_{secrets.token_hex(4)}",
                    timestamp=result.get("timestamp", time.time()),
                    stage=result.get("stage", "unknown"),
                    request_data=result.get("request", {}),
                    response_data=result.get("response", {}),
                    payload=result.get("payload", ""),
                    payload_base64=result.get("payload_base64", ""),
                    success=result.get("success", False),
                    notes=result.get("notes", ""),
                )
                report.evidence_chain.append(evidence)

            report.summary = f"证据链生成完成，共{len(report.evidence_chain)}条证据"
            report.severity = self._calculate_severity(exploit_results)

            await self._report_progress("完成", 100)
            await self._report_log(report.summary)

            self._report_history.append(report)

        except Exception as e:
            await self._report_log(f"证据链生成失败: {e}")
            logger.error("Evidence chain generation failed: %s", e)

        return report

    async def generate_reproduction_script(
        self,
        exploit_results: List[Dict[str, Any]],
        target: Dict[str, Any],
    ) -> DeserReport:
        """Generate reproduction script.

        Args:
            exploit_results: List of exploitation results.
            target: Target information.

        Returns:
            DeserReport with reproduction script.
        """
        report = DeserReport(
            report_id=f"repro_{int(time.time())}_{secrets.token_hex(4)}",
            report_type=ReportType.REPRODUCTION_SCRIPT,
            target=target,
            created_at=time.time(),
        )

        try:
            await self._report_progress("生成复现脚本", 10)

            script = self._build_python_reproduction_script(
                exploit_results, target
            )
            report.reproduction_script = script

            report.summary = f"复现脚本生成完成，共{len(script)}行代码"
            report.severity = self._calculate_severity(exploit_results)

            await self._report_progress("完成", 100)
            await self._report_log(report.summary)

            self._report_history.append(report)

        except Exception as e:
            await self._report_log(f"复现脚本生成失败: {e}")
            logger.error("Reproduction script generation failed: %s", e)

        return report

    async def generate_attack_timeline(
        self,
        exploit_results: List[Dict[str, Any]],
        target: Dict[str, Any],
    ) -> DeserReport:
        """Generate attack timeline.

        Args:
            exploit_results: List of exploitation results.
            target: Target information.

        Returns:
            DeserReport with attack timeline.
        """
        report = DeserReport(
            report_id=f"timeline_{int(time.time())}_{secrets.token_hex(4)}",
            report_type=ReportType.ATTACK_TIMELINE,
            target=target,
            created_at=time.time(),
        )

        try:
            await self._report_progress("生成攻击时间线", 10)

            timeline: List[Dict[str, Any]] = []
            for i, result in enumerate(exploit_results):
                event = {
                    "id": f"event_{i}",
                    "timestamp": result.get("timestamp", time.time()),
                    "stage": result.get("stage", "unknown"),
                    "action": result.get("action", ""),
                    "success": result.get("success", False),
                    "details": result.get("details", ""),
                }
                timeline.append(event)

            report.attack_timeline = timeline
            report.summary = f"攻击时间线生成完成，共{len(timeline)}个事件"
            report.severity = self._calculate_severity(exploit_results)

            await self._report_progress("完成", 100)
            await self._report_log(report.summary)

            self._report_history.append(report)

        except Exception as e:
            await self._report_log(f"攻击时间线生成失败: {e}")
            logger.error("Attack timeline generation failed: %s", e)

        return report

    async def generate_remediation(
        self,
        gadget_chains: List[str],
        target: Dict[str, Any],
    ) -> DeserReport:
        """Generate remediation recommendations.

        Args:
            gadget_chains: List of affected gadget chains.
            target: Target information.

        Returns:
            DeserReport with remediation recommendations.
        """
        report = DeserReport(
            report_id=f"remediation_{int(time.time())}_{secrets.token_hex(4)}",
            report_type=ReportType.REMEDIATION,
            target=target,
            created_at=time.time(),
        )

        try:
            await self._report_progress("生成修复建议", 10)

            for chain in gadget_chains:
                chain_key = chain.lower().replace(" ", "_")
                remediation = self.REMEDIATION_DB.get(chain_key)
                if remediation:
                    report.remediation_items.append(remediation)
                else:
                    generic = self._generate_generic_remediation(chain)
                    report.remediation_items.append(generic)

            report.summary = f"修复建议生成完成，共{len(report.remediation_items)}条建议"
            report.severity = self._calculate_severity_from_chains(gadget_chains)

            await self._report_progress("完成", 100)
            await self._report_log(report.summary)

            self._report_history.append(report)

        except Exception as e:
            await self._report_log(f"修复建议生成失败: {e}")
            logger.error("Remediation generation failed: %s", e)

        return report

    async def generate_full_report(
        self,
        exploit_results: List[Dict[str, Any]],
        gadget_chains: List[str],
        target: Dict[str, Any],
    ) -> DeserReport:
        """Generate full exploitation report.

        Args:
            exploit_results: List of exploitation results.
            gadget_chains: List of affected gadget chains.
            target: Target information.

        Returns:
            DeserReport with full report.
        """
        report = DeserReport(
            report_id=f"full_{int(time.time())}_{secrets.token_hex(4)}",
            report_type=ReportType.FULL_REPORT,
            target=target,
            created_at=time.time(),
        )

        try:
            await self._report_progress("生成完整报告", 10)

            evidence_report = await self.generate_evidence_chain(
                exploit_results, target
            )
            report.evidence_chain = evidence_report.evidence_chain

            repro_report = await self.generate_reproduction_script(
                exploit_results, target
            )
            report.reproduction_script = repro_report.reproduction_script

            timeline_report = await self.generate_attack_timeline(
                exploit_results, target
            )
            report.attack_timeline = timeline_report.attack_timeline

            remediation_report = await self.generate_remediation(
                gadget_chains, target
            )
            report.remediation_items = remediation_report.remediation_items

            report.summary = (
                f"完整报告生成完成:\n"
                f"- 证据链: {len(report.evidence_chain)}条\n"
                f"- 复现脚本: {len(report.reproduction_script)}行\n"
                f"- 时间线: {len(report.attack_timeline)}个事件\n"
                f"- 修复建议: {len(report.remediation_items)}条"
            )
            report.severity = self._calculate_severity(exploit_results)

            await self._report_progress("完成", 100)
            await self._report_log(report.summary)

            self._report_history.append(report)

        except Exception as e:
            await self._report_log(f"完整报告生成失败: {e}")
            logger.error("Full report generation failed: %s", e)

        return report

    def _build_python_reproduction_script(
        self,
        exploit_results: List[Dict[str, Any]],
        target: Dict[str, Any],
    ) -> str:
        """Build Python reproduction script.

        Args:
            exploit_results: List of exploitation results.
            target: Target information.

        Returns:
            Python script string.
        """
        script_lines: List[str] = [
            "#!/usr/bin/env python3",
            "# -*- coding: utf-8 -*-",
            '"""Java Deserialization Vulnerability Reproduction Script"""',
            "",
            "import requests",
            "import base64",
            "import sys",
            "",
            f"TARGET_HOST = \"{target.get('host', 'localhost')}\"",
            f"TARGET_PORT = {target.get('port', 8080)}",
            f"TARGET_PATH = \"{target.get('path', '/')}\"",
            "",
            "def exploit():",
            '    """Execute deserialization exploit."""',
            f"    url = f\"http://{{TARGET_HOST}}:{{TARGET_PORT}}{{TARGET_PATH}}\"",
            "",
        ]

        for i, result in enumerate(exploit_results):
            payload = result.get("payload_base64", "")
            stage = result.get("stage", "unknown")

            script_lines.extend([
                f"    # Stage {i+1}: {stage}",
                f"    payload_{i} = base64.b64decode(\"{payload}\")",
                f"    response_{i} = requests.post(",
                f"        url,",
                f"        data=payload_{i},",
                f"        headers={{\"Content-Type\": \"application/x-java-serialized-object\"}},",
                f"        timeout=10",
                f"    )",
                f"    print(f\"Stage {i+1}: {{response_{i}.status_code}}\")",
                "",
            ])

        script_lines.extend([
            "if __name__ == \"__main__\":",
            "    exploit()",
            "",
        ])

        return "\n".join(script_lines)

    def _generate_generic_remediation(self, chain: str) -> RemediationItem:
        """Generate generic remediation recommendation.

        Args:
            chain: Gadget chain name.

        Returns:
            RemediationItem.
        """
        return RemediationItem(
            recommendation_id=f"rem_{chain.lower().replace(' ', '_')}",
            gadget_chain=chain,
            severity=Severity.HIGH,
            description=f"{chain}反序列化漏洞，攻击者可构造恶意序列化数据执行任意代码。",
            upgrade_advice="升级相关依赖到最新版本，应用最新安全补丁。",
            config_changes=[
                "实施Java序列化白名单",
                "启用JEP 290序列化过滤",
                "禁用不必要的反序列化端点",
            ],
            waf_rules=[
                "检测HTTP请求中的序列化魔数",
                "拦截异常序列化数据",
            ],
            monitoring_rules=[
                "监控JVM进程异常行为",
                "监控异常类加载",
            ],
            mitre_technique="T1566.001",
            references=[],
        )

    def _calculate_severity(
        self,
        exploit_results: List[Dict[str, Any]],
    ) -> Severity:
        """Calculate overall severity.

        Args:
            exploit_results: List of exploitation results.

        Returns:
            Severity.
        """
        success_count = sum(1 for r in exploit_results if r.get("success", False))
        total = len(exploit_results)

        if total == 0:
            return Severity.INFO
        elif success_count == total:
            return Severity.CRITICAL
        elif success_count > total / 2:
            return Severity.HIGH
        elif success_count > 0:
            return Severity.MEDIUM
        else:
            return Severity.LOW

    def _calculate_severity_from_chains(
        self,
        gadget_chains: List[str],
    ) -> Severity:
        """Calculate severity from gadget chains.

        Args:
            gadget_chains: List of gadget chains.

        Returns:
            Severity.
        """
        critical_chains = [
            "commons_collections",
            "shiro",
            "weblogic",
            "fastjson",
            "jackson",
        ]

        for chain in gadget_chains:
            chain_lower = chain.lower()
            if any(c in chain_lower for c in critical_chains):
                return Severity.CRITICAL

        return Severity.HIGH

    def export_report(
        self,
        report: DeserReport,
        format: str = "json",
    ) -> str:
        """Export report to specified format.

        Args:
            report: Report to export.
            format: Export format (json/markdown).

        Returns:
            Exported report string.
        """
        if format == "json":
            return json.dumps(report.to_dict(), indent=2, ensure_ascii=False)
        elif format == "markdown":
            return self._export_markdown(report)
        else:
            return json.dumps(report.to_dict(), indent=2, ensure_ascii=False)

    def _export_markdown(self, report: DeserReport) -> str:
        """Export report to markdown format.

        Args:
            report: Report to export.

        Returns:
            Markdown string.
        """
        lines: List[str] = [
            f"# Java反序列化漏洞利用报告",
            "",
            f"**报告ID**: {report.report_id}",
            f"**报告类型**: {report.report_type.value}",
            f"**严重程度**: {report.severity.value}",
            f"**生成时间**: {datetime.fromtimestamp(report.created_at).isoformat()}",
            "",
            "## 目标信息",
            "",
        ]

        for key, value in report.target.items():
            lines.append(f"- **{key}**: {value}")

        lines.extend([
            "",
            "## 证据链",
            "",
            f"共{len(report.evidence_chain)}条证据",
            "",
        ])

        for i, evidence in enumerate(report.evidence_chain):
            lines.extend([
                f"### 证据 {i+1}: {evidence.stage}",
                "",
                f"- **时间**: {datetime.fromtimestamp(evidence.timestamp).isoformat()}",
                f"- **成功**: {'是' if evidence.success else '否'}",
                f"- **备注**: {evidence.notes}",
                "",
            ])

        lines.extend([
            "## 修复建议",
            "",
            f"共{len(report.remediation_items)}条建议",
            "",
        ])

        for i, remediation in enumerate(report.remediation_items):
            lines.extend([
                f"### 建议 {i+1}: {remediation.gadget_chain}",
                "",
                f"- **严重程度**: {remediation.severity.value}",
                f"- **描述**: {remediation.description}",
                f"- **升级建议**: {remediation.upgrade_advice}",
                f"- **MITRE ATT&CK**: {remediation.mitre_technique}",
                "",
            ])

        lines.extend([
            "## 总结",
            "",
            report.summary,
            "",
        ])

        return "\n".join(lines)

    def get_report_history(self) -> List[DeserReport]:
        """Get report history.

        Returns:
            List of reports.
        """
        return self._report_history

    def get_report_by_id(self, report_id: str) -> Optional[DeserReport]:
        """Get report by ID.

        Args:
            report_id: Report identifier.

        Returns:
            DeserReport or None.
        """
        for report in self._report_history:
            if report.report_id == report_id:
                return report
        return None
