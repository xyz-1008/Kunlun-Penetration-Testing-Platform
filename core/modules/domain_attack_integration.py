"""Domain attack integration layer for Kunlun penetration testing platform.

Provides:
- Integration with credential database (auto-store results)
- Integration with event bus (broadcast attack events)
- Integration with report module (attack chain timeline)
- MITRE ATT&CK mapping
"""

import asyncio
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Coroutine, Dict, List, Optional, Tuple

from .adminsdholder import AdminSDHolderResult
from .cross_domain_trust import CrossDomainAttackResult, SIDHistoryInjectionResult
from .dcsync_attack import DCSyncResult
from .shadow_credentials import ShadowAttackResult
from .skeleton_key import SkeletonKeyResult

logger = logging.getLogger(__name__)


class AttackType(Enum):
    """Type of domain attack."""
    DCSYNC = "dcsync"
    SHADOW_CREDENTIALS = "shadow_credentials"
    SKELETON_KEY = "skeleton_key"
    ADMINSDHOLDER = "adminsdholder"
    CROSS_DOMAIN = "cross_domain"


@dataclass
class AttackTimelineEntry:
    """Entry in attack timeline.

    Attributes:
        timestamp: Attack timestamp
        attack_type: Type of attack
        success: Whether attack succeeded
        target: Target of attack
        details: Attack details
        attck_technique: Associated ATT&CK technique
        is_critical: Whether this is a critical node
        credential_count: Number of credentials obtained
    """
    timestamp: float = 0.0
    attack_type: AttackType = AttackType.DCSYNC
    success: bool = False
    target: str = ""
    details: str = ""
    attck_technique: str = ""
    is_critical: bool = False
    credential_count: int = 0


@dataclass
class IntegrationResult:
    """Result of integration operation.

    Attributes:
        success: Whether integration succeeded
        credentials_stored: Number of credentials stored
        events_broadcast: Number of events broadcast
        report_entries: Number of report entries created
        error_message: Error message if failed
    """
    success: bool = False
    credentials_stored: int = 0
    events_broadcast: int = 0
    report_entries: int = 0
    error_message: str = ""


ATTACK_ATTACK_MAPPING: Dict[AttackType, List[str]] = {
    AttackType.DCSYNC: ["T1003.006", "T1003"],
    AttackType.SHADOW_CREDENTIALS: ["T1649", "T1528"],
    AttackType.SKELETON_KEY: ["T1556", "T1055"],
    AttackType.ADMINSDHOLDER: ["T1484.001", "T1484"],
    AttackType.CROSS_DOMAIN: ["T1558", "T1558.001", "T1178"],
}


class DomainAttackIntegration:
    """Integration layer for domain attack modules.

    Provides integration with credential database, event bus,
    and report module for unified attack management.
    """

    def __init__(
        self,
        credential_db: Optional[Any] = None,
        event_bus: Optional[Any] = None,
        report_module: Optional[Any] = None,
    ) -> None:
        """Initialize domain attack integration.

        Args:
            credential_db: Credential database.
            event_bus: Event bus.
            report_module: Report module.
        """
        self.credential_db = credential_db
        self.event_bus = event_bus
        self.report_module = report_module
        self._timeline: List[AttackTimelineEntry] = []
        self._integration_log: List[str] = []

    async def integrate_dcsync_result(self, result: DCSyncResult) -> IntegrationResult:
        """Integrate DCSync attack result.

        Args:
            result: DCSync attack result.

        Returns:
            IntegrationResult.
        """
        integration = IntegrationResult()

        try:
            await self._log("开始集成DCSync攻击结果...")

            if result.success and self.credential_db:
                stored = await self._store_dcsync_credentials(result)
                integration.credentials_stored = stored

            if self.event_bus:
                events = await self._broadcast_dcsync_event(result)
                integration.events_broadcast = events

            if self.report_module:
                entries = await self._add_to_report_timeline(
                    AttackType.DCSYNC,
                    result.success,
                    result.target_dc or "all",
                    f"导出 {result.exported_count} 个用户凭据",
                    result.attck_technique,
                    result.success,
                    result.exported_count,
                )
                integration.report_entries = entries

            integration.success = True
            await self._log(f"DCSync集成完成: {integration.credentials_stored} 凭据, "
                          f"{integration.events_broadcast} 事件, "
                          f"{integration.report_entries} 报告条目")

        except Exception as e:
            integration.error_message = str(e)
            await self._log(f"DCSync集成失败: {e}")
            logger.error("DCSync integration failed: %s", e)

        return integration

    async def integrate_shadow_result(self, result: ShadowAttackResult) -> IntegrationResult:
        """Integrate Shadow Credentials attack result.

        Args:
            result: Shadow attack result.

        Returns:
            IntegrationResult.
        """
        integration = IntegrationResult()

        try:
            await self._log("开始集成Shadow Credentials攻击结果...")

            if result.success and result.tgt_ticket and self.credential_db:
                stored = await self._store_shadow_credential(result)
                integration.credentials_stored = stored

            if self.event_bus:
                events = await self._broadcast_shadow_event(result)
                integration.events_broadcast = events

            if self.report_module:
                entries = await self._add_to_report_timeline(
                    AttackType.SHADOW_CREDENTIALS,
                    result.success,
                    result.target.sam_account_name if result.target else "unknown",
                    f"获取TGT: {result.tgt_ticket[:50] if result.tgt_ticket else 'N/A'}",
                    result.attck_technique,
                    result.success,
                    1 if result.tgt_ticket else 0,
                )
                integration.report_entries = entries

            integration.success = True
            await self._log(f"Shadow Credentials集成完成")

        except Exception as e:
            integration.error_message = str(e)
            await self._log(f"Shadow Credentials集成失败: {e}")
            logger.error("Shadow integration failed: %s", e)

        return integration

    async def integrate_skeleton_key_result(self, result: SkeletonKeyResult) -> IntegrationResult:
        """Integrate Skeleton Key attack result.

        Args:
            result: Skeleton Key result.

        Returns:
            IntegrationResult.
        """
        integration = IntegrationResult()

        try:
            await self._log("开始集成Skeleton Key攻击结果...")

            if result.success and self.credential_db:
                stored = await self._store_skeleton_key_credential(result)
                integration.credentials_stored = stored

            if self.event_bus:
                events = await self._broadcast_skeleton_key_event(result)
                integration.events_broadcast = events

            if self.report_module:
                entries = await self._add_to_report_timeline(
                    AttackType.SKELETON_KEY,
                    result.success,
                    result.target_dc or "unknown",
                    f"万能密码安装: {'成功' if result.success else '失败'}",
                    result.attck_technique,
                    result.success,
                    1 if result.success else 0,
                )
                integration.report_entries = entries

            integration.success = True
            await self._log(f"Skeleton Key集成完成")

        except Exception as e:
            integration.error_message = str(e)
            await self._log(f"Skeleton Key集成失败: {e}")
            logger.error("Skeleton Key integration failed: %s", e)

        return integration

    async def integrate_adminsdholder_result(self, result: AdminSDHolderResult) -> IntegrationResult:
        """Integrate AdminSDHolder attack result.

        Args:
            result: AdminSDHolder result.

        Returns:
            IntegrationResult.
        """
        integration = IntegrationResult()

        try:
            await self._log("开始集成AdminSDHolder攻击结果...")

            if self.event_bus:
                events = await self._broadcast_adminsdholder_event(result)
                integration.events_broadcast = events

            if self.report_module:
                entries = await self._add_to_report_timeline(
                    AttackType.ADMINSDHOLDER,
                    result.success,
                    result.target_user,
                    f"ACE注入: {result.injected_ace.trustee if result.injected_ace else 'N/A'}",
                    result.attck_technique,
                    result.success,
                    0,
                )
                integration.report_entries = entries

            integration.success = True
            await self._log(f"AdminSDHolder集成完成")

        except Exception as e:
            integration.error_message = str(e)
            await self._log(f"AdminSDHolder集成失败: {e}")
            logger.error("AdminSDHolder integration failed: %s", e)

        return integration

    async def integrate_cross_domain_result(self, result: CrossDomainAttackResult) -> IntegrationResult:
        """Integrate cross-domain attack result.

        Args:
            result: Cross-domain attack result.

        Returns:
            IntegrationResult.
        """
        integration = IntegrationResult()

        try:
            await self._log("开始集成跨域攻击结果...")

            if result.sid_history_result and self.credential_db:
                stored = await self._store_sid_history_credential(result.sid_history_result)
                integration.credentials_stored += stored

            if result.kerberos_result and self.credential_db:
                stored = await self._store_kerberos_credential(result.kerberos_result)
                integration.credentials_stored += stored

            if self.event_bus:
                events = await self._broadcast_cross_domain_event(result)
                integration.events_broadcast = events

            if self.report_module:
                entries = await self._add_to_report_timeline(
                    AttackType.CROSS_DOMAIN,
                    result.success,
                    "cross_domain",
                    f"信任关系: {result.trusts_found} 个, 可利用: {result.exploitable_trusts} 个",
                    result.attck_technique,
                    result.success,
                    integration.credentials_stored,
                )
                integration.report_entries = entries

            integration.success = True
            await self._log(f"跨域攻击集成完成")

        except Exception as e:
            integration.error_message = str(e)
            await self._log(f"跨域攻击集成失败: {e}")
            logger.error("Cross-domain integration failed: %s", e)

        return integration

    async def _store_dcsync_credentials(self, result: DCSyncResult) -> int:
        """Store DCSync credentials in database.

        Args:
            result: DCSync result.

        Returns:
            Number of credentials stored.
        """
        if not self.credential_db or not result.exported_credentials:
            return 0

        stored = 0
        try:
            for cred in result.exported_credentials:
                await self.credential_db.add_credential(
                    username=cred.username,
                    domain=cred.domain,
                    ntlm_hash=cred.ntlm_hash,
                    kerberos_key=cred.kerberos_key,
                    credential_type="dcsync_export",
                    is_high_value=cred.is_high_value,
                    source="dcsync_attack",
                    timestamp=time.time(),
                )
                stored += 1
                if cred.is_high_value:
                    await self._log(f"[高价值] 凭据入库: {cred.username}")
        except Exception as e:
            logger.error("Failed to store DCSync credentials: %s", e)

        return stored

    async def _store_shadow_credential(self, result: ShadowAttackResult) -> int:
        """Store Shadow Credentials TGT in database.

        Args:
            result: Shadow attack result.

        Returns:
            Number of credentials stored.
        """
        if not self.credential_db or not result.tgt_ticket:
            return 0

        try:
            target = result.target
            username = target.sam_account_name if target else "unknown"
            domain = target.domain if target else "unknown"
            is_high_value = target.is_high_value if target else False

            await self.credential_db.add_credential(
                username=username,
                domain=domain,
                ticket_data=result.tgt_ticket,
                credential_type="shadow_tgt",
                is_high_value=is_high_value,
                source="shadow_credentials",
                timestamp=time.time(),
            )
            return 1
        except Exception as e:
            logger.error("Failed to store shadow credential: %s", e)
            return 0

    async def _store_skeleton_key_credential(self, result: SkeletonKeyResult) -> int:
        """Store Skeleton Key password in database.

        Args:
            result: Skeleton Key result.

        Returns:
            Number of credentials stored.
        """
        if not self.credential_db or not result.password:
            return 0

        try:
            await self.credential_db.add_credential(
                username="skeleton_key",
                domain=result.target_dc or "unknown",
                password=result.password,
                credential_type="skeleton_key",
                is_high_value=True,
                source="skeleton_key",
                timestamp=time.time(),
            )
            return 1
        except Exception as e:
            logger.error("Failed to store skeleton key: %s", e)
            return 0

    async def _store_sid_history_credential(self, result: SIDHistoryInjectionResult) -> int:
        """Store SID History injection result.

        Args:
            result: SID History result.

        Returns:
            Number of credentials stored.
        """
        if not self.credential_db:
            return 0

        try:
            await self.credential_db.add_credential(
                username=result.target_user,
                domain=result.source_domain,
                credential_type="sid_history",
                is_high_value=True,
                source="cross_domain_attack",
                timestamp=time.time(),
            )
            return 1
        except Exception as e:
            logger.error("Failed to store SID History: %s", e)
            return 0

    async def _store_kerberos_credential(self, result: Any) -> int:
        """Store Kerberos ticket in database.

        Args:
            result: Kerberos attack result.

        Returns:
            Number of credentials stored.
        """
        if not self.credential_db or not result.ticket_data:
            return 0

        try:
            await self.credential_db.add_credential(
                username="cross_domain",
                domain=result.target_domain,
                ticket_data=result.ticket_data,
                credential_type=f"cross_domain_{result.attack_type}",
                is_high_value=True,
                source="cross_domain_kerberos",
                timestamp=time.time(),
            )
            return 1
        except Exception as e:
            logger.error("Failed to store Kerberos ticket: %s", e)
            return 0

    async def _broadcast_dcsync_event(self, result: DCSyncResult) -> int:
        """Broadcast DCSync event.

        Args:
            result: DCSync result.

        Returns:
            Number of events broadcast.
        """
        if not self.event_bus:
            return 0

        try:
            event_data = {
                "event_type": "dcsync_attack",
                "success": result.success,
                "target_dc": result.target_dc,
                "exported_count": result.exported_count,
                "high_value_count": result.high_value_count,
                "attck_technique": result.attck_technique,
                "timestamp": time.time(),
            }
            await self.event_bus.publish("domain_attack", event_data)
            return 1
        except Exception as e:
            logger.error("Failed to broadcast DCSync event: %s", e)
            return 0

    async def _broadcast_shadow_event(self, result: ShadowAttackResult) -> int:
        """Broadcast Shadow Credentials event.

        Args:
            result: Shadow attack result.

        Returns:
            Number of events broadcast.
        """
        if not self.event_bus:
            return 0

        try:
            event_data = {
                "event_type": "shadow_credentials",
                "success": result.success,
                "target": result.target.sam_account_name if result.target else "unknown",
                "tgt_obtained": bool(result.tgt_ticket),
                "attck_technique": result.attck_technique,
                "timestamp": time.time(),
            }
            await self.event_bus.publish("domain_attack", event_data)
            return 1
        except Exception as e:
            logger.error("Failed to broadcast shadow event: %s", e)
            return 0

    async def _broadcast_skeleton_key_event(self, result: SkeletonKeyResult) -> int:
        """Broadcast Skeleton Key event.

        Args:
            result: Skeleton Key result.

        Returns:
            Number of events broadcast.
        """
        if not self.event_bus:
            return 0

        try:
            event_data = {
                "event_type": "skeleton_key",
                "success": result.success,
                "target_dc": result.target_dc,
                "verification_passed": result.verification_passed,
                "attck_technique": result.attck_technique,
                "timestamp": time.time(),
            }
            await self.event_bus.publish("domain_attack", event_data)
            return 1
        except Exception as e:
            logger.error("Failed to broadcast skeleton key event: %s", e)
            return 0

    async def _broadcast_adminsdholder_event(self, result: AdminSDHolderResult) -> int:
        """Broadcast AdminSDHolder event.

        Args:
            result: AdminSDHolder result.

        Returns:
            Number of events broadcast.
        """
        if not self.event_bus:
            return 0

        try:
            event_data = {
                "event_type": "adminsdholder",
                "success": result.success,
                "target_user": result.target_user,
                "propagation_status": result.propagation_status.value if result.propagation_status else "unknown",
                "attck_technique": result.attck_technique,
                "timestamp": time.time(),
            }
            await self.event_bus.publish("domain_attack", event_data)
            return 1
        except Exception as e:
            logger.error("Failed to broadcast adminsdholder event: %s", e)
            return 0

    async def _broadcast_cross_domain_event(self, result: CrossDomainAttackResult) -> int:
        """Broadcast cross-domain event.

        Args:
            result: Cross-domain result.

        Returns:
            Number of events broadcast.
        """
        if not self.event_bus:
            return 0

        try:
            event_data = {
                "event_type": "cross_domain",
                "success": result.success,
                "trusts_found": result.trusts_found,
                "exploitable_trusts": result.exploitable_trusts,
                "sid_history_success": result.sid_history_result.success if result.sid_history_result else False,
                "kerberos_success": result.kerberos_result.success if result.kerberos_result else False,
                "attck_technique": result.attck_technique,
                "timestamp": time.time(),
            }
            await self.event_bus.publish("domain_attack", event_data)
            return 1
        except Exception as e:
            logger.error("Failed to broadcast cross-domain event: %s", e)
            return 0

    async def _add_to_report_timeline(
        self,
        attack_type: AttackType,
        success: bool,
        target: str,
        details: str,
        attck_technique: str,
        is_critical: bool,
        credential_count: int = 0,
    ) -> int:
        """Add attack to report timeline.

        Args:
            attack_type: Type of attack.
            success: Whether attack succeeded.
            target: Target of attack.
            details: Attack details.
            attck_technique: ATT&CK technique.
            is_critical: Whether this is critical.
            credential_count: Number of credentials obtained.

        Returns:
            Number of entries added.
        """
        if not self.report_module:
            return 0

        try:
            entry = AttackTimelineEntry(
                timestamp=time.time(),
                attack_type=attack_type,
                success=success,
                target=target,
                details=details,
                attck_technique=attck_technique,
                is_critical=is_critical,
                credential_count=credential_count,
            )
            self._timeline.append(entry)

            await self.report_module.add_timeline_entry(
                timestamp=entry.timestamp,
                attack_type=attack_type.value,
                success=success,
                target=target,
                details=details,
                attck_technique=attck_technique,
                is_critical=is_critical,
            )

            if is_critical:
                await self._log(f"[关键节点] 已添加到报告: {details}")

            return 1
        except Exception as e:
            logger.error("Failed to add to report timeline: %s", e)
            return 0

    async def _log(self, message: str) -> None:
        """Log integration message.

        Args:
            message: Log message.
        """
        self._integration_log.append(f"[{time.strftime('%H:%M:%S')}] {message}")
        logger.info("Integration: %s", message)

    def get_timeline(self) -> List[AttackTimelineEntry]:
        """Get attack timeline.

        Returns:
            List of timeline entries.
        """
        return self._timeline.copy()

    def get_integration_summary(self) -> Dict[str, Any]:
        """Get integration summary.

        Returns:
            Dictionary with integration summary.
        """
        return {
            "total_attacks": len(self._timeline),
            "successful_attacks": sum(1 for e in self._timeline if e.success),
            "critical_nodes": sum(1 for e in self._timeline if e.is_critical),
            "total_credentials": sum(e.credential_count for e in self._timeline),
            "attck_coverage": list(set(
                tech for e in self._timeline for tech in ATTACK_ATTACK_MAPPING.get(e.attack_type, [])
            )),
            "integration_log_count": len(self._integration_log),
        }
