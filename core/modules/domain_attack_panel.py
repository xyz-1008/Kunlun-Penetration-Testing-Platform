"""Domain attack panel module for Kunlun penetration testing platform.

Provides:
- Unified attack panel with tabbed interface
- Permission status display
- Attack chain recommendation
- Risk annotation and safety warnings
"""

import asyncio
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Coroutine, Dict, List, Optional, Tuple

from .adminsdholder import AdminSDHolderAttack, AdminSDHolderResult, ACEType
from .cross_domain_trust import CrossDomainAttackResult, CrossDomainTrustAttack, TrustRelationship
from .dcsync_attack import DCSyncAttack, DCSyncConfig, DCSyncResult, PermissionLevel
from .shadow_credentials import (
    ShadowAttackResult,
    ShadowCredentialsAttack,
    ShadowTargetInfo,
)
from .skeleton_key import SkeletonKeyAttack, SkeletonKeyConfig, SkeletonKeyResult

logger = logging.getLogger(__name__)


class RiskLevel(Enum):
    """Risk level for attack operations."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AttackStatus(Enum):
    """Status of attack operation."""
    READY = "ready"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    REQUIRES_PERMISSION = "requires_permission"


@dataclass
class AttackModuleInfo:
    """Information about an attack module.

    Attributes:
        module_id: Unique module identifier
        name: Module display name
        description: Module description
        risk_level: Risk level
        detection_probability: Detection probability (0-1)
        required_permission: Required permission level
        attck_technique: Associated ATT&CK technique ID
        status: Current module status
        is_available: Whether module is available
        prerequisites_met: Whether prerequisites are met
    """
    module_id: str = ""
    name: str = ""
    description: str = ""
    risk_level: RiskLevel = RiskLevel.MEDIUM
    detection_probability: float = 0.5
    required_permission: str = ""
    attck_technique: str = ""
    status: AttackStatus = AttackStatus.READY
    is_available: bool = False
    prerequisites_met: bool = False


@dataclass
class AttackChainStep:
    """Step in attack chain recommendation.

    Attributes:
        step_number: Step number
        module_id: Associated module ID
        action: Action description
        reason: Reason for this step
        expected_outcome: Expected outcome
        is_critical: Whether step is critical
    """
    step_number: int = 0
    module_id: str = ""
    action: str = ""
    reason: str = ""
    expected_outcome: str = ""
    is_critical: bool = False


@dataclass
class AttackChainRecommendation:
    """Recommended attack chain.

    Attributes:
        chain_name: Chain name
        description: Chain description
        current_permission: Current permission level
        steps: Recommended steps
        estimated_impact: Estimated impact
        total_risk: Total risk level
    """
    chain_name: str = ""
    description: str = ""
    current_permission: str = ""
    steps: List[AttackChainStep] = field(default_factory=list)
    estimated_impact: str = ""
    total_risk: RiskLevel = RiskLevel.MEDIUM


@dataclass
class PanelState:
    """State of the attack panel.

    Attributes:
        current_permission: Current permission level
        permission_details: Permission details
        recommended_targets: Recommended attack targets
        attack_chains: Recommended attack chains
        module_statuses: Status of all modules
        stealth_mode: Whether stealth mode is enabled
        operation_log: Operation log entries
    """
    current_permission: str = ""
    permission_details: Dict[str, Any] = field(default_factory=dict)
    recommended_targets: List[str] = field(default_factory=list)
    attack_chains: List[AttackChainRecommendation] = field(default_factory=list)
    module_statuses: Dict[str, AttackModuleInfo] = field(default_factory=dict)
    stealth_mode: bool = False
    operation_log: List[str] = field(default_factory=list)


ATTACK_MODULES: List[AttackModuleInfo] = [
    AttackModuleInfo(
        module_id="dcsync",
        name="DCSync",
        description="导出域内任意用户的NTLM哈希和Kerberos密钥",
        risk_level=RiskLevel.CRITICAL,
        detection_probability=0.7,
        required_permission="Domain Admins / Enterprise Admins",
        attck_technique="T1003.006",
    ),
    AttackModuleInfo(
        module_id="shadow_credentials",
        name="Shadow Credentials",
        description="向目标账户添加Key Credential并获取TGT",
        risk_level=RiskLevel.HIGH,
        detection_probability=0.4,
        required_permission="Write msDS-KeyCredentialLink",
        attck_technique="T1649",
    ),
    AttackModuleInfo(
        module_id="skeleton_key",
        name="Skeleton Key",
        description="通过LSASS注入万能密码，持久化域控访问",
        risk_level=RiskLevel.CRITICAL,
        detection_probability=0.8,
        required_permission="SYSTEM + DC Local Admin",
        attck_technique="T1556",
    ),
    AttackModuleInfo(
        module_id="adminsdholder",
        name="AdminSDHolder",
        description="修改AdminSDHolder实现权限持久化",
        risk_level=RiskLevel.HIGH,
        detection_probability=0.3,
        required_permission="Write DACL on AdminSDHolder",
        attck_technique="T1484.001",
    ),
    AttackModuleInfo(
        module_id="cross_domain",
        name="跨域信任利用",
        description="利用域信任关系进行跨域攻击",
        risk_level=RiskLevel.HIGH,
        detection_probability=0.5,
        required_permission="Domain Admins",
        attck_technique="T1558",
    ),
]

RISK_COLORS: Dict[RiskLevel, str] = {
    RiskLevel.LOW: "#16a34a",
    RiskLevel.MEDIUM: "#ca8a04",
    RiskLevel.HIGH: "#ea580c",
    RiskLevel.CRITICAL: "#dc2626",
}

PERMISSION_COLORS: Dict[str, str] = {
    "available": "#16a34a",
    "requires_elevation": "#ca8a04",
    "unavailable": "#dc2626",
}


class DomainAttackPanel:
    """Unified domain attack panel.

    Provides tabbed interface for all domain attack modules,
    permission status display, attack chain recommendation,
    and risk annotation.
    """

    def __init__(
        self,
        c2_session: Optional[Any] = None,
        credential_db: Optional[Any] = None,
        event_bus: Optional[Any] = None,
    ) -> None:
        """Initialize domain attack panel.

        Args:
            c2_session: C2 framework session.
            credential_db: Credential database.
            event_bus: Event bus.
        """
        self.c2_session = c2_session
        self.credential_db = credential_db
        self.event_bus = event_bus

        self.dcsync = DCSyncAttack(c2_session, credential_db, event_bus)
        self.shadow = ShadowCredentialsAttack(c2_session, credential_db, event_bus)
        self.skeleton = SkeletonKeyAttack(c2_session, credential_db, event_bus)
        self.adminsdholder = AdminSDHolderAttack(c2_session, credential_db, event_bus)
        self.cross_domain = CrossDomainTrustAttack(c2_session, credential_db, event_bus)

        self.panel_state = PanelState()
        self._progress_callback: Optional[Callable[[str, float], Coroutine[Any, Any, None]]] = None
        self._log_callback: Optional[Callable[[str], Coroutine[Any, Any, None]]] = None
        self._confirm_callback: Optional[Callable[[str], Coroutine[Any, Any, bool]]] = None

        self._setup_callbacks()

    def _setup_callbacks(self) -> None:
        """Setup callbacks for all attack modules."""
        modules = [
            self.dcsync,
            self.shadow,
            self.skeleton,
            self.adminsdholder,
            self.cross_domain,
        ]
        for module in modules:
            if hasattr(module, "set_callbacks"):
                module.set_callbacks(
                    progress_cb=self._on_module_progress,
                    log_cb=self._on_module_log,
                )

    def set_callbacks(
        self,
        progress_cb: Optional[Callable[[str, float], Coroutine[Any, Any, None]]] = None,
        log_cb: Optional[Callable[[str], Coroutine[Any, Any, None]]] = None,
        confirm_cb: Optional[Callable[[str], Coroutine[Any, Any, bool]]] = None,
    ) -> None:
        """Set UI callbacks.

        Args:
            progress_cb: Progress update callback.
            log_cb: Log message callback.
            confirm_cb: Confirmation dialog callback.
        """
        self._progress_callback = progress_cb
        self._log_callback = log_cb
        self._confirm_callback = confirm_cb

    async def _on_module_progress(self, message: str, percentage: float) -> None:
        """Handle module progress update.

        Args:
            message: Progress message.
            percentage: Progress percentage.
        """
        if self._progress_callback:
            await self._progress_callback(message, percentage)

    async def _on_module_log(self, message: str) -> None:
        """Handle module log message.

        Args:
            message: Log message.
        """
        self.panel_state.operation_log.append(f"[{time.strftime('%H:%M:%S')}] {message}")
        if self._log_callback:
            await self._log_callback(message)

    async def _confirm_operation(self, message: str) -> bool:
        """Show confirmation dialog for high-risk operations.

        Args:
            message: Confirmation message.

        Returns:
            True if confirmed.
        """
        if self._confirm_callback:
            return await self._confirm_callback(message)
        return True

    async def initialize_panel(self) -> PanelState:
        """Initialize the attack panel with current state.

        Returns:
            PanelState with current information.
        """
        await self._on_module_log("初始化域控攻击面板...")

        await self._update_permission_status()
        await self._update_module_statuses()
        await self._generate_attack_chains()
        await self._identify_recommended_targets()

        await self._on_module_log("面板初始化完成")

        return self.panel_state

    async def _update_permission_status(self) -> None:
        """Update current permission status."""
        try:
            perm_level, perm_details = await self.dcsync.check_permissions()
            self.panel_state.current_permission = perm_level.value
            self.panel_state.permission_details = perm_details
        except Exception as e:
            logger.error("Failed to update permission status: %s", e)
            self.panel_state.current_permission = "unknown"

    async def _update_module_statuses(self) -> None:
        """Update status of all attack modules."""
        for module_info in ATTACK_MODULES:
            available = await self._check_module_availability(module_info)
            module_info.is_available = available
            module_info.prerequisites_met = available
            if available:
                module_info.status = AttackStatus.READY
            else:
                module_info.status = AttackStatus.REQUIRES_PERMISSION
            self.panel_state.module_statuses[module_info.module_id] = module_info

    async def _check_module_availability(self, module_info: AttackModuleInfo) -> bool:
        """Check if module is available based on current permissions.

        Args:
            module_info: Module information.

        Returns:
            True if module is available.
        """
        current = self.panel_state.current_permission

        if module_info.module_id == "dcsync":
            return current in ["domain_admin", "enterprise_admin", "dc_local_admin"]
        elif module_info.module_id == "shadow_credentials":
            return current in ["domain_user", "domain_admin", "enterprise_admin"]
        elif module_info.module_id == "skeleton_key":
            return current in ["dc_local_admin"]
        elif module_info.module_id == "adminsdholder":
            return current in ["domain_admin", "enterprise_admin"]
        elif module_info.module_id == "cross_domain":
            return current in ["domain_admin", "enterprise_admin"]
        return False

    async def _generate_attack_chains(self) -> None:
        """Generate attack chain recommendations based on current state."""
        chains: List[AttackChainRecommendation] = []
        current = self.panel_state.current_permission

        if current in ["domain_admin", "enterprise_admin"]:
            chains.append(AttackChainRecommendation(
                chain_name="高权限完整攻击链",
                description="利用域管权限执行完整域控攻击",
                current_permission=current,
                steps=[
                    AttackChainStep(
                        step_number=1,
                        module_id="dcsync",
                        action="执行DCSync导出krbtgt哈希",
                        reason="获取krbtgt哈希用于后续黄金票据",
                        expected_outcome="获取域内所有用户凭据",
                        is_critical=True,
                    ),
                    AttackChainStep(
                        step_number=2,
                        module_id="skeleton_key",
                        action="安装Skeleton Key万能密码",
                        reason="确保持久化访问域控",
                        expected_outcome="万能密码安装成功",
                        is_critical=False,
                    ),
                    AttackChainStep(
                        step_number=3,
                        module_id="adminsdholder",
                        action="注入AdminSDHolder ACE",
                        reason="即使被移除域管组也能自动恢复权限",
                        expected_outcome="权限持久化完成",
                        is_critical=False,
                    ),
                    AttackChainStep(
                        step_number=4,
                        module_id="cross_domain",
                        action="利用信任关系进行跨域攻击",
                        reason="扩展到其他域/林",
                        expected_outcome="跨域权限获取",
                        is_critical=False,
                    ),
                ],
                estimated_impact="完全控制当前域及信任域",
                total_risk=RiskLevel.CRITICAL,
            ))

        if current in ["domain_user", "domain_admin"]:
            chains.append(AttackChainRecommendation(
                chain_name="中权限提权攻击链",
                description="通过Shadow Credentials提权后执行DCSync",
                current_permission=current,
                steps=[
                    AttackChainStep(
                        step_number=1,
                        module_id="shadow_credentials",
                        action="检测AD CS并执行Shadow Credentials",
                        reason="通过Key Credential注入获取域管TGT",
                        expected_outcome="获取域管账户TGT",
                        is_critical=True,
                    ),
                    AttackChainStep(
                        step_number=2,
                        module_id="dcsync",
                        action="使用获取的凭据执行DCSync",
                        reason="导出域内所有用户凭据",
                        expected_outcome="获取域内所有用户凭据",
                        is_critical=True,
                    ),
                ],
                estimated_impact="提权至域管并完全控制域",
                total_risk=RiskLevel.HIGH,
            ))

        if current == "insufficient":
            chains.append(AttackChainRecommendation(
                chain_name="低权限初始攻击链",
                description="需要先获取域内凭据再执行域控攻击",
                current_permission=current,
                steps=[
                    AttackChainStep(
                        step_number=1,
                        module_id="shadow_credentials",
                        action="检测可攻击的Shadow Credentials目标",
                        reason="寻找可注入Key Credential的账户",
                        expected_outcome="发现可攻击目标",
                        is_critical=True,
                    ),
                ],
                estimated_impact="可能获取初始域访问权限",
                total_risk=RiskLevel.MEDIUM,
            ))

        self.panel_state.attack_chains = chains

    async def _identify_recommended_targets(self) -> None:
        """Identify recommended attack targets."""
        targets: List[str] = []

        try:
            shadow_targets = await self.shadow.detect_shadow_targets()
            high_value = [t for t in shadow_targets if t.is_high_value and t.attackable]
            for target in high_value:
                targets.append(f"{target.sam_account_name} ({target.object_class})")

            if not targets:
                targets.append("krbtgt (域控服务账户)")
                targets.append("administrator (内置管理员)")

        except Exception as e:
            logger.error("Failed to identify targets: %s", e)
            targets = ["krbtgt", "administrator"]

        self.panel_state.recommended_targets = targets

    async def execute_dcsync_attack(
        self,
        target_dc: str = "",
        target_users: Optional[List[str]] = None,
        stealth_mode: bool = False,
    ) -> DCSyncResult:
        """Execute DCSync attack from panel.

        Args:
            target_dc: Target domain controller.
            target_users: Specific users to export.
            stealth_mode: Enable stealth mode.

        Returns:
            DCSyncResult.
        """
        module = self.panel_state.module_statuses.get("dcsync")
        if module and module.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL):
            confirmed = await self._confirm_operation(
                f"DCSync是高风险操作 (检测概率: {module.detection_probability*100:.0f}%)\n"
                f"ATT&CK: {module.attck_technique}\n"
                f"是否继续?"
            )
            if not confirmed:
                return DCSyncResult(error_message="用户取消操作")

        config = DCSyncConfig(
            target_dc=target_dc,
            target_users=target_users or [],
            stealth_mode=stealth_mode or self.panel_state.stealth_mode,
        )

        if module:
            module.status = AttackStatus.RUNNING
        result = await self.dcsync.execute_dcsync(config)
        if module:
            module.status = AttackStatus.SUCCESS if result.success else AttackStatus.FAILED

        await self._on_module_log(f"DCSync攻击完成: {'成功' if result.success else '失败'}")

        return result

    async def execute_shadow_attack(
        self,
        target: ShadowTargetInfo,
        auto_cleanup: bool = False,
    ) -> ShadowAttackResult:
        """Execute Shadow Credentials attack from panel.

        Args:
            target: Target account info.
            auto_cleanup: Whether to auto cleanup.

        Returns:
            ShadowAttackResult.
        """
        module = self.panel_state.module_statuses.get("shadow_credentials")
        if module and module.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL):
            confirmed = await self._confirm_operation(
                f"Shadow Credentials是高风险操作 (检测概率: {module.detection_probability*100:.0f}%)\n"
                f"ATT&CK: {module.attck_technique}\n"
                f"目标: {target.sam_account_name}\n"
                f"是否继续?"
            )
            if not confirmed:
                return ShadowAttackResult(error_message="用户取消操作")

        if module:
            module.status = AttackStatus.RUNNING
        result = await self.shadow.execute_full_attack(target, auto_cleanup)
        if module:
            module.status = AttackStatus.SUCCESS if result.success else AttackStatus.FAILED

        await self._on_module_log(
            f"Shadow Credentials攻击完成: {'成功' if result.success else '失败'}"
        )

        return result

    async def execute_skeleton_key_attack(
        self,
        target_dc: str = "",
        custom_password: str = "",
        validity_hours: int = 0,
    ) -> SkeletonKeyResult:
        """Execute Skeleton Key attack from panel.

        Args:
            target_dc: Target domain controller.
            custom_password: Custom password.
            validity_hours: Validity period.

        Returns:
            SkeletonKeyResult.
        """
        module = self.panel_state.module_statuses.get("skeleton_key")
        if module and module.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL):
            confirmed = await self._confirm_operation(
                f"Skeleton Key是极高风险操作 (检测概率: {module.detection_probability*100:.0f}%)\n"
                f"ATT&CK: {module.attck_technique}\n"
                f"将修改LSASS内存，可能触发EDR告警\n"
                f"是否继续?"
            )
            if not confirmed:
                return SkeletonKeyResult(error_message="用户取消操作")

        config = SkeletonKeyConfig(
            target_dc=target_dc,
            custom_password=custom_password,
            validity_hours=validity_hours,
            stealth_mode=self.panel_state.stealth_mode,
        )

        if module:
            module.status = AttackStatus.RUNNING
        result = await self.skeleton.install_skeleton_key(config)
        if module:
            module.status = AttackStatus.SUCCESS if result.success else AttackStatus.FAILED

        await self._on_module_log(
            f"Skeleton Key攻击完成: {'成功' if result.success else '失败'}"
        )

        return result

    async def execute_adminsdholder_attack(
        self,
        target_user: str,
        ace_type: ACEType = ACEType.FULL_CONTROL,
        auto_trigger_sdprop: bool = True,
    ) -> AdminSDHolderResult:
        """Execute AdminSDHolder attack from panel.

        Args:
            target_user: Target user.
            ace_type: ACE type.
            auto_trigger_sdprop: Whether to auto trigger SDProp.

        Returns:
            AdminSDHolderResult.
        """
        module = self.panel_state.module_statuses.get("adminsdholder")
        if module and module.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL):
            confirmed = await self._confirm_operation(
                f"AdminSDHolder是高风险操作 (检测概率: {module.detection_probability*100:.0f}%)\n"
                f"ATT&CK: {module.attck_technique}\n"
                f"将修改域级ACL配置\n"
                f"是否继续?"
            )
            if not confirmed:
                return AdminSDHolderResult(error_message="用户取消操作")

        if module:
            module.status = AttackStatus.RUNNING
        result = await self.adminsdholder.execute_full_attack(
            target_user,
            ace_type,
            auto_trigger_sdprop,
        )
        if module:
            module.status = AttackStatus.SUCCESS if result.success else AttackStatus.FAILED

        await self._on_module_log(
            f"AdminSDHolder攻击完成: {'成功' if result.success else '失败'}"
        )

        return result

    async def execute_cross_domain_attack(
        self,
        target_domain: str,
        target_user: str = "administrator",
        inject_sid: bool = True,
        kerberos_attack: bool = True,
        krbtgt_hash: str = "",
    ) -> CrossDomainAttackResult:
        """Execute cross-domain attack from panel.

        Args:
            target_domain: Target domain.
            target_user: Target user.
            inject_sid: Whether to inject SID History.
            kerberos_attack: Whether to perform Kerberos attack.
            krbtgt_hash: Krbtgt hash.

        Returns:
            CrossDomainAttackResult.
        """
        module = self.panel_state.module_statuses.get("cross_domain")
        if module and module.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL):
            confirmed = await self._confirm_operation(
                f"跨域攻击是高风险操作 (检测概率: {module.detection_probability*100:.0f}%)\n"
                f"ATT&CK: {module.attck_technique}\n"
                f"将影响多个域/林\n"
                f"是否继续?"
            )
            if not confirmed:
                return CrossDomainAttackResult(error_message="用户取消操作")

        if module:
            module.status = AttackStatus.RUNNING
        result = await self.cross_domain.execute_full_attack(
            target_domain,
            target_user,
            inject_sid,
            kerberos_attack,
            krbtgt_hash,
        )
        if module:
            module.status = AttackStatus.SUCCESS if result.success else AttackStatus.FAILED

        await self._on_module_log(
            f"跨域攻击完成: {'成功' if result.success else '失败'}"
        )

        return result

    def toggle_stealth_mode(self) -> bool:
        """Toggle stealth mode.

        Returns:
            New stealth mode status.
        """
        self.panel_state.stealth_mode = not self.panel_state.stealth_mode
        return self.panel_state.stealth_mode

    def get_panel_summary(self) -> Dict[str, Any]:
        """Get panel summary for display.

        Returns:
            Dictionary with panel summary.
        """
        return {
            "current_permission": self.panel_state.current_permission,
            "permission_color": PERMISSION_COLORS.get(
                "available" if self.panel_state.current_permission in [
                    "domain_admin", "enterprise_admin", "dc_local_admin"
                ] else "unavailable",
                "#6b7280",
            ),
            "modules": {
                mid: {
                    "name": m.name,
                    "status": m.status.value,
                    "risk_level": m.risk_level.value,
                    "risk_color": RISK_COLORS.get(m.risk_level, "#6b7280"),
                    "detection_probability": m.detection_probability,
                    "attck_technique": m.attck_technique,
                    "is_available": m.is_available,
                }
                for mid, m in self.panel_state.module_statuses.items()
            },
            "recommended_targets": self.panel_state.recommended_targets,
            "attack_chains": [
                {
                    "name": c.chain_name,
                    "description": c.description,
                    "total_risk": c.total_risk.value,
                    "step_count": len(c.steps),
                }
                for c in self.panel_state.attack_chains
            ],
            "stealth_mode": self.panel_state.stealth_mode,
            "operation_log_count": len(self.panel_state.operation_log),
        }
