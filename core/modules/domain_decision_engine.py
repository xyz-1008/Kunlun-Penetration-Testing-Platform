"""Domain decision engine module for Kunlun platform.

Provides:
- Attack path Cost-Benefit analysis (success probability, detection risk, time)
- Automatic attack chain adjustment on failure
- Domain environment adaptive learning
- Anonymous success record synchronization to community knowledge base
"""

import asyncio
import json
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Coroutine, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class AttackTechnique(Enum):
    """Attack technique types."""
    DCSYNC = "dcsync"
    SHADOW_CREDENTIALS = "shadow_credentials"
    SKELETON_KEY = "skeleton_key"
    ADMINSDHOLDER = "adminsdholder"
    CROSS_DOMAIN_TRUST = "cross_domain_trust"
    DSRM_BACKDOOR = "dsrm_backdoor"
    SSP_BACKDOOR = "ssp_backdoor"
    DCSHADOW = "dcshadow"
    ADCS_ESCALATION = "adcs_escalation"
    GPO_BACKDOOR = "gpo_backdoor"
    GOLDEN_TICKET = "golden_ticket"
    SID_HISTORY = "sid_history"


class DecisionStatus(Enum):
    """Decision engine status."""
    ANALYZING = "analyzing"
    RECOMMENDED = "recommended"
    EXECUTING = "executing"
    BLOCKED = "blocked"
    SWITCHED = "switched"
    COMPLETED = "completed"


@dataclass
class AttackPathScore:
    """Score for an attack path.

    Attributes:
        path_name: Attack path name
        technique: Attack technique
        success_probability: Probability of success (0-1)
        detection_risk: Detection risk level (0-1)
        time_required_minutes: Estimated time required
        prerequisites_met: Whether prerequisites are met
        cost_benefit_score: Calculated cost-benefit score
        recommendation_rank: Recommendation rank (1 = best)
    """
    path_name: str = ""
    technique: AttackTechnique = AttackTechnique.DCSYNC
    success_probability: float = 0.0
    detection_risk: float = 0.0
    time_required_minutes: float = 0.0
    prerequisites_met: bool = False
    cost_benefit_score: float = 0.0
    recommendation_rank: int = 0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "path_name": self.path_name,
            "technique": self.technique.value,
            "success_probability": self.success_probability,
            "detection_risk": self.detection_risk,
            "time_required_minutes": self.time_required_minutes,
            "prerequisites_met": self.prerequisites_met,
            "cost_benefit_score": self.cost_benefit_score,
            "recommendation_rank": self.recommendation_rank,
        }


@dataclass
class EnvironmentProfile:
    """Domain environment profile.

    Attributes:
        os_version: Domain controller OS version
        patch_level: Patch level
        security_products: List of security products detected
        siem_enabled: Whether SIEM is enabled
        edi_enabled: Whether EDR is enabled
        mdi_enabled: Whether MDI is enabled
        adcs_enabled: Whether ADCS is enabled
        domain_functional_level: Domain functional level
        total_domain_controllers: Number of domain controllers
        total_users: Number of domain users
    """
    os_version: str = ""
    patch_level: str = ""
    security_products: List[str] = field(default_factory=list)
    siem_enabled: bool = False
    edi_enabled: bool = False
    mdi_enabled: bool = False
    adcs_enabled: bool = False
    domain_functional_level: str = ""
    total_domain_controllers: int = 0
    total_users: int = 0


@dataclass
class DecisionResult:
    """Result of decision engine operation.

    Attributes:
        status: Decision status
        recommended_path: Recommended attack path
        all_scores: All attack path scores
        blocked_reason: Reason if path is blocked
        switched_to: Switched path if original was blocked
        environment_profile: Environment profile
        learning_applied: Whether learning was applied
        error_message: Error message if failed
        duration_seconds: Operation duration
    """
    status: DecisionStatus = DecisionStatus.ANALYZING
    recommended_path: Optional[AttackPathScore] = None
    all_scores: List[AttackPathScore] = field(default_factory=list)
    blocked_reason: str = ""
    switched_to: str = ""
    environment_profile: Optional[EnvironmentProfile] = None
    learning_applied: bool = False
    error_message: str = ""
    duration_seconds: float = 0.0


@dataclass
class AttackRecord:
    """Record of an attack attempt.

    Attributes:
        technique: Attack technique used
        success: Whether attack succeeded
        duration_seconds: Attack duration
        detection_triggered: Whether detection was triggered
        environment_profile: Environment profile during attack
        prerequisites: List of prerequisites
        timestamp: Record timestamp
    """
    technique: AttackTechnique = AttackTechnique.DCSYNC
    success: bool = False
    duration_seconds: float = 0.0
    detection_triggered: bool = False
    environment_profile: str = ""
    prerequisites: List[str] = field(default_factory=list)
    timestamp: float = 0.0


class DomainDecisionEngine:
    """Domain decision engine module.

    Provides Cost-Benefit analysis, automatic attack path adjustment,
    and domain environment adaptive learning.
    """

    TECHNIQUE_BASE_SCORES: Dict[AttackTechnique, Dict[str, float]] = {
        AttackTechnique.DCSYNC: {
            "base_success": 0.85,
            "base_detection": 0.7,
            "base_time": 5.0,
        },
        AttackTechnique.SHADOW_CREDENTIALS: {
            "base_success": 0.75,
            "base_detection": 0.4,
            "base_time": 10.0,
        },
        AttackTechnique.SKELETON_KEY: {
            "base_success": 0.9,
            "base_detection": 0.8,
            "base_time": 3.0,
        },
        AttackTechnique.ADMINSDHOLDER: {
            "base_success": 0.8,
            "base_detection": 0.5,
            "base_time": 15.0,
        },
        AttackTechnique.CROSS_DOMAIN_TRUST: {
            "base_success": 0.7,
            "base_detection": 0.6,
            "base_time": 20.0,
        },
        AttackTechnique.DSRM_BACKDOOR: {
            "base_success": 0.85,
            "base_detection": 0.3,
            "base_time": 5.0,
        },
        AttackTechnique.SSP_BACKDOOR: {
            "base_success": 0.8,
            "base_detection": 0.6,
            "base_time": 8.0,
        },
        AttackTechnique.DCSHADOW: {
            "base_success": 0.75,
            "base_detection": 0.4,
            "base_time": 12.0,
        },
        AttackTechnique.ADCS_ESCALATION: {
            "base_success": 0.7,
            "base_detection": 0.5,
            "base_time": 15.0,
        },
        AttackTechnique.GPO_BACKDOOR: {
            "base_success": 0.8,
            "base_detection": 0.6,
            "base_time": 10.0,
        },
        AttackTechnique.GOLDEN_TICKET: {
            "base_success": 0.9,
            "base_detection": 0.5,
            "base_time": 5.0,
        },
        AttackTechnique.SID_HISTORY: {
            "base_success": 0.75,
            "base_detection": 0.7,
            "base_time": 8.0,
        },
    }

    def __init__(
        self,
        c2_session: Optional[Any] = None,
        credential_db: Optional[Any] = None,
        event_bus: Optional[Any] = None,
    ) -> None:
        """Initialize domain decision engine module.

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
        self._attack_records: List[AttackRecord] = []
        self._environment_profile: Optional[EnvironmentProfile] = None
        self._knowledge_base: Dict[str, Any] = {}

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
        logger.info("Decision Engine Progress: %.1f%% - %s", percentage, message)

    async def _report_log(self, message: str) -> None:
        """Report log via callback.

        Args:
            message: Log message.
        """
        if self._log_callback:
            await self._log_callback(message)
        logger.info("Decision Engine: %s", message)

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

    async def analyze_attack_paths(
        self,
        available_techniques: Optional[List[AttackTechnique]] = None,
        current_permissions: Optional[List[str]] = None,
    ) -> DecisionResult:
        """Analyze and recommend optimal attack paths.

        Args:
            available_techniques: List of available attack techniques.
            current_permissions: List of current permissions.

        Returns:
            DecisionResult with recommended path.
        """
        start_time = time.time()
        result = DecisionResult()

        try:
            await self._report_progress("分析攻击路径", 10)
            await self._report_log("开始Cost-Benefit分析...")

            techniques = available_techniques or list(AttackTechnique)
            permissions = current_permissions or []

            await self._report_progress("评估环境特征", 20)
            env_profile = await self.profile_environment()
            result.environment_profile = env_profile
            self._environment_profile = env_profile

            await self._report_progress("计算路径评分", 40)
            scores: List[AttackPathScore] = []

            for technique in techniques:
                score = await self._calculate_path_score(
                    technique,
                    env_profile,
                    permissions,
                )
                scores.append(score)

            scores.sort(key=lambda s: s.cost_benefit_score, reverse=True)

            for i, score in enumerate(scores):
                score.recommendation_rank = i + 1

            result.all_scores = scores

            if scores:
                result.recommended_path = scores[0]
                result.status = DecisionStatus.RECOMMENDED
                await self._report_log(
                    f"推荐攻击路径: {result.recommended_path.path_name} "
                    f"(评分: {result.recommended_path.cost_benefit_score:.2f})"
                )

            result.duration_seconds = time.time() - start_time
            await self._report_progress("完成", 100)

        except Exception as e:
            result.error_message = str(e)
            result.duration_seconds = time.time() - start_time
            await self._report_log(f"攻击路径分析失败: {e}")
            logger.error("Attack path analysis failed: %s", e)

        return result

    async def _calculate_path_score(
        self,
        technique: AttackTechnique,
        env_profile: EnvironmentProfile,
        permissions: List[str],
    ) -> AttackPathScore:
        """Calculate score for an attack path.

        Args:
            technique: Attack technique.
            env_profile: Environment profile.
            permissions: Current permissions.

        Returns:
            AttackPathScore.
        """
        base_scores = self.TECHNIQUE_BASE_SCORES.get(technique, {
            "base_success": 0.5,
            "base_detection": 0.5,
            "base_time": 10.0,
        })

        success_prob = base_scores["base_success"]
        detection_risk = base_scores["base_detection"]
        time_required = base_scores["base_time"]

        if env_profile.mdi_enabled:
            detection_risk = min(detection_risk + 0.2, 1.0)

        if env_profile.siem_enabled:
            detection_risk = min(detection_risk + 0.15, 1.0)

        if env_profile.edi_enabled:
            detection_risk = min(detection_risk + 0.1, 1.0)

        prereq_met = self._check_prerequisites(technique, permissions)
        if not prereq_met:
            success_prob *= 0.3

        historical_success = self._get_historical_success_rate(technique)
        if historical_success > 0:
            success_prob = (success_prob + historical_success) / 2

        cost_benefit = (success_prob * 0.5) - (detection_risk * 0.3) - (time_required * 0.01)

        return AttackPathScore(
            path_name=technique.value,
            technique=technique,
            success_probability=success_prob,
            detection_risk=detection_risk,
            time_required_minutes=time_required,
            prerequisites_met=prereq_met,
            cost_benefit_score=cost_benefit,
        )

    def _check_prerequisites(
        self,
        technique: AttackTechnique,
        permissions: List[str],
    ) -> bool:
        """Check if prerequisites are met for technique.

        Args:
            technique: Attack technique.
            permissions: Current permissions.

        Returns:
            True if prerequisites are met.
        """
        required_perms: Dict[AttackTechnique, List[str]] = {
            AttackTechnique.DCSYNC: ["domain_admin", "enterprise_admin"],
            AttackTechnique.SHADOW_CREDENTIALS: ["write_property"],
            AttackTechnique.SKELETON_KEY: ["local_admin", "system"],
            AttackTechnique.ADMINSDHOLDER: ["write_dacl"],
            AttackTechnique.CROSS_DOMAIN_TRUST: ["domain_admin"],
            AttackTechnique.DSRM_BACKDOOR: ["local_admin", "system"],
            AttackTechnique.SSP_BACKDOOR: ["local_admin", "system"],
            AttackTechnique.DCSHADOW: ["domain_admin", "enterprise_admin"],
            AttackTechnique.ADCS_ESCALATION: ["enroll"],
            AttackTechnique.GPO_BACKDOOR: ["domain_admin", "gpo_creator"],
            AttackTechnique.GOLDEN_TICKET: ["krbtgt_hash"],
            AttackTechnique.SID_HISTORY: ["domain_admin"],
        }

        required = required_perms.get(technique, [])
        return any(perm in permissions for perm in required)

    def _get_historical_success_rate(self, technique: AttackTechnique) -> float:
        """Get historical success rate for technique.

        Args:
            technique: Attack technique.

        Returns:
            Historical success rate (0-1).
        """
        records = [r for r in self._attack_records if r.technique == technique]
        if not records:
            return 0.0

        success_count = sum(1 for r in records if r.success)
        return success_count / len(records)

    async def handle_blocked_path(
        self,
        blocked_technique: AttackTechnique,
        block_reason: str,
        available_techniques: Optional[List[AttackTechnique]] = None,
    ) -> DecisionResult:
        """Handle blocked attack path and switch to alternative.

        Args:
            blocked_technique: Blocked attack technique.
            block_reason: Reason for blocking.
            available_techniques: Available alternative techniques.

        Returns:
            DecisionResult with switched path.
        """
        start_time = time.time()
        result = DecisionResult()

        try:
            await self._report_progress("处理受阻路径", 10)
            await self._report_log(f"攻击路径受阻: {blocked_technique.value} - {block_reason}")

            result.blocked_reason = block_reason
            result.status = DecisionStatus.BLOCKED

            await self._report_progress("寻找替代路径", 30)

            alternatives = available_techniques or [
                t for t in AttackTechnique if t != blocked_technique
            ]

            analysis = await self.analyze_attack_paths(alternatives)

            if analysis.recommended_path:
                result.recommended_path = analysis.recommended_path
                result.switched_to = analysis.recommended_path.path_name
                result.status = DecisionStatus.SWITCHED
                result.all_scores = analysis.all_scores
                result.environment_profile = analysis.environment_profile

                await self._report_log(
                    f"已切换到替代路径: {result.switched_to}"
                )

            result.duration_seconds = time.time() - start_time
            await self._report_progress("完成", 100)

        except Exception as e:
            result.error_message = str(e)
            result.duration_seconds = time.time() - start_time
            await self._report_log(f"受阻路径处理失败: {e}")
            logger.error("Blocked path handling failed: %s", e)

        return result

    async def profile_environment(self) -> EnvironmentProfile:
        """Profile domain environment for adaptive learning.

        Returns:
            EnvironmentProfile.
        """
        profile = EnvironmentProfile()

        try:
            await self._report_progress("分析域环境", 10)
            await self._report_log("开始分析域环境特征...")

            os_result = await self._execute_command(
                "Get-ADDomain | Select-Object -ExpandProperty DomainMode"
            )
            if os_result.get("success"):
                profile.domain_functional_level = str(os_result.get("output", "")).strip()

            dc_result = await self._execute_command(
                "Get-ADDomainController -Filter * | Measure-Object | Select-Object -ExpandProperty Count"
            )
            if dc_result.get("success"):
                try:
                    profile.total_domain_controllers = int(str(dc_result.get("output", "")).strip())
                except ValueError:
                    pass

            user_result = await self._execute_command(
                "Get-ADUser -Filter * | Measure-Object | Select-Object -ExpandProperty Count"
            )
            if user_result.get("success"):
                try:
                    profile.total_users = int(str(user_result.get("output", "")).strip())
                except ValueError:
                    pass

            siem_result = await self._execute_command(
                "Get-Service -Name *SIEM*, *Splunk*, *QRadar* -ErrorAction SilentlyContinue"
            )
            profile.siem_enabled = siem_result.get("success", False)

            mdi_result = await self._execute_command(
                "Get-ADComputer -LDAPFilter \"(servicePrincipalName=*MDI*)\" | Measure-Object | Select-Object -ExpandProperty Count"
            )
            profile.mdi_enabled = mdi_result.get("success", False)

            adcs_result = await self._execute_command(
                "Get-ADObject -LDAPFilter \"(objectClass=pKIEnrollmentService)\" | Measure-Object | Select-Object -ExpandProperty Count"
            )
            profile.adcs_enabled = adcs_result.get("success", False)

            self._environment_profile = profile
            await self._report_log("域环境分析完成")

        except Exception as e:
            await self._report_log(f"域环境分析失败: {e}")
            logger.error("Environment profiling failed: %s", e)

        return profile

    async def record_attack_outcome(self, record: AttackRecord) -> bool:
        """Record attack outcome for learning.

        Args:
            record: Attack record.

        Returns:
            True if recording successful.
        """
        try:
            record.timestamp = time.time()
            self._attack_records.append(record)

            await self._report_log(
                f"记录攻击结果: {record.technique.value} - "
                f"{'成功' if record.success else '失败'}"
            )

            if len(self._attack_records) >= 10:
                await self._sync_to_knowledge_base()

            return True

        except Exception as e:
            logger.error("Attack recording failed: %s", e)
            return False

    async def _sync_to_knowledge_base(self) -> bool:
        """Synchronize attack records to community knowledge base.

        Returns:
            True if synchronization successful.
        """
        try:
            anonymized_records = []
            for record in self._attack_records[-10:]:
                anon_record = {
                    "technique": record.technique.value,
                    "success": record.success,
                    "duration_seconds": record.duration_seconds,
                    "detection_triggered": record.detection_triggered,
                    "environment_profile": record.environment_profile,
                }
                anonymized_records.append(anon_record)

            self._knowledge_base["records"] = anonymized_records
            self._knowledge_base["last_sync"] = time.time()

            await self._report_log("攻击记录已匿名化并同步到知识库")
            return True

        except Exception as e:
            logger.error("Knowledge base sync failed: %s", e)
            return False

    async def get_learning_recommendations(self) -> List[Dict[str, Any]]:
        """Get learning-based attack recommendations.

        Returns:
            List of recommendations.
        """
        recommendations: List[Dict[str, Any]] = []

        try:
            technique_stats: Dict[str, Dict[str, int]] = {}

            for record in self._attack_records:
                tech = record.technique.value
                if tech not in technique_stats:
                    technique_stats[tech] = {"success": 0, "total": 0}
                technique_stats[tech]["total"] += 1
                if record.success:
                    technique_stats[tech]["success"] += 1

            for tech, stats in technique_stats.items():
                if stats["total"] >= 3:
                    success_rate = stats["success"] / stats["total"]
                    recommendations.append({
                        "technique": tech,
                        "success_rate": success_rate,
                        "attempts": stats["total"],
                        "recommended": success_rate > 0.7,
                    })

            recommendations.sort(key=lambda r: r["success_rate"], reverse=True)

        except Exception as e:
            logger.error("Learning recommendations failed: %s", e)

        return recommendations
