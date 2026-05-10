"""Collaboration Dashboard: Real-time war room panel, attack progress visualization, member statistics.

Provides:
- Project dashboard: discovered assets/confirmed vulnerabilities/controlled hosts/obtained credentials
- Attack progress bar: visualization of attack stages for each target
- Member contribution statistics: asset discovery/vulnerability discovery/credential acquisition rankings
- High-risk alerts: notifications to all members when severe vulnerabilities are found
"""

import asyncio
import logging
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Callable, Coroutine, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


class AttackStage(Enum):
    """Stages of the attack lifecycle."""
    RECONNAISSANCE = "reconnaissance"
    ENUMERATION = "enumeration"
    VULNERABILITY_DISCOVERY = "vulnerability_discovery"
    EXPLOITATION = "exploitation"
    POST_EXPLOITATION = "post_exploitation"
    LATERAL_MOVEMENT = "lateral_movement"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DATA_EXFILTRATION = "data_exfiltration"
    COMPLETED = "completed"


@dataclass
class TargetProgress:
    """Attack progress for a specific target.

    Attributes:
        target_id: Target identifier (IP/domain)
        target_name: Display name of target
        current_stage: Current attack stage
        stage_progress: Progress within current stage (0-100)
        overall_progress: Overall progress across all stages (0-100)
        assets_found: Number of assets discovered
        vulnerabilities_found: Number of vulnerabilities found
        credentials_obtained: Number of credentials obtained
        is_compromised: Whether target is fully compromised
        last_updated: Last update timestamp
    """
    target_id: str = ""
    target_name: str = ""
    current_stage: AttackStage = AttackStage.RECONNAISSANCE
    stage_progress: float = 0.0
    overall_progress: float = 0.0
    assets_found: int = 0
    vulnerabilities_found: int = 0
    credentials_obtained: int = 0
    is_compromised: bool = False
    last_updated: float = 0.0


@dataclass
class MemberContribution:
    """Contribution statistics for a team member.

    Attributes:
        member_id: Member identifier
        member_name: Display name
        assets_discovered: Number of assets discovered
        vulnerabilities_found: Number of vulnerabilities found
        credentials_obtained: Number of credentials obtained
        tasks_completed: Number of tasks completed
        messages_sent: Number of messages sent
        operations_count: Total operations performed
        last_active: Last active timestamp
    """
    member_id: str = ""
    member_name: str = ""
    assets_discovered: int = 0
    vulnerabilities_found: int = 0
    credentials_obtained: int = 0
    tasks_completed: int = 0
    messages_sent: int = 0
    operations_count: int = 0
    last_active: float = 0.0


@dataclass
class DashboardData:
    """Complete dashboard data for a project.

    Attributes:
        project_id: Project identifier
        total_assets: Total discovered assets
        total_vulnerabilities: Total vulnerabilities found
        total_credentials: Total credentials obtained
        total_tasks: Total tasks created
        completed_tasks: Completed tasks count
        active_members: Currently active members count
        high_risk_alerts: List of high-risk alert messages
        target_progress: Progress for each target
        member_contributions: Contribution stats for each member
        updated_at: Dashboard last updated timestamp
    """
    project_id: str = ""
    total_assets: int = 0
    total_vulnerabilities: int = 0
    total_credentials: int = 0
    total_tasks: int = 0
    completed_tasks: int = 0
    active_members: int = 0
    high_risk_alerts: List[str] = field(default_factory=list)
    target_progress: List[TargetProgress] = field(default_factory=list)
    member_contributions: List[MemberContribution] = field(default_factory=list)
    updated_at: float = 0.0


class DashboardManager:
    """Manages the real-time war room dashboard for project operations.

    Provides project dashboard metrics, attack progress visualization,
    member contribution statistics, and high-risk alert notifications.
    """

    def __init__(self) -> None:
        """Initialize dashboard manager."""
        self._project_dashboards: Dict[str, DashboardData] = {}
        self._target_progress: Dict[str, Dict[str, TargetProgress]] = {}
        self._member_contributions: Dict[str, Dict[str, MemberContribution]] = {}
        self._alert_callbacks: List[Callable[[str, str], Coroutine[Any, Any, None]]] = []
        self._update_callbacks: List[Callable[[str, DashboardData], Coroutine[Any, Any, None]]] = []

    def register_alert_callback(
        self,
        callback: Callable[[str, str], Coroutine[Any, Any, None]],
    ) -> None:
        """Register callback for high-risk alerts.

        Args:
            callback: Async callback receiving project_id and alert message.
        """
        self._alert_callbacks.append(callback)

    def register_update_callback(
        self,
        callback: Callable[[str, DashboardData], Coroutine[Any, Any, None]],
    ) -> None:
        """Register callback for dashboard updates.

        Args:
            callback: Async callback receiving project_id and dashboard data.
        """
        self._update_callbacks.append(callback)

    def initialize_project(self, project_id: str) -> None:
        """Initialize dashboard for a new project.

        Args:
            project_id: Project identifier.
        """
        self._project_dashboards[project_id] = DashboardData(
            project_id=project_id,
            updated_at=time.time(),
        )
        self._target_progress[project_id] = {}
        self._member_contributions[project_id] = {}

    def update_project_metrics(
        self,
        project_id: str,
        total_assets: Optional[int] = None,
        total_vulnerabilities: Optional[int] = None,
        total_credentials: Optional[int] = None,
        total_tasks: Optional[int] = None,
        completed_tasks: Optional[int] = None,
        active_members: Optional[int] = None,
    ) -> None:
        """Update project-level metrics.

        Args:
            project_id: Project identifier.
            total_assets: Total discovered assets.
            total_vulnerabilities: Total vulnerabilities found.
            total_credentials: Total credentials obtained.
            total_tasks: Total tasks created.
            completed_tasks: Completed tasks count.
            active_members: Currently active members count.
        """
        dashboard = self._project_dashboards.get(project_id)
        if not dashboard:
            self.initialize_project(project_id)
            dashboard = self._project_dashboards[project_id]

        if total_assets is not None:
            dashboard.total_assets = total_assets
        if total_vulnerabilities is not None:
            dashboard.total_vulnerabilities = total_vulnerabilities
        if total_credentials is not None:
            dashboard.total_credentials = total_credentials
        if total_tasks is not None:
            dashboard.total_tasks = total_tasks
        if completed_tasks is not None:
            dashboard.completed_tasks = completed_tasks
        if active_members is not None:
            dashboard.active_members = active_members

        dashboard.updated_at = time.time()

    def update_target_progress(
        self,
        project_id: str,
        target_id: str,
        target_name: str,
        current_stage: Optional[AttackStage] = None,
        stage_progress: Optional[float] = None,
        assets_found: Optional[int] = None,
        vulnerabilities_found: Optional[int] = None,
        credentials_obtained: Optional[int] = None,
        is_compromised: Optional[bool] = None,
    ) -> None:
        """Update attack progress for a specific target.

        Args:
            project_id: Project identifier.
            target_id: Target identifier.
            target_name: Display name of target.
            current_stage: Current attack stage.
            stage_progress: Progress within current stage.
            assets_found: Number of assets discovered.
            vulnerabilities_found: Number of vulnerabilities found.
            credentials_obtained: Number of credentials obtained.
            is_compromised: Whether target is fully compromised.
        """
        if project_id not in self._target_progress:
            self._target_progress[project_id] = {}

        progress = self._target_progress[project_id].get(target_id)
        if not progress:
            progress = TargetProgress(
                target_id=target_id,
                target_name=target_name,
                last_updated=time.time(),
            )
            self._target_progress[project_id][target_id] = progress

        if current_stage is not None:
            progress.current_stage = current_stage
        if stage_progress is not None:
            progress.stage_progress = max(0.0, min(100.0, stage_progress))
        if assets_found is not None:
            progress.assets_found = assets_found
        if vulnerabilities_found is not None:
            progress.vulnerabilities_found = vulnerabilities_found
        if credentials_obtained is not None:
            progress.credentials_obtained = credentials_obtained
        if is_compromised is not None:
            progress.is_compromised = is_compromised

        progress.last_updated = time.time()

        self._recalculate_overall_progress(progress)

        dashboard = self._project_dashboards.get(project_id)
        if dashboard:
            dashboard.target_progress = list(self._target_progress[project_id].values())
            dashboard.updated_at = time.time()

    def increment_member_contribution(
        self,
        project_id: str,
        member_id: str,
        member_name: str,
        assets_discovered: int = 0,
        vulnerabilities_found: int = 0,
        credentials_obtained: int = 0,
        tasks_completed: int = 0,
        messages_sent: int = 0,
    ) -> None:
        """Increment member contribution statistics.

        Args:
            project_id: Project identifier.
            member_id: Member identifier.
            member_name: Display name.
            assets_discovered: Assets discovered count to add.
            vulnerabilities_found: Vulnerabilities found count to add.
            credentials_obtained: Credentials obtained count to add.
            tasks_completed: Tasks completed count to add.
            messages_sent: Messages sent count to add.
        """
        if project_id not in self._member_contributions:
            self._member_contributions[project_id] = {}

        contribution = self._member_contributions[project_id].get(member_id)
        if not contribution:
            contribution = MemberContribution(
                member_id=member_id,
                member_name=member_name,
                last_active=time.time(),
            )
            self._member_contributions[project_id][member_id] = contribution

        contribution.assets_discovered += assets_discovered
        contribution.vulnerabilities_found += vulnerabilities_found
        contribution.credentials_obtained += credentials_obtained
        contribution.tasks_completed += tasks_completed
        contribution.messages_sent += messages_sent
        contribution.operations_count += (
            assets_discovered + vulnerabilities_found + credentials_obtained + tasks_completed + messages_sent
        )
        contribution.last_active = time.time()

        dashboard = self._project_dashboards.get(project_id)
        if dashboard:
            dashboard.member_contributions = list(self._member_contributions[project_id].values())
            dashboard.updated_at = time.time()

    async def add_high_risk_alert(self, project_id: str, alert_message: str) -> None:
        """Add a high-risk alert and notify all members.

        Args:
            project_id: Project identifier.
            alert_message: Alert message.
        """
        dashboard = self._project_dashboards.get(project_id)
        if not dashboard:
            self.initialize_project(project_id)
            dashboard = self._project_dashboards[project_id]

        dashboard.high_risk_alerts.append(alert_message)

        if len(dashboard.high_risk_alerts) > 50:
            dashboard.high_risk_alerts = dashboard.high_risk_alerts[-50:]

        dashboard.updated_at = time.time()

        for callback in self._alert_callbacks:
            try:
                await callback(project_id, alert_message)
            except Exception as e:
                logger.error(f"Alert callback error: {e}")

    def get_dashboard(self, project_id: str) -> DashboardData:
        """Get complete dashboard data for a project.

        Args:
            project_id: Project identifier.

        Returns:
            DashboardData object.
        """
        dashboard = self._project_dashboards.get(project_id)
        if not dashboard:
            self.initialize_project(project_id)
            dashboard = self._project_dashboards[project_id]

        return dashboard

    def get_member_rankings(
        self,
        project_id: str,
        metric: str = "operations_count",
    ) -> List[MemberContribution]:
        """Get member rankings by a specific metric.

        Args:
            project_id: Project identifier.
            metric: Metric to rank by (assets_discovered, vulnerabilities_found, etc.).

        Returns:
            List of MemberContribution sorted by metric (descending).
        """
        contributions = self._member_contributions.get(project_id, {}).values()

        return sorted(
            contributions,
            key=lambda c: getattr(c, metric, 0),
            reverse=True,
        )

    def get_compromised_targets(self, project_id: str) -> List[TargetProgress]:
        """Get list of fully compromised targets.

        Args:
            project_id: Project identifier.

        Returns:
            List of compromised TargetProgress objects.
        """
        targets = self._target_progress.get(project_id, {}).values()

        return [t for t in targets if t.is_compromised]

    def get_attack_stage_summary(self, project_id: str) -> Dict[str, int]:
        """Get summary of targets by attack stage.

        Args:
            project_id: Project identifier.

        Returns:
            Dictionary mapping attack stage to target count.
        """
        targets = self._target_progress.get(project_id, {}).values()

        summary: Dict[str, int] = {}
        for target in targets:
            stage_name = target.current_stage.value
            summary[stage_name] = summary.get(stage_name, 0) + 1

        return summary

    def clear_alerts(self, project_id: str) -> None:
        """Clear all high-risk alerts for a project.

        Args:
            project_id: Project identifier.
        """
        dashboard = self._project_dashboards.get(project_id)
        if dashboard:
            dashboard.high_risk_alerts.clear()
            dashboard.updated_at = time.time()

    def _recalculate_overall_progress(self, progress: TargetProgress) -> None:
        """Recalculate overall progress based on current stage and stage progress.

        Args:
            progress: TargetProgress to update.
        """
        stage_order = list(AttackStage)
        try:
            current_index = stage_order.index(progress.current_stage)
        except ValueError:
            current_index = 0

        total_stages = len(stage_order)
        base_progress = (current_index / total_stages) * 100
        stage_fraction = progress.stage_progress / 100.0
        stage_weight = 100.0 / total_stages

        progress.overall_progress = base_progress + (stage_fraction * stage_weight)
        progress.overall_progress = max(0.0, min(100.0, progress.overall_progress))

        if progress.current_stage == AttackStage.COMPLETED:
            progress.overall_progress = 100.0
            progress.is_compromised = True
