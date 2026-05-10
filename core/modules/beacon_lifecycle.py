"""
Beacon Lifecycle Management Module - Lifecycle policies, auto-destruction, key rotation.

This module provides:
    1. Beacon lifecycle policies (short-term, mid-term, long-term)
    2. Automatic cleanup on lifecycle expiration
    3. Manual lifecycle extension or termination
    4. Automated key rotation with seamless switching
    5. Old key retention for pending task decryption

Core capabilities:
    - Lifecycle type management (24h/7d/90d)
    - Automatic cleanup procedures
    - Key rotation with zero downtime
    - Graceful key retirement and destruction

Author: Kunlun Security Lab
License: Internal Use Only
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import logging
import os
import secrets
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Coroutine, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


# =============================================================================
# Enums
# =============================================================================

class LifecycleType(str, Enum):
    """Beacon lifecycle types."""

    SHORT_TERM = "short_term"
    MID_TERM = "mid_term"
    LONG_TERM = "long_term"


class BeaconState(str, Enum):
    """Beacon operational states."""

    ACTIVE = "active"
    SLEEPING = "sleeping"
    CLEANING = "cleaning"
    DESTROYED = "destroyed"
    TERMINATED = "terminated"


class CleanupPhase(str, Enum):
    """Cleanup execution phases."""

    REMOVE_PERSISTENCE = "remove_persistence"
    DELETE_LOGS = "delete_logs"
    OVERWRITE_MEMORY = "overwrite_memory"
    SELF_DELETE = "self_delete"
    COMPLETE = "complete"


# =============================================================================
# Data Models
# =============================================================================

@dataclass
class LifecyclePolicy:
    """Lifecycle policy configuration.

    Attributes:
        lifecycle_type: Type of lifecycle
        duration_hours: Total duration in hours
        key_rotation_hours: Key rotation interval
        cleanup_enabled: Whether to run cleanup on expiry
        auto_extend: Whether to auto-extend on activity
    """

    lifecycle_type: LifecycleType = LifecycleType.SHORT_TERM
    duration_hours: float = 24.0
    key_rotation_hours: float = 24.0
    cleanup_enabled: bool = True
    auto_extend: bool = False

    @classmethod
    def short_term(cls) -> "LifecyclePolicy":
        """Create short-term policy (24h)."""
        return cls(
            lifecycle_type=LifecycleType.SHORT_TERM,
            duration_hours=24.0,
            key_rotation_hours=12.0,
            cleanup_enabled=True,
            auto_extend=False,
        )

    @classmethod
    def mid_term(cls) -> "LifecyclePolicy":
        """Create mid-term policy (7 days)."""
        return cls(
            lifecycle_type=LifecycleType.MID_TERM,
            duration_hours=168.0,
            key_rotation_hours=24.0,
            cleanup_enabled=True,
            auto_extend=False,
        )

    @classmethod
    def long_term(cls) -> "LifecyclePolicy":
        """Create long-term policy (90 days)."""
        return cls(
            lifecycle_type=LifecycleType.LONG_TERM,
            duration_hours=2160.0,
            key_rotation_hours=48.0,
            cleanup_enabled=True,
            auto_extend=True,
        )


@dataclass
class EncryptionKey:
    """Encryption key record.

    Attributes:
        key_id: Unique key identifier
        key_material: Key bytes
        created_at: Creation timestamp
        expires_at: Expiration timestamp
        is_active: Whether key is currently active
        is_retired: Whether key is retired but still valid for decryption
    """

    key_id: str = ""
    key_material: bytes = b""
    created_at: float = 0.0
    expires_at: float = 0.0
    is_active: bool = False
    is_retired: bool = False

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "key_id": self.key_id,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "is_active": self.is_active,
            "is_retired": self.is_retired,
        }


@dataclass
class BeaconLifecycle:
    """Beacon lifecycle state.

    Attributes:
        beacon_id: Beacon identifier
        policy: Lifecycle policy
        state: Current beacon state
        created_at: Creation timestamp
        expires_at: Expiration timestamp
        last_key_rotation: Last key rotation timestamp
        active_keys: Currently active keys
        retired_keys: Retired keys still valid for decryption
        cleanup_phase: Current cleanup phase
        cleanup_progress: Cleanup progress (0-1)
    """

    beacon_id: str = ""
    policy: Optional[LifecyclePolicy] = None
    state: BeaconState = BeaconState.ACTIVE
    created_at: float = 0.0
    expires_at: float = 0.0
    last_key_rotation: float = 0.0
    active_keys: List[EncryptionKey] = field(default_factory=list)
    retired_keys: List[EncryptionKey] = field(default_factory=list)
    cleanup_phase: CleanupPhase = CleanupPhase.REMOVE_PERSISTENCE
    cleanup_progress: float = 0.0

    @property
    def time_remaining(self) -> float:
        """Get remaining time in hours."""
        if self.state in (BeaconState.DESTROYED, BeaconState.TERMINATED):
            return 0.0
        remaining = self.expires_at - time.time()
        return max(0.0, remaining / 3600)

    @property
    def is_expired(self) -> bool:
        """Check if lifecycle has expired."""
        return time.time() >= self.expires_at

    @property
    def active_key_count(self) -> int:
        """Get count of active keys."""
        return len(self.active_keys)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "beacon_id": self.beacon_id,
            "policy_type": self.policy.lifecycle_type.value if self.policy else None,
            "state": self.state.value,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "time_remaining_hours": round(self.time_remaining, 2),
            "is_expired": self.is_expired,
            "active_key_count": self.active_key_count,
            "cleanup_phase": self.cleanup_phase.value,
            "cleanup_progress": self.cleanup_progress,
        }


# =============================================================================
# Key Manager
# =============================================================================

class KeyManager:
    """Manages encryption key lifecycle.

    Handles key generation, rotation, retirement,
    and secure destruction.

    Attributes:
        _key_retention_hours: Hours to retain old keys
        _key_size: Key size in bytes
    """

    def __init__(
        self,
        key_retention_hours: float = 48.0,
        key_size: int = 32,
    ) -> None:
        """Initialize the KeyManager.

        Args:
            key_retention_hours: Hours to retain retired keys.
            key_size: Key size in bytes.
        """
        self._key_retention_hours = key_retention_hours
        self._key_size = key_size

    def generate_key(self, duration_hours: float = 24.0) -> EncryptionKey:
        """Generate a new encryption key.

        Args:
            duration_hours: Key validity duration.

        Returns:
            New EncryptionKey.
        """
        key_id = hashlib.sha256(
            f"key_{time.time()}_{secrets.token_hex(8)}".encode()
        ).hexdigest()[:16]

        now = time.time()

        return EncryptionKey(
            key_id=key_id,
            key_material=secrets.token_bytes(self._key_size),
            created_at=now,
            expires_at=now + (duration_hours * 3600),
            is_active=True,
            is_retired=False,
        )

    def rotate_key(
        self,
        active_keys: List[EncryptionKey],
        retired_keys: List[EncryptionKey],
        duration_hours: float = 24.0,
    ) -> Tuple[List[EncryptionKey], List[EncryptionKey]]:
        """Rotate encryption keys.

        Args:
            active_keys: Current active keys.
            retired_keys: Current retired keys.
            duration_hours: New key duration.

        Returns:
            Tuple of (new_active_keys, new_retired_keys).
        """
        new_active: List[EncryptionKey] = []
        new_retired: List[EncryptionKey] = []

        now = time.time()
        retention_cutoff = now - (self._key_retention_hours * 3600)

        for key in active_keys:
            key.is_active = False
            key.is_retired = True
            new_retired.append(key)

        for key in retired_keys:
            if key.expires_at > retention_cutoff:
                new_retired.append(key)

        new_key = self.generate_key(duration_hours)
        new_active.append(new_key)

        logger.info(
            f"Key rotated: new key {new_key.key_id}, "
            f"{len(new_retired)} keys retired"
        )

        return new_active, new_retired

    def get_active_key(
        self, active_keys: List[EncryptionKey],
    ) -> Optional[EncryptionKey]:
        """Get the current active key.

        Args:
            active_keys: List of active keys.

        Returns:
            Active EncryptionKey, or None.
        """
        for key in active_keys:
            if key.is_active:
                return key
        return None

    def find_decryption_key(
        self,
        key_id: str,
        active_keys: List[EncryptionKey],
        retired_keys: List[EncryptionKey],
    ) -> Optional[EncryptionKey]:
        """Find key for decryption by ID.

        Args:
            key_id: Key identifier.
            active_keys: Active keys.
            retired_keys: Retired keys.

        Returns:
            Matching EncryptionKey, or None.
        """
        for key in active_keys + retired_keys:
            if key.key_id == key_id:
                return key
        return None

    def destroy_expired_keys(
        self,
        retired_keys: List[EncryptionKey],
    ) -> List[EncryptionKey]:
        """Destroy keys past retention period.

        Args:
            retired_keys: Retired keys to check.

        Returns:
            Remaining valid keys.
        """
        now = time.time()
        retention_cutoff = now - (self._key_retention_hours * 3600)

        valid_keys: List[EncryptionKey] = []

        for key in retired_keys:
            if key.expires_at > retention_cutoff:
                valid_keys.append(key)
            else:
                key.key_material = b"\x00" * len(key.key_material)
                logger.info(f"Key {key.key_id} securely destroyed")

        return valid_keys


# =============================================================================
# Cleanup Engine
# =============================================================================

class CleanupEngine:
    """Executes beacon cleanup procedures.

    Performs systematic cleanup: persistence removal,
    log deletion, memory overwrite, and self-deletion.

    Attributes:
        _cleanup_callbacks: Registered cleanup callbacks
    """

    def __init__(self) -> None:
        """Initialize the CleanupEngine."""
        self._cleanup_callbacks: Dict[
            CleanupPhase, Callable[..., Coroutine[Any, Any, bool]]
        ] = {}

    def register_callback(
        self,
        phase: CleanupPhase,
        callback: Callable[..., Coroutine[Any, Any, bool]],
    ) -> None:
        """Register a cleanup callback.

        Args:
            phase: Cleanup phase.
            callback: Async callback function.
        """
        self._cleanup_callbacks[phase] = callback

    async def execute_cleanup(
        self,
        beacon_id: str,
        progress_callback: Optional[
            Callable[[CleanupPhase, float], None]
        ] = None,
    ) -> bool:
        """Execute full cleanup sequence.

        Args:
            beacon_id: Beacon identifier.
            progress_callback: Optional progress callback.

        Returns:
            True if cleanup completed successfully.
        """
        phases = [
            CleanupPhase.REMOVE_PERSISTENCE,
            CleanupPhase.DELETE_LOGS,
            CleanupPhase.OVERWRITE_MEMORY,
            CleanupPhase.SELF_DELETE,
        ]

        for i, phase in enumerate(phases):
            callback = self._cleanup_callbacks.get(phase)

            if callback:
                success = await callback(beacon_id)
                if not success:
                    logger.warning(
                        f"Cleanup phase {phase.value} failed for {beacon_id}"
                    )
            else:
                success = True

            progress = (i + 1) / len(phases)

            if progress_callback:
                progress_callback(phase, progress)

            await asyncio.sleep(0.1)

        return True


# =============================================================================
# Beacon Lifecycle Manager
# =============================================================================

class BeaconLifecycleManager:
    """Main beacon lifecycle coordination engine.

    Manages beacon lifecycles, key rotation,
    and cleanup procedures.

    Attributes:
        _lifecycles: Beacon lifecycle records
        _key_manager: Encryption key manager
        _cleanup_engine: Cleanup engine
        _running: Whether manager is running
    """

    def __init__(self) -> None:
        """Initialize the BeaconLifecycleManager."""
        self._lifecycles: Dict[str, BeaconLifecycle] = {}
        self._key_manager = KeyManager()
        self._cleanup_engine = CleanupEngine()
        self._running = False

    def create_lifecycle(
        self,
        beacon_id: str,
        policy: Optional[LifecyclePolicy] = None,
    ) -> BeaconLifecycle:
        """Create a new beacon lifecycle.

        Args:
            beacon_id: Beacon identifier.
            policy: Lifecycle policy.

        Returns:
            Created BeaconLifecycle.
        """
        policy = policy or LifecyclePolicy.short_term()

        now = time.time()
        initial_key = self._key_manager.generate_key(policy.key_rotation_hours)

        lifecycle = BeaconLifecycle(
            beacon_id=beacon_id,
            policy=policy,
            state=BeaconState.ACTIVE,
            created_at=now,
            expires_at=now + (policy.duration_hours * 3600),
            last_key_rotation=now,
            active_keys=[initial_key],
            retired_keys=[],
        )

        self._lifecycles[beacon_id] = lifecycle

        logger.info(
            f"Lifecycle created for {beacon_id}: "
            f"type={policy.lifecycle_type.value}, "
            f"duration={policy.duration_hours}h"
        )

        return lifecycle

    def extend_lifecycle(
        self,
        beacon_id: str,
        additional_hours: float,
    ) -> bool:
        """Extend a beacon lifecycle.

        Args:
            beacon_id: Beacon identifier.
            additional_hours: Hours to extend.

        Returns:
            True if extended successfully.
        """
        lifecycle = self._lifecycles.get(beacon_id)
        if not lifecycle:
            return False

        if lifecycle.state in (BeaconState.DESTROYED, BeaconState.TERMINATED):
            return False

        lifecycle.expires_at += additional_hours * 3600

        if lifecycle.policy and lifecycle.policy.auto_extend:
            lifecycle.policy.duration_hours += additional_hours

        logger.info(
            f"Lifecycle extended for {beacon_id}: "
            f"+{additional_hours}h, new expiry: "
            f"{lifecycle.time_remaining:.1f}h remaining"
        )

        return True

    def terminate_lifecycle(self, beacon_id: str) -> bool:
        """Terminate a beacon lifecycle immediately.

        Args:
            beacon_id: Beacon identifier.

        Returns:
            True if terminated successfully.
        """
        lifecycle = self._lifecycles.get(beacon_id)
        if not lifecycle:
            return False

        lifecycle.state = BeaconState.TERMINATED
        lifecycle.expires_at = time.time()

        for key in lifecycle.active_keys:
            key.is_active = False
            key.key_material = b"\x00" * len(key.key_material)

        logger.info(f"Lifecycle terminated for {beacon_id}")
        return True

    async def rotate_keys(self, beacon_id: str) -> bool:
        """Rotate encryption keys for a beacon.

        Args:
            beacon_id: Beacon identifier.

        Returns:
            True if rotation succeeded.
        """
        lifecycle = self._lifecycles.get(beacon_id)
        if not lifecycle or not lifecycle.policy:
            return False

        if lifecycle.state != BeaconState.ACTIVE:
            return False

        new_active, new_retired = self._key_manager.rotate_key(
            lifecycle.active_keys,
            lifecycle.retired_keys,
            lifecycle.policy.key_rotation_hours,
        )

        lifecycle.active_keys = new_active
        lifecycle.retired_keys = new_retired
        lifecycle.last_key_rotation = time.time()

        logger.info(f"Keys rotated for {beacon_id}")
        return True

    async def check_and_cleanup(self) -> List[str]:
        """Check for expired lifecycles and run cleanup.

        Returns:
            List of beacon IDs that were cleaned up.
        """
        cleaned: List[str] = []

        for beacon_id, lifecycle in list(self._lifecycles.items()):
            if lifecycle.state != BeaconState.ACTIVE:
                continue

            if lifecycle.is_expired:
                if lifecycle.policy and lifecycle.policy.cleanup_enabled:
                    await self._execute_cleanup(beacon_id)

                lifecycle.state = BeaconState.DESTROYED
                cleaned.append(beacon_id)

        return cleaned

    async def _execute_cleanup(self, beacon_id: str) -> bool:
        """Execute cleanup for a beacon.

        Args:
            beacon_id: Beacon identifier.

        Returns:
            True if cleanup succeeded.
        """
        lifecycle = self._lifecycles.get(beacon_id)
        if not lifecycle:
            return False

        lifecycle.state = BeaconState.CLEANING

        def on_progress(phase: CleanupPhase, progress: float) -> None:
            lifecycle.cleanup_phase = phase
            lifecycle.cleanup_progress = progress

        success = await self._cleanup_engine.execute_cleanup(
            beacon_id, on_progress,
        )

        lifecycle.cleanup_phase = CleanupPhase.COMPLETE
        lifecycle.cleanup_progress = 1.0

        for key in lifecycle.active_keys + lifecycle.retired_keys:
            key.key_material = b"\x00" * len(key.key_material)

        return success

    def get_lifecycle(self, beacon_id: str) -> Optional[BeaconLifecycle]:
        """Get a beacon lifecycle.

        Args:
            beacon_id: Beacon identifier.

        Returns:
            BeaconLifecycle, or None.
        """
        return self._lifecycles.get(beacon_id)

    def get_all_lifecycles(self) -> List[BeaconLifecycle]:
        """Get all beacon lifecycles.

        Returns:
            List of BeaconLifecycle.
        """
        return list(self._lifecycles.values())

    def get_active_beacons(self) -> List[BeaconLifecycle]:
        """Get all active beacon lifecycles.

        Returns:
            List of active BeaconLifecycle.
        """
        return [
            lc for lc in self._lifecycles.values()
            if lc.state == BeaconState.ACTIVE
        ]

    def get_status(self) -> Dict[str, Any]:
        """Get lifecycle manager status.

        Returns:
            Dictionary with status summary.
        """
        total = len(self._lifecycles)
        active = len(self.get_active_beacons())
        destroyed = sum(
            1 for lc in self._lifecycles.values()
            if lc.state == BeaconState.DESTROYED
        )
        terminated = sum(
            1 for lc in self._lifecycles.values()
            if lc.state == BeaconState.TERMINATED
        )

        return {
            "total_beacons": total,
            "active": active,
            "destroyed": destroyed,
            "terminated": terminated,
            "cleanup_in_progress": sum(
                1 for lc in self._lifecycles.values()
                if lc.state == BeaconState.CLEANING
            ),
        }


# =============================================================================
# Global Singleton
# =============================================================================

_lifecycle_manager: Optional[BeaconLifecycleManager] = None


def get_lifecycle_manager() -> BeaconLifecycleManager:
    """Get the global BeaconLifecycleManager singleton.

    Returns:
        Singleton BeaconLifecycleManager instance.
    """
    global _lifecycle_manager
    if _lifecycle_manager is None:
        _lifecycle_manager = BeaconLifecycleManager()
    return _lifecycle_manager


__all__ = [
    "BeaconLifecycleManager",
    "LifecyclePolicy",
    "BeaconLifecycle",
    "EncryptionKey",
    "KeyManager",
    "CleanupEngine",
    "LifecycleType",
    "BeaconState",
    "CleanupPhase",
    "get_lifecycle_manager",
]
