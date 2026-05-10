"""
C2 Observability Module - Beacon health monitoring, operational statistics, alerting.

This module provides:
    1. Beacon health monitoring dashboard
    2. Communication quality scoring
    3. Anomaly detection
    4. Operational data statistics and reporting
    5. Alert and notification system

Core capabilities:
    - Real-time beacon status tracking
    - Health score calculation
    - Communication quality metrics
    - Anomaly detection algorithms
    - Multi-channel alert notifications
    - Operational data analytics

Author: Kunlun Security Lab
License: Internal Use Only
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import math
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Coroutine, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


# =============================================================================
# Enums
# =============================================================================

class BeaconStatus(str, Enum):
    """Beacon operational status."""

    ONLINE = "online"
    OFFLINE = "offline"
    SLEEPING = "sleeping"
    DETECTED = "detected"
    COMPROMISED = "compromised"


class AlertSeverity(str, Enum):
    """Alert severity levels."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AlertType(str, Enum):
    """Alert types."""

    BEACON_OFFLINE = "beacon_offline"
    BEACON_DETECTED = "beacon_detected"
    ANOMALY_DETECTED = "anomaly_detected"
    LIFECYCLE_EXPIRED = "lifecycle_expired"
    COMMUNICATION_ERROR = "communication_error"
    KEY_ROTATION_FAILED = "key_rotation_failed"


class NotificationChannel(str, Enum):
    """Notification delivery channels."""

    WEBHOOK = "webhook"
    EMAIL = "email"
    SLACK = "slack"
    TELEGRAM = "telegram"
    DISCORD = "discord"


# =============================================================================
# Data Models
# =============================================================================

@dataclass
class BeaconHealthMetrics:
    """Beacon health metrics.

    Attributes:
        beacon_id: Beacon identifier
        status: Current beacon status
        last_seen: Last communication timestamp
        latency_ms: Average latency in milliseconds
        packet_loss_rate: Packet loss rate (0-1)
        throughput_bps: Data throughput in bytes per second
        camouflage_similarity: Camouflage similarity score (0-1)
        heartbeat_interval: Current heartbeat interval
        consecutive_failures: Consecutive communication failures
        total_uptime_hours: Total uptime in hours
        total_data_transferred_mb: Total data transferred in MB
    """

    beacon_id: str = ""
    status: BeaconStatus = BeaconStatus.OFFLINE
    last_seen: float = 0.0
    latency_ms: float = 0.0
    packet_loss_rate: float = 0.0
    throughput_bps: float = 0.0
    camouflage_similarity: float = 0.0
    heartbeat_interval: float = 0.0
    consecutive_failures: int = 0
    total_uptime_hours: float = 0.0
    total_data_transferred_mb: float = 0.0

    @property
    def health_score(self) -> float:
        """Calculate overall health score (0-1)."""
        latency_score = max(0, 1 - (self.latency_ms / 5000))
        packet_score = 1 - self.packet_loss_rate
        camouflage_score = self.camouflage_similarity
        failure_score = max(0, 1 - (self.consecutive_failures * 0.1))

        weights = {
            "latency": 0.25,
            "packet": 0.25,
            "camouflage": 0.3,
            "failure": 0.2,
        }

        return (
            latency_score * weights["latency"]
            + packet_score * weights["packet"]
            + camouflage_score * weights["camouflage"]
            + failure_score * weights["failure"]
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "beacon_id": self.beacon_id,
            "status": self.status.value,
            "health_score": round(self.health_score, 3),
            "latency_ms": round(self.latency_ms, 2),
            "packet_loss_rate": round(self.packet_loss_rate, 4),
            "camouflage_similarity": round(self.camouflage_similarity, 3),
            "consecutive_failures": self.consecutive_failures,
        }


@dataclass
class Alert:
    """System alert.

    Attributes:
        alert_id: Unique alert identifier
        alert_type: Type of alert
        severity: Alert severity
        beacon_id: Associated beacon ID
        message: Alert message
        timestamp: Alert timestamp
        acknowledged: Whether alert has been acknowledged
        metadata: Additional alert metadata
    """

    alert_id: str = ""
    alert_type: AlertType = AlertType.BEACON_OFFLINE
    severity: AlertSeverity = AlertSeverity.LOW
    beacon_id: str = ""
    message: str = ""
    timestamp: float = 0.0
    acknowledged: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "alert_id": self.alert_id,
            "alert_type": self.alert_type.value,
            "severity": self.severity.value,
            "beacon_id": self.beacon_id,
            "message": self.message,
            "timestamp": self.timestamp,
            "acknowledged": self.acknowledged,
        }


@dataclass
class NotificationConfig:
    """Notification configuration.

    Attributes:
        channel: Notification channel
        endpoint: Endpoint URL or address
        enabled: Whether notifications are enabled
        severity_threshold: Minimum severity to notify
    """

    channel: NotificationChannel = NotificationChannel.WEBHOOK
    endpoint: str = ""
    enabled: bool = True
    severity_threshold: AlertSeverity = AlertSeverity.MEDIUM


@dataclass
class OperationalStats:
    """Operational statistics.

    Attributes:
        profile_id: Profile identifier
        total_beacons: Total beacons using profile
        avg_lifetime_hours: Average beacon lifetime
        detection_count: Number of detections
        data_success_rate: Data transmission success rate
        avg_health_score: Average health score
        last_updated: Last statistics update
    """

    profile_id: str = ""
    total_beacons: int = 0
    avg_lifetime_hours: float = 0.0
    detection_count: int = 0
    data_success_rate: float = 0.0
    avg_health_score: float = 0.0
    last_updated: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "profile_id": self.profile_id,
            "total_beacons": self.total_beacons,
            "avg_lifetime_hours": round(self.avg_lifetime_hours, 2),
            "detection_count": self.detection_count,
            "data_success_rate": round(self.data_success_rate, 4),
            "avg_health_score": round(self.avg_health_score, 3),
        }


# =============================================================================
# Anomaly Detector
# =============================================================================

class AnomalyDetector:
    """Detects anomalous beacon behavior.

    Monitors heartbeat intervals, communication volumes,
    and connection patterns for anomalies.

    Attributes:
        _baseline_data: Historical baseline data
        _anomaly_threshold: Standard deviation threshold
    """

    def __init__(self, anomaly_threshold: float = 2.5) -> None:
        """Initialize the AnomalyDetector.

        Args:
            anomaly_threshold: Standard deviation threshold.
        """
        self._baseline_data: Dict[str, List[float]] = {}
        self._anomaly_threshold = anomaly_threshold

    def add_data_point(self, beacon_id: str, value: float) -> None:
        """Add a data point for anomaly detection.

        Args:
            beacon_id: Beacon identifier.
            value: Metric value.
        """
        if beacon_id not in self._baseline_data:
            self._baseline_data[beacon_id] = []

        self._baseline_data[beacon_id].append(value)

        if len(self._baseline_data[beacon_id]) > 1000:
            self._baseline_data[beacon_id] = self._baseline_data[beacon_id][-500:]

    def check_anomaly(self, beacon_id: str, value: float) -> bool:
        """Check if a value is anomalous.

        Args:
            beacon_id: Beacon identifier.
            value: Current metric value.

        Returns:
            True if value is anomalous.
        """
        data = self._baseline_data.get(beacon_id, [])

        if len(data) < 10:
            return False

        mean = sum(data) / len(data)
        variance = sum((x - mean) ** 2 for x in data) / len(data)
        std_dev = math.sqrt(variance)

        if std_dev == 0:
            return abs(value - mean) > 0.1

        z_score = abs(value - mean) / std_dev

        return z_score > self._anomaly_threshold

    def get_baseline(self, beacon_id: str) -> Dict[str, float]:
        """Get baseline statistics for a beacon.

        Args:
            beacon_id: Beacon identifier.

        Returns:
            Dictionary with baseline statistics.
        """
        data = self._baseline_data.get(beacon_id, [])

        if not data:
            return {}

        mean = sum(data) / len(data)
        variance = sum((x - mean) ** 2 for x in data) / len(data)

        return {
            "mean": mean,
            "std_dev": math.sqrt(variance),
            "min": min(data),
            "max": max(data),
            "sample_count": len(data),
        }


# =============================================================================
# Alert Manager
# =============================================================================

class AlertManager:
    """Manages alerts and notifications.

    Creates alerts, routes them through configured
    notification channels.

    Attributes:
        _alerts: All alerts
        _notification_configs: Notification configurations
        _alert_callbacks: Registered alert callbacks
    """

    def __init__(self) -> None:
        """Initialize the AlertManager."""
        self._alerts: List[Alert] = []
        self._notification_configs: List[NotificationConfig] = []
        self._alert_callbacks: List[
            Callable[[Alert], Coroutine[Any, Any, None]]
        ] = []

    def add_notification_config(
        self, config: NotificationConfig,
    ) -> None:
        """Add a notification configuration.

        Args:
            config: Notification configuration.
        """
        self._notification_configs.append(config)

    def register_callback(
        self,
        callback: Callable[[Alert], Coroutine[Any, Any, None]],
    ) -> None:
        """Register an alert callback.

        Args:
            callback: Async callback function.
        """
        self._alert_callbacks.append(callback)

    def create_alert(
        self,
        alert_type: AlertType,
        beacon_id: str,
        message: str,
        severity: Optional[AlertSeverity] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Alert:
        """Create a new alert.

        Args:
            alert_type: Type of alert.
            beacon_id: Associated beacon ID.
            message: Alert message.
            severity: Alert severity.
            metadata: Additional metadata.

        Returns:
            Created Alert.
        """
        if severity is None:
            severity = self._default_severity(alert_type)

        alert_id = hashlib.md5(
            f"alert_{time.time()}_{beacon_id}".encode()
        ).hexdigest()[:12]

        alert = Alert(
            alert_id=alert_id,
            alert_type=alert_type,
            severity=severity,
            beacon_id=beacon_id,
            message=message,
            timestamp=time.time(),
            metadata=metadata or {},
        )

        self._alerts.append(alert)

        logger.warning(
            f"Alert [{severity.value}] {alert_type.value}: {message}"
        )

        return alert

    async def dispatch_alert(self, alert: Alert) -> None:
        """Dispatch alert through notification channels.

        Args:
            alert: Alert to dispatch.
        """
        for config in self._notification_configs:
            if not config.enabled:
                continue

            if self._severity_rank(alert.severity) < self._severity_rank(
                config.severity_threshold,
            ):
                continue

            await self._send_notification(config, alert)

        for callback in self._alert_callbacks:
            try:
                await callback(alert)
            except Exception as e:
                logger.error(f"Alert callback failed: {e}")

    async def _send_notification(
        self,
        config: NotificationConfig,
        alert: Alert,
    ) -> None:
        """Send notification through a channel.

        Args:
            config: Notification configuration.
            alert: Alert to send.
        """
        payload = {
            "alert_id": alert.alert_id,
            "type": alert.alert_type.value,
            "severity": alert.severity.value,
            "beacon_id": alert.beacon_id,
            "message": alert.message,
            "timestamp": alert.timestamp,
        }

        if config.channel == NotificationChannel.WEBHOOK:
            await self._send_webhook(config.endpoint, payload)
        elif config.channel == NotificationChannel.EMAIL:
            await self._send_email(config.endpoint, payload)
        elif config.channel == NotificationChannel.SLACK:
            await self._send_slack(config.endpoint, payload)

    async def _send_webhook(
        self, url: str, payload: Dict[str, Any],
    ) -> None:
        """Send webhook notification.

        Args:
            url: Webhook URL.
            payload: Notification payload.
        """
        try:
            import aiohttp

            async with aiohttp.ClientSession() as session:
                async with session.post(
                    url,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as response:
                    if response.status == 200:
                        logger.info("Webhook notification sent")
        except Exception as e:
            logger.error(f"Webhook notification failed: {e}")

    async def _send_email(
        self, email: str, payload: Dict[str, Any],
    ) -> None:
        """Send email notification.

        Args:
            email: Recipient email.
            payload: Notification payload.
        """
        logger.info(f"Email notification to {email}: {payload['message']}")

    async def _send_slack(
        self, webhook_url: str, payload: Dict[str, Any],
    ) -> None:
        """Send Slack notification.

        Args:
            webhook_url: Slack webhook URL.
            payload: Notification payload.
        """
        slack_payload = {
            "text": f"[{payload['severity'].upper()}] {payload['message']}",
            "attachments": [
                {
                    "color": self._slack_color(payload["severity"]),
                    "fields": [
                        {"title": "Beacon", "value": payload["beacon_id"], "short": True},
                        {"title": "Type", "value": payload["type"], "short": True},
                    ],
                },
            ],
        }

        try:
            import aiohttp

            async with aiohttp.ClientSession() as session:
                async with session.post(
                    webhook_url,
                    json=slack_payload,
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as response:
                    if response.status == 200:
                        logger.info("Slack notification sent")
        except Exception as e:
            logger.error(f"Slack notification failed: {e}")

    def _default_severity(self, alert_type: AlertType) -> AlertSeverity:
        """Get default severity for alert type.

        Args:
            alert_type: Alert type.

        Returns:
            Default AlertSeverity.
        """
        severity_map = {
            AlertType.BEACON_OFFLINE: AlertSeverity.MEDIUM,
            AlertType.BEACON_DETECTED: AlertSeverity.CRITICAL,
            AlertType.ANOMALY_DETECTED: AlertSeverity.HIGH,
            AlertType.LIFECYCLE_EXPIRED: AlertSeverity.HIGH,
            AlertType.COMMUNICATION_ERROR: AlertSeverity.MEDIUM,
            AlertType.KEY_ROTATION_FAILED: AlertSeverity.HIGH,
        }
        return severity_map.get(alert_type, AlertSeverity.LOW)

    def _severity_rank(self, severity: AlertSeverity) -> int:
        """Get numeric rank for severity.

        Args:
            severity: Alert severity.

        Returns:
            Severity rank.
        """
        ranks = {
            AlertSeverity.LOW: 0,
            AlertSeverity.MEDIUM: 1,
            AlertSeverity.HIGH: 2,
            AlertSeverity.CRITICAL: 3,
        }
        return ranks.get(severity, 0)

    def _slack_color(self, severity: str) -> str:
        """Get Slack color for severity.

        Args:
            severity: Severity string.

        Returns:
            Color hex code.
        """
        colors = {
            "low": "#36a64f",
            "medium": "#ff9900",
            "high": "#ff6600",
            "critical": "#cc0000",
        }
        return colors.get(severity, "#36a64f")

    def get_unacknowledged_alerts(self) -> List[Alert]:
        """Get unacknowledged alerts.

        Returns:
            List of unacknowledged Alerts.
        """
        return [a for a in self._alerts if not a.acknowledged]

    def acknowledge_alert(self, alert_id: str) -> bool:
        """Acknowledge an alert.

        Args:
            alert_id: Alert identifier.

        Returns:
            True if acknowledged successfully.
        """
        for alert in self._alerts:
            if alert.alert_id == alert_id:
                alert.acknowledged = True
                return True
        return False


# =============================================================================
# C2 Observability Manager
# =============================================================================

class C2ObservabilityManager:
    """Main C2 observability coordination engine.

    Integrates health monitoring, anomaly detection,
    statistics, and alerting.

    Attributes:
        _beacon_metrics: Beacon health metrics
        _anomaly_detector: Anomaly detector
        _alert_manager: Alert manager
        _operational_stats: Operational statistics
        _offline_threshold_seconds: Offline detection threshold
    """

    def __init__(
        self,
        offline_threshold_seconds: float = 300.0,
    ) -> None:
        """Initialize the C2ObservabilityManager.

        Args:
            offline_threshold_seconds: Seconds before beacon is considered offline.
        """
        self._beacon_metrics: Dict[str, BeaconHealthMetrics] = {}
        self._anomaly_detector = AnomalyDetector()
        self._alert_manager = AlertManager()
        self._operational_stats: Dict[str, OperationalStats] = {}
        self._offline_threshold = offline_threshold_seconds

    def update_beacon_metrics(
        self,
        beacon_id: str,
        latency_ms: float,
        packet_loss: float,
        throughput: float,
        camouflage_score: float,
        heartbeat_interval: float,
    ) -> None:
        """Update beacon health metrics.

        Args:
            beacon_id: Beacon identifier.
            latency_ms: Latency in milliseconds.
            packet_loss: Packet loss rate.
            throughput: Data throughput.
            camouflage_score: Camouflage similarity.
            heartbeat_interval: Heartbeat interval.
        """
        if beacon_id not in self._beacon_metrics:
            self._beacon_metrics[beacon_id] = BeaconHealthMetrics(
                beacon_id=beacon_id,
                status=BeaconStatus.ONLINE,
            )

        metrics = self._beacon_metrics[beacon_id]
        metrics.last_seen = time.time()
        metrics.latency_ms = latency_ms
        metrics.packet_loss_rate = packet_loss
        metrics.throughput_bps = throughput
        metrics.camouflage_similarity = camouflage_score
        metrics.heartbeat_interval = heartbeat_interval
        metrics.status = BeaconStatus.ONLINE
        metrics.consecutive_failures = 0

        self._anomaly_detector.add_data_point(beacon_id, heartbeat_interval)
        self._anomaly_detector.add_data_point(beacon_id, throughput)

        if self._anomaly_detector.check_anomaly(beacon_id, heartbeat_interval):
            self._alert_manager.create_alert(
                AlertType.ANOMALY_DETECTED,
                beacon_id,
                f"Anomalous heartbeat interval: {heartbeat_interval:.1f}s",
                AlertSeverity.HIGH,
                {"metric": "heartbeat_interval", "value": heartbeat_interval},
            )

    def check_beacon_status(self) -> None:
        """Check all beacon statuses and generate alerts."""
        now = time.time()

        for beacon_id, metrics in self._beacon_metrics.items():
            if metrics.status == BeaconStatus.DETECTED:
                continue

            time_since_seen = now - metrics.last_seen

            if time_since_seen > self._offline_threshold:
                if metrics.status != BeaconStatus.OFFLINE:
                    metrics.status = BeaconStatus.OFFLINE
                    self._alert_manager.create_alert(
                        AlertType.BEACON_OFFLINE,
                        beacon_id,
                        f"Beacon offline for {time_since_seen / 60:.0f} minutes",
                        AlertSeverity.MEDIUM,
                        {"offline_duration": time_since_seen},
                    )

            if metrics.consecutive_failures > 5:
                self._alert_manager.create_alert(
                    AlertType.COMMUNICATION_ERROR,
                    beacon_id,
                    f"Consecutive failures: {metrics.consecutive_failures}",
                    AlertSeverity.HIGH,
                    {"failures": metrics.consecutive_failures},
                )

    def mark_beacon_detected(self, beacon_id: str) -> None:
        """Mark a beacon as detected.

        Args:
            beacon_id: Beacon identifier.
        """
        if beacon_id in self._beacon_metrics:
            self._beacon_metrics[beacon_id].status = BeaconStatus.DETECTED
            self._alert_manager.create_alert(
                AlertType.BEACON_DETECTED,
                beacon_id,
                f"Beacon {beacon_id} has been detected",
                AlertSeverity.CRITICAL,
            )

    def record_beacon_failure(self, beacon_id: str) -> None:
        """Record a communication failure.

        Args:
            beacon_id: Beacon identifier.
        """
        if beacon_id in self._beacon_metrics:
            self._beacon_metrics[beacon_id].consecutive_failures += 1

    def update_operational_stats(
        self,
        profile_id: str,
        beacon_count: int,
        avg_lifetime: float,
        detections: int,
        success_rate: float,
    ) -> None:
        """Update operational statistics for a profile.

        Args:
            profile_id: Profile identifier.
            beacon_count: Number of beacons.
            avg_lifetime: Average beacon lifetime.
            detections: Detection count.
            success_rate: Data success rate.
        """
        self._operational_stats[profile_id] = OperationalStats(
            profile_id=profile_id,
            total_beacons=beacon_count,
            avg_lifetime_hours=avg_lifetime,
            detection_count=detections,
            data_success_rate=success_rate,
            avg_health_score=self._get_profile_avg_health(profile_id),
            last_updated=time.time(),
        )

    def get_beacon_health(self, beacon_id: str) -> Optional[BeaconHealthMetrics]:
        """Get beacon health metrics.

        Args:
            beacon_id: Beacon identifier.

        Returns:
            BeaconHealthMetrics, or None.
        """
        return self._beacon_metrics.get(beacon_id)

    def get_all_beacon_health(self) -> Dict[str, BeaconHealthMetrics]:
        """Get all beacon health metrics.

        Returns:
            Dictionary of beacon health metrics.
        """
        return self._beacon_metrics.copy()

    def get_dashboard(self) -> Dict[str, Any]:
        """Get observability dashboard data.

        Returns:
            Dictionary with dashboard data.
        """
        total = len(self._beacon_metrics)
        online = sum(
            1 for m in self._beacon_metrics.values()
            if m.status == BeaconStatus.ONLINE
        )
        offline = sum(
            1 for m in self._beacon_metrics.values()
            if m.status == BeaconStatus.OFFLINE
        )
        detected = sum(
            1 for m in self._beacon_metrics.values()
            if m.status == BeaconStatus.DETECTED
        )

        avg_health = 0.0
        if self._beacon_metrics:
            avg_health = sum(
                m.health_score for m in self._beacon_metrics.values()
            ) / len(self._beacon_metrics)

        unack_alerts = len(
            self._alert_manager.get_unacknowledged_alerts(),
        )

        return {
            "total_beacons": total,
            "online": online,
            "offline": offline,
            "detected": detected,
            "avg_health_score": round(avg_health, 3),
            "unacknowledged_alerts": unack_alerts,
            "operational_profiles": len(self._operational_stats),
        }

    def get_alerts(
        self,
        severity: Optional[AlertSeverity] = None,
        unacknowledged_only: bool = False,
    ) -> List[Alert]:
        """Get alerts.

        Args:
            severity: Filter by severity.
            unacknowledged_only: Only unacknowledged alerts.

        Returns:
            List of matching Alerts.
        """
        alerts = self._alert_manager._alerts

        if severity:
            alerts = [a for a in alerts if a.severity == severity]

        if unacknowledged_only:
            alerts = [a for a in alerts if not a.acknowledged]

        return alerts

    def _get_profile_avg_health(self, profile_id: str) -> float:
        """Get average health score for a profile.

        Args:
            profile_id: Profile identifier.

        Returns:
            Average health score.
        """
        profile_beacons = [
            m for m in self._beacon_metrics.values()
            if profile_id in m.beacon_id
        ]

        if not profile_beacons:
            return 0.0

        return sum(m.health_score for m in profile_beacons) / len(profile_beacons)

    def get_status(self) -> Dict[str, Any]:
        """Get observability manager status.

        Returns:
            Dictionary with status summary.
        """
        return {
            "dashboard": self.get_dashboard(),
            "total_alerts": len(self._alert_manager._alerts),
            "operational_stats_count": len(self._operational_stats),
        }


# =============================================================================
# Global Singleton
# =============================================================================

_observability_manager: Optional[C2ObservabilityManager] = None


def get_observability_manager() -> C2ObservabilityManager:
    """Get the global C2ObservabilityManager singleton.

    Returns:
        Singleton C2ObservabilityManager instance.
    """
    global _observability_manager
    if _observability_manager is None:
        _observability_manager = C2ObservabilityManager()
    return _observability_manager


__all__ = [
    "C2ObservabilityManager",
    "BeaconHealthMetrics",
    "AnomalyDetector",
    "AlertManager",
    "Alert",
    "OperationalStats",
    "NotificationConfig",
    "BeaconStatus",
    "AlertSeverity",
    "AlertType",
    "NotificationChannel",
    "get_observability_manager",
]
