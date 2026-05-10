"""
Threat Intelligence Module - Threat intel integration and automatic evasion.

This module provides:
    1. MISP/OpenCTI threat intelligence platform integration
    2. Automatic EDR/AV detection rule updates
    3. Profile auto-adjustment based on new detection rules
    4. Detection rule analysis and evasion suggestions

Core capabilities:
    - Threat intel feed aggregation
    - Detection rule parsing and analysis
    - Profile evasion recommendations
    - Automatic Profile adjustment
    - Threat actor TTP tracking
    - IOC (Indicators of Compromise) management

Author: Kunlun Security Lab
License: Internal Use Only
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Coroutine, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


# =============================================================================
# Enums
# =============================================================================

class IntelSource(str, Enum):
    """Threat intelligence sources."""

    MISP = "misp"
    OPENCTI = "opencti"
    ALIENVAULT = "alienvault"
    VIRUSTOTAL = "virustotal"
    CUSTOM = "custom"


class DetectionRuleType(str, Enum):
    """Detection rule types."""

    YARA = "yara"
    SIGMA = "sigma"
    SNORT = "snort"
    SURICATA = "suricata"
    CUSTOM = "custom"


class ThreatLevel(str, Enum):
    """Threat severity levels."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class EvasionStatus(str, Enum):
    """Profile evasion status."""

    SAFE = "safe"
    AT_RISK = "at_risk"
    DETECTED = "detected"
    EVADING = "evading"


# =============================================================================
# Data Models
# =============================================================================

@dataclass
class IOC:
    """Indicator of Compromise.

    Attributes:
        ioc_id: Unique IOC identifier
        ioc_type: IOC type (hash, ip, domain, url)
        value: IOC value
        threat_level: Threat severity
        source: Intelligence source
        first_seen: First seen timestamp
        last_seen: Last seen timestamp
        tags: IOC tags
        confidence: Confidence score (0-1)
    """

    ioc_id: str = ""
    ioc_type: str = "hash"
    value: str = ""
    threat_level: ThreatLevel = ThreatLevel.LOW
    source: IntelSource = IntelSource.CUSTOM
    first_seen: float = 0.0
    last_seen: float = 0.0
    tags: List[str] = field(default_factory=list)
    confidence: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "ioc_id": self.ioc_id,
            "ioc_type": self.ioc_type,
            "value": self.value,
            "threat_level": self.threat_level.value,
            "source": self.source.value,
            "confidence": round(self.confidence, 3),
            "tags": self.tags,
        }


@dataclass
class DetectionRule:
    """Security detection rule.

    Attributes:
        rule_id: Unique rule identifier
        rule_type: Rule type
        name: Rule name
        description: Rule description
        content: Rule content/pattern
        severity: Detection severity
        created_at: Creation timestamp
        updated_at: Last update timestamp
        tags: Rule tags
        is_active: Whether rule is active
    """

    rule_id: str = ""
    rule_type: DetectionRuleType = DetectionRuleType.YARA
    name: str = ""
    description: str = ""
    content: str = ""
    severity: ThreatLevel = ThreatLevel.LOW
    created_at: float = 0.0
    updated_at: float = 0.0
    tags: List[str] = field(default_factory=list)
    is_active: bool = True

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "rule_id": self.rule_id,
            "rule_type": self.rule_type.value,
            "name": self.name,
            "severity": self.severity.value,
            "is_active": self.is_active,
            "tags": self.tags,
        }


@dataclass
class EvasionRecommendation:
    """Profile evasion recommendation.

    Attributes:
        recommendation_id: Recommendation identifier
        triggered_by: Detection rule that triggered
        profile_field: Profile field to modify
        current_value: Current profile value
        suggested_value: Suggested new value
        reason: Reason for change
        priority: Recommendation priority
    """

    recommendation_id: str = ""
    triggered_by: str = ""
    profile_field: str = ""
    current_value: str = ""
    suggested_value: str = ""
    reason: str = ""
    priority: ThreatLevel = ThreatLevel.LOW

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "recommendation_id": self.recommendation_id,
            "triggered_by": self.triggered_by,
            "profile_field": self.profile_field,
            "current_value": self.current_value[:100],
            "suggested_value": self.suggested_value[:100],
            "reason": self.reason,
            "priority": self.priority.value,
        }


@dataclass
class ThreatActor:
    """Threat actor profile.

    Attributes:
        actor_id: Actor identifier
        name: Actor name
        aliases: Known aliases
        ttps: MITRE ATT&CK techniques
        target_sectors: Targeted sectors
        target_regions: Targeted regions
        malware_families: Associated malware
        last_activity: Last known activity
        threat_level: Overall threat level
    """

    actor_id: str = ""
    name: str = ""
    aliases: List[str] = field(default_factory=list)
    ttps: List[str] = field(default_factory=list)
    target_sectors: List[str] = field(default_factory=list)
    target_regions: List[str] = field(default_factory=list)
    malware_families: List[str] = field(default_factory=list)
    last_activity: float = 0.0
    threat_level: ThreatLevel = ThreatLevel.LOW

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "actor_id": self.actor_id,
            "name": self.name,
            "ttps": self.ttps,
            "threat_level": self.threat_level.value,
        }


@dataclass
class IntelFeedConfig:
    """Intelligence feed configuration.

    Attributes:
        source: Intelligence source
        url: Feed URL
        api_key: API key
        enabled: Whether feed is enabled
        update_interval_seconds: Update interval
        last_update: Last update timestamp
    """

    source: IntelSource = IntelSource.CUSTOM
    url: str = ""
    api_key: str = ""
    enabled: bool = True
    update_interval_seconds: float = 3600.0
    last_update: float = 0.0


# =============================================================================
# Detection Rule Analyzer
# =============================================================================

class DetectionRuleAnalyzer:
    """Analyzes detection rules for evasion opportunities.

    Parses YARA, Sigma, and other rule formats to
    identify patterns that could detect Profile traffic.

    Attributes:
        _rules: Loaded detection rules
        _pattern_cache: Cached rule patterns
    """

    def __init__(self) -> None:
        """Initialize the DetectionRuleAnalyzer."""
        self._rules: List[DetectionRule] = []
        self._pattern_cache: Dict[str, List[str]] = {}

    def add_rule(self, rule: DetectionRule) -> None:
        """Add a detection rule.

        Args:
            rule: Detection rule to add.
        """
        self._rules.append(rule)
        self._parse_rule_patterns(rule)

    def add_rules(self, rules: List[DetectionRule]) -> None:
        """Add multiple detection rules.

        Args:
            rules: Detection rules to add.
        """
        for rule in rules:
            self.add_rule(rule)

    def analyze_profile_risk(
        self,
        profile_config: Dict[str, Any],
    ) -> Tuple[float, List[EvasionRecommendation]]:
        """Analyze Profile risk against detection rules.

        Args:
            profile_config: Profile configuration.

        Returns:
            Tuple of (risk_score, recommendations).
        """
        risk_score = 0.0
        recommendations: List[EvasionRecommendation] = []

        http_config = profile_config.get("http", {})
        headers = http_config.get("headers", {})
        user_agent = headers.get("User-Agent", "")
        body = http_config.get("body", "")

        for rule in self._rules:
            if not rule.is_active:
                continue

            matched, match_details = self._check_rule_match(
                rule, headers, user_agent, body,
            )

            if matched:
                severity_weight = self._severity_weight(rule.severity)
                risk_score += severity_weight

                recommendation = self._generate_recommendation(
                    rule, profile_config, match_details,
                )
                if recommendation:
                    recommendations.append(recommendation)

        risk_score = min(risk_score, 1.0)

        return risk_score, recommendations

    def _parse_rule_patterns(self, rule: DetectionRule) -> None:
        """Parse patterns from a detection rule.

        Args:
            rule: Detection rule.
        """
        patterns: List[str] = []

        if rule.rule_type == DetectionRuleType.YARA:
            patterns = self._extract_yara_patterns(rule.content)
        elif rule.rule_type == DetectionRuleType.SIGMA:
            patterns = self._extract_sigma_patterns(rule.content)
        elif rule.rule_type == DetectionRuleType.SNORT:
            patterns = self._extract_snort_patterns(rule.content)

        self._pattern_cache[rule.rule_id] = patterns

    def _extract_yara_patterns(self, content: str) -> List[str]:
        """Extract patterns from YARA rule.

        Args:
            content: YARA rule content.

        Returns:
            List of extracted patterns.
        """
        patterns: List[str] = []

        string_pattern = re.compile(r'\$[a-zA-Z0-9_]+\s*=\s*"([^"]+)"')
        for match in string_pattern.finditer(content):
            patterns.append(match.group(1))

        hex_pattern = re.compile(r'\$[a-zA-Z0-9_]+\s*=\s*\{([^}]+)\}')
        for match in hex_pattern.finditer(content):
            patterns.append(match.group(1))

        return patterns

    def _extract_sigma_patterns(self, content: str) -> List[str]:
        """Extract patterns from Sigma rule.

        Args:
            content: Sigma rule content.

        Returns:
            List of extracted patterns.
        """
        patterns: List[str] = []

        try:
            import yaml
            data = yaml.safe_load(content)
            if isinstance(data, dict):
                detection = data.get("detection", {})
                condition = detection.get("condition", "")

                for key, value in detection.items():
                    if key != "condition" and isinstance(value, dict):
                        for field_name, field_value in value.items():
                            if isinstance(field_value, str):
                                patterns.append(field_value)
                            elif isinstance(field_value, list):
                                patterns.extend(field_value)
        except Exception:
            pass

        return patterns

    def _extract_snort_patterns(self, content: str) -> List[str]:
        """Extract patterns from Snort rule.

        Args:
            content: Snort rule content.

        Returns:
            List of extracted patterns.
        """
        patterns: List[str] = []

        content_pattern = re.compile(r'content:"([^"]+)"')
        for match in content_pattern.finditer(content):
            patterns.append(match.group(1))

        return patterns

    def _check_rule_match(
        self,
        rule: DetectionRule,
        headers: Dict[str, str],
        user_agent: str,
        body: str,
    ) -> Tuple[bool, Dict[str, Any]]:
        """Check if Profile matches a detection rule.

        Args:
            rule: Detection rule.
            headers: Profile headers.
            user_agent: Profile User-Agent.
            body: Profile body.

        Returns:
            Tuple of (is_match, match_details).
        """
        patterns = self._pattern_cache.get(rule.rule_id, [])
        match_details: Dict[str, Any] = {"matched_patterns": []}

        for pattern in patterns:
            pattern_lower = pattern.lower()

            if pattern_lower in user_agent.lower():
                match_details["matched_patterns"].append(pattern)
                match_details["field"] = "user_agent"
                return True, match_details

            for header_name, header_value in headers.items():
                if pattern_lower in header_value.lower():
                    match_details["matched_patterns"].append(pattern)
                    match_details["field"] = f"header:{header_name}"
                    return True, match_details

            if pattern_lower in body.lower():
                match_details["matched_patterns"].append(pattern)
                match_details["field"] = "body"
                return True, match_details

        return False, match_details

    def _severity_weight(self, severity: ThreatLevel) -> float:
        """Get weight for threat severity.

        Args:
            severity: Threat level.

        Returns:
            Severity weight.
        """
        weights = {
            ThreatLevel.LOW: 0.1,
            ThreatLevel.MEDIUM: 0.25,
            ThreatLevel.HIGH: 0.5,
            ThreatLevel.CRITICAL: 0.8,
        }
        return weights.get(severity, 0.1)

    def _generate_recommendation(
        self,
        rule: DetectionRule,
        profile_config: Dict[str, Any],
        match_details: Dict[str, Any],
    ) -> Optional[EvasionRecommendation]:
        """Generate evasion recommendation.

        Args:
            rule: Detection rule.
            profile_config: Profile configuration.
            match_details: Rule match details.

        Returns:
            EvasionRecommendation, or None.
        """
        import hashlib
        import time

        field_name = match_details.get("field", "")

        if "user_agent" in field_name:
            return EvasionRecommendation(
                recommendation_id=hashlib.md5(
                    f"rec_{time.time()}".encode()
                ).hexdigest()[:12],
                triggered_by=rule.rule_id,
                profile_field="http.headers.User-Agent",
                current_value=profile_config.get("http", {}).get("headers", {}).get("User-Agent", ""),
                suggested_value="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                reason=f"User-Agent matches detection rule: {rule.name}",
                priority=rule.severity,
            )

        if "header:" in field_name:
            header_name = field_name.split(":")[1]
            return EvasionRecommendation(
                recommendation_id=hashlib.md5(
                    f"rec_{time.time()}".encode()
                ).hexdigest()[:12],
                triggered_by=rule.rule_id,
                profile_field=f"http.headers.{header_name}",
                current_value=profile_config.get("http", {}).get("headers", {}).get(header_name, ""),
                suggested_value="[randomized_value]",
                reason=f"Header {header_name} matches detection rule: {rule.name}",
                priority=rule.severity,
            )

        return None

    def get_rules_by_type(
        self, rule_type: DetectionRuleType,
    ) -> List[DetectionRule]:
        """Get rules by type.

        Args:
            rule_type: Rule type.

        Returns:
            List of matching DetectionRule.
        """
        return [r for r in self._rules if r.rule_type == rule_type]

    def get_status(self) -> Dict[str, Any]:
        """Get analyzer status.

        Returns:
            Dictionary with status summary.
        """
        type_counts: Dict[str, int] = {}

        for rule in self._rules:
            if rule.is_active:
                rule_type = rule.rule_type.value
                type_counts[rule_type] = type_counts.get(rule_type, 0) + 1

        return {
            "total_rules": len(self._rules),
            "active_rules": sum(1 for r in self._rules if r.is_active),
            "rules_by_type": type_counts,
        }


# =============================================================================
# Threat Intel Client
# =============================================================================

class ThreatIntelClient:
    """Client for threat intelligence platforms.

    Fetches IOCs, detection rules, and threat actor
    information from MISP, OpenCTI, and other sources.

    Attributes:
        _feeds: Configured intelligence feeds
        _ioc_cache: Cached IOCs
    """

    def __init__(self) -> None:
        """Initialize the ThreatIntelClient."""
        self._feeds: List[IntelFeedConfig] = []
        self._ioc_cache: List[IOC] = []

    def add_feed(self, config: IntelFeedConfig) -> None:
        """Add an intelligence feed.

        Args:
            config: Feed configuration.
        """
        self._feeds.append(config)

    async def fetch_intelligence(self) -> Dict[str, Any]:
        """Fetch intelligence from all configured feeds.

        Returns:
            Dictionary with fetched intelligence.
        """
        results: Dict[str, Any] = {
            "iocs": [],
            "rules": [],
            "threat_actors": [],
            "sources_updated": [],
        }

        for feed in self._feeds:
            if not feed.enabled:
                continue

            try:
                if feed.source == IntelSource.MISP:
                    feed_data = await self._fetch_misp(feed)
                elif feed.source == IntelSource.OPENCTI:
                    feed_data = await self._fetch_opencti(feed)
                else:
                    feed_data = await self._fetch_custom(feed)

                results["iocs"].extend(feed_data.get("iocs", []))
                results["rules"].extend(feed_data.get("rules", []))
                results["threat_actors"].extend(
                    feed_data.get("threat_actors", []),
                )
                results["sources_updated"].append(feed.source.value)

                feed.last_update = time.time()

            except Exception as e:
                logger.error(f"Feed {feed.source.value} failed: {e}")

        return results

    async def _fetch_misp(
        self, feed: IntelFeedConfig,
    ) -> Dict[str, Any]:
        """Fetch intelligence from MISP.

        Args:
            feed: Feed configuration.

        Returns:
            Dictionary with MISP data.
        """
        logger.info(f"Fetching MISP intelligence from {feed.url}")

        return {
            "iocs": [],
            "rules": [],
            "threat_actors": [],
        }

    async def _fetch_opencti(
        self, feed: IntelFeedConfig,
    ) -> Dict[str, Any]:
        """Fetch intelligence from OpenCTI.

        Args:
            feed: Feed configuration.

        Returns:
            Dictionary with OpenCTI data.
        """
        logger.info(f"Fetching OpenCTI intelligence from {feed.url}")

        return {
            "iocs": [],
            "rules": [],
            "threat_actors": [],
        }

    async def _fetch_custom(
        self, feed: IntelFeedConfig,
    ) -> Dict[str, Any]:
        """Fetch intelligence from custom source.

        Args:
            feed: Feed configuration.

        Returns:
            Dictionary with custom data.
        """
        logger.info(f"Fetching custom intelligence from {feed.url}")

        return {
            "iocs": [],
            "rules": [],
            "threat_actors": [],
        }

    def add_ioc(self, ioc: IOC) -> None:
        """Add an IOC to cache.

        Args:
            ioc: IOC to add.
        """
        self._ioc_cache.append(ioc)

    def get_iocs(
        self,
        ioc_type: Optional[str] = None,
        min_confidence: float = 0.0,
    ) -> List[IOC]:
        """Get IOCs from cache.

        Args:
            ioc_type: Filter by IOC type.
            min_confidence: Minimum confidence.

        Returns:
            List of matching IOCs.
        """
        results = self._ioc_cache

        if ioc_type:
            results = [i for i in results if i.ioc_type == ioc_type]

        results = [i for i in results if i.confidence >= min_confidence]

        return results

    def get_status(self) -> Dict[str, Any]:
        """Get client status.

        Returns:
            Dictionary with status summary.
        """
        return {
            "feed_count": len(self._feeds),
            "enabled_feeds": sum(1 for f in self._feeds if f.enabled),
            "ioc_count": len(self._ioc_cache),
            "feeds": [
                {
                    "source": f.source.value,
                    "enabled": f.enabled,
                    "last_update": f.last_update,
                }
                for f in self._feeds
            ],
        }


# =============================================================================
# Profile Auto-Evasion Engine
# =============================================================================

class ProfileAutoEvasionEngine:
    """Automatically adjusts Profiles to evade detection.

    Applies evasion recommendations to Profile
    configurations and validates effectiveness.

    Attributes:
        _analyzer: Detection rule analyzer
        _evasion_history: Evasion attempt history
    """

    def __init__(
        self,
        analyzer: Optional[DetectionRuleAnalyzer] = None,
    ) -> None:
        """Initialize the ProfileAutoEvasionEngine.

        Args:
            analyzer: Detection rule analyzer.
        """
        self._analyzer = analyzer or DetectionRuleAnalyzer()
        self._evasion_history: List[Dict[str, Any]] = []

    async def analyze_and_evaluate(
        self,
        profile_config: Dict[str, Any],
    ) -> Tuple[float, List[EvasionRecommendation]]:
        """Analyze Profile and generate evasion recommendations.

        Args:
            profile_config: Profile configuration.

        Returns:
            Tuple of (risk_score, recommendations).
        """
        return self._analyzer.analyze_profile_risk(profile_config)

    async def apply_evasion(
        self,
        profile_config: Dict[str, Any],
        recommendations: List[EvasionRecommendation],
        auto_apply: bool = False,
    ) -> Dict[str, Any]:
        """Apply evasion recommendations to Profile.

        Args:
            profile_config: Profile configuration.
            recommendations: Evasion recommendations.
            auto_apply: Whether to auto-apply changes.

        Returns:
            Dictionary with evasion results.
        """
        import copy

        original_config = copy.deepcopy(profile_config)
        modified_config = copy.deepcopy(profile_config)
        applied_changes: List[Dict[str, Any]] = []

        for rec in recommendations:
            if rec.priority in (ThreatLevel.HIGH, ThreatLevel.CRITICAL) or auto_apply:
                success = self._apply_single_recommendation(
                    modified_config, rec,
                )
                if success:
                    applied_changes.append(rec.to_dict())

        new_risk_score, _ = self._analyzer.analyze_profile_risk(
            modified_config,
        )

        evasion_result = {
            "original_risk": self._calculate_risk(profile_config),
            "new_risk": new_risk_score,
            "risk_reduction": self._calculate_risk(profile_config) - new_risk_score,
            "changes_applied": len(applied_changes),
            "applied_changes": applied_changes,
            "modified_profile": modified_config,
        }

        self._evasion_history.append({
            "timestamp": time.time(),
            "result": evasion_result,
        })

        logger.info(
            f"Evasion applied: {len(applied_changes)} changes, "
            f"risk reduced from {evasion_result['original_risk']:.2f} "
            f"to {evasion_result['new_risk']:.2f}"
        )

        return evasion_result

    def _apply_single_recommendation(
        self,
        profile_config: Dict[str, Any],
        recommendation: EvasionRecommendation,
    ) -> bool:
        """Apply a single evasion recommendation.

        Args:
            profile_config: Profile configuration.
            recommendation: Recommendation to apply.

        Returns:
            True if applied successfully.
        """
        field_path = recommendation.profile_field.split(".")

        current = profile_config
        for key in field_path[:-1]:
            if key not in current:
                return False
            current = current[key]

        if field_path[-1] in current:
            current[field_path[-1]] = recommendation.suggested_value
            return True

        return False

    def _calculate_risk(self, profile_config: Dict[str, Any]) -> float:
        """Calculate Profile risk score.

        Args:
            profile_config: Profile configuration.

        Returns:
            Risk score.
        """
        risk_score, _ = self._analyzer.analyze_profile_risk(
            profile_config,
        )
        return risk_score

    def get_evasion_history(self) -> List[Dict[str, Any]]:
        """Get evasion history.

        Returns:
            List of evasion records.
        """
        return self._evasion_history.copy()

    def get_status(self) -> Dict[str, Any]:
        """Get evasion engine status.

        Returns:
            Dictionary with status summary.
        """
        return {
            "analyzer": self._analyzer.get_status(),
            "evasion_attempts": len(self._evasion_history),
        }


# =============================================================================
# Threat Intelligence Manager
# =============================================================================

class ThreatIntelligenceManager:
    """Main threat intelligence coordination engine.

    Integrates intel feeds, detection rule analysis,
    and Profile auto-evasion.

    Attributes:
        _intel_client: Threat intel client
        _analyzer: Detection rule analyzer
        _evasion_engine: Auto-evasion engine
        _threat_actors: Known threat actors
    """

    def __init__(self) -> None:
        """Initialize the ThreatIntelligenceManager."""
        self._intel_client = ThreatIntelClient()
        self._analyzer = DetectionRuleAnalyzer()
        self._evasion_engine = ProfileAutoEvasionEngine(self._analyzer)
        self._threat_actors: Dict[str, ThreatActor] = {}

    def add_feed(self, config: IntelFeedConfig) -> None:
        """Add an intelligence feed.

        Args:
            config: Feed configuration.
        """
        self._intel_client.add_feed(config)

    def add_detection_rule(self, rule: DetectionRule) -> None:
        """Add a detection rule.

        Args:
            rule: Detection rule.
        """
        self._analyzer.add_rule(rule)

    async def update_intelligence(self) -> Dict[str, Any]:
        """Update intelligence from all feeds.

        Returns:
            Dictionary with update results.
        """
        intel_data = await self._intel_client.fetch_intelligence()

        for ioc_data in intel_data.get("iocs", []):
            ioc = IOC(**ioc_data) if isinstance(ioc_data, dict) else ioc_data
            self._intel_client.add_ioc(ioc)

        for rule_data in intel_data.get("rules", []):
            if isinstance(rule_data, dict):
                rule = DetectionRule(**rule_data)
                self._analyzer.add_rule(rule)

        for actor_data in intel_data.get("threat_actors", []):
            if isinstance(actor_data, dict):
                actor = ThreatActor(**actor_data)
                self._threat_actors[actor.actor_id] = actor

        return intel_data

    async def analyze_profile(
        self,
        profile_config: Dict[str, Any],
    ) -> Tuple[float, List[EvasionRecommendation]]:
        """Analyze Profile against detection rules.

        Args:
            profile_config: Profile configuration.

        Returns:
            Tuple of (risk_score, recommendations).
        """
        return await self._evasion_engine.analyze_and_evaluate(
            profile_config,
        )

    async def apply_evasion(
        self,
        profile_config: Dict[str, Any],
        recommendations: List[EvasionRecommendation],
        auto_apply: bool = False,
    ) -> Dict[str, Any]:
        """Apply evasion recommendations.

        Args:
            profile_config: Profile configuration.
            recommendations: Evasion recommendations.
            auto_apply: Whether to auto-apply.

        Returns:
            Dictionary with evasion results.
        """
        return await self._evasion_engine.apply_evasion(
            profile_config, recommendations, auto_apply,
        )

    def get_iocs(
        self,
        ioc_type: Optional[str] = None,
        min_confidence: float = 0.0,
    ) -> List[IOC]:
        """Get IOCs.

        Args:
            ioc_type: Filter by type.
            min_confidence: Minimum confidence.

        Returns:
            List of IOCs.
        """
        return self._intel_client.get_iocs(ioc_type, min_confidence)

    def get_threat_actors(self) -> List[ThreatActor]:
        """Get known threat actors.

        Returns:
            List of ThreatActor.
        """
        return list(self._threat_actors.values())

    def get_status(self) -> Dict[str, Any]:
        """Get threat intelligence status.

        Returns:
            Dictionary with status summary.
        """
        return {
            "intel_client": self._intel_client.get_status(),
            "analyzer": self._analyzer.get_status(),
            "evasion_engine": self._evasion_engine.get_status(),
            "threat_actor_count": len(self._threat_actors),
        }


# =============================================================================
# Global Singleton
# =============================================================================

_threat_intel_manager: Optional[ThreatIntelligenceManager] = None


def get_threat_intel_manager() -> ThreatIntelligenceManager:
    """Get the global ThreatIntelligenceManager singleton.

    Returns:
        Singleton ThreatIntelligenceManager instance.
    """
    global _threat_intel_manager
    if _threat_intel_manager is None:
        _threat_intel_manager = ThreatIntelligenceManager()
    return _threat_intel_manager


__all__ = [
    "ThreatIntelligenceManager",
    "ThreatIntelClient",
    "DetectionRuleAnalyzer",
    "ProfileAutoEvasionEngine",
    "IOC",
    "DetectionRule",
    "EvasionRecommendation",
    "ThreatActor",
    "IntelFeedConfig",
    "IntelSource",
    "DetectionRuleType",
    "ThreatLevel",
    "EvasionStatus",
    "get_threat_intel_manager",
]
