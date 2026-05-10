"""
Profile Generator Module - Reverse engineer profiles from PCAP/HAR/Burp requests.

This module analyzes captured network traffic (PCAP files, HAR exports, or
Burp Suite request dumps) and automatically generates Malleable C2 Profile
templates that match the observed traffic patterns.

Core capabilities:
    1. PCAP file parsing and HTTP request extraction
    2. HAR (HTTP Archive) file parsing
    3. Burp Suite request paste parsing
    4. Automatic profile template generation from extracted requests
    5. Multi-request pattern analysis for optimal profile selection

Author: Kunlun Security Lab
License: Internal Use Only
"""

from __future__ import annotations

import base64
import json
import logging
import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


# =============================================================================
# Data Models
# =============================================================================

@dataclass
class ExtractedRequest:
    """An HTTP request extracted from traffic capture.

    Attributes:
        url: Full request URL
        method: HTTP method
        headers: Request headers
        body: Request body
        user_agent: User-Agent string
        content_type: Content-Type header
        referer: Referer header
        cookies: Cookie string
        source: Source of the extraction (pcap/har/burp)
        timestamp: Request timestamp
    """

    url: str = ""
    method: str = "GET"
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    user_agent: str = ""
    content_type: str = ""
    referer: str = ""
    cookies: str = ""
    source: str = "unknown"
    timestamp: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "url": self.url,
            "method": self.method,
            "user_agent": self.user_agent,
            "content_type": self.content_type,
            "referer": self.referer,
            "source": self.source,
            "header_count": len(self.headers),
            "body_length": len(self.body),
        }


@dataclass
class GeneratedProfile:
    """A profile generated from extracted traffic.

    Attributes:
        name: Profile identifier
        yaml_content: Generated YAML profile content
        source_requests: Number of source requests used
        confidence_score: Profile quality score
        suggestions: Optimization suggestions
        created_at: Creation timestamp
    """

    name: str = ""
    yaml_content: str = ""
    source_requests: int = 0
    confidence_score: float = 0.0
    suggestions: List[str] = field(default_factory=list)
    created_at: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "name": self.name,
            "source_requests": self.source_requests,
            "confidence_score": round(self.confidence_score, 2),
            "suggestions": self.suggestions,
            "created_at": self.created_at,
        }


# =============================================================================
# HTTP Request Parser
# =============================================================================

class HttpRequestParser:
    """Parses raw HTTP request strings into structured data.

    Handles both standard HTTP request format and Burp Suite
    copy-as-request format.

    Attributes:
        _header_pattern: Regex for parsing HTTP headers
    """

    HEADER_PATTERN = re.compile(r"^([A-Za-z0-9\-_]+):\s*(.+)$")

    def parse_raw_request(self, raw: str) -> ExtractedRequest:
        """Parse a raw HTTP request string.

        Args:
            raw: Raw HTTP request string (method + headers + body).

        Returns:
            ExtractedRequest with parsed fields.
        """
        request = ExtractedRequest()
        lines = raw.strip().split("\n")

        if not lines:
            return request

        request_line = lines[0].strip()
        parts = request_line.split(" ", 2)

        if len(parts) >= 2:
            request.method = parts[0]
            request.url = parts[1] if len(parts) >= 2 else ""

        header_end = len(lines)
        body_start = -1

        for i, line in enumerate(lines[1:], 1):
            if line.strip() == "":
                body_start = i + 1
                header_end = i
                break

        for line in lines[1:header_end]:
            match = self.HEADER_PATTERN.match(line.strip())
            if match:
                key, value = match.group(1), match.group(2)
                request.headers[key] = value

                key_lower = key.lower()
                if key_lower == "user-agent":
                    request.user_agent = value
                elif key_lower == "content-type":
                    request.content_type = value
                elif key_lower == "referer":
                    request.referer = value
                elif key_lower == "cookie":
                    request.cookies = value

        if body_start > 0 and body_start < len(lines):
            request.body = "\n".join(lines[body_start:])

        return request

    def parse_multiple_requests(self, raw: str) -> List[ExtractedRequest]:
        """Parse multiple raw HTTP requests separated by blank lines.

        Args:
            raw: Raw text containing multiple HTTP requests.

        Returns:
            List of ExtractedRequest instances.
        """
        requests: List[ExtractedRequest] = []
        blocks = re.split(r"\n\s*\n(?=[A-Z]+ /)", raw)

        for block in blocks:
            block = block.strip()
            if block and re.match(r"^[A-Z]+ /", block):
                req = self.parse_raw_request(block)
                if req.method and req.url:
                    requests.append(req)

        return requests


# =============================================================================
# PCAP Parser
# =============================================================================

class PCAPParser:
    """Parses PCAP/PCAPNG files to extract HTTP requests.

    Uses dpkt or scapy for packet parsing, extracting HTTP requests
    from captured traffic.

    Attributes:
        _parser: Available parser backend (dpkt/scapy/none)
    """

    def __init__(self) -> None:
        """Initialize the PCAPParser and detect available backends."""
        self._parser: Optional[str] = None

        try:
            import dpkt
            self._parser = "dpkt"
        except ImportError:
            pass

        if not self._parser:
            try:
                from scapy.all import sniff
                self._parser = "scapy"
            except ImportError:
                logger.warning(
                    "No PCAP parser available. Install dpkt or scapy "
                    "for PCAP parsing support."
                )

    def parse_file(self, file_path: str) -> List[ExtractedRequest]:
        """Parse a PCAP file and extract HTTP requests.

        Args:
            file_path: Path to the PCAP/PCAPNG file.

        Returns:
            List of ExtractedRequest instances.
        """
        if self._parser == "dpkt":
            return self._parse_with_dpkt(file_path)
        elif self._parser == "scapy":
            return self._parse_with_scapy(file_path)
        else:
            logger.error("No PCAP parser backend available")
            return []

    def _parse_with_dpkt(self, file_path: str) -> List[ExtractedRequest]:
        """Parse PCAP using dpkt library.

        Args:
            file_path: Path to the PCAP file.

        Returns:
            List of ExtractedRequest instances.
        """
        import dpkt

        requests: List[ExtractedRequest] = []

        try:
            with open(file_path, "rb") as f:
                pcap = dpkt.pcap.Reader(f)

                for _timestamp, buf in pcap:
                    try:
                        eth = dpkt.ethernet.Ethernet(buf)

                        if not isinstance(eth.data, dpkt.ip.IP):
                            continue

                        ip = eth.data

                        if not isinstance(ip.data, dpkt.tcp.TCP):
                            continue

                        tcp = ip.data

                        if tcp.dport == 80 and tcp.data:
                            try:
                                http_req = dpkt.http.Request(tcp.data)
                                extracted = ExtractedRequest(
                                    url=http_req.uri.decode("utf-8", errors="ignore"),
                                    method=http_req.method.decode("utf-8", errors="ignore"),
                                    source="pcap",
                                    timestamp=_timestamp,
                                )

                                for key, value in http_req.headers.items():
                                    key_str = key.decode("utf-8", errors="ignore")
                                    value_str = value.decode("utf-8", errors="ignore")
                                    extracted.headers[key_str] = value_str

                                    if key_str.lower() == "user-agent":
                                        extracted.user_agent = value_str
                                    elif key_str.lower() == "content-type":
                                        extracted.content_type = value_str
                                    elif key_str.lower() == "referer":
                                        extracted.referer = value_str
                                    elif key_str.lower() == "host":
                                        extracted.url = f"http://{value_str}{extracted.url}"

                                if http_req.body:
                                    extracted.body = http_req.body.decode(
                                        "utf-8", errors="ignore",
                                    )

                                requests.append(extracted)

                            except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
                                continue

                    except Exception:
                        continue

        except Exception as e:
            logger.error(f"Failed to parse PCAP file: {e}")

        logger.info(f"Extracted {len(requests)} HTTP requests from PCAP")
        return requests

    def _parse_with_scapy(self, file_path: str) -> List[ExtractedRequest]:
        """Parse PCAP using scapy library.

        Args:
            file_path: Path to the PCAP file.

        Returns:
            List of ExtractedRequest instances.
        """
        from scapy.all import rdpcap, TCP, Raw

        requests: List[ExtractedRequest] = []
        parser = HttpRequestParser()

        try:
            packets = rdpcap(file_path)

            for pkt in packets:
                if pkt.haslayer(TCP) and pkt.haslayer(Raw):
                    tcp = pkt[TCP]
                    payload = tcp[Raw].load.decode("utf-8", errors="ignore")

                    if payload.startswith(("GET ", "POST ", "PUT ", "DELETE ", "PATCH ", "HEAD ", "OPTIONS ")):
                        req = parser.parse_raw_request(payload)
                        req.source = "pcap"
                        req.timestamp = float(pkt.time)
                        requests.append(req)

        except Exception as e:
            logger.error(f"Failed to parse PCAP with scapy: {e}")

        logger.info(f"Extracted {len(requests)} HTTP requests from PCAP (scapy)")
        return requests


# =============================================================================
# HAR Parser
# =============================================================================

class HARParser:
    """Parses HTTP Archive (HAR) files to extract HTTP requests.

    HAR files are JSON exports from browser DevTools that contain
    detailed information about all network requests.

    Attributes:
        _parser: HTTP request parser for raw request strings
    """

    def __init__(self) -> None:
        """Initialize the HARParser."""
        self._parser = HttpRequestParser()

    def parse_file(self, file_path: str) -> List[ExtractedRequest]:
        """Parse a HAR file and extract HTTP requests.

        Args:
            file_path: Path to the HAR JSON file.

        Returns:
            List of ExtractedRequest instances.
        """
        try:
            with open(file_path, encoding="utf-8") as f:
                har_data = json.load(f)

            return self.parse_data(har_data)

        except Exception as e:
            logger.error(f"Failed to parse HAR file: {e}")
            return []

    def parse_data(self, har_data: Dict[str, Any]) -> List[ExtractedRequest]:
        """Parse HAR data dictionary.

        Args:
            har_data: HAR JSON data as dictionary.

        Returns:
            List of ExtractedRequest instances.
        """
        requests: List[ExtractedRequest] = []

        try:
            entries = har_data.get("log", {}).get("entries", [])

            for entry in entries:
                req_data = entry.get("request", {})

                url = req_data.get("url", "")
                method = req_data.get("method", "GET")

                extracted = ExtractedRequest(
                    url=url,
                    method=method,
                    source="har",
                    timestamp=self._parse_har_timestamp(entry),
                )

                for header in req_data.get("headers", []):
                    name = header.get("name", "")
                    value = header.get("value", "")
                    extracted.headers[name] = value

                    name_lower = name.lower()
                    if name_lower == "user-agent":
                        extracted.user_agent = value
                    elif name_lower == "content-type":
                        extracted.content_type = value
                    elif name_lower == "referer":
                        extracted.referer = value
                    elif name_lower == "cookie":
                        extracted.cookies = value

                post_data = req_data.get("postData", {})
                if post_data:
                    extracted.body = post_data.get("text", "")
                    if not extracted.content_type:
                        extracted.content_type = post_data.get("mimeType", "")

                requests.append(extracted)

        except Exception as e:
            logger.error(f"Failed to parse HAR entries: {e}")

        logger.info(f"Extracted {len(requests)} HTTP requests from HAR")
        return requests

    @staticmethod
    def _parse_har_timestamp(entry: Dict[str, Any]) -> float:
        """Parse HAR entry timestamp.

        Args:
            entry: HAR entry dictionary.

        Returns:
            Unix timestamp as float.
        """
        started = entry.get("startedDateTime", "")
        if started:
            try:
                from datetime import datetime
                dt = datetime.fromisoformat(started.replace("Z", "+00:00"))
                return dt.timestamp()
            except (ValueError, TypeError):
                pass
        return 0.0


# =============================================================================
# Burp Request Parser
# =============================================================================

class BurpRequestParser:
    """Parses Burp Suite copy-as-request format.

    Handles the raw HTTP request format copied from Burp Suite's
    HTTP history or Repeater tab.

    Attributes:
        _http_parser: HTTP request parser
    """

    def __init__(self) -> None:
        """Initialize the BurpRequestParser."""
        self._http_parser = HttpRequestParser()

    def parse_single(self, raw_request: str) -> ExtractedRequest:
        """Parse a single Burp Suite request.

        Args:
            raw_request: Raw HTTP request string from Burp.

        Returns:
            ExtractedRequest with parsed fields.
        """
        request = self._http_parser.parse_raw_request(raw_request)
        request.source = "burp"
        return request

    def parse_multiple(self, raw_text: str) -> List[ExtractedRequest]:
        """Parse multiple Burp Suite requests.

        Args:
            raw_text: Text containing multiple Burp requests.

        Returns:
            List of ExtractedRequest instances.
        """
        return self._http_parser.parse_multiple_requests(raw_text)

    def parse_from_clipboard(self) -> List[ExtractedRequest]:
        """Parse requests from system clipboard.

        Returns:
            List of ExtractedRequest instances from clipboard.
        """
        try:
            import subprocess
            import platform

            if platform.system() == "Windows":
                result = subprocess.run(
                    ["powershell", "-command", "Get-Clipboard"],
                    capture_output=True, text=True, timeout=5,
                )
                raw = result.stdout
            elif platform.system() == "Darwin":
                result = subprocess.run(
                    ["pbpaste"],
                    capture_output=True, text=True, timeout=5,
                )
                raw = result.stdout
            else:
                raw = ""

            if raw:
                return self.parse_multiple(raw)

        except Exception as e:
            logger.warning(f"Failed to read clipboard: {e}")

        return []


# =============================================================================
# Profile Template Generator
# =============================================================================

class ProfileTemplateGenerator:
    """Generates Malleable C2 Profile YAML from extracted requests.

    Analyzes extracted HTTP requests and generates optimal profile
    configurations that match the observed traffic patterns.

    Attributes:
        _profile_counter: Counter for unique profile names
    """

    def __init__(self) -> None:
        """Initialize the ProfileTemplateGenerator."""
        self._profile_counter = 0

    def generate_from_requests(
        self,
        requests: List[ExtractedRequest],
        profile_name: str = "",
    ) -> GeneratedProfile:
        """Generate a profile from a list of extracted requests.

        Args:
            requests: List of ExtractedRequest instances.
            profile_name: Custom profile name (auto-generated if empty).

        Returns:
            GeneratedProfile with YAML content and metadata.
        """
        if not requests:
            return GeneratedProfile(
                suggestions=["No requests provided for profile generation"],
            )

        self._profile_counter += 1

        if not profile_name:
            first_url = requests[0].url
            try:
                parsed = urlparse(first_url)
                domain = parsed.hostname or "unknown"
                profile_name = f"generated_{domain}_{self._profile_counter}"
            except Exception:
                profile_name = f"generated_profile_{self._profile_counter}"

        dominant_request = self._find_dominant_request(requests)
        common_headers = self._extract_common_headers(requests)
        common_user_agents = self._extract_common_user_agents(requests)
        body_format = self._infer_body_format(dominant_request)

        yaml_content = self._build_yaml(
            profile_name=profile_name,
            request=dominant_request,
            headers=common_headers,
            user_agents=common_user_agents,
            body_format=body_format,
            request_count=len(requests),
        )

        confidence = self._compute_confidence(requests)
        suggestions = self._generate_suggestions(requests, confidence)

        return GeneratedProfile(
            name=profile_name,
            yaml_content=yaml_content,
            source_requests=len(requests),
            confidence_score=confidence,
            suggestions=suggestions,
            created_at=time.strftime("%Y-%m-%dT%H:%M:%S"),
        )

    def _find_dominant_request(
        self, requests: List[ExtractedRequest],
    ) -> ExtractedRequest:
        """Find the most representative request from the set.

        Args:
            requests: List of requests to analyze.

        Returns:
            Most representative ExtractedRequest.
        """
        if len(requests) == 1:
            return requests[0]

        method_counter: Dict[str, int] = {}
        for req in requests:
            method_counter[req.method] = method_counter.get(req.method, 0) + 1

        dominant_method = max(method_counter, key=lambda k: method_counter[k])
        method_requests = [r for r in requests if r.method == dominant_method]

        if method_requests:
            return method_requests[0]
        return requests[0]

    def _extract_common_headers(
        self, requests: List[ExtractedRequest],
    ) -> Dict[str, str]:
        """Extract headers common across all requests.

        Args:
            requests: List of requests to analyze.

        Returns:
            Dictionary of common headers.
        """
        if not requests:
            return {}

        header_sets: List[Dict[str, str]] = [r.headers for r in requests]
        common: Dict[str, str] = {}

        if header_sets:
            first = header_sets[0]
            for key, value in first.items():
                key_lower = key.lower()
                if key_lower in ("host", "content-length", "connection"):
                    continue
                if all(key in h for h in header_sets[1:]):
                    common[key] = value

        return common

    def _extract_common_user_agents(
        self, requests: List[ExtractedRequest],
    ) -> List[str]:
        """Extract unique User-Agent strings from requests.

        Args:
            requests: List of requests to analyze.

        Returns:
            List of unique User-Agent strings.
        """
        user_agents: List[str] = []
        seen: set[str] = set()

        for req in requests:
            if req.user_agent and req.user_agent not in seen:
                user_agents.append(req.user_agent)
                seen.add(req.user_agent)

        return user_agents[:5]

    def _infer_body_format(self, request: ExtractedRequest) -> str:
        """Infer body format from request characteristics.

        Args:
            request: Request to analyze.

        Returns:
            Body format string.
        """
        ct = request.content_type.lower()

        if "json" in ct:
            return "json"
        elif "xml" in ct:
            return "xml"
        elif "form" in ct:
            return "form"
        elif request.body:
            return "plain"
        return "plain"

    def _build_yaml(
        self,
        profile_name: str,
        request: ExtractedRequest,
        headers: Dict[str, str],
        user_agents: List[str],
        body_format: str,
        request_count: int,
    ) -> str:
        """Build YAML profile content.

        Args:
            profile_name: Profile name.
            request: Dominant request.
            headers: Common headers.
            user_agents: Common User-Agents.
            body_format: Inferred body format.
            request_count: Number of source requests.

        Returns:
            YAML profile string.
        """
        try:
            parsed = urlparse(request.url)
            uri = parsed.path or "/"
            if parsed.query:
                uri += f"?{parsed.query}"
        except Exception:
            uri = request.url or "/"

        uri = uri.replace("{{", "{{{{").replace("}}", "}}}}")
        uri = uri.replace("{{{{", "{{").replace("}}}}", "}}")

        if "?" in uri:
            uri = re.sub(r"[&?]ts=\d+", "?ts={{timestamp}}", uri)
            uri = re.sub(r"[&?]id=[^&]+", "&id={{random_string}}", uri)
        else:
            uri += "?ts={{timestamp}}"

        headers_yaml = ""
        for key, value in headers.items():
            value_escaped = value.replace('"', '\\"')
            headers_yaml += f'    {key}: "{value_escaped}"\n'

        if not headers_yaml:
            headers_yaml = '    Accept: "*/*"\n'

        user_agents_yaml = ""
        for ua in user_agents:
            ua_escaped = ua.replace('"', '\\"')
            user_agents_yaml += f'    - "{ua_escaped}"\n'

        if not user_agents_yaml:
            user_agents_yaml = (
                '    - "Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                'AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"\n'
            )

        referer = request.referer or f"https://{parsed.hostname if parsed else 'example.com'}/"

        yaml_content = (
            f"# Auto-generated profile from {request_count} extracted requests\n"
            f"# Source: {request.source}\n\n"
            f"name: {profile_name}\n"
            f'version: "1.0.0"\n'
            f'author: "Kunlun Profile Generator"\n'
            f'description: "Generated from captured traffic analysis"\n'
            f"protocols:\n"
            f"  - https\n\n"
            f"http:\n"
            f"  http_method: {request.method}\n"
            f'  http_uri: "{uri}"\n'
            f"  user_agent:\n"
            f"{user_agents_yaml}"
            f"  headers:\n"
            f"{headers_yaml}"
            f'  referer: "{referer}"\n'
            f"  body_format: {body_format}\n\n"
            f"heartbeat:\n"
            f"  sleep_time: 60\n"
            f"  jitter: 20\n"
            f"  max_retry: 5\n"
            f"  work_hours_start: 9\n"
            f"  work_hours_end: 18\n"
            f"  work_hours_multiplier: 0.5\n\n"
            f"encryption:\n"
            f"  encryption: aes-256-gcm\n"
            f"  encoding: base64\n"
            f'  key: ""\n'
        )

        return yaml_content

    def _compute_confidence(self, requests: List[ExtractedRequest]) -> float:
        """Compute confidence score for the generated profile.

        Args:
            requests: Source requests.

        Returns:
            Confidence score (0.0-1.0).
        """
        score = 0.0

        if len(requests) >= 10:
            score += 0.3
        elif len(requests) >= 5:
            score += 0.2
        elif len(requests) >= 1:
            score += 0.1

        has_ua = any(r.user_agent for r in requests)
        has_headers = any(r.headers for r in requests)

        if has_ua:
            score += 0.2
        if has_headers:
            score += 0.2

        if all(r.method == requests[0].method for r in requests):
            score += 0.15

        if all(r.content_type == requests[0].content_type for r in requests if r.content_type):
            score += 0.15

        return min(score, 1.0)

    def _generate_suggestions(
        self, requests: List[ExtractedRequest], confidence: float,
    ) -> List[str]:
        """Generate optimization suggestions for the profile.

        Args:
            requests: Source requests.
            confidence: Profile confidence score.

        Returns:
            List of suggestion strings.
        """
        suggestions: List[str] = []

        if len(requests) < 5:
            suggestions.append(
                "Consider capturing more requests (>= 5) for better pattern analysis",
            )

        user_agents = set(r.user_agent for r in requests if r.user_agent)
        if len(user_agents) > 3:
            suggestions.append(
                "Multiple User-Agents detected; consider using a User-Agent pool",
            )

        if not any(r.referer for r in requests):
            suggestions.append(
                "No Referer headers found; adding a Referer improves credibility",
            )

        if confidence < 0.5:
            suggestions.append(
                "Low confidence score; review generated profile before use",
            )

        return suggestions


# =============================================================================
# Profile Generator (Main Class)
# =============================================================================

class ProfileGenerator:
    """Main profile generation engine coordinating all parsers and generators.

    Provides a unified interface for generating Malleable C2 Profiles from
    PCAP files, HAR exports, or Burp Suite request dumps.

    Attributes:
        _pcap_parser: PCAP file parser
        _har_parser: HAR file parser
        _burp_parser: Burp request parser
        _template_generator: Profile template generator
        _generated_profiles: History of generated profiles
    """

    def __init__(self) -> None:
        """Initialize the ProfileGenerator."""
        self._pcap_parser = PCAPParser()
        self._har_parser = HARParser()
        self._burp_parser = BurpRequestParser()
        self._template_generator = ProfileTemplateGenerator()
        self._generated_profiles: List[GeneratedProfile] = []

    def generate_from_pcap(
        self, file_path: str, profile_name: str = "",
    ) -> GeneratedProfile:
        """Generate a profile from a PCAP file.

        Args:
            file_path: Path to the PCAP/PCAPNG file.
            profile_name: Custom profile name.

        Returns:
            GeneratedProfile with YAML content.
        """
        requests = self._pcap_parser.parse_file(file_path)

        if not requests:
            return GeneratedProfile(
                suggestions=["No HTTP requests found in PCAP file"],
            )

        profile = self._template_generator.generate_from_requests(
            requests, profile_name,
        )
        self._generated_profiles.append(profile)
        return profile

    def generate_from_har(
        self, file_path: str, profile_name: str = "",
    ) -> GeneratedProfile:
        """Generate a profile from a HAR file.

        Args:
            file_path: Path to the HAR JSON file.
            profile_name: Custom profile name.

        Returns:
            GeneratedProfile with YAML content.
        """
        requests = self._har_parser.parse_file(file_path)

        if not requests:
            return GeneratedProfile(
                suggestions=["No HTTP requests found in HAR file"],
            )

        profile = self._template_generator.generate_from_requests(
            requests, profile_name,
        )
        self._generated_profiles.append(profile)
        return profile

    def generate_from_burp(
        self, raw_request: str, profile_name: str = "",
    ) -> GeneratedProfile:
        """Generate a profile from a Burp Suite request.

        Args:
            raw_request: Raw HTTP request string from Burp.
            profile_name: Custom profile name.

        Returns:
            GeneratedProfile with YAML content.
        """
        request = self._burp_parser.parse_single(raw_request)
        profile = self._template_generator.generate_from_requests(
            [request], profile_name,
        )
        self._generated_profiles.append(profile)
        return profile

    def generate_from_clipboard(
        self, profile_name: str = "",
    ) -> List[GeneratedProfile]:
        """Generate profiles from clipboard content.

        Args:
            profile_name: Custom profile name prefix.

        Returns:
            List of GeneratedProfile instances.
        """
        requests = self._burp_parser.parse_from_clipboard()

        if not requests:
            return [GeneratedProfile(
                suggestions=["No requests found in clipboard"],
            )]

        profiles: List[GeneratedProfile] = []

        for i, req in enumerate(requests):
            name = f"{profile_name}_{i + 1}" if profile_name else ""
            profile = self._template_generator.generate_from_requests([req], name)
            profiles.append(profile)
            self._generated_profiles.append(profile)

        return profiles

    def generate_from_raw(
        self, raw_text: str, profile_name: str = "",
    ) -> GeneratedProfile:
        """Generate a profile from raw HTTP request text.

        Args:
            raw_text: Raw HTTP request string.
            profile_name: Custom profile name.

        Returns:
            GeneratedProfile with YAML content.
        """
        parser = HttpRequestParser()
        requests = parser.parse_multiple_requests(raw_text)

        if not requests:
            requests = [parser.parse_raw_request(raw_text)]

        profile = self._template_generator.generate_from_requests(
            requests, profile_name,
        )
        self._generated_profiles.append(profile)
        return profile

    def get_generated_profiles(self) -> List[GeneratedProfile]:
        """Get all generated profiles.

        Returns:
            List of GeneratedProfile instances.
        """
        return list(self._generated_profiles)


# =============================================================================
# Global Singleton
# =============================================================================

_profile_generator: Optional[ProfileGenerator] = None


def get_profile_generator() -> ProfileGenerator:
    """Get the global ProfileGenerator singleton.

    Returns:
        Singleton ProfileGenerator instance.
    """
    global _profile_generator
    if _profile_generator is None:
        _profile_generator = ProfileGenerator()
    return _profile_generator


__all__ = [
    "ProfileGenerator",
    "PCAPParser",
    "HARParser",
    "BurpRequestParser",
    "HttpRequestParser",
    "ProfileTemplateGenerator",
    "ExtractedRequest",
    "GeneratedProfile",
    "get_profile_generator",
]
