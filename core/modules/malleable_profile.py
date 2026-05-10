"""
Malleable C2 Profile Module - Profile loading, parsing, validation, and hot-reload.

This module provides the core infrastructure for managing Malleable C2 Profiles
that allow Beacon communication traffic to be highly customized and disguised
as legitimate business API requests, bypassing EDR and network traffic audit devices.

Profile Format (YAML):
    - name: Profile name
    - version: Profile version
    - author: Profile author
    - description: Profile description
    - protocols: Applicable protocols (http/https/dns/websocket)
    - http: HTTP/HTTPS protocol configuration
    - heartbeat: Heartbeat parameters
    - encryption: Encryption and encoding settings

Author: Kunlun Security Lab
License: Internal Use Only
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Coroutine, Dict, List, Optional, Set, Tuple

import yaml

logger = logging.getLogger(__name__)


# =============================================================================
# Enums
# =============================================================================

class EncryptionAlgorithm(str, Enum):
    """Encryption algorithms supported by profiles."""

    AES_256_GCM = "aes-256-gcm"
    AES_256_CBC = "aes-256-cbc"
    XOR = "xor"
    NONE = "none"


class EncodingType(str, Enum):
    """Transport encoding types."""

    BASE64 = "base64"
    HEX = "hex"
    RAW = "raw"


class BodyFormat(str, Enum):
    """Request body formats."""

    JSON = "json"
    XML = "xml"
    FORM = "form"
    PLAIN = "plain"


class ProtocolType(str, Enum):
    """Supported communication protocols."""

    HTTP = "http"
    HTTPS = "https"
    DNS = "dns"
    WEBSOCKET = "websocket"


class ProfileStatus(str, Enum):
    """Profile lifecycle status."""

    LOADED = "loaded"
    ACTIVE = "active"
    INACTIVE = "inactive"
    ERROR = "error"


class ValidationSeverity(str, Enum):
    """Validation issue severity levels."""

    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


# =============================================================================
# Data Models
# =============================================================================

@dataclass
class HttpProfileConfig:
    """HTTP/HTTPS protocol configuration within a profile.

    Attributes:
        http_method: HTTP request method (GET/POST/PUT/etc.)
        http_uri: Request path, supports dynamic variables (e.g., /api/v1/{{endpoint}})
        user_agent: User-Agent string, supports random pool
        headers: Custom request headers (Key-Value), supports random values
        cookie: Custom Cookie content
        body_format: Request body format (json/xml/form/plain)
        body_template: Body content template, supports variable substitution
        referer: Referer header for context consistency
        accept_language: Accept-Language matching User-Agent locale
    """

    http_method: str = "POST"
    http_uri: str = "/api/v1/status"
    user_agent: List[str] = field(default_factory=lambda: [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    ])
    headers: Dict[str, str | List[str]] = field(default_factory=dict)
    cookie: str = ""
    body_format: BodyFormat = BodyFormat.JSON
    body_template: str = ""
    referer: str = ""
    accept_language: str = "en-US,en;q=0.9"

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation.

        Returns:
            Dictionary containing all HTTP profile configuration fields.
        """
        return {
            "http_method": self.http_method,
            "http_uri": self.http_uri,
            "user_agent": self.user_agent,
            "headers": self.headers,
            "cookie": self.cookie,
            "body_format": self.body_format.value,
            "body_template": self.body_template,
            "referer": self.referer,
            "accept_language": self.accept_language,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "HttpProfileConfig":
        """Create instance from dictionary.

        Args:
            data: Dictionary containing HTTP profile configuration.

        Returns:
            HttpProfileConfig instance populated from the dictionary.
        """
        body_format = data.get("body_format", "json")
        if isinstance(body_format, str):
            body_format = BodyFormat(body_format)

        user_agent = data.get("user_agent", [])
        if isinstance(user_agent, str):
            user_agent = [user_agent]

        return cls(
            http_method=data.get("http_method", "POST"),
            http_uri=data.get("http_uri", "/api/v1/status"),
            user_agent=user_agent,
            headers=data.get("headers", {}),
            cookie=data.get("cookie", ""),
            body_format=body_format,
            body_template=data.get("body_template", ""),
            referer=data.get("referer", ""),
            accept_language=data.get("accept_language", "en-US,en;q=0.9"),
        )


@dataclass
class HeartbeatConfig:
    """Heartbeat timing configuration.

    Attributes:
        sleep_time: Base sleep interval in seconds
        jitter: Jitter percentage (0-100)
        max_retry: Maximum retry attempts on failure
        work_hours_start: Work hour start (24h format)
        work_hours_end: Work hour end (24h format)
        work_hours_multiplier: Activity multiplier during work hours
    """

    sleep_time: int = 60
    jitter: int = 20
    max_retry: int = 5
    work_hours_start: int = 9
    work_hours_end: int = 18
    work_hours_multiplier: float = 0.5

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation.

        Returns:
            Dictionary containing all heartbeat configuration fields.
        """
        return {
            "sleep_time": self.sleep_time,
            "jitter": self.jitter,
            "max_retry": self.max_retry,
            "work_hours_start": self.work_hours_start,
            "work_hours_end": self.work_hours_end,
            "work_hours_multiplier": self.work_hours_multiplier,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "HeartbeatConfig":
        """Create instance from dictionary.

        Args:
            data: Dictionary containing heartbeat configuration.

        Returns:
            HeartbeatConfig instance populated from the dictionary.
        """
        return cls(
            sleep_time=data.get("sleep_time", 60),
            jitter=min(max(data.get("jitter", 20), 0), 100),
            max_retry=data.get("max_retry", 5),
            work_hours_start=data.get("work_hours_start", 9),
            work_hours_end=data.get("work_hours_end", 18),
            work_hours_multiplier=data.get("work_hours_multiplier", 0.5),
        )


@dataclass
class EncryptionConfig:
    """Encryption and encoding configuration.

    Attributes:
        encryption: Encryption algorithm
        encoding: Transport encoding
        key: Encryption key (optional, auto-generated if empty)
    """

    encryption: EncryptionAlgorithm = EncryptionAlgorithm.AES_256_GCM
    encoding: EncodingType = EncodingType.BASE64
    key: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation.

        Returns:
            Dictionary containing all encryption configuration fields.
        """
        return {
            "encryption": self.encryption.value,
            "encoding": self.encoding.value,
            "key": self.key,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "EncryptionConfig":
        """Create instance from dictionary.

        Args:
            data: Dictionary containing encryption configuration.

        Returns:
            EncryptionConfig instance populated from the dictionary.
        """
        encryption = data.get("encryption", "aes-256-gcm")
        if isinstance(encryption, str):
            encryption = EncryptionAlgorithm(encryption)

        encoding = data.get("encoding", "base64")
        if isinstance(encoding, str):
            encoding = EncodingType(encoding)

        return cls(
            encryption=encryption,
            encoding=encoding,
            key=data.get("key", ""),
        )


@dataclass
class DnsProfileConfig:
    """DNS tunnel protocol configuration.

    Attributes:
        dns_server: DNS server address
        dns_domain: Base domain for DNS tunneling
        query_type: DNS query type (A/AAAA/TXT/CNAME/MX)
        subdomain_format: Subdomain format template
        max_subdomain_length: Maximum subdomain length
    """

    dns_server: str = "8.8.8.8"
    dns_domain: str = "cdn.example.com"
    query_type: str = "A"
    subdomain_format: str = "{{beacon_id}}.{{data}}"
    max_subdomain_length: int = 63

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation.

        Returns:
            Dictionary containing all DNS profile configuration fields.
        """
        return {
            "dns_server": self.dns_server,
            "dns_domain": self.dns_domain,
            "query_type": self.query_type,
            "subdomain_format": self.subdomain_format,
            "max_subdomain_length": self.max_subdomain_length,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DnsProfileConfig":
        """Create instance from dictionary.

        Args:
            data: Dictionary containing DNS profile configuration.

        Returns:
            DnsProfileConfig instance populated from the dictionary.
        """
        return cls(
            dns_server=data.get("dns_server", "8.8.8.8"),
            dns_domain=data.get("dns_domain", "cdn.example.com"),
            query_type=data.get("query_type", "A"),
            subdomain_format=data.get("subdomain_format", "{{beacon_id}}.{{data}}"),
            max_subdomain_length=data.get("max_subdomain_length", 63),
        )


@dataclass
class ValidationIssue:
    """Profile validation issue.

    Attributes:
        severity: Issue severity level
        field: Affected configuration field
        message: Human-readable description
        suggestion: Suggested fix
    """

    severity: ValidationSeverity = ValidationSeverity.ERROR
    field: str = ""
    message: str = ""
    suggestion: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation.

        Returns:
            Dictionary containing all validation issue fields.
        """
        return {
            "severity": self.severity.value,
            "field": self.field,
            "message": self.message,
            "suggestion": self.suggestion,
        }


@dataclass
class MalleableProfile:
    """Complete Malleable C2 Profile definition.

    Attributes:
        name: Profile name (unique identifier)
        version: Profile version string
        author: Profile author
        description: Profile description
        protocols: Applicable protocols
        http: HTTP/HTTPS configuration
        dns: DNS tunnel configuration
        heartbeat: Heartbeat timing configuration
        encryption: Encryption and encoding configuration
        status: Current profile status
        file_path: Source file path
        checksum: SHA256 checksum of the source file
        created_at: Profile creation timestamp
        updated_at: Profile last update timestamp
        metadata: Additional metadata
    """

    name: str = ""
    version: str = "1.0.0"
    author: str = ""
    description: str = ""
    protocols: List[ProtocolType] = field(default_factory=lambda: [ProtocolType.HTTPS])
    http: HttpProfileConfig = field(default_factory=HttpProfileConfig)
    dns: DnsProfileConfig = field(default_factory=DnsProfileConfig)
    heartbeat: HeartbeatConfig = field(default_factory=HeartbeatConfig)
    encryption: EncryptionConfig = field(default_factory=EncryptionConfig)
    status: ProfileStatus = ProfileStatus.INACTIVE
    file_path: str = ""
    checksum: str = ""
    created_at: str = ""
    updated_at: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation.

        Returns:
            Dictionary containing all profile fields.
        """
        return {
            "name": self.name,
            "version": self.version,
            "author": self.author,
            "description": self.description,
            "protocols": [p.value for p in self.protocols],
            "http": self.http.to_dict(),
            "dns": self.dns.to_dict(),
            "heartbeat": self.heartbeat.to_dict(),
            "encryption": self.encryption.to_dict(),
            "status": self.status.value,
            "file_path": self.file_path,
            "checksum": self.checksum,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "metadata": self.metadata,
        }

    def to_yaml(self) -> str:
        """Convert to YAML string representation.

        Returns:
            YAML-formatted string of the profile.
        """
        return yaml.dump(self.to_dict(), default_flow_style=False, allow_unicode=True)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "MalleableProfile":
        """Create instance from dictionary.

        Args:
            data: Dictionary containing profile data.

        Returns:
            MalleableProfile instance populated from the dictionary.
        """
        protocols = data.get("protocols", ["https"])
        if isinstance(protocols, list):
            protocols = [
                ProtocolType(p) if isinstance(p, str) else p
                for p in protocols
            ]

        return cls(
            name=data.get("name", ""),
            version=data.get("version", "1.0.0"),
            author=data.get("author", ""),
            description=data.get("description", ""),
            protocols=protocols,
            http=HttpProfileConfig.from_dict(data.get("http", {})),
            dns=DnsProfileConfig.from_dict(data.get("dns", {})),
            heartbeat=HeartbeatConfig.from_dict(data.get("heartbeat", {})),
            encryption=EncryptionConfig.from_dict(data.get("encryption", {})),
            status=ProfileStatus(data.get("status", "inactive")),
            file_path=data.get("file_path", ""),
            checksum=data.get("checksum", ""),
            created_at=data.get("created_at", ""),
            updated_at=data.get("updated_at", ""),
            metadata=data.get("metadata", {}),
        )


# =============================================================================
# Profile Validator
# =============================================================================

class ProfileValidator:
    """Validates Malleable C2 Profile configurations.

    Performs comprehensive validation of profile fields including required
    fields, value ranges, format correctness, and cross-field consistency.

    Attributes:
        _required_fields: List of required top-level fields
        _valid_http_methods: Set of valid HTTP methods
        _valid_query_types: Set of valid DNS query types
    """

    REQUIRED_FIELDS = ["name", "version", "author", "description"]

    VALID_HTTP_METHODS = {"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"}

    VALID_QUERY_TYPES = {"A", "AAAA", "TXT", "CNAME", "MX", "NS", "SOA", "SRV"}

    VALID_BODY_FORMATS = {bf.value for bf in BodyFormat}

    VALID_ENCRYPTIONS = {ea.value for ea in EncryptionAlgorithm}

    VALID_ENCODINGS = {et.value for et in EncodingType}

    def validate(self, profile: MalleableProfile) -> List[ValidationIssue]:
        """Validate a complete profile.

        Args:
            profile: The MalleableProfile instance to validate.

        Returns:
            List of ValidationIssue objects describing any problems found.
        """
        issues: List[ValidationIssue] = []

        issues.extend(self._validate_metadata(profile))
        issues.extend(self._validate_protocols(profile))
        issues.extend(self._validate_http(profile.http))
        issues.extend(self._validate_heartbeat(profile.heartbeat))
        issues.extend(self._validate_encryption(profile.encryption))
        issues.extend(self._validate_dns(profile.dns))
        issues.extend(self._validate_cross_field(profile))

        return issues

    def _validate_metadata(self, profile: MalleableProfile) -> List[ValidationIssue]:
        """Validate profile metadata fields.

        Args:
            profile: The profile to validate.

        Returns:
            List of validation issues found in metadata.
        """
        issues: List[ValidationIssue] = []

        for field_name in self.REQUIRED_FIELDS:
            value = getattr(profile, field_name, None)
            if not value or not str(value).strip():
                issues.append(ValidationIssue(
                    severity=ValidationSeverity.ERROR,
                    field=field_name,
                    message=f"Required field '{field_name}' is empty",
                    suggestion=f"Provide a value for '{field_name}'",
                ))

        if profile.name and not profile.name.replace("_", "").replace("-", "").isalnum():
            issues.append(ValidationIssue(
                severity=ValidationSeverity.WARNING,
                field="name",
                message="Profile name contains special characters",
                suggestion="Use alphanumeric characters, underscores, or hyphens only",
            ))

        return issues

    def _validate_protocols(self, profile: MalleableProfile) -> List[ValidationIssue]:
        """Validate protocol configuration.

        Args:
            profile: The profile to validate.

        Returns:
            List of validation issues found in protocols.
        """
        issues: List[ValidationIssue] = []

        if not profile.protocols:
            issues.append(ValidationIssue(
                severity=ValidationSeverity.ERROR,
                field="protocols",
                message="At least one protocol must be specified",
                suggestion="Add at least one protocol: http, https, dns, or websocket",
            ))

        return issues

    def _validate_http(self, http: HttpProfileConfig) -> List[ValidationIssue]:
        """Validate HTTP configuration.

        Args:
            http: The HTTP configuration to validate.

        Returns:
            List of validation issues found in HTTP config.
        """
        issues: List[ValidationIssue] = []

        if http.http_method.upper() not in self.VALID_HTTP_METHODS:
            issues.append(ValidationIssue(
                severity=ValidationSeverity.ERROR,
                field="http.http_method",
                message=f"Invalid HTTP method: {http.http_method}",
                suggestion=f"Use one of: {', '.join(sorted(self.VALID_HTTP_METHODS))}",
            ))

        if not http.http_uri.startswith("/"):
            issues.append(ValidationIssue(
                severity=ValidationSeverity.WARNING,
                field="http.http_uri",
                message="URI should start with '/'",
                suggestion="Prefix URI with '/' (e.g., /api/v1/status)",
            ))

        if not http.user_agent:
            issues.append(ValidationIssue(
                severity=ValidationSeverity.WARNING,
                field="http.user_agent",
                message="No User-Agent strings configured",
                suggestion="Add at least one User-Agent string for realistic traffic",
            ))

        if http.body_format.value not in self.VALID_BODY_FORMATS:
            issues.append(ValidationIssue(
                severity=ValidationSeverity.ERROR,
                field="http.body_format",
                message=f"Invalid body format: {http.body_format}",
                suggestion=f"Use one of: {', '.join(sorted(self.VALID_BODY_FORMATS))}",
            ))

        return issues

    def _validate_heartbeat(self, heartbeat: HeartbeatConfig) -> List[ValidationIssue]:
        """Validate heartbeat configuration.

        Args:
            heartbeat: The heartbeat configuration to validate.

        Returns:
            List of validation issues found in heartbeat config.
        """
        issues: List[ValidationIssue] = []

        if heartbeat.sleep_time < 1:
            issues.append(ValidationIssue(
                severity=ValidationSeverity.ERROR,
                field="heartbeat.sleep_time",
                message="Sleep time must be at least 1 second",
                suggestion="Set sleep_time to 1 or greater",
            ))

        if heartbeat.sleep_time > 86400:
            issues.append(ValidationIssue(
                severity=ValidationSeverity.WARNING,
                field="heartbeat.sleep_time",
                message="Sleep time exceeds 24 hours",
                suggestion="Consider reducing sleep_time for more reliable communication",
            ))

        if not (0 <= heartbeat.jitter <= 100):
            issues.append(ValidationIssue(
                severity=ValidationSeverity.ERROR,
                field="heartbeat.jitter",
                message=f"Jitter must be between 0 and 100, got {heartbeat.jitter}",
                suggestion="Set jitter to a value between 0 and 100",
            ))

        if heartbeat.max_retry < 1:
            issues.append(ValidationIssue(
                severity=ValidationSeverity.WARNING,
                field="heartbeat.max_retry",
                message="Max retry should be at least 1",
                suggestion="Set max_retry to 1 or greater for reliability",
            ))

        if heartbeat.work_hours_start >= heartbeat.work_hours_end:
            issues.append(ValidationIssue(
                severity=ValidationSeverity.WARNING,
                field="heartbeat.work_hours",
                message="Work hours start must be before end",
                suggestion="Set work_hours_start < work_hours_end",
            ))

        return issues

    def _validate_encryption(self, encryption: EncryptionConfig) -> List[ValidationIssue]:
        """Validate encryption configuration.

        Args:
            encryption: The encryption configuration to validate.

        Returns:
            List of validation issues found in encryption config.
        """
        issues: List[ValidationIssue] = []

        if encryption.encryption.value not in self.VALID_ENCRYPTIONS:
            issues.append(ValidationIssue(
                severity=ValidationSeverity.ERROR,
                field="encryption.encryption",
                message=f"Invalid encryption algorithm: {encryption.encryption}",
                suggestion=f"Use one of: {', '.join(sorted(self.VALID_ENCRYPTIONS))}",
            ))

        if encryption.encoding.value not in self.VALID_ENCODINGS:
            issues.append(ValidationIssue(
                severity=ValidationSeverity.ERROR,
                field="encryption.encoding",
                message=f"Invalid encoding type: {encryption.encoding}",
                suggestion=f"Use one of: {', '.join(sorted(self.VALID_ENCODINGS))}",
            ))

        if encryption.encryption != EncryptionAlgorithm.NONE and not encryption.key:
            issues.append(ValidationIssue(
                severity=ValidationSeverity.WARNING,
                field="encryption.key",
                message="Encryption key is empty, will auto-generate",
                suggestion="Provide a fixed key for consistent encryption across sessions",
            ))

        return issues

    def _validate_dns(self, dns: DnsProfileConfig) -> List[ValidationIssue]:
        """Validate DNS configuration.

        Args:
            dns: The DNS configuration to validate.

        Returns:
            List of validation issues found in DNS config.
        """
        issues: List[ValidationIssue] = []

        if dns.query_type.upper() not in self.VALID_QUERY_TYPES:
            issues.append(ValidationIssue(
                severity=ValidationSeverity.ERROR,
                field="dns.query_type",
                message=f"Invalid DNS query type: {dns.query_type}",
                suggestion=f"Use one of: {', '.join(sorted(self.VALID_QUERY_TYPES))}",
            ))

        if not dns.dns_domain:
            issues.append(ValidationIssue(
                severity=ValidationSeverity.ERROR,
                field="dns.dns_domain",
                message="DNS domain is required for DNS tunneling",
                suggestion="Set dns_domain to your controlled domain",
            ))

        if dns.max_subdomain_length > 63:
            issues.append(ValidationIssue(
                severity=ValidationSeverity.ERROR,
                field="dns.max_subdomain_length",
                message="Subdomain length exceeds DNS limit of 63 characters",
                suggestion="Set max_subdomain_length to 63 or less",
            ))

        return issues

    def _validate_cross_field(self, profile: MalleableProfile) -> List[ValidationIssue]:
        """Validate cross-field consistency.

        Args:
            profile: The profile to validate.

        Returns:
            List of validation issues found in cross-field checks.
        """
        issues: List[ValidationIssue] = []

        if ProtocolType.HTTPS in profile.protocols and not profile.http.http_uri:
            issues.append(ValidationIssue(
                severity=ValidationSeverity.ERROR,
                field="http.http_uri",
                message="HTTPS protocol requires HTTP URI configuration",
                suggestion="Add http_uri configuration for HTTPS protocol",
            ))

        if ProtocolType.DNS in profile.protocols and not profile.dns.dns_domain:
            issues.append(ValidationIssue(
                severity=ValidationSeverity.ERROR,
                field="dns.dns_domain",
                message="DNS protocol requires DNS domain configuration",
                suggestion="Add dns_domain configuration for DNS protocol",
            ))

        return issues


# =============================================================================
# Profile Loader with Hot-Reload
# =============================================================================

class ProfileLoader:
    """Loads, parses, validates, and hot-reloads Malleable C2 Profiles.

    Monitors profile directories for changes and automatically reloads
    modified profiles without requiring C2 server restart.

    Attributes:
        _profiles: Dictionary of loaded profiles keyed by name
        _validator: Profile validator instance
        _watch_dirs: Directories being watched for changes
        _file_hashes: File hash cache for change detection
        _watch_task: Async file watcher task
        _callbacks: Reload notification callbacks
        _running: Whether the watcher is active
    """

    def __init__(self) -> None:
        """Initialize the ProfileLoader with empty state."""
        self._profiles: Dict[str, MalleableProfile] = {}
        self._validator = ProfileValidator()
        self._watch_dirs: Set[str] = set()
        self._file_hashes: Dict[str, str] = {}
        self._watch_task: Optional[asyncio.Task] = None
        self._callbacks: List[Callable[..., Coroutine]] = []
        self._running = False

    @property
    def profiles(self) -> Dict[str, MalleableProfile]:
        """Get all loaded profiles.

        Returns:
            Dictionary mapping profile names to MalleableProfile instances.
        """
        return dict(self._profiles)

    def get_profile(self, name: str) -> Optional[MalleableProfile]:
        """Get a specific profile by name.

        Args:
            name: The profile name to look up.

        Returns:
            The MalleableProfile instance if found, None otherwise.
        """
        return self._profiles.get(name)

    def get_active_profile(self) -> Optional[MalleableProfile]:
        """Get the currently active profile.

        Returns:
            The active MalleableProfile instance, or None if no profile is active.
        """
        for profile in self._profiles.values():
            if profile.status == ProfileStatus.ACTIVE:
                return profile
        return None

    async def load_from_file(self, file_path: str) -> Tuple[bool, List[ValidationIssue]]:
        """Load a single profile from a YAML file.

        Args:
            file_path: Absolute or relative path to the YAML profile file.

        Returns:
            Tuple of (success, validation_issues).
        """
        try:
            path = Path(file_path)
            if not path.exists():
                logger.error(f"Profile file not found: {file_path}")
                return False, [ValidationIssue(
                    severity=ValidationSeverity.ERROR,
                    field="file_path",
                    message=f"File not found: {file_path}",
                    suggestion="Check the file path and ensure the file exists",
                )]

            content = path.read_text(encoding="utf-8")
            data = yaml.safe_load(content)

            if not isinstance(data, dict):
                return False, [ValidationIssue(
                    severity=ValidationSeverity.ERROR,
                    field="file",
                    message="YAML file must contain a mapping at the root level",
                    suggestion="Ensure the YAML file has proper key-value structure",
                )]

            profile = MalleableProfile.from_dict(data)
            profile.file_path = str(path.absolute())
            profile.checksum = hashlib.sha256(content.encode()).hexdigest()[:16]
            profile.created_at = profile.created_at or datetime.now().isoformat()
            profile.updated_at = datetime.now().isoformat()

            issues = self._validator.validate(profile)
            has_errors = any(
                i.severity == ValidationSeverity.ERROR for i in issues
            )

            if has_errors:
                profile.status = ProfileStatus.ERROR
                logger.warning(
                    f"Profile '{profile.name}' loaded with errors: "
                    f"{len(issues)} issues found"
                )
            else:
                profile.status = ProfileStatus.INACTIVE
                logger.info(f"Profile '{profile.name}' loaded successfully from {file_path}")

            self._profiles[profile.name] = profile
            self._file_hashes[str(path.absolute())] = profile.checksum

            return not has_errors, issues

        except yaml.YAMLError as e:
            logger.error(f"YAML parsing error in {file_path}: {e}")
            return False, [ValidationIssue(
                severity=ValidationSeverity.ERROR,
                field="yaml",
                message=f"YAML parsing error: {e}",
                suggestion="Fix YAML syntax errors in the profile file",
            )]
        except Exception as e:
            logger.error(f"Failed to load profile from {file_path}: {e}")
            return False, [ValidationIssue(
                severity=ValidationSeverity.ERROR,
                field="file",
                message=f"Failed to load profile: {e}",
                suggestion="Check file permissions and format",
            )]

    async def load_from_directory(self, dir_path: str) -> Dict[str, Tuple[bool, List[ValidationIssue]]]:
        """Load all YAML profile files from a directory.

        Args:
            dir_path: Path to the directory containing profile YAML files.

        Returns:
            Dictionary mapping file paths to (success, issues) tuples.
        """
        results: Dict[str, Tuple[bool, List[ValidationIssue]]] = {}
        path = Path(dir_path)

        if not path.exists() or not path.is_dir():
            logger.error(f"Profile directory not found: {dir_path}")
            return results

        yaml_files = list(path.glob("*.yaml")) + list(path.glob("*.yml"))

        for yaml_file in yaml_files:
            success, issues = await self.load_from_file(str(yaml_file))
            results[str(yaml_file)] = (success, issues)

        logger.info(
            f"Loaded {len(results)} profiles from {dir_path}: "
            f"{sum(1 for s, _ in results.values() if s)} successful, "
            f"{sum(1 for s, _ in results.values() if not s)} failed"
        )

        return results

    async def reload_profile(self, name: str) -> Tuple[bool, List[ValidationIssue]]:
        """Reload a specific profile from its source file.

        Args:
            name: The profile name to reload.

        Returns:
            Tuple of (success, validation_issues).
        """
        profile = self._profiles.get(name)
        if not profile or not profile.file_path:
            return False, [ValidationIssue(
                severity=ValidationSeverity.ERROR,
                field="name",
                message=f"Profile '{name}' not found or has no file path",
                suggestion="Load the profile from a file first",
            )]

        was_active = profile.status == ProfileStatus.ACTIVE
        success, issues = await self.load_from_file(profile.file_path)

        if success and was_active:
            self._profiles[name].status = ProfileStatus.ACTIVE

        if success:
            await self._notify_reload(name)

        return success, issues

    def activate_profile(self, name: str) -> bool:
        """Activate a profile by name.

        Args:
            name: The profile name to activate.

        Returns:
            True if the profile was found and activated, False otherwise.
        """
        if name not in self._profiles:
            logger.warning(f"Cannot activate unknown profile: {name}")
            return False

        for profile in self._profiles.values():
            if profile.status == ProfileStatus.ACTIVE:
                profile.status = ProfileStatus.INACTIVE

        self._profiles[name].status = ProfileStatus.ACTIVE
        logger.info(f"Profile '{name}' activated")
        return True

    def deactivate_profile(self, name: str) -> bool:
        """Deactivate a profile by name.

        Args:
            name: The profile name to deactivate.

        Returns:
            True if the profile was found and deactivated, False otherwise.
        """
        profile = self._profiles.get(name)
        if not profile:
            return False

        profile.status = ProfileStatus.INACTIVE
        logger.info(f"Profile '{name}' deactivated")
        return True

    def register_reload_callback(self, callback: Callable[..., Coroutine]) -> None:
        """Register a callback for profile reload notifications.

        Args:
            callback: Async callable that receives (profile_name, profile) arguments.
        """
        self._callbacks.append(callback)

    async def _notify_reload(self, profile_name: str) -> None:
        """Notify all registered callbacks about a profile reload.

        Args:
            profile_name: The name of the reloaded profile.
        """
        profile = self._profiles.get(profile_name)
        for callback in self._callbacks:
            try:
                await callback(profile_name, profile)
            except Exception as e:
                logger.error(f"Reload callback error: {e}")

    async def start_watching(self, interval: float = 5.0) -> None:
        """Start watching profile directories for file changes.

        Args:
            interval: Polling interval in seconds for change detection.
        """
        if self._running:
            logger.warning("Profile watcher is already running")
            return

        self._running = True
        self._watch_task = asyncio.create_task(self._watch_loop(interval))
        logger.info(f"Profile watcher started with {interval}s interval")

    async def stop_watching(self) -> None:
        """Stop watching profile directories."""
        self._running = False
        if self._watch_task:
            self._watch_task.cancel()
            try:
                await self._watch_task
            except asyncio.CancelledError:
                pass
            self._watch_task = None
            logger.info("Profile watcher stopped")

    def add_watch_directory(self, dir_path: str) -> None:
        """Add a directory to watch for profile changes.

        Args:
            dir_path: Path to the directory to watch.
        """
        self._watch_dirs.add(dir_path)
        logger.info(f"Added watch directory: {dir_path}")

    async def _watch_loop(self, interval: float) -> None:
        """Main watch loop for detecting profile file changes.

        Args:
            interval: Polling interval in seconds.
        """
        while self._running:
            try:
                await self._check_for_changes()
            except Exception as e:
                logger.error(f"Profile watch loop error: {e}")

            await asyncio.sleep(interval)

    async def _check_for_changes(self) -> None:
        """Check all watched directories for profile file changes."""
        for dir_path in self._watch_dirs:
            path = Path(dir_path)
            if not path.exists():
                continue

            for yaml_file in path.glob("*.yaml"):
                await self._check_file_change(yaml_file)

            for yaml_file in path.glob("*.yml"):
                await self._check_file_change(yaml_file)

    async def _check_file_change(self, file_path: Path) -> None:
        """Check if a specific profile file has changed.

        Args:
            file_path: Path to the profile file to check.
        """
        try:
            content = file_path.read_text(encoding="utf-8")
            current_hash = hashlib.sha256(content.encode()).hexdigest()[:16]
            cached_hash = self._file_hashes.get(str(file_path.absolute()))

            if cached_hash and cached_hash != current_hash:
                logger.info(f"Profile file changed: {file_path}, reloading...")

                data = yaml.safe_load(content)
                if isinstance(data, dict):
                    profile = MalleableProfile.from_dict(data)
                    profile.file_path = str(file_path.absolute())
                    profile.checksum = current_hash
                    profile.updated_at = datetime.now().isoformat()

                    issues = self._validator.validate(profile)
                    has_errors = any(
                        i.severity == ValidationSeverity.ERROR for i in issues
                    )

                    if has_errors:
                        profile.status = ProfileStatus.ERROR
                        logger.warning(
                            f"Hot-reloaded profile '{profile.name}' has errors"
                        )
                    else:
                        was_active = (
                            self._profiles.get(profile.name, MalleableProfile())
                            .status == ProfileStatus.ACTIVE
                        )
                        profile.status = (
                            ProfileStatus.ACTIVE if was_active else ProfileStatus.INACTIVE
                        )
                        logger.info(
                            f"Profile '{profile.name}' hot-reloaded successfully"
                        )

                    self._profiles[profile.name] = profile
                    self._file_hashes[str(file_path.absolute())] = current_hash

                    await self._notify_reload(profile.name)

            elif not cached_hash:
                self._file_hashes[str(file_path.absolute())] = current_hash

        except Exception as e:
            logger.error(f"Error checking file {file_path}: {e}")


# =============================================================================
# Built-in Profile Templates
# =============================================================================

class BuiltInProfiles:
    """Provides built-in Malleable C2 Profile templates.

    These profiles simulate common legitimate traffic patterns to help
    Beacon communications blend in with normal network activity.
    """

    @staticmethod
    def jquery_update() -> MalleableProfile:
        """Create the jQuery update simulation profile.

        Simulates jQuery library update check requests with GET method
        and JavaScript file URI patterns.

        Returns:
            MalleableProfile configured to mimic jQuery update traffic.
        """
        return MalleableProfile(
            name="jquery_update",
            version="1.0.0",
            author="Kunlun Security Lab",
            description="Simulates jQuery AJAX update requests",
            protocols=[ProtocolType.HTTPS],
            http=HttpProfileConfig(
                http_method="GET",
                http_uri="/js/jquery-{{random_string}}.min.js?ts={{timestamp}}",
                user_agent=[
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                ],
                headers={
                    "Accept": "application/javascript, */*;q=0.8",
                    "Accept-Encoding": "gzip, deflate, br",
                    "Accept-Language": "en-US,en;q=0.9",
                    "Cache-Control": "no-cache",
                    "Pragma": "no-cache",
                },
                referer="https://{{hostname}}/index.html",
                body_format=BodyFormat.PLAIN,
            ),
            heartbeat=HeartbeatConfig(
                sleep_time=120,
                jitter=30,
                max_retry=5,
            ),
            encryption=EncryptionConfig(
                encryption=EncryptionAlgorithm.AES_256_GCM,
                encoding=EncodingType.BASE64,
            ),
        )

    @staticmethod
    def google_analytics() -> MalleableProfile:
        """Create the Google Analytics simulation profile.

        Simulates Google Analytics pageview reporting with POST method
        and /collect endpoint patterns.

        Returns:
            MalleableProfile configured to mimic Google Analytics traffic.
        """
        return MalleableProfile(
            name="google_analytics",
            version="1.0.0",
            author="Kunlun Security Lab",
            description="Simulates Google Analytics pageview reporting",
            protocols=[ProtocolType.HTTPS],
            http=HttpProfileConfig(
                http_method="POST",
                http_uri="/collect?v=1&t=pageview&_={{timestamp}}",
                user_agent=[
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                ],
                headers={
                    "Accept": "*/*",
                    "Accept-Encoding": "gzip, deflate, br",
                    "Accept-Language": "en-US,en;q=0.9",
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Origin": "https://www.google.com",
                    "Referer": "https://www.google.com/",
                },
                cookie="_ga={{random_string}}; _gid={{random_string}}",
                body_format=BodyFormat.FORM,
                body_template=(
                    "v=1&t=pageview&tid=UA-{{random_int}}-1&cid={{beacon_id}}"
                    "&dl=https%3A%2F%2F{{hostname}}%2F&dt={{random_string}}"
                ),
                referer="https://www.google.com/",
            ),
            heartbeat=HeartbeatConfig(
                sleep_time=300,
                jitter=20,
                max_retry=3,
            ),
            encryption=EncryptionConfig(
                encryption=EncryptionAlgorithm.AES_256_GCM,
                encoding=EncodingType.BASE64,
            ),
        )

    @staticmethod
    def microsoft_office() -> MalleableProfile:
        """Create the Microsoft Office 365 telemetry simulation profile.

        Simulates Office 365 telemetry and diagnostic reporting with
        POST method and /api/telemetry endpoint patterns.

        Returns:
            MalleableProfile configured to mimic Office 365 telemetry traffic.
        """
        return MalleableProfile(
            name="microsoft_office",
            version="1.0.0",
            author="Kunlun Security Lab",
            description="Simulates Office 365 telemetry requests",
            protocols=[ProtocolType.HTTPS],
            http=HttpProfileConfig(
                http_method="POST",
                http_uri="/api/v1/telemetry/{{beacon_id}}",
                user_agent=[
                    "Microsoft Office/16.0 (Windows NT 10.0; Microsoft Outlook 16.0.1234; Pro)",
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 "
                    "Edge/120.0.0.0",
                ],
                headers={
                    "Accept": "application/json",
                    "Accept-Encoding": "gzip, deflate",
                    "Accept-Language": "en-US,en;q=0.9",
                    "Content-Type": "application/json",
                    "Authorization": "Bearer {{random_string}}",
                    "X-Client-Info": "office-telemetry/1.0",
                },
                body_format=BodyFormat.JSON,
                body_template=(
                    '{"deviceId":"{{beacon_id}}","timestamp":{{timestamp}},'
                    '"events":[{"type":"heartbeat","data":"{{random_string}}"}]}'
                ),
                referer="https://outlook.office365.com/",
            ),
            heartbeat=HeartbeatConfig(
                sleep_time=180,
                jitter=25,
                max_retry=5,
            ),
            encryption=EncryptionConfig(
                encryption=EncryptionAlgorithm.AES_256_GCM,
                encoding=EncodingType.BASE64,
            ),
        )

    @staticmethod
    def cdn_resource() -> MalleableProfile:
        """Create the CDN resource request simulation profile.

        Simulates CDN static resource fetching with GET method and
        random asset URI patterns.

        Returns:
            MalleableProfile configured to mimic CDN resource requests.
        """
        return MalleableProfile(
            name="cdn_resource",
            version="1.0.0",
            author="Kunlun Security Lab",
            description="Simulates CDN static resource requests",
            protocols=[ProtocolType.HTTPS],
            http=HttpProfileConfig(
                http_method="GET",
                http_uri="/assets/{{random_string}}.js?v={{random_int}}",
                user_agent=[
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
                    "(KHTML, like Gecko) Version/17.0 Safari/605.1.15",
                    "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
                ],
                headers={
                    "Accept": "*/*",
                    "Accept-Encoding": "gzip, deflate, br",
                    "Accept-Language": "en-US,en;q=0.9",
                    "Cache-Control": "max-age=31536000",
                    "If-None-Match": '"{{random_string}}"',
                },
                referer="https://cdn.{{hostname}}/app.html",
                body_format=BodyFormat.PLAIN,
            ),
            heartbeat=HeartbeatConfig(
                sleep_time=90,
                jitter=40,
                max_retry=3,
            ),
            encryption=EncryptionConfig(
                encryption=EncryptionAlgorithm.AES_256_GCM,
                encoding=EncodingType.BASE64,
            ),
        )

    @staticmethod
    def api_mock() -> MalleableProfile:
        """Create the REST API status check simulation profile.

        Simulates common REST API health check requests with GET method
        and /api/v2/status endpoint patterns.

        Returns:
            MalleableProfile configured to mimic REST API status checks.
        """
        return MalleableProfile(
            name="api_mock",
            version="1.0.0",
            author="Kunlun Security Lab",
            description="Simulates REST API health check requests",
            protocols=[ProtocolType.HTTPS],
            http=HttpProfileConfig(
                http_method="GET",
                http_uri="/api/v2/status?_={{timestamp}}",
                user_agent=[
                    "python-requests/2.31.0",
                    "axios/1.6.0",
                    "node-fetch/3.3.0",
                ],
                headers={
                    "Accept": "application/json",
                    "Accept-Encoding": "gzip, deflate",
                    "Accept-Language": "en-US,en;q=0.9",
                    "Content-Type": "application/json",
                    "X-Request-Id": "{{random_string}}",
                    "X-Api-Version": "2.0",
                },
                body_format=BodyFormat.JSON,
            ),
            heartbeat=HeartbeatConfig(
                sleep_time=60,
                jitter=15,
                max_retry=5,
            ),
            encryption=EncryptionConfig(
                encryption=EncryptionAlgorithm.AES_256_GCM,
                encoding=EncodingType.BASE64,
            ),
        )

    @classmethod
    def get_all(cls) -> List[MalleableProfile]:
        """Get all built-in profiles.

        Returns:
            List of all built-in MalleableProfile instances.
        """
        return [
            cls.jquery_update(),
            cls.google_analytics(),
            cls.microsoft_office(),
            cls.cdn_resource(),
            cls.api_mock(),
        ]


# =============================================================================
# Global Singleton
# =============================================================================

_profile_loader: Optional[ProfileLoader] = None


def get_profile_loader() -> ProfileLoader:
    """Get the global ProfileLoader singleton instance.

    Returns:
        The singleton ProfileLoader instance.
    """
    global _profile_loader
    if _profile_loader is None:
        _profile_loader = ProfileLoader()
    return _profile_loader


__all__ = [
    "MalleableProfile",
    "ProfileLoader",
    "ProfileValidator",
    "BuiltInProfiles",
    "HttpProfileConfig",
    "HeartbeatConfig",
    "EncryptionConfig",
    "DnsProfileConfig",
    "ValidationIssue",
    "EncryptionAlgorithm",
    "EncodingType",
    "BodyFormat",
    "ProtocolType",
    "ProfileStatus",
    "ValidationSeverity",
    "get_profile_loader",
]
