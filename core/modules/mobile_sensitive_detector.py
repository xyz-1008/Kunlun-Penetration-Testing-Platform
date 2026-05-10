"""Mobile Sensitive Detector: Hardcoded key/URL/email extraction.

Provides:
- Extract hardcoded strings from classes.dex: URLs, IPs, emails, API key patterns, JWT, password keywords
- Parse resource.arsc to extract resource strings
- Extract sensitive file names from assets directory (.pem, .p12, .jks, .bks, .properties)
- Detect Firebase/Google Cloud/AWS configuration files
- Comprehensive pattern matching for secrets detection
- Risk classification for detected sensitive information
"""

import base64
import hashlib
import json
import logging
import os
import re
import time
import zipfile
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


class SecretType(Enum):
    """Types of detected secrets."""
    URL = "url"
    IP_ADDRESS = "ip_address"
    EMAIL = "email"
    API_KEY = "api_key"
    JWT_TOKEN = "jwt_token"
    PASSWORD = "password"
    AWS_KEY = "aws_key"
    FIREBASE_CONFIG = "firebase_config"
    PRIVATE_KEY = "private_key"
    CONNECTION_STRING = "connection_string"
    ENCRYPTION_KEY = "encryption_key"
    CREDENTIAL = "credential"


class RiskLevel(Enum):
    """Risk levels for detected secrets."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class DetectedSecret:
    """Detected sensitive information.

    Attributes:
        secret_id: Unique secret identifier
        secret_type: Type of secret
        risk_level: Risk severity
        value: Detected value (may be masked)
        location: File/location where found
        context: Surrounding context
        confidence: Detection confidence (0.0-1.0)
    """
    secret_id: str = ""
    secret_type: SecretType = SecretType.URL
    risk_level: RiskLevel = RiskLevel.INFO
    value: str = ""
    location: str = ""
    context: str = ""
    confidence: float = 0.0


@dataclass
class SensitiveFile:
    """Sensitive file found in the application.

    Attributes:
        file_path: File path within the package
        file_type: File type/extension
        risk_level: Risk severity
        file_size: File size in bytes
        description: Description of why file is sensitive
    """
    file_path: str = ""
    file_type: str = ""
    risk_level: RiskLevel = RiskLevel.INFO
    file_size: int = 0
    description: str = ""


@dataclass
class DetectionResult:
    """Complete sensitive information detection result.

    Attributes:
        source_path: Path to analyzed file
        detected_secrets: List of detected secrets
        sensitive_files: List of sensitive files
        total_strings_analyzed: Total strings analyzed
        detection_timestamp: Detection timestamp
    """
    source_path: str = ""
    detected_secrets: List[DetectedSecret] = field(default_factory=list)
    sensitive_files: List[SensitiveFile] = field(default_factory=list)
    total_strings_analyzed: int = 0
    detection_timestamp: float = 0.0


class SensitiveDetector:
    """Detects hardcoded sensitive information in mobile applications.

    Provides comprehensive pattern matching for URLs, IPs, emails, API keys,
    JWT tokens, passwords, and cloud configuration files.
    """

    URL_PATTERN = re.compile(
        r'https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]{10,200}',
        re.IGNORECASE,
    )

    IP_PATTERN = re.compile(
        r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b',
    )

    EMAIL_PATTERN = re.compile(
        r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
    )

    API_KEY_PATTERNS = {
        "generic_api_key": re.compile(r'(?:api[_-]?key|apikey)\s*[=:]\s*["\']?([a-zA-Z0-9_\-]{16,})["\']?', re.IGNORECASE),
        "aws_access_key": re.compile(r'(?:AKIA)[0-9A-Z]{16}'),
        "aws_secret_key": re.compile(r'(?:aws[_-]?secret)[_\s]*[=:]\s*["\']?([a-zA-Z0-9/+=]{40})["\']?', re.IGNORECASE),
        "firebase_api_key": re.compile(r'AIza[0-9A-Za-z\-_]{35}'),
        "google_oauth": re.compile(r'[0-9]+-[a-z0-9_]{32}\.apps\.googleusercontent\.com'),
        "github_token": re.compile(r'ghp_[a-zA-Z0-9]{36}'),
        "slack_token": re.compile(r'xox[baprs]-[a-zA-Z0-9\-]{10,}'),
        "jwt_token": re.compile(r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*'),
    }

    PASSWORD_PATTERNS = {
        "password_assignment": re.compile(r'(?:password|passwd|pwd)\s*[=:]\s*["\']([^\s"\']{4,})["\']', re.IGNORECASE),
        "connection_string": re.compile(r'(?:Server|Data Source|Host|Address)\s*=\s*[^\s;]+.*(?:Password|Pwd)\s*=\s*[^\s;]+', re.IGNORECASE),
        "basic_auth": re.compile(r'(?:Authorization)\s*:\s*Basic\s+([a-zA-Z0-9+/=]{10,})', re.IGNORECASE),
    }

    PRIVATE_KEY_PATTERNS = {
        "rsa_key": re.compile(r'-----BEGIN (?:RSA )?PRIVATE KEY-----'),
        "ec_key": re.compile(r'-----BEGIN EC PRIVATE KEY-----'),
        "dsa_key": re.compile(r'-----BEGIN DSA PRIVATE KEY-----'),
    }

    SENSITIVE_FILE_EXTENSIONS = {
        ".pem": ("PEM Certificate", RiskLevel.HIGH),
        ".p12": ("PKCS12 Keystore", RiskLevel.CRITICAL),
        ".pfx": ("PKCS12 Certificate", RiskLevel.CRITICAL),
        ".jks": ("Java Keystore", RiskLevel.CRITICAL),
        ".bks": ("Bouncy Castle Keystore", RiskLevel.CRITICAL),
        ".keystore": ("Keystore", RiskLevel.CRITICAL),
        ".properties": ("Properties File", RiskLevel.MEDIUM),
        ".env": ("Environment File", RiskLevel.HIGH),
        ".config": ("Configuration File", RiskLevel.MEDIUM),
        ".json": ("JSON Config", RiskLevel.LOW),
        ".xml": ("XML Config", RiskLevel.LOW),
        ".sql": ("SQL File", RiskLevel.MEDIUM),
        ".db": ("Database File", RiskLevel.HIGH),
    }

    CLOUD_CONFIG_FILES = {
        "google-services.json": ("Google Services Config", RiskLevel.HIGH),
        "GoogleService-Info.plist": ("Firebase Config", RiskLevel.HIGH),
        "awsconfiguration.json": ("AWS Config", RiskLevel.HIGH),
        "aws-configuration.json": ("AWS Config", RiskLevel.HIGH),
        "firebase.json": ("Firebase Config", RiskLevel.HIGH),
        "app-config.json": ("App Config", RiskLevel.MEDIUM),
        "config.json": ("Configuration", RiskLevel.LOW),
        "secrets.json": ("Secrets File", RiskLevel.CRITICAL),
    }

    def __init__(self) -> None:
        """Initialize sensitive information detector."""
        self._secret_counter = 0

    async def detect_from_apk(self, apk_path: str) -> DetectionResult:
        """Detect sensitive information in an APK file.

        Args:
            apk_path: Path to the APK file.

        Returns:
            DetectionResult with all detected secrets and files.

        Raises:
            FileNotFoundError: If APK file does not exist.
        """
        if not os.path.exists(apk_path):
            raise FileNotFoundError(f"APK file not found: {apk_path}")

        result = DetectionResult(
            source_path=apk_path,
            detection_timestamp=time.time(),
        )

        with zipfile.ZipFile(apk_path, "r") as zf:
            strings = self._extract_strings_from_dex(zf)
            result.total_strings_analyzed = len(strings)

            for text_block in strings:
                secrets = self._scan_text(text_block, "classes.dex")
                result.detected_secrets.extend(secrets)

            result.sensitive_files = self._find_sensitive_files(zf)

        return result

    async def detect_from_ipa(self, ipa_path: str) -> DetectionResult:
        """Detect sensitive information in an IPA file.

        Args:
            ipa_path: Path to the IPA file.

        Returns:
            DetectionResult with all detected secrets and files.

        Raises:
            FileNotFoundError: If IPA file does not exist.
        """
        if not os.path.exists(ipa_path):
            raise FileNotFoundError(f"IPA file not found: {ipa_path}")

        result = DetectionResult(
            source_path=ipa_path,
            detection_timestamp=time.time(),
        )

        with zipfile.ZipFile(ipa_path, "r") as zf:
            strings = self._extract_strings_from_binary(zf)
            result.total_strings_analyzed = len(strings)

            for text_block in strings:
                secrets = self._scan_text(text_block, "binary")
                result.detected_secrets.extend(secrets)

            result.sensitive_files = self._find_sensitive_files(zf)

        return result

    async def detect_from_file(self, file_path: str) -> DetectionResult:
        """Detect sensitive information in a single file.

        Args:
            file_path: Path to the file to analyze.

        Returns:
            DetectionResult with all detected secrets.

        Raises:
            FileNotFoundError: If file does not exist.
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        result = DetectionResult(
            source_path=file_path,
            detection_timestamp=time.time(),
        )

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            result.total_strings_analyzed = 1
            result.detected_secrets = self._scan_text(content, file_path)

        except Exception as e:
            logger.warning(f"Failed to read file: {e}")

        return result

    def _extract_strings_from_dex(self, zf: zipfile.ZipFile) -> List[str]:
        """Extract strings from DEX files in APK.

        Args:
            zf: ZipFile object of the APK.

        Returns:
            List of extracted string blocks.
        """
        strings = []

        dex_files = [f for f in zf.namelist() if f.endswith(".dex")]

        for dex_file in dex_files:
            try:
                data = zf.read(dex_file)
                text_blocks = self._extract_printable_strings(data)
                strings.extend(text_blocks)
            except Exception as e:
                logger.warning(f"Failed to extract from {dex_file}: {e}")

        string_files = [f for f in zf.namelist() if f.endswith((".xml", ".json", ".properties"))]
        for string_file in string_files:
            try:
                data = zf.read(string_file)
                text = data.decode("utf-8", errors="ignore")
                strings.append(text)
            except Exception:
                continue

        return strings

    def _extract_strings_from_binary(self, zf: zipfile.ZipFile) -> List[str]:
        """Extract strings from binary files in IPA.

        Args:
            zf: ZipFile object of the IPA.

        Returns:
            List of extracted string blocks.
        """
        strings = []

        binary_files = [
            f for f in zf.namelist()
            if not f.endswith("/") and not f.endswith((".png", ".jpg", ".plist"))
        ]

        for binary_file in binary_files[:10]:
            try:
                data = zf.read(binary_file)
                text_blocks = self._extract_printable_strings(data)
                strings.extend(text_blocks)
            except Exception:
                continue

        plist_files = [f for f in zf.namelist() if f.endswith(".plist")]
        for plist_file in plist_files:
            try:
                data = zf.read(plist_file)
                text = data.decode("utf-8", errors="ignore")
                strings.append(text)
            except Exception:
                continue

        return strings

    def _extract_printable_strings(self, data: bytes, min_length: int = 8) -> List[str]:
        """Extract printable ASCII strings from binary data.

        Args:
            data: Binary data to scan.
            min_length: Minimum string length.

        Returns:
            List of extracted strings.
        """
        strings = []
        current = bytearray()

        for byte in data:
            if 32 <= byte <= 126:
                current.append(byte)
            else:
                if len(current) >= min_length:
                    try:
                        strings.append(current.decode("ascii"))
                    except Exception:
                        pass
                current = bytearray()

        if len(current) >= min_length:
            try:
                strings.append(current.decode("ascii"))
            except Exception:
                pass

        return strings

    def _scan_text(self, text: str, location: str) -> List[DetectedSecret]:
        """Scan text for sensitive patterns.

        Args:
            text: Text to scan.
            location: Source location.

        Returns:
            List of detected secrets.
        """
        secrets = []

        for match in self.URL_PATTERN.finditer(text):
            value = match.group(0)
            if not self._is_safe_url(value):
                secrets.append(self._create_secret(
                    SecretType.URL,
                    RiskLevel.LOW,
                    value,
                    location,
                    text[max(0, match.start()-20):match.end()+20],
                    0.7,
                ))

        for match in self.IP_PATTERN.finditer(text):
            value = match.group(0)
            if not self._is_private_ip(value):
                secrets.append(self._create_secret(
                    SecretType.IP_ADDRESS,
                    RiskLevel.MEDIUM,
                    value,
                    location,
                    text[max(0, match.start()-20):match.end()+20],
                    0.8,
                ))

        for match in self.EMAIL_PATTERN.finditer(text):
            value = match.group(0)
            secrets.append(self._create_secret(
                SecretType.EMAIL,
                RiskLevel.LOW,
                value,
                location,
                text[max(0, match.start()-20):match.end()+20],
                0.9,
            ))

        for key_type, pattern in self.API_KEY_PATTERNS.items():
            for match in pattern.finditer(text):
                value = match.group(0)
                risk = self._get_api_key_risk(key_type)
                secrets.append(self._create_secret(
                    SecretType.API_KEY,
                    risk,
                    self._mask_value(value),
                    location,
                    text[max(0, match.start()-30):match.end()+30],
                    0.85,
                ))

        for pwd_type, pattern in self.PASSWORD_PATTERNS.items():
            for match in pattern.finditer(text):
                value = match.group(0)
                secrets.append(self._create_secret(
                    SecretType.PASSWORD,
                    RiskLevel.CRITICAL,
                    self._mask_value(value),
                    location,
                    text[max(0, match.start()-30):match.end()+30],
                    0.9,
                ))

        for key_type, pattern in self.PRIVATE_KEY_PATTERNS.items():
            for match in pattern.finditer(text):
                secrets.append(self._create_secret(
                    SecretType.PRIVATE_KEY,
                    RiskLevel.CRITICAL,
                    "[PRIVATE KEY DETECTED]",
                    location,
                    text[max(0, match.start()-10):match.end()+50],
                    1.0,
                ))

        return secrets

    def _find_sensitive_files(self, zf: zipfile.ZipFile) -> List[SensitiveFile]:
        """Find sensitive files in the archive.

        Args:
            zf: ZipFile object.

        Returns:
            List of sensitive files found.
        """
        sensitive_files = []

        for file_info in zf.infolist():
            file_name = file_info.filename

            if file_name in self.CLOUD_CONFIG_FILES:
                desc, risk = self.CLOUD_CONFIG_FILES[file_name]
                sensitive_files.append(SensitiveFile(
                    file_path=file_name,
                    file_type="Cloud Config",
                    risk_level=risk,
                    file_size=file_info.file_size,
                    description=desc,
                ))
                continue

            _, ext = os.path.splitext(file_name.lower())
            if ext in self.SENSITIVE_FILE_EXTENSIONS:
                desc, risk = self.SENSITIVE_FILE_EXTENSIONS[ext]
                sensitive_files.append(SensitiveFile(
                    file_path=file_name,
                    file_type=ext,
                    risk_level=risk,
                    file_size=file_info.file_size,
                    description=desc,
                ))

        return sensitive_files

    def _create_secret(
        self,
        secret_type: SecretType,
        risk_level: RiskLevel,
        value: str,
        location: str,
        context: str,
        confidence: float,
    ) -> DetectedSecret:
        """Create a DetectedSecret object.

        Args:
            secret_type: Type of secret.
            risk_level: Risk severity.
            value: Secret value.
            location: Source location.
            context: Surrounding context.
            confidence: Detection confidence.

        Returns:
            DetectedSecret object.
        """
        self._secret_counter += 1

        return DetectedSecret(
            secret_id=f"secret_{self._secret_counter:04d}",
            secret_type=secret_type,
            risk_level=risk_level,
            value=value,
            location=location,
            context=context[:100],
            confidence=confidence,
        )

    def _mask_value(self, value: str, visible_chars: int = 4) -> str:
        """Mask a sensitive value for safe display.

        Args:
            value: Value to mask.
            visible_chars: Number of characters to show at end.

        Returns:
            Masked value string.
        """
        if len(value) <= visible_chars:
            return "****"

        return "****" + value[-visible_chars:]

    def _is_safe_url(self, url: str) -> bool:
        """Check if a URL is likely safe (not sensitive).

        Args:
            url: URL to check.

        Returns:
            True if URL appears safe.
        """
        safe_domains = {
            "schemas.android.com",
            "w3.org",
            "example.com",
            "android.com",
            "developer.android.com",
        }

        for domain in safe_domains:
            if domain in url.lower():
                return True

        return False

    def _is_private_ip(self, ip: str) -> bool:
        """Check if an IP is a private/internal address.

        Args:
            ip: IP address to check.

        Returns:
            True if IP is private.
        """
        if ip.startswith("127.") or ip.startswith("0."):
            return True

        parts = ip.split(".")
        if len(parts) == 4:
            try:
                first = int(parts[0])
                second = int(parts[1])

                if first == 10:
                    return True
                if first == 172 and 16 <= second <= 31:
                    return True
                if first == 192 and second == 168:
                    return True
            except ValueError:
                pass

        return False

    def _get_api_key_risk(self, key_type: str) -> RiskLevel:
        """Get risk level for an API key type.

        Args:
            key_type: API key type identifier.

        Returns:
            RiskLevel for the key type.
        """
        critical_types = {"aws_secret_key", "github_token", "slack_token"}
        high_types = {"aws_access_key", "firebase_api_key", "google_oauth"}

        if key_type in critical_types:
            return RiskLevel.CRITICAL
        if key_type in high_types:
            return RiskLevel.HIGH

        return RiskLevel.MEDIUM
