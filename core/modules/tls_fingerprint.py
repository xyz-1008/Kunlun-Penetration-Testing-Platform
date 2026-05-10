"""
TLS Fingerprint Module - JA3/JA3S customization and fingerprint library management.

This module provides TLS fingerprint spoofing capabilities to make C2 communication
blend in with legitimate browser traffic by mimicking TLS handshake characteristics.

Core capabilities:
    1. JA3 fingerprint customization (client-side TLS fingerprint)
    2. JA3S fingerprint customization (server-side TLS fingerprint)
    3. Built-in fingerprint library for Chrome/Firefox/Edge/Safari
    4. Custom TLS extension ordering and cipher suite prioritization
    5. Automatic fingerprint rotation for anti-detection

Author: Kunlun Security Lab
License: Internal Use Only
"""

from __future__ import annotations

import hashlib
import logging
import random
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# =============================================================================
# Enums
# =============================================================================

class TLSVersion(str, Enum):
    """Supported TLS versions."""

    TLS_1_0 = "TLSv1.0"
    TLS_1_1 = "TLSv1.1"
    TLS_1_2 = "TLSv1.2"
    TLS_1_3 = "TLSv1.3"


class BrowserType(str, Enum):
    """Browser types for fingerprint targeting."""

    CHROME = "chrome"
    FIREFOX = "firefox"
    EDGE = "edge"
    SAFARI = "safari"
    CURL = "curl"
    PYTHON_REQUESTS = "python_requests"


class ServerType(str, Enum):
    """Server types for JA3S fingerprint targeting."""

    NGINX = "nginx"
    APACHE = "apache"
    IIS = "iis"
    CLOUDFLARE = "cloudflare"
    AWS_ALB = "aws_alb"
    AKAMAI = "akamai"


# =============================================================================
# Data Models
# =============================================================================

@dataclass
class CipherSuite:
    """TLS cipher suite definition.

    Attributes:
        name: IANA cipher suite name
        value: Numeric cipher suite value
        description: Human-readable description
    """

    name: str = ""
    value: int = 0
    description: str = ""


@dataclass
class TLSExtension:
    """TLS extension definition.

    Attributes:
        name: Extension name
        value: Numeric extension value
        data: Extension data (hex string)
    """

    name: str = ""
    value: int = 0
    data: str = ""


@dataclass
class EllipticCurve:
    """TLS elliptic curve definition.

    Attributes:
        name: Curve name
        value: Numeric curve value
    """

    name: str = ""
    value: int = 0


@dataclass
class ECPointFormat:
    """TLS elliptic curve point format.

    Attributes:
        name: Format name
        value: Numeric format value
    """

    name: str = ""
    value: int = 0


@dataclass
class TLSFingerprint:
    """Complete TLS fingerprint definition.

    Attributes:
        name: Fingerprint identifier
        browser: Target browser type
        version: Browser/server version
        tls_version: TLS protocol version
        cipher_suites: Ordered list of cipher suite values
        extensions: Ordered list of extension values
        elliptic_curves: Ordered list of EC values
        ec_point_formats: Ordered list of EC point format values
        ja3_hash: Computed JA3 fingerprint hash
        ja3_string: JA3 string representation
        user_agent: Associated User-Agent string
        metadata: Additional metadata
    """

    name: str = ""
    browser: BrowserType = BrowserType.CHROME
    version: str = ""
    tls_version: TLSVersion = TLSVersion.TLS_1_3
    cipher_suites: List[int] = field(default_factory=list)
    extensions: List[int] = field(default_factory=list)
    elliptic_curves: List[int] = field(default_factory=list)
    ec_point_formats: List[int] = field(default_factory=list)
    ja3_hash: str = ""
    ja3_string: str = ""
    user_agent: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def compute_ja3(self) -> str:
        """Compute the JA3 fingerprint string.

        JA3 format: SSLVersion,Cipher,Extension,EllipticCurve,EllipticCurvePointFormat

        Returns:
            JA3 string representation.
        """
        ssl_version = self._ssl_version_to_int()
        cipher_str = ",".join(str(c) for c in self.cipher_suites)
        ext_str = ",".join(str(e) for e in self.extensions)
        curve_str = ",".join(str(c) for c in self.elliptic_curves)
        point_str = ",".join(str(p) for p in self.ec_point_formats)

        self.ja3_string = f"{ssl_version},{cipher_str},{ext_str},{curve_str},{point_str}"
        self.ja3_hash = hashlib.md5(self.ja3_string.encode()).hexdigest()

        return self.ja3_string

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation.

        Returns:
            Dictionary containing all fingerprint fields.
        """
        return {
            "name": self.name,
            "browser": self.browser.value,
            "version": self.version,
            "tls_version": self.tls_version.value,
            "cipher_suites": self.cipher_suites,
            "extensions": self.extensions,
            "elliptic_curves": self.elliptic_curves,
            "ec_point_formats": self.ec_point_formats,
            "ja3_hash": self.ja3_hash,
            "ja3_string": self.ja3_string,
            "user_agent": self.user_agent,
        }

    def _ssl_version_to_int(self) -> int:
        """Convert TLS version to SSL version integer.

        Returns:
            SSL version integer (0x0301 = TLS 1.0, etc.)
        """
        mapping = {
            TLSVersion.TLS_1_0: 0x0301,
            TLSVersion.TLS_1_1: 0x0302,
            TLSVersion.TLS_1_2: 0x0303,
            TLSVersion.TLS_1_3: 0x0304,
        }
        return mapping.get(self.tls_version, 0x0303)


@dataclass
class ServerFingerprint:
    """Server-side TLS fingerprint (JA3S).

    Attributes:
        name: Fingerprint identifier
        server_type: Target server type
        tls_version: TLS protocol version
        cipher_suite: Selected cipher suite value
        extensions: Ordered list of extension values
        ja3s_hash: Computed JA3S fingerprint hash
        ja3s_string: JA3S string representation
    """

    name: str = ""
    server_type: ServerType = ServerType.NGINX
    tls_version: TLSVersion = TLSVersion.TLS_1_2
    cipher_suite: int = 0
    extensions: List[int] = field(default_factory=list)
    ja3s_hash: str = ""
    ja3s_string: str = ""

    def compute_ja3s(self) -> str:
        """Compute the JA3S fingerprint string.

        JA3S format: SSLVersion,Cipher,Extension

        Returns:
            JA3S string representation.
        """
        ssl_version = self._ssl_version_to_int()
        ext_str = ",".join(str(e) for e in self.extensions)

        self.ja3s_string = f"{ssl_version},{self.cipher_suite},{ext_str}"
        self.ja3s_hash = hashlib.md5(self.ja3s_string.encode()).hexdigest()

        return self.ja3s_string

    def _ssl_version_to_int(self) -> int:
        """Convert TLS version to SSL version integer."""
        mapping = {
            TLSVersion.TLS_1_0: 0x0301,
            TLSVersion.TLS_1_1: 0x0302,
            TLSVersion.TLS_1_2: 0x0303,
            TLSVersion.TLS_1_3: 0x0304,
        }
        return mapping.get(self.tls_version, 0x0303)


# =============================================================================
# Built-in Fingerprint Library
# =============================================================================

class BuiltInFingerprints:
    """Built-in TLS fingerprint library for major browsers and servers.

    Provides pre-configured JA3/JA3S fingerprints that match real-world
    browser and server TLS handshake characteristics.
    """

    @classmethod
    def get_chrome_120(cls) -> TLSFingerprint:
        """Get Chrome 120+ TLS fingerprint.

        Returns:
            TLSFingerprint matching Chrome 120+ TLS handshake.
        """
        fp = TLSFingerprint(
            name="chrome_120",
            browser=BrowserType.CHROME,
            version="120.0.6099",
            tls_version=TLSVersion.TLS_1_3,
            cipher_suites=[
                0x1301,  # TLS_AES_128_GCM_SHA256
                0x1302,  # TLS_AES_256_GCM_SHA384
                0x1303,  # TLS_CHACHA20_POLY1305_SHA256
                0xC02B,  # TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
                0xC02F,  # TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
                0xC02C,  # TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
                0xC030,  # TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
                0xCCA9,  # TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
                0xCCA8,  # TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
                0xC013,  # TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
                0xC014,  # TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
                0x009C,  # TLS_RSA_WITH_AES_128_GCM_SHA256
                0x009D,  # TLS_RSA_WITH_AES_256_GCM_SHA384
                0x002F,  # TLS_RSA_WITH_AES_128_CBC_SHA
                0x0035,  # TLS_RSA_WITH_AES_256_CBC_SHA
            ],
            extensions=[
                0x0000,  # server_name (SNI)
                0x0005,  # status_request
                0x000A,  # supported_groups
                0x000B,  # ec_point_formats
                0x000D,  # signature_algorithms
                0x0012,  # signed_certificate_timestamp
                0x0015,  # padding
                0x0017,  # extended_master_secret
                0x001B,  # compress_certificate
                0x0022,  # delegated_credentials
                0x0023,  # session_ticket
                0x002B,  # supported_versions
                0x002D,  # psk_key_exchange_modes
                0x0033,  # key_share
                0x0039,  # encrypted_client_hello
                0xFF01,  # renegotiation_info
            ],
            elliptic_curves=[
                0x001D,  # X25519
                0x0017,  # secp256r1
                0x0018,  # secp384r1
                0x0019,  # secp521r1
            ],
            ec_point_formats=[0],  # uncompressed
            user_agent=(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            ),
        )
        fp.compute_ja3()
        return fp

    @classmethod
    def get_firefox_120(cls) -> TLSFingerprint:
        """Get Firefox 120+ TLS fingerprint.

        Returns:
            TLSFingerprint matching Firefox 120+ TLS handshake.
        """
        fp = TLSFingerprint(
            name="firefox_120",
            browser=BrowserType.FIREFOX,
            version="120.0",
            tls_version=TLSVersion.TLS_1_3,
            cipher_suites=[
                0x1301,  # TLS_AES_128_GCM_SHA256
                0x1303,  # TLS_CHACHA20_POLY1305_SHA256
                0x1302,  # TLS_AES_256_GCM_SHA384
                0xC02B,  # TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
                0xC02F,  # TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
                0xCCA9,  # TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
                0xCCA8,  # TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
                0xC02C,  # TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
                0xC030,  # TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
                0xC00A,  # TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
                0xC014,  # TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
                0x009C,  # TLS_RSA_WITH_AES_128_GCM_SHA256
                0x009D,  # TLS_RSA_WITH_AES_256_GCM_SHA384
                0x002F,  # TLS_RSA_WITH_AES_128_CBC_SHA
                0x0035,  # TLS_RSA_WITH_AES_256_CBC_SHA
            ],
            extensions=[
                0x0000,  # server_name
                0x0005,  # status_request
                0x000A,  # supported_groups
                0x000B,  # ec_point_formats
                0x000D,  # signature_algorithms
                0x0012,  # signed_certificate_timestamp
                0x0015,  # padding
                0x0017,  # extended_master_secret
                0x001B,  # compress_certificate
                0x0022,  # delegated_credentials
                0x0023,  # session_ticket
                0x002B,  # supported_versions
                0x002D,  # psk_key_exchange_modes
                0x0033,  # key_share
                0xFE0D,  # encrypted_client_hello (draft)
                0xFF01,  # renegotiation_info
            ],
            elliptic_curves=[
                0x001D,  # X25519
                0x0017,  # secp256r1
                0x0018,  # secp384r1
                0x0019,  # secp521r1
                0x0100,  # ffdhe2048
                0x0101,  # ffdhe3072
            ],
            ec_point_formats=[0],
            user_agent=(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) "
                "Gecko/20100101 Firefox/120.0"
            ),
        )
        fp.compute_ja3()
        return fp

    @classmethod
    def get_edge_120(cls) -> TLSFingerprint:
        """Get Edge 120+ TLS fingerprint.

        Returns:
            TLSFingerprint matching Edge 120+ TLS handshake.
        """
        fp = TLSFingerprint(
            name="edge_120",
            browser=BrowserType.EDGE,
            version="120.0.2210",
            tls_version=TLSVersion.TLS_1_3,
            cipher_suites=[
                0x1301,  # TLS_AES_128_GCM_SHA256
                0x1302,  # TLS_AES_256_GCM_SHA384
                0x1303,  # TLS_CHACHA20_POLY1305_SHA256
                0xC02B,  # TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
                0xC02F,  # TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
                0xC02C,  # TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
                0xC030,  # TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
                0xCCA9,  # TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
                0xCCA8,  # TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
                0xC013,  # TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
                0xC014,  # TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
                0x009C,  # TLS_RSA_WITH_AES_128_GCM_SHA256
                0x009D,  # TLS_RSA_WITH_AES_256_GCM_SHA384
                0x002F,  # TLS_RSA_WITH_AES_128_CBC_SHA
                0x0035,  # TLS_RSA_WITH_AES_256_CBC_SHA
            ],
            extensions=[
                0x0000,  # server_name
                0x0005,  # status_request
                0x000A,  # supported_groups
                0x000B,  # ec_point_formats
                0x000D,  # signature_algorithms
                0x0012,  # signed_certificate_timestamp
                0x0015,  # padding
                0x0017,  # extended_master_secret
                0x001B,  # compress_certificate
                0x0022,  # delegated_credentials
                0x0023,  # session_ticket
                0x002B,  # supported_versions
                0x002D,  # psk_key_exchange_modes
                0x0033,  # key_share
                0x0039,  # encrypted_client_hello
                0xFF01,  # renegotiation_info
            ],
            elliptic_curves=[
                0x001D,  # X25519
                0x0017,  # secp256r1
                0x0018,  # secp384r1
                0x0019,  # secp521r1
            ],
            ec_point_formats=[0],
            user_agent=(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0"
            ),
        )
        fp.compute_ja3()
        return fp

    @classmethod
    def get_safari_17(cls) -> TLSFingerprint:
        """Get Safari 17 TLS fingerprint.

        Returns:
            TLSFingerprint matching Safari 17 TLS handshake.
        """
        fp = TLSFingerprint(
            name="safari_17",
            browser=BrowserType.SAFARI,
            version="17.2",
            tls_version=TLSVersion.TLS_1_3,
            cipher_suites=[
                0x1301,  # TLS_AES_128_GCM_SHA256
                0x1302,  # TLS_AES_256_GCM_SHA384
                0x1303,  # TLS_CHACHA20_POLY1305_SHA256
                0xC02B,  # TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
                0xC02F,  # TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
                0xC02C,  # TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
                0xC030,  # TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
                0xCCA9,  # TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
                0xCCA8,  # TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
                0xC009,  # TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
                0xC013,  # TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
                0xC00A,  # TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
                0xC014,  # TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
                0x009C,  # TLS_RSA_WITH_AES_128_GCM_SHA256
                0x009D,  # TLS_RSA_WITH_AES_256_GCM_SHA384
                0x002F,  # TLS_RSA_WITH_AES_128_CBC_SHA
                0x0035,  # TLS_RSA_WITH_AES_256_CBC_SHA
            ],
            extensions=[
                0x0000,  # server_name
                0x0005,  # status_request
                0x000A,  # supported_groups
                0x000B,  # ec_point_formats
                0x000D,  # signature_algorithms
                0x0012,  # signed_certificate_timestamp
                0x0015,  # padding
                0x0017,  # extended_master_secret
                0x0023,  # session_ticket
                0x002B,  # supported_versions
                0x002D,  # psk_key_exchange_modes
                0x0033,  # key_share
                0xFF01,  # renegotiation_info
            ],
            elliptic_curves=[
                0x001D,  # X25519
                0x0017,  # secp256r1
                0x0018,  # secp384r1
            ],
            ec_point_formats=[0],
            user_agent=(
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15"
            ),
        )
        fp.compute_ja3()
        return fp

    @classmethod
    def get_server_fingerprint(cls, server_type: ServerType) -> ServerFingerprint:
        """Get server-side JA3S fingerprint for a server type.

        Args:
            server_type: Target server type.

        Returns:
            ServerFingerprint matching the specified server type.
        """
        fingerprints: Dict[ServerType, ServerFingerprint] = {
            ServerType.NGINX: ServerFingerprint(
                name="nginx_1.24",
                server_type=ServerType.NGINX,
                tls_version=TLSVersion.TLS_1_2,
                cipher_suite=0xC02F,
                extensions=[0x0005, 0x0017, 0xFF01],
            ),
            ServerType.APACHE: ServerFingerprint(
                name="apache_2.4",
                server_type=ServerType.APACHE,
                tls_version=TLSVersion.TLS_1_2,
                cipher_suite=0xC02F,
                extensions=[0x0005, 0x0017],
            ),
            ServerType.IIS: ServerFingerprint(
                name="iis_10",
                server_type=ServerType.IIS,
                tls_version=TLSVersion.TLS_1_2,
                cipher_suite=0xC02F,
                extensions=[0x0017, 0xFF01],
            ),
            ServerType.CLOUDFLARE: ServerFingerprint(
                name="cloudflare",
                server_type=ServerType.CLOUDFLARE,
                tls_version=TLSVersion.TLS_1_3,
                cipher_suite=0x1301,
                extensions=[0x0005, 0x0017],
            ),
            ServerType.AWS_ALB: ServerFingerprint(
                name="aws_alb",
                server_type=ServerType.AWS_ALB,
                tls_version=TLSVersion.TLS_1_2,
                cipher_suite=0xC02F,
                extensions=[0x0005, 0x0017, 0xFF01],
            ),
            ServerType.AKAMAI: ServerFingerprint(
                name="akamai",
                server_type=ServerType.AKAMAI,
                tls_version=TLSVersion.TLS_1_2,
                cipher_suite=0xC02F,
                extensions=[0x0005, 0x0017],
            ),
        }

        sf = fingerprints.get(server_type, fingerprints[ServerType.NGINX])
        sf.compute_ja3s()
        return sf

    @classmethod
    def get_all_browser_fingerprints(cls) -> List[TLSFingerprint]:
        """Get all built-in browser fingerprints.

        Returns:
            List of all built-in TLSFingerprint instances.
        """
        return [
            cls.get_chrome_120(),
            cls.get_firefox_120(),
            cls.get_edge_120(),
            cls.get_safari_17(),
        ]


# =============================================================================
# TLS Fingerprint Manager
# =============================================================================

class TLSFingerprintManager:
    """Manages TLS fingerprint selection, rotation, and customization.

    Provides:
        - Fingerprint selection by browser/server type
        - Automatic rotation for anti-detection
        - Custom fingerprint creation
        - JA3/JA3S hash computation and matching

    Attributes:
        _client_fingerprints: Registered client-side fingerprints
        _server_fingerprints: Registered server-side fingerprints
        _current_fingerprint: Currently active client fingerprint
        _rotation_interval: Seconds between automatic rotations
        _last_rotation: Last rotation timestamp
        _auto_rotate: Whether automatic rotation is enabled
    """

    def __init__(
        self,
        rotation_interval: int = 3600,
        auto_rotate: bool = True,
    ) -> None:
        """Initialize the TLSFingerprintManager.

        Args:
            rotation_interval: Interval between automatic rotations (seconds).
            auto_rotate: Whether to enable automatic fingerprint rotation.
        """
        self._client_fingerprints: Dict[str, TLSFingerprint] = {}
        self._server_fingerprints: Dict[str, ServerFingerprint] = {}
        self._current_fingerprint: Optional[TLSFingerprint] = None
        self._rotation_interval = rotation_interval
        self._last_rotation = time.time()
        self._auto_rotate = auto_rotate

        self._load_built_in_fingerprints()

    def _load_built_in_fingerprints(self) -> None:
        """Load all built-in browser and server fingerprints."""
        for fp in BuiltInFingerprints.get_all_browser_fingerprints():
            self._client_fingerprints[fp.name] = fp

        for st in ServerType:
            sf = BuiltInFingerprints.get_server_fingerprint(st)
            self._server_fingerprints[sf.name] = sf

        logger.info(
            f"Loaded {len(self._client_fingerprints)} client and "
            f"{len(self._server_fingerprints)} server fingerprints"
        )

    def get_fingerprint_by_browser(
        self, browser: BrowserType,
    ) -> Optional[TLSFingerprint]:
        """Get a fingerprint matching the specified browser type.

        Args:
            browser: Target browser type.

        Returns:
            Matching TLSFingerprint, or None if not found.
        """
        for fp in self._client_fingerprints.values():
            if fp.browser == browser:
                return fp
        return None

    def get_fingerprint_by_name(self, name: str) -> Optional[TLSFingerprint]:
        """Get a fingerprint by its name.

        Args:
            name: Fingerprint name.

        Returns:
            Matching TLSFingerprint, or None if not found.
        """
        return self._client_fingerprints.get(name)

    def get_random_fingerprint(self) -> Optional[TLSFingerprint]:
        """Get a random fingerprint from the library.

        Returns:
            Random TLSFingerprint, or None if library is empty.
        """
        if not self._client_fingerprints:
            return None
        return random.choice(list(self._client_fingerprints.values()))

    def set_active_fingerprint(self, name: str) -> bool:
        """Set the active TLS fingerprint.

        Args:
            name: Fingerprint name to activate.

        Returns:
            True if the fingerprint was found and activated.
        """
        fp = self._client_fingerprints.get(name)
        if fp:
            self._current_fingerprint = fp
            self._last_rotation = time.time()
            logger.info(f"Active TLS fingerprint set to: {name} (JA3: {fp.ja3_hash})")
            return True
        logger.warning(f"Fingerprint not found: {name}")
        return False

    def rotate_fingerprint(self) -> Optional[TLSFingerprint]:
        """Rotate to a random fingerprint.

        Returns:
            The new active TLSFingerprint, or None if rotation not possible.
        """
        old_name = self._current_fingerprint.name if self._current_fingerprint else "none"
        new_fp = self.get_random_fingerprint()

        if new_fp:
            self._current_fingerprint = new_fp
            self._last_rotation = time.time()
            logger.info(
                f"TLS fingerprint rotated: {old_name} -> {new_fp.name} "
                f"(JA3: {new_fp.ja3_hash})"
            )
            return new_fp

        return None

    def should_rotate(self) -> bool:
        """Check if automatic rotation is due.

        Returns:
            True if rotation should occur.
        """
        if not self._auto_rotate or not self._current_fingerprint:
            return False

        elapsed = time.time() - self._last_rotation
        return elapsed >= self._rotation_interval

    def check_and_rotate(self) -> Optional[TLSFingerprint]:
        """Check rotation status and rotate if needed.

        Returns:
            New fingerprint if rotated, None otherwise.
        """
        if self.should_rotate():
            return self.rotate_fingerprint()
        return None

    @property
    def active_fingerprint(self) -> Optional[TLSFingerprint]:
        """Get the currently active fingerprint.

        Returns:
            Active TLSFingerprint, or None if not set.
        """
        return self._current_fingerprint

    def add_custom_fingerprint(self, fp: TLSFingerprint) -> None:
        """Register a custom TLS fingerprint.

        Args:
            fp: Custom TLSFingerprint to register.
        """
        if not fp.ja3_hash:
            fp.compute_ja3()
        self._client_fingerprints[fp.name] = fp
        logger.info(f"Custom fingerprint registered: {fp.name} (JA3: {fp.ja3_hash})")

    def get_server_fingerprint(self, name: str) -> Optional[ServerFingerprint]:
        """Get a server fingerprint by name.

        Args:
            name: Server fingerprint name.

        Returns:
            Matching ServerFingerprint, or None if not found.
        """
        return self._server_fingerprints.get(name)

    def get_all_fingerprints(self) -> Dict[str, TLSFingerprint]:
        """Get all registered client fingerprints.

        Returns:
            Dictionary mapping fingerprint names to TLSFingerprint instances.
        """
        return dict(self._client_fingerprints)

    def get_ja3_match_score(self, ja3_hash: str) -> Tuple[Optional[str], float]:
        """Find the closest fingerprint match for a given JA3 hash.

        Args:
            ja3_hash: JA3 hash to match against.

        Returns:
            Tuple of (best_match_name, similarity_score).
        """
        best_name: Optional[str] = None
        best_score = 0.0

        for name, fp in self._client_fingerprints.items():
            if fp.ja3_hash == ja3_hash:
                return name, 1.0

            score = self._compute_similarity(fp.ja3_hash, ja3_hash)
            if score > best_score:
                best_score = score
                best_name = name

        return best_name, best_score

    @staticmethod
    def _compute_similarity(hash1: str, hash2: str) -> float:
        """Compute similarity between two JA3 hashes.

        Args:
            hash1: First JA3 hash.
            hash2: Second JA3 hash.

        Returns:
            Similarity score (0.0 to 1.0).
        """
        if len(hash1) != len(hash2):
            return 0.0

        matches = sum(a == b for a, b in zip(hash1, hash2))
        return matches / len(hash1)

    def create_custom_fingerprint(
        self,
        name: str,
        cipher_suites: Optional[List[int]] = None,
        extensions: Optional[List[int]] = None,
        elliptic_curves: Optional[List[int]] = None,
        ec_point_formats: Optional[List[int]] = None,
        tls_version: TLSVersion = TLSVersion.TLS_1_3,
        user_agent: str = "",
    ) -> TLSFingerprint:
        """Create a custom TLS fingerprint.

        Args:
            name: Fingerprint identifier.
            cipher_suites: Custom cipher suite list.
            extensions: Custom extension list.
            elliptic_curves: Custom elliptic curve list.
            ec_point_formats: Custom EC point format list.
            tls_version: TLS protocol version.
            user_agent: Associated User-Agent string.

        Returns:
            Newly created TLSFingerprint instance.
        """
        fp = TLSFingerprint(
            name=name,
            browser=BrowserType.CHROME,
            version="custom",
            tls_version=tls_version,
            cipher_suites=cipher_suites or [],
            extensions=extensions or [],
            elliptic_curves=elliptic_curves or [],
            ec_point_formats=ec_point_formats or [0],
            user_agent=user_agent,
        )
        fp.compute_ja3()
        return fp


# =============================================================================
# HTTP/2 Fingerprint Manager
# =============================================================================

@dataclass
class HTTP2Settings:
    """HTTP/2 SETTINGS frame parameters.

    Attributes:
        header_table_size: HPACK header table size
        enable_push: Enable server push
        max_concurrent_streams: Maximum concurrent streams
        initial_window_size: Initial window size
        max_frame_size: Maximum frame size
        max_header_list_size: Maximum header list size
        settings_order: Order of SETTINGS parameters (for fingerprinting)
    """

    header_table_size: int = 4096
    enable_push: bool = True
    max_concurrent_streams: int = 100
    initial_window_size: int = 65535
    max_frame_size: int = 16384
    max_header_list_size: int = 262144
    settings_order: List[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        """Set default settings order if not provided."""
        if not self.settings_order:
            self.settings_order = [
                "header_table_size",
                "enable_push",
                "max_concurrent_streams",
                "initial_window_size",
                "max_frame_size",
            ]


@dataclass
class HTTP2Fingerprint:
    """HTTP/2 connection fingerprint.

    Attributes:
        name: Fingerprint identifier
        browser: Target browser type
        settings: HTTP/2 SETTINGS frame parameters
        window_update: Initial WINDOW_UPDATE value
        header_order: Order of pseudo-headers in HEADERS frame
        priority_frames: PRIORITY frame configuration
        ja4h_hash: Computed JA4 HTTP/2 fingerprint hash
    """

    name: str = ""
    browser: BrowserType = BrowserType.CHROME
    settings: HTTP2Settings = field(default_factory=HTTP2Settings)
    window_update: int = 15663105
    header_order: List[str] = field(default_factory=lambda: [
        ":method", ":authority", ":scheme", ":path",
    ])
    priority_frames: List[Dict[str, Any]] = field(default_factory=list)
    ja4h_hash: str = ""

    def compute_ja4h(self) -> str:
        """Compute JA4 HTTP/2 fingerprint hash.

        Returns:
            JA4h hash string.
        """
        settings_str = ",".join(
            f"{k}={getattr(self.settings, k)}"
            for k in self.settings.settings_order
        )
        header_str = ",".join(self.header_order)
        raw = f"{settings_str}|{self.window_update}|{header_str}"
        self.ja4h_hash = hashlib.md5(raw.encode()).hexdigest()
        return self.ja4h_hash

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "name": self.name,
            "browser": self.browser.value,
            "settings": {
                k: getattr(self.settings, k)
                for k in self.settings.settings_order
            },
            "window_update": self.window_update,
            "header_order": self.header_order,
            "ja4h_hash": self.ja4h_hash,
        }


class HTTP2FingerprintManager:
    """Manages HTTP/2 fingerprint customization and rotation.

    Provides:
        - Built-in HTTP/2 fingerprints for major browsers
        - Custom SETTINGS frame parameter configuration
        - HEADERS frame pseudo-header ordering
        - WINDOW_UPDATE value customization

    Attributes:
        _fingerprints: Registered HTTP/2 fingerprints
        _active_fingerprint: Currently active fingerprint
    """

    def __init__(self) -> None:
        """Initialize the HTTP2FingerprintManager with built-in fingerprints."""
        self._fingerprints: Dict[str, HTTP2Fingerprint] = {}
        self._active_fingerprint: Optional[HTTP2Fingerprint] = None
        self._load_built_in_fingerprints()

    def _load_built_in_fingerprints(self) -> None:
        """Load built-in HTTP/2 fingerprints."""
        chrome_h2 = HTTP2Fingerprint(
            name="chrome_120_h2",
            browser=BrowserType.CHROME,
            settings=HTTP2Settings(
                header_table_size=65536,
                enable_push=False,
                max_concurrent_streams=1000,
                initial_window_size=6291456,
                max_frame_size=16384,
                settings_order=[
                    "header_table_size",
                    "enable_push",
                    "max_concurrent_streams",
                    "initial_window_size",
                    "max_frame_size",
                ],
            ),
            window_update=15663105,
            header_order=[":method", ":authority", ":scheme", ":path"],
        )
        chrome_h2.compute_ja4h()
        self._fingerprints[chrome_h2.name] = chrome_h2

        firefox_h2 = HTTP2Fingerprint(
            name="firefox_120_h2",
            browser=BrowserType.FIREFOX,
            settings=HTTP2Settings(
                header_table_size=65536,
                enable_push=False,
                max_concurrent_streams=100,
                initial_window_size=131072,
                max_frame_size=16384,
                settings_order=[
                    "header_table_size",
                    "enable_push",
                    "max_concurrent_streams",
                    "initial_window_size",
                    "max_frame_size",
                ],
            ),
            window_update=12517377,
            header_order=[":method", ":path", ":authority", ":scheme"],
        )
        firefox_h2.compute_ja4h()
        self._fingerprints[firefox_h2.name] = firefox_h2

        safari_h2 = HTTP2Fingerprint(
            name="safari_17_h2",
            browser=BrowserType.SAFARI,
            settings=HTTP2Settings(
                header_table_size=4096,
                enable_push=False,
                max_concurrent_streams=100,
                initial_window_size=2097152,
                max_frame_size=16384,
                settings_order=[
                    "header_table_size",
                    "enable_push",
                    "max_concurrent_streams",
                    "initial_window_size",
                    "max_frame_size",
                ],
            ),
            window_update=10485760,
            header_order=[":method", ":scheme", ":path", ":authority"],
        )
        safari_h2.compute_ja4h()
        self._fingerprints[safari_h2.name] = safari_h2

        logger.info(f"Loaded {len(self._fingerprints)} HTTP/2 fingerprints")

    def get_fingerprint_by_browser(
        self, browser: BrowserType,
    ) -> Optional[HTTP2Fingerprint]:
        """Get HTTP/2 fingerprint by browser type.

        Args:
            browser: Target browser type.

        Returns:
            Matching HTTP2Fingerprint, or None if not found.
        """
        for fp in self._fingerprints.values():
            if fp.browser == browser:
                return fp
        return None

    def set_active_fingerprint(self, name: str) -> bool:
        """Set the active HTTP/2 fingerprint.

        Args:
            name: Fingerprint name.

        Returns:
            True if fingerprint was found and activated.
        """
        fp = self._fingerprints.get(name)
        if fp:
            self._active_fingerprint = fp
            logger.info(f"Active HTTP/2 fingerprint set to: {name}")
            return True
        return False

    @property
    def active_fingerprint(self) -> Optional[HTTP2Fingerprint]:
        """Get the currently active HTTP/2 fingerprint."""
        return self._active_fingerprint

    def get_all_fingerprints(self) -> Dict[str, HTTP2Fingerprint]:
        """Get all registered HTTP/2 fingerprints."""
        return dict(self._fingerprints)


# =============================================================================
# Global Singleton
# =============================================================================

_tls_manager: Optional[TLSFingerprintManager] = None
_h2_manager: Optional[HTTP2FingerprintManager] = None


def get_tls_manager() -> TLSFingerprintManager:
    """Get the global TLSFingerprintManager singleton.

    Returns:
        Singleton TLSFingerprintManager instance.
    """
    global _tls_manager
    if _tls_manager is None:
        _tls_manager = TLSFingerprintManager()
    return _tls_manager


def get_h2_manager() -> HTTP2FingerprintManager:
    """Get the global HTTP2FingerprintManager singleton.

    Returns:
        Singleton HTTP2FingerprintManager instance.
    """
    global _h2_manager
    if _h2_manager is None:
        _h2_manager = HTTP2FingerprintManager()
    return _h2_manager


__all__ = [
    "TLSFingerprintManager",
    "HTTP2FingerprintManager",
    "BuiltInFingerprints",
    "TLSFingerprint",
    "ServerFingerprint",
    "HTTP2Fingerprint",
    "HTTP2Settings",
    "TLSVersion",
    "BrowserType",
    "ServerType",
    "get_tls_manager",
    "get_h2_manager",
]
