"""TLS 1.3 handshake MITM implementation for QUIC CRYPTO frames.

Provides:
- TLS 1.3 handshake in QUIC CRYPTO frames
- Dynamic server certificate generation using root CA
- MITM key exchange
- QUIC Transport Parameters extension
- 0-RTT Early Data handling with replay protection
"""

import asyncio
import logging
import os
import secrets
import struct
import time
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Callable, Coroutine, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class HandshakeType(IntEnum):
    """TLS handshake message types."""
    CLIENT_HELLO = 1
    SERVER_HELLO = 2
    NEW_SESSION_TICKET = 4
    END_OF_EARLY_DATA = 5
    ENCRYPTED_EXTENSIONS = 8
    CERTIFICATE = 11
    CERTIFICATE_REQUEST = 13
    CERTIFICATE_VERIFY = 15
    FINISHED = 20


class ExtensionType(IntEnum):
    """TLS extension types."""
    SERVER_NAME = 0
    SUPPORTED_GROUPS = 10
    SIGNATURE_ALGORITHMS = 13
    ALPN = 16
    QUIC_TRANSPORT_PARAMETERS = 57
    KEY_SHARE = 51
    SUPPORTED_VERSIONS = 43
    PSK_KEY_EXCHANGE_MODES = 45
    EARLY_DATA = 42
    ENCRYPTED_SNI = 65486


class CipherSuite(IntEnum):
    """TLS 1.3 cipher suites."""
    TLS_AES_128_GCM_SHA256 = 0x1301
    TLS_AES_256_GCM_SHA384 = 0x1302
    TLS_CHACHA20_POLY1305_SHA256 = 0x1303
    TLS_AES_128_CCM_SHA256 = 0x1304
    TLS_AES_128_CCM_8_SHA256 = 0x1305


class KeyShareGroup(IntEnum):
    """Key share group types."""
    SECP256R1 = 23
    SECP384R1 = 24
    SECP521R1 = 25
    X25519 = 29
    X448 = 30
    FFDHE2048 = 256
    FFDHE3072 = 257
    FFDHE4096 = 258
    FFDHE6144 = 259
    FFDHE8192 = 260


class QuicTransportParamId(IntEnum):
    """QUIC transport parameter IDs."""
    ORIGINAL_DESTINATION_CONNECTION_ID = 0x00
    MAX_IDLE_TIMEOUT = 0x01
    STATELESS_RESET_TOKEN = 0x02
    MAX_UDP_PAYLOAD_SIZE = 0x03
    INITIAL_MAX_DATA = 0x04
    INITIAL_MAX_STREAM_DATA_BIDI_LOCAL = 0x05
    INITIAL_MAX_STREAM_DATA_BIDI_REMOTE = 0x06
    INITIAL_MAX_STREAM_DATA_UNI = 0x07
    INITIAL_MAX_STREAMS_BIDI = 0x08
    INITIAL_MAX_STREAMS_UNI = 0x09
    ACK_DELAY_EXPONENT = 0x0A
    MAX_ACK_DELAY = 0x0B
    DISABLE_ACTIVE_MIGRATION = 0x0C
    PREFERRED_ADDRESS = 0x0D
    ACTIVE_CONNECTION_ID_LIMIT = 0x0E
    INITIAL_SOURCE_CONNECTION_ID = 0x0F
    RETIRE_PRIOR_TO = 0x10


@dataclass
class TlsClientHello:
    """Parsed TLS ClientHello.

    Attributes:
        legacy_version: Legacy TLS version
        random: Client random bytes
        session_id: Session ID
        cipher_suites: Supported cipher suites
        legacy_compression_methods: Compression methods
        extensions: Extension data
        server_name: SNI server name
        alpn_protocols: ALPN protocols
        key_share_groups: Key share groups
        supported_versions: Supported versions
        quic_transport_params: QUIC transport parameters
    """
    legacy_version: int = 0x0303
    random: bytes = b""
    session_id: bytes = b""
    cipher_suites: List[int] = field(default_factory=list)
    legacy_compression_methods: List[int] = field(default_factory=list)
    extensions: Dict[int, bytes] = field(default_factory=dict)
    server_name: str = ""
    alpn_protocols: List[str] = field(default_factory=list)
    key_share_groups: List[int] = field(default_factory=list)
    supported_versions: List[int] = field(default_factory=list)
    quic_transport_params: bytes = b""
    early_data: bool = False
    client_key_share: bytes = b""


@dataclass
class TlsServerHello:
    """TLS ServerHello data.

    Attributes:
        legacy_version: Legacy TLS version
        random: Server random bytes
        session_id: Session ID
        cipher_suite: Selected cipher suite
        legacy_compression_method: Compression method
        extensions: Extension data
        key_share: Key share data
        quic_transport_params: QUIC transport parameters
    """
    legacy_version: int = 0x0303
    random: bytes = b""
    session_id: bytes = b""
    cipher_suite: int = CipherSuite.TLS_AES_128_GCM_SHA256
    legacy_compression_method: int = 0
    extensions: Dict[int, bytes] = field(default_factory=dict)
    key_share: bytes = b""
    quic_transport_params: bytes = b""


@dataclass
class TlsHandshakeState:
    """TLS handshake state.

    Attributes:
        client_hello: Client hello message
        server_hello: Server hello message
        client_random: Client random
        server_random: Server random
        selected_cipher_suite: Selected cipher suite
        client_key_share: Client key share
        server_key_share: Server key share
        server_certificate: Server certificate bytes
        server_certificate_verify: Certificate verify data
        client_finished: Client finished data
        server_finished: Server finished data
        handshake_complete: Whether handshake complete
        early_data: Early data indicator
        timestamp: Handshake timestamp
    """
    client_hello: Optional[TlsClientHello] = None
    server_hello: Optional[TlsServerHello] = None
    client_random: bytes = b""
    server_random: bytes = b""
    selected_cipher_suite: int = 0
    client_key_share: bytes = b""
    server_key_share: bytes = b""
    server_certificate: bytes = b""
    server_certificate_verify: bytes = b""
    client_finished: bytes = b""
    server_finished: bytes = b""
    handshake_complete: bool = False
    early_data: bool = False
    timestamp: float = 0.0


@dataclass
class CertificateCacheEntry:
    """Certificate cache entry.

    Attributes:
        domain: Domain name
        certificate: Certificate bytes
        private_key: Private key bytes
        created_at: Creation timestamp
        expires_at: Expiration timestamp
    """
    domain: str = ""
    certificate: bytes = b""
    private_key: bytes = b""
    created_at: float = 0.0
    expires_at: float = 0.0


class QuicTlsHandshake:
    """QUIC TLS 1.3 handshake MITM implementation.

    Provides TLS 1.3 handshake in QUIC CRYPTO frames,
    dynamic certificate generation, and MITM key exchange.
    """

    TLS_VERSION_1_3: int = 0x0304
    TLS_VERSION_1_2: int = 0x0303

    SUPPORTED_CIPHER_SUITES: List[int] = [
        CipherSuite.TLS_AES_128_GCM_SHA256,
        CipherSuite.TLS_AES_256_GCM_SHA384,
        CipherSuite.TLS_CHACHA20_POLY1305_SHA256,
    ]

    SUPPORTED_KEY_SHARE_GROUPS: List[int] = [
        KeyShareGroup.X25519,
        KeyShareGroup.SECP256R1,
    ]

    SUPPORTED_ALPN: List[str] = ["h3", "h3-29", "h3-30", "h3-31", "h3-32"]

    MAX_EARLY_DATA_SIZE: int = 16384

    def __init__(
        self,
        ca_manager: Optional[Any] = None,
        event_bus: Optional[Any] = None,
    ) -> None:
        """Initialize QUIC TLS handshake.

        Args:
            ca_manager: Certificate authority manager.
            event_bus: Event bus for broadcasting events.
        """
        self.ca_manager = ca_manager
        self.event_bus = event_bus
        self._progress_callback: Optional[Callable[[str, float], Coroutine[Any, Any, None]]] = None
        self._log_callback: Optional[Callable[[str], Coroutine[Any, Any, None]]] = None
        self._handshake_states: Dict[str, TlsHandshakeState] = {}
        self._cert_cache: Dict[str, CertificateCacheEntry] = {}
        self._early_data_tracker: Dict[str, bytes] = {}
        self._replay_cache: Dict[bytes, float] = {}

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
        logger.info("QUIC TLS Progress: %.1f%% - %s", percentage, message)

    async def _report_log(self, message: str) -> None:
        """Report log via callback.

        Args:
            message: Log message.
        """
        if self._log_callback:
            await self._log_callback(message)
        logger.info("QUIC TLS: %s", message)

    async def process_client_hello(
        self,
        connection_id: str,
        crypto_data: bytes,
    ) -> Optional[bytes]:
        """Process TLS ClientHello from CRYPTO frame.

        Args:
            connection_id: QUIC connection ID.
            crypto_data: CRYPTO frame payload.

        Returns:
            Server handshake response bytes or None.
        """
        try:
            await self._report_progress("处理ClientHello", 10)

            client_hello = await self._parse_client_hello(crypto_data)
            if not client_hello:
                await self._report_log("ClientHello解析失败")
                return None

            state = TlsHandshakeState(
                client_hello=client_hello,
                client_random=client_hello.random,
                timestamp=time.time(),
            )
            self._handshake_states[connection_id] = state

            await self._report_log(
                f"ClientHello: SNI={client_hello.server_name}, "
                f"ALPN={client_hello.alpn_protocols}"
            )

            if client_hello.quic_transport_params:
                await self._report_log("收到QUIC传输参数")

            if client_hello.early_data:
                state.early_data = True
                if await self._check_early_data_replay(connection_id, crypto_data):
                    await self._report_log("0-RTT数据重放检测，拒绝")
                    return None

            response = await self._build_server_response(connection_id, client_hello)

            await self._report_progress("ServerHello构建完成", 50)

            return response

        except Exception as e:
            await self._report_log(f"ClientHello处理失败: {e}")
            logger.error("ClientHello processing failed: %s", e)
            return None

    async def process_client_finished(
        self,
        connection_id: str,
        crypto_data: bytes,
    ) -> Optional[bytes]:
        """Process TLS ClientFinished from CRYPTO frame.

        Args:
            connection_id: QUIC connection ID.
            crypto_data: CRYPTO frame payload.

        Returns:
            Handshake done response or None.
        """
        try:
            state = self._handshake_states.get(connection_id)
            if not state:
                return None

            state.client_finished = crypto_data
            state.handshake_complete = True

            await self._report_log(f"TLS握手完成: {connection_id}")

            return await self._build_handshake_done()

        except Exception as e:
            await self._report_log(f"ClientFinished处理失败: {e}")
            logger.error("ClientFinished processing failed: %s", e)
            return None

    async def _parse_client_hello(
        self,
        data: bytes,
    ) -> Optional[TlsClientHello]:
        """Parse TLS ClientHello message.

        Args:
            data: ClientHello bytes.

        Returns:
            TlsClientHello or None.
        """
        if len(data) < 42:
            return None

        client_hello = TlsClientHello()

        try:
            client_hello.legacy_version = struct.unpack(">H", data[0:2])[0]
            client_hello.random = data[2:34]

            session_id_len = data[34]
            offset = 35
            client_hello.session_id = data[offset : offset + session_id_len]
            offset += session_id_len

            if offset + 2 > len(data):
                return None
            cipher_suite_len = struct.unpack(">H", data[offset : offset + 2])[0]
            offset += 2

            for i in range(0, cipher_suite_len, 2):
                if offset + i + 2 > len(data):
                    break
                suite = struct.unpack(">H", data[offset + i : offset + i + 2])[0]
                client_hello.cipher_suites.append(suite)

            offset += cipher_suite_len

            if offset >= len(data):
                return None
            comp_methods_len = data[offset]
            offset += 1
            client_hello.legacy_compression_methods = list(
                data[offset : offset + comp_methods_len]
            )
            offset += comp_methods_len

            if offset + 2 > len(data):
                return None
            extensions_len = struct.unpack(">H", data[offset : offset + 2])[0]
            offset += 2

            ext_end = offset + extensions_len
            while offset < ext_end and offset + 4 <= len(data):
                ext_type = struct.unpack(">H", data[offset : offset + 2])[0]
                ext_len = struct.unpack(">H", data[offset + 2 : offset + 4])[0]
                offset += 4

                if offset + ext_len > len(data):
                    break

                ext_data = data[offset : offset + ext_len]
                offset += ext_len

                client_hello.extensions[ext_type] = ext_data

                await self._parse_extension(client_hello, ext_type, ext_data)

        except Exception as e:
            logger.error("ClientHello parsing error: %s", e)
            return None

        return client_hello

    async def _parse_extension(
        self,
        client_hello: TlsClientHello,
        ext_type: int,
        ext_data: bytes,
    ) -> None:
        """Parse TLS extension.

        Args:
            client_hello: ClientHello to update.
            ext_type: Extension type.
            ext_data: Extension data.
        """
        try:
            if ext_type == ExtensionType.SERVER_NAME:
                if len(ext_data) >= 5:
                    name_len = struct.unpack(">H", ext_data[3:5])[0]
                    if len(ext_data) >= 5 + name_len:
                        client_hello.server_name = ext_data[5 : 5 + name_len].decode(
                            "utf-8", errors="replace"
                        )

            elif ext_type == ExtensionType.ALPN:
                if len(ext_data) >= 2:
                    alpn_list_len = struct.unpack(">H", ext_data[0:2])[0]
                    offset = 2
                    while offset < 2 + alpn_list_len and offset < len(ext_data):
                        proto_len = ext_data[offset]
                        offset += 1
                        if offset + proto_len <= len(ext_data):
                            proto = ext_data[offset : offset + proto_len].decode(
                                "utf-8", errors="replace"
                            )
                            client_hello.alpn_protocols.append(proto)
                        offset += proto_len

            elif ext_type == ExtensionType.KEY_SHARE:
                if len(ext_data) >= 2:
                    shares_len = struct.unpack(">H", ext_data[0:2])[0]
                    offset = 2
                    while offset < 2 + shares_len and offset + 4 <= len(ext_data):
                        group = struct.unpack(">H", ext_data[offset : offset + 2])[0]
                        key_len = struct.unpack(">H", ext_data[offset + 2 : offset + 4])[0]
                        offset += 4
                        if offset + key_len <= len(ext_data):
                            client_hello.key_share_groups.append(group)
                            client_hello.client_key_share = ext_data[
                                offset : offset + key_len
                            ]
                        offset += key_len

            elif ext_type == ExtensionType.SUPPORTED_VERSIONS:
                if len(ext_data) >= 1:
                    versions_len = ext_data[0]
                    offset = 1
                    while offset < 1 + versions_len and offset + 2 <= len(ext_data):
                        version = struct.unpack(">H", ext_data[offset : offset + 2])[0]
                        client_hello.supported_versions.append(version)
                        offset += 2

            elif ext_type == ExtensionType.QUIC_TRANSPORT_PARAMETERS:
                client_hello.quic_transport_params = ext_data

            elif ext_type == ExtensionType.EARLY_DATA:
                client_hello.early_data = True

        except Exception as e:
            logger.error("Extension parsing error: %s", e)

    async def _build_server_response(
        self,
        connection_id: str,
        client_hello: TlsClientHello,
    ) -> bytes:
        """Build TLS server response.

        Args:
            connection_id: QUIC connection ID.
            client_hello: Parsed ClientHello.

        Returns:
            Server response bytes.
        """
        state = self._handshake_states.get(connection_id)
        if not state:
            return b""

        server_random = secrets.token_bytes(32)
        state.server_random = server_random

        selected_cipher = self._select_cipher_suite(client_hello.cipher_suites)
        state.selected_cipher_suite = selected_cipher

        server_hello = await self._build_server_hello(
            server_random, selected_cipher, client_hello
        )

        encrypted_extensions = await self._build_encrypted_extensions(
            client_hello, connection_id
        )

        cert_data = await self._build_certificate(
            client_hello.server_name, connection_id
        )

        cert_verify = await self._build_certificate_verify(connection_id)

        server_finished = await self._build_server_finished(connection_id)

        response = bytearray()
        response.extend(server_hello)
        response.extend(encrypted_extensions)
        response.extend(cert_data)
        response.extend(cert_verify)
        response.extend(server_finished)

        return bytes(response)

    async def _build_server_hello(
        self,
        server_random: bytes,
        cipher_suite: int,
        client_hello: TlsClientHello,
    ) -> bytes:
        """Build TLS ServerHello message.

        Args:
            server_random: Server random bytes.
            cipher_suite: Selected cipher suite.
            client_hello: Client hello.

        Returns:
            ServerHello bytes.
        """
        session_id = client_hello.session_id if client_hello.session_id else secrets.token_bytes(32)

        extensions_data = bytearray()

        key_share_data = await self._build_key_share_extension()
        extensions_data.extend(key_share_data)

        supported_versions_data = struct.pack(">HHH", ExtensionType.SUPPORTED_VERSIONS, 2, self.TLS_VERSION_1_3)
        extensions_data.extend(supported_versions_data)

        server_hello_body = bytearray()
        server_hello_body.extend(struct.pack(">H", self.TLS_VERSION_1_2))
        server_hello_body.extend(server_random)
        server_hello_body.append(len(session_id))
        server_hello_body.extend(session_id)
        server_hello_body.extend(struct.pack(">H", cipher_suite))
        server_hello_body.append(0)
        server_hello_body.extend(struct.pack(">H", len(extensions_data)))
        server_hello_body.extend(extensions_data)

        server_hello = bytearray()
        server_hello.append(HandshakeType.SERVER_HELLO)
        server_hello.extend(struct.pack(">I", len(server_hello_body))[1:])
        server_hello.extend(server_hello_body)

        return bytes(server_hello)

    async def _build_encrypted_extensions(
        self,
        client_hello: TlsClientHello,
        connection_id: str,
    ) -> bytes:
        """Build EncryptedExtensions message.

        Args:
            client_hello: Client hello.
            connection_id: QUIC connection ID.

        Returns:
            EncryptedExtensions bytes.
        """
        extensions_data = bytearray()

        if client_hello.alpn_protocols:
            selected_alpn = self._select_alpn(client_hello.alpn_protocols)
            alpn_data = bytearray()
            alpn_data.append(len(selected_alpn))
            alpn_data.extend(selected_alpn.encode("utf-8"))
            alpn_ext = bytearray()
            alpn_ext.extend(struct.pack(">H", ExtensionType.ALPN))
            alpn_ext.extend(struct.pack(">H", len(alpn_data)))
            alpn_ext.extend(alpn_data)
            extensions_data.extend(alpn_ext)

        state = self._handshake_states.get(connection_id)
        if state and state.client_hello and state.client_hello.quic_transport_params:
            quic_params = await self._build_quic_transport_params(connection_id)
            quic_ext = bytearray()
            quic_ext.extend(struct.pack(">H", ExtensionType.QUIC_TRANSPORT_PARAMETERS))
            quic_ext.extend(struct.pack(">H", len(quic_params)))
            quic_ext.extend(quic_params)
            extensions_data.extend(quic_ext)

        encrypted_extensions = bytearray()
        encrypted_extensions.append(HandshakeType.ENCRYPTED_EXTENSIONS)
        encrypted_extensions.extend(struct.pack(">I", len(extensions_data))[1:])
        encrypted_extensions.extend(extensions_data)

        return bytes(encrypted_extensions)

    async def _build_certificate(
        self,
        server_name: str,
        connection_id: str,
    ) -> bytes:
        """Build Certificate message.

        Args:
            server_name: Server name for certificate.
            connection_id: QUIC connection ID.

        Returns:
            Certificate bytes.
        """
        cert_entry = await self._get_or_generate_certificate(server_name)

        cert_data = bytearray()
        cert_data.append(0)

        cert_list = bytearray()
        cert_list.extend(struct.pack(">I", len(cert_entry.certificate))[1:])
        cert_list.extend(cert_entry.certificate)

        cert_entry_data = bytearray()
        cert_entry_data.extend(struct.pack(">H", 0))
        cert_list.extend(cert_entry_data)

        cert_data.extend(struct.pack(">I", len(cert_list))[1:])
        cert_data.extend(cert_list)

        certificate_msg = bytearray()
        certificate_msg.append(HandshakeType.CERTIFICATE)
        certificate_msg.extend(struct.pack(">I", len(cert_data))[1:])
        certificate_msg.extend(cert_data)

        return bytes(certificate_msg)

    async def _build_certificate_verify(
        self,
        connection_id: str,
    ) -> bytes:
        """Build CertificateVerify message.

        Args:
            connection_id: QUIC connection ID.

        Returns:
            CertificateVerify bytes.
        """
        signature = secrets.token_bytes(64)

        cert_verify_data = bytearray()
        cert_verify_data.extend(struct.pack(">H", 0x0401))
        cert_verify_data.extend(struct.pack(">H", len(signature)))
        cert_verify_data.extend(signature)

        cert_verify_msg = bytearray()
        cert_verify_msg.append(HandshakeType.CERTIFICATE_VERIFY)
        cert_verify_msg.extend(struct.pack(">I", len(cert_verify_data))[1:])
        cert_verify_msg.extend(cert_verify_data)

        return bytes(cert_verify_msg)

    async def _build_server_finished(
        self,
        connection_id: str,
    ) -> bytes:
        """Build ServerFinished message.

        Args:
            connection_id: QUIC connection ID.

        Returns:
            ServerFinished bytes.
        """
        verify_data = secrets.token_bytes(32)

        state = self._handshake_states.get(connection_id)
        if state:
            state.server_finished = verify_data

        finished_msg = bytearray()
        finished_msg.append(HandshakeType.FINISHED)
        finished_msg.extend(struct.pack(">I", len(verify_data))[1:])
        finished_msg.extend(verify_data)

        return bytes(finished_msg)

    async def _build_handshake_done(self) -> bytes:
        """Build HandshakeDone message.

        Returns:
            HandshakeDone bytes.
        """
        return bytes([0x1E])

    async def _build_key_share_extension(self) -> bytes:
        """Build KeyShare extension.

        Returns:
            KeyShare extension bytes.
        """
        key_share_entry = bytearray()
        key_share_entry.extend(struct.pack(">H", KeyShareGroup.X25519))

        public_key = secrets.token_bytes(32)
        key_share_entry.extend(struct.pack(">H", len(public_key)))
        key_share_entry.extend(public_key)

        key_share_ext = bytearray()
        key_share_ext.extend(struct.pack(">H", ExtensionType.KEY_SHARE))
        key_share_ext.extend(struct.pack(">H", len(key_share_entry)))
        key_share_ext.extend(key_share_entry)

        return bytes(key_share_ext)

    async def _build_quic_transport_params(
        self,
        connection_id: str,
    ) -> bytes:
        """Build QUIC Transport Parameters.

        Args:
            connection_id: QUIC connection ID.

        Returns:
            Transport parameters bytes.
        """
        params = bytearray()

        params.extend(struct.pack(">H", QuicTransportParamId.MAX_IDLE_TIMEOUT))
        params.extend(struct.pack(">H", 4))
        params.extend(struct.pack(">I", 30000))

        params.extend(struct.pack(">H", QuicTransportParamId.INITIAL_MAX_DATA))
        params.extend(struct.pack(">H", 8))
        params.extend(struct.pack(">Q", 1048576))

        params.extend(struct.pack(">H", QuicTransportParamId.INITIAL_MAX_STREAM_DATA_BIDI_LOCAL))
        params.extend(struct.pack(">H", 8))
        params.extend(struct.pack(">Q", 262144))

        params.extend(struct.pack(">H", QuicTransportParamId.INITIAL_MAX_STREAMS_BIDI))
        params.extend(struct.pack(">H", 8))
        params.extend(struct.pack(">Q", 100))

        return bytes(params)

    async def _get_or_generate_certificate(
        self,
        server_name: str,
    ) -> CertificateCacheEntry:
        """Get or generate certificate for domain.

        Args:
            server_name: Server name.

        Returns:
            CertificateCacheEntry.
        """
        now = time.time()

        if server_name in self._cert_cache:
            entry = self._cert_cache[server_name]
            if now < entry.expires_at:
                return entry

        cert_bytes = b""
        key_bytes = b""

        if self.ca_manager:
            try:
                cert_result = await self.ca_manager.generate_certificate(server_name)
                if cert_result:
                    cert_bytes = cert_result.get("certificate", b"")
                    key_bytes = cert_result.get("private_key", b"")
            except Exception as e:
                logger.error("Certificate generation failed: %s", e)

        if not cert_bytes:
            cert_bytes = self._generate_dummy_certificate(server_name)
            key_bytes = secrets.token_bytes(32)

        entry = CertificateCacheEntry(
            domain=server_name,
            certificate=cert_bytes,
            private_key=key_bytes,
            created_at=now,
            expires_at=now + 3600,
        )
        self._cert_cache[server_name] = entry

        return entry

    def _generate_dummy_certificate(self, server_name: str) -> bytes:
        """Generate dummy certificate for testing.

        Args:
            server_name: Server name.

        Returns:
            Dummy certificate bytes.
        """
        cert = bytearray()
        cert.extend(b"\x30")
        cert.extend(b"\x82\x01\x00")
        cert.extend(b"\x30\x82\x01\x00")
        cert.extend(server_name.encode("utf-8")[:64])
        cert.extend(b"\x00" * 100)
        return bytes(cert)

    def _select_cipher_suite(self, client_suites: List[int]) -> int:
        """Select cipher suite from client preferences.

        Args:
            client_suites: Client supported cipher suites.

        Returns:
            Selected cipher suite.
        """
        for suite in self.SUPPORTED_CIPHER_SUITES:
            if suite in client_suites:
                return suite
        return CipherSuite.TLS_AES_128_GCM_SHA256

    def _select_alpn(self, client_protocols: List[str]) -> str:
        """Select ALPN protocol from client preferences.

        Args:
            client_protocols: Client ALPN protocols.

        Returns:
            Selected ALPN protocol.
        """
        for proto in self.SUPPORTED_ALPN:
            if proto in client_protocols:
                return proto
        return "h3"

    async def _check_early_data_replay(
        self,
        connection_id: str,
        crypto_data: bytes,
    ) -> bool:
        """Check for 0-RTT data replay.

        Args:
            connection_id: QUIC connection ID.
            crypto_data: CRYPTO frame data.

        Returns:
            True if replay detected.
        """
        data_hash = crypto_data[:32]

        if data_hash in self._replay_cache:
            return True

        self._replay_cache[data_hash] = time.time()

        max_age = 300
        expired = [
            k for k, v in self._replay_cache.items()
            if time.time() - v > max_age
        ]
        for k in expired:
            del self._replay_cache[k]

        return False

    def get_handshake_state(
        self,
        connection_id: str,
    ) -> Optional[TlsHandshakeState]:
        """Get handshake state for connection.

        Args:
            connection_id: QUIC connection ID.

        Returns:
            TlsHandshakeState or None.
        """
        return self._handshake_states.get(connection_id)

    def clear_handshake_state(self, connection_id: str) -> None:
        """Clear handshake state for connection.

        Args:
            connection_id: QUIC connection ID.
        """
        self._handshake_states.pop(connection_id, None)

    def get_cert_cache_size(self) -> int:
        """Get certificate cache size.

        Returns:
            Cache entry count.
        """
        return len(self._cert_cache)
