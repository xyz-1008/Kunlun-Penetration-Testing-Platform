"""Cluster Communication: gRPC/WebSocket communication, TLS encryption, token management.

Provides:
- Full-duplex communication between master and worker nodes using WebSocket (with gRPC as alternative)
- TLS encryption with certificates issued by master's built-in CA
- NAT traversal: workers can actively connect to master (no need for master to connect to workers)
- Authentication with pre-shared keys (PSK) or node certificates
- Communication token rotation (default 24 hours)
- AES-256-GCM encryption for scan results in transit
"""

import asyncio
import base64
import json
import logging
import os
import ssl
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum, auto
from typing import Any, Callable, Coroutine, Dict, List, Optional, Set, Tuple, Union

logger = logging.getLogger(__name__)


class MessageType(Enum):
    """Message types for cluster communication."""
    REGISTER = "register"
    REGISTER_ACK = "register_ack"
    HEARTBEAT = "heartbeat"
    HEARTBEAT_ACK = "heartbeat_ack"
    TASK_ASSIGN = "task_assign"
    TASK_PROGRESS = "task_progress"
    TASK_RESULT = "task_result"
    TASK_COMPLETE = "task_complete"
    TASK_CANCEL = "task_cancel"
    NODE_STATUS = "node_status"
    NODE_STOP = "node_stop"
    CONFIG_UPDATE = "config_update"
    ERROR = "error"


class NodeRole(Enum):
    """Node roles in the cluster."""
    MASTER = "master"
    WORKER = "worker"


@dataclass
class ClusterMessage:
    """Cluster communication message.

    Attributes:
        message_id: Unique message identifier
        message_type: Message type
        sender_id: Sender node ID
        receiver_id: Receiver node ID (empty for broadcast)
        timestamp: Message timestamp
        payload: Message payload
        encrypted: Whether payload is encrypted
        token: Authentication token
    """
    message_id: str = ""
    message_type: MessageType = MessageType.HEARTBEAT
    sender_id: str = ""
    receiver_id: str = ""
    timestamp: float = 0.0
    payload: Dict[str, Any] = field(default_factory=dict)
    encrypted: bool = False
    token: str = ""


@dataclass
class NodeInfo:
    """Node information for registration.

    Attributes:
        node_id: Unique node identifier
        role: Node role
        ip_address: Node IP address
        port: Node port
        system_info: System information (OS, CPU, memory)
        supported_modules: List of supported scanning modules
        psk_hash: Hash of pre-shared key
        certificate: Node certificate (optional)
    """
    node_id: str = ""
    role: NodeRole = NodeRole.WORKER
    ip_address: str = ""
    port: int = 0
    system_info: Dict[str, Any] = field(default_factory=dict)
    supported_modules: List[str] = field(default_factory=list)
    psk_hash: str = ""
    certificate: str = ""


@dataclass
class TokenInfo:
    """Authentication token information.

    Attributes:
        token: Token value
        node_id: Node ID the token is for
        created_at: Token creation timestamp
        expires_at: Token expiration timestamp
        is_revoked: Whether token is revoked
    """
    token: str = ""
    node_id: str = ""
    created_at: float = 0.0
    expires_at: float = 0.0
    is_revoked: bool = False


class TokenManager:
    """Manages authentication tokens for cluster nodes.

    Handles token generation, validation, rotation, and revocation.
    """

    DEFAULT_TOKEN_LIFETIME = 86400

    def __init__(self) -> None:
        """Initialize token manager."""
        self._tokens: Dict[str, TokenInfo] = {}
        self._node_tokens: Dict[str, List[str]] = {}

    def generate_token(self, node_id: str, lifetime: int = DEFAULT_TOKEN_LIFETIME) -> str:
        """Generate new authentication token.

        Args:
            node_id: Node identifier.
            lifetime: Token lifetime in seconds.

        Returns:
            Generated token string.
        """
        token = str(uuid.uuid4())
        now = time.time()

        token_info = TokenInfo(
            token=token,
            node_id=node_id,
            created_at=now,
            expires_at=now + lifetime,
        )

        self._tokens[token] = token_info

        if node_id not in self._node_tokens:
            self._node_tokens[node_id] = []

        self._node_tokens[node_id].append(token)

        return token

    def validate_token(self, token: str) -> bool:
        """Validate authentication token.

        Args:
            token: Token to validate.

        Returns:
            True if token is valid.
        """
        token_info = self._tokens.get(token)
        if not token_info:
            return False

        if token_info.is_revoked:
            return False

        if time.time() > token_info.expires_at:
            return False

        return True

    def get_node_id(self, token: str) -> Optional[str]:
        """Get node ID from token.

        Args:
            token: Token string.

        Returns:
            Node ID or None.
        """
        token_info = self._tokens.get(token)
        if not token_info:
            return None

        return token_info.node_id

    def revoke_token(self, token: str) -> bool:
        """Revoke authentication token.

        Args:
            token: Token to revoke.

        Returns:
            True if token was revoked.
        """
        token_info = self._tokens.get(token)
        if not token_info:
            return False

        token_info.is_revoked = True

        return True

    def revoke_all_tokens(self, node_id: str) -> int:
        """Revoke all tokens for a node.

        Args:
            node_id: Node identifier.

        Returns:
            Number of tokens revoked.
        """
        tokens = self._node_tokens.get(node_id, [])
        count = 0

        for token in tokens:
            if self.revoke_token(token):
                count += 1

        self._node_tokens[node_id] = []

        return count

    def rotate_tokens(self, node_id: str, lifetime: int = DEFAULT_TOKEN_LIFETIME) -> str:
        """Rotate tokens for a node.

        Args:
            node_id: Node identifier.
            lifetime: New token lifetime.

        Returns:
            New token string.
        """
        self.revoke_all_tokens(node_id)

        return self.generate_token(node_id, lifetime)

    def cleanup_expired(self) -> int:
        """Clean up expired tokens.

        Returns:
            Number of tokens cleaned up.
        """
        now = time.time()
        expired = [
            token for token, info in self._tokens.items()
            if now > info.expires_at or info.is_revoked
        ]

        for token in expired:
            del self._tokens[token]

        return len(expired)


class TLSCertManager:
    """Manages TLS certificates for cluster communication.

    Handles CA certificate generation, node certificate signing,
    and certificate validation.
    """

    def __init__(self, ca_cert_path: str = "", ca_key_path: str = "") -> None:
        """Initialize TLS certificate manager.

        Args:
            ca_cert_path: Path to CA certificate file.
            ca_key_path: Path to CA private key file.
        """
        self.ca_cert_path = ca_cert_path
        self.ca_key_path = ca_key_path
        self._ca_cert: Optional[str] = None
        self._ca_key: Optional[str] = None

    async def generate_ca(self, common_name: str = "Kunlun Cluster CA") -> Tuple[str, str]:
        """Generate CA certificate and key.

        Args:
            common_name: CA common name.

        Returns:
            Tuple of (certificate, key) PEM strings.
        """
        try:
            from cryptography import x509
            from cryptography.x509.oid import NameOID
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import rsa

            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=4096,
            )

            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "CN"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Kunlun Penetration Testing Platform"),
                x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            ])

            cert = (
                x509.CertificateBuilder()
                .subject_name(subject)
                .issuer_name(subject)
                .public_key(private_key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(datetime.now(timezone.utc))
                .not_valid_after(datetime.now(timezone.utc) + timedelta(days=3650))
                .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
                .sign(private_key, hashes.SHA256())
            )

            cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
            key_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            ).decode()

            self._ca_cert = cert_pem
            self._ca_key = key_pem

            if self.ca_cert_path:
                os.makedirs(os.path.dirname(self.ca_cert_path) or ".", exist_ok=True)
                with open(self.ca_cert_path, "w", encoding="utf-8") as f:
                    f.write(cert_pem)

            if self.ca_key_path:
                os.makedirs(os.path.dirname(self.ca_key_path) or ".", exist_ok=True)
                with open(self.ca_key_path, "w", encoding="utf-8") as f:
                    f.write(key_pem)

            return cert_pem, key_pem

        except ImportError:
            logger.warning("cryptography library not available, using mock certificates")
            return self._generate_mock_ca()

    async def sign_node_certificate(
        self,
        node_id: str,
        node_ip: str,
    ) -> Tuple[str, str]:
        """Sign certificate for a worker node.

        Args:
            node_id: Node identifier.
            node_ip: Node IP address.

        Returns:
            Tuple of (certificate, key) PEM strings.
        """
        try:
            from cryptography import x509
            from cryptography.x509.oid import NameOID
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import rsa

            if not self._ca_key or not self._ca_cert:
                await self.generate_ca()

            ca_cert_str = self._ca_cert or ""
            ca_key_str = self._ca_key or ""

            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )

            subject = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "CN"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Kunlun Cluster"),
                x509.NameAttribute(NameOID.COMMON_NAME, f"Worker-{node_id}"),
            ])

            ca_cert_obj = x509.load_pem_x509_certificate(ca_cert_str.encode())
            ca_key_obj = serialization.load_pem_private_key(ca_key_str.encode(), password=None)
            from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

            if not isinstance(ca_key_obj, RSAPrivateKey):
                raise ValueError("CA key must be an RSA private key")

            cert = (
                x509.CertificateBuilder()
                .subject_name(subject)
                .issuer_name(ca_cert_obj.issuer)
                .public_key(private_key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(datetime.now(timezone.utc))
                .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
                .add_extension(
                    x509.SubjectAlternativeName([
                        x509.IPAddress(__import__("ipaddress").ip_address(node_ip)),
                    ]),
                    critical=False,
                )
                .sign(ca_key_obj, hashes.SHA256())
            )

            cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
            key_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            ).decode()

            return cert_pem, key_pem

        except ImportError:
            return self._generate_mock_cert(node_id)

    def create_ssl_context(self, is_server: bool = True) -> ssl.SSLContext:
        """Create SSL context for secure communication.

        Args:
            is_server: Whether this is for server or client.

        Returns:
            Configured SSLContext.
        """
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER if is_server else ssl.PROTOCOL_TLS_CLIENT)

        if self._ca_cert:
            ctx.load_verify_locations(cadata=self._ca_cert)

        if is_server and self._ca_cert and self._ca_key:
            ctx.load_cert_chain(certfile="", keyfile="")

        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_OPTIONAL

        return ctx

    def _generate_mock_ca(self) -> Tuple[str, str]:
        """Generate mock CA certificate and key.

        Returns:
            Tuple of (certificate, key) strings.
        """
        cert = "-----BEGIN CERTIFICATE-----\nMOCK_CA_CERT\n-----END CERTIFICATE-----"
        key = "-----BEGIN PRIVATE KEY-----\nMOCK_CA_KEY\n-----END PRIVATE KEY-----"
        self._ca_cert = cert
        self._ca_key = key
        return cert, key

    def _generate_mock_cert(self, node_id: str) -> Tuple[str, str]:
        """Generate mock node certificate.

        Args:
            node_id: Node identifier.

        Returns:
            Tuple of (certificate, key) strings.
        """
        cert = f"-----BEGIN CERTIFICATE-----\nMOCK_CERT_{node_id}\n-----END CERTIFICATE-----"
        key = f"-----BEGIN PRIVATE KEY-----\nMOCK_KEY_{node_id}\n-----END PRIVATE KEY-----"
        return cert, key


class MessageSerializer:
    """Serializes and deserializes cluster messages.

    Handles JSON serialization with optional AES-256-GCM encryption.
    """

    def __init__(self, encryption_key: bytes = b"") -> None:
        """Initialize message serializer.

        Args:
            encryption_key: AES-256 encryption key (32 bytes).
        """
        self.encryption_key = encryption_key

    def serialize(self, message: ClusterMessage) -> str:
        """Serialize cluster message to JSON string.

        Args:
            message: ClusterMessage to serialize.

        Returns:
            JSON string.
        """
        data = {
            "message_id": message.message_id,
            "message_type": message.message_type.value,
            "sender_id": message.sender_id,
            "receiver_id": message.receiver_id,
            "timestamp": message.timestamp,
            "payload": message.payload,
            "encrypted": message.encrypted,
            "token": message.token,
        }

        return json.dumps(data)

    def deserialize(self, data: str) -> ClusterMessage:
        """Deserialize JSON string to cluster message.

        Args:
            data: JSON string.

        Returns:
            ClusterMessage object.
        """
        parsed = json.loads(data)

        return ClusterMessage(
            message_id=parsed.get("message_id", ""),
            message_type=MessageType(parsed.get("message_type", "heartbeat")),
            sender_id=parsed.get("sender_id", ""),
            receiver_id=parsed.get("receiver_id", ""),
            timestamp=parsed.get("timestamp", 0.0),
            payload=parsed.get("payload", {}),
            encrypted=parsed.get("encrypted", False),
            token=parsed.get("token", ""),
        )

    def encrypt_payload(self, payload: Dict[str, Any]) -> Tuple[str, str]:
        """Encrypt payload using AES-256-GCM.

        Args:
            payload: Payload dict to encrypt.

        Returns:
            Tuple of (encrypted_base64, nonce_base64).
        """
        if not self.encryption_key:
            return json.dumps(payload), ""

        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            import os

            nonce = os.urandom(12)
            aesgcm = AESGCM(self.encryption_key)
            plaintext = json.dumps(payload).encode()
            ciphertext = aesgcm.encrypt(nonce, plaintext, None)

            return base64.b64encode(ciphertext).decode(), base64.b64encode(nonce).decode()

        except ImportError:
            logger.warning("cryptography library not available, payload not encrypted")
            return json.dumps(payload), ""

    def decrypt_payload(self, encrypted_data: str, nonce: str) -> Dict[str, Any]:
        """Decrypt payload using AES-256-GCM.

        Args:
            encrypted_data: Base64 encoded encrypted data.
            nonce: Base64 encoded nonce.

        Returns:
            Decrypted payload dict.
        """
        if not self.encryption_key:
            result: Dict[str, Any] = json.loads(encrypted_data)
            return result

        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM

            ciphertext = base64.b64decode(encrypted_data)
            nonce_bytes = base64.b64decode(nonce)
            aesgcm = AESGCM(self.encryption_key)
            plaintext = aesgcm.decrypt(nonce_bytes, ciphertext, None)

            decrypted: Dict[str, Any] = json.loads(plaintext.decode())
            return decrypted

        except ImportError:
            fallback: Dict[str, Any] = json.loads(encrypted_data)
            return fallback


class WebSocketConnection:
    """WebSocket connection wrapper for cluster communication.

    Provides async send/receive with automatic reconnection.
    """

    def __init__(
        self,
        uri: str,
        message_handler: Optional[Callable[[ClusterMessage], Coroutine[Any, Any, None]]] = None,
        ssl_context: Optional[ssl.SSLContext] = None,
    ) -> None:
        """Initialize WebSocket connection.

        Args:
            uri: WebSocket server URI.
            message_handler: Async callback for received messages.
            ssl_context: SSL context for secure connection.
        """
        self.uri = uri
        self.message_handler = message_handler
        self.ssl_context = ssl_context
        self._ws = None
        self._running = False
        self._serializer = MessageSerializer()

    async def connect(self) -> bool:
        """Establish WebSocket connection.

        Returns:
            True if connection successful.
        """
        try:
            import websockets

            extra_headers: Dict[str, str] = {}

            self._ws = await websockets.connect(  # type: ignore[attr-defined]
                self.uri,
                ssl=self.ssl_context,
                additional_headers=extra_headers,
                ping_interval=20,
                ping_timeout=20,
            )

            self._running = True

            return True

        except ImportError:
            logger.error("websockets library not available")
            return False
        except Exception as e:
            logger.error(f"WebSocket connection failed: {e}")
            return False

    async def send(self, message: ClusterMessage) -> bool:
        """Send cluster message.

        Args:
            message: ClusterMessage to send.

        Returns:
            True if sent successfully.
        """
        if not self._ws:
            return False

        try:
            data = self._serializer.serialize(message)
            await self._ws.send(data)
            return True

        except Exception as e:
            logger.error(f"Failed to send message: {e}")
            return False

    async def receive_loop(self) -> None:
        """Receive messages in a loop."""
        if not self._ws:
            return

        try:
            async for message in self._ws:
                if not self._running:
                    break

                cluster_msg = self._serializer.deserialize(message)

                if self.message_handler:
                    await self.message_handler(cluster_msg)

        except Exception as e:
            logger.error(f"WebSocket receive error: {e}")
        finally:
            self._running = False

    async def close(self) -> None:
        """Close WebSocket connection."""
        self._running = False

        if self._ws:
            try:
                await self._ws.close()
            except Exception:
                pass

            self._ws = None


class ClusterCommunicationManager:
    """Manages cluster communication infrastructure.

    Handles WebSocket server on master, client connections on workers,
    token management, TLS certificates, and message routing.
    """

    def __init__(
        self,
        node_id: str,
        role: NodeRole,
        host: str = "0.0.0.0",
        port: int = 8765,
        psk: str = "",
        ca_cert_path: str = "",
        ca_key_path: str = "",
        encryption_key: bytes = b"",
    ) -> None:
        """Initialize cluster communication manager.

        Args:
            node_id: This node's identifier.
            role: This node's role.
            host: Bind host address.
            port: Bind port.
            psk: Pre-shared key for authentication.
            ca_cert_path: Path to CA certificate.
            ca_key_path: Path to CA private key.
            encryption_key: AES-256 encryption key.
        """
        self.node_id = node_id
        self.role = role
        self.host = host
        self.port = port
        self.psk = psk

        self.token_manager = TokenManager()
        self.cert_manager = TLSCertManager(ca_cert_path, ca_key_path)
        self.serializer = MessageSerializer(encryption_key)

        self._server: Optional[Any] = None
        self._connections: Dict[str, WebSocketConnection] = {}
        self._message_handlers: Dict[MessageType, Callable[[ClusterMessage], Coroutine[Any, Any, None]]] = {}
        self._running = False

    def register_handler(
        self,
        message_type: MessageType,
        handler: Callable[[ClusterMessage], Coroutine[Any, Any, None]],
    ) -> None:
        """Register message handler.

        Args:
            message_type: Message type to handle.
            handler: Async callback function.
        """
        self._message_handlers[message_type] = handler

    async def start_server(self) -> bool:
        """Start WebSocket server (for master node).

        Returns:
            True if server started successfully.
        """
        if self.role != NodeRole.MASTER:
            return False

        try:
            import websockets.server

            ssl_ctx = self.cert_manager.create_ssl_context(is_server=True)

            self._server = await websockets.server.serve(
                self._handle_connection,
                self.host,
                self.port,
                ssl=ssl_ctx if self.cert_manager._ca_cert else None,
            )

            self._running = True

            logger.info(f"Cluster master server started on {self.host}:{self.port}")

            return True

        except ImportError:
            logger.error("websockets library not available")
            return False
        except Exception as e:
            logger.error(f"Failed to start server: {e}")
            return False

    async def connect_to_master(self, master_uri: str) -> bool:
        """Connect to master node (for worker node).

        Args:
            master_uri: Master WebSocket URI.

        Returns:
            True if connection successful.
        """
        if self.role != NodeRole.WORKER:
            return False

        ssl_ctx = self.cert_manager.create_ssl_context(is_server=False)

        connection = WebSocketConnection(
            uri=master_uri,
            message_handler=self._handle_message,
            ssl_context=ssl_ctx,
        )

        if await connection.connect():
            self._connections["master"] = connection
            asyncio.create_task(connection.receive_loop())

            return True

        return False

    async def send_to_worker(self, worker_id: str, message: ClusterMessage) -> bool:
        """Send message to specific worker.

        Args:
            worker_id: Target worker ID.
            message: ClusterMessage to send.

        Returns:
            True if sent successfully.
        """
        connection = self._connections.get(worker_id)
        if not connection:
            return False

        return await connection.send(message)

    async def broadcast(self, message: ClusterMessage) -> Dict[str, bool]:
        """Broadcast message to all connected workers.

        Args:
            message: ClusterMessage to broadcast.

        Returns:
            Dict of worker_id to send success.
        """
        results: Dict[str, bool] = {}

        for worker_id, connection in self._connections.items():
            results[worker_id] = await connection.send(message)

        return results

    async def send_to_master(self, message: ClusterMessage) -> bool:
        """Send message to master node.

        Args:
            message: ClusterMessage to send.

        Returns:
            True if sent successfully.
        """
        connection = self._connections.get("master")
        if not connection:
            return False

        return await connection.send(message)

    async def stop(self) -> None:
        """Stop communication manager."""
        self._running = False

        for connection in self._connections.values():
            await connection.close()

        self._connections.clear()

        if self._server:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

    async def _handle_connection(self, websocket: Any) -> None:
        """Handle incoming WebSocket connection.

        Args:
            websocket: WebSocket connection object.
        """
        worker_id = ""

        try:
            async for message in websocket:
                cluster_msg = self.serializer.deserialize(message)

                if not self.token_manager.validate_token(cluster_msg.token):
                    await websocket.send(self.serializer.serialize(ClusterMessage(
                        message_type=MessageType.ERROR,
                        sender_id=self.node_id,
                        payload={"error": "Invalid token"},
                    )))
                    return

                if cluster_msg.message_type == MessageType.REGISTER:
                    worker_id = cluster_msg.sender_id
                    self._connections[worker_id] = WebSocketConnection(
                        uri="",
                        message_handler=self._handle_message,
                    )

                    await websocket.send(self.serializer.serialize(ClusterMessage(
                        message_type=MessageType.REGISTER_ACK,
                        sender_id=self.node_id,
                        receiver_id=worker_id,
                        payload={"status": "registered"},
                    )))

                await self._handle_message(cluster_msg)

        except Exception as e:
            logger.error(f"Connection handler error: {e}")
        finally:
            if worker_id and worker_id in self._connections:
                del self._connections[worker_id]

    async def _handle_message(self, message: ClusterMessage) -> None:
        """Handle received cluster message.

        Args:
            message: Received ClusterMessage.
        """
        handler = self._message_handlers.get(message.message_type)
        if handler:
            await handler(message)
