"""IoT MQTT Scanner: MQTT connection, topic enumeration, message listening.

Provides:
- MQTT connection with anonymous and default credential attempts
- Topic enumeration with built-in common topic dictionary
- Message listening with wildcard topic subscription (#)
- TLS encryption detection
- Default credential testing
- Message capture and analysis
"""

import asyncio
import logging
import socket
import ssl
import struct
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Callable, Coroutine, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


class MQTTQoS(Enum):
    """MQTT Quality of Service levels."""
    AT_MOST_ONCE = 0
    AT_LEAST_ONCE = 1
    EXACTLY_ONCE = 2


class MQTTConnAck(Enum):
    """MQTT Connection Acknowledgment codes."""
    ACCEPTED = 0
    UNACCEPTABLE_PROTOCOL = 1
    IDENTIFIER_REJECTED = 2
    SERVER_UNAVAILABLE = 3
    BAD_USERNAME_PASSWORD = 4
    NOT_AUTHORIZED = 5


@dataclass
class MQTTMessage:
    """Captured MQTT message.

    Attributes:
        topic: Message topic
        payload: Message payload (bytes)
        qos: Quality of Service level
        retain: Whether message is retained
        timestamp: Message capture timestamp
    """
    topic: str = ""
    payload: bytes = b""
    qos: MQTTQoS = MQTTQoS.AT_MOST_ONCE
    retain: bool = False
    timestamp: float = 0.0


@dataclass
class MQTTBrokerInfo:
    """MQTT broker information.

    Attributes:
        host: Broker host
        port: Broker port
        is_tls_enabled: Whether TLS is enabled
        protocol_version: MQTT protocol version
        client_id: Client identifier used
        server_keep_alive: Server keep alive interval
    """
    host: str = ""
    port: int = 1883
    is_tls_enabled: bool = False
    protocol_version: str = ""
    client_id: str = ""
    server_keep_alive: int = 0


@dataclass
class MQTTScanResult:
    """MQTT scan result.

    Attributes:
        broker_info: Broker information
        is_anonymous_access: Whether anonymous access is allowed
        default_credentials_work: Whether default credentials work
        discovered_topics: List of discovered topics
        captured_messages: List of captured messages
        security_findings: List of security findings
        scan_timestamp: Scan timestamp
    """
    broker_info: Optional[MQTTBrokerInfo] = None
    is_anonymous_access: bool = False
    default_credentials_work: bool = False
    discovered_topics: List[str] = field(default_factory=list)
    captured_messages: List[MQTTMessage] = field(default_factory=list)
    security_findings: List[str] = field(default_factory=list)
    scan_timestamp: float = 0.0


class MQTTScanner:
    """Scans MQTT brokers for security vulnerabilities.

    Provides anonymous connection testing, default credential testing,
    topic enumeration, and message capture capabilities.
    """

    DEFAULT_CREDENTIALS = [
        ("admin", "admin"),
        ("admin", "password"),
        ("admin", "123456"),
        ("root", "root"),
        ("root", "password"),
        ("guest", "guest"),
        ("mqtt", "mqtt"),
        ("user", "user"),
        ("test", "test"),
        ("", ""),
    ]

    COMMON_TOPICS = [
        "test",
        "home/temperature",
        "home/humidity",
        "home/light",
        "home/door",
        "home/window",
        "home/motion",
        "home/camera",
        "home/alarm",
        "device/status",
        "device/config",
        "device/data",
        "device/control",
        "sensor/temperature",
        "sensor/humidity",
        "sensor/pressure",
        "sensor/light",
        "system/log",
        "system/status",
        "system/config",
        "iot/data",
        "iot/control",
        "iot/status",
        "factory/line1",
        "factory/line2",
        "building/hvac",
        "building/access",
        "energy/power",
        "energy/solar",
        "water/level",
        "water/flow",
    ]

    WILDCARD_TOPICS = [
        "#",
        "+/#",
        "home/#",
        "device/#",
        "sensor/#",
        "iot/#",
        "system/#",
    ]

    def __init__(self, timeout: float = 5.0) -> None:
        """Initialize MQTT scanner.

        Args:
            timeout: Connection timeout in seconds.
        """
        self.timeout = timeout
        self._message_callbacks: List[Callable[[MQTTMessage], Coroutine[Any, Any, None]]] = []

    def register_message_callback(
        self,
        callback: Callable[[MQTTMessage], Coroutine[Any, Any, None]],
    ) -> None:
        """Register callback for captured messages.

        Args:
            callback: Async callback for each captured message.
        """
        self._message_callbacks.append(callback)

    async def scan_broker(
        self,
        host: str,
        port: int = 1883,
        use_tls: bool = False,
    ) -> MQTTScanResult:
        """Scan an MQTT broker for vulnerabilities.

        Args:
            host: Broker host address.
            port: Broker port number.
            use_tls: Whether to use TLS connection.

        Returns:
            MQTTScanResult with scan findings.
        """
        result = MQTTScanResult(
            broker_info=MQTTBrokerInfo(
                host=host,
                port=port,
                is_tls_enabled=use_tls,
            ),
            scan_timestamp=time.time(),
        )

        anonymous_success = await self._test_anonymous_access(host, port, use_tls)
        result.is_anonymous_access = anonymous_success

        if anonymous_success:
            result.security_findings.append("Anonymous access is allowed")

        if not anonymous_success:
            creds_work = await self._test_default_credentials(host, port, use_tls)
            result.default_credentials_work = creds_work

            if creds_work:
                result.security_findings.append("Default credentials are accepted")

        topics = await self._enumerate_topics(host, port, use_tls)
        result.discovered_topics = topics

        if topics:
            result.security_findings.append(f"Discovered {len(topics)} accessible topics")

        messages = await self._capture_messages(host, port, use_tls, duration=10.0)
        result.captured_messages = messages

        if messages:
            result.security_findings.append(f"Captured {len(messages)} messages")

        if not use_tls:
            result.security_findings.append("TLS is not enabled - traffic is unencrypted")

        return result

    async def _test_anonymous_access(
        self,
        host: str,
        port: int,
        use_tls: bool,
    ) -> bool:
        """Test if broker allows anonymous access.

        Args:
            host: Broker host.
            port: Broker port.
            use_tls: Whether to use TLS.

        Returns:
            True if anonymous access is allowed.
        """
        try:
            reader, writer = await self._connect(host, port, use_tls)

            client_id = f"scanner_{int(time.time())}"
            connect_packet = self._build_connect_packet(
                client_id=client_id,
                username="",
                password="",
            )

            writer.write(connect_packet)
            await writer.drain()

            connack = await asyncio.wait_for(reader.readexactly(4), timeout=self.timeout)

            writer.close()
            await writer.wait_closed()

            if len(connack) >= 4 and connack[3] == MQTTConnAck.ACCEPTED.value:
                return True

        except Exception as e:
            logger.debug(f"Anonymous access test failed: {e}")

        return False

    async def _test_default_credentials(
        self,
        host: str,
        port: int,
        use_tls: bool,
    ) -> bool:
        """Test default credentials against the broker.

        Args:
            host: Broker host.
            port: Broker port.
            use_tls: Whether to use TLS.

        Returns:
            True if any default credentials work.
        """
        for username, password in self.DEFAULT_CREDENTIALS:
            try:
                reader, writer = await self._connect(host, port, use_tls)

                client_id = f"scanner_{int(time.time())}"
                connect_packet = self._build_connect_packet(
                    client_id=client_id,
                    username=username,
                    password=password,
                )

                writer.write(connect_packet)
                await writer.drain()

                connack = await asyncio.wait_for(reader.readexactly(4), timeout=self.timeout)

                writer.close()
                await writer.wait_closed()

                if len(connack) >= 4 and connack[3] == MQTTConnAck.ACCEPTED.value:
                    logger.info(f"Default credentials worked: {username}:{password}")
                    return True

            except Exception:
                continue

        return False

    async def _enumerate_topics(
        self,
        host: str,
        port: int,
        use_tls: bool,
    ) -> List[str]:
        """Enumerate accessible topics on the broker.

        Args:
            host: Broker host.
            port: Broker port.
            use_tls: Whether to use TLS.

        Returns:
            List of accessible topic names.
        """
        discovered = []

        try:
            reader, writer = await self._connect(host, port, use_tls)

            client_id = f"scanner_{int(time.time())}"
            connect_packet = self._build_connect_packet(client_id=client_id)
            writer.write(connect_packet)
            await writer.drain()

            await asyncio.wait_for(reader.readexactly(4), timeout=self.timeout)

            for topic in self.COMMON_TOPICS:
                subscribe_packet = self._build_subscribe_packet(
                    packet_id=1,
                    topic=topic,
                    qos=MQTTQoS.AT_MOST_ONCE,
                )
                writer.write(subscribe_packet)
                await writer.drain()

                try:
                    suback = await asyncio.wait_for(reader.readexactly(5), timeout=self.timeout)
                    if len(suback) >= 5 and suback[4] < 0x80:
                        discovered.append(topic)
                except asyncio.TimeoutError:
                    pass

            writer.close()
            await writer.wait_closed()

        except Exception as e:
            logger.debug(f"Topic enumeration failed: {e}")

        return discovered

    async def _capture_messages(
        self,
        host: str,
        port: int,
        use_tls: bool,
        duration: float = 10.0,
    ) -> List[MQTTMessage]:
        """Capture messages from the broker using wildcard subscriptions.

        Args:
            host: Broker host.
            port: Broker port.
            use_tls: Whether to use TLS.
            duration: Capture duration in seconds.

        Returns:
            List of captured MQTTMessage objects.
        """
        messages = []

        try:
            reader, writer = await self._connect(host, port, use_tls)

            client_id = f"scanner_{int(time.time())}"
            connect_packet = self._build_connect_packet(client_id=client_id)
            writer.write(connect_packet)
            await writer.drain()

            await asyncio.wait_for(reader.readexactly(4), timeout=self.timeout)

            for wildcard in self.WILDCARD_TOPICS:
                subscribe_packet = self._build_subscribe_packet(
                    packet_id=1,
                    topic=wildcard,
                    qos=MQTTQoS.AT_MOST_ONCE,
                )
                writer.write(subscribe_packet)
                await writer.drain()

                try:
                    await asyncio.wait_for(reader.readexactly(5), timeout=self.timeout)
                except asyncio.TimeoutError:
                    pass

            start_time = time.time()
            while time.time() - start_time < duration:
                try:
                    data = await asyncio.wait_for(reader.read(256), timeout=1.0)
                    if not data:
                        break

                    parsed = self._parse_mqtt_message(data)
                    if parsed:
                        messages.append(parsed)

                        for callback in self._message_callbacks:
                            try:
                                await callback(parsed)
                            except Exception:
                                pass

                except asyncio.TimeoutError:
                    continue

            writer.close()
            await writer.wait_closed()

        except Exception as e:
            logger.debug(f"Message capture failed: {e}")

        return messages

    async def _connect(
        self,
        host: str,
        port: int,
        use_tls: bool,
    ) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """Establish connection to MQTT broker.

        Args:
            host: Broker host.
            port: Broker port.
            use_tls: Whether to use TLS.

        Returns:
            Tuple of (reader, writer).
        """
        if use_tls:
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE

            reader, writer = await asyncio.open_connection(
                host, port, ssl=ssl_context
            )
        else:
            reader, writer = await asyncio.open_connection(host, port)

        return reader, writer

    def _build_connect_packet(
        self,
        client_id: str,
        username: str = "",
        password: str = "",
    ) -> bytes:
        """Build MQTT CONNECT packet.

        Args:
            client_id: Client identifier.
            username: Username for authentication.
            password: Password for authentication.

        Returns:
            MQTT CONNECT packet bytes.
        """
        protocol_name = b"\x00\x04MQTT"
        protocol_level = b"\x04"
        connect_flags = b"\x02"

        if username:
            connect_flags = bytes([connect_flags[0] | 0x80 | 0x40])

        keep_alive = struct.pack(">H", 60)

        payload = self._encode_utf8_string(client_id)

        if username:
            payload += self._encode_utf8_string(username)
            payload += self._encode_utf8_string(password)

        variable_header = protocol_name + protocol_level + connect_flags + keep_alive

        remaining_length = len(variable_header) + len(payload)
        packet = b"\x10" + self._encode_remaining_length(remaining_length)
        packet += variable_header + payload

        return packet

    def _build_subscribe_packet(
        self,
        packet_id: int,
        topic: str,
        qos: MQTTQoS,
    ) -> bytes:
        """Build MQTT SUBSCRIBE packet.

        Args:
            packet_id: Packet identifier.
            topic: Topic to subscribe to.
            qos: Quality of Service level.

        Returns:
            MQTT SUBSCRIBE packet bytes.
        """
        variable_header = struct.pack(">H", packet_id)
        payload = self._encode_utf8_string(topic) + bytes([qos.value])

        remaining_length = len(variable_header) + len(payload)
        packet = b"\x82" + self._encode_remaining_length(remaining_length)
        packet += variable_header + payload

        return packet

    def _parse_mqtt_message(self, data: bytes) -> Optional[MQTTMessage]:
        """Parse an MQTT message from raw bytes.

        Args:
            data: Raw MQTT message bytes.

        Returns:
            MQTTMessage object or None.
        """
        try:
            if len(data) < 2:
                return None

            msg_type = (data[0] >> 4) & 0x0F

            if msg_type != 3:
                return None

            qos = (data[0] >> 1) & 0x03
            retain = bool(data[0] & 0x01)

            topic, payload_data = self._decode_variable_header(data[1:])

            return MQTTMessage(
                topic=topic,
                payload=payload_data,
                qos=MQTTQoS(qos),
                retain=retain,
                timestamp=time.time(),
            )

        except Exception:
            return None

    def _encode_utf8_string(self, text: str) -> bytes:
        """Encode a string as UTF-8 with length prefix.

        Args:
            text: String to encode.

        Returns:
            Encoded bytes with length prefix.
        """
        encoded = text.encode("utf-8")
        return struct.pack(">H", len(encoded)) + encoded

    def _encode_remaining_length(self, length: int) -> bytes:
        """Encode remaining length field.

        Args:
            length: Length value to encode.

        Returns:
            Encoded remaining length bytes.
        """
        encoded = bytearray()
        while True:
            byte = length % 128
            length //= 128
            if length > 0:
                byte |= 0x80
            encoded.append(byte)
            if length == 0:
                break
        return bytes(encoded)

    def _decode_variable_header(self, data: bytes) -> Tuple[str, bytes]:
        """Decode MQTT variable header.

        Args:
            data: Variable header bytes.

        Returns:
            Tuple of (topic, payload).
        """
        if len(data) < 2:
            return "", b""

        topic_length = struct.unpack(">H", data[:2])[0]
        topic = data[2:2+topic_length].decode("utf-8", errors="ignore")

        payload = data[2+topic_length:]

        return topic, payload
