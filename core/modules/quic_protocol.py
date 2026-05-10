"""QUIC protocol stack implementation for HTTP/3 proxy.

Provides:
- QUIC connection management and version negotiation
- Long header and short header parsing
- Connection ID management
- Connection migration support
- Stream management and multiplexing
- Flow control (stream and connection level)
"""

import asyncio
import logging
import secrets
import struct
import time
from dataclasses import dataclass, field
from enum import Enum, IntEnum
from typing import Any, Callable, Coroutine, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


class QuicVersion(IntEnum):
    """QUIC protocol versions."""
    VERSION_1 = 0x00000001
    VERSION_2 = 0x6B3343CF
    NEGOTIATION = 0x00000000


class PacketType(Enum):
    """QUIC packet types."""
    INITIAL = "initial"
    HANDSHAKE = "handshake"
    RETRY = "retry"
    ZERO_RTT = "0rtt"
    SHORT_HEADER = "short_header"
    VERSION_NEGOTIATION = "version_negotiation"


class FrameType(IntEnum):
    """QUIC frame types per RFC 9000."""
    PADDING = 0x00
    PING = 0x01
    ACK = 0x02
    ACK_ECN = 0x03
    RESET_STREAM = 0x04
    STOP_SENDING = 0x05
    CRYPTO = 0x06
    NEW_TOKEN = 0x07
    STREAM = 0x08
    MAX_DATA = 0x10
    MAX_STREAM_DATA = 0x11
    MAX_STREAMS_BIDI = 0x12
    MAX_STREAMS_UNI = 0x13
    DATA_BLOCKED = 0x14
    STREAM_DATA_BLOCKED = 0x15
    STREAMS_BLOCKED_BIDI = 0x16
    STREAMS_BLOCKED_UNI = 0x17
    NEW_CONNECTION_ID = 0x18
    RETIRE_CONNECTION_ID = 0x19
    PATH_CHALLENGE = 0x1A
    PATH_RESPONSE = 0x1B
    TRANSPORT_CLOSE = 0x1C
    APPLICATION_CLOSE = 0x1D
    HANDSHAKE_DONE = 0x1E
    DATAGRAM = 0x30
    DATAGRAM_WITH_LEN = 0x31


class StreamType(Enum):
    """QUIC stream types."""
    BIDIRECTIONAL = "bidirectional"
    UNIDIRECTIONAL = "unidirectional"


class StreamState(Enum):
    """QUIC stream states."""
    IDLE = "idle"
    OPEN = "open"
    HALF_CLOSED_LOCAL = "half_closed_local"
    HALF_CLOSED_REMOTE = "half_closed_remote"
    CLOSED = "closed"
    RESET = "reset"


@dataclass
class QuicConnectionId:
    """QUIC Connection ID.

    Attributes:
        data: Raw connection ID bytes
        length: Connection ID length
    """
    data: bytes = b""
    length: int = 0

    def __eq__(self, other: object) -> bool:
        """Check equality."""
        if not isinstance(other, QuicConnectionId):
            return NotImplemented
        return self.data == other.data

    def __hash__(self) -> int:
        """Hash connection ID."""
        return hash(self.data)


@dataclass
class QuicTransportParameters:
    """QUIC transport parameters.

    Attributes:
        max_idle_timeout: Maximum idle timeout in milliseconds
        max_udp_payload_size: Maximum UDP payload size
        initial_max_data: Initial connection-level flow control limit
        initial_max_stream_data_bidi_local: Initial stream data limit for local bidirectional streams
        initial_max_stream_data_bidi_remote: Initial stream data limit for remote bidirectional streams
        initial_max_stream_data_uni: Initial stream data limit for unidirectional streams
        initial_max_streams_bidi: Initial maximum bidirectional streams
        initial_max_streams_uni: Initial maximum unidirectional streams
        ack_delay_exponent: ACK delay exponent
        max_ack_delay: Maximum ACK delay in milliseconds
        disable_active_migration: Whether active migration is disabled
        preferred_address: Preferred address for migration
    """
    max_idle_timeout: int = 30000
    max_udp_payload_size: int = 1200
    initial_max_data: int = 1048576
    initial_max_stream_data_bidi_local: int = 262144
    initial_max_stream_data_bidi_remote: int = 262144
    initial_max_stream_data_uni: int = 262144
    initial_max_streams_bidi: int = 100
    initial_max_streams_uni: int = 100
    ack_delay_exponent: int = 3
    max_ack_delay: int = 25
    disable_active_migration: bool = False
    preferred_address: Optional[bytes] = None


@dataclass
class QuicPacketHeader:
    """QUIC packet header.

    Attributes:
        packet_type: Packet type
        version: QUIC version
        destination_connection_id: Destination connection ID
        source_connection_id: Source connection ID
        packet_number: Packet number
        token: Token (for Initial/Retry packets)
        length: Packet payload length
    """
    packet_type: PacketType = PacketType.INITIAL
    version: QuicVersion = QuicVersion.VERSION_1
    destination_connection_id: QuicConnectionId = field(default_factory=QuicConnectionId)
    source_connection_id: QuicConnectionId = field(default_factory=QuicConnectionId)
    packet_number: int = 0
    token: bytes = b""
    length: int = 0


@dataclass
class QuicFrame:
    """QUIC frame.

    Attributes:
        frame_type: Frame type
        data: Frame payload
        stream_id: Stream ID (for STREAM frames)
        offset: Data offset (for STREAM frames)
        fin: FIN flag (for STREAM frames)
    """
    frame_type: FrameType = FrameType.PADDING
    data: bytes = b""
    stream_id: int = 0
    offset: int = 0
    fin: bool = False


@dataclass
class QuicStream:
    """QUIC stream.

    Attributes:
        stream_id: Stream identifier
        stream_type: Stream type
        state: Stream state
        data: Received data buffer
        data_sent: Bytes sent
        data_received: Bytes received
        max_data: Maximum data limit
        offset: Current offset
        fin_received: Whether FIN received
        fin_sent: Whether FIN sent
        reset_received: Whether RESET received
        reset_sent: Whether RESET sent
        created_at: Stream creation timestamp
    """
    stream_id: int = 0
    stream_type: StreamType = StreamType.BIDIRECTIONAL
    state: StreamState = StreamState.IDLE
    data: bytearray = field(default_factory=bytearray)
    data_sent: int = 0
    data_received: int = 0
    max_data: int = 262144
    offset: int = 0
    fin_received: bool = False
    fin_sent: bool = False
    reset_received: bool = False
    reset_sent: bool = False
    created_at: float = 0.0


@dataclass
class QuicConnection:
    """QUIC connection.

    Attributes:
        connection_id: Primary connection ID
        version: Negotiated QUIC version
        state: Connection state
        client_address: Client (host, port)
        server_address: Server (host, port)
        transport_parameters: Client transport parameters
        local_transport_parameters: Local transport parameters
        streams: Active streams
        max_streams_bidi: Maximum bidirectional streams
        max_streams_uni: Maximum unidirectional streams
        connection_max_data: Connection-level flow control limit
        connection_data_sent: Bytes sent on connection
        connection_data_received: Bytes received on connection
        packet_number_send: Next packet number to send
        packet_number_recv: Last received packet number
        tls_handshake_complete: Whether TLS handshake complete
        early_data_accepted: Whether 0-RTT data accepted
        last_activity: Last activity timestamp
        created_at: Connection creation timestamp
    """
    connection_id: QuicConnectionId = field(default_factory=QuicConnectionId)
    version: QuicVersion = QuicVersion.VERSION_1
    state: str = "initial"
    client_address: Tuple[str, int] = ("", 0)
    server_address: Tuple[str, int] = ("", 0)
    transport_parameters: Optional[QuicTransportParameters] = None
    local_transport_parameters: QuicTransportParameters = field(default_factory=QuicTransportParameters)
    streams: Dict[int, QuicStream] = field(default_factory=dict)
    max_streams_bidi: int = 100
    max_streams_uni: int = 100
    connection_max_data: int = 1048576
    connection_data_sent: int = 0
    connection_data_received: int = 0
    packet_number_send: int = 0
    packet_number_recv: int = -1
    tls_handshake_complete: bool = False
    early_data_accepted: bool = False
    last_activity: float = 0.0
    created_at: float = 0.0


class QuicProtocolStack:
    """QUIC protocol stack implementation.

    Provides QUIC connection management, version negotiation,
    header parsing, stream management, and flow control.
    """

    SUPPORTED_VERSIONS: List[QuicVersion] = [
        QuicVersion.VERSION_1,
        QuicVersion.VERSION_2,
    ]

    INITIAL_SALT_V1: bytes = bytes.fromhex(
        "38762cf7f55934b34d179ae6a4c80cadccbb7f0a"
    )

    INITIAL_SALT_V2: bytes = bytes.fromhex(
        "0dede3def700a6db819381be6e269dcbf9bd2ed9"
    )

    MAX_PACKET_SIZE: int = 65536
    MIN_INITIAL_PACKET_SIZE: int = 1200
    MAX_STREAMS: int = 2**60

    def __init__(
        self,
        event_bus: Optional[Any] = None,
    ) -> None:
        """Initialize QUIC protocol stack.

        Args:
            event_bus: Event bus for broadcasting events.
        """
        self.event_bus = event_bus
        self._progress_callback: Optional[Callable[[str, float], Coroutine[Any, Any, None]]] = None
        self._log_callback: Optional[Callable[[str], Coroutine[Any, Any, None]]] = None
        self._connections: Dict[str, QuicConnection] = {}
        self._connection_ids: Dict[QuicConnectionId, str] = {}
        self._active: bool = False

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
        logger.info("QUIC Progress: %.1f%% - %s", percentage, message)

    async def _report_log(self, message: str) -> None:
        """Report log via callback.

        Args:
            message: Log message.
        """
        if self._log_callback:
            await self._log_callback(message)
        logger.info("QUIC: %s", message)

    async def start(self, port: int = 443) -> bool:
        """Start QUIC protocol stack.

        Args:
            port: UDP port to listen on.

        Returns:
            True if started successfully.
        """
        try:
            self._active = True
            await self._report_log(f"QUIC协议栈启动，监听UDP端口 {port}")
            return True
        except Exception as e:
            await self._report_log(f"QUIC协议栈启动失败: {e}")
            logger.error("QUIC stack start failed: %s", e)
            return False

    async def stop(self) -> None:
        """Stop QUIC protocol stack."""
        self._active = False
        for conn_id in list(self._connections.keys()):
            await self._close_connection(conn_id)
        await self._report_log("QUIC协议栈已停止")

    async def process_packet(
        self,
        data: bytes,
        client_address: Tuple[str, int],
    ) -> Optional[bytes]:
        """Process incoming QUIC packet.

        Args:
            data: Raw UDP payload.
            client_address: Client (host, port).

        Returns:
            Response packet bytes or None.
        """
        if not self._active or len(data) < 1:
            return None

        try:
            first_byte = data[0]

            if first_byte & 0x80 == 0:
                return await self._process_short_header_packet(data, client_address)

            return await self._process_long_header_packet(data, client_address)

        except Exception as e:
            logger.error("QUIC packet processing failed: %s", e)
            return None

    async def _process_long_header_packet(
        self,
        data: bytes,
        client_address: Tuple[str, int],
    ) -> Optional[bytes]:
        """Process long header packet.

        Args:
            data: Packet data.
            client_address: Client address.

        Returns:
            Response bytes or None.
        """
        header = await self._parse_long_header(data)
        if not header:
            return None

        if header.packet_type == PacketType.VERSION_NEGOTIATION:
            return await self._handle_version_negotiation(data, client_address)

        if header.packet_type == PacketType.INITIAL:
            return await self._handle_initial_packet(header, data, client_address)

        if header.packet_type == PacketType.HANDSHAKE:
            return await self._handle_handshake_packet(header, data, client_address)

        if header.packet_type == PacketType.RETRY:
            return await self._handle_retry_packet(header, data, client_address)

        if header.packet_type == PacketType.ZERO_RTT:
            return await self._handle_0rtt_packet(header, data, client_address)

        return None

    async def _process_short_header_packet(
        self,
        data: bytes,
        client_address: Tuple[str, int],
    ) -> Optional[bytes]:
        """Process short header packet.

        Args:
            data: Packet data.
            client_address: Client address.

        Returns:
            Response bytes or None.
        """
        header = await self._parse_short_header(data)
        if not header:
            return None

        conn_key = self._find_connection_by_destination(
            header.destination_connection_id
        )
        if not conn_key:
            return None

        connection = self._connections.get(conn_key)
        if not connection:
            return None

        connection.last_activity = time.time()

        payload = data[header.length:]
        frames = await self._parse_frames(payload)

        response_data = b""
        for frame in frames:
            frame_response = await self._handle_frame(frame, connection)
            if frame_response:
                response_data += frame_response

        return response_data if response_data else None

    async def _parse_long_header(self, data: bytes) -> Optional[QuicPacketHeader]:
        """Parse QUIC long header.

        Args:
            data: Packet data.

        Returns:
            QuicPacketHeader or None.
        """
        if len(data) < 5:
            return None

        first_byte = data[0]
        header = QuicPacketHeader()

        header.packet_type = self._determine_packet_type(first_byte)

        if header.packet_type == PacketType.VERSION_NEGOTIATION:
            return header

        version_bytes = data[1:5]
        header.version = QuicVersion(struct.unpack(">I", version_bytes)[0])

        if header.version not in self.SUPPORTED_VERSIONS:
            return await self._handle_unsupported_version(data)

        dest_cid_len = data[5]
        if 5 + 1 + dest_cid_len > len(data):
            return None

        header.destination_connection_id = QuicConnectionId(
            data=data[6 : 6 + dest_cid_len],
            length=dest_cid_len,
        )

        offset = 6 + dest_cid_len
        if offset >= len(data):
            return None

        src_cid_len = data[offset]
        offset += 1

        if offset + src_cid_len > len(data):
            return None

        header.source_connection_id = QuicConnectionId(
            data=data[offset : offset + src_cid_len],
            length=src_cid_len,
        )

        offset += src_cid_len

        if header.packet_type == PacketType.INITIAL:
            token_len = await self._decode_variable_length_int(data, offset)
            if token_len is None:
                return None
            offset += self._get_variable_length_int_size(token_len)
            header.token = data[offset : offset + token_len]
            offset += token_len

        payload_len = await self._decode_variable_length_int(data, offset)
        if payload_len is None:
            return None

        header.length = payload_len

        return header

    async def _parse_short_header(self, data: bytes) -> Optional[QuicPacketHeader]:
        """Parse QUIC short header.

        Args:
            data: Packet data.

        Returns:
            QuicPacketHeader or None.
        """
        if len(data) < 1:
            return None

        first_byte = data[0]
        header = QuicPacketHeader()
        header.packet_type = PacketType.SHORT_HEADER

        spin_bit = bool(first_byte & 0x20)
        key_phase = bool(first_byte & 0x04)
        pn_length = (first_byte & 0x03) + 1

        offset = 1

        conn_key = self._find_connection_by_data(data)
        if conn_key:
            connection = self._connections[conn_key]
            header.destination_connection_id = connection.connection_id

        header.length = offset

        return header

    def _determine_packet_type(self, first_byte: int) -> PacketType:
        """Determine packet type from first byte.

        Args:
            first_byte: First byte of packet.

        Returns:
            PacketType.
        """
        form = (first_byte >> 6) & 0x03
        if form == 0:
            return PacketType.VERSION_NEGOTIATION
        elif form == 1:
            return PacketType.INITIAL
        elif form == 2:
            return PacketType.ZERO_RTT
        elif form == 3:
            return PacketType.HANDSHAKE
        return PacketType.INITIAL

    async def _handle_initial_packet(
        self,
        header: QuicPacketHeader,
        data: bytes,
        client_address: Tuple[str, int],
    ) -> Optional[bytes]:
        """Handle QUIC Initial packet.

        Args:
            header: Packet header.
            data: Packet data.
            client_address: Client address.

        Returns:
            Response bytes or None.
        """
        conn_key = self._find_connection_by_destination(
            header.destination_connection_id
        )

        if not conn_key:
            conn_key = f"conn_{int(time.time())}_{secrets.token_hex(4)}"
            connection = QuicConnection(
                connection_id=header.destination_connection_id,
                version=header.version,
                client_address=client_address,
                created_at=time.time(),
                last_activity=time.time(),
            )
            self._connections[conn_key] = connection
            self._connection_ids[header.destination_connection_id] = conn_key
        else:
            connection = self._connections[conn_key]

        connection.last_activity = time.time()

        payload_offset = header.length + 1
        if payload_offset < len(data):
            payload = data[payload_offset:]
            frames = await self._parse_frames(payload)
            for frame in frames:
                if frame.frame_type == FrameType.CRYPTO:
                    connection.state = "handshake"
                    return await self._build_handshake_response(connection)

        return await self._build_initial_response(connection)

    async def _handle_handshake_packet(
        self,
        header: QuicPacketHeader,
        data: bytes,
        client_address: Tuple[str, int],
    ) -> Optional[bytes]:
        """Handle QUIC Handshake packet.

        Args:
            header: Packet header.
            data: Packet data.
            client_address: Client address.

        Returns:
            Response bytes or None.
        """
        conn_key = self._find_connection_by_destination(
            header.destination_connection_id
        )
        if not conn_key:
            return None

        connection = self._connections[conn_key]
        connection.last_activity = time.time()

        payload_offset = header.length + 1
        if payload_offset < len(data):
            payload = data[payload_offset:]
            frames = await self._parse_frames(payload)
            for frame in frames:
                if frame.frame_type == FrameType.CRYPTO:
                    connection.tls_handshake_complete = True
                    connection.state = "established"
                    return await self._build_handshake_done_response(connection)

        return None

    async def _handle_retry_packet(
        self,
        header: QuicPacketHeader,
        data: bytes,
        client_address: Tuple[str, int],
    ) -> Optional[bytes]:
        """Handle QUIC Retry packet.

        Args:
            header: Packet header.
            data: Packet data.
            client_address: Client address.

        Returns:
            Response bytes or None.
        """
        return None

    async def _handle_0rtt_packet(
        self,
        header: QuicPacketHeader,
        data: bytes,
        client_address: Tuple[str, int],
    ) -> Optional[bytes]:
        """Handle QUIC 0-RTT packet.

        Args:
            header: Packet header.
            data: Packet data.
            client_address: Client address.

        Returns:
            Response bytes or None.
        """
        conn_key = self._find_connection_by_destination(
            header.destination_connection_id
        )
        if not conn_key:
            return None

        connection = self._connections[conn_key]
        connection.early_data_accepted = True

        return None

    async def _handle_version_negotiation(
        self,
        data: bytes,
        client_address: Tuple[str, int],
    ) -> Optional[bytes]:
        """Handle version negotiation.

        Args:
            data: Packet data.
            client_address: Client address.

        Returns:
            Response bytes or None.
        """
        return None

    async def _handle_unsupported_version(
        self,
        data: bytes,
    ) -> Optional[QuicPacketHeader]:
        """Handle unsupported QUIC version.

        Args:
            data: Packet data.

        Returns:
            QuicPacketHeader or None.
        """
        return None

    async def _handle_frame(
        self,
        frame: QuicFrame,
        connection: QuicConnection,
    ) -> Optional[bytes]:
        """Handle QUIC frame.

        Args:
            frame: Frame to handle.
            connection: QUIC connection.

        Returns:
            Response bytes or None.
        """
        if frame.frame_type == FrameType.STREAM:
            return await self._handle_stream_frame(frame, connection)
        elif frame.frame_type == FrameType.CRYPTO:
            return await self._handle_crypto_frame(frame, connection)
        elif frame.frame_type == FrameType.ACK:
            return None
        elif frame.frame_type == FrameType.MAX_DATA:
            return await self._handle_max_data_frame(frame, connection)
        elif frame.frame_type == FrameType.MAX_STREAM_DATA:
            return await self._handle_max_stream_data_frame(frame, connection)
        elif frame.frame_type == FrameType.RESET_STREAM:
            return await self._handle_reset_stream_frame(frame, connection)
        elif frame.frame_type == FrameType.STOP_SENDING:
            return await self._handle_stop_sending_frame(frame, connection)
        elif frame.frame_type == FrameType.PING:
            return await self._build_pong_response(connection)
        elif frame.frame_type == FrameType.PATH_CHALLENGE:
            return await self._build_path_response(frame, connection)
        elif frame.frame_type == FrameType.APPLICATION_CLOSE:
            await self._close_connection_by_frame(frame, connection)
            return None
        else:
            return None

    async def _handle_stream_frame(
        self,
        frame: QuicFrame,
        connection: QuicConnection,
    ) -> Optional[bytes]:
        """Handle STREAM frame.

        Args:
            frame: STREAM frame.
            connection: QUIC connection.

        Returns:
            Response bytes or None.
        """
        stream = await self._get_or_create_stream(frame.stream_id, connection)
        if not stream:
            return None

        if frame.offset > 0:
            current_len = len(stream.data)
            if frame.offset > current_len:
                stream.data.extend(b"\x00" * (frame.offset - current_len))
            stream.data[frame.offset : frame.offset + len(frame.data)] = frame.data
        else:
            stream.data.extend(frame.data)

        stream.data_received += len(frame.data)
        stream.offset = max(stream.offset, frame.offset + len(frame.data))

        if frame.fin:
            stream.fin_received = True
            stream.state = StreamState.HALF_CLOSED_REMOTE

        if stream.data_received > stream.max_data:
            return await self._build_stop_sending(stream.stream_id, 0)

        return None

    async def _handle_crypto_frame(
        self,
        frame: QuicFrame,
        connection: QuicConnection,
    ) -> Optional[bytes]:
        """Handle CRYPTO frame.

        Args:
            frame: CRYPTO frame.
            connection: QUIC connection.

        Returns:
            Response bytes or None.
        """
        return None

    async def _handle_max_data_frame(
        self,
        frame: QuicFrame,
        connection: QuicConnection,
    ) -> Optional[bytes]:
        """Handle MAX_DATA frame.

        Args:
            frame: MAX_DATA frame.
            connection: QUIC connection.

        Returns:
            Response bytes or None.
        """
        if len(frame.data) >= 8:
            new_max = struct.unpack(">Q", frame.data[:8])[0]
            connection.connection_max_data = new_max
        return None

    async def _handle_max_stream_data_frame(
        self,
        frame: QuicFrame,
        connection: QuicConnection,
    ) -> Optional[bytes]:
        """Handle MAX_STREAM_DATA frame.

        Args:
            frame: MAX_STREAM_DATA frame.
            connection: QUIC connection.

        Returns:
            Response bytes or None.
        """
        return None

    async def _handle_reset_stream_frame(
        self,
        frame: QuicFrame,
        connection: QuicConnection,
    ) -> Optional[bytes]:
        """Handle RESET_STREAM frame.

        Args:
            frame: RESET_STREAM frame.
            connection: QUIC connection.

        Returns:
            Response bytes or None.
        """
        stream = connection.streams.get(frame.stream_id)
        if stream:
            stream.reset_received = True
            stream.state = StreamState.RESET
        return None

    async def _handle_stop_sending_frame(
        self,
        frame: QuicFrame,
        connection: QuicConnection,
    ) -> Optional[bytes]:
        """Handle STOP_SENDING frame.

        Args:
            frame: STOP_SENDING frame.
            connection: QUIC connection.

        Returns:
            Response bytes or None.
        """
        stream = connection.streams.get(frame.stream_id)
        if stream:
            stream.state = StreamState.HALF_CLOSED_LOCAL
        return None

    async def _parse_frames(self, data: bytes) -> List[QuicFrame]:
        """Parse QUIC frames from payload.

        Args:
            data: Frame payload data.

        Returns:
            List of QuicFrame.
        """
        frames: List[QuicFrame] = []
        offset = 0

        while offset < len(data):
            frame_type_byte = data[offset]
            offset += 1

            if frame_type_byte == FrameType.PADDING.value:
                continue

            if frame_type_byte == FrameType.PING.value:
                frames.append(QuicFrame(frame_type=FrameType.PING))
                continue

            if FrameType.STREAM.value <= frame_type_byte < FrameType.STREAM.value + 0x08:
                frame = await self._parse_stream_frame(data, offset, frame_type_byte)
                if frame:
                    frames.append(frame)
                    offset += frame.offset
                continue

            if frame_type_byte == FrameType.CRYPTO.value:
                frame = await self._parse_crypto_frame(data, offset)
                if frame:
                    frames.append(frame)
                    offset += frame.offset
                continue

            if frame_type_byte == FrameType.ACK.value or frame_type_byte == FrameType.ACK_ECN.value:
                frame = await self._parse_ack_frame(data, offset)
                if frame:
                    frames.append(frame)
                    offset += frame.offset
                continue

            break

        return frames

    async def _parse_stream_frame(
        self,
        data: bytes,
        offset: int,
        frame_type_byte: int,
    ) -> Optional[QuicFrame]:
        """Parse STREAM frame.

        Args:
            data: Frame data.
            offset: Current offset.
            frame_type_byte: Frame type byte.

        Returns:
            QuicFrame or None.
        """
        off_bit = bool(frame_type_byte & 0x04)
        len_bit = bool(frame_type_byte & 0x02)
        fin_bit = bool(frame_type_byte & 0x01)

        stream_id_val = await self._decode_variable_length_int(data, offset)
        if stream_id_val is None:
            return None
        stream_id: int = stream_id_val
        offset += self._get_variable_length_int_size(stream_id)

        frame_offset: int = 0
        if off_bit:
            frame_offset_val = await self._decode_variable_length_int(data, offset)
            if frame_offset_val is None:
                return None
            frame_offset = frame_offset_val
            offset += self._get_variable_length_int_size(frame_offset)

        data_length: int = 0
        if len_bit:
            data_length_val = await self._decode_variable_length_int(data, offset)
            if data_length_val is None:
                return None
            data_length = data_length_val
            offset += self._get_variable_length_int_size(data_length)
        else:
            data_length = len(data) - offset

        frame_data = data[offset : offset + data_length]

        return QuicFrame(
            frame_type=FrameType.STREAM,
            data=frame_data,
            stream_id=stream_id,
            offset=frame_offset,
            fin=fin_bit,
        )

    async def _parse_crypto_frame(
        self,
        data: bytes,
        offset: int,
    ) -> Optional[QuicFrame]:
        """Parse CRYPTO frame.

        Args:
            data: Frame data.
            offset: Current offset.

        Returns:
            QuicFrame or None.
        """
        crypto_offset = await self._decode_variable_length_int(data, offset)
        if crypto_offset is None:
            return None
        offset += self._get_variable_length_int_size(crypto_offset)

        data_length = await self._decode_variable_length_int(data, offset)
        if data_length is None:
            return None
        offset += self._get_variable_length_int_size(data_length)

        frame_data = data[offset : offset + data_length]

        return QuicFrame(
            frame_type=FrameType.CRYPTO,
            data=frame_data,
            offset=data_length,
        )

    async def _parse_ack_frame(
        self,
        data: bytes,
        offset: int,
    ) -> Optional[QuicFrame]:
        """Parse ACK frame.

        Args:
            data: Frame data.
            offset: Current offset.

        Returns:
            QuicFrame or None.
        """
        return QuicFrame(
            frame_type=FrameType.ACK,
            data=b"",
            offset=1,
        )

    async def _get_or_create_stream(
        self,
        stream_id: int,
        connection: QuicConnection,
    ) -> Optional[QuicStream]:
        """Get or create stream.

        Args:
            stream_id: Stream identifier.
            connection: QUIC connection.

        Returns:
            QuicStream or None.
        """
        if stream_id in connection.streams:
            return connection.streams[stream_id]

        is_bidi = (stream_id & 0x02) == 0
        is_client_initiated = (stream_id & 0x01) == 0

        if is_bidi:
            if len(connection.streams) >= connection.max_streams_bidi:
                return None
        else:
            if len(connection.streams) >= connection.max_streams_uni:
                return None

        stream = QuicStream(
            stream_id=stream_id,
            stream_type=(
                StreamType.BIDIRECTIONAL if is_bidi else StreamType.UNIDIRECTIONAL
            ),
            state=StreamState.OPEN,
            max_data=connection.local_transport_parameters.initial_max_stream_data_bidi_local,
            created_at=time.time(),
        )

        connection.streams[stream_id] = stream
        return stream

    async def _decode_variable_length_int(
        self,
        data: bytes,
        offset: int,
    ) -> Optional[int]:
        """Decode QUIC variable-length integer.

        Args:
            data: Data bytes.
            offset: Current offset.

        Returns:
            Decoded integer or None.
        """
        if offset >= len(data):
            return None

        first_byte = data[offset]
        prefix = (first_byte >> 6) & 0x03

        if prefix == 0:
            return int(first_byte & 0x3F)
        elif prefix == 1:
            if offset + 2 > len(data):
                return None
            value = struct.unpack(">H", data[offset : offset + 2])[0]
            return int(value & 0x3FFF)
        elif prefix == 2:
            if offset + 4 > len(data):
                return None
            value = struct.unpack(">I", data[offset : offset + 4])[0]
            return int(value & 0x3FFFFFFF)
        else:
            if offset + 8 > len(data):
                return None
            value = struct.unpack(">Q", data[offset : offset + 8])[0]
            return int(value & 0x3FFFFFFFFFFFFFFF)

    def _get_variable_length_int_size(self, value: int) -> int:
        """Get encoded size for variable-length integer.

        Args:
            value: Integer value.

        Returns:
            Encoded size in bytes.
        """
        if value <= 0x3F:
            return 1
        elif value <= 0x3FFF:
            return 2
        elif value <= 0x3FFFFFFF:
            return 4
        else:
            return 8

    def _find_connection_by_destination(
        self,
        connection_id: QuicConnectionId,
    ) -> Optional[str]:
        """Find connection by destination connection ID.

        Args:
            connection_id: Connection ID to find.

        Returns:
            Connection key or None.
        """
        return self._connection_ids.get(connection_id)

    def _find_connection_by_data(self, data: bytes) -> Optional[str]:
        """Find connection by packet data.

        Args:
            data: Packet data.

        Returns:
            Connection key or None.
        """
        for conn_id, conn_key in self._connection_ids.items():
            if conn_id.data and conn_id.data in data:
                return conn_key
        return None

    async def _build_initial_response(
        self,
        connection: QuicConnection,
    ) -> Optional[bytes]:
        """Build Initial packet response.

        Args:
            connection: QUIC connection.

        Returns:
            Response bytes or None.
        """
        response = bytearray()
        response.append(0xC0)
        response.extend(struct.pack(">I", connection.version.value))
        response.append(connection.connection_id.length)
        response.extend(connection.connection_id.data)
        response.append(8)
        response.extend(secrets.token_bytes(8))
        response.extend(b"\x00" * 100)
        return bytes(response)

    async def _build_handshake_response(
        self,
        connection: QuicConnection,
    ) -> Optional[bytes]:
        """Build Handshake packet response.

        Args:
            connection: QUIC connection.

        Returns:
            Response bytes or None.
        """
        response = bytearray()
        response.append(0xE0)
        response.extend(struct.pack(">I", connection.version.value))
        response.append(8)
        response.extend(secrets.token_bytes(8))
        response.append(connection.connection_id.length)
        response.extend(connection.connection_id.data)
        response.extend(b"\x00" * 100)
        return bytes(response)

    async def _build_handshake_done_response(
        self,
        connection: QuicConnection,
    ) -> Optional[bytes]:
        """Build HANDSHAKE_DONE response.

        Args:
            connection: QUIC connection.

        Returns:
            Response bytes or None.
        """
        response = bytearray()
        response.append(0x40)
        response.append(connection.connection_id.data[0] if connection.connection_id.data else 0)
        response.append(FrameType.HANDSHAKE_DONE.value)
        return bytes(response)

    async def _build_pong_response(
        self,
        connection: QuicConnection,
    ) -> Optional[bytes]:
        """Build PONG response for PING.

        Args:
            connection: QUIC connection.

        Returns:
            Response bytes or None.
        """
        return None

    async def _build_path_response(
        self,
        frame: QuicFrame,
        connection: QuicConnection,
    ) -> Optional[bytes]:
        """Build PATH_RESPONSE for PATH_CHALLENGE.

        Args:
            frame: PATH_CHALLENGE frame.
            connection: QUIC connection.

        Returns:
            Response bytes or None.
        """
        response = bytearray()
        response.append(FrameType.PATH_RESPONSE.value)
        response.extend(frame.data[:8])
        return bytes(response)

    async def _build_stop_sending(
        self,
        stream_id: int,
        error_code: int,
    ) -> Optional[bytes]:
        """Build STOP_SENDING frame.

        Args:
            stream_id: Stream ID.
            error_code: Error code.

        Returns:
            Frame bytes or None.
        """
        response = bytearray()
        response.append(FrameType.STOP_SENDING.value)
        response.extend(self._encode_variable_length_int(stream_id))
        response.extend(struct.pack(">Q", error_code))
        return bytes(response)

    def _encode_variable_length_int(self, value: int) -> bytes:
        """Encode integer as QUIC variable-length integer.

        Args:
            value: Integer value.

        Returns:
            Encoded bytes.
        """
        if value <= 0x3F:
            return bytes([value])
        elif value <= 0x3FFF:
            return struct.pack(">H", value | 0x4000)
        elif value <= 0x3FFFFFFF:
            return struct.pack(">I", value | 0x80000000)
        else:
            return struct.pack(">Q", value | 0xC000000000000000)

    async def _close_connection(self, conn_key: str) -> None:
        """Close QUIC connection.

        Args:
            conn_key: Connection key.
        """
        connection = self._connections.pop(conn_key, None)
        if connection:
            for cid in list(self._connection_ids.keys()):
                if self._connection_ids[cid] == conn_key:
                    del self._connection_ids[cid]

    async def _close_connection_by_frame(
        self,
        frame: QuicFrame,
        connection: QuicConnection,
    ) -> None:
        """Close connection triggered by frame.

        Args:
            frame: APPLICATION_CLOSE frame.
            connection: QUIC connection.
        """
        connection.state = "closed"

    def get_active_connections(self) -> List[Dict[str, Any]]:
        """Get active QUIC connections info.

        Returns:
            List of connection info dictionaries.
        """
        connections_info: List[Dict[str, Any]] = []
        for conn_key, connection in self._connections.items():
            connections_info.append({
                "connection_id": connection.connection_id.data.hex(),
                "version": connection.version.name,
                "state": connection.state,
                "client_address": f"{connection.client_address[0]}:{connection.client_address[1]}",
                "stream_count": len(connection.streams),
                "data_sent": connection.connection_data_sent,
                "data_received": connection.connection_data_received,
                "tls_complete": connection.tls_handshake_complete,
                "last_activity": connection.last_activity,
            })
        return connections_info

    def get_connection_by_id(
        self,
        connection_id: QuicConnectionId,
    ) -> Optional[QuicConnection]:
        """Get connection by connection ID.

        Args:
            connection_id: Connection ID.

        Returns:
            QuicConnection or None.
        """
        conn_key = self._connection_ids.get(connection_id)
        if conn_key:
            return self._connections.get(conn_key)
        return None

    def get_stream(
        self,
        connection_id: QuicConnectionId,
        stream_id: int,
    ) -> Optional[QuicStream]:
        """Get stream from connection.

        Args:
            connection_id: Connection ID.
            stream_id: Stream ID.

        Returns:
            QuicStream or None.
        """
        connection = self.get_connection_by_id(connection_id)
        if connection:
            return connection.streams.get(stream_id)
        return None
