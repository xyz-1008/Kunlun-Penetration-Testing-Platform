"""HTTP/3 frame processing and QPACK header compression.

Provides:
- HTTP/3 frame type parsing (HEADERS, DATA, SETTINGS, etc.)
- QPACK encoder and decoder implementation
- Dynamic table management
- Pseudo-header to standard HTTP conversion
- Stream processing for HTTP/3
"""

import asyncio
import logging
import struct
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Callable, Coroutine, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class Http3FrameType(IntEnum):
    """HTTP/3 frame types per RFC 9114."""
    DATA = 0x00
    HEADERS = 0x01
    PRIORITY = 0x02
    CANCEL_PUSH = 0x03
    SETTINGS = 0x04
    PUSH_PROMISE = 0x05
    GOAWAY = 0x07
    MAX_PUSH_ID = 0x0D
    DUPLICATE_PUSH = 0x0E
    ORIGIN = 0x40


class QpackInstructionType(IntEnum):
    """QPACK instruction types."""
    INDEXED = 0x80
    INDEXED_WITH_POST_BASE = 0x10
    LITERAL_WITH_NAME_REF = 0x40
    LITERAL_WITH_POST_BASE_NAME_REF = 0x08
    LITERAL_WITH_NAME = 0x20
    LITERAL_WITH_POST_BASE_NAME = 0x00
    SET_DYNAMIC_TABLE_CAPACITY = 0x20
    INSERT_WITH_NAME_REF = 0x40
    INSERT_WITHOUT_NAME_REF = 0x00
    DUPLICATE = 0x00


class Http3SettingsId(IntEnum):
    """HTTP/3 settings identifiers."""
    QPACK_MAX_TABLE_CAPACITY = 0x01
    MAX_FIELD_SECTION_SIZE = 0x06
    QPACK_BLOCKED_STREAMS = 0x07
    ENABLE_CONNECT_PROTOCOL = 0x08


class HttpStreamType(IntEnum):
    """HTTP/3 stream types."""
    CONTROL = 0x00
    PUSH = 0x01
    QPACK_ENCODER = 0x02
    QPACK_DECODER = 0x03


@dataclass
class Http3Frame:
    """HTTP/3 frame.

    Attributes:
        frame_type: Frame type
        payload: Frame payload data
        stream_id: Stream ID
        length: Payload length
    """
    frame_type: Http3FrameType = Http3FrameType.DATA
    payload: bytes = b""
    stream_id: int = 0
    length: int = 0


@dataclass
class Http3Header:
    """HTTP/3 headers.

    Attributes:
        pseudo_headers: Pseudo headers (method, path, etc.)
        regular_headers: Regular headers
        encoded_headers: QPACK encoded headers
        stream_id: Stream ID
    """
    pseudo_headers: Dict[str, str] = field(default_factory=dict)
    regular_headers: Dict[str, str] = field(default_factory=dict)
    encoded_headers: bytes = b""
    stream_id: int = 0


@dataclass
class Http3Request:
    """Standardized HTTP/3 request.

    Attributes:
        method: HTTP method
        path: Request path
        authority: Request authority
        scheme: Request scheme
        headers: All headers
        body: Request body
        stream_id: Stream ID
        raw_headers: Raw HTTP/3 headers
    """
    method: str = "GET"
    path: str = "/"
    authority: str = ""
    scheme: str = "https"
    headers: Dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    stream_id: int = 0
    raw_headers: Dict[str, str] = field(default_factory=dict)


@dataclass
class Http3Response:
    """Standardized HTTP/3 response.

    Attributes:
        status_code: HTTP status code
        headers: Response headers
        body: Response body
        stream_id: Stream ID
        raw_headers: Raw HTTP/3 headers
    """
    status_code: int = 200
    headers: Dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    stream_id: int = 0
    raw_headers: Dict[str, str] = field(default_factory=dict)


@dataclass
class QpackDynamicTableEntry:
    """QPACK dynamic table entry.

    Attributes:
        name: Header name
        value: Header value
        index: Table index
    """
    name: str = ""
    value: str = ""
    index: int = 0


@dataclass
class Http3Settings:
    """HTTP/3 settings.

    Attributes:
        qpack_max_table_capacity: QPACK max dynamic table capacity
        max_field_section_size: Maximum header list size
        qpack_blocked_streams: Maximum blocked streams
        enable_connect_protocol: CONNECT protocol enabled
        custom_settings: Custom settings
    """
    qpack_max_table_capacity: int = 0
    max_field_section_size: int = 65536
    qpack_blocked_streams: int = 0
    enable_connect_protocol: int = 0
    custom_settings: Dict[int, int] = field(default_factory=dict)


class QpackStaticTable:
    """QPACK static table per RFC 9204."""

    STATIC_TABLE: List[Tuple[str, str]] = [
        (":authority", ""),
        (":path", "/"),
        ("age", "0"),
        ("content-disposition", ""),
        ("content-length", "0"),
        ("cookie", ""),
        ("date", ""),
        ("etag", ""),
        ("if-modified-since", ""),
        ("if-none-match", ""),
        ("last-modified", ""),
        ("link", ""),
        ("location", ""),
        ("referer", ""),
        ("set-cookie", ""),
        (":method", "CONNECT"),
        (":method", "DELETE"),
        (":method", "GET"),
        (":method", "HEAD"),
        (":method", "OPTIONS"),
        (":method", "POST"),
        (":method", "PUT"),
        (":scheme", "http"),
        (":scheme", "https"),
        (":status", "103"),
        (":status", "200"),
        (":status", "304"),
        (":status", "404"),
        (":status", "503"),
        ("accept", "*/*"),
        ("accept", "application/dns-message"),
        ("accept-encoding", "gzip, deflate, br"),
        ("accept-ranges", "bytes"),
        ("access-control-allow-headers", "cache-control"),
        ("access-control-allow-headers", "content-type"),
        ("access-control-allow-origin", "*"),
        ("cache-control", "max-age=0"),
        ("cache-control", "max-age=2592000"),
        ("cache-control", "max-age=604800"),
        ("cache-control", "no-cache"),
        ("cache-control", "no-store"),
        ("cache-control", "public, max-age=31536000"),
        ("content-encoding", "gzip"),
        ("content-type", "application/dns-message"),
        ("content-type", "application/javascript"),
        ("content-type", "application/json"),
        ("content-type", "application/x-www-form-urlencoded"),
        ("content-type", "image/gif"),
        ("content-type", "image/jpeg"),
        ("content-type", "image/png"),
        ("content-type", "text/css"),
        ("content-type", "text/html; charset=utf-8"),
        ("content-type", "text/plain"),
        ("content-type", "text/plain;charset=utf-8"),
        ("range", "bytes=0-"),
        ("strict-transport-security", "max-age=31536000"),
        ("strict-transport-security", "max-age=31536000; includesubdomains"),
        ("strict-transport-security", "max-age=31536000; includesubdomains; preload"),
        ("vary", "accept-encoding"),
        ("vary", "origin"),
        ("x-content-type-options", "nosniff"),
        ("x-xss-protection", "1; mode=block"),
        (":status", "100"),
        (":status", "204"),
        (":status", "206"),
        (":status", "302"),
        (":status", "400"),
        (":status", "403"),
        (":status", "421"),
        (":status", "425"),
        (":status", "500"),
        ("accept-language", ""),
        ("access-control-allow-headers", "*"),
        ("access-control-allow-methods", "get"),
        ("access-control-allow-methods", "get, post, options"),
        ("access-control-allow-methods", "options"),
        ("access-control-expose-headers", "content-length"),
        ("access-control-request-headers", "content-type"),
        ("alt-svc", "clear"),
        ("authorization", ""),
        ("content-security-policy", "script-src 'none'; object-src 'none'; base-uri 'none'"),
        ("early-data", "1"),
        ("expect-ct", ""),
        ("forwarded", ""),
        ("if-range", ""),
        ("origin", ""),
        ("purpose", "prefetch"),
        ("server", ""),
        ("timing-allow-origin", "*"),
        ("upgrade-insecure-requests", "1"),
        ("user-agent", ""),
        ("x-forwarded-for", ""),
        ("x-frame-options", "deny"),
        ("x-frame-options", "sameorigin"),
    ]

    @classmethod
    def get_entry(cls, index: int) -> Optional[Tuple[str, str]]:
        """Get static table entry by index.

        Args:
            index: Static table index.

        Returns:
            Tuple of (name, value) or None.
        """
        if 0 <= index < len(cls.STATIC_TABLE):
            return cls.STATIC_TABLE[index]
        return None

    @classmethod
    def find_index(cls, name: str, value: str = "") -> int:
        """Find static table index for header.

        Args:
            name: Header name.
            value: Header value.

        Returns:
            Static table index or -1.
        """
        for i, (n, v) in enumerate(cls.STATIC_TABLE):
            if n == name and (value == "" or v == value):
                return i
        return -1


class QpackEncoderDecoder:
    """QPACK encoder and decoder implementation.

    Provides QPACK header compression and decompression
    with dynamic table management.
    """

    MAX_DYNAMIC_TABLE_SIZE: int = 4096
    DEFAULT_DYNAMIC_TABLE_SIZE: int = 0

    def __init__(self) -> None:
        """Initialize QPACK encoder/decoder."""
        self._dynamic_table: List[QpackDynamicTableEntry] = []
        self._max_table_capacity: int = self.DEFAULT_DYNAMIC_TABLE_SIZE
        self._current_table_size: int = 0
        self._insert_count: int = 0
        self._dropped_count: int = 0
        self._blocked_streams: int = 0
        self._max_blocked_streams: int = 0

    def set_max_table_capacity(self, capacity: int) -> None:
        """Set maximum dynamic table capacity.

        Args:
            capacity: Maximum table capacity in bytes.
        """
        self._max_table_capacity = min(capacity, self.MAX_DYNAMIC_TABLE_SIZE)
        if self._current_table_size > self._max_table_capacity:
            self._evict_entries()

    def set_max_blocked_streams(self, max_blocked: int) -> None:
        """Set maximum blocked streams.

        Args:
            max_blocked: Maximum blocked streams.
        """
        self._max_blocked_streams = max_blocked

    async def encode_headers(
        self,
        headers: Dict[str, str],
        is_request: bool = True,
    ) -> bytes:
        """Encode headers using QPACK.

        Args:
            headers: Headers to encode.
            is_request: Whether this is a request.

        Returns:
            QPACK encoded bytes.
        """
        encoded = bytearray()

        for name, value in headers.items():
            name_lower = name.lower()

            static_index = QpackStaticTable.find_index(name_lower, value)
            if static_index >= 0:
                encoded.append(0x80 | static_index)
                continue

            dynamic_index = await self._find_dynamic_index(name_lower, value)
            if dynamic_index >= 0:
                encoded.append(0x80 | (dynamic_index + len(QpackStaticTable.STATIC_TABLE)))
                continue

            name_static_index = QpackStaticTable.find_index(name_lower)
            if name_static_index >= 0:
                encoded.append(0x40 | name_static_index)
                encoded.extend(await self._encode_string(value))
                await self._add_to_dynamic_table(name_lower, value)
                continue

            encoded.append(0x20)
            encoded.extend(await self._encode_string(name_lower))
            encoded.extend(await self._encode_string(value))
            await self._add_to_dynamic_table(name_lower, value)

        return bytes(encoded)

    async def decode_headers(self, encoded: bytes) -> Dict[str, str]:
        """Decode QPACK encoded headers.

        Args:
            encoded: QPACK encoded bytes.

        Returns:
            Decoded headers dictionary.
        """
        headers: Dict[str, str] = {}
        offset = 0

        while offset < len(encoded):
            first_byte = encoded[offset]

            if first_byte & 0x80:
                index = first_byte & 0x7F
                offset += 1

                if index < len(QpackStaticTable.STATIC_TABLE):
                    static_entry = QpackStaticTable.get_entry(index)
                    if static_entry:
                        headers[static_entry[0]] = static_entry[1]
                else:
                    dynamic_index = index - len(QpackStaticTable.STATIC_TABLE)
                    dynamic_entry = await self._get_dynamic_entry(dynamic_index)
                    if dynamic_entry:
                        headers[dynamic_entry.name] = dynamic_entry.value

            elif first_byte & 0x40:
                name_index = first_byte & 0x3F
                offset += 1

                if name_index < len(QpackStaticTable.STATIC_TABLE):
                    name = QpackStaticTable.STATIC_TABLE[name_index][0]
                else:
                    dynamic_index = name_index - len(QpackStaticTable.STATIC_TABLE)
                    dynamic_entry = await self._get_dynamic_entry(dynamic_index)
                    name = dynamic_entry.name if dynamic_entry else ""

                value, value_len = await self._decode_string(encoded, offset)
                offset += value_len
                headers[name] = value

                await self._add_to_dynamic_table(name, value)

            elif first_byte & 0x20:
                offset += 1

                name, name_len = await self._decode_string(encoded, offset)
                offset += name_len

                value, value_len = await self._decode_string(encoded, offset)
                offset += value_len

                headers[name] = value

                await self._add_to_dynamic_table(name, value)

            else:
                offset += 1

        return headers

    async def _encode_string(self, value: str) -> bytes:
        """Encode string with length prefix.

        Args:
            value: String to encode.

        Returns:
            Encoded bytes.
        """
        data = value.encode("utf-8")
        length = len(data)

        if length <= 127:
            return bytes([length]) + data
        elif length <= 16383:
            return struct.pack(">H", length | 0x8000) + data
        else:
            return struct.pack(">I", length | 0xC0000000) + data

    async def _decode_string(
        self,
        data: bytes,
        offset: int,
    ) -> Tuple[str, int]:
        """Decode string with length prefix.

        Args:
            data: Data bytes.
            offset: Current offset.

        Returns:
            Tuple of (decoded string, bytes consumed).
        """
        if offset >= len(data):
            return "", 0

        first_byte = data[offset]

        if first_byte & 0x80:
            if offset + 2 > len(data):
                return "", 0
            length = struct.unpack(">H", data[offset : offset + 2])[0] & 0x7FFF
            offset += 2
        elif first_byte & 0x40:
            if offset + 4 > len(data):
                return "", 0
            length = struct.unpack(">I", data[offset : offset + 4])[0] & 0x3FFFFFFF
            offset += 4
        else:
            length = first_byte & 0x7F
            offset += 1

        if offset + length > len(data):
            return "", 0

        value = data[offset : offset + length].decode("utf-8", errors="replace")
        return value, length + (offset - (offset - length - (2 if length <= 127 else 4 if length <= 16383 else 4)))

    async def _add_to_dynamic_table(self, name: str, value: str) -> None:
        """Add entry to dynamic table.

        Args:
            name: Header name.
            value: Header value.
        """
        entry_size = len(name) + len(value) + 32

        if entry_size > self._max_table_capacity:
            return

        while self._current_table_size + entry_size > self._max_table_capacity:
            self._evict_one_entry()

        entry = QpackDynamicTableEntry(
            name=name,
            value=value,
            index=self._insert_count,
        )
        self._dynamic_table.insert(0, entry)
        self._current_table_size += entry_size
        self._insert_count += 1

    async def _find_dynamic_index(self, name: str, value: str) -> int:
        """Find entry in dynamic table.

        Args:
            name: Header name.
            value: Header value.

        Returns:
            Dynamic table index or -1.
        """
        for i, entry in enumerate(self._dynamic_table):
            if entry.name == name and entry.value == value:
                return i
        return -1

    async def _get_dynamic_entry(self, index: int) -> Optional[QpackDynamicTableEntry]:
        """Get dynamic table entry by index.

        Args:
            index: Entry index.

        Returns:
            QpackDynamicTableEntry or None.
        """
        if 0 <= index < len(self._dynamic_table):
            return self._dynamic_table[index]
        return None

    def _evict_entries(self) -> None:
        """Evict entries to fit within capacity."""
        while self._current_table_size > self._max_table_capacity and self._dynamic_table:
            self._evict_one_entry()

    def _evict_one_entry(self) -> None:
        """Evict oldest entry from dynamic table."""
        if self._dynamic_table:
            entry = self._dynamic_table.pop()
            entry_size = len(entry.name) + len(entry.value) + 32
            self._current_table_size -= entry_size
            self._dropped_count += 1

    def get_table_size(self) -> int:
        """Get current dynamic table size.

        Returns:
            Current table size in bytes.
        """
        return self._current_table_size

    def get_entry_count(self) -> int:
        """Get dynamic table entry count.

        Returns:
            Entry count.
        """
        return len(self._dynamic_table)


class Http3FrameProcessor:
    """HTTP/3 frame processor.

    Provides HTTP/3 frame parsing, building, and
    request/response standardization.
    """

    MAX_FRAME_SIZE: int = 16777215
    MAX_HEADER_LIST_SIZE: int = 65536

    def __init__(self) -> None:
        """Initialize HTTP/3 frame processor."""
        self._qpack = QpackEncoderDecoder()
        self._settings: Http3Settings = Http3Settings()
        self._pending_data: Dict[int, bytearray] = {}
        self._pending_headers: Dict[int, bytearray] = {}
        self._stream_complete: Dict[int, bool] = {}

    async def parse_frame(self, data: bytes, stream_id: int = 0) -> Optional[Http3Frame]:
        """Parse HTTP/3 frame from bytes.

        Args:
            data: Frame bytes.
            stream_id: Stream ID.

        Returns:
            Http3Frame or None.
        """
        if len(data) < 2:
            return None

        offset = 0

        frame_type = await self._decode_variable_int(data, offset)
        if frame_type is None:
            return None
        offset += self._get_variable_int_size(frame_type)

        if offset >= len(data):
            return None

        length = await self._decode_variable_int(data, offset)
        if length is None:
            return None
        offset += self._get_variable_int_size(length)

        if length > self.MAX_FRAME_SIZE:
            return None

        if offset + length > len(data):
            return None

        payload = data[offset : offset + length]

        return Http3Frame(
            frame_type=Http3FrameType(frame_type),
            payload=payload,
            stream_id=stream_id,
            length=length,
        )

    async def parse_frames_stream(
        self,
        data: bytes,
        stream_id: int,
    ) -> List[Http3Frame]:
        """Parse multiple HTTP/3 frames from stream data.

        Args:
            data: Stream data.
            stream_id: Stream ID.

        Returns:
            List of Http3Frame.
        """
        frames: List[Http3Frame] = []
        offset = 0

        while offset < len(data):
            if offset + 2 > len(data):
                break

            frame_type = await self._decode_variable_int(data, offset)
            if frame_type is None:
                break
            offset += self._get_variable_int_size(frame_type)

            if offset >= len(data):
                break

            length = await self._decode_variable_int(data, offset)
            if length is None:
                break
            offset += self._get_variable_int_size(length)

            if offset + length > len(data):
                break

            payload = data[offset : offset + length]
            offset += length

            frames.append(Http3Frame(
                frame_type=Http3FrameType(frame_type),
                payload=payload,
                stream_id=stream_id,
                length=length,
            ))

        return frames

    async def process_headers_frame(
        self,
        frame: Http3Frame,
    ) -> Optional[Http3Header]:
        """Process HEADERS frame.

        Args:
            frame: HEADERS frame.

        Returns:
            Http3Header or None.
        """
        if frame.frame_type != Http3FrameType.HEADERS:
            return None

        headers = await self._qpack.decode_headers(frame.payload)

        pseudo_headers: Dict[str, str] = {}
        regular_headers: Dict[str, str] = {}

        for name, value in headers.items():
            if name.startswith(":"):
                pseudo_headers[name] = value
            else:
                regular_headers[name.lower()] = value

        return Http3Header(
            pseudo_headers=pseudo_headers,
            regular_headers=regular_headers,
            encoded_headers=frame.payload,
            stream_id=frame.stream_id,
        )

    async def process_data_frame(
        self,
        frame: Http3Frame,
    ) -> bytes:
        """Process DATA frame.

        Args:
            frame: DATA frame.

        Returns:
            Data payload.
        """
        if frame.frame_type != Http3FrameType.DATA:
            return b""

        stream_id = frame.stream_id
        if stream_id not in self._pending_data:
            self._pending_data[stream_id] = bytearray()

        self._pending_data[stream_id].extend(frame.payload)
        return frame.payload

    async def process_settings_frame(
        self,
        frame: Http3Frame,
    ) -> Optional[Http3Settings]:
        """Process SETTINGS frame.

        Args:
            frame: SETTINGS frame.

        Returns:
            Http3Settings or None.
        """
        if frame.frame_type != Http3FrameType.SETTINGS:
            return None

        settings = Http3Settings()
        offset = 0

        while offset + 2 <= len(frame.payload):
            setting_id = await self._decode_variable_int(frame.payload, offset)
            if setting_id is None:
                break
            offset += self._get_variable_int_size(setting_id)

            setting_value = await self._decode_variable_int(frame.payload, offset)
            if setting_value is None:
                break
            offset += self._get_variable_int_size(setting_value)

            if setting_id == Http3SettingsId.QPACK_MAX_TABLE_CAPACITY:
                settings.qpack_max_table_capacity = setting_value
                self._qpack.set_max_table_capacity(setting_value)
            elif setting_id == Http3SettingsId.MAX_FIELD_SECTION_SIZE:
                settings.max_field_section_size = setting_value
            elif setting_id == Http3SettingsId.QPACK_BLOCKED_STREAMS:
                settings.qpack_blocked_streams = setting_value
                self._qpack.set_max_blocked_streams(setting_value)
            elif setting_id == Http3SettingsId.ENABLE_CONNECT_PROTOCOL:
                settings.enable_connect_protocol = setting_value
            else:
                settings.custom_settings[setting_id] = setting_value

        self._settings = settings
        return settings

    async def build_headers_frame(
        self,
        headers: Dict[str, str],
    ) -> bytes:
        """Build HEADERS frame.

        Args:
            headers: Headers to encode.

        Returns:
            HEADERS frame bytes.
        """
        encoded = await self._qpack.encode_headers(headers)

        frame = bytearray()
        frame.extend(self._encode_variable_int(Http3FrameType.HEADERS))
        frame.extend(self._encode_variable_int(len(encoded)))
        frame.extend(encoded)

        return bytes(frame)

    async def build_data_frame(self, data: bytes) -> bytes:
        """Build DATA frame.

        Args:
            data: Data payload.

        Returns:
            DATA frame bytes.
        """
        frame = bytearray()
        frame.extend(self._encode_variable_int(Http3FrameType.DATA))
        frame.extend(self._encode_variable_int(len(data)))
        frame.extend(data)

        return bytes(frame)

    async def build_settings_frame(self, settings: Optional[Http3Settings] = None) -> bytes:
        """Build SETTINGS frame.

        Args:
            settings: HTTP/3 settings.

        Returns:
            SETTINGS frame bytes.
        """
        if settings is None:
            settings = self._settings

        payload = bytearray()

        if settings.qpack_max_table_capacity > 0:
            payload.extend(self._encode_variable_int(Http3SettingsId.QPACK_MAX_TABLE_CAPACITY))
            payload.extend(self._encode_variable_int(settings.qpack_max_table_capacity))

        payload.extend(self._encode_variable_int(Http3SettingsId.MAX_FIELD_SECTION_SIZE))
        payload.extend(self._encode_variable_int(settings.max_field_section_size))

        if settings.qpack_blocked_streams > 0:
            payload.extend(self._encode_variable_int(Http3SettingsId.QPACK_BLOCKED_STREAMS))
            payload.extend(self._encode_variable_int(settings.qpack_blocked_streams))

        frame = bytearray()
        frame.extend(self._encode_variable_int(Http3FrameType.SETTINGS))
        frame.extend(self._encode_variable_int(len(payload)))
        frame.extend(payload)

        return bytes(frame)

    async def build_push_promise_frame(
        self,
        push_id: int,
        headers: Dict[str, str],
    ) -> bytes:
        """Build PUSH_PROMISE frame.

        Args:
            push_id: Push ID.
            headers: Promised headers.

        Returns:
            PUSH_PROMISE frame bytes.
        """
        encoded = await self._qpack.encode_headers(headers)

        payload = bytearray()
        payload.extend(self._encode_variable_int(push_id))
        payload.extend(encoded)

        frame = bytearray()
        frame.extend(self._encode_variable_int(Http3FrameType.PUSH_PROMISE))
        frame.extend(self._encode_variable_int(len(payload)))
        frame.extend(payload)

        return bytes(frame)

    async def build_goaway_frame(self, stream_id: int) -> bytes:
        """Build GOAWAY frame.

        Args:
            stream_id: Last processed stream ID.

        Returns:
            GOAWAY frame bytes.
        """
        payload = self._encode_variable_int(stream_id)

        frame = bytearray()
        frame.extend(self._encode_variable_int(Http3FrameType.GOAWAY))
        frame.extend(self._encode_variable_int(len(payload)))
        frame.extend(payload)

        return bytes(frame)

    async def build_cancel_push_frame(self, push_id: int) -> bytes:
        """Build CANCEL_PUSH frame.

        Args:
            push_id: Push ID to cancel.

        Returns:
            CANCEL_PUSH frame bytes.
        """
        payload = self._encode_variable_int(push_id)

        frame = bytearray()
        frame.extend(self._encode_variable_int(Http3FrameType.CANCEL_PUSH))
        frame.extend(self._encode_variable_int(len(payload)))
        frame.extend(payload)

        return bytes(frame)

    async def standardize_request(self, header: Http3Header, body: bytes = b"") -> Http3Request:
        """Standardize HTTP/3 request to common format.

        Args:
            header: HTTP/3 header.
            body: Request body.

        Returns:
            Http3Request.
        """
        request = Http3Request(
            method=header.pseudo_headers.get(":method", "GET"),
            path=header.pseudo_headers.get(":path", "/"),
            authority=header.pseudo_headers.get(":authority", ""),
            scheme=header.pseudo_headers.get(":scheme", "https"),
            headers=header.regular_headers.copy(),
            body=body,
            stream_id=header.stream_id,
            raw_headers={**header.pseudo_headers, **header.regular_headers},
        )

        return request

    async def standardize_response(
        self,
        header: Http3Header,
        body: bytes = b"",
    ) -> Http3Response:
        """Standardize HTTP/3 response to common format.

        Args:
            header: HTTP/3 header.
            body: Response body.

        Returns:
            Http3Response.
        """
        status_str = header.pseudo_headers.get(":status", "200")
        try:
            status_code = int(status_str)
        except ValueError:
            status_code = 200

        response = Http3Response(
            status_code=status_code,
            headers=header.regular_headers.copy(),
            body=body,
            stream_id=header.stream_id,
            raw_headers={**header.pseudo_headers, **header.regular_headers},
        )

        return response

    async def convert_to_http1_headers(
        self,
        headers: Dict[str, str],
    ) -> List[Tuple[str, str]]:
        """Convert HTTP/3 headers to HTTP/1.1 format.

        Args:
            headers: HTTP/3 headers.

        Returns:
            List of (name, value) tuples.
        """
        http1_headers: List[Tuple[str, str]] = []

        for name, value in headers.items():
            if name.startswith(":"):
                if name == ":method":
                    http1_headers.append(("X-HTTP-Method", value))
                elif name == ":path":
                    http1_headers.append(("X-HTTP-Path", value))
                elif name == ":authority":
                    http1_headers.append(("Host", value))
                elif name == ":scheme":
                    http1_headers.append(("X-HTTP-Scheme", value))
                elif name == ":status":
                    http1_headers.append(("X-HTTP-Status", value))
            else:
                http1_headers.append((name, value))

        return http1_headers

    async def convert_from_http1_headers(
        self,
        method: str,
        path: str,
        headers: List[Tuple[str, str]],
        scheme: str = "https",
    ) -> Dict[str, str]:
        """Convert HTTP/1.1 headers to HTTP/3 format.

        Args:
            method: HTTP method.
            path: Request path.
            headers: HTTP/1.1 headers.
            scheme: Request scheme.

        Returns:
            HTTP/3 headers dictionary.
        """
        http3_headers: Dict[str, str] = {}

        http3_headers[":method"] = method
        http3_headers[":path"] = path
        http3_headers[":scheme"] = scheme

        for name, value in headers:
            name_lower = name.lower()
            if name_lower == "host":
                http3_headers[":authority"] = value
            elif name_lower not in ("connection", "transfer-encoding", "upgrade"):
                http3_headers[name_lower] = value

        return http3_headers

    async def _decode_variable_int(
        self,
        data: bytes,
        offset: int,
    ) -> Optional[int]:
        """Decode HTTP/3 variable-length integer.

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

    def _get_variable_int_size(self, value: int) -> int:
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

    def _encode_variable_int(self, value: int) -> bytes:
        """Encode integer as variable-length integer.

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

    def get_settings(self) -> Http3Settings:
        """Get current HTTP/3 settings.

        Returns:
            Http3Settings.
        """
        return self._settings

    def get_pending_data(self, stream_id: int) -> bytes:
        """Get pending data for stream.

        Args:
            stream_id: Stream ID.

        Returns:
            Pending data bytes.
        """
        if stream_id in self._pending_data:
            return bytes(self._pending_data[stream_id])
        return b""

    def clear_pending_data(self, stream_id: int) -> None:
        """Clear pending data for stream.

        Args:
            stream_id: Stream ID.
        """
        self._pending_data.pop(stream_id, None)

    def get_qpack_table_size(self) -> int:
        """Get QPACK dynamic table size.

        Returns:
            Table size in bytes.
        """
        return self._qpack.get_table_size()
