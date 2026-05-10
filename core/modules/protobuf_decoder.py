"""Protobuf binary format decoder with schema-less decoding and field type inference.

Provides:
- Pure Python Protobuf binary format parser (no .proto file required)
- Wire Type parsing (Varint/Fixed64/Length-delimited/Fixed32)
- Field type inference with confidence scoring
- Nested message and repeated field detection
- Protobuf-JSON bidirectional conversion
"""

import asyncio
import json
import logging
import struct
import time
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Callable, Coroutine, Dict, List, Optional, Tuple, Union

logger = logging.getLogger(__name__)


class WireType(IntEnum):
    """Protobuf wire types."""
    VARINT = 0
    FIXED64 = 1
    LENGTH_DELIMITED = 2
    START_GROUP = 3
    END_GROUP = 4
    FIXED32 = 5


class InferredType(IntEnum):
    """Inferred field types."""
    UNKNOWN = 0
    BOOL = 1
    INT32 = 2
    INT64 = 3
    UINT32 = 4
    UINT64 = 5
    SINT32 = 6
    SINT64 = 7
    FLOAT = 8
    DOUBLE = 9
    STRING = 10
    BYTES = 11
    NESTED_MESSAGE = 12
    ENUM = 13
    TIMESTAMP = 14


class ConfidenceLevel(IntEnum):
    """Type inference confidence levels."""
    LOW = 0
    MEDIUM = 1
    HIGH = 2
    CERTAIN = 3


@dataclass
class ProtobufField:
    """Decoded Protobuf field.

    Attributes:
        field_number: Field number
        wire_type: Wire type
        value: Decoded value
        inferred_type: Inferred type
        confidence: Confidence level
        raw_bytes: Raw field bytes
        field_name: Human-readable field name
        is_repeated: Whether repeated field
        is_nested_message: Whether nested message
        nested_fields: Nested fields (if nested message)
    """
    field_number: int = 0
    wire_type: WireType = WireType.VARINT
    value: Any = None
    inferred_type: InferredType = InferredType.UNKNOWN
    confidence: ConfidenceLevel = ConfidenceLevel.LOW
    raw_bytes: bytes = b""
    field_name: str = ""
    is_repeated: bool = False
    is_nested_message: bool = False
    nested_fields: List["ProtobufField"] = field(default_factory=list)


@dataclass
class ProtobufMessage:
    """Decoded Protobuf message.

    Attributes:
        fields: List of decoded fields
        raw_bytes: Raw message bytes
        field_count: Number of fields
        decoded_at: Decode timestamp
        decode_time_ms: Decode time in milliseconds
    """
    fields: List[ProtobufField] = field(default_factory=list)
    raw_bytes: bytes = b""
    field_count: int = 0
    decoded_at: float = 0.0
    decode_time_ms: float = 0.0


@dataclass
class DecodeTemplate:
    """Decode template for caching.

    Attributes:
        field_types: Field number to inferred type mapping
        field_names: Field number to field name mapping
        message_hash: Hash of message structure
        use_count: Number of times used
        created_at: Creation timestamp
    """
    field_types: Dict[int, InferredType] = field(default_factory=dict)
    field_names: Dict[int, str] = field(default_factory=dict)
    message_hash: str = ""
    use_count: int = 0
    created_at: float = 0.0


class ProtobufDecoder:
    """Protobuf binary format decoder.

    Provides schema-less decoding with wire type parsing,
    field type inference, and Protobuf-JSON conversion.
    """

    MAX_VARINT_BYTES: int = 10
    MAX_NESTING_DEPTH: int = 32
    MAX_FIELD_NUMBER: int = 536870911

    CONFIDENCE_COLORS: Dict[ConfidenceLevel, str] = {
        ConfidenceLevel.LOW: "#FF6B6B",
        ConfidenceLevel.MEDIUM: "#FFD93D",
        ConfidenceLevel.HIGH: "#6BCB77",
        ConfidenceLevel.CERTAIN: "#4D96FF",
    }

    def __init__(self) -> None:
        """Initialize Protobuf decoder."""
        self._template_cache: Dict[str, DecodeTemplate] = {}
        self._schema_map: Dict[str, Any] = {}
        self._progress_callback: Optional[Callable[[str, float], Coroutine[Any, Any, None]]] = None
        self._log_callback: Optional[Callable[[str], Coroutine[Any, Any, None]]] = None

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
        logger.info("Protobuf Progress: %.1f%% - %s", percentage, message)

    async def _report_log(self, message: str) -> None:
        """Report log via callback.

        Args:
            message: Log message.
        """
        if self._log_callback:
            await self._log_callback(message)
        logger.info("Protobuf: %s", message)

    async def decode_message(
        self,
        data: bytes,
        schema: Optional[Any] = None,
        depth: int = 0,
    ) -> ProtobufMessage:
        """Decode Protobuf message from bytes.

        Args:
            data: Protobuf encoded bytes.
            schema: Optional schema descriptor.
            depth: Current nesting depth.

        Returns:
            Decoded ProtobufMessage.
        """
        start_time = time.time()

        message = ProtobufMessage(
            raw_bytes=data,
            decoded_at=time.time(),
        )

        if schema:
            message.fields = await self._decode_with_schema(data, schema, depth)
        else:
            message.fields = await self._decode_without_schema(data, depth)

        message.field_count = len(message.fields)
        message.decode_time_ms = (time.time() - start_time) * 1000

        if depth == 0:
            template_hash = self._compute_template_hash(message.fields)
            await self._cache_template(template_hash, message.fields)

        return message

    async def _decode_without_schema(
        self,
        data: bytes,
        depth: int = 0,
    ) -> List[ProtobufField]:
        """Decode Protobuf message without schema.

        Args:
            data: Protobuf encoded bytes.
            depth: Current nesting depth.

        Returns:
            List of decoded ProtobufField.
        """
        fields: List[ProtobufField] = []
        offset = 0
        field_counts: Dict[int, int] = {}

        while offset < len(data):
            if depth >= self.MAX_NESTING_DEPTH:
                break

            tag, tag_size = await self._decode_varint(data, offset)
            if tag is None:
                break

            field_number = tag >> 3
            wire_type_value = tag & 0x07

            if field_number > self.MAX_FIELD_NUMBER:
                break

            try:
                wire_type = WireType(wire_type_value)
            except ValueError:
                break

            offset += tag_size

            field_count = field_counts.get(field_number, 0)
            field_counts[field_number] = field_count + 1

            field_value, field_size, inferred_type, confidence = await self._decode_field(
                data, offset, wire_type, field_number, depth
            )

            if field_size is None:
                break

            field_raw = data[offset - tag_size : offset + field_size]

            is_repeated = field_count > 0

            if inferred_type == InferredType.NESTED_MESSAGE:
                nested_fields = await self._decode_without_schema(
                    field_value if isinstance(field_value, bytes) else b"",
                    depth + 1,
                )
                field_obj = ProtobufField(
                    field_number=field_number,
                    wire_type=wire_type,
                    value=field_value,
                    inferred_type=inferred_type,
                    confidence=confidence,
                    raw_bytes=field_raw,
                    field_name=f"Field_{field_number}",
                    is_repeated=is_repeated,
                    is_nested_message=True,
                    nested_fields=nested_fields,
                )
            else:
                field_obj = ProtobufField(
                    field_number=field_number,
                    wire_type=wire_type,
                    value=field_value,
                    inferred_type=inferred_type,
                    confidence=confidence,
                    raw_bytes=field_raw,
                    field_name=f"Field_{field_number}",
                    is_repeated=is_repeated,
                )

            fields.append(field_obj)
            offset += field_size

        return fields

    async def _decode_field(
        self,
        data: bytes,
        offset: int,
        wire_type: WireType,
        field_number: int,
        depth: int,
    ) -> Tuple[Any, Optional[int], InferredType, ConfidenceLevel]:
        """Decode a single Protobuf field.

        Args:
            data: Data bytes.
            offset: Current offset.
            wire_type: Wire type.
            field_number: Field number.
            depth: Nesting depth.

        Returns:
            Tuple of (value, size, inferred_type, confidence).
        """
        if wire_type == WireType.VARINT:
            value, size = await self._decode_varint(data, offset)
            if value is None:
                return None, None, InferredType.UNKNOWN, ConfidenceLevel.LOW

            inferred_type, confidence = await self._infer_varint_type(value)
            return value, size, inferred_type, confidence

        elif wire_type == WireType.FIXED64:
            if offset + 8 > len(data):
                return None, None, InferredType.UNKNOWN, ConfidenceLevel.LOW
            value = struct.unpack("<Q", data[offset : offset + 8])[0]
            return value, 8, InferredType.UINT64, ConfidenceLevel.HIGH

        elif wire_type == WireType.FIXED32:
            if offset + 4 > len(data):
                return None, None, InferredType.UNKNOWN, ConfidenceLevel.LOW
            value = struct.unpack("<I", data[offset : offset + 4])[0]
            return value, 4, InferredType.UINT32, ConfidenceLevel.HIGH

        elif wire_type == WireType.LENGTH_DELIMITED:
            length, length_size = await self._decode_varint(data, offset)
            if length is None:
                return None, None, InferredType.UNKNOWN, ConfidenceLevel.LOW

            value_offset = offset + length_size
            if value_offset + length > len(data):
                return None, None, InferredType.UNKNOWN, ConfidenceLevel.LOW

            value_bytes = data[value_offset : value_offset + length]

            inferred_type, confidence = await self._infer_length_delimited_type(
                value_bytes, depth
            )

            return value_bytes, length_size + length, inferred_type, confidence

        elif wire_type == WireType.START_GROUP or wire_type == WireType.END_GROUP:
            return None, 0, InferredType.UNKNOWN, ConfidenceLevel.LOW

        return None, None, InferredType.UNKNOWN, ConfidenceLevel.LOW

    async def _infer_varint_type(
        self,
        value: int,
    ) -> Tuple[InferredType, ConfidenceLevel]:
        """Infer type from varint value.

        Args:
            value: Varint value.

        Returns:
            Tuple of (inferred_type, confidence).
        """
        if value in (0, 1):
            return InferredType.BOOL, ConfidenceLevel.MEDIUM
        elif value == 0:
            return InferredType.INT32, ConfidenceLevel.LOW
        elif value <= 2147483647:
            if 1000000000 <= value <= 2000000000:
                return InferredType.TIMESTAMP, ConfidenceLevel.MEDIUM
            return InferredType.INT32, ConfidenceLevel.MEDIUM
        elif value <= 9223372036854775807:
            if 1000000000000 <= value <= 9999999999999:
                return InferredType.TIMESTAMP, ConfidenceLevel.MEDIUM
            return InferredType.INT64, ConfidenceLevel.MEDIUM
        else:
            return InferredType.UINT64, ConfidenceLevel.MEDIUM

    async def _infer_length_delimited_type(
        self,
        value: bytes,
        depth: int,
    ) -> Tuple[InferredType, ConfidenceLevel]:
        """Infer type from length-delimited value.

        Args:
            value: Length-delimited value bytes.
            depth: Nesting depth.

        Returns:
            Tuple of (inferred_type, confidence).
        """
        if len(value) == 0:
            return InferredType.STRING, ConfidenceLevel.LOW

        try:
            decoded = value.decode("utf-8")
            if all(c.isprintable() or c in "\n\r\t" for c in decoded):
                return InferredType.STRING, ConfidenceLevel.HIGH
        except (UnicodeDecodeError, ValueError):
            pass

        if depth < self.MAX_NESTING_DEPTH - 1:
            try:
                nested_fields = await self._decode_without_schema(value, depth + 1)
                if nested_fields:
                    return InferredType.NESTED_MESSAGE, ConfidenceLevel.HIGH
            except Exception:
                pass

        return InferredType.BYTES, ConfidenceLevel.MEDIUM

    async def _decode_varint(
        self,
        data: bytes,
        offset: int,
    ) -> Tuple[Optional[int], int]:
        """Decode Protobuf varint.

        Args:
            data: Data bytes.
            offset: Current offset.

        Returns:
            Tuple of (value, bytes_consumed).
        """
        result = 0
        shift = 0
        bytes_consumed = 0

        while offset + bytes_consumed < len(data):
            if bytes_consumed >= self.MAX_VARINT_BYTES:
                return None, 0

            byte = data[offset + bytes_consumed]
            bytes_consumed += 1

            result |= (byte & 0x7F) << shift
            shift += 7

            if not (byte & 0x80):
                return result, bytes_consumed

        return None, 0

    def _compute_template_hash(self, fields: List[ProtobufField]) -> str:
        """Compute hash of message structure for template caching.

        Args:
            fields: List of fields.

        Returns:
            Hash string.
        """
        structure = []
        for f in sorted(fields, key=lambda x: x.field_number):
            structure.append(f"{f.field_number}:{f.wire_type.value}")
        return "|".join(structure)

    async def _cache_template(
        self,
        template_hash: str,
        fields: List[ProtobufField],
    ) -> None:
        """Cache decode template for future use.

        Args:
            template_hash: Template hash.
            fields: List of fields.
        """
        if template_hash in self._template_cache:
            self._template_cache[template_hash].use_count += 1
            return

        template = DecodeTemplate(
            message_hash=template_hash,
            use_count=1,
            created_at=time.time(),
        )

        for f in fields:
            template.field_types[f.field_number] = f.inferred_type
            template.field_names[f.field_number] = f.field_name

        self._template_cache[template_hash] = template

    async def message_to_json(
        self,
        message: ProtobufMessage,
        indent: int = 2,
    ) -> str:
        """Convert Protobuf message to JSON string.

        Args:
            message: ProtobufMessage.
            indent: JSON indentation.

        Returns:
            JSON string.
        """
        json_obj = await self._fields_to_dict(message.fields)
        return json.dumps(json_obj, indent=indent, ensure_ascii=False, default=str)

    async def _fields_to_dict(
        self,
        fields: List[ProtobufField],
    ) -> Dict[str, Any]:
        """Convert fields list to dictionary.

        Args:
            fields: List of ProtobufField.

        Returns:
            Dictionary representation.
        """
        result: Dict[str, Any] = {}

        for f in fields:
            key = f.field_name

            if f.is_nested_message and f.nested_fields:
                nested_value: Any = await self._fields_to_dict(f.nested_fields)
                value = nested_value
            elif f.inferred_type == InferredType.STRING:
                try:
                    value = f.value.decode("utf-8") if isinstance(f.value, bytes) else str(f.value)
                except (UnicodeDecodeError, AttributeError):
                    value = str(f.value)
            elif f.inferred_type == InferredType.BYTES:
                value = f.value.hex() if isinstance(f.value, bytes) else str(f.value)
            else:
                value = f.value

            if f.is_repeated:
                if key not in result:
                    result[key] = []
                if isinstance(result[key], list):
                    result[key].append(value)
                else:
                    result[key] = [result[key], value]
            else:
                result[key] = value

        return result

    async def json_to_protobuf(
        self,
        json_data: Dict[str, Any],
        template: Optional[DecodeTemplate] = None,
    ) -> bytes:
        """Convert JSON data back to Protobuf bytes.

        Args:
            json_data: JSON data dictionary.
            template: Optional decode template.

        Returns:
            Protobuf encoded bytes.
        """
        result = bytearray()

        for key, value in json_data.items():
            if key.startswith("Field_"):
                try:
                    field_number = int(key.split("_")[1])
                except (ValueError, IndexError):
                    continue
            else:
                continue

            wire_type = WireType.VARINT
            if template and field_number in template.field_types:
                inferred = template.field_types[field_number]
                wire_type = self._inferred_type_to_wire_type(inferred)

            if isinstance(value, list):
                for item in value:
                    result.extend(await self._encode_field(field_number, wire_type, item))
            else:
                result.extend(await self._encode_field(field_number, wire_type, value))

        return bytes(result)

    async def _encode_field(
        self,
        field_number: int,
        wire_type: WireType,
        value: Any,
    ) -> bytes:
        """Encode a single field to Protobuf bytes.

        Args:
            field_number: Field number.
            wire_type: Wire type.
            value: Field value.

        Returns:
            Encoded field bytes.
        """
        tag = (field_number << 3) | wire_type.value
        result = bytearray()

        result.extend(self._encode_varint(tag))

        if wire_type == WireType.VARINT:
            if isinstance(value, bool):
                result.extend(self._encode_varint(1 if value else 0))
            elif isinstance(value, int):
                result.extend(self._encode_varint(value))
            else:
                result.extend(self._encode_varint(int(value)))

        elif wire_type == WireType.FIXED64:
            if isinstance(value, int):
                result.extend(struct.pack("<Q", value))

        elif wire_type == WireType.FIXED32:
            if isinstance(value, int):
                result.extend(struct.pack("<I", value))

        elif wire_type == WireType.LENGTH_DELIMITED:
            if isinstance(value, str):
                encoded = value.encode("utf-8")
                result.extend(self._encode_varint(len(encoded)))
                result.extend(encoded)
            elif isinstance(value, bytes):
                result.extend(self._encode_varint(len(value)))
                result.extend(value)
            elif isinstance(value, dict):
                nested = await self.json_to_protobuf(value)
                result.extend(self._encode_varint(len(nested)))
                result.extend(nested)

        return bytes(result)

    def _encode_varint(self, value: int) -> bytes:
        """Encode integer as Protobuf varint.

        Args:
            value: Integer value.

        Returns:
            Varint encoded bytes.
        """
        if value < 0:
            value = value & 0xFFFFFFFFFFFFFFFF

        result = bytearray()
        while value > 0x7F:
            result.append((value & 0x7F) | 0x80)
            value >>= 7
        result.append(value & 0x7F)

        return bytes(result) if result else b"\x00"

    def _inferred_type_to_wire_type(self, inferred_type: InferredType) -> WireType:
        """Convert inferred type to wire type.

        Args:
            inferred_type: Inferred type.

        Returns:
            Wire type.
        """
        if inferred_type in (
            InferredType.BOOL,
            InferredType.INT32,
            InferredType.INT64,
            InferredType.UINT32,
            InferredType.UINT64,
            InferredType.SINT32,
            InferredType.SINT64,
            InferredType.ENUM,
            InferredType.TIMESTAMP,
        ):
            return WireType.VARINT
        elif inferred_type in (InferredType.FLOAT, InferredType.DOUBLE):
            return WireType.FIXED64
        elif inferred_type in (
            InferredType.STRING,
            InferredType.BYTES,
            InferredType.NESTED_MESSAGE,
        ):
            return WireType.LENGTH_DELIMITED
        return WireType.VARINT

    async def decode_with_schema(
        self,
        data: bytes,
        schema_descriptor: Any,
    ) -> ProtobufMessage:
        """Decode Protobuf message using schema descriptor.

        Args:
            data: Protobuf encoded bytes.
            schema_descriptor: Schema descriptor.

        Returns:
            Decoded ProtobufMessage.
        """
        start_time = time.time()

        message = ProtobufMessage(
            raw_bytes=data,
            decoded_at=time.time(),
        )

        message.fields = await self._decode_with_schema(data, schema_descriptor, 0)
        message.field_count = len(message.fields)
        message.decode_time_ms = (time.time() - start_time) * 1000

        return message

    async def _decode_with_schema(
        self,
        data: bytes,
        schema: Any,
        depth: int,
    ) -> List[ProtobufField]:
        """Decode using schema descriptor.

        Args:
            data: Protobuf encoded bytes.
            schema: Schema descriptor.
            depth: Nesting depth.

        Returns:
            List of decoded ProtobufField.
        """
        fields: List[ProtobufField] = []
        offset = 0

        while offset < len(data):
            tag, tag_size = await self._decode_varint(data, offset)
            if tag is None:
                break

            field_number = tag >> 3
            wire_type_value = tag & 0x07

            offset += tag_size

            try:
                wire_type = WireType(wire_type_value)
            except ValueError:
                break

            field_info = await self._lookup_field_schema(schema, field_number)

            if field_info:
                field_value, field_size_int = await self._decode_field_with_schema(
                    data, offset, wire_type, field_info
                )

                field_obj = ProtobufField(
                    field_number=field_number,
                    wire_type=wire_type,
                    value=field_value,
                    inferred_type=field_info.get("type", InferredType.UNKNOWN),
                    confidence=ConfidenceLevel.CERTAIN,
                    raw_bytes=data[offset - tag_size : offset + field_size_int],
                    field_name=field_info.get("name", f"Field_{field_number}"),
                )
                fields.append(field_obj)
                offset += field_size_int
            else:
                field_value, field_size, inferred_type, confidence = await self._decode_field(
                    data, offset, wire_type, field_number, depth
                )

                if field_size is None:
                    break

                field_obj = ProtobufField(
                    field_number=field_number,
                    wire_type=wire_type,
                    value=field_value,
                    inferred_type=inferred_type,
                    confidence=confidence,
                    raw_bytes=data[offset - tag_size : offset + field_size],
                    field_name=f"Field_{field_number}",
                )
                fields.append(field_obj)
                offset += field_size

        return fields

    async def _lookup_field_schema(
        self,
        schema: Any,
        field_number: int,
    ) -> Optional[Dict[str, Any]]:
        """Look up field schema by field number.

        Args:
            schema: Schema descriptor.
            field_number: Field number.

        Returns:
            Field schema info or None.
        """
        if isinstance(schema, dict):
            fields_dict: Dict[int, Dict[str, Any]] = schema.get("fields", {})
            result: Optional[Dict[str, Any]] = fields_dict.get(field_number)
            return result
        return None

    async def _decode_field_with_schema(
        self,
        data: bytes,
        offset: int,
        wire_type: WireType,
        field_info: Dict[str, Any],
    ) -> Tuple[Any, int]:
        """Decode field using schema information.

        Args:
            data: Data bytes.
            offset: Current offset.
            wire_type: Wire type.
            field_info: Field schema info.

        Returns:
            Tuple of (value, size).
        """
        field_type = field_info.get("type", InferredType.UNKNOWN)

        if wire_type == WireType.VARINT:
            value, size = await self._decode_varint(data, offset)
            return value, size or 0

        elif wire_type == WireType.FIXED64:
            if offset + 8 > len(data):
                return None, 0
            value = struct.unpack("<Q", data[offset : offset + 8])[0]
            return value, 8

        elif wire_type == WireType.FIXED32:
            if offset + 4 > len(data):
                return None, 0
            value = struct.unpack("<I", data[offset : offset + 4])[0]
            return value, 4

        elif wire_type == WireType.LENGTH_DELIMITED:
            length, length_size = await self._decode_varint(data, offset)
            if length is None:
                return None, 0

            value_offset = offset + length_size
            if value_offset + length > len(data):
                return None, 0

            value_bytes = data[value_offset : value_offset + length]
            return value_bytes, length_size + length

        return None, 0

    def get_template_cache_size(self) -> int:
        """Get template cache size.

        Returns:
            Number of cached templates.
        """
        return len(self._template_cache)

    def clear_template_cache(self) -> None:
        """Clear template cache."""
        self._template_cache.clear()

    def get_confidence_color(self, confidence: ConfidenceLevel) -> str:
        """Get confidence level color for UI.

        Args:
            confidence: Confidence level.

        Returns:
            Color hex string.
        """
        return self.CONFIDENCE_COLORS.get(confidence, "#FFFFFF")
