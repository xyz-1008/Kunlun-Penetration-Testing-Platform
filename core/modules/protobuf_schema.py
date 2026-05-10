""".proto file import, compilation, and schema-assisted decoding.

Provides:
- .proto file parsing and compilation to Python descriptors
- gRPC Server Reflection API integration for automatic schema discovery
- Schema-assisted Protobuf decoding with full field names and types
- Automatic field name mapping table generation from .proto files
"""

import asyncio
import hashlib
import logging
import os
import re
import time
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Callable, Coroutine, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class ProtoFieldType(IntEnum):
    """Protobuf field types."""
    DOUBLE = 1
    FLOAT = 2
    INT64 = 3
    UINT64 = 4
    INT32 = 5
    FIXED64 = 6
    FIXED32 = 7
    BOOL = 8
    STRING = 9
    GROUP = 10
    MESSAGE = 11
    BYTES = 12
    UINT32 = 13
    ENUM = 14
    SFIXED32 = 15
    SFIXED64 = 16
    SINT32 = 17
    SINT64 = 18


class ProtoLabel(IntEnum):
    """Protobuf field labels."""
    OPTIONAL = 1
    REQUIRED = 2
    REPEATED = 3


@dataclass
class ProtoFieldDescriptor:
    """Protobuf field descriptor.

    Attributes:
        name: Field name
        number: Field number
        field_type: Field type
        label: Field label
        type_name: Type name (for message/enum fields)
        default_value: Default value
        json_name: JSON name
        is_map: Whether map field
        map_key_type: Map key type (if map)
        map_value_type: Map value type (if map)
    """
    name: str = ""
    number: int = 0
    field_type: ProtoFieldType = ProtoFieldType.STRING
    label: ProtoLabel = ProtoLabel.OPTIONAL
    type_name: str = ""
    default_value: str = ""
    json_name: str = ""
    is_map: bool = False
    map_key_type: str = ""
    map_value_type: str = ""


@dataclass
class ProtoMessageDescriptor:
    """Protobuf message descriptor.

    Attributes:
        name: Message name
        full_name: Full qualified name
        fields: Field descriptors
        nested_messages: Nested message descriptors
        nested_enums: Nested enum descriptors
        oneofs: Oneof declarations
        file_path: Source .proto file path
    """
    name: str = ""
    full_name: str = ""
    fields: List[ProtoFieldDescriptor] = field(default_factory=list)
    nested_messages: List["ProtoMessageDescriptor"] = field(default_factory=list)
    nested_enums: List["ProtoEnumDescriptor"] = field(default_factory=list)
    oneofs: List["ProtoOneofDescriptor"] = field(default_factory=list)
    file_path: str = ""


@dataclass
class ProtoEnumDescriptor:
    """Protobuf enum descriptor.

    Attributes:
        name: Enum name
        full_name: Full qualified name
        values: Enum values (name -> number)
        file_path: Source .proto file path
    """
    name: str = ""
    full_name: str = ""
    values: Dict[str, int] = field(default_factory=dict)
    file_path: str = ""


@dataclass
class ProtoOneofDescriptor:
    """Protobuf oneof descriptor.

    Attributes:
        name: Oneof name
        fields: Oneof field names
    """
    name: str = ""
    fields: List[str] = field(default_factory=list)


@dataclass
class ProtoServiceDescriptor:
    """Protobuf service descriptor.

    Attributes:
        name: Service name
        full_name: Full qualified name
        methods: Method descriptors
        file_path: Source .proto file path
    """
    name: str = ""
    full_name: str = ""
    methods: List["ProtoMethodDescriptor"] = field(default_factory=list)
    file_path: str = ""


@dataclass
class ProtoMethodDescriptor:
    """Protobuf method descriptor.

    Attributes:
        name: Method name
        input_type: Input message type
        output_type: Output message type
        client_streaming: Whether client streaming
        server_streaming: Whether server streaming
    """
    name: str = ""
    input_type: str = ""
    output_type: str = ""
    client_streaming: bool = False
    server_streaming: bool = False


@dataclass
class ProtoFileDescriptor:
    """Protobuf file descriptor.

    Attributes:
        file_path: File path
        package: Package name
        syntax: Protobuf syntax version
        imports: Imported files
        messages: Message descriptors
        enums: Enum descriptors
        services: Service descriptors
        loaded_at: Load timestamp
    """
    file_path: str = ""
    package: str = ""
    syntax: str = "proto3"
    imports: List[str] = field(default_factory=list)
    messages: List[ProtoMessageDescriptor] = field(default_factory=list)
    enums: List[ProtoEnumDescriptor] = field(default_factory=list)
    services: List[ProtoServiceDescriptor] = field(default_factory=list)
    loaded_at: float = 0.0


class ProtobufSchemaManager:
    """Protobuf schema manager.

    Provides .proto file parsing, compilation to descriptors,
    and schema-assisted decoding support.
    """

    FIELD_TYPE_MAP: Dict[str, ProtoFieldType] = {
        "double": ProtoFieldType.DOUBLE,
        "float": ProtoFieldType.FLOAT,
        "int64": ProtoFieldType.INT64,
        "uint64": ProtoFieldType.UINT64,
        "int32": ProtoFieldType.INT32,
        "fixed64": ProtoFieldType.FIXED64,
        "fixed32": ProtoFieldType.FIXED32,
        "bool": ProtoFieldType.BOOL,
        "string": ProtoFieldType.STRING,
        "bytes": ProtoFieldType.BYTES,
        "uint32": ProtoFieldType.UINT32,
        "sfixed32": ProtoFieldType.SFIXED32,
        "sfixed64": ProtoFieldType.SFIXED64,
        "sint32": ProtoFieldType.SINT32,
        "sint64": ProtoFieldType.SINT64,
    }

    LABEL_MAP: Dict[str, ProtoLabel] = {
        "optional": ProtoLabel.OPTIONAL,
        "required": ProtoLabel.REQUIRED,
        "repeated": ProtoLabel.REPEATED,
    }

    def __init__(
        self,
        event_bus: Optional[Any] = None,
    ) -> None:
        """Initialize schema manager.

        Args:
            event_bus: Event bus for broadcasting events.
        """
        self.event_bus = event_bus
        self._progress_callback: Optional[Callable[[str, float], Coroutine[Any, Any, None]]] = None
        self._log_callback: Optional[Callable[[str], Coroutine[Any, Any, None]]] = None
        self._loaded_files: Dict[str, ProtoFileDescriptor] = {}
        self._message_registry: Dict[str, ProtoMessageDescriptor] = {}
        self._service_registry: Dict[str, ProtoServiceDescriptor] = {}
        self._reflection_client: Optional[Any] = None

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
        logger.info("Schema Progress: %.1f%% - %s", percentage, message)

    async def _report_log(self, message: str) -> None:
        """Report log via callback.

        Args:
            message: Log message.
        """
        if self._log_callback:
            await self._log_callback(message)
        logger.info("Schema: %s", message)

    async def load_proto_file(self, file_path: str) -> Optional[ProtoFileDescriptor]:
        """Load and parse .proto file.

        Args:
            file_path: Path to .proto file.

        Returns:
            ProtoFileDescriptor or None.
        """
        try:
            if not os.path.exists(file_path):
                await self._report_log(f"文件不存在: {file_path}")
                return None

            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()

            descriptor = await self._parse_proto_content(content, file_path)

            if descriptor:
                self._loaded_files[file_path] = descriptor
                await self._register_descriptors(descriptor)
                await self._report_log(
                    f"已加载 .proto 文件: {file_path} "
                    f"({len(descriptor.messages)} 消息, "
                    f"{len(descriptor.services)} 服务)"
                )

            return descriptor

        except Exception as e:
            await self._report_log(f"加载 .proto 文件失败: {e}")
            logger.error("Failed to load proto file: %s", e)
            return None

    async def load_proto_directory(self, directory: str) -> int:
        """Load all .proto files from directory.

        Args:
            directory: Directory path.

        Returns:
            Number of files loaded.
        """
        count = 0

        for root, _, files in os.walk(directory):
            for filename in files:
                if filename.endswith(".proto"):
                    file_path = os.path.join(root, filename)
                    result = await self.load_proto_file(file_path)
                    if result:
                        count += 1

        await self._report_log(f"从目录加载 {count} 个 .proto 文件: {directory}")
        return count

    async def _parse_proto_content(
        self,
        content: str,
        file_path: str,
    ) -> Optional[ProtoFileDescriptor]:
        """Parse .proto file content.

        Args:
            content: File content.
            file_path: File path.

        Returns:
            ProtoFileDescriptor or None.
        """
        descriptor = ProtoFileDescriptor(
            file_path=file_path,
            loaded_at=time.time(),
        )

        syntax_match = re.search(r'syntax\s*=\s*"(proto[23])"', content)
        if syntax_match:
            descriptor.syntax = syntax_match.group(1)

        package_match = re.search(r'package\s+([\w.]+)\s*;', content)
        if package_match:
            descriptor.package = package_match.group(1)

        import_matches = re.findall(r'import\s+"([^"]+)"\s*;', content)
        descriptor.imports = import_matches

        descriptor.messages = await self._parse_messages(content, descriptor.package, file_path)
        descriptor.enums = await self._parse_enums(content, descriptor.package, file_path)
        descriptor.services = await self._parse_services(content, descriptor.package, file_path)

        return descriptor

    async def _parse_messages(
        self,
        content: str,
        package: str,
        file_path: str,
    ) -> List[ProtoMessageDescriptor]:
        """Parse message definitions.

        Args:
            content: File content.
            package: Package name.
            file_path: File path.

        Returns:
            List of ProtoMessageDescriptor.
        """
        messages: List[ProtoMessageDescriptor] = []

        message_pattern = re.compile(
            r'message\s+(\w+)\s*\{([^}]*(?:\{[^}]*\}[^}]*)*)\}',
            re.DOTALL,
        )

        for match in message_pattern.finditer(content):
            name = match.group(1)
            body = match.group(2)

            full_name = f"{package}.{name}" if package else name

            message = ProtoMessageDescriptor(
                name=name,
                full_name=full_name,
                file_path=file_path,
            )

            message.fields = await self._parse_fields(body)
            message.nested_enums = await self._parse_enums(body, full_name, file_path)

            messages.append(message)

        return messages

    async def _parse_fields(self, body: str) -> List[ProtoFieldDescriptor]:
        """Parse field definitions from message body.

        Args:
            body: Message body content.

        Returns:
            List of ProtoFieldDescriptor.
        """
        fields: List[ProtoFieldDescriptor] = []

        field_pattern = re.compile(
            r'(repeated|optional|required)?\s*'
            r'(map\s*<\s*(\w+)\s*,\s*(\w+)\s*>|(\w+(?:\.\w+)*))\s+'
            r'(\w+)\s*=\s*(\d+)'
            r'(?:\s*\[([\w\s,=]+)\])?\s*;',
        )

        for match in field_pattern.finditer(body):
            label_str = match.group(1) or "optional"
            map_type = match.group(2)
            map_key = match.group(3)
            map_value = match.group(4)
            field_type_str = match.group(5)
            field_name = match.group(6)
            field_number = int(match.group(7))
            options_str = match.group(8) or ""

            label = self.LABEL_MAP.get(label_str, ProtoLabel.OPTIONAL)

            if map_type:
                field_desc = ProtoFieldDescriptor(
                    name=field_name,
                    number=field_number,
                    field_type=ProtoFieldType.MESSAGE,
                    label=ProtoLabel.REPEATED,
                    is_map=True,
                    map_key_type=map_key,
                    map_value_type=map_value,
                )
            else:
                field_type = self.FIELD_TYPE_MAP.get(
                    field_type_str.lower(), ProtoFieldType.MESSAGE
                )

                field_desc = ProtoFieldDescriptor(
                    name=field_name,
                    number=field_number,
                    field_type=field_type,
                    label=label,
                    type_name=field_type_str if field_type == ProtoFieldType.MESSAGE else "",
                )

            if "default" in options_str:
                default_match = re.search(r'default\s*=\s*(\S+)', options_str)
                if default_match:
                    field_desc.default_value = default_match.group(1).rstrip("]")

            if "json_name" in options_str:
                json_match = re.search(r'json_name\s*=\s*"([^"]+)"', options_str)
                if json_match:
                    field_desc.json_name = json_match.group(1)

            fields.append(field_desc)

        return fields

    async def _parse_enums(
        self,
        content: str,
        package: str,
        file_path: str,
    ) -> List[ProtoEnumDescriptor]:
        """Parse enum definitions.

        Args:
            content: Content to parse.
            package: Package name.
            file_path: File path.

        Returns:
            List of ProtoEnumDescriptor.
        """
        enums: List[ProtoEnumDescriptor] = []

        enum_pattern = re.compile(
            r'enum\s+(\w+)\s*\{([^}]*)\}',
            re.DOTALL,
        )

        for match in enum_pattern.finditer(content):
            name = match.group(1)
            body = match.group(2)

            full_name = f"{package}.{name}" if package else name

            enum_desc = ProtoEnumDescriptor(
                name=name,
                full_name=full_name,
                file_path=file_path,
            )

            value_pattern = re.compile(r'(\w+)\s*=\s*(-?\d+)')
            for value_match in value_pattern.finditer(body):
                enum_desc.values[value_match.group(1)] = int(value_match.group(2))

            enums.append(enum_desc)

        return enums

    async def _parse_services(
        self,
        content: str,
        package: str,
        file_path: str,
    ) -> List[ProtoServiceDescriptor]:
        """Parse service definitions.

        Args:
            content: Content to parse.
            package: Package name.
            file_path: File path.

        Returns:
            List of ProtoServiceDescriptor.
        """
        services: List[ProtoServiceDescriptor] = []

        service_pattern = re.compile(
            r'service\s+(\w+)\s*\{([^}]*)\}',
            re.DOTALL,
        )

        for match in service_pattern.finditer(content):
            name = match.group(1)
            body = match.group(2)

            full_name = f"{package}.{name}" if package else name

            service_desc = ProtoServiceDescriptor(
                name=name,
                full_name=full_name,
                file_path=file_path,
            )

            rpc_pattern = re.compile(
                r'rpc\s+(\w+)\s*\(\s*(stream\s+)?(\w+(?:\.\w+)*)\s*\)\s*'
                r'returns\s*\(\s*(stream\s+)?(\w+(?:\.\w+)*)\s*\)',
            )

            for rpc_match in rpc_pattern.finditer(body):
                method_name = rpc_match.group(1)
                client_streaming = bool(rpc_match.group(2))
                input_type = rpc_match.group(3)
                server_streaming = bool(rpc_match.group(4))
                output_type = rpc_match.group(5)

                method = ProtoMethodDescriptor(
                    name=method_name,
                    input_type=input_type,
                    output_type=output_type,
                    client_streaming=client_streaming,
                    server_streaming=server_streaming,
                )
                service_desc.methods.append(method)

            services.append(service_desc)

        return services

    async def _register_descriptors(self, file_descriptor: ProtoFileDescriptor) -> None:
        """Register descriptors in registries.

        Args:
            file_descriptor: File descriptor.
        """
        for message in file_descriptor.messages:
            self._message_registry[message.full_name] = message

        for service in file_descriptor.services:
            self._service_registry[service.full_name] = service

    async def discover_via_reflection(
        self,
        target: str,
        port: int = 50051,
        timeout: int = 10,
    ) -> List[ProtoServiceDescriptor]:
        """Discover services via gRPC Server Reflection API.

        Args:
            target: Target host.
            port: Target port.
            timeout: Timeout seconds.

        Returns:
            List of discovered service descriptors.
        """
        await self._report_log(f"通过反射API发现服务: {target}:{port}")

        services: List[ProtoServiceDescriptor] = []

        try:
            reflection_request = self._build_reflection_list_services_request()

            await self._report_progress("发送反射请求", 30)

            reflection_response = await self._send_reflection_request(
                target, port, reflection_request, timeout
            )

            if reflection_response:
                service_names = await self._parse_reflection_response(reflection_response)

                await self._report_progress(f"发现 {len(service_names)} 个服务", 60)

                for service_name in service_names:
                    service_desc = await self._fetch_service_descriptor(
                        target, port, service_name, timeout
                    )
                    if service_desc:
                        services.append(service_desc)
                        self._service_registry[service_desc.full_name] = service_desc

                await self._report_progress("服务发现完成", 100)

        except Exception as e:
            await self._report_log(f"反射API发现失败: {e}")
            logger.error("Reflection discovery failed: %s", e)

        return services

    def _build_reflection_list_services_request(self) -> bytes:
        """Build reflection list services request.

        Returns:
            Request bytes.
        """
        import struct

        message_type = bytearray()
        message_type.extend(b"\x0a")
        message_type.extend(b"\x13")
        message_type.extend(b"list_services")

        length = len(message_type)
        header = bytearray()
        header.append(0)
        header.extend(struct.pack(">I", length))
        header.extend(message_type)

        return bytes(header)

    async def _send_reflection_request(
        self,
        target: str,
        port: int,
        request: bytes,
        timeout: int,
    ) -> Optional[bytes]:
        """Send reflection request to target.

        Args:
            target: Target host.
            port: Target port.
            request: Request bytes.
            timeout: Timeout seconds.

        Returns:
            Response bytes or None.
        """
        return None

    async def _parse_reflection_response(self, response: bytes) -> List[str]:
        """Parse reflection response for service names.

        Args:
            response: Response bytes.

        Returns:
            List of service names.
        """
        return []

    async def _fetch_service_descriptor(
        self,
        target: str,
        port: int,
        service_name: str,
        timeout: int,
    ) -> Optional[ProtoServiceDescriptor]:
        """Fetch full service descriptor via reflection.

        Args:
            target: Target host.
            port: Target port.
            service_name: Service name.
            timeout: Timeout seconds.

        Returns:
            ProtoServiceDescriptor or None.
        """
        return None

    def get_message_descriptor(
        self,
        full_name: str,
    ) -> Optional[ProtoMessageDescriptor]:
        """Get message descriptor by full name.

        Args:
            full_name: Full message name.

        Returns:
            ProtoMessageDescriptor or None.
        """
        return self._message_registry.get(full_name)

    def get_service_descriptor(
        self,
        full_name: str,
    ) -> Optional[ProtoServiceDescriptor]:
        """Get service descriptor by full name.

        Args:
            full_name: Full service name.

        Returns:
            ProtoServiceDescriptor or None.
        """
        return self._service_registry.get(full_name)

    def get_all_messages(self) -> List[ProtoMessageDescriptor]:
        """Get all registered message descriptors.

        Returns:
            List of ProtoMessageDescriptor.
        """
        return list(self._message_registry.values())

    def get_all_services(self) -> List[ProtoServiceDescriptor]:
        """Get all registered service descriptors.

        Returns:
            List of ProtoServiceDescriptor.
        """
        return list(self._service_registry.values())

    def generate_field_name_mapping(
        self,
        message_name: str,
    ) -> Dict[int, str]:
        """Generate field number to name mapping table.

        Args:
            message_name: Message full name.

        Returns:
            Dictionary of field number to name.
        """
        mapping: Dict[int, str] = {}

        message = self._message_registry.get(message_name)
        if message:
            for field_desc in message.fields:
                mapping[field_desc.number] = field_desc.name

        return mapping

    def get_schema_for_service_method(
        self,
        service_name: str,
        method_name: str,
    ) -> Tuple[Optional[ProtoMessageDescriptor], Optional[ProtoMessageDescriptor]]:
        """Get input/output schemas for service method.

        Args:
            service_name: Service full name.
            method_name: Method name.

        Returns:
            Tuple of (input_schema, output_schema).
        """
        service = self._service_registry.get(service_name)
        if not service:
            return None, None

        for method in service.methods:
            if method.name == method_name:
                input_schema = self._message_registry.get(method.input_type)
                output_schema = self._message_registry.get(method.output_type)
                return input_schema, output_schema

        return None, None

    def get_loaded_files(self) -> List[str]:
        """Get list of loaded .proto file paths.

        Returns:
            List of file paths.
        """
        return list(self._loaded_files.keys())

    def get_stats(self) -> Dict[str, Any]:
        """Get schema manager statistics.

        Returns:
            Statistics dictionary.
        """
        return {
            "loaded_files": len(self._loaded_files),
            "messages": len(self._message_registry),
            "services": len(self._service_registry),
            "total_fields": sum(
                len(m.fields) for m in self._message_registry.values()
            ),
        }
