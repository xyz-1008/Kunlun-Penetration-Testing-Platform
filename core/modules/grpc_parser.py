"""gRPC traffic parsing, message frame parsing, service discovery, and streaming support.

Provides:
- gRPC traffic identification (application/grpc headers)
- gRPC message frame parsing (compression flag + length + body)
- gRPC-Web protocol support
- Streaming call pattern detection (Unary/Server/Client/Bidirectional)
- Service discovery and reflection API support
"""

import asyncio
import logging
import struct
import time
from dataclasses import dataclass, field
from enum import Enum, IntEnum
from typing import Any, Callable, Coroutine, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


class GrpcContentType(Enum):
    """gRPC content types."""
    GRPC = "application/grpc"
    GRPC_WEB = "application/grpc-web"
    GRPC_WEB_TEXT = "application/grpc-web-text"
    GRPC_PROTO = "application/grpc+proto"
    GRPC_JSON = "application/grpc+json"


class GrpcCallType(Enum):
    """gRPC call types."""
    UNARY = "unary"
    SERVER_STREAMING = "server_streaming"
    CLIENT_STREAMING = "client_streaming"
    BIDIRECTIONAL_STREAMING = "bidirectional_streaming"


class GrpcStatusCode(IntEnum):
    """gRPC status codes."""
    OK = 0
    CANCELLED = 1
    UNKNOWN = 2
    INVALID_ARGUMENT = 3
    DEADLINE_EXCEEDED = 4
    NOT_FOUND = 5
    ALREADY_EXISTS = 6
    PERMISSION_DENIED = 7
    RESOURCE_EXHAUSTED = 8
    FAILED_PRECONDITION = 9
    ABORTED = 10
    OUT_OF_RANGE = 11
    UNIMPLEMENTED = 12
    INTERNAL = 13
    UNAVAILABLE = 14
    DATA_LOSS = 15
    UNAUTHENTICATED = 16


class GrpcCompressionFlag(IntEnum):
    """gRPC compression flags."""
    NONE = 0
    COMPRESSED = 1


@dataclass
class GrpcMessageFrame:
    """gRPC message frame.

    Attributes:
        compression_flag: Compression flag (1 byte)
        message_length: Message body length (4 bytes big-endian)
        message_body: Raw message body bytes
        is_compressed: Whether message is compressed
        raw_bytes: Complete raw frame bytes
    """
    compression_flag: int = GrpcCompressionFlag.NONE
    message_length: int = 0
    message_body: bytes = b""
    is_compressed: bool = False
    raw_bytes: bytes = b""


@dataclass
class GrpcMetadata:
    """gRPC metadata (headers/trailers).

    Attributes:
        headers: Request/response headers
        trailers: gRPC trailers (status details)
        content_type: Content type
        te: Transfer encoding
        user_agent: User agent
        authorization: Authorization header
        grpc_timeout: gRPC timeout
        grpc_encoding: gRPC encoding
    """
    headers: Dict[str, str] = field(default_factory=dict)
    trailers: Dict[str, str] = field(default_factory=dict)
    content_type: str = ""
    te: str = ""
    user_agent: str = ""
    authorization: str = ""
    grpc_timeout: str = ""
    grpc_encoding: str = ""


@dataclass
class GrpcServiceInfo:
    """gRPC service information.

    Attributes:
        package: Package name
        service_name: Service name
        method_name: Method name
        full_path: Full service path
        call_type: Detected call type
        request_count: Number of requests observed
        last_seen: Last seen timestamp
        methods: Available methods
        is_reflection_discovered: Whether discovered via reflection
    """
    package: str = ""
    service_name: str = ""
    method_name: str = ""
    full_path: str = ""
    call_type: GrpcCallType = GrpcCallType.UNARY
    request_count: int = 0
    last_seen: float = 0.0
    methods: List[str] = field(default_factory=list)
    is_reflection_discovered: bool = False


@dataclass
class GrpcRequest:
    """Parsed gRPC request.

    Attributes:
        request_id: Unique request ID
        timestamp: Request timestamp
        service_path: Full gRPC service path
        method: gRPC method name
        content_type: Content type
        metadata: gRPC metadata
        messages: Request messages
        call_type: Call type
        authority: Target authority
        scheme: Request scheme
        is_streaming: Whether streaming call
        duration_ms: Request duration
    """
    request_id: str = ""
    timestamp: float = 0.0
    service_path: str = ""
    method: str = ""
    content_type: str = ""
    metadata: Optional[GrpcMetadata] = None
    messages: List[GrpcMessageFrame] = field(default_factory=list)
    call_type: GrpcCallType = GrpcCallType.UNARY
    authority: str = ""
    scheme: str = "https"
    is_streaming: bool = False
    duration_ms: float = 0.0


@dataclass
class GrpcResponse:
    """Parsed gRPC response.

    Attributes:
        status_code: gRPC status code
        status_message: Status message
        messages: Response messages
        metadata: Response metadata
        trailers: gRPC trailers
        duration_ms: Response duration
    """
    status_code: int = GrpcStatusCode.OK
    status_message: str = "OK"
    messages: List[GrpcMessageFrame] = field(default_factory=list)
    metadata: Optional[GrpcMetadata] = None
    trailers: Dict[str, str] = field(default_factory=dict)
    duration_ms: float = 0.0


class GrpcParser:
    """gRPC traffic parser and service discovery.

    Provides gRPC traffic identification, message frame parsing,
    streaming call detection, and service discovery.
    """

    GRPC_CONTENT_TYPES: Set[str] = {
        "application/grpc",
        "application/grpc-web",
        "application/grpc-web-text",
        "application/grpc+proto",
        "application/grpc+json",
    }

    GRPC_FRAME_HEADER_SIZE: int = 5

    REFLECTION_SERVICE: str = "grpc.reflection.v1alpha.ServerReflection"
    REFLECTION_METHOD: str = "ServerReflectionInfo"

    def __init__(
        self,
        event_bus: Optional[Any] = None,
    ) -> None:
        """Initialize gRPC parser.

        Args:
            event_bus: Event bus for broadcasting events.
        """
        self.event_bus = event_bus
        self._progress_callback: Optional[Callable[[str, float], Coroutine[Any, Any, None]]] = None
        self._log_callback: Optional[Callable[[str], Coroutine[Any, Any, None]]] = None
        self._discovered_services: Dict[str, GrpcServiceInfo] = {}
        self._request_history: List[GrpcRequest] = []
        self._streaming_sessions: Dict[str, Dict[str, Any]] = {}

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
        logger.info("gRPC Progress: %.1f%% - %s", percentage, message)

    async def _report_log(self, message: str) -> None:
        """Report log via callback.

        Args:
            message: Log message.
        """
        if self._log_callback:
            await self._log_callback(message)
        logger.info("gRPC: %s", message)

    def is_grpc_request(self, headers: Dict[str, str]) -> bool:
        """Check if request is gRPC based on headers.

        Args:
            headers: HTTP headers.

        Returns:
            True if gRPC request.
        """
        content_type = headers.get("content-type", "").lower()
        return any(
            content_type.startswith(ct.lower())
            for ct in self.GRPC_CONTENT_TYPES
        )

    def get_content_type(self, headers: Dict[str, str]) -> Optional[GrpcContentType]:
        """Get gRPC content type from headers.

        Args:
            headers: HTTP headers.

        Returns:
            GrpcContentType or None.
        """
        content_type = headers.get("content-type", "").lower()

        if content_type == "application/grpc":
            return GrpcContentType.GRPC
        elif content_type == "application/grpc-web":
            return GrpcContentType.GRPC_WEB
        elif content_type == "application/grpc-web-text":
            return GrpcContentType.GRPC_WEB_TEXT
        elif content_type == "application/grpc+proto":
            return GrpcContentType.GRPC_PROTO
        elif content_type == "application/grpc+json":
            return GrpcContentType.GRPC_JSON
        return None

    def parse_service_path(self, path: str) -> Tuple[str, str, str]:
        """Parse gRPC service path into components.

        Args:
            path: gRPC path (e.g., /package.Service/Method).

        Returns:
            Tuple of (package, service_name, method_name).
        """
        path = path.lstrip("/")

        if "/" not in path:
            return "", path, ""

        parts = path.split("/", 1)
        service_path = parts[0]
        method_name = parts[1] if len(parts) > 1 else ""

        service_parts = service_path.rsplit(".", 1)
        if len(service_parts) == 2:
            package = service_parts[0]
            service_name = service_parts[1]
        else:
            package = ""
            service_name = service_parts[0]

        return package, service_name, method_name

    async def parse_grpc_frames(self, data: bytes) -> List[GrpcMessageFrame]:
        """Parse gRPC message frames from raw data.

        Args:
            data: Raw gRPC message data.

        Returns:
            List of GrpcMessageFrame.
        """
        frames: List[GrpcMessageFrame] = []
        offset = 0

        while offset + self.GRPC_FRAME_HEADER_SIZE <= len(data):
            compression_flag = data[offset]
            message_length = struct.unpack(">I", data[offset + 1 : offset + 5])[0]

            if offset + self.GRPC_FRAME_HEADER_SIZE + message_length > len(data):
                break

            message_body = data[
                offset + self.GRPC_FRAME_HEADER_SIZE :
                offset + self.GRPC_FRAME_HEADER_SIZE + message_length
            ]

            frame = GrpcMessageFrame(
                compression_flag=compression_flag,
                message_length=message_length,
                message_body=message_body,
                is_compressed=(compression_flag == GrpcCompressionFlag.COMPRESSED),
                raw_bytes=data[
                    offset :
                    offset + self.GRPC_FRAME_HEADER_SIZE + message_length
                ],
            )
            frames.append(frame)

            offset += self.GRPC_FRAME_HEADER_SIZE + message_length

        return frames

    async def build_grpc_frame(
        self,
        message_body: bytes,
        compressed: bool = False,
    ) -> bytes:
        """Build gRPC message frame.

        Args:
            message_body: Message body bytes.
            compressed: Whether to mark as compressed.

        Returns:
            Complete gRPC frame bytes.
        """
        compression_flag = GrpcCompressionFlag.COMPRESSED if compressed else GrpcCompressionFlag.NONE
        message_length = len(message_body)

        frame = bytearray()
        frame.append(compression_flag)
        frame.extend(struct.pack(">I", message_length))
        frame.extend(message_body)

        return bytes(frame)

    def detect_call_type(
        self,
        request_count: int,
        response_count: int,
        has_trailers: bool = False,
    ) -> GrpcCallType:
        """Detect gRPC call type from message counts.

        Args:
            request_count: Number of request messages.
            response_count: Number of response messages.
            has_trailers: Whether response has trailers.

        Returns:
            Detected GrpcCallType.
        """
        if request_count == 1 and response_count == 1:
            return GrpcCallType.UNARY
        elif request_count == 1 and response_count > 1:
            return GrpcCallType.SERVER_STREAMING
        elif request_count > 1 and response_count == 1:
            return GrpcCallType.CLIENT_STREAMING
        elif request_count > 1 and response_count > 1:
            return GrpcCallType.BIDIRECTIONAL_STREAMING
        return GrpcCallType.UNARY

    async def parse_grpc_request(
        self,
        method: str,
        path: str,
        headers: Dict[str, str],
        body: bytes,
    ) -> Optional[GrpcRequest]:
        """Parse complete gRPC request.

        Args:
            method: HTTP method.
            path: Request path.
            headers: HTTP headers.
            body: Request body.

        Returns:
            GrpcRequest or None.
        """
        if not self.is_grpc_request(headers):
            return None

        package, service_name, method_name = self.parse_service_path(path)

        grpc_metadata = await self._parse_metadata(headers)

        frames = await self.parse_grpc_frames(body)

        call_type = self.detect_call_type(
            request_count=len(frames),
            response_count=0,
        )

        request = GrpcRequest(
            request_id=f"grpc_{int(time.time())}_{id(body)}",
            timestamp=time.time(),
            service_path=path,
            method=method_name,
            content_type=headers.get("content-type", ""),
            metadata=grpc_metadata,
            messages=frames,
            call_type=call_type,
            authority=headers.get(":authority", headers.get("host", "")),
            scheme=headers.get(":scheme", "https"),
            is_streaming=(call_type != GrpcCallType.UNARY),
        )

        await self._register_service(package, service_name, method_name, path, call_type)

        self._request_history.append(request)

        await self._report_log(
            f"gRPC请求: {path} ({call_type.value}), {len(frames)} 消息"
        )

        return request

    async def parse_grpc_response(
        self,
        status_code: int,
        headers: Dict[str, str],
        trailers: Dict[str, str],
        body: bytes,
    ) -> GrpcResponse:
        """Parse complete gRPC response.

        Args:
            status_code: HTTP status code.
            headers: Response headers.
            trailers: gRPC trailers.
            body: Response body.

        Returns:
            GrpcResponse.
        """
        grpc_status = int(trailers.get("grpc-status", "0"))
        grpc_message = trailers.get("grpc-message", "OK")

        frames = await self.parse_grpc_frames(body)

        response = GrpcResponse(
            status_code=grpc_status,
            status_message=grpc_message,
            messages=frames,
            metadata=await self._parse_metadata(headers),
            trailers=trailers,
        )

        return response

    async def _parse_metadata(self, headers: Dict[str, str]) -> GrpcMetadata:
        """Parse gRPC metadata from HTTP headers.

        Args:
            headers: HTTP headers.

        Returns:
            GrpcMetadata.
        """
        grpc_metadata = GrpcMetadata(
            headers=headers.copy(),
            content_type=headers.get("content-type", ""),
            te=headers.get("te", ""),
            user_agent=headers.get("user-agent", ""),
            authorization=headers.get("authorization", ""),
            grpc_timeout=headers.get("grpc-timeout", ""),
            grpc_encoding=headers.get("grpc-encoding", ""),
        )

        return grpc_metadata

    async def _register_service(
        self,
        package: str,
        service_name: str,
        method_name: str,
        full_path: str,
        call_type: GrpcCallType,
    ) -> None:
        """Register discovered gRPC service.

        Args:
            package: Package name.
            service_name: Service name.
            method_name: Method name.
            full_path: Full service path.
            call_type: Call type.
        """
        service_key = f"{package}.{service_name}" if package else service_name

        if service_key not in self._discovered_services:
            self._discovered_services[service_key] = GrpcServiceInfo(
                package=package,
                service_name=service_name,
                full_path=full_path,
                call_type=call_type,
                last_seen=time.time(),
            )

        service_info = self._discovered_services[service_key]
        service_info.request_count += 1
        service_info.last_seen = time.time()
        service_info.call_type = call_type

        if method_name and method_name not in service_info.methods:
            service_info.methods.append(method_name)

    def get_discovered_services(self) -> Dict[str, GrpcServiceInfo]:
        """Get all discovered gRPC services.

        Returns:
            Dictionary of service key to GrpcServiceInfo.
        """
        return self._discovered_services.copy()

    def get_service_tree(self) -> Dict[str, List[str]]:
        """Get service tree for UI display.

        Returns:
            Dictionary of service name to method list.
        """
        tree: Dict[str, List[str]] = {}

        for service_key, service_info in self._discovered_services.items():
            tree[service_key] = service_info.methods.copy()

        return tree

    def get_request_history(
        self,
        limit: int = 100,
        service_filter: Optional[str] = None,
    ) -> List[GrpcRequest]:
        """Get gRPC request history.

        Args:
            limit: Maximum records to return.
            service_filter: Filter by service path.

        Returns:
            List of GrpcRequest.
        """
        requests = self._request_history

        if service_filter:
            requests = [
                r for r in requests
                if service_filter.lower() in r.service_path.lower()
            ]

        return requests[-limit:]

    async def handle_reflection_request(
        self,
        request_body: bytes,
    ) -> Optional[bytes]:
        """Handle gRPC Server Reflection request.

        Args:
            request_body: Reflection request body.

        Returns:
            Reflection response body or None.
        """
        await self._report_log("收到gRPC Server Reflection请求")

        services = list(self._discovered_services.keys())

        reflection_response = bytearray()
        for service_name in services:
            service_info = self._discovered_services[service_name]
            reflection_response.extend(service_name.encode("utf-8"))
            reflection_response.extend(b"\n")
            for method in service_info.methods:
                reflection_response.extend(f"  {method}\n".encode("utf-8"))

        return bytes(reflection_response)

    async def start_streaming_session(
        self,
        request_id: str,
        service_path: str,
        call_type: GrpcCallType,
    ) -> str:
        """Start a new streaming session.

        Args:
            request_id: Request ID.
            service_path: Service path.
            call_type: Call type.

        Returns:
            Session ID.
        """
        session_id = f"stream_{request_id}_{int(time.time())}"

        self._streaming_sessions[session_id] = {
            "request_id": request_id,
            "service_path": service_path,
            "call_type": call_type,
            "request_messages": [],
            "response_messages": [],
            "is_active": True,
            "created_at": time.time(),
        }

        await self._report_log(f"gRPC流式会话已创建: {session_id}")

        return session_id

    async def add_stream_message(
        self,
        session_id: str,
        message: GrpcMessageFrame,
        is_request: bool = True,
    ) -> None:
        """Add message to streaming session.

        Args:
            session_id: Session ID.
            message: Message frame.
            is_request: Whether request message.
        """
        session = self._streaming_sessions.get(session_id)
        if not session:
            return

        if is_request:
            session["request_messages"].append(message)
        else:
            session["response_messages"].append(message)

    async def close_streaming_session(self, session_id: str) -> None:
        """Close streaming session.

        Args:
            session_id: Session ID.
        """
        session = self._streaming_sessions.get(session_id)
        if session:
            session["is_active"] = False
            await self._report_log(f"gRPC流式会话已关闭: {session_id}")

    def get_active_streaming_sessions(self) -> List[Dict[str, Any]]:
        """Get active streaming sessions.

        Returns:
            List of session info dictionaries.
        """
        return [
            {
                "session_id": sid,
                "service_path": info["service_path"],
                "call_type": info["call_type"].value,
                "request_count": len(info["request_messages"]),
                "response_count": len(info["response_messages"]),
                "is_active": info["is_active"],
            }
            for sid, info in self._streaming_sessions.items()
            if info["is_active"]
        ]

    def get_stats(self) -> Dict[str, Any]:
        """Get parser statistics.

        Returns:
            Statistics dictionary.
        """
        return {
            "total_services": len(self._discovered_services),
            "total_requests": len(self._request_history),
            "active_streams": sum(
                1 for s in self._streaming_sessions.values()
                if s["is_active"]
            ),
            "total_methods": sum(
                len(s.methods) for s in self._discovered_services.values()
            ),
        }
