"""HTTP/3 proxy main logic with existing proxy system integration.

Provides:
- HTTP/3 proxy server with UDP listening
- Integration with existing interception rules and breakpoint modification
- Protocol downgrade and adaptive fallback
- Web Fuzzer and passive scanning engine linkage
- QUIC connection status panel
- Alt-Svc header management
"""

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Coroutine, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


@dataclass
class Http3ProxyConfig:
    """HTTP/3 proxy configuration.

    Attributes:
        listen_port: UDP listen port
        listen_host: Listen host
        max_connections: Maximum concurrent connections
        max_streams_per_connection: Maximum streams per connection
        enable_0rtt: Enable 0-RTT early data
        enable_push: Enable server push
        alt_svc_port: Alt-Svc announcement port
        enable_webtransport: Enable WebTransport support
        qpack_max_table_capacity: QPACK max table capacity
        max_field_section_size: Maximum header list size
        timeout_seconds: Connection timeout
    """
    listen_port: int = 443
    listen_host: str = "0.0.0.0"
    max_connections: int = 1000
    max_streams_per_connection: int = 100
    enable_0rtt: bool = False
    enable_push: bool = True
    alt_svc_port: int = 443
    enable_webtransport: bool = False
    qpack_max_table_capacity: int = 4096
    max_field_section_size: int = 65536
    timeout_seconds: int = 30


@dataclass
class Http3TrafficRecord:
    """HTTP/3 traffic record.

    Attributes:
        record_id: Unique record ID
        timestamp: Request timestamp
        method: HTTP method
        path: Request path
        authority: Request authority
        status_code: Response status code
        request_headers: Request headers
        response_headers: Response headers
        request_body: Request body
        response_body: Response body
        stream_id: QUIC stream ID
        connection_id: QUIC connection ID
        protocol: Protocol version (H3)
        duration_ms: Request duration in milliseconds
        is_intercepted: Whether request was intercepted
        is_modified: Whether request/response was modified
        is_webtransport: Whether WebTransport session
    """
    record_id: str = ""
    timestamp: float = 0.0
    method: str = ""
    path: str = ""
    authority: str = ""
    status_code: int = 0
    request_headers: Dict[str, str] = field(default_factory=dict)
    response_headers: Dict[str, str] = field(default_factory=dict)
    request_body: bytes = b""
    response_body: bytes = b""
    stream_id: int = 0
    connection_id: str = ""
    protocol: str = "H3"
    duration_ms: float = 0.0
    is_intercepted: bool = False
    is_modified: bool = False
    is_webtransport: bool = False


@dataclass
class QuicConnectionStatus:
    """QUIC connection status for panel display.

    Attributes:
        connection_id: Connection ID
        client_address: Client address
        state: Connection state
        stream_count: Active stream count
        data_sent: Bytes sent
        data_received: Bytes received
        tls_complete: TLS handshake complete
        last_activity: Last activity timestamp
        created_at: Connection creation timestamp
    """
    connection_id: str = ""
    client_address: str = ""
    state: str = ""
    stream_count: int = 0
    data_sent: int = 0
    data_received: int = 0
    tls_complete: bool = False
    last_activity: float = 0.0
    created_at: float = 0.0


class Http3Proxy:
    """HTTP/3 proxy server.

    Provides HTTP/3 proxy with QUIC/UDP support,
    integration with existing proxy system, and
    protocol downgrade capabilities.
    """

    PROTOCOL_H3: str = "H3"
    PROTOCOL_H2: str = "H2"
    PROTOCOL_H1: str = "H1.1"

    def __init__(
        self,
        config: Optional[Http3ProxyConfig] = None,
        quic_stack: Optional[Any] = None,
        quic_tls: Optional[Any] = None,
        http3_processor: Optional[Any] = None,
        connection_pool: Optional[Any] = None,
        ca_manager: Optional[Any] = None,
        event_bus: Optional[Any] = None,
        interceptor: Optional[Any] = None,
        passive_scanner: Optional[Any] = None,
        web_fuzzer: Optional[Any] = None,
    ) -> None:
        """Initialize HTTP/3 proxy.

        Args:
            config: Proxy configuration.
            quic_stack: QUIC protocol stack.
            quic_tls: QUIC TLS handshake handler.
            http3_processor: HTTP/3 frame processor.
            connection_pool: QUIC connection pool.
            ca_manager: Certificate authority manager.
            event_bus: Event bus.
            interceptor: Request/response interceptor.
            passive_scanner: Passive scanning engine.
            web_fuzzer: Web Fuzzer engine.
        """
        self.config = config or Http3ProxyConfig()
        self.quic_stack = quic_stack
        self.quic_tls = quic_tls
        self.http3_processor = http3_processor
        self.connection_pool = connection_pool
        self.ca_manager = ca_manager
        self.event_bus = event_bus
        self.interceptor = interceptor
        self.passive_scanner = passive_scanner
        self.web_fuzzer = web_fuzzer

        self._transport: Optional[asyncio.DatagramTransport] = None
        self._protocol: Optional[asyncio.DatagramProtocol] = None
        self._running: bool = False
        self._traffic_records: List[Http3TrafficRecord] = []
        self._connection_statuses: Dict[str, QuicConnectionStatus] = {}
        self._progress_callback: Optional[Callable[[str, float], Coroutine[Any, Any, None]]] = None
        self._log_callback: Optional[Callable[[str], Coroutine[Any, Any, None]]] = None
        self._request_callback: Optional[
            Callable[[Http3TrafficRecord], Coroutine[Any, Any, Optional[Http3TrafficRecord]]]
        ] = None

    def set_callbacks(
        self,
        progress_cb: Optional[Callable[[str, float], Coroutine[Any, Any, None]]] = None,
        log_cb: Optional[Callable[[str], Coroutine[Any, Any, None]]] = None,
        request_cb: Optional[
            Callable[[Http3TrafficRecord], Coroutine[Any, Any, Optional[Http3TrafficRecord]]]
        ] = None,
    ) -> None:
        """Set callbacks for progress, logging, and request handling.

        Args:
            progress_cb: Progress callback (message, percentage).
            log_cb: Log callback.
            request_cb: Request handling callback.
        """
        self._progress_callback = progress_cb
        self._log_callback = log_cb
        self._request_callback = request_cb

    async def _report_progress(self, message: str, percentage: float) -> None:
        """Report progress.

        Args:
            message: Progress message.
            percentage: Progress percentage.
        """
        if self._progress_callback:
            await self._progress_callback(message, percentage)
        logger.info("HTTP/3 Proxy Progress: %.1f%% - %s", percentage, message)

    async def _report_log(self, message: str) -> None:
        """Report log.

        Args:
            message: Log message.
        """
        if self._log_callback:
            await self._log_callback(message)
        logger.info("HTTP/3 Proxy: %s", message)

    async def start(self) -> bool:
        """Start HTTP/3 proxy server.

        Returns:
            True if started successfully.
        """
        try:
            await self._report_progress("启动HTTP/3代理", 10)

            loop = asyncio.get_event_loop()

            class QuicProtocol(asyncio.DatagramProtocol):
                """QUIC UDP protocol handler."""

                def __init__(self, proxy: "Http3Proxy") -> None:
                    """Initialize protocol.

                    Args:
                        proxy: HTTP/3 proxy instance.
                    """
                    self.proxy = proxy

                def datagram_received(
                    self,
                    data: bytes,
                    addr: Tuple[str, int],
                ) -> None:
                    """Handle received datagram.

                    Args:
                        data: UDP payload.
                        addr: Source address.
                    """
                    asyncio.create_task(self.proxy._handle_datagram(data, addr))

                def error_received(self, exc: Exception) -> None:
                    """Handle error.

                    Args:
                        exc: Exception.
                    """
                    logger.error("QUIC UDP error: %s", exc)

            protocol_instance = QuicProtocol(self)
            self._protocol = protocol_instance

            transport, _ = await loop.create_datagram_endpoint(
                lambda: protocol_instance,
                local_addr=(self.config.listen_host, self.config.listen_port),
            )
            self._transport = transport

            self._running = True

            await self._report_log(
                f"HTTP/3代理已启动，监听 {self.config.listen_host}:{self.config.listen_port}/udp"
            )

            if self.quic_stack:
                await self.quic_stack.start(self.config.listen_port)

            await self._report_progress("HTTP/3代理启动完成", 100)

            return True

        except Exception as e:
            await self._report_log(f"HTTP/3代理启动失败: {e}")
            logger.error("HTTP/3 proxy start failed: %s", e)
            return False

    async def stop(self) -> None:
        """Stop HTTP/3 proxy server."""
        self._running = False

        if self._transport:
            self._transport.close()
            self._transport = None

        if self.quic_stack:
            await self.quic_stack.stop()

        await self._report_log("HTTP/3代理已停止")

    async def _handle_datagram(
        self,
        data: bytes,
        client_address: Tuple[str, int],
    ) -> None:
        """Handle incoming UDP datagram.

        Args:
            data: UDP payload.
            client_address: Client address.
        """
        if not self._running or len(data) < 1:
            return

        try:
            if self.quic_stack:
                response = await self.quic_stack.process_packet(data, client_address)

                if response:
                    if self._transport:
                        self._transport.sendto(response, client_address)

        except Exception as e:
            logger.error("Datagram handling failed: %s", e)

    async def handle_http3_request(
        self,
        method: str,
        path: str,
        authority: str,
        headers: Dict[str, str],
        body: bytes,
        stream_id: int,
        connection_id: str,
    ) -> Optional[Http3TrafficRecord]:
        """Handle HTTP/3 request through proxy pipeline.

        Args:
            method: HTTP method.
            path: Request path.
            authority: Request authority.
            headers: Request headers.
            body: Request body.
            stream_id: Stream ID.
            connection_id: Connection ID.

        Returns:
            Http3TrafficRecord or None.
        """
        start_time = time.time()

        record = Http3TrafficRecord(
            record_id=f"h3_{int(start_time)}_{stream_id}",
            timestamp=start_time,
            method=method,
            path=path,
            authority=authority,
            request_headers=headers.copy(),
            request_body=body,
            stream_id=stream_id,
            connection_id=connection_id,
            protocol=self.PROTOCOL_H3,
        )

        await self._report_log(f"H3请求: {method} {authority}{path}")

        if self._request_callback:
            modified_record = await self._request_callback(record)
            if modified_record:
                record = modified_record

        if self.interceptor:
            intercepted = await self.interceptor.intercept_request(
                method=record.method,
                url=f"{record.authority}{record.path}",
                headers=record.request_headers,
                body=record.request_body,
                protocol=self.PROTOCOL_H3,
            )
            if intercepted:
                record.is_intercepted = True
                if intercepted.get("modified"):
                    record.method = intercepted.get("method", record.method)
                    record.path = intercepted.get("path", record.path)
                    record.request_headers = intercepted.get("headers", record.request_headers)
                    record.request_body = intercepted.get("body", record.request_body)
                    record.is_modified = True

        if self.passive_scanner:
            await self.passive_scanner.scan_request(
                method=record.method,
                url=f"{record.authority}{record.path}",
                headers=record.request_headers,
                body=record.request_body,
                protocol=self.PROTOCOL_H3,
            )

        self._traffic_records.append(record)

        await self._broadcast_traffic_update(record)

        return record

    async def handle_http3_response(
        self,
        record: Http3TrafficRecord,
        status_code: int,
        headers: Dict[str, str],
        body: bytes,
    ) -> Http3TrafficRecord:
        """Handle HTTP/3 response through proxy pipeline.

        Args:
            record: Traffic record.
            status_code: Response status code.
            headers: Response headers.
            body: Response body.

        Returns:
            Updated Http3TrafficRecord.
        """
        record.status_code = status_code
        record.response_headers = headers.copy()
        record.response_body = body
        record.duration_ms = (time.time() - record.timestamp) * 1000

        await self._report_log(
            f"H3响应: {record.method} {record.authority}{record.path} -> {status_code}"
        )

        if self.interceptor:
            intercepted = await self.interceptor.intercept_response(
                status_code=record.status_code,
                headers=record.response_headers,
                body=record.response_body,
                protocol=self.PROTOCOL_H3,
            )
            if intercepted:
                record.is_intercepted = True
                if intercepted.get("modified"):
                    record.status_code = intercepted.get("status_code", record.status_code)
                    record.response_headers = intercepted.get("headers", record.response_headers)
                    record.response_body = intercepted.get("body", record.response_body)
                    record.is_modified = True

        if self.passive_scanner:
            await self.passive_scanner.scan_response(
                status_code=record.status_code,
                headers=record.response_headers,
                body=record.response_body,
                protocol=self.PROTOCOL_H3,
            )

        if self.web_fuzzer:
            await self.web_fuzzer.add_to_queue(
                method=record.method,
                url=f"{record.authority}{record.path}",
                headers=record.request_headers,
                body=record.request_body,
                protocol=self.PROTOCOL_H3,
            )

        await self._broadcast_traffic_update(record)

        return record

    async def send_to_web_fuzzer(self, record: Http3TrafficRecord) -> bool:
        """Send request to Web Fuzzer for testing.

        Args:
            record: Traffic record.

        Returns:
            True if sent successfully.
        """
        if not self.web_fuzzer:
            return False

        try:
            await self.web_fuzzer.add_to_queue(
                method=record.method,
                url=f"{record.authority}{record.path}",
                headers=record.request_headers,
                body=record.request_body,
                protocol=self.PROTOCOL_H3,
            )
            await self._report_log(f"已发送到Web Fuzzer: {record.record_id}")
            return True
        except Exception as e:
            await self._report_log(f"发送到Web Fuzzer失败: {e}")
            return False

    def get_traffic_records(
        self,
        protocol_filter: Optional[str] = None,
        limit: int = 100,
    ) -> List[Http3TrafficRecord]:
        """Get traffic records with optional filtering.

        Args:
            protocol_filter: Protocol filter (H3/H2/H1.1).
            limit: Maximum records to return.

        Returns:
            List of Http3TrafficRecord.
        """
        records = self._traffic_records

        if protocol_filter:
            records = [r for r in records if r.protocol == protocol_filter]

        return records[-limit:]

    def get_connection_statuses(self) -> List[QuicConnectionStatus]:
        """Get QUIC connection statuses for panel display.

        Returns:
            List of QuicConnectionStatus.
        """
        return list(self._connection_statuses.values())

    def update_connection_status(
        self,
        connection_id: str,
        status: QuicConnectionStatus,
    ) -> None:
        """Update QUIC connection status.

        Args:
            connection_id: Connection ID.
            status: Connection status.
        """
        self._connection_statuses[connection_id] = status

    def remove_connection_status(self, connection_id: str) -> None:
        """Remove QUIC connection status.

        Args:
            connection_id: Connection ID.
        """
        self._connection_statuses.pop(connection_id, None)

    def generate_alt_svc_header(self, port: Optional[int] = None) -> str:
        """Generate Alt-Svc header for HTTP/3 announcement.

        Args:
            port: Alt-Svc port.

        Returns:
            Alt-Svc header value.
        """
        alt_port = port or self.config.alt_svc_port
        return f'h3=":{alt_port}"; ma=86400, h3-29=":{alt_port}"; ma=86400'

    def should_downgrade_protocol(
        self,
        client_address: Tuple[str, int],
        request_headers: Dict[str, str],
    ) -> str:
        """Determine if protocol should be downgraded.

        Args:
            client_address: Client address.
            request_headers: Request headers.

        Returns:
            Protocol to use (H3/H2/H1.1).
        """
        if not self._running:
            return self.PROTOCOL_H2

        user_agent = request_headers.get("user-agent", "").lower()

        if "quic" not in user_agent and "http/3" not in user_agent:
            return self.PROTOCOL_H2

        if self.connection_pool:
            pool_status = self.connection_pool.get_status()
            if pool_status.get("available", False) is False:
                return self.PROTOCOL_H2

        return self.PROTOCOL_H3

    async def handle_webtransport_session(
        self,
        stream_id: int,
        connection_id: str,
        headers: Dict[str, str],
    ) -> bool:
        """Handle WebTransport session.

        Args:
            stream_id: Stream ID.
            connection_id: Connection ID.
            headers: Request headers.

        Returns:
            True if WebTransport session accepted.
        """
        if not self.config.enable_webtransport:
            return False

        method = headers.get(":method", "")
        protocol = headers.get(":protocol", "")

        if method == "CONNECT" and protocol == "webtransport":
            await self._report_log(f"WebTransport会话已建立: {connection_id}:{stream_id}")

            record = Http3TrafficRecord(
                record_id=f"wt_{int(time.time())}_{stream_id}",
                timestamp=time.time(),
                method="CONNECT",
                path=headers.get(":path", "/"),
                authority=headers.get(":authority", ""),
                request_headers=headers,
                stream_id=stream_id,
                connection_id=connection_id,
                protocol=self.PROTOCOL_H3,
                is_webtransport=True,
            )

            self._traffic_records.append(record)

            return True

        return False

    async def _broadcast_traffic_update(self, record: Http3TrafficRecord) -> None:
        """Broadcast traffic update to event bus.

        Args:
            record: Traffic record.
        """
        if self.event_bus:
            try:
                await self.event_bus.emit("http3_traffic", {
                    "record_id": record.record_id,
                    "method": record.method,
                    "path": record.path,
                    "authority": record.authority,
                    "status_code": record.status_code,
                    "protocol": record.protocol,
                    "timestamp": record.timestamp,
                    "is_intercepted": record.is_intercepted,
                    "is_modified": record.is_modified,
                })
            except Exception as e:
                logger.error("Traffic update broadcast failed: %s", e)

    def get_stats(self) -> Dict[str, Any]:
        """Get proxy statistics.

        Returns:
            Statistics dictionary.
        """
        return {
            "running": self._running,
            "total_requests": len(self._traffic_records),
            "active_connections": len(self._connection_statuses),
            "intercepted_requests": sum(
                1 for r in self._traffic_records if r.is_intercepted
            ),
            "modified_requests": sum(
                1 for r in self._traffic_records if r.is_modified
            ),
            "webtransport_sessions": sum(
                1 for r in self._traffic_records if r.is_webtransport
            ),
            "listen_port": self.config.listen_port,
            "protocol": self.PROTOCOL_H3,
        }
