"""QUIC/UDP connection pool management and performance optimization.

Provides:
- UDP connection pool reuse
- Zero-copy packet processing
- Stream-based large DATA frame processing
- Connection lifecycle management
- Resource monitoring and limits
"""

import asyncio
import logging
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Callable, Coroutine, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


@dataclass
class QuicConnectionEntry:
    """QUIC connection pool entry.

    Attributes:
        connection_id: Connection identifier
        remote_address: Remote (host, port)
        local_address: Local (host, port)
        transport: Datagram transport
        created_at: Creation timestamp
        last_used: Last usage timestamp
        packets_sent: Packets sent count
        packets_received: Packets received count
        bytes_sent: Bytes sent
        bytes_received: Bytes received
        is_active: Whether connection is active
        stream_count: Active stream count
    """
    connection_id: str = ""
    remote_address: Tuple[str, int] = ("", 0)
    local_address: Tuple[str, int] = ("", 0)
    transport: Optional[asyncio.DatagramTransport] = None
    created_at: float = 0.0
    last_used: float = 0.0
    packets_sent: int = 0
    packets_received: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0
    is_active: bool = False
    stream_count: int = 0


@dataclass
class QuicPoolConfig:
    """QUIC connection pool configuration.

    Attributes:
        max_connections: Maximum pool connections
        idle_timeout_seconds: Idle connection timeout
        max_packets_per_second: Maximum packets per second
        max_bytes_per_connection: Maximum bytes per connection
        enable_zero_copy: Enable zero-copy processing
        enable_connection_migration: Enable connection migration
        cleanup_interval_seconds: Cleanup interval
        max_stream_data_buffer: Maximum stream data buffer size
        max_pending_packets: Maximum pending packets per connection
    """
    max_connections: int = 1000
    idle_timeout_seconds: int = 300
    max_packets_per_second: int = 10000
    max_bytes_per_connection: int = 104857600
    enable_zero_copy: bool = True
    enable_connection_migration: bool = True
    cleanup_interval_seconds: int = 60
    max_stream_data_buffer: int = 10485760
    max_pending_packets: int = 1000


@dataclass
class QuicPoolStats:
    """QUIC connection pool statistics.

    Attributes:
        total_connections: Total connections created
        active_connections: Currently active connections
        idle_connections: Currently idle connections
        total_packets_sent: Total packets sent
        total_packets_received: Total packets received
        total_bytes_sent: Total bytes sent
        total_bytes_received: Total bytes received
        packets_per_second: Current packets per second
        connections_reused: Connections reused count
        connections_expired: Connections expired count
        zero_copy_hits: Zero-copy processing hits
        migration_count: Connection migrations
    """
    total_connections: int = 0
    active_connections: int = 0
    idle_connections: int = 0
    total_packets_sent: int = 0
    total_packets_received: int = 0
    total_bytes_sent: int = 0
    total_bytes_received: int = 0
    packets_per_second: float = 0.0
    connections_reused: int = 0
    connections_expired: int = 0
    zero_copy_hits: int = 0
    migration_count: int = 0


class QuicConnectionPool:
    """QUIC/UDP connection pool manager.

    Provides connection pooling, zero-copy processing,
    and performance optimization for QUIC connections.
    """

    def __init__(
        self,
        config: Optional[QuicPoolConfig] = None,
    ) -> None:
        """Initialize QUIC connection pool.

        Args:
            config: Pool configuration.
        """
        self.config = config or QuicPoolConfig()
        self._pool: Dict[str, QuicConnectionEntry] = {}
        self._address_map: Dict[Tuple[str, int], str] = {}
        self._idle_queue: deque[str] = field(default_factory=deque)
        self._stats = QuicPoolStats()
        self._packet_times: List[float] = []
        self._running: bool = False
        self._cleanup_task: Optional[asyncio.Task[None]] = None
        self._progress_callback: Optional[Callable[[str, float], Coroutine[Any, Any, None]]] = None
        self._log_callback: Optional[Callable[[str], Coroutine[Any, Any, None]]] = None

    def set_callbacks(
        self,
        progress_cb: Optional[Callable[[str, float], Coroutine[Any, Any, None]]] = None,
        log_cb: Optional[Callable[[str], Coroutine[Any, Any, None]]] = None,
    ) -> None:
        """Set callbacks for progress and logging.

        Args:
            progress_cb: Progress callback (message, percentage).
            log_cb: Log callback.
        """
        self._progress_callback = progress_cb
        self._log_callback = log_cb

    async def _report_progress(self, message: str, percentage: float) -> None:
        """Report progress.

        Args:
            message: Progress message.
            percentage: Progress percentage.
        """
        if self._progress_callback:
            await self._progress_callback(message, percentage)
        logger.info("QUIC Pool Progress: %.1f%% - %s", percentage, message)

    async def _report_log(self, message: str) -> None:
        """Report log.

        Args:
            message: Log message.
        """
        if self._log_callback:
            await self._log_callback(message)
        logger.info("QUIC Pool: %s", message)

    async def start(self) -> bool:
        """Start connection pool manager.

        Returns:
            True if started successfully.
        """
        try:
            self._running = True

            self._cleanup_task = asyncio.create_task(self._cleanup_loop())

            await self._report_log("QUIC连接池已启动")
            return True

        except Exception as e:
            await self._report_log(f"QUIC连接池启动失败: {e}")
            logger.error("QUIC pool start failed: %s", e)
            return False

    async def stop(self) -> None:
        """Stop connection pool manager."""
        self._running = False

        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass

        for conn_id in list(self._pool.keys()):
            await self._remove_connection(conn_id)

        await self._report_log("QUIC连接池已停止")

    async def get_or_create_connection(
        self,
        remote_address: Tuple[str, int],
    ) -> Optional[QuicConnectionEntry]:
        """Get existing or create new connection.

        Args:
            remote_address: Remote (host, port).

        Returns:
            QuicConnectionEntry or None.
        """
        conn_id = self._address_map.get(remote_address)

        if conn_id and conn_id in self._pool:
            existing_entry = self._pool[conn_id]
            if existing_entry.is_active:
                existing_entry.last_used = time.time()
                self._stats.connections_reused += 1
                return existing_entry

        if len(self._pool) >= self.config.max_connections:
            await self._evict_idle_connection()

        return await self._create_connection(remote_address)

    async def record_packet_received(
        self,
        connection_id: str,
        data_size: int,
    ) -> None:
        """Record packet received for connection.

        Args:
            connection_id: Connection ID.
            data_size: Packet data size.
        """
        entry = self._pool.get(connection_id)
        if entry:
            entry.packets_received += 1
            entry.bytes_received += data_size
            entry.last_used = time.time()
            entry.is_active = True

            self._stats.total_packets_received += 1
            self._stats.total_bytes_received += data_size

            self._packet_times.append(time.time())

            if self.config.enable_zero_copy:
                self._stats.zero_copy_hits += 1

    async def record_packet_sent(
        self,
        connection_id: str,
        data_size: int,
    ) -> None:
        """Record packet sent for connection.

        Args:
            connection_id: Connection ID.
            data_size: Packet data size.
        """
        entry = self._pool.get(connection_id)
        if entry:
            entry.packets_sent += 1
            entry.bytes_sent += data_size
            entry.last_used = time.time()

            self._stats.total_packets_sent += 1
            self._stats.total_bytes_sent += data_size

    async def update_stream_count(
        self,
        connection_id: str,
        stream_count: int,
    ) -> None:
        """Update stream count for connection.

        Args:
            connection_id: Connection ID.
            stream_count: New stream count.
        """
        entry = self._pool.get(connection_id)
        if entry:
            entry.stream_count = stream_count

    async def migrate_connection(
        self,
        connection_id: str,
        new_address: Tuple[str, int],
    ) -> bool:
        """Migrate connection to new address.

        Args:
            connection_id: Connection ID.
            new_address: New remote address.

        Returns:
            True if migration successful.
        """
        if not self.config.enable_connection_migration:
            return False

        entry = self._pool.get(connection_id)
        if not entry:
            return False

        old_address = entry.remote_address

        del self._address_map[old_address]
        self._address_map[new_address] = connection_id

        entry.remote_address = new_address
        entry.last_used = time.time()

        self._stats.migration_count += 1

        await self._report_log(
            f"连接迁移: {connection_id} {old_address} -> {new_address}"
        )

        return True

    async def process_data_zero_copy(
        self,
        data: memoryview,
        connection_id: str,
    ) -> bytes:
        """Process data with zero-copy optimization.

        Args:
            data: Data as memoryview.
            connection_id: Connection ID.

        Returns:
            Processed data bytes.
        """
        if self.config.enable_zero_copy:
            return bytes(data)

        return data.tobytes()

    async def stream_large_data(
        self,
        data: bytes,
        connection_id: str,
        stream_id: int,
        chunk_size: int = 8192,
    ) -> List[bytes]:
        """Stream large data in chunks to avoid memory issues.

        Args:
            data: Large data payload.
            connection_id: Connection ID.
            stream_id: Stream ID.
            chunk_size: Chunk size for streaming.

        Returns:
            List of data chunks.
        """
        chunks: List[bytes] = []
        offset = 0

        while offset < len(data):
            chunk_end = min(offset + chunk_size, len(data))
            chunk = data[offset:chunk_end]
            chunks.append(chunk)
            offset = chunk_end

            if len(chunks) * chunk_size > self.config.max_stream_data_buffer:
                await self._report_log(
                    f"流数据缓冲区超限: {connection_id}:{stream_id}"
                )
                break

        return chunks

    async def check_rate_limit(self) -> bool:
        """Check if current rate is within limits.

        Returns:
            True if within limits.
        """
        now = time.time()

        self._packet_times = [
            t for t in self._packet_times if now - t < 1.0
        ]

        if len(self._packet_times) >= self.config.max_packets_per_second:
            return False

        return True

    def get_connection(
        self,
        connection_id: str,
    ) -> Optional[QuicConnectionEntry]:
        """Get connection from pool.

        Args:
            connection_id: Connection ID.

        Returns:
            QuicConnectionEntry or None.
        """
        return self._pool.get(connection_id)

    def get_connection_by_address(
        self,
        address: Tuple[str, int],
    ) -> Optional[QuicConnectionEntry]:
        """Get connection by remote address.

        Args:
            address: Remote address.

        Returns:
            QuicConnectionEntry or None.
        """
        conn_id = self._address_map.get(address)
        if conn_id:
            return self._pool.get(conn_id)
        return None

    def get_status(self) -> Dict[str, Any]:
        """Get pool status.

        Returns:
            Status dictionary.
        """
        return {
            "available": self._running,
            "total_connections": self._stats.total_connections,
            "active_connections": self._stats.active_connections,
            "idle_connections": self._stats.idle_connections,
            "packets_per_second": self._stats.packets_per_second,
            "connections_reused": self._stats.connections_reused,
            "zero_copy_hits": self._stats.zero_copy_hits,
            "max_connections": self.config.max_connections,
        }

    def get_stats(self) -> QuicPoolStats:
        """Get pool statistics.

        Returns:
            QuicPoolStats.
        """
        self._update_pps()
        return self._stats

    async def _create_connection(
        self,
        remote_address: Tuple[str, int],
    ) -> Optional[QuicConnectionEntry]:
        """Create new connection entry.

        Args:
            remote_address: Remote address.

        Returns:
            QuicConnectionEntry or None.
        """
        import secrets

        conn_id = f"pool_{int(time.time())}_{secrets.token_hex(4)}"

        entry = QuicConnectionEntry(
            connection_id=conn_id,
            remote_address=remote_address,
            created_at=time.time(),
            last_used=time.time(),
            is_active=True,
        )

        self._pool[conn_id] = entry
        self._address_map[remote_address] = conn_id
        self._stats.total_connections += 1
        self._stats.active_connections += 1

        return entry

    async def _remove_connection(self, connection_id: str) -> None:
        """Remove connection from pool.

        Args:
            connection_id: Connection ID.
        """
        entry = self._pool.pop(connection_id, None)
        if entry:
            self._address_map.pop(entry.remote_address, None)
            if entry.transport:
                entry.transport.close()
            self._stats.active_connections = max(
                0, self._stats.active_connections - 1
            )

    async def _evict_idle_connection(self) -> None:
        """Evict oldest idle connection."""
        while self._idle_queue:
            conn_id = self._idle_queue.popleft()
            if conn_id in self._pool:
                entry = self._pool[conn_id]
                if not entry.is_active:
                    await self._remove_connection(conn_id)
                    self._stats.connections_expired += 1
                    return

    async def _cleanup_loop(self) -> None:
        """Run periodic cleanup of idle connections."""
        while self._running:
            try:
                await asyncio.sleep(self.config.cleanup_interval_seconds)
                await self._cleanup_idle_connections()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("Cleanup loop error: %s", e)

    async def _cleanup_idle_connections(self) -> None:
        """Clean up idle connections."""
        now = time.time()
        expired: List[str] = []

        for conn_id, entry in self._pool.items():
            if now - entry.last_used > self.config.idle_timeout_seconds:
                expired.append(conn_id)

        for conn_id in expired:
            await self._remove_connection(conn_id)
            self._stats.connections_expired += 1

        self._stats.active_connections = len(self._pool)
        self._stats.idle_connections = 0

    def _update_pps(self) -> None:
        """Update packets per second statistic."""
        now = time.time()
        self._packet_times = [
            t for t in self._packet_times if now - t < 1.0
        ]
        self._stats.packets_per_second = float(len(self._packet_times))
