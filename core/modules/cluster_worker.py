"""Cluster Worker: Worker node registration, heartbeat, sub-task execution, result reporting.

Provides:
- Node registration with master: Report node ID, system resources, supported modules
- Heartbeat: Send heartbeat every 30 seconds with current load information
- Sub-task execution engine: Receive sub-task descriptions, execute local scan modules, report progress
- Result reporting: Serialize results (Pydantic models), compress and send to master, incremental reporting, local cache with retry
- Node self-protection: Adaptive scan rate based on CPU/memory, disk space protection, graceful shutdown
"""

import asyncio
import json
import logging
import os
import platform
import time
import uuid
from enum import Enum
from dataclasses import dataclass, field
from typing import Any, Callable, Coroutine, Dict, List, Optional, Tuple

from core.modules.cluster_communication import (
    ClusterCommunicationManager,
    ClusterMessage,
    MessageType,
    NodeRole,
)

logger = logging.getLogger(__name__)


class WorkerStatus(Enum):
    """Worker node status."""
    IDLE = "idle"
    RUNNING = "running"
    STOPPING = "stopping"
    ERROR = "error"


@dataclass
class SubTaskConfig:
    """Sub-task configuration from master.

    Attributes:
        sub_task_id: Sub-task identifier
        task_id: Parent task ID
        targets: List of targets to scan
        ports: List of ports to scan
        modules: List of scan modules to use
        parameters: Additional parameters
    """
    sub_task_id: str = ""
    task_id: str = ""
    targets: List[str] = field(default_factory=list)
    ports: List[int] = field(default_factory=list)
    modules: List[str] = field(default_factory=list)
    parameters: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ScanResult:
    """Scan result from sub-task execution.

    Attributes:
        result_id: Unique result identifier
        sub_task_id: Sub-task identifier
        target: Scanned target
        port: Scanned port
        protocol: Protocol detected
        service: Service detected
        fingerprint: Service fingerprint
        vulnerabilities: List of vulnerabilities found
        metadata: Additional metadata
    """
    result_id: str = ""
    sub_task_id: str = ""
    target: str = ""
    port: int = 0
    protocol: str = ""
    service: str = ""
    fingerprint: str = ""
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class WorkerConfig:
    """Worker node configuration.

    Attributes:
        node_id: Node identifier
        master_uri: Master WebSocket URI
        psk: Pre-shared key
        heartbeat_interval: Heartbeat interval in seconds
        max_concurrent_tasks: Maximum concurrent tasks
        result_batch_size: Result batch size for reporting
        retry_count: Retry count for failed operations
        max_cpu_percent: Maximum CPU usage percentage
        max_memory_percent: Maximum memory usage percentage
        max_disk_percent: Maximum disk usage percentage
        supported_modules: List of supported scan modules
    """
    node_id: str = ""
    master_uri: str = ""
    psk: str = ""
    heartbeat_interval: int = 30
    max_concurrent_tasks: int = 5
    result_batch_size: int = 100
    retry_count: int = 3
    max_cpu_percent: float = 80.0
    max_memory_percent: float = 80.0
    max_disk_percent: float = 90.0
    supported_modules: List[str] = field(default_factory=lambda: [
        "port_scan",
        "service_detection",
        "vulnerability_scan",
        "poc_verify",
        "asset_discovery",
    ])


class ResourceMonitor:
    """Monitors system resources for self-protection.

    Tracks CPU, memory, and disk usage to adjust scan rate dynamically.
    """

    def __init__(
        self,
        max_cpu: float = 80.0,
        max_memory: float = 80.0,
        max_disk: float = 90.0,
    ) -> None:
        """Initialize resource monitor.

        Args:
            max_cpu: Maximum CPU usage percentage.
            max_memory: Maximum memory usage percentage.
            max_disk: Maximum disk usage percentage.
        """
        self.max_cpu = max_cpu
        self.max_memory = max_memory
        self.max_disk = max_disk

    def get_cpu_usage(self) -> float:
        """Get current CPU usage percentage.

        Returns:
            CPU usage percentage.
        """
        try:
            import psutil
            cpu: float = psutil.cpu_percent(interval=0.1)
            return cpu
        except ImportError:
            return 0.0

    def get_memory_usage(self) -> float:
        """Get current memory usage percentage.

        Returns:
            Memory usage percentage.
        """
        try:
            import psutil
            mem: float = psutil.virtual_memory().percent
            return mem
        except ImportError:
            return 0.0

    def get_disk_usage(self) -> float:
        """Get current disk usage percentage.

        Returns:
            Disk usage percentage.
        """
        try:
            import psutil
            disk: float = psutil.disk_usage("/").percent
            return disk
        except ImportError:
            return 0.0

    def is_resources_available(self) -> Tuple[bool, str]:
        """Check if system resources are available for scanning.

        Returns:
            Tuple of (available, reason).
        """
        cpu = self.get_cpu_usage()
        memory = self.get_memory_usage()
        disk = self.get_disk_usage()

        if cpu > self.max_cpu:
            return False, f"CPU usage too high: {cpu:.1f}%"

        if memory > self.max_memory:
            return False, f"Memory usage too high: {memory:.1f}%"

        if disk > self.max_disk:
            return False, f"Disk usage too high: {disk:.1f}%"

        return True, "Resources available"

    def get_recommended_concurrency(self, base_concurrency: int) -> int:
        """Get recommended concurrency based on resource usage.

        Args:
            base_concurrency: Base concurrency level.

        Returns:
            Recommended concurrency.
        """
        cpu = self.get_cpu_usage()
        memory = self.get_memory_usage()

        cpu_factor = max(0.1, 1.0 - (cpu / 100.0))
        memory_factor = max(0.1, 1.0 - (memory / 100.0))

        factor = min(cpu_factor, memory_factor)

        return max(1, int(base_concurrency * factor))


class ResultCache:
    """Caches scan results for reliable reporting.

    Handles local caching, batch reporting, and retry on failure.
    """

    def __init__(self, batch_size: int = 100, cache_path: str = "") -> None:
        """Initialize result cache.

        Args:
            batch_size: Number of results per batch.
            cache_path: Path for persistent cache.
        """
        self.batch_size = batch_size
        self.cache_path = cache_path
        self._pending_results: List[Dict[str, Any]] = []
        self._cache_file = os.path.join(cache_path, "result_cache.json") if cache_path else ""

        if cache_path:
            os.makedirs(cache_path, exist_ok=True)
            self._load_cache()

    def add_result(self, result: Dict[str, Any]) -> None:
        """Add result to cache.

        Args:
            result: Result dict to cache.
        """
        self._pending_results.append(result)

        if len(self._pending_results) >= self.batch_size:
            self._save_cache()

    def get_batch(self) -> List[Dict[str, Any]]:
        """Get batch of results for reporting.

        Returns:
            List of result dicts.
        """
        batch = self._pending_results[:self.batch_size]
        self._pending_results = self._pending_results[self.batch_size:]

        return batch

    def has_pending(self) -> bool:
        """Check if there are pending results.

        Returns:
            True if pending results exist.
        """
        return len(self._pending_results) > 0

    def _save_cache(self) -> None:
        """Save cache to disk."""
        if not self._cache_file:
            return

        try:
            with open(self._cache_file, "w", encoding="utf-8") as f:
                json.dump(self._pending_results, f, ensure_ascii=False, indent=2)
        except Exception as e:
            logger.error(f"Failed to save result cache: {e}")

    def _load_cache(self) -> None:
        """Load cache from disk."""
        if not self._cache_file or not os.path.exists(self._cache_file):
            return

        try:
            with open(self._cache_file, "r", encoding="utf-8") as f:
                self._pending_results = json.load(f)
        except Exception as e:
            logger.error(f"Failed to load result cache: {e}")


class ClusterWorker:
    """Worker node for distributed scan cluster.

    Registers with master, receives and executes sub-tasks,
    reports results, and provides self-protection.
    """

    def __init__(self, config: WorkerConfig) -> None:
        """Initialize cluster worker.

        Args:
            config: Worker configuration.
        """
        self.config = config
        self.status = WorkerStatus.IDLE

        self.comm_manager = ClusterCommunicationManager(
            node_id=config.node_id,
            role=NodeRole.WORKER,
            psk=config.psk,
        )

        self.resource_monitor = ResourceMonitor(
            max_cpu=config.max_cpu_percent,
            max_memory=config.max_memory_percent,
            max_disk=config.max_disk_percent,
        )

        self.result_cache = ResultCache(
            batch_size=config.result_batch_size,
            cache_path="",
        )

        self._current_tasks: Dict[str, SubTaskConfig] = {}
        self._scan_modules: Dict[str, Callable[..., Coroutine[Any, Any, List[ScanResult]]]] = {}
        self._running = False
        self._token = ""

        self._setup_message_handlers()

    def register_scan_module(
        self,
        module_name: str,
        module_func: Callable[..., Coroutine[Any, Any, List[ScanResult]]],
    ) -> None:
        """Register a scan module.

        Args:
            module_name: Module name.
            module_func: Async function to execute the module.
        """
        self._scan_modules[module_name] = module_func

    async def start(self) -> bool:
        """Start worker node.

        Returns:
            True if started successfully.
        """
        if not await self.comm_manager.connect_to_master(self.config.master_uri):
            return False

        self._running = True

        await self._register_with_master()

        asyncio.create_task(self._heartbeat_loop())
        asyncio.create_task(self._result_report_loop())

        logger.info(f"Worker started: {self.config.node_id}")

        return True

    async def stop(self) -> None:
        """Stop worker node gracefullyfully."""
        self.status = WorkerStatus.STOPPING
        self._running = False

        await self._wait_for_current_tasks()

        await self.comm_manager.stop()

        logger.info(f"Worker stopped: {self.config.node_id}")

    async def _register_with_master(self) -> None:
        """Register with master node."""
        system_info = {
            "os": platform.system(),
            "os_version": platform.version(),
            "architecture": platform.machine(),
            "hostname": platform.node(),
            "python_version": platform.python_version(),
        }

        await self.comm_manager.send_to_master(
            ClusterMessage(
                message_type=MessageType.REGISTER,
                sender_id=self.config.node_id,
                payload={
                    "ip_address": self._get_local_ip(),
                    "system_info": system_info,
                    "supported_modules": self.config.supported_modules,
                },
            ),
        )

    async def _heartbeat_loop(self) -> None:
        """Send periodic heartbeats to master."""
        while self._running:
            await asyncio.sleep(self.config.heartbeat_interval)

            available, _ = self.resource_monitor.is_resources_available()

            await self.comm_manager.send_to_master(
                ClusterMessage(
                    message_type=MessageType.HEARTBEAT,
                    sender_id=self.config.node_id,
                    payload={
                        "current_load": len(self._current_tasks),
                        "resources_available": available,
                        "cpu_usage": self.resource_monitor.get_cpu_usage(),
                        "memory_usage": self.resource_monitor.get_memory_usage(),
                    },
                ),
            )

    async def _result_report_loop(self) -> None:
        """Periodically report cached results to master."""
        while self._running:
            await asyncio.sleep(5)

            if not self.result_cache.has_pending():
                continue

            batch = self.result_cache.get_batch()

            if batch:
                success = await self._report_results(batch)

                if not success:
                    self.result_cache._pending_results = batch + self.result_cache._pending_results

    async def _report_results(self, results: List[Dict[str, Any]]) -> bool:
        """Report results to master.

        Args:
            results: List of result dicts.

        Returns:
            True if reported successfully.
        """
        if not results:
            return True

        sub_task_id = results[0].get("sub_task_id", "")

        message = ClusterMessage(
            message_type=MessageType.TASK_RESULT,
            sender_id=self.config.node_id,
            payload={
                "sub_task_id": sub_task_id,
                "results": results,
            },
        )

        return await self.comm_manager.send_to_master(message)

    def _setup_message_handlers(self) -> None:
        """Setup message handlers."""
        self.comm_manager.register_handler(MessageType.REGISTER_ACK, self._handle_register_ack)
        self.comm_manager.register_handler(MessageType.HEARTBEAT_ACK, self._handle_heartbeat_ack)
        self.comm_manager.register_handler(MessageType.TASK_ASSIGN, self._handle_task_assign)
        self.comm_manager.register_handler(MessageType.TASK_CANCEL, self._handle_task_cancel)
        self.comm_manager.register_handler(MessageType.CONFIG_UPDATE, self._handle_config_update)

    async def _handle_register_ack(self, message: ClusterMessage) -> None:
        """Handle registration acknowledgment.

        Args:
            message: Register ACK message.
        """
        payload = message.payload
        self._token = payload.get("token", "")

        config = payload.get("config", {})
        if config:
            self.config.heartbeat_interval = config.get("heartbeat_interval", 30)
            self.config.max_concurrent_tasks = config.get("max_concurrent_tasks", 5)
            self.config.result_batch_size = config.get("result_batch_size", 100)

        logger.info(f"Registered with master, token received")

    async def _handle_heartbeat_ack(self, message: ClusterMessage) -> None:
        """Handle heartbeat acknowledgment.

        Args:
            message: Heartbeat ACK message.
        """
        pass

    async def _handle_task_assign(self, message: ClusterMessage) -> None:
        """Handle task assignment.

        Args:
            message: Task assignment message.
        """
        if len(self._current_tasks) >= self.config.max_concurrent_tasks:
            logger.warning("Maximum concurrent tasks reached, rejecting task")
            return

        available, reason = self.resource_monitor.is_resources_available()
        if not available:
            logger.warning(f"Resources not available: {reason}")
            return

        payload = message.payload

        sub_task_config = SubTaskConfig(
            sub_task_id=payload.get("sub_task_id", ""),
            task_id=payload.get("task_id", ""),
            targets=payload.get("targets", []),
            ports=payload.get("ports", []),
            modules=payload.get("modules", []),
            parameters=payload.get("parameters", {}),
        )

        self._current_tasks[sub_task_config.sub_task_id] = sub_task_config

        asyncio.create_task(self._execute_sub_task(sub_task_config))

    async def _handle_task_cancel(self, message: ClusterMessage) -> None:
        """Handle task cancellation.

        Args:
            message: Task cancel message.
        """
        sub_task_id = message.payload.get("sub_task_id", "")

        if sub_task_id in self._current_tasks:
            del self._current_tasks[sub_task_id]

            logger.info(f"Task cancelled: {sub_task_id}")

    async def _handle_config_update(self, message: ClusterMessage) -> None:
        """Handle configuration update.

        Args:
            message: Config update message.
        """
        config = message.payload

        if "heartbeat_interval" in config:
            self.config.heartbeat_interval = config["heartbeat_interval"]

        if "max_concurrent_tasks" in config:
            self.config.max_concurrent_tasks = config["max_concurrent_tasks"]

        if "result_batch_size" in config:
            self.config.result_batch_size = config["result_batch_size"]

        logger.info("Configuration updated from master")

    async def _execute_sub_task(self, config: SubTaskConfig) -> None:
        """Execute assigned sub-task.

        Args:
            config: Sub-task configuration.
        """
        self.status = WorkerStatus.RUNNING

        start_time = time.time()
        total_targets = len(config.targets)
        processed = 0

        try:
            for module_name in config.modules:
                module_func = self._scan_modules.get(module_name)
                if not module_func:
                    logger.warning(f"Module not available: {module_name}")
                    continue

                recommended_concurrency = self.resource_monitor.get_recommended_concurrency(
                    self.config.max_concurrent_tasks,
                )

                results = await module_func(
                    targets=config.targets,
                    ports=config.ports,
                    parameters=config.parameters,
                    concurrency=recommended_concurrency,
                )

                for result in results:
                    result_data = {
                        "result_id": result.result_id,
                        "sub_task_id": config.sub_task_id,
                        "target": result.target,
                        "port": result.port,
                        "protocol": result.protocol,
                        "service": result.service,
                        "fingerprint": result.fingerprint,
                        "vulnerabilities": result.vulnerabilities,
                        "metadata": result.metadata,
                    }

                    self.result_cache.add_result(result_data)

                processed += len(config.targets)

                progress = (processed / total_targets) * 100 if total_targets > 0 else 100

                await self._report_progress(config.sub_task_id, progress, len(results))

            elapsed = time.time() - start_time

            await self.comm_manager.send_to_master(
                ClusterMessage(
                    message_type=MessageType.TASK_COMPLETE,
                    sender_id=self.config.node_id,
                    payload={
                        "sub_task_id": config.sub_task_id,
                        "success": True,
                        "elapsed": elapsed,
                        "results_count": processed,
                    },
                ),
            )

        except Exception as e:
            logger.error(f"Sub-task execution failed: {e}")

            await self.comm_manager.send_to_master(
                ClusterMessage(
                    message_type=MessageType.TASK_COMPLETE,
                    sender_id=self.config.node_id,
                    payload={
                        "sub_task_id": config.sub_task_id,
                        "success": False,
                        "error": str(e),
                    },
                ),
            )

        finally:
            if config.sub_task_id in self._current_tasks:
                del self._current_tasks[config.sub_task_id]

            self.status = WorkerStatus.IDLE

    async def _report_progress(
        self,
        sub_task_id: str,
        progress: float,
        result_count: int,
    ) -> None:
        """Report sub-task progress to master.

        Args:
            sub_task_id: Sub-task identifier.
            progress: Progress percentage.
            result_count: Number of results so far.
        """
        await self.comm_manager.send_to_master(
            ClusterMessage(
                message_type=MessageType.TASK_PROGRESS,
                sender_id=self.config.node_id,
                payload={
                    "sub_task_id": sub_task_id,
                    "progress": progress,
                    "result_count": result_count,
                },
            ),
        )

    async def _wait_for_current_tasks(self) -> None:
        """Wait for current tasks to complete."""
        while self._current_tasks:
            await asyncio.sleep(1)

    @staticmethod
    def _get_local_ip() -> str:
        """Get local IP address.

        Returns:
            Local IP address.
        """
        try:
            import socket
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip: str = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"
