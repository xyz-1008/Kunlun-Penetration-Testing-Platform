"""Cluster Master: Task scheduling, result aggregation, node management, high availability.

Provides:
- Task scheduling engine: Receive scan tasks, split into sub-tasks, maintain worker pool, assign with strategies (round-robin, least-load, weighted), priority queue
- Result aggregator: Receive sub-task results, deduplicate by IP+port+fingerprints, merge vulnerability findings, real-time progress tracking
- Node management: Worker registration, heartbeat detection (30s default), offline handling with task reassignment, blacklist for failing nodes
- High availability: State persistence to SQLite, task recovery after restart, standby master interface
"""

import asyncio
import json
import logging
import os
import sqlite3
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Callable, Coroutine, Dict, List, Optional, Set, Tuple

from core.modules.cluster_communication import (
    ClusterCommunicationManager,
    ClusterMessage,
    MessageType,
    NodeRole,
)

logger = logging.getLogger(__name__)


class TaskStatus(Enum):
    """Task status."""
    PENDING = "pending"
    ASSIGNED = "assigned"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class TaskPriority(Enum):
    """Task priority levels."""
    LOW = 0
    NORMAL = 1
    HIGH = 2
    URGENT = 3


class NodeStatus(Enum):
    """Worker node status."""
    ONLINE = "online"
    OFFLINE = "offline"
    BUSY = "busy"
    BLACKLISTED = "blacklisted"


class AllocationStrategy(Enum):
    """Task allocation strategies."""
    ROUND_ROBIN = "round_robin"
    LEAST_LOAD = "least_load"
    WEIGHTED = "weighted"


@dataclass
class ScanTask:
    """Scan task definition.

    Attributes:
        task_id: Unique task identifier
        name: Task name
        targets: List of target IPs/domains
        ports: List of ports to scan
        modules: List of scan modules to use
        priority: Task priority
        status: Task status
        created_at: Creation timestamp
        started_at: Start timestamp
        completed_at: Completion timestamp
        parameters: Additional scan parameters
        sub_tasks: List of sub-task IDs
    """
    task_id: str = ""
    name: str = ""
    targets: List[str] = field(default_factory=list)
    ports: List[int] = field(default_factory=list)
    modules: List[str] = field(default_factory=list)
    priority: TaskPriority = TaskPriority.NORMAL
    status: TaskStatus = TaskStatus.PENDING
    created_at: float = 0.0
    started_at: float = 0.0
    completed_at: float = 0.0
    parameters: Dict[str, Any] = field(default_factory=dict)
    sub_tasks: List[str] = field(default_factory=list)


@dataclass
class SubTask:
    """Sub-task assigned to a worker.

    Attributes:
        sub_task_id: Unique sub-task identifier
        task_id: Parent task ID
        worker_id: Assigned worker ID
        targets: Sub-task targets
        ports: Sub-task ports
        modules: Sub-task modules
        status: Sub-task status
        assigned_at: Assignment timestamp
        started_at: Start timestamp
        completed_at: Completion timestamp
        progress: Progress percentage (0-100)
        result_count: Number of results
        retry_count: Number of retries
        error_message: Error message if failed
    """
    sub_task_id: str = ""
    task_id: str = ""
    worker_id: str = ""
    targets: List[str] = field(default_factory=list)
    ports: List[int] = field(default_factory=list)
    modules: List[str] = field(default_factory=list)
    status: TaskStatus = TaskStatus.PENDING
    assigned_at: float = 0.0
    started_at: float = 0.0
    completed_at: float = 0.0
    progress: float = 0.0
    result_count: int = 0
    retry_count: int = 0
    error_message: str = ""


@dataclass
class WorkerNode:
    """Worker node information.

    Attributes:
        node_id: Unique node identifier
        ip_address: Node IP address
        status: Node status
        registered_at: Registration timestamp
        last_heartbeat: Last heartbeat timestamp
        system_info: System information
        supported_modules: Supported scan modules
        current_load: Current task load
        total_tasks: Total tasks completed
        success_rate: Historical success rate
        weight: Node weight for allocation
        failure_count: Consecutive failure count
    """
    node_id: str = ""
    ip_address: str = ""
    status: NodeStatus = NodeStatus.OFFLINE
    registered_at: float = 0.0
    last_heartbeat: float = 0.0
    system_info: Dict[str, Any] = field(default_factory=dict)
    supported_modules: List[str] = field(default_factory=list)
    current_load: int = 0
    total_tasks: int = 0
    success_rate: float = 100.0
    weight: float = 1.0
    failure_count: int = 0


@dataclass
class AggregatedResult:
    """Aggregated scan result.

    Attributes:
        result_id: Unique result identifier
        task_id: Parent task ID
        asset_key: Unique asset key (IP+port+fingerprints)
        asset_data: Asset information
        vulnerabilities: List of vulnerabilities found
        discovering_nodes: List of nodes that discovered this asset
        first_discovered: First discovery timestamp
        last_updated: Last update timestamp
    """
    result_id: str = ""
    task_id: str = ""
    asset_key: str = ""
    asset_data: Dict[str, Any] = field(default_factory=dict)
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    discovering_nodes: List[str] = field(default_factory=list)
    first_discovered: float = 0.0
    last_updated: float = 0.0


class TaskScheduler:
    """Schedules and distributes scan tasks to worker nodes.

    Handles task splitting, priority queue management, and allocation strategies.
    """

    DEFAULT_SHARD_SIZE = 100

    def __init__(
        self,
        strategy: AllocationStrategy = AllocationStrategy.LEAST_LOAD,
        shard_size: int = DEFAULT_SHARD_SIZE,
    ) -> None:
        """Initialize task scheduler.

        Args:
            strategy: Allocation strategy.
            shard_size: Number of targets per shard.
        """
        self.strategy = strategy
        self.shard_size = shard_size
        self._task_queue: List[Tuple[int, ScanTask]] = []
        self._round_robin_index = 0

    def add_task(self, task: ScanTask) -> None:
        """Add task to priority queue.

        Args:
            task: ScanTask to add.
        """
        self._task_queue.append((-task.priority.value, task))
        self._task_queue.sort()

    def get_next_task(self) -> Optional[ScanTask]:
        """Get next task from priority queue.

        Returns:
            Next ScanTask or None.
        """
        if not self._task_queue:
            return None

        _, task = self._task_queue.pop(0)

        return task

    def split_task(self, task: ScanTask) -> List[SubTask]:
        """Split scan task into sub-tasks.

        Args:
            task: ScanTask to split.

        Returns:
            List of SubTask objects.
        """
        sub_tasks: List[SubTask] = []

        target_chunks = self._chunk_list(task.targets, self.shard_size)

        for i, chunk in enumerate(target_chunks):
            sub_task_id = f"{task.task_id}_sub_{i}"

            sub_task = SubTask(
                sub_task_id=sub_task_id,
                task_id=task.task_id,
                targets=chunk,
                ports=task.ports,
                modules=task.modules,
            )

            sub_tasks.append(sub_task)

        return sub_tasks

    def select_worker(
        self,
        sub_task: SubTask,
        workers: Dict[str, WorkerNode],
    ) -> Optional[str]:
        """Select worker for sub-task based on strategy.

        Args:
            sub_task: SubTask to assign.
            workers: Available worker nodes.

        Returns:
            Selected worker ID or None.
        """
        available_workers = {
            wid: w for wid, w in workers.items()
            if w.status in (NodeStatus.ONLINE, NodeStatus.BUSY)
        }

        if not available_workers:
            return None

        if self.strategy == AllocationStrategy.ROUND_ROBIN:
            return self._select_round_robin(list(available_workers.keys()))
        elif self.strategy == AllocationStrategy.LEAST_LOAD:
            return self._select_least_load(available_workers)
        elif self.strategy == AllocationStrategy.WEIGHTED:
            return self._select_weighted(available_workers)

        return self._select_least_load(available_workers)

    def _select_round_robin(self, worker_ids: List[str]) -> str:
        """Select worker using round-robin.

        Args:
            worker_ids: List of worker IDs.

        Returns:
            Selected worker ID.
        """
        worker_id = worker_ids[self._round_robin_index % len(worker_ids)]
        self._round_robin_index += 1

        return worker_id

    def _select_least_load(self, workers: Dict[str, WorkerNode]) -> str:
        """Select worker with least load.

        Args:
            workers: Available worker nodes.

        Returns:
            Selected worker ID.
        """
        return min(workers.keys(), key=lambda wid: workers[wid].current_load)

    def _select_weighted(self, workers: Dict[str, WorkerNode]) -> str:
        """Select worker using weighted allocation.

        Args:
            workers: Available worker nodes.

        Returns:
            Selected worker ID.
        """
        import random

        total_weight = sum(w.weight for w in workers.values())
        r = random.uniform(0, total_weight)
        cumulative = 0.0

        for wid, worker in workers.items():
            cumulative += worker.weight
            if r <= cumulative:
                return wid

        return list(workers.keys())[-1]

    @staticmethod
    def _chunk_list(lst: List[Any], chunk_size: int) -> List[List[Any]]:
        """Split list into chunks.

        Args:
            lst: List to split.
            chunk_size: Size of each chunk.

        Returns:
            List of chunks.
        """
        return [lst[i:i + chunk_size] for i in range(0, len(lst), chunk_size)]


class ResultAggregator:
    """Aggregates and deduplicates scan results from workers.

    Merges results from multiple nodes, deduplicates by asset key,
    and provides real-time progress tracking.
    """

    def __init__(self) -> None:
        """Initialize result aggregator."""
        self._results: Dict[str, AggregatedResult] = {}
        self._task_progress: Dict[str, Dict[str, Any]] = {}

    def add_result(self, task_id: str, result_data: Dict[str, Any], worker_id: str) -> AggregatedResult:
        """Add scan result and deduplicate.

        Args:
            task_id: Task identifier.
            result_data: Result data dict.
            worker_id: Worker that discovered the result.

        Returns:
            AggregatedResult.
        """
        asset_key = self._build_asset_key(result_data)

        if asset_key in self._results:
            existing = self._results[asset_key]

            if worker_id not in existing.discovering_nodes:
                existing.discovering_nodes.append(worker_id)

            for vuln in result_data.get("vulnerabilities", []):
                if vuln not in existing.vulnerabilities:
                    existing.vulnerabilities.append(vuln)

            existing.last_updated = time.time()

            return existing

        result_id = f"result_{task_id}_{asset_key}"

        aggregated = AggregatedResult(
            result_id=result_id,
            task_id=task_id,
            asset_key=asset_key,
            asset_data=result_data,
            vulnerabilities=result_data.get("vulnerabilities", []),
            discovering_nodes=[worker_id],
            first_discovered=time.time(),
            last_updated=time.time(),
        )

        self._results[asset_key] = aggregated

        return aggregated

    def update_progress(
        self,
        task_id: str,
        sub_task_id: str,
        progress: float,
        result_count: int,
        status: TaskStatus,
    ) -> Dict[str, Any]:
        """Update task progress.

        Args:
            task_id: Task identifier.
            sub_task_id: Sub-task identifier.
            progress: Progress percentage.
            result_count: Number of results.
            status: Sub-task status.

        Returns:
            Updated progress dict.
        """
        if task_id not in self._task_progress:
            self._task_progress[task_id] = {
                "sub_tasks": {},
                "total_progress": 0.0,
                "completed": 0,
                "in_progress": 0,
                "failed": 0,
                "total_results": 0,
            }

        progress_data = self._task_progress[task_id]

        progress_data["sub_tasks"][sub_task_id] = {
            "progress": progress,
            "result_count": result_count,
            "status": status.value,
        }

        progress_data["total_results"] += result_count

        if status == TaskStatus.COMPLETED:
            progress_data["completed"] += 1
        elif status == TaskStatus.IN_PROGRESS:
            progress_data["in_progress"] += 1
        elif status == TaskStatus.FAILED:
            progress_data["failed"] += 1

        total_sub_tasks = len(progress_data["sub_tasks"])
        if total_sub_tasks > 0:
            progress_data["total_progress"] = (
                (progress_data["completed"] / total_sub_tasks) * 100
            )

        return progress_data

    def get_task_progress(self, task_id: str) -> Dict[str, Any]:
        """Get task progress.

        Args:
            task_id: Task identifier.

        Returns:
            Progress dict.
        """
        return self._task_progress.get(task_id, {})

    def get_results_for_task(self, task_id: str) -> List[AggregatedResult]:
        """Get aggregated results for a task.

        Args:
            task_id: Task identifier.

        Returns:
            List of AggregatedResult objects.
        """
        return [r for r in self._results.values() if r.task_id == task_id]

    @staticmethod
    def _build_asset_key(result_data: Dict[str, Any]) -> str:
        """Build unique asset key from result data.

        Args:
            result_data: Result data dict.

        Returns:
            Asset key string.
        """
        ip = result_data.get("ip", "")
        port = result_data.get("port", 0)
        fingerprint = result_data.get("fingerprint", "")

        return f"{ip}:{port}:{fingerprint}"


class ClusterMaster:
    """Master node for distributed scan cluster.

    Manages task scheduling, worker nodes, result aggregation,
    and provides high availability through state persistence.
    """

    HEARTBEAT_TIMEOUT = 30
    MAX_FAILURE_COUNT = 5

    def __init__(
        self,
        node_id: str = "master",
        host: str = "0.0.0.0",
        port: int = 8765,
        psk: str = "",
        storage_path: str = "",
        strategy: AllocationStrategy = AllocationStrategy.LEAST_LOAD,
    ) -> None:
        """Initialize cluster master.

        Args:
            node_id: Master node identifier.
            host: Bind host address.
            port: Bind port.
            psk: Pre-shared key for authentication.
            storage_path: Path for state persistence.
            strategy: Task allocation strategy.
        """
        self.node_id = node_id
        self.host = host
        self.port = port
        self.psk = psk
        self.storage_path = storage_path

        self.scheduler = TaskScheduler(strategy=strategy)
        self.aggregator = ResultAggregator()
        self.comm_manager = ClusterCommunicationManager(
            node_id=node_id,
            role=NodeRole.MASTER,
            host=host,
            port=port,
            psk=psk,
        )

        self._workers: Dict[str, WorkerNode] = {}
        self._tasks: Dict[str, ScanTask] = {}
        self._sub_tasks: Dict[str, SubTask] = {}
        self._running = False

        if storage_path:
            os.makedirs(storage_path, exist_ok=True)
            self._init_database()
            self._load_state()

        self._setup_message_handlers()

    async def start(self) -> bool:
        """Start cluster master.

        Returns:
            True if started successfully.
        """
        if not await self.comm_manager.start_server():
            return False

        self._running = True

        asyncio.create_task(self._heartbeat_monitor())
        asyncio.create_task(self._task_dispatcher())

        logger.info("Cluster master started")

        return True

    async def submit_task(self, task: ScanTask) -> str:
        """Submit new scan task.

        Args:
            task: ScanTask to submit.

        Returns:
            Task ID.
        """
        if not task.task_id:
            task.task_id = f"task_{int(time.time())}_{uuid.uuid4().hex[:8]}"

        task.created_at = time.time()
        task.status = TaskStatus.PENDING

        self._tasks[task.task_id] = task

        sub_tasks = self.scheduler.split_task(task)
        task.sub_tasks = [st.sub_task_id for st in sub_tasks]

        for sub_task in sub_tasks:
            self._sub_tasks[sub_task.sub_task_id] = sub_task

        self.scheduler.add_task(task)

        self._save_state()

        return task.task_id

    async def cancel_task(self, task_id: str) -> bool:
        """Cancel scan task.

        Args:
            task_id: Task identifier.

        Returns:
            True if cancelled successfully.
        """
        task = self._tasks.get(task_id)
        if not task:
            return False

        task.status = TaskStatus.CANCELLED
        task.completed_at = time.time()

        for sub_task_id in task.sub_tasks:
            sub_task = self._sub_tasks.get(sub_task_id)
            if sub_task and sub_task.status in (TaskStatus.PENDING, TaskStatus.ASSIGNED):
                sub_task.status = TaskStatus.CANCELLED

                if sub_task.worker_id:
                    await self.comm_manager.send_to_worker(
                        sub_task.worker_id,
                        ClusterMessage(
                            message_type=MessageType.TASK_CANCEL,
                            sender_id=self.node_id,
                            receiver_id=sub_task.worker_id,
                            payload={"sub_task_id": sub_task_id},
                        ),
                    )

        self._save_state()

        return True

    def get_task_status(self, task_id: str) -> Optional[Dict[str, Any]]:
        """Get task status and progress.

        Args:
            task_id: Task identifier.

        Returns:
            Task status dict or None.
        """
        task = self._tasks.get(task_id)
        if not task:
            return None

        progress = self.aggregator.get_task_progress(task_id)

        return {
            "task_id": task.task_id,
            "name": task.name,
            "status": task.status.value,
            "priority": task.priority.value,
            "created_at": task.created_at,
            "started_at": task.started_at,
            "completed_at": task.completed_at,
            "total_sub_tasks": len(task.sub_tasks),
            "progress": progress,
        }

    def get_worker_list(self) -> List[Dict[str, Any]]:
        """Get list of registered workers.

        Returns:
            List of worker info dicts.
        """
        return [
            {
                "node_id": w.node_id,
                "ip_address": w.ip_address,
                "status": w.status.value,
                "last_heartbeat": w.last_heartbeat,
                "current_load": w.current_load,
                "total_tasks": w.total_tasks,
                "success_rate": w.success_rate,
                "supported_modules": w.supported_modules,
            }
            for w in self._workers.values()
        ]

    def get_cluster_stats(self) -> Dict[str, Any]:
        """Get cluster statistics.

        Returns:
            Cluster stats dict.
        """
        online_workers = sum(
            1 for w in self._workers.values()
            if w.status in (NodeStatus.ONLINE, NodeStatus.BUSY)
        )

        total_tasks = len(self._tasks)
        completed_tasks = sum(
            1 for t in self._tasks.values()
            if t.status == TaskStatus.COMPLETED
        )

        return {
            "online_workers": online_workers,
            "total_workers": len(self._workers),
            "total_tasks": total_tasks,
            "completed_tasks": completed_tasks,
            "pending_tasks": sum(1 for t in self._tasks.values() if t.status == TaskStatus.PENDING),
            "in_progress_tasks": sum(1 for t in self._tasks.values() if t.status == TaskStatus.IN_PROGRESS),
            "total_results": len(self.aggregator._results),
        }

    async def stop(self) -> None:
        """Stop cluster master."""
        self._running = False

        await self.comm_manager.stop()

        self._save_state()

        logger.info("Cluster master stopped")

    def _setup_message_handlers(self) -> None:
        """Setup message handlers for cluster communication."""
        self.comm_manager.register_handler(MessageType.REGISTER, self._handle_register)
        self.comm_manager.register_handler(MessageType.HEARTBEAT, self._handle_heartbeat)
        self.comm_manager.register_handler(MessageType.TASK_PROGRESS, self._handle_task_progress)
        self.comm_manager.register_handler(MessageType.TASK_RESULT, self._handle_task_result)
        self.comm_manager.register_handler(MessageType.TASK_COMPLETE, self._handle_task_complete)

    async def _handle_register(self, message: ClusterMessage) -> None:
        """Handle worker registration.

        Args:
            message: Registration message.
        """
        payload = message.payload

        worker = WorkerNode(
            node_id=message.sender_id,
            ip_address=payload.get("ip_address", ""),
            status=NodeStatus.ONLINE,
            registered_at=time.time(),
            last_heartbeat=time.time(),
            system_info=payload.get("system_info", {}),
            supported_modules=payload.get("supported_modules", []),
        )

        self._workers[worker.node_id] = worker

        token = self.comm_manager.token_manager.generate_token(worker.node_id)

        await self.comm_manager.send_to_worker(
            worker.node_id,
            ClusterMessage(
                message_type=MessageType.REGISTER_ACK,
                sender_id=self.node_id,
                receiver_id=worker.node_id,
                payload={
                    "status": "registered",
                    "token": token,
                    "config": self._get_default_config(),
                },
            ),
        )

        logger.info(f"Worker registered: {worker.node_id}")

    async def _handle_heartbeat(self, message: ClusterMessage) -> None:
        """Handle worker heartbeat.

        Args:
            message: Heartbeat message.
        """
        worker = self._workers.get(message.sender_id)
        if not worker:
            return

        worker.last_heartbeat = time.time()
        worker.current_load = message.payload.get("current_load", 0)

        if worker.current_load > 0:
            worker.status = NodeStatus.BUSY
        else:
            worker.status = NodeStatus.ONLINE

        await self.comm_manager.send_to_worker(
            worker.node_id,
            ClusterMessage(
                message_type=MessageType.HEARTBEAT_ACK,
                sender_id=self.node_id,
                receiver_id=worker.node_id,
            ),
        )

    async def _handle_task_progress(self, message: ClusterMessage) -> None:
        """Handle task progress update.

        Args:
            message: Progress message.
        """
        payload = message.payload
        sub_task_id = payload.get("sub_task_id", "")
        progress = payload.get("progress", 0.0)
        result_count = payload.get("result_count", 0)

        sub_task = self._sub_tasks.get(sub_task_id)
        if sub_task:
            sub_task.progress = progress
            sub_task.result_count = result_count

            self.aggregator.update_progress(
                sub_task.task_id,
                sub_task_id,
                progress,
                result_count,
                TaskStatus.IN_PROGRESS,
            )

    async def _handle_task_result(self, message: ClusterMessage) -> None:
        """Handle task result.

        Args:
            message: Result message.
        """
        payload = message.payload
        sub_task_id = payload.get("sub_task_id", "")
        results = payload.get("results", [])

        sub_task = self._sub_tasks.get(sub_task_id)
        if not sub_task:
            return

        for result_data in results:
            self.aggregator.add_result(
                sub_task.task_id,
                result_data,
                message.sender_id,
            )

    async def _handle_task_complete(self, message: ClusterMessage) -> None:
        """Handle task completion.

        Args:
            message: Completion message.
        """
        payload = message.payload
        sub_task_id = payload.get("sub_task_id", "")
        success = payload.get("success", False)

        sub_task = self._sub_tasks.get(sub_task_id)
        if not sub_task:
            return

        sub_task.completed_at = time.time()

        if success:
            sub_task.status = TaskStatus.COMPLETED
            worker = self._workers.get(sub_task.worker_id)
            if worker:
                worker.total_tasks += 1
                worker.current_load = max(0, worker.current_load - 1)
                worker.failure_count = 0
        else:
            sub_task.status = TaskStatus.FAILED
            sub_task.error_message = payload.get("error", "")

            worker = self._workers.get(sub_task.worker_id)
            if worker:
                worker.failure_count += 1
                worker.current_load = max(0, worker.current_load - 1)

                if worker.failure_count >= self.MAX_FAILURE_COUNT:
                    worker.status = NodeStatus.BLACKLISTED
                    await self._reassign_sub_tasks(sub_task.worker_id)

        self._check_task_completion(sub_task.task_id)

        self._save_state()

    async def _heartbeat_monitor(self) -> None:
        """Monitor worker heartbeats and detect offline nodes."""
        while self._running:
            await asyncio.sleep(self.HEARTBEAT_TIMEOUT)

            now = time.time()

            for worker_id, worker in list(self._workers.items()):
                if now - worker.last_heartbeat > self.HEARTBEAT_TIMEOUT * 3:
                    if worker.status != NodeStatus.OFFLINE:
                        worker.status = NodeStatus.OFFLINE
                        logger.warning(f"Worker offline: {worker_id}")
                        await self._reassign_sub_tasks(worker_id)

    async def _task_dispatcher(self) -> None:
        """Dispatch tasks to available workers."""
        while self._running:
            await asyncio.sleep(1)

            task = self.scheduler.get_next_task()
            if not task:
                continue

            task.status = TaskStatus.IN_PROGRESS
            task.started_at = time.time()

            for sub_task_id in task.sub_tasks:
                sub_task = self._sub_tasks.get(sub_task_id)
                if not sub_task or sub_task.status != TaskStatus.PENDING:
                    continue

                worker_id = self.scheduler.select_worker(sub_task, self._workers)
                if not worker_id:
                    continue

                sub_task.worker_id = worker_id
                sub_task.status = TaskStatus.ASSIGNED
                sub_task.assigned_at = time.time()

                worker = self._workers.get(worker_id)
                if worker:
                    worker.current_load += 1

                await self.comm_manager.send_to_worker(
                    worker_id,
                    ClusterMessage(
                        message_type=MessageType.TASK_ASSIGN,
                        sender_id=self.node_id,
                        receiver_id=worker_id,
                        payload={
                            "sub_task_id": sub_task_id,
                            "task_id": task.task_id,
                            "targets": sub_task.targets,
                            "ports": sub_task.ports,
                            "modules": sub_task.modules,
                            "parameters": task.parameters,
                        },
                    ),
                )

    async def _reassign_sub_tasks(self, worker_id: str) -> None:
        """Reassign sub-tasks from offline worker.

        Args:
            worker_id: Offline worker ID.
        """
        for sub_task in self._sub_tasks.values():
            if (
                sub_task.worker_id == worker_id
                and sub_task.status in (TaskStatus.ASSIGNED, TaskStatus.IN_PROGRESS)
            ):
                sub_task.worker_id = ""
                sub_task.status = TaskStatus.PENDING
                sub_task.retry_count += 1

                self.scheduler.add_task(
                    self._tasks.get(sub_task.task_id, ScanTask(task_id=sub_task.task_id)),
                )

    def _check_task_completion(self, task_id: str) -> None:
        """Check if all sub-tasks of a task are complete.

        Args:
            task_id: Task identifier.
        """
        task = self._tasks.get(task_id)
        if not task:
            return

        sub_tasks = [
            self._sub_tasks.get(st_id)
            for st_id in task.sub_tasks
        ]

        all_done = all(
            st and st.status in (TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.CANCELLED)
            for st in sub_tasks
        )

        if all_done:
            task.status = TaskStatus.COMPLETED
            task.completed_at = time.time()

    def _get_default_config(self) -> Dict[str, Any]:
        """Get default configuration for workers.

        Returns:
            Default config dict.
        """
        return {
            "heartbeat_interval": self.HEARTBEAT_TIMEOUT,
            "max_concurrent_tasks": 5,
            "result_batch_size": 100,
            "retry_count": 3,
        }

    def _init_database(self) -> None:
        """Initialize SQLite database for state persistence."""
        if not self.storage_path:
            return

        db_path = os.path.join(self.storage_path, "cluster_master.db")

        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS tasks (
                task_id TEXT PRIMARY KEY,
                name TEXT,
                targets TEXT,
                ports TEXT,
                modules TEXT,
                priority INTEGER,
                status TEXT,
                created_at REAL,
                started_at REAL,
                completed_at REAL,
                parameters TEXT,
                sub_tasks TEXT
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS sub_tasks (
                sub_task_id TEXT PRIMARY KEY,
                task_id TEXT,
                worker_id TEXT,
                targets TEXT,
                ports TEXT,
                modules TEXT,
                status TEXT,
                assigned_at REAL,
                started_at REAL,
                completed_at REAL,
                progress REAL,
                result_count INTEGER,
                retry_count INTEGER,
                error_message TEXT
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS workers (
                node_id TEXT PRIMARY KEY,
                ip_address TEXT,
                status TEXT,
                registered_at REAL,
                last_heartbeat REAL,
                system_info TEXT,
                supported_modules TEXT,
                current_load INTEGER,
                total_tasks INTEGER,
                success_rate REAL,
                weight REAL,
                failure_count INTEGER
            )
        """)

        conn.commit()
        conn.close()

    def _save_state(self) -> None:
        """Save state to SQLite database."""
        if not self.storage_path:
            return

        db_path = os.path.join(self.storage_path, "cluster_master.db")

        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()

            for task in self._tasks.values():
                cursor.execute(
                    "INSERT OR REPLACE INTO tasks VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        task.task_id,
                        task.name,
                        json.dumps(task.targets),
                        json.dumps(task.ports),
                        json.dumps(task.modules),
                        task.priority.value,
                        task.status.value,
                        task.created_at,
                        task.started_at,
                        task.completed_at,
                        json.dumps(task.parameters),
                        json.dumps(task.sub_tasks),
                    ),
                )

            for sub_task in self._sub_tasks.values():
                cursor.execute(
                    "INSERT OR REPLACE INTO sub_tasks VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        sub_task.sub_task_id,
                        sub_task.task_id,
                        sub_task.worker_id,
                        json.dumps(sub_task.targets),
                        json.dumps(sub_task.ports),
                        json.dumps(sub_task.modules),
                        sub_task.status.value,
                        sub_task.assigned_at,
                        sub_task.started_at,
                        sub_task.completed_at,
                        sub_task.progress,
                        sub_task.result_count,
                        sub_task.retry_count,
                        sub_task.error_message,
                    ),
                )

            for worker in self._workers.values():
                cursor.execute(
                    "INSERT OR REPLACE INTO workers VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        worker.node_id,
                        worker.ip_address,
                        worker.status.value,
                        worker.registered_at,
                        worker.last_heartbeat,
                        json.dumps(worker.system_info),
                        json.dumps(worker.supported_modules),
                        worker.current_load,
                        worker.total_tasks,
                        worker.success_rate,
                        worker.weight,
                        worker.failure_count,
                    ),
                )

            conn.commit()
            conn.close()

        except Exception as e:
            logger.error(f"Failed to save state: {e}")

    def _load_state(self) -> None:
        """Load state from SQLite database."""
        if not self.storage_path:
            return

        db_path = os.path.join(self.storage_path, "cluster_master.db")

        if not os.path.exists(db_path):
            return

        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()

            cursor.execute("SELECT * FROM tasks")
            for row in cursor.fetchall():
                task = ScanTask(
                    task_id=row[0],
                    name=row[1],
                    targets=json.loads(row[2]),
                    ports=json.loads(row[3]),
                    modules=json.loads(row[4]),
                    priority=TaskPriority(row[5]),
                    status=TaskStatus(row[6]),
                    created_at=row[7],
                    started_at=row[8],
                    completed_at=row[9],
                    parameters=json.loads(row[10]),
                    sub_tasks=json.loads(row[11]),
                )
                self._tasks[task.task_id] = task

            cursor.execute("SELECT * FROM sub_tasks")
            for row in cursor.fetchall():
                sub_task = SubTask(
                    sub_task_id=row[0],
                    task_id=row[1],
                    worker_id=row[2],
                    targets=json.loads(row[3]),
                    ports=json.loads(row[4]),
                    modules=json.loads(row[5]),
                    status=TaskStatus(row[6]),
                    assigned_at=row[7],
                    started_at=row[8],
                    completed_at=row[9],
                    progress=row[10],
                    result_count=row[11],
                    retry_count=row[12],
                    error_message=row[13],
                )
                self._sub_tasks[sub_task.sub_task_id] = sub_task

            cursor.execute("SELECT * FROM workers")
            for row in cursor.fetchall():
                worker = WorkerNode(
                    node_id=row[0],
                    ip_address=row[1],
                    status=NodeStatus(row[2]),
                    registered_at=row[3],
                    last_heartbeat=row[4],
                    system_info=json.loads(row[5]),
                    supported_modules=json.loads(row[6]),
                    current_load=row[7],
                    total_tasks=row[8],
                    success_rate=row[9],
                    weight=row[10],
                    failure_count=row[11],
                )
                self._workers[worker.node_id] = worker

            conn.close()

        except Exception as e:
            logger.error(f"Failed to load state: {e}")
