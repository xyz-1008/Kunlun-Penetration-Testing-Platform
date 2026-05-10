"""Cluster Manager: Cluster dashboard, task management panel, node configuration management.

Provides:
- Cluster dashboard: Real-time display of online nodes, total sub-tasks, completion rate, scan rate, discovered assets
- Node list: Status, load, scan rate, last heartbeat for each node
- Node details: System resources (CPU/memory/disk), current sub-tasks, historical task statistics
- Task management panel: Task list with name, creation time, target range, assigned nodes, completion progress
- Sub-task details: Assigned node, execution status, start/end time, result count
- Failed task handling: Manual retry, reassignment, ignore
- Node configuration management: Global config, per-node overrides, batch operations
"""

import asyncio
import json
import logging
import os
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Callable, Coroutine, Dict, List, Optional, Set, Tuple

from core.modules.cluster_master import (
    AllocationStrategy,
    ClusterMaster,
    NodeStatus,
    ScanTask,
    SubTask,
    TaskPriority,
    TaskStatus,
    WorkerNode,
)
from core.modules.cluster_communication import ClusterMessage, MessageType

logger = logging.getLogger(__name__)


@dataclass
class ClusterConfig:
    """Global cluster configuration.

    Attributes:
        heartbeat_interval: Heartbeat interval in seconds
        max_concurrent_tasks: Maximum concurrent tasks per worker
        result_batch_size: Result batch size for reporting
        retry_count: Retry count for failed tasks
        allocation_strategy: Task allocation strategy
        shard_size: Number of targets per shard
        max_workers: Maximum number of workers
        token_lifetime: Token lifetime in seconds
        result_retention_days: Days to retain results
    """
    heartbeat_interval: int = 30
    max_concurrent_tasks: int = 5
    result_batch_size: int = 100
    retry_count: int = 3
    allocation_strategy: AllocationStrategy = AllocationStrategy.LEAST_LOAD
    shard_size: int = 100
    max_workers: int = 100
    token_lifetime: int = 86400
    result_retention_days: int = 30


@dataclass
class NodeConfigOverride:
    """Per-node configuration override.

    Attributes:
        node_id: Node identifier
        max_concurrent_tasks: Override for max concurrent tasks
        heartbeat_interval: Override for heartbeat interval
        result_batch_size: Override for result batch size
        enabled: Whether node is enabled
        weight: Node weight for weighted allocation
    """
    node_id: str = ""
    max_concurrent_tasks: Optional[int] = None
    heartbeat_interval: Optional[int] = None
    result_batch_size: Optional[int] = None
    enabled: bool = True
    weight: float = 1.0


@dataclass
class DashboardData:
    """Cluster dashboard data.

    Attributes:
        online_workers: Number of online workers
        total_workers: Total registered workers
        total_tasks: Total tasks
        completed_tasks: Completed tasks
        pending_tasks: Pending tasks
        in_progress_tasks: In-progress tasks
        failed_tasks: Failed tasks
        completion_rate: Task completion rate
        scan_rate: Current scan rate (targets/second)
        discovered_assets: Number of discovered assets
        timestamp: Dashboard data timestamp
    """
    online_workers: int = 0
    total_workers: int = 0
    total_tasks: int = 0
    completed_tasks: int = 0
    pending_tasks: int = 0
    in_progress_tasks: int = 0
    failed_tasks: int = 0
    completion_rate: float = 0.0
    scan_rate: float = 0.0
    discovered_assets: int = 0
    timestamp: float = 0.0


class ClusterManager:
    """Manages cluster operations, provides dashboard and configuration management.

    Interfaces with ClusterMaster to provide management capabilities
    for monitoring, task management, and configuration.
    """

    def __init__(
        self,
        master: ClusterMaster,
        config: Optional[ClusterConfig] = None,
        storage_path: str = "",
    ) -> None:
        """Initialize cluster manager.

        Args:
            master: ClusterMaster instance.
            config: Cluster configuration.
            storage_path: Path for configuration storage.
        """
        self.master = master
        self.config = config or ClusterConfig()
        self.storage_path = storage_path

        self._node_overrides: Dict[str, NodeConfigOverride] = {}
        self._dashboard_history: List[DashboardData] = []
        self._task_callbacks: List[Callable[[DashboardData], Coroutine[Any, Any, None]]] = []

        if storage_path:
            os.makedirs(storage_path, exist_ok=True)
            self._load_config()

    def register_dashboard_callback(
        self,
        callback: Callable[[DashboardData], Coroutine[Any, Any, None]],
    ) -> None:
        """Register callback for dashboard updates.

        Args:
            callback: Async callback function.
        """
        self._task_callbacks.append(callback)

    async def start_dashboard_updates(self, interval: int = 5) -> None:
        """Start periodic dashboard updates.

        Args:
            interval: Update interval in seconds.
        """
        while True:
            await asyncio.sleep(interval)

            dashboard = self.get_dashboard_data()

            for callback in self._task_callbacks:
                try:
                    await callback(dashboard)
                except Exception as e:
                    logger.error(f"Dashboard callback error: {e}")

            self._dashboard_history.append(dashboard)

            if len(self._dashboard_history) > 1000:
                self._dashboard_history = self._dashboard_history[-500:]

    def get_dashboard_data(self) -> DashboardData:
        """Get current dashboard data.

        Returns:
            DashboardData object.
        """
        stats = self.master.get_cluster_stats()

        workers = self.master.get_worker_list()
        online_workers = sum(
            1 for w in workers
            if w["status"] in ("online", "busy")
        )

        total_tasks = stats.get("total_tasks", 0)
        completed_tasks = stats.get("completed_tasks", 0)

        completion_rate = (completed_tasks / total_tasks * 100) if total_tasks > 0 else 0.0

        total_results = stats.get("total_results", 0)

        scan_rate = self._calculate_scan_rate()

        return DashboardData(
            online_workers=online_workers,
            total_workers=stats.get("total_workers", 0),
            total_tasks=total_tasks,
            completed_tasks=completed_tasks,
            pending_tasks=stats.get("pending_tasks", 0),
            in_progress_tasks=stats.get("in_progress_tasks", 0),
            failed_tasks=self._count_failed_tasks(),
            completion_rate=completion_rate,
            scan_rate=scan_rate,
            discovered_assets=total_results,
            timestamp=time.time(),
        )

    def get_node_list(self) -> List[Dict[str, Any]]:
        """Get list of all nodes with details.

        Returns:
            List of node info dicts.
        """
        workers = self.master.get_worker_list()

        result = []
        for worker in workers:
            override = self._node_overrides.get(worker["node_id"])

            node_info = {
                **worker,
                "enabled": override.enabled if override else True,
                "weight": override.weight if override else 1.0,
                "config_override": override is not None,
            }

            result.append(node_info)

        return result

    def get_node_details(self, node_id: str) -> Optional[Dict[str, Any]]:
        """Get detailed information for a specific node.

        Args:
            node_id: Node identifier.

        Returns:
            Node details dict or None.
        """
        workers = self.master.get_worker_list()

        for worker in workers:
            if worker["node_id"] == node_id:
                current_sub_tasks = self._get_node_current_tasks(node_id)

                return {
                    **worker,
                    "current_sub_tasks": current_sub_tasks,
                    "historical_stats": self._get_node_historical_stats(node_id),
                    "config_override": self._node_overrides.get(node_id),
                }

        return None

    def get_task_list(self) -> List[Dict[str, Any]]:
        """Get list of all tasks.

        Returns:
            List of task info dicts.
        """
        stats = self.master.get_cluster_stats()

        tasks = []

        for task_id in self.master._tasks:
            task_status = self.master.get_task_status(task_id)
            if task_status:
                tasks.append(task_status)

        return tasks

    def get_sub_task_details(self, sub_task_id: str) -> Optional[Dict[str, Any]]:
        """Get details for a specific sub-task.

        Args:
            sub_task_id: Sub-task identifier.

        Returns:
            Sub-task details dict or None.
        """
        sub_task = self.master._sub_tasks.get(sub_task_id)
        if not sub_task:
            return None

        return {
            "sub_task_id": sub_task.sub_task_id,
            "task_id": sub_task.task_id,
            "worker_id": sub_task.worker_id,
            "targets": sub_task.targets,
            "ports": sub_task.ports,
            "modules": sub_task.modules,
            "status": sub_task.status.value,
            "assigned_at": sub_task.assigned_at,
            "started_at": sub_task.started_at,
            "completed_at": sub_task.completed_at,
            "progress": sub_task.progress,
            "result_count": sub_task.result_count,
            "retry_count": sub_task.retry_count,
            "error_message": sub_task.error_message,
        }

    async def retry_failed_task(self, sub_task_id: str) -> bool:
        """Retry a failed sub-task.

        Args:
            sub_task_id: Sub-task identifier.

        Returns:
            True if retried successfully.
        """
        sub_task = self.master._sub_tasks.get(sub_task_id)
        if not sub_task:
            return False

        if sub_task.status != TaskStatus.FAILED:
            return False

        sub_task.status = TaskStatus.PENDING
        sub_task.worker_id = ""
        sub_task.retry_count += 1
        sub_task.error_message = ""

        task = self.master._tasks.get(sub_task.task_id)
        if task:
            self.master.scheduler.add_task(task)

        self.master._save_state()

        return True

    async def reassign_sub_task(self, sub_task_id: str, new_worker_id: str) -> bool:
        """Reassign sub-task to a specific worker.

        Args:
            sub_task_id: Sub-task identifier.
            new_worker_id: New worker ID.

        Returns:
            True if reassigned successfully.
        """
        sub_task = self.master._sub_tasks.get(sub_task_id)
        if not sub_task:
            return False

        worker = self.master._workers.get(new_worker_id)
        if not worker or worker.status not in (NodeStatus.ONLINE, NodeStatus.BUSY):
            return False

        sub_task.worker_id = new_worker_id
        sub_task.status = TaskStatus.ASSIGNED
        sub_task.assigned_at = time.time()

        worker.current_load += 1

        await self.master.comm_manager.send_to_worker(
            new_worker_id,
            ClusterMessage(
                message_type=MessageType.TASK_ASSIGN,
                sender_id=self.master.node_id,
                receiver_id=new_worker_id,
                payload={
                    "sub_task_id": sub_task_id,
                    "task_id": sub_task.task_id,
                    "targets": sub_task.targets,
                    "ports": sub_task.ports,
                    "modules": sub_task.modules,
                    "parameters": self.master._tasks.get(sub_task.task_id, ScanTask()).parameters,
                },
            ),
        )

        return True

    async def ignore_failed_task(self, sub_task_id: str) -> bool:
        """Mark failed sub-task as ignored.

        Args:
            sub_task_id: Sub-task identifier.

        Returns:
            True if ignored successfully.
        """
        sub_task = self.master._sub_tasks.get(sub_task_id)
        if not sub_task:
            return False

        sub_task.status = TaskStatus.FAILED

        self.master._check_task_completion(sub_task.task_id)

        self.master._save_state()

        return True

    def set_node_override(self, override: NodeConfigOverride) -> None:
        """Set configuration override for a node.

        Args:
            override: NodeConfigOverride object.
        """
        self._node_overrides[override.node_id] = override

        self._save_config()

    def remove_node_override(self, node_id: str) -> bool:
        """Remove configuration override for a node.

        Args:
            node_id: Node identifier.

        Returns:
            True if removed successfully.
        """
        if node_id in self._node_overrides:
            del self._node_overrides[node_id]
            self._save_config()
            return True

        return False

    async def batch_enable_nodes(self, node_ids: List[str]) -> int:
        """Batch enable nodes.

        Args:
            node_ids: List of node IDs to enable.

        Returns:
            Number of nodes enabled.
        """
        count = 0

        for node_id in node_ids:
            override = self._node_overrides.get(node_id)
            if override:
                override.enabled = True
            else:
                self._node_overrides[node_id] = NodeConfigOverride(node_id=node_id, enabled=True)
            count += 1

        self._save_config()

        return count

    async def batch_disable_nodes(self, node_ids: List[str]) -> int:
        """Batch disable nodes.

        Args:
            node_ids: List of node IDs to disable.

        Returns:
            Number of nodes disabled.
        """
        count = 0

        for node_id in node_ids:
            override = self._node_overrides.get(node_id)
            if override:
                override.enabled = False
            else:
                self._node_overrides[node_id] = NodeConfigOverride(node_id=node_id, enabled=False)

            worker = self.master._workers.get(node_id)
            if worker:
                await self.master._reassign_sub_tasks(node_id)

            count += 1

        self._save_config()

        return count

    async def batch_update_config(self, config: ClusterConfig) -> None:
        """Batch update configuration for all nodes.

        Args:
            config: New cluster configuration.
        """
        self.config = config

        await self.master.comm_manager.broadcast(
            ClusterMessage(
                message_type=MessageType.CONFIG_UPDATE,
                sender_id=self.master.node_id,
                payload={
                    "heartbeat_interval": config.heartbeat_interval,
                    "max_concurrent_tasks": config.max_concurrent_tasks,
                    "result_batch_size": config.result_batch_size,
                },
            ),
        )

        self._save_config()

    def get_dashboard_history(self, limit: int = 100) -> List[DashboardData]:
        """Get dashboard history.

        Args:
            limit: Maximum history entries.

        Returns:
            List of DashboardData objects.
        """
        return self._dashboard_history[-limit:]

    def _calculate_scan_rate(self) -> float:
        """Calculate current scan rate.

        Returns:
            Scan rate (targets/second).
        """
        if len(self._dashboard_history) < 2:
            return 0.0

        latest = self._dashboard_history[-1]
        previous = self._dashboard_history[-2]

        time_diff = latest.timestamp - previous.timestamp
        if time_diff <= 0:
            return 0.0

        asset_diff = latest.discovered_assets - previous.discovered_assets

        return asset_diff / time_diff

    def _count_failed_tasks(self) -> int:
        """Count failed tasks.

        Returns:
            Number of failed tasks.
        """
        return sum(
            1 for st in self.master._sub_tasks.values()
            if st.status == TaskStatus.FAILED
        )

    def _get_node_current_tasks(self, node_id: str) -> List[Dict[str, Any]]:
        """Get current tasks for a node.

        Args:
            node_id: Node identifier.

        Returns:
            List of current task dicts.
        """
        return [
            {
                "sub_task_id": st.sub_task_id,
                "task_id": st.task_id,
                "progress": st.progress,
                "status": st.status.value,
            }
            for st in self.master._sub_tasks.values()
            if st.worker_id == node_id and st.status in (TaskStatus.ASSIGNED, TaskStatus.IN_PROGRESS)
        ]

    def _get_node_historical_stats(self, node_id: str) -> Dict[str, Any]:
        """Get historical statistics for a node.

        Args:
            node_id: Node identifier.

        Returns:
            Historical stats dict.
        """
        worker = self.master._workers.get(node_id)
        if not worker:
            return {}

        total_sub_tasks = sum(
            1 for st in self.master._sub_tasks.values()
            if st.worker_id == node_id
        )

        completed_sub_tasks = sum(
            1 for st in self.master._sub_tasks.values()
            if st.worker_id == node_id and st.status == TaskStatus.COMPLETED
        )

        return {
            "total_sub_tasks": total_sub_tasks,
            "completed_sub_tasks": completed_sub_tasks,
            "success_rate": worker.success_rate,
            "total_tasks": worker.total_tasks,
            "failure_count": worker.failure_count,
        }

    def _save_config(self) -> None:
        """Save configuration to disk."""
        if not self.storage_path:
            return

        try:
            config_file = os.path.join(self.storage_path, "cluster_config.json")

            config_data = {
                "global_config": {
                    "heartbeat_interval": self.config.heartbeat_interval,
                    "max_concurrent_tasks": self.config.max_concurrent_tasks,
                    "result_batch_size": self.config.result_batch_size,
                    "retry_count": self.config.retry_count,
                    "allocation_strategy": self.config.allocation_strategy.value,
                    "shard_size": self.config.shard_size,
                    "max_workers": self.config.max_workers,
                    "token_lifetime": self.config.token_lifetime,
                    "result_retention_days": self.config.result_retention_days,
                },
                "node_overrides": {
                    node_id: {
                        "node_id": override.node_id,
                        "max_concurrent_tasks": override.max_concurrent_tasks,
                        "heartbeat_interval": override.heartbeat_interval,
                        "result_batch_size": override.result_batch_size,
                        "enabled": override.enabled,
                        "weight": override.weight,
                    }
                    for node_id, override in self._node_overrides.items()
                },
            }

            with open(config_file, "w", encoding="utf-8") as f:
                json.dump(config_data, f, ensure_ascii=False, indent=2)

        except Exception as e:
            logger.error(f"Failed to save config: {e}")

    def _load_config(self) -> None:
        """Load configuration from disk."""
        if not self.storage_path:
            return

        config_file = os.path.join(self.storage_path, "cluster_config.json")

        if not os.path.exists(config_file):
            return

        try:
            with open(config_file, "r", encoding="utf-8") as f:
                config_data = json.load(f)

                global_config = config_data.get("global_config", {})

                if global_config:
                    self.config.heartbeat_interval = global_config.get("heartbeat_interval", 30)
                    self.config.max_concurrent_tasks = global_config.get("max_concurrent_tasks", 5)
                    self.config.result_batch_size = global_config.get("result_batch_size", 100)
                    self.config.retry_count = global_config.get("retry_count", 3)
                    self.config.allocation_strategy = AllocationStrategy(
                        global_config.get("allocation_strategy", "least_load")
                    )
                    self.config.shard_size = global_config.get("shard_size", 100)
                    self.config.max_workers = global_config.get("max_workers", 100)
                    self.config.token_lifetime = global_config.get("token_lifetime", 86400)
                    self.config.result_retention_days = global_config.get("result_retention_days", 30)

                node_overrides = config_data.get("node_overrides", {})

                for node_id, override_data in node_overrides.items():
                    self._node_overrides[node_id] = NodeConfigOverride(
                        node_id=node_id,
                        max_concurrent_tasks=override_data.get("max_concurrent_tasks"),
                        heartbeat_interval=override_data.get("heartbeat_interval"),
                        result_batch_size=override_data.get("result_batch_size"),
                        enabled=override_data.get("enabled", True),
                        weight=override_data.get("weight", 1.0),
                    )

        except Exception as e:
            logger.error(f"Failed to load config: {e}")
