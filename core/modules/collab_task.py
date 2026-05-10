"""Collaboration Task: Task creation/assignment/claiming, sub-task splitting, progress tracking.

Provides:
- Task creation with name, description, target scope, deadline, priority
- Assignment methods: assign to specific member or open for claiming
- Sub-task splitting: main task can contain multiple sub-tasks
- Task status: pending/claimed/in_progress/completed/blocked
- Progress tracking: members update progress percentage and notes
- Real-time progress viewing for team leaders
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

logger = logging.getLogger(__name__)


class TaskPriority(Enum):
    """Task priority levels."""
    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    CRITICAL = "critical"


class TaskStatus(Enum):
    """Task lifecycle status."""
    PENDING = "pending"
    CLAIMED = "claimed"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    BLOCKED = "blocked"


@dataclass
class SubTask:
    """Sub-task within a main task.

    Attributes:
        sub_task_id: Unique sub-task identifier
        task_id: Parent task ID
        name: Sub-task name
        description: Sub-task description
        assigned_to: Member assigned to this sub-task
        status: Sub-task status
        progress: Progress percentage (0-100)
        notes: Progress notes
        created_at: Creation timestamp
        started_at: Start timestamp
        completed_at: Completion timestamp
    """
    sub_task_id: str = ""
    task_id: str = ""
    name: str = ""
    description: str = ""
    assigned_to: str = ""
    status: TaskStatus = TaskStatus.PENDING
    progress: float = 0.0
    notes: str = ""
    created_at: float = 0.0
    started_at: float = 0.0
    completed_at: float = 0.0


@dataclass
class CollaborationTask:
    """Main task in the collaboration system.

    Attributes:
        task_id: Unique task identifier
        project_id: Parent project ID
        name: Task name
        description: Task description
        target_scope: Target scope (IP ranges, domains)
        priority: Task priority
        status: Task status
        created_by: Member who created this task
        assigned_to: Member assigned (empty for open claiming)
        deadline: Deadline timestamp
        progress: Overall progress percentage (0-100)
        notes: Progress notes
        sub_tasks: List of sub-task IDs
        created_at: Creation timestamp
        started_at: Start timestamp
        completed_at: Completion timestamp
    """
    task_id: str = ""
    project_id: str = ""
    name: str = ""
    description: str = ""
    target_scope: List[str] = field(default_factory=list)
    priority: TaskPriority = TaskPriority.NORMAL
    status: TaskStatus = TaskStatus.PENDING
    created_by: str = ""
    assigned_to: str = ""
    deadline: float = 0.0
    progress: float = 0.0
    notes: str = ""
    sub_tasks: List[str] = field(default_factory=list)
    created_at: float = 0.0
    started_at: float = 0.0
    completed_at: float = 0.0


class TaskManager:
    """Manages collaboration tasks, sub-tasks, assignment, claiming, and progress tracking.

    Provides task creation, assignment to specific members or open claiming,
    sub-task splitting, progress updates, and real-time progress viewing.
    """

    def __init__(self, db_path: str = "") -> None:
        """Initialize task manager.

        Args:
            db_path: Path to SQLite database file.
        """
        self.db_path = db_path or "collab_tasks.db"
        self._tasks: Dict[str, CollaborationTask] = {}
        self._sub_tasks: Dict[str, SubTask] = {}
        self._progress_callbacks: List[Callable[[str, CollaborationTask], Coroutine[Any, Any, None]]] = []

        self._init_database()
        self._load_data()

    def register_progress_callback(
        self,
        callback: Callable[[str, CollaborationTask], Coroutine[Any, Any, None]],
    ) -> None:
        """Register callback for task progress updates.

        Args:
            callback: Async callback receiving project_id and task.
        """
        self._progress_callbacks.append(callback)

    def _init_database(self) -> None:
        """Initialize SQLite database schema."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS tasks (
                task_id TEXT PRIMARY KEY,
                project_id TEXT NOT NULL,
                name TEXT NOT NULL,
                description TEXT,
                target_scope TEXT,
                priority TEXT NOT NULL,
                status TEXT NOT NULL,
                created_by TEXT NOT NULL,
                assigned_to TEXT,
                deadline REAL,
                progress REAL NOT NULL,
                notes TEXT,
                sub_tasks TEXT,
                created_at REAL NOT NULL,
                started_at REAL,
                completed_at REAL
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS sub_tasks (
                sub_task_id TEXT PRIMARY KEY,
                task_id TEXT NOT NULL,
                name TEXT NOT NULL,
                description TEXT,
                assigned_to TEXT,
                status TEXT NOT NULL,
                progress REAL NOT NULL,
                notes TEXT,
                created_at REAL NOT NULL,
                started_at REAL,
                completed_at REAL,
                FOREIGN KEY (task_id) REFERENCES tasks(task_id)
            )
        """)

        conn.commit()
        conn.close()

    def _load_data(self) -> None:
        """Load all tasks from database."""
        if not os.path.exists(self.db_path):
            return

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM tasks")
        for row in cursor.fetchall():
            task = CollaborationTask(
                task_id=row[0],
                project_id=row[1],
                name=row[2],
                description=row[3] or "",
                target_scope=json.loads(row[4]) if row[4] else [],
                priority=TaskPriority(row[5]),
                status=TaskStatus(row[6]),
                created_by=row[7],
                assigned_to=row[8] or "",
                deadline=row[9] or 0.0,
                progress=row[10],
                notes=row[11] or "",
                sub_tasks=json.loads(row[12]) if row[12] else [],
                created_at=row[13],
                started_at=row[14] or 0.0,
                completed_at=row[15] or 0.0,
            )
            self._tasks[task.task_id] = task

        cursor.execute("SELECT * FROM sub_tasks")
        for row in cursor.fetchall():
            sub_task = SubTask(
                sub_task_id=row[0],
                task_id=row[1],
                name=row[2],
                description=row[3] or "",
                assigned_to=row[4] or "",
                status=TaskStatus(row[5]),
                progress=row[6],
                notes=row[7] or "",
                created_at=row[8],
                started_at=row[9] or 0.0,
                completed_at=row[10] or 0.0,
            )
            self._sub_tasks[sub_task.sub_task_id] = sub_task

        conn.close()

    async def create_task(
        self,
        project_id: str,
        name: str,
        description: str,
        created_by: str,
        target_scope: Optional[List[str]] = None,
        priority: TaskPriority = TaskPriority.NORMAL,
        assigned_to: str = "",
        deadline: float = 0.0,
        sub_task_names: Optional[List[Tuple[str, str]]] = None,
    ) -> str:
        """Create a new collaboration task.

        Args:
            project_id: Target project ID.
            name: Task name.
            description: Task description.
            created_by: Member who created this task.
            target_scope: Target scope (IP ranges, domains).
            priority: Task priority.
            assigned_to: Member to assign (empty for open claiming).
            deadline: Deadline timestamp.
            sub_task_names: Optional list of (name, description) for sub-tasks.

        Returns:
            New task ID.
        """
        task_id = f"task_{uuid.uuid4().hex[:12]}"
        now = time.time()

        task = CollaborationTask(
            task_id=task_id,
            project_id=project_id,
            name=name,
            description=description,
            target_scope=target_scope or [],
            priority=priority,
            status=TaskStatus.PENDING,
            created_by=created_by,
            assigned_to=assigned_to,
            deadline=deadline,
            created_at=now,
        )

        if assigned_to:
            task.status = TaskStatus.CLAIMED

        self._tasks[task_id] = task
        self._save_task(task)

        if sub_task_names:
            for sub_name, sub_desc in sub_task_names:
                await self.create_sub_task(task_id, sub_name, sub_desc, assigned_to)

        return task_id

    async def create_sub_task(
        self,
        task_id: str,
        name: str,
        description: str,
        assigned_to: str = "",
    ) -> str:
        """Create a sub-task within a main task.

        Args:
            task_id: Parent task ID.
            name: Sub-task name.
            description: Sub-task description.
            assigned_to: Member to assign.

        Returns:
            New sub-task ID.
        """
        task = self._tasks.get(task_id)
        if not task:
            raise ValueError(f"Task not found: {task_id}")

        sub_task_id = f"sub_{uuid.uuid4().hex[:12]}"
        now = time.time()

        sub_task = SubTask(
            sub_task_id=sub_task_id,
            task_id=task_id,
            name=name,
            description=description,
            assigned_to=assigned_to,
            status=TaskStatus.CLAIMED if assigned_to else TaskStatus.PENDING,
            created_at=now,
        )

        self._sub_tasks[sub_task_id] = sub_task
        task.sub_tasks.append(sub_task_id)

        self._save_sub_task(sub_task)
        self._save_task(task)

        return sub_task_id

    async def claim_task(self, task_id: str, member_id: str) -> bool:
        """Claim an open task for execution.

        Args:
            task_id: Task to claim.
            member_id: Member claiming the task.

        Returns:
            True if claimed successfully.
        """
        task = self._tasks.get(task_id)
        if not task:
            return False

        if task.assigned_to:
            return False

        task.assigned_to = member_id
        task.status = TaskStatus.CLAIMED
        task.started_at = time.time()

        self._save_task(task)

        return True

    async def start_task(self, task_id: str, member_id: str) -> bool:
        """Mark a claimed task as in progress.

        Args:
            task_id: Task to start.
            member_id: Member starting the task.

        Returns:
            True if started successfully.
        """
        task = self._tasks.get(task_id)
        if not task:
            return False

        if task.assigned_to != member_id:
            return False

        task.status = TaskStatus.IN_PROGRESS
        task.started_at = time.time()

        self._save_task(task)

        return True

    async def complete_task(self, task_id: str, member_id: str) -> bool:
        """Mark a task as completed.

        Args:
            task_id: Task to complete.
            member_id: Member completing the task.

        Returns:
            True if completed successfully.
        """
        task = self._tasks.get(task_id)
        if not task:
            return False

        if task.assigned_to != member_id:
            return False

        task.status = TaskStatus.COMPLETED
        task.progress = 100.0
        task.completed_at = time.time()

        self._save_task(task)

        for callback in self._progress_callbacks:
            try:
                await callback(task.project_id, task)
            except Exception as e:
                logger.error(f"Progress callback error: {e}")

        return True

    async def block_task(self, task_id: str, member_id: str, reason: str) -> bool:
        """Mark a task as blocked.

        Args:
            task_id: Task to block.
            member_id: Member blocking the task.
            reason: Reason for blocking.

        Returns:
            True if blocked successfully.
        """
        task = self._tasks.get(task_id)
        if not task:
            return False

        if task.assigned_to != member_id:
            return False

        task.status = TaskStatus.BLOCKED
        task.notes = f"Blocked: {reason}"

        self._save_task(task)

        return True

    async def update_task_progress(
        self,
        task_id: str,
        member_id: str,
        progress: float,
        notes: str = "",
    ) -> bool:
        """Update task progress percentage and notes.

        Args:
            task_id: Task to update.
            member_id: Member updating the task.
            progress: Progress percentage (0-100).
            notes: Progress notes.

        Returns:
            True if updated successfully.
        """
        task = self._tasks.get(task_id)
        if not task:
            return False

        if task.assigned_to != member_id:
            return False

        task.progress = max(0.0, min(100.0, progress))
        if notes:
            task.notes = notes

        self._save_task(task)

        for callback in self._progress_callbacks:
            try:
                await callback(task.project_id, task)
            except Exception as e:
                logger.error(f"Progress callback error: {e}")

        return True

    async def update_sub_task_progress(
        self,
        sub_task_id: str,
        member_id: str,
        progress: float,
        notes: str = "",
    ) -> bool:
        """Update sub-task progress.

        Args:
            sub_task_id: Sub-task to update.
            member_id: Member updating the sub-task.
            progress: Progress percentage (0-100).
            notes: Progress notes.

        Returns:
            True if updated successfully.
        """
        sub_task = self._sub_tasks.get(sub_task_id)
        if not sub_task:
            return False

        if sub_task.assigned_to and sub_task.assigned_to != member_id:
            return False

        sub_task.progress = max(0.0, min(100.0, progress))
        if notes:
            sub_task.notes = notes

        if progress >= 100.0:
            sub_task.status = TaskStatus.COMPLETED
            sub_task.completed_at = time.time()

        self._save_sub_task(sub_task)

        task = self._tasks.get(sub_task.task_id)
        if task:
            self._recalculate_task_progress(task)

        return True

    def get_task(self, task_id: str) -> Optional[CollaborationTask]:
        """Get task by ID.

        Args:
            task_id: Task identifier.

        Returns:
            CollaborationTask or None.
        """
        return self._tasks.get(task_id)

    def get_sub_task(self, sub_task_id: str) -> Optional[SubTask]:
        """Get sub-task by ID.

        Args:
            sub_task_id: Sub-task identifier.

        Returns:
            SubTask or None.
        """
        return self._sub_tasks.get(sub_task_id)

    def get_project_tasks(self, project_id: str) -> List[CollaborationTask]:
        """Get all tasks for a project.

        Args:
            project_id: Project identifier.

        Returns:
            List of CollaborationTask objects.
        """
        return [t for t in self._tasks.values() if t.project_id == project_id]

    def get_member_tasks(self, project_id: str, member_id: str) -> List[CollaborationTask]:
        """Get tasks assigned to a specific member.

        Args:
            project_id: Project identifier.
            member_id: Member identifier.

        Returns:
            List of CollaborationTask objects.
        """
        return [
            t for t in self._tasks.values()
            if t.project_id == project_id and t.assigned_to == member_id
        ]

    def get_open_tasks(self, project_id: str) -> List[CollaborationTask]:
        """Get open tasks available for claiming.

        Args:
            project_id: Project identifier.

        Returns:
            List of CollaborationTask objects.
        """
        return [
            t for t in self._tasks.values()
            if t.project_id == project_id and not t.assigned_to
        ]

    def get_task_sub_tasks(self, task_id: str) -> List[SubTask]:
        """Get all sub-tasks for a main task.

        Args:
            task_id: Task identifier.

        Returns:
            List of SubTask objects.
        """
        return [s for s in self._sub_tasks.values() if s.task_id == task_id]

    def _recalculate_task_progress(self, task: CollaborationTask) -> None:
        """Recalculate overall task progress from sub-tasks.

        Args:
            task: Task to recalculate.
        """
        if not task.sub_tasks:
            return

        sub_tasks = [self._sub_tasks.get(st_id) for st_id in task.sub_tasks]
        valid_sub_tasks: List[SubTask] = [st for st in sub_tasks if st is not None]

        if not valid_sub_tasks:
            return

        total_progress = sum(st.progress for st in valid_sub_tasks)
        task.progress = total_progress / len(valid_sub_tasks)

        if task.progress >= 100.0:
            task.status = TaskStatus.COMPLETED
            task.completed_at = time.time()

        self._save_task(task)

    def _save_task(self, task: CollaborationTask) -> None:
        """Save task to database.

        Args:
            task: CollaborationTask to save.
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT OR REPLACE INTO tasks VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                task.task_id,
                task.project_id,
                task.name,
                task.description,
                json.dumps(task.target_scope),
                task.priority.value,
                task.status.value,
                task.created_by,
                task.assigned_to or None,
                task.deadline if task.deadline > 0 else None,
                task.progress,
                task.notes,
                json.dumps(task.sub_tasks),
                task.created_at,
                task.started_at if task.started_at > 0 else None,
                task.completed_at if task.completed_at > 0 else None,
            ),
        )
        conn.commit()
        conn.close()

    def _save_sub_task(self, sub_task: SubTask) -> None:
        """Save sub-task to database.

        Args:
            sub_task: SubTask to save.
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT OR REPLACE INTO sub_tasks VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                sub_task.sub_task_id,
                sub_task.task_id,
                sub_task.name,
                sub_task.description,
                sub_task.assigned_to or None,
                sub_task.status.value,
                sub_task.progress,
                sub_task.notes,
                sub_task.created_at,
                sub_task.started_at if sub_task.started_at > 0 else None,
                sub_task.completed_at if sub_task.completed_at > 0 else None,
            ),
        )
        conn.commit()
        conn.close()
