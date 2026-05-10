"""Collaboration Timeline: War room timeline aggregation, filtering, export.

Provides:
- Automatic aggregation of all project operations into a war room timeline
- Display: timestamp, operator, operation type, target, result summary
- Filter by operator, operation type, time range
- Timeline export as report or audit log
"""

import asyncio
import csv
import io
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


class OperationType(Enum):
    """Types of operations recorded in the timeline."""
    ASSET_DISCOVERY = "asset_discovery"
    VULNERABILITY_FOUND = "vulnerability_found"
    CREDENTIAL_OBTAINED = "credential_obtained"
    TASK_CREATED = "task_created"
    TASK_CLAIMED = "task_claimed"
    TASK_COMPLETED = "task_completed"
    MESSAGE_SENT = "message_sent"
    COMMAND_EXECUTED = "command_executed"
    EXPLOIT_RUN = "exploit_run"
    LATERAL_MOVE = "lateral_move"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    SCAN_STARTED = "scan_started"
    SCAN_COMPLETED = "scan_completed"
    FILE_UPLOADED = "file_uploaded"
    MEMBER_JOINED = "member_joined"
    MEMBER_LEFT = "member_left"
    PROJECT_CREATED = "project_created"
    PROJECT_ARCHIVED = "project_archived"
    CUSTOM = "custom"


@dataclass
class TimelineEntry:
    """Single entry in the war room timeline.

    Attributes:
        entry_id: Unique entry identifier
        project_id: Parent project ID
        timestamp: Operation timestamp
        operator_id: Member who performed the operation
        operator_name: Display name of operator
        operation_type: Type of operation
        target: Target of the operation (IP, domain, etc.)
        result_summary: Brief summary of the result
        details: Additional details in JSON format
        is_sensitive: Whether this is a sensitive operation
    """
    entry_id: str = ""
    project_id: str = ""
    timestamp: float = 0.0
    operator_id: str = ""
    operator_name: str = ""
    operation_type: OperationType = OperationType.CUSTOM
    target: str = ""
    result_summary: str = ""
    details: str = ""
    is_sensitive: bool = False


class TimelineManager:
    """Manages the war room timeline for project operations.

    Aggregates all operations into a searchable, filterable timeline
    with export capabilities for reporting and auditing.
    """

    def __init__(self, db_path: str = "") -> None:
        """Initialize timeline manager.

        Args:
            db_path: Path to SQLite database file.
        """
        self.db_path = db_path or "collab_timeline.db"
        self._entries: List[TimelineEntry] = []
        self._entry_callbacks: List[Callable[[str, TimelineEntry], Coroutine[Any, Any, None]]] = []

        self._init_database()
        self._load_entries()

    def register_entry_callback(
        self,
        callback: Callable[[str, TimelineEntry], Coroutine[Any, Any, None]],
    ) -> None:
        """Register callback for new timeline entries.

        Args:
            callback: Async callback receiving project_id and entry.
        """
        self._entry_callbacks.append(callback)

    def _init_database(self) -> None:
        """Initialize SQLite database schema."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS timeline_entries (
                entry_id TEXT PRIMARY KEY,
                project_id TEXT NOT NULL,
                timestamp REAL NOT NULL,
                operator_id TEXT NOT NULL,
                operator_name TEXT NOT NULL,
                operation_type TEXT NOT NULL,
                target TEXT,
                result_summary TEXT,
                details TEXT,
                is_sensitive INTEGER NOT NULL
            )
        """)

        cursor.execute("CREATE INDEX IF NOT EXISTS idx_timeline_project ON timeline_entries(project_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_timeline_timestamp ON timeline_entries(timestamp)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_timeline_operator ON timeline_entries(operator_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_timeline_type ON timeline_entries(operation_type)")

        conn.commit()
        conn.close()

    def _load_entries(self) -> None:
        """Load all timeline entries from database."""
        if not os.path.exists(self.db_path):
            return

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM timeline_entries ORDER BY timestamp ASC")
        for row in cursor.fetchall():
            entry = TimelineEntry(
                entry_id=row[0],
                project_id=row[1],
                timestamp=row[2],
                operator_id=row[3],
                operator_name=row[4],
                operation_type=OperationType(row[5]),
                target=row[6] or "",
                result_summary=row[7] or "",
                details=row[8] or "",
                is_sensitive=bool(row[9]),
            )
            self._entries.append(entry)

        conn.close()

    async def add_entry(
        self,
        project_id: str,
        operator_id: str,
        operator_name: str,
        operation_type: OperationType,
        target: str = "",
        result_summary: str = "",
        details: Optional[Dict[str, Any]] = None,
        is_sensitive: bool = False,
    ) -> str:
        """Add a new entry to the war room timeline.

        Args:
            project_id: Target project ID.
            operator_id: Member who performed the operation.
            operator_name: Display name of operator.
            operation_type: Type of operation.
            target: Target of the operation.
            result_summary: Brief summary of the result.
            details: Additional details.
            is_sensitive: Whether this is a sensitive operation.

        Returns:
            New entry ID.
        """
        entry_id = f"tl_{uuid.uuid4().hex[:12]}"
        now = time.time()

        entry = TimelineEntry(
            entry_id=entry_id,
            project_id=project_id,
            timestamp=now,
            operator_id=operator_id,
            operator_name=operator_name,
            operation_type=operation_type,
            target=target,
            result_summary=result_summary,
            details=json.dumps(details) if details else "",
            is_sensitive=is_sensitive,
        )

        self._entries.append(entry)
        self._save_entry(entry)

        for callback in self._entry_callbacks:
            try:
                await callback(project_id, entry)
            except Exception as e:
                logger.error(f"Timeline callback error: {e}")

        return entry_id

    def get_project_timeline(
        self,
        project_id: str,
        limit: int = 100,
        offset: int = 0,
    ) -> List[TimelineEntry]:
        """Get timeline entries for a project.

        Args:
            project_id: Project identifier.
            limit: Maximum entries to return.
            offset: Number of entries to skip.

        Returns:
            List of TimelineEntry objects, newest first.
        """
        project_entries = [
            e for e in self._entries
            if e.project_id == project_id
        ]

        project_entries.sort(key=lambda x: x.timestamp, reverse=True)

        return project_entries[offset:offset + limit]

    def filter_timeline(
        self,
        project_id: str,
        operator_id: str = "",
        operation_type: Optional[OperationType] = None,
        start_time: float = 0.0,
        end_time: float = 0.0,
        sensitive_only: bool = False,
    ) -> List[TimelineEntry]:
        """Filter timeline entries by various criteria.

        Args:
            project_id: Project identifier.
            operator_id: Filter by operator (empty for all).
            operation_type: Filter by operation type (None for all).
            start_time: Filter entries after this timestamp.
            end_time: Filter entries before this timestamp.
            sensitive_only: Only return sensitive operations.

        Returns:
            Filtered list of TimelineEntry objects.
        """
        results = [e for e in self._entries if e.project_id == project_id]

        if operator_id:
            results = [e for e in results if e.operator_id == operator_id]

        if operation_type:
            results = [e for e in results if e.operation_type == operation_type]

        if start_time > 0:
            results = [e for e in results if e.timestamp >= start_time]

        if end_time > 0:
            results = [e for e in results if e.timestamp <= end_time]

        if sensitive_only:
            results = [e for e in results if e.is_sensitive]

        results.sort(key=lambda x: x.timestamp, reverse=True)

        return results

    def export_timeline_json(self, project_id: str) -> str:
        """Export timeline as JSON string.

        Args:
            project_id: Project identifier.

        Returns:
            JSON string of timeline entries.
        """
        entries = self.get_project_timeline(project_id, limit=10000)

        export_data = [
            {
                "entry_id": e.entry_id,
                "timestamp": e.timestamp,
                "timestamp_human": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(e.timestamp)),
                "operator_id": e.operator_id,
                "operator_name": e.operator_name,
                "operation_type": e.operation_type.value,
                "target": e.target,
                "result_summary": e.result_summary,
                "details": json.loads(e.details) if e.details else {},
                "is_sensitive": e.is_sensitive,
            }
            for e in entries
        ]

        return json.dumps(export_data, ensure_ascii=False, indent=2)

    def export_timeline_csv(self, project_id: str) -> str:
        """Export timeline as CSV string.

        Args:
            project_id: Project identifier.

        Returns:
            CSV string of timeline entries.
        """
        entries = self.get_project_timeline(project_id, limit=10000)

        output = io.StringIO()
        writer = csv.writer(output)

        writer.writerow([
            "Timestamp", "Operator", "Operation Type",
            "Target", "Result Summary", "Is Sensitive",
        ])

        for entry in entries:
            writer.writerow([
                time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(entry.timestamp)),
                entry.operator_name,
                entry.operation_type.value,
                entry.target,
                entry.result_summary,
                "Yes" if entry.is_sensitive else "No",
            ])

        return output.getvalue()

    def export_timeline_markdown(self, project_id: str) -> str:
        """Export timeline as Markdown report.

        Args:
            project_id: Project identifier.

        Returns:
            Markdown string of timeline entries.
        """
        entries = self.get_project_timeline(project_id, limit=10000)

        lines = ["# War Room Timeline Report\n"]

        if entries:
            first_time = entries[-1].timestamp
            last_time = entries[0].timestamp
            lines.append(f"**Time Range**: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(first_time))} to {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(last_time))}")
            lines.append(f"**Total Operations**: {len(entries)}\n")

        lines.append("| Time | Operator | Operation | Target | Result |")
        lines.append("|------|----------|-----------|--------|--------|")

        for entry in entries:
            sensitive_marker = " ⚠️" if entry.is_sensitive else ""
            lines.append(
                f"| {time.strftime('%H:%M:%S', time.localtime(entry.timestamp))} "
                f"| {entry.operator_name} "
                f"| {entry.operation_type.value}{sensitive_marker} "
                f"| {entry.target} "
                f"| {entry.result_summary} |"
            )

        return "\n".join(lines)

    def get_statistics(self, project_id: str) -> Dict[str, Any]:
        """Get timeline statistics for a project.

        Args:
            project_id: Project identifier.

        Returns:
            Statistics dictionary.
        """
        entries = [e for e in self._entries if e.project_id == project_id]

        if not entries:
            return {
                "total_entries": 0,
                "operation_counts": {},
                "operator_counts": {},
                "sensitive_count": 0,
                "time_range": {"start": 0.0, "end": 0.0},
            }

        operation_counts: Dict[str, int] = {}
        operator_counts: Dict[str, int] = {}
        sensitive_count = 0

        for entry in entries:
            op_type = entry.operation_type.value
            operation_counts[op_type] = operation_counts.get(op_type, 0) + 1

            operator_counts[entry.operator_name] = operator_counts.get(entry.operator_name, 0) + 1

            if entry.is_sensitive:
                sensitive_count += 1

        timestamps = [e.timestamp for e in entries]

        return {
            "total_entries": len(entries),
            "operation_counts": operation_counts,
            "operator_counts": operator_counts,
            "sensitive_count": sensitive_count,
            "time_range": {
                "start": min(timestamps),
                "end": max(timestamps),
            },
        }

    def _save_entry(self, entry: TimelineEntry) -> None:
        """Save timeline entry to database.

        Args:
            entry: TimelineEntry to save.
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT OR REPLACE INTO timeline_entries VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                entry.entry_id,
                entry.project_id,
                entry.timestamp,
                entry.operator_id,
                entry.operator_name,
                entry.operation_type.value,
                entry.target or None,
                entry.result_summary or None,
                entry.details or None,
                int(entry.is_sensitive),
            ),
        )
        conn.commit()
        conn.close()
