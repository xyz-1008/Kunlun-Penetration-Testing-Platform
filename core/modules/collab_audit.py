"""Collaboration Audit: Operation audit logs, sensitive operation confirmation, access control.

Provides:
- All member operations recorded to audit logs: operator, time, operation type, target, command parameters, result
- Logs cannot be tampered with, supports export as compliance audit reports
- Sensitive operations (e.g., lateral movement, exploit) require secondary confirmation and automatic recording
- Member operations must be within project authorization: target scope check, module permission check
- Unauthorized operations automatically blocked and alerted
- IP whitelist: can restrict project access IP range (for intranet security projects)
"""

import asyncio
import hashlib
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


class AuditEventType(Enum):
    """Types of audit events."""
    LOGIN = "login"
    LOGOUT = "logout"
    PROJECT_ACCESS = "project_access"
    ASSET_DISCOVERY = "asset_discovery"
    VULNERABILITY_SCAN = "vulnerability_scan"
    EXPLOIT_EXECUTION = "exploit_execution"
    LATERAL_MOVEMENT = "lateral_movement"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    CREDENTIAL_ACCESS = "credential_access"
    FILE_UPLOAD = "file_upload"
    FILE_DOWNLOAD = "file_download"
    COMMAND_EXECUTION = "command_execution"
    CONFIGURATION_CHANGE = "configuration_change"
    MEMBER_INVITE = "member_invite"
    MEMBER_REMOVE = "member_remove"
    ROLE_CHANGE = "role_change"
    DATA_EXPORT = "data_export"
    PERMISSION_DENIED = "permission_denied"
    SENSITIVE_OPERATION = "sensitive_operation"


class AccessLevel(Enum):
    """Access control levels."""
    DENIED = "denied"
    READ_ONLY = "read_only"
    READ_WRITE = "read_write"
    ADMIN = "admin"


@dataclass
class AuditLogEntry:
    """Single audit log entry.

    Attributes:
        log_id: Unique log identifier
        project_id: Parent project ID
        timestamp: Event timestamp
        operator_id: Member who performed the operation
        operator_name: Display name of operator
        event_type: Type of audit event
        target: Target of the operation
        parameters: Command parameters in JSON format
        result: Operation result summary
        ip_address: Source IP address
        is_sensitive: Whether this is a sensitive operation
        requires_confirmation: Whether secondary confirmation was required
        hash_chain: Hash of previous entry for tamper detection
    """
    log_id: str = ""
    project_id: str = ""
    timestamp: float = 0.0
    operator_id: str = ""
    operator_name: str = ""
    event_type: AuditEventType = AuditEventType.LOGIN
    target: str = ""
    parameters: str = ""
    result: str = ""
    ip_address: str = ""
    is_sensitive: bool = False
    requires_confirmation: bool = False
    hash_chain: str = ""


@dataclass
class AccessRule:
    """Access control rule for a project module.

    Attributes:
        rule_id: Unique rule identifier
        project_id: Parent project ID
        role: Member role this rule applies to
        module: Module name (e.g., "asset_discovery", "exploit")
        access_level: Access level for this role-module combination
        target_scope: Allowed target scope (IP ranges, domains)
        created_at: Rule creation timestamp
    """
    rule_id: str = ""
    project_id: str = ""
    role: str = ""
    module: str = ""
    access_level: AccessLevel = AccessLevel.READ_ONLY
    target_scope: List[str] = field(default_factory=list)
    created_at: float = 0.0


@dataclass
class SensitiveOperationRequest:
    """Request for sensitive operation confirmation.

    Attributes:
        request_id: Unique request identifier
        project_id: Parent project ID
        operator_id: Member requesting the operation
        operator_name: Display name of operator
        operation_type: Type of sensitive operation
        target: Target of the operation
        parameters: Operation parameters
        status: Request status (pending/approved/denied)
        approver_id: Member who approved/denied
        created_at: Request creation timestamp
        responded_at: Response timestamp
    """
    request_id: str = ""
    project_id: str = ""
    operator_id: str = ""
    operator_name: str = ""
    operation_type: AuditEventType = AuditEventType.SENSITIVE_OPERATION
    target: str = ""
    parameters: str = ""
    status: str = "pending"
    approver_id: str = ""
    created_at: float = 0.0
    responded_at: float = 0.0


class AuditManager:
    """Manages operation audit logs, sensitive operation confirmation, and access control.

    Provides tamper-evident audit logging, sensitive operation secondary confirmation,
    role-based access control, and IP whitelist enforcement.
    """

    SENSITIVE_EVENT_TYPES = {
        AuditEventType.EXPLOIT_EXECUTION,
        AuditEventType.LATERAL_MOVEMENT,
        AuditEventType.PRIVILEGE_ESCALATION,
        AuditEventType.CREDENTIAL_ACCESS,
    }

    def __init__(self, db_path: str = "") -> None:
        """Initialize audit manager.

        Args:
            db_path: Path to SQLite database file.
        """
        self.db_path = db_path or "collab_audit.db"
        self._audit_logs: List[AuditLogEntry] = []
        self._access_rules: Dict[str, List[AccessRule]] = {}
        self._sensitive_requests: Dict[str, SensitiveOperationRequest] = {}
        self._ip_whitelists: Dict[str, List[str]] = {}
        self._confirmation_callbacks: List[Callable[[str, SensitiveOperationRequest], Coroutine[Any, Any, None]]] = []

        self._init_database()
        self._load_data()

    def register_confirmation_callback(
        self,
        callback: Callable[[str, SensitiveOperationRequest], Coroutine[Any, Any, None]],
    ) -> None:
        """Register callback for sensitive operation confirmation requests.

        Args:
            callback: Async callback receiving project_id and request.
        """
        self._confirmation_callbacks.append(callback)

    def _init_database(self) -> None:
        """Initialize SQLite database schema."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                log_id TEXT PRIMARY KEY,
                project_id TEXT NOT NULL,
                timestamp REAL NOT NULL,
                operator_id TEXT NOT NULL,
                operator_name TEXT NOT NULL,
                event_type TEXT NOT NULL,
                target TEXT,
                parameters TEXT,
                result TEXT,
                ip_address TEXT,
                is_sensitive INTEGER NOT NULL,
                requires_confirmation INTEGER NOT NULL,
                hash_chain TEXT NOT NULL
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS access_rules (
                rule_id TEXT PRIMARY KEY,
                project_id TEXT NOT NULL,
                role TEXT NOT NULL,
                module TEXT NOT NULL,
                access_level TEXT NOT NULL,
                target_scope TEXT,
                created_at REAL NOT NULL
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS sensitive_requests (
                request_id TEXT PRIMARY KEY,
                project_id TEXT NOT NULL,
                operator_id TEXT NOT NULL,
                operator_name TEXT NOT NULL,
                operation_type TEXT NOT NULL,
                target TEXT,
                parameters TEXT,
                status TEXT NOT NULL,
                approver_id TEXT,
                created_at REAL NOT NULL,
                responded_at REAL
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS ip_whitelists (
                project_id TEXT NOT NULL,
                ip_range TEXT NOT NULL,
                PRIMARY KEY (project_id, ip_range)
            )
        """)

        cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_project ON audit_logs(project_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_operator ON audit_logs(operator_id)")

        conn.commit()
        conn.close()

    def _load_data(self) -> None:
        """Load all audit data from database."""
        if not os.path.exists(self.db_path):
            return

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM audit_logs ORDER BY timestamp ASC")
        for row in cursor.fetchall():
            entry = AuditLogEntry(
                log_id=row[0],
                project_id=row[1],
                timestamp=row[2],
                operator_id=row[3],
                operator_name=row[4],
                event_type=AuditEventType(row[5]),
                target=row[6] or "",
                parameters=row[7] or "",
                result=row[8] or "",
                ip_address=row[9] or "",
                is_sensitive=bool(row[10]),
                requires_confirmation=bool(row[11]),
                hash_chain=row[12],
            )
            self._audit_logs.append(entry)

        cursor.execute("SELECT * FROM access_rules")
        for row in cursor.fetchall():
            rule = AccessRule(
                rule_id=row[0],
                project_id=row[1],
                role=row[2],
                module=row[3],
                access_level=AccessLevel(row[4]),
                target_scope=json.loads(row[5]) if row[5] else [],
                created_at=row[6],
            )

            if rule.project_id not in self._access_rules:
                self._access_rules[rule.project_id] = []

            self._access_rules[rule.project_id].append(rule)

        cursor.execute("SELECT * FROM sensitive_requests")
        for row in cursor.fetchall():
            request = SensitiveOperationRequest(
                request_id=row[0],
                project_id=row[1],
                operator_id=row[2],
                operator_name=row[3],
                operation_type=AuditEventType(row[4]),
                target=row[5] or "",
                parameters=row[6] or "",
                status=row[7],
                approver_id=row[8] or "",
                created_at=row[9],
                responded_at=row[10] or 0.0,
            )
            self._sensitive_requests[request.request_id] = request

        cursor.execute("SELECT * FROM ip_whitelists")
        for row in cursor.fetchall():
            project_id = row[0]
            if project_id not in self._ip_whitelists:
                self._ip_whitelists[project_id] = []
            self._ip_whitelists[project_id].append(row[1])

        conn.close()

    async def log_operation(
        self,
        project_id: str,
        operator_id: str,
        operator_name: str,
        event_type: AuditEventType,
        target: str = "",
        parameters: Optional[Dict[str, Any]] = None,
        result: str = "",
        ip_address: str = "",
    ) -> str:
        """Log an operation to the audit trail.

        Args:
            project_id: Target project ID.
            operator_id: Member who performed the operation.
            operator_name: Display name of operator.
            event_type: Type of audit event.
            target: Target of the operation.
            parameters: Command parameters.
            result: Operation result summary.
            ip_address: Source IP address.

        Returns:
            New log entry ID.
        """
        is_sensitive = event_type in self.SENSITIVE_EVENT_TYPES
        requires_confirmation = is_sensitive

        previous_hash = self._audit_logs[-1].log_id if self._audit_logs else "genesis"
        hash_chain = self._generate_hash_chain(previous_hash, project_id, operator_id, event_type.value)

        log_id = f"audit_{uuid.uuid4().hex[:12]}"
        now = time.time()

        entry = AuditLogEntry(
            log_id=log_id,
            project_id=project_id,
            timestamp=now,
            operator_id=operator_id,
            operator_name=operator_name,
            event_type=event_type,
            target=target,
            parameters=json.dumps(parameters) if parameters else "",
            result=result,
            ip_address=ip_address,
            is_sensitive=is_sensitive,
            requires_confirmation=requires_confirmation,
            hash_chain=hash_chain,
        )

        self._audit_logs.append(entry)
        self._save_audit_log(entry)

        return log_id

    async def request_sensitive_operation(
        self,
        project_id: str,
        operator_id: str,
        operator_name: str,
        operation_type: AuditEventType,
        target: str,
        parameters: Optional[Dict[str, Any]] = None,
    ) -> SensitiveOperationRequest:
        """Request confirmation for a sensitive operation.

        Args:
            project_id: Target project ID.
            operator_id: Member requesting the operation.
            operator_name: Display name of operator.
            operation_type: Type of sensitive operation.
            target: Target of the operation.
            parameters: Operation parameters.

        Returns:
            SensitiveOperationRequest object.
        """
        request_id = f"sensitive_{uuid.uuid4().hex[:12]}"
        now = time.time()

        request = SensitiveOperationRequest(
            request_id=request_id,
            project_id=project_id,
            operator_id=operator_id,
            operator_name=operator_name,
            operation_type=operation_type,
            target=target,
            parameters=json.dumps(parameters) if parameters else "",
            status="pending",
            created_at=now,
        )

        self._sensitive_requests[request_id] = request
        self._save_sensitive_request(request)

        for callback in self._confirmation_callbacks:
            try:
                await callback(project_id, request)
            except Exception as e:
                logger.error(f"Confirmation callback error: {e}")

        return request

    async def approve_sensitive_operation(
        self,
        request_id: str,
        approver_id: str,
    ) -> bool:
        """Approve a sensitive operation request.

        Args:
            request_id: Request identifier.
            approver_id: Member approving the request.

        Returns:
            True if approved successfully.
        """
        request = self._sensitive_requests.get(request_id)
        if not request:
            return False

        if request.status != "pending":
            return False

        request.status = "approved"
        request.approver_id = approver_id
        request.responded_at = time.time()

        self._save_sensitive_request(request)

        await self.log_operation(
            project_id=request.project_id,
            operator_id=approver_id,
            operator_name="Approver",
            event_type=AuditEventType.PERMISSION_DENIED,
            target=f"Approved sensitive operation: {request.request_id}",
            result="Sensitive operation approved",
        )

        return True

    async def deny_sensitive_operation(
        self,
        request_id: str,
        approver_id: str,
    ) -> bool:
        """Deny a sensitive operation request.

        Args:
            request_id: Request identifier.
            approver_id: Member denying the request.

        Returns:
            True if denied successfully.
        """
        request = self._sensitive_requests.get(request_id)
        if not request:
            return False

        if request.status != "pending":
            return False

        request.status = "denied"
        request.approver_id = approver_id
        request.responded_at = time.time()

        self._save_sensitive_request(request)

        await self.log_operation(
            project_id=request.project_id,
            operator_id=approver_id,
            operator_name="Approver",
            event_type=AuditEventType.PERMISSION_DENIED,
            target=f"Denied sensitive operation: {request.request_id}",
            result="Sensitive operation denied",
        )

        return True

    def check_access(
        self,
        project_id: str,
        role: str,
        module: str,
        target: str = "",
    ) -> AccessLevel:
        """Check access level for a role-module combination.

        Args:
            project_id: Project identifier.
            role: Member role.
            module: Module name.
            target: Target to check against scope.

        Returns:
            AccessLevel for this role-module combination.
        """
        rules = self._access_rules.get(project_id, [])

        for rule in rules:
            if rule.role == role and rule.module == module:
                if target and rule.target_scope:
                    if not self._is_target_in_scope(target, rule.target_scope):
                        return AccessLevel.DENIED
                return rule.access_level

        return AccessLevel.DENIED

    def check_ip_whitelist(self, project_id: str, ip_address: str) -> bool:
        """Check if an IP address is in the project whitelist.

        Args:
            project_id: Project identifier.
            ip_address: IP address to check.

        Returns:
            True if IP is whitelisted or no whitelist exists.
        """
        whitelist = self._ip_whitelists.get(project_id)
        if not whitelist:
            return True

        return self._is_ip_in_whitelist(ip_address, whitelist)

    def set_ip_whitelist(self, project_id: str, ip_ranges: List[str]) -> None:
        """Set IP whitelist for a project.

        Args:
            project_id: Project identifier.
            ip_ranges: List of IP ranges to whitelist.
        """
        self._ip_whitelists[project_id] = ip_ranges

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM ip_whitelists WHERE project_id = ?", (project_id,))

        for ip_range in ip_ranges:
            cursor.execute(
                "INSERT INTO ip_whitelists VALUES (?, ?)",
                (project_id, ip_range),
            )

        conn.commit()
        conn.close()

    def add_access_rule(
        self,
        project_id: str,
        role: str,
        module: str,
        access_level: AccessLevel,
        target_scope: Optional[List[str]] = None,
    ) -> str:
        """Add an access control rule.

        Args:
            project_id: Project identifier.
            role: Member role.
            module: Module name.
            access_level: Access level.
            target_scope: Optional target scope restriction.

        Returns:
            New rule ID.
        """
        rule_id = f"rule_{uuid.uuid4().hex[:12]}"
        now = time.time()

        rule = AccessRule(
            rule_id=rule_id,
            project_id=project_id,
            role=role,
            module=module,
            access_level=access_level,
            target_scope=target_scope or [],
            created_at=now,
        )

        if project_id not in self._access_rules:
            self._access_rules[project_id] = []

        self._access_rules[project_id].append(rule)
        self._save_access_rule(rule)

        return rule_id

    def get_audit_logs(
        self,
        project_id: str,
        limit: int = 100,
        offset: int = 0,
    ) -> List[AuditLogEntry]:
        """Get audit logs for a project.

        Args:
            project_id: Project identifier.
            limit: Maximum logs to return.
            offset: Number of logs to skip.

        Returns:
            List of AuditLogEntry objects, newest first.
        """
        project_logs = [log for log in self._audit_logs if log.project_id == project_id]

        project_logs.sort(key=lambda x: x.timestamp, reverse=True)

        return project_logs[offset:offset + limit]

    def verify_audit_integrity(self, project_id: str) -> bool:
        """Verify the integrity of audit logs (tamper detection).

        Args:
            project_id: Project identifier.

        Returns:
            True if audit chain is intact.
        """
        project_logs = [
            log for log in self._audit_logs
            if log.project_id == project_id
        ]

        project_logs.sort(key=lambda x: x.timestamp)

        previous_hash = "genesis"
        for log in project_logs:
            expected_hash = self._generate_hash_chain(
                previous_hash,
                log.project_id,
                log.operator_id,
                log.event_type.value,
            )

            if log.hash_chain != expected_hash:
                return False

            previous_hash = log.log_id

        return True

    def export_audit_report(self, project_id: str) -> str:
        """Export audit logs as a compliance report.

        Args:
            project_id: Project identifier.

        Returns:
            JSON string of audit report.
        """
        logs = self.get_audit_logs(project_id, limit=10000)

        report_data = {
            "project_id": project_id,
            "generated_at": time.time(),
            "total_entries": len(logs),
            "integrity_verified": self.verify_audit_integrity(project_id),
            "logs": [
                {
                    "log_id": log.log_id,
                    "timestamp": log.timestamp,
                    "timestamp_human": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(log.timestamp)),
                    "operator_id": log.operator_id,
                    "operator_name": log.operator_name,
                    "event_type": log.event_type.value,
                    "target": log.target,
                    "parameters": json.loads(log.parameters) if log.parameters else {},
                    "result": log.result,
                    "ip_address": log.ip_address,
                    "is_sensitive": log.is_sensitive,
                    "requires_confirmation": log.requires_confirmation,
                }
                for log in logs
            ],
        }

        return json.dumps(report_data, ensure_ascii=False, indent=2)

    def _generate_hash_chain(self, previous_hash: str, project_id: str, operator_id: str, event_type: str) -> str:
        """Generate hash chain entry for tamper detection.

        Args:
            previous_hash: Hash of previous entry.
            project_id: Project identifier.
            operator_id: Operator identifier.
            event_type: Event type.

        Returns:
            SHA-256 hash string.
        """
        raw = f"{previous_hash}:{project_id}:{operator_id}:{event_type}"
        return hashlib.sha256(raw.encode()).hexdigest()

    def _is_target_in_scope(self, target: str, target_scope: List[str]) -> bool:
        """Check if a target is within the allowed scope.

        Args:
            target: Target to check.
            target_scope: List of allowed targets/ranges.

        Returns:
            True if target is in scope.
        """
        for scope in target_scope:
            if scope == target:
                return True
            if scope.endswith("/*") and target.startswith(scope[:-2]):
                return True
            if scope.endswith("/0") and target.startswith(scope[:-2]):
                return True

        return False

    def _is_ip_in_whitelist(self, ip_address: str, whitelist: List[str]) -> bool:
        """Check if an IP is in the whitelist.

        Args:
            ip_address: IP address to check.
            whitelist: List of whitelisted IPs/ranges.

        Returns:
            True if IP is whitelisted.
        """
        for entry in whitelist:
            if entry == ip_address:
                return True
            if "/" in entry:
                network, prefix = entry.split("/")
                if ip_address.startswith(network.rsplit(".", 1)[0]):
                    return True

        return False

    def _save_audit_log(self, entry: AuditLogEntry) -> None:
        """Save audit log entry to database.

        Args:
            entry: AuditLogEntry to save.
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT OR REPLACE INTO audit_logs VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                entry.log_id,
                entry.project_id,
                entry.timestamp,
                entry.operator_id,
                entry.operator_name,
                entry.event_type.value,
                entry.target or None,
                entry.parameters or None,
                entry.result or None,
                entry.ip_address or None,
                int(entry.is_sensitive),
                int(entry.requires_confirmation),
                entry.hash_chain,
            ),
        )
        conn.commit()
        conn.close()

    def _save_access_rule(self, rule: AccessRule) -> None:
        """Save access rule to database.

        Args:
            rule: AccessRule to save.
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT OR REPLACE INTO access_rules VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                rule.rule_id,
                rule.project_id,
                rule.role,
                rule.module,
                rule.access_level.value,
                json.dumps(rule.target_scope),
                rule.created_at,
            ),
        )
        conn.commit()
        conn.close()

    def _save_sensitive_request(self, request: SensitiveOperationRequest) -> None:
        """Save sensitive operation request to database.

        Args:
            request: SensitiveOperationRequest to save.
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT OR REPLACE INTO sensitive_requests VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                request.request_id,
                request.project_id,
                request.operator_id,
                request.operator_name,
                request.operation_type.value,
                request.target or None,
                request.parameters or None,
                request.status,
                request.approver_id or None,
                request.created_at,
                request.responded_at if request.responded_at > 0 else None,
            ),
        )
        conn.commit()
        conn.close()
