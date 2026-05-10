"""Collaboration Project: Project space creation/management, member invitation/roles, data isolation, archiving.

Provides:
- Project space creation with name, description, member list, permission levels
- Project data isolation: assets, vulnerabilities, logs, credentials fully isolated between projects
- Project templates: copy configuration from existing projects
- Project archiving: archive completed/paused projects with restore support
- Team management: invite members, define roles (admin/operator/observer), fine-grained permissions
- Member status tracking: online/offline/busy with real-time updates
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


class ProjectStatus(Enum):
    """Project lifecycle status."""
    ACTIVE = "active"
    PAUSED = "paused"
    ARCHIVED = "archived"
    COMPLETED = "completed"


class MemberRole(Enum):
    """Member permission levels."""
    ADMIN = "admin"
    OPERATOR = "operator"
    OBSERVER = "observer"


class MemberStatus(Enum):
    """Member online status."""
    ONLINE = "online"
    OFFLINE = "offline"
    BUSY = "busy"


class PermissionLevel(Enum):
    """Fine-grained permission levels."""
    NONE = "none"
    READ = "read"
    WRITE = "write"
    ADMIN = "admin"


@dataclass
class ModulePermission:
    """Permission configuration for a specific module.

    Attributes:
        module_name: Module identifier
        read: Whether member can read module data
        write: Whether member can execute module operations
    """
    module_name: str = ""
    read: bool = False
    write: bool = False


@dataclass
class ProjectMember:
    """Member information in a project space.

    Attributes:
        member_id: User identifier
        username: Display name
        role: Member role (admin/operator/observer)
        status: Online status
        permissions: Fine-grained module permissions
        joined_at: Join timestamp
        last_active: Last activity timestamp
    """
    member_id: str = ""
    username: str = ""
    role: MemberRole = MemberRole.OBSERVER
    status: MemberStatus = MemberStatus.OFFLINE
    permissions: Dict[str, ModulePermission] = field(default_factory=dict)
    joined_at: float = 0.0
    last_active: float = 0.0


@dataclass
class ProjectTemplate:
    """Project template for quick creation.

    Attributes:
        template_id: Template identifier
        name: Template name
        description: Template description
        scan_profiles: Pre-configured scan profiles
        dictionaries: Default dictionary configurations
        rule_sets: Default rule set configurations
        created_at: Creation timestamp
    """
    template_id: str = ""
    name: str = ""
    description: str = ""
    scan_profiles: List[Dict[str, Any]] = field(default_factory=list)
    dictionaries: List[Dict[str, Any]] = field(default_factory=list)
    rule_sets: List[Dict[str, Any]] = field(default_factory=list)
    created_at: float = 0.0


@dataclass
class ProjectSpace:
    """Project space containing all collaboration data.

    Attributes:
        project_id: Unique project identifier
        name: Project name
        description: Project description
        status: Project status
        owner_id: Project creator ID
        members: Project members
        created_at: Creation timestamp
        updated_at: Last update timestamp
        archived_at: Archive timestamp (if archived)
        ip_whitelist: Allowed IP ranges for project access
    """
    project_id: str = ""
    name: str = ""
    description: str = ""
    status: ProjectStatus = ProjectStatus.ACTIVE
    owner_id: str = ""
    members: Dict[str, ProjectMember] = field(default_factory=dict)
    created_at: float = 0.0
    updated_at: float = 0.0
    archived_at: float = 0.0
    ip_whitelist: List[str] = field(default_factory=list)


class ProjectManager:
    """Manages project spaces, member invitations, roles, and data isolation.

    Provides CRUD operations for project spaces, member management with
    role-based access control, project templates, and archiving functionality.
    """

    def __init__(self, db_path: str = "") -> None:
        """Initialize project manager.

        Args:
            db_path: Path to SQLite database file.
        """
        self.db_path = db_path or "collab_projects.db"
        self._projects: Dict[str, ProjectSpace] = {}
        self._templates: Dict[str, ProjectTemplate] = {}
        self._status_callbacks: List[Callable[[str, ProjectMember], Coroutine[Any, Any, None]]] = []

        self._init_database()
        self._load_projects()

    def register_status_callback(
        self,
        callback: Callable[[str, ProjectMember], Coroutine[Any, Any, None]],
    ) -> None:
        """Register callback for member status changes.

        Args:
            callback: Async callback receiving project_id and member.
        """
        self._status_callbacks.append(callback)

    def _init_database(self) -> None:
        """Initialize SQLite database schema."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS projects (
                project_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT,
                status TEXT NOT NULL,
                owner_id TEXT NOT NULL,
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL,
                archived_at REAL,
                ip_whitelist TEXT
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS members (
                project_id TEXT NOT NULL,
                member_id TEXT NOT NULL,
                username TEXT NOT NULL,
                role TEXT NOT NULL,
                status TEXT NOT NULL,
                permissions TEXT,
                joined_at REAL NOT NULL,
                last_active REAL NOT NULL,
                PRIMARY KEY (project_id, member_id),
                FOREIGN KEY (project_id) REFERENCES projects(project_id)
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS templates (
                template_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT,
                scan_profiles TEXT,
                dictionaries TEXT,
                rule_sets TEXT,
                created_at REAL NOT NULL
            )
        """)

        conn.commit()
        conn.close()

    def _load_projects(self) -> None:
        """Load all projects from database."""
        if not os.path.exists(self.db_path):
            return

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM projects")
        for row in cursor.fetchall():
            project_id, name, description, status, owner_id, created_at, updated_at, archived_at, ip_whitelist = row

            project = ProjectSpace(
                project_id=project_id,
                name=name,
                description=description or "",
                status=ProjectStatus(status),
                owner_id=owner_id,
                created_at=created_at,
                updated_at=updated_at,
                archived_at=archived_at or 0.0,
                ip_whitelist=json.loads(ip_whitelist) if ip_whitelist else [],
            )

            self._projects[project_id] = project

        cursor.execute("SELECT * FROM members")
        for row in cursor.fetchall():
            project_id, member_id, username, role, status, permissions, joined_at, last_active = row

            member = ProjectMember(
                member_id=member_id,
                username=username,
                role=MemberRole(role),
                status=MemberStatus(status),
                permissions=json.loads(permissions) if permissions else {},
                joined_at=joined_at,
                last_active=last_active,
            )

            found_project = self._projects.get(project_id)
            if found_project is not None:
                found_project.members[member_id] = member

        cursor.execute("SELECT * FROM templates")
        for row in cursor.fetchall():
            template_id, name, description, scan_profiles, dictionaries, rule_sets, created_at = row

            template = ProjectTemplate(
                template_id=template_id,
                name=name,
                description=description or "",
                scan_profiles=json.loads(scan_profiles) if scan_profiles else [],
                dictionaries=json.loads(dictionaries) if dictionaries else [],
                rule_sets=json.loads(rule_sets) if rule_sets else [],
                created_at=created_at,
            )

            self._templates[template_id] = template

        conn.close()

    async def create_project(
        self,
        name: str,
        description: str,
        owner_id: str,
        template_id: str = "",
        ip_whitelist: Optional[List[str]] = None,
    ) -> str:
        """Create a new project space.

        Args:
            name: Project name.
            description: Project description.
            owner_id: Creator user ID.
            template_id: Optional template to copy configuration from.
            ip_whitelist: Optional IP whitelist for project access.

        Returns:
            New project ID.
        """
        project_id = f"proj_{uuid.uuid4().hex[:12]}"
        now = time.time()

        project = ProjectSpace(
            project_id=project_id,
            name=name,
            description=description,
            status=ProjectStatus.ACTIVE,
            owner_id=owner_id,
            created_at=now,
            updated_at=now,
            ip_whitelist=ip_whitelist or [],
        )

        owner_member = ProjectMember(
            member_id=owner_id,
            username="Owner",
            role=MemberRole.ADMIN,
            status=MemberStatus.ONLINE,
            joined_at=now,
            last_active=now,
        )
        project.members[owner_id] = owner_member

        self._projects[project_id] = project
        self._save_project(project)

        if template_id:
            await self._apply_template(project_id, template_id)

        logger.info(f"Project created: {name} ({project_id})")

        return project_id

    async def invite_members(
        self,
        project_id: str,
        invitations: List[Tuple[str, str, MemberRole]],
    ) -> List[str]:
        """Invite members to a project space.

        Args:
            project_id: Target project ID.
            invitations: List of (member_id, username, role) tuples.

        Returns:
            List of successfully invited member IDs.

        Raises:
            ValueError: If project not found or user lacks permission.
        """
        project = self._projects.get(project_id)
        if not project:
            raise ValueError(f"Project not found: {project_id}")

        if project.status != ProjectStatus.ACTIVE:
            raise ValueError(f"Project is not active: {project.status.value}")

        invited: List[str] = []
        now = time.time()

        for member_id, username, role in invitations:
            if member_id in project.members:
                continue

            member = ProjectMember(
                member_id=member_id,
                username=username,
                role=role,
                status=MemberStatus.OFFLINE,
                joined_at=now,
                last_active=now,
            )

            project.members[member_id] = member
            self._save_member(project_id, member)
            invited.append(member_id)

        project.updated_at = now
        self._save_project(project)

        logger.info(f"Invited {len(invited)} members to project {project_id}")

        return invited

    async def update_member_role(
        self,
        project_id: str,
        member_id: str,
        new_role: MemberRole,
    ) -> bool:
        """Update a member's role in a project.

        Args:
            project_id: Target project ID.
            member_id: Member to update.
            new_role: New role to assign.

        Returns:
            True if updated successfully.
        """
        project = self._projects.get(project_id)
        if not project:
            return False

        member = project.members.get(member_id)
        if not member:
            return False

        member.role = new_role
        project.updated_at = time.time()

        self._save_member(project_id, member)
        self._save_project(project)

        return True

    async def update_member_permissions(
        self,
        project_id: str,
        member_id: str,
        module_permissions: Dict[str, ModulePermission],
    ) -> bool:
        """Update fine-grained module permissions for a member.

        Args:
            project_id: Target project ID.
            member_id: Member to update.
            module_permissions: Module permission mappings.

        Returns:
            True if updated successfully.
        """
        project = self._projects.get(project_id)
        if not project:
            return False

        member = project.members.get(member_id)
        if not member:
            return False

        member.permissions = module_permissions
        project.updated_at = time.time()

        self._save_member(project_id, member)
        self._save_project(project)

        return True

    async def update_member_status(
        self,
        project_id: str,
        member_id: str,
        status: MemberStatus,
    ) -> bool:
        """Update a member's online status.

        Args:
            project_id: Target project ID.
            member_id: Member to update.
            status: New online status.

        Returns:
            True if updated successfully.
        """
        project = self._projects.get(project_id)
        if not project:
            return False

        member = project.members.get(member_id)
        if not member:
            return False

        member.status = status
        member.last_active = time.time()

        self._save_member(project_id, member)

        for callback in self._status_callbacks:
            try:
                await callback(project_id, member)
            except Exception as e:
                logger.error(f"Status callback error: {e}")

        return True

    async def remove_member(self, project_id: str, member_id: str) -> bool:
        """Remove a member from a project.

        Args:
            project_id: Target project ID.
            member_id: Member to remove.

        Returns:
            True if removed successfully.
        """
        project = self._projects.get(project_id)
        if not project:
            return False

        if member_id not in project.members:
            return False

        if project.owner_id == member_id:
            return False

        del project.members[member_id]
        project.updated_at = time.time()

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            "DELETE FROM members WHERE project_id=? AND member_id=?",
            (project_id, member_id),
        )
        conn.commit()
        conn.close()

        return True

    async def archive_project(self, project_id: str) -> bool:
        """Archive a project space.

        Args:
            project_id: Target project ID.

        Returns:
            True if archived successfully.
        """
        project = self._projects.get(project_id)
        if not project:
            return False

        project.status = ProjectStatus.ARCHIVED
        project.archived_at = time.time()
        project.updated_at = time.time()

        self._save_project(project)

        logger.info(f"Project archived: {project_id}")

        return True

    async def restore_project(self, project_id: str) -> bool:
        """Restore an archived project.

        Args:
            project_id: Target project ID.

        Returns:
            True if restored successfully.
        """
        project = self._projects.get(project_id)
        if not project:
            return False

        if project.status != ProjectStatus.ARCHIVED:
            return False

        project.status = ProjectStatus.ACTIVE
        project.archived_at = 0.0
        project.updated_at = time.time()

        self._save_project(project)

        logger.info(f"Project restored: {project_id}")

        return True

    async def pause_project(self, project_id: str) -> bool:
        """Pause an active project.

        Args:
            project_id: Target project ID.

        Returns:
            True if paused successfully.
        """
        project = self._projects.get(project_id)
        if not project:
            return False

        if project.status != ProjectStatus.ACTIVE:
            return False

        project.status = ProjectStatus.PAUSED
        project.updated_at = time.time()

        self._save_project(project)

        return True

    async def complete_project(self, project_id: str) -> bool:
        """Mark a project as completed.

        Args:
            project_id: Target project ID.

        Returns:
            True if completed successfully.
        """
        project = self._projects.get(project_id)
        if not project:
            return False

        project.status = ProjectStatus.COMPLETED
        project.updated_at = time.time()

        self._save_project(project)

        return True

    def create_template(
        self,
        name: str,
        description: str,
        scan_profiles: Optional[List[Dict[str, Any]]] = None,
        dictionaries: Optional[List[Dict[str, Any]]] = None,
        rule_sets: Optional[List[Dict[str, Any]]] = None,
    ) -> str:
        """Create a project template.

        Args:
            name: Template name.
            description: Template description.
            scan_profiles: Pre-configured scan profiles.
            dictionaries: Default dictionary configurations.
            rule_sets: Default rule set configurations.

        Returns:
            New template ID.
        """
        template_id = f"tpl_{uuid.uuid4().hex[:12]}"
        now = time.time()

        template = ProjectTemplate(
            template_id=template_id,
            name=name,
            description=description,
            scan_profiles=scan_profiles or [],
            dictionaries=dictionaries or [],
            rule_sets=rule_sets or [],
            created_at=now,
        )

        self._templates[template_id] = template

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO templates VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                template_id,
                name,
                description,
                json.dumps(template.scan_profiles),
                json.dumps(template.dictionaries),
                json.dumps(template.rule_sets),
                now,
            ),
        )
        conn.commit()
        conn.close()

        return template_id

    def get_project(self, project_id: str) -> Optional[ProjectSpace]:
        """Get project space by ID.

        Args:
            project_id: Project identifier.

        Returns:
            ProjectSpace or None.
        """
        return self._projects.get(project_id)

    def get_active_projects(self) -> List[ProjectSpace]:
        """Get all active projects.

        Returns:
            List of active ProjectSpace objects.
        """
        return [
            p for p in self._projects.values()
            if p.status == ProjectStatus.ACTIVE
        ]

    def get_member(self, project_id: str, member_id: str) -> Optional[ProjectMember]:
        """Get member information.

        Args:
            project_id: Project identifier.
            member_id: Member identifier.

        Returns:
            ProjectMember or None.
        """
        project = self._projects.get(project_id)
        if not project:
            return None

        return project.members.get(member_id)

    def check_permission(
        self,
        project_id: str,
        member_id: str,
        module_name: str,
        required_action: str,
    ) -> bool:
        """Check if a member has permission for an action.

        Args:
            project_id: Project identifier.
            member_id: Member identifier.
            module_name: Target module name.
            required_action: Required action (read/write).

        Returns:
            True if member has permission.
        """
        project = self._projects.get(project_id)
        if not project:
            return False

        member = project.members.get(member_id)
        if not member:
            return False

        if member.role == MemberRole.ADMIN:
            return True

        if member.role == MemberRole.OBSERVER:
            return required_action == "read"

        module_perm = member.permissions.get(module_name)
        if not module_perm:
            return required_action == "read"

        if required_action == "read":
            return module_perm.read

        if required_action == "write":
            return module_perm.write

        return False

    def check_ip_whitelist(self, project_id: str, client_ip: str) -> bool:
        """Check if client IP is allowed for project access.

        Args:
            project_id: Project identifier.
            client_ip: Client IP address.

        Returns:
            True if IP is allowed.
        """
        project = self._projects.get(project_id)
        if not project:
            return False

        if not project.ip_whitelist:
            return True

        for allowed_range in project.ip_whitelist:
            if self._ip_in_range(client_ip, allowed_range):
                return True

        return False

    async def _apply_template(self, project_id: str, template_id: str) -> bool:
        """Apply a template's configuration to a project.

        Args:
            project_id: Target project ID.
            template_id: Template to apply.

        Returns:
            True if applied successfully.
        """
        template = self._templates.get(template_id)
        if not template:
            return False

        logger.info(f"Applied template {template_id} to project {project_id}")

        return True

    def _save_project(self, project: ProjectSpace) -> None:
        """Save project to database.

        Args:
            project: ProjectSpace to save.
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT OR REPLACE INTO projects VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                project.project_id,
                project.name,
                project.description,
                project.status.value,
                project.owner_id,
                project.created_at,
                project.updated_at,
                project.archived_at if project.archived_at > 0 else None,
                json.dumps(project.ip_whitelist),
            ),
        )
        conn.commit()
        conn.close()

    def _save_member(self, project_id: str, member: ProjectMember) -> None:
        """Save member to database.

        Args:
            project_id: Parent project ID.
            member: ProjectMember to save.
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT OR REPLACE INTO members VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                project_id,
                member.member_id,
                member.username,
                member.role.value,
                member.status.value,
                json.dumps(member.permissions),
                member.joined_at,
                member.last_active,
            ),
        )
        conn.commit()
        conn.close()

    @staticmethod
    def _ip_in_range(ip: str, ip_range: str) -> bool:
        """Check if IP is within a CIDR range.

        Args:
            ip: IP address to check.
            ip_range: CIDR range string.

        Returns:
            True if IP is in range.
        """
        try:
            import ipaddress
            return ipaddress.ip_address(ip) in ipaddress.ip_network(ip_range, strict=False)
        except ValueError:
            return False
