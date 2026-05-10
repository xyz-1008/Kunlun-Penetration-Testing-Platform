"""Collaboration Integration: Integration interfaces with asset, proxy, C2, and report modules.

Provides:
- Asset discovery module integration: automatic asset sharing to team pool
- Proxy module integration: traffic sharing and request import
- C2 module integration: credential import and session sharing
- Report module integration: timeline export and audit log export
- Event bus integration: real-time notifications across modules
"""

import asyncio
import json
import logging
import time
from typing import Any, Callable, Coroutine, Dict, List, Optional, Set, Tuple

from .collab_project import ProjectManager, ProjectSpace, MemberRole
from .collab_sharing import (
    SharingPool,
    SharedAsset,
    SharedCredential,
    SharedTraffic,
    SharedVulnerability,
    CredentialType,
    AssetClaimStatus,
    VulnerabilityStatus,
)
from .collab_task import TaskManager, CollaborationTask, SubTask, TaskPriority, TaskStatus
from .collab_timeline import TimelineManager, TimelineEntry, OperationType
from .collab_dashboard import DashboardManager, DashboardData, AttackStage, TargetProgress, MemberContribution
from .collab_chat import ChatManager, ChatMessage, MessageType
from .collab_audit import AuditManager, AuditLogEntry, AuditEventType, AccessLevel, SensitiveOperationRequest

logger = logging.getLogger(__name__)


class CollaborationIntegration:
    """Integration layer connecting collaboration modules with existing penetration testing tools.

    Provides unified interfaces for asset discovery, proxy, C2, and report modules
    to interact with the collaboration system. Handles event routing, data synchronization,
    and cross-module notifications.
    """

    def __init__(
        self,
        project_manager: Optional[ProjectManager] = None,
        sharing_pool: Optional[SharingPool] = None,
        task_manager: Optional[TaskManager] = None,
        timeline_manager: Optional[TimelineManager] = None,
        dashboard_manager: Optional[DashboardManager] = None,
        chat_manager: Optional[ChatManager] = None,
        audit_manager: Optional[AuditManager] = None,
    ) -> None:
        """Initialize collaboration integration.

        Args:
            project_manager: Project space manager instance.
            sharing_pool: Sharing pool instance.
            task_manager: Task manager instance.
            timeline_manager: Timeline manager instance.
            dashboard_manager: Dashboard manager instance.
            chat_manager: Chat manager instance.
            audit_manager: Audit manager instance.
        """
        self.project_manager = project_manager or ProjectManager()
        self.sharing_pool = sharing_pool or SharingPool()
        self.task_manager = task_manager or TaskManager()
        self.timeline_manager = timeline_manager or TimelineManager()
        self.dashboard_manager = dashboard_manager or DashboardManager()
        self.chat_manager = chat_manager or ChatManager()
        self.audit_manager = audit_manager or AuditManager()

        self._event_handlers: Dict[str, List[Callable[[Dict[str, Any]], Coroutine[Any, Any, None]]]] = {}
        self._setup_internal_callbacks()

    def _setup_internal_callbacks(self) -> None:
        """Setup internal callbacks for cross-module synchronization."""
        self.sharing_pool.register_asset_callback(self._on_asset_shared)
        self.sharing_pool.register_credential_callback(self._on_credential_shared)
        self.sharing_pool.register_vulnerability_callback(self._on_vulnerability_shared)
        self.task_manager.register_progress_callback(self._on_task_progress)
        self.timeline_manager.register_entry_callback(self._on_timeline_entry)
        self.dashboard_manager.register_alert_callback(self._on_dashboard_alert)
        self.dashboard_manager.register_update_callback(self._on_dashboard_update)
        self.chat_manager.register_message_callback(self._on_chat_message)
        self.audit_manager.register_confirmation_callback(self._on_sensitive_request)

    def register_event_handler(
        self,
        event_type: str,
        handler: Callable[[Dict[str, Any]], Coroutine[Any, Any, None]],
    ) -> None:
        """Register handler for collaboration events.

        Args:
            event_type: Event type string.
            handler: Async event handler function.
        """
        if event_type not in self._event_handlers:
            self._event_handlers[event_type] = []

        self._event_handlers[event_type].append(handler)

    async def emit_event(self, event_type: str, data: Dict[str, Any]) -> None:
        """Emit a collaboration event to all registered handlers.

        Args:
            event_type: Event type string.
            data: Event data dictionary.
        """
        handlers = self._event_handlers.get(event_type, [])

        for handler in handlers:
            try:
                await handler(data)
            except Exception as e:
                logger.error(f"Event handler error for {event_type}: {e}")

    async def on_asset_discovered(
        self,
        project_id: str,
        member_id: str,
        member_name: str,
        ip: str,
        port: int,
        protocol: str,
        service: str = "",
        fingerprint: str = "",
        hostname: str = "",
    ) -> Optional[SharedAsset]:
        """Handle asset discovery from asset discovery module.

        Args:
            project_id: Target project ID.
            member_id: Member who discovered the asset.
            member_name: Display name of member.
            ip: IP address.
            port: Port number.
            protocol: Protocol detected.
            service: Service name.
            fingerprint: Service fingerprint.
            hostname: Hostname.

        Returns:
            SharedAsset if new, or existing if duplicate.
        """
        asset = await self.sharing_pool.share_asset(
            project_id=project_id,
            ip=ip,
            port=port,
            protocol=protocol,
            service=service,
            discovered_by=member_id,
            fingerprint=fingerprint,
            hostname=hostname,
        )

        if asset:
            await self.timeline_manager.add_entry(
                project_id=project_id,
                operator_id=member_id,
                operator_name=member_name,
                operation_type=OperationType.ASSET_DISCOVERY,
                target=f"{ip}:{port}",
                result_summary=f"Discovered {service or protocol} service",
            )

            self.dashboard_manager.update_project_metrics(
                project_id=project_id,
                total_assets=len(self.sharing_pool.get_project_assets(project_id)),
            )

            self.dashboard_manager.increment_member_contribution(
                project_id=project_id,
                member_id=member_id,
                member_name=member_name,
                assets_discovered=1,
            )

            await self.emit_event("asset_discovered", {
                "project_id": project_id,
                "member_id": member_id,
                "asset_id": asset.asset_id,
                "ip": ip,
                "port": port,
            })

        return asset

    async def on_traffic_captured(
        self,
        project_id: str,
        member_id: str,
        member_name: str,
        request: str,
        response: str,
        url: str,
        method: str,
        status_code: int,
        tags: Optional[List[str]] = None,
        notes: str = "",
    ) -> str:
        """Handle traffic capture from proxy module.

        Args:
            project_id: Target project ID.
            member_id: Member who captured the traffic.
            member_name: Display name of member.
            request: HTTP request data.
            response: HTTP response data.
            url: Request URL.
            method: HTTP method.
            status_code: Response status code.
            tags: Optional tags.
            notes: Optional notes.

        Returns:
            New traffic ID.
        """
        traffic_id = await self.sharing_pool.share_traffic(
            project_id=project_id,
            request=request,
            response=response,
            url=url,
            method=method,
            status_code=status_code,
            shared_by=member_id,
            tags=tags,
            notes=notes,
        )

        await self.timeline_manager.add_entry(
            project_id=project_id,
            operator_id=member_id,
            operator_name=member_name,
            operation_type=OperationType.CUSTOM,
            target=url,
            result_summary=f"Captured {method} {status_code}",
        )

        return traffic_id

    async def on_vulnerability_found(
        self,
        project_id: str,
        member_id: str,
        member_name: str,
        asset_id: str,
        title: str,
        severity: str,
        description: str,
        proof: str,
    ) -> Optional[SharedVulnerability]:
        """Handle vulnerability discovery from vulnerability scanning module.

        Args:
            project_id: Target project ID.
            member_id: Member who found the vulnerability.
            member_name: Display name of member.
            asset_id: Associated asset ID.
            title: Vulnerability title.
            severity: Severity level.
            description: Vulnerability description.
            proof: Proof of concept.

        Returns:
            SharedVulnerability if new, or existing if duplicate.
        """
        vuln = await self.sharing_pool.share_vulnerability(
            project_id=project_id,
            asset_id=asset_id,
            title=title,
            severity=severity,
            description=description,
            proof=proof,
            discovered_by=member_id,
        )

        if vuln:
            await self.timeline_manager.add_entry(
                project_id=project_id,
                operator_id=member_id,
                operator_name=member_name,
                operation_type=OperationType.VULNERABILITY_FOUND,
                target=asset_id,
                result_summary=f"Found {severity} vulnerability: {title}",
                is_sensitive=severity in ("critical", "high"),
            )

            self.dashboard_manager.update_project_metrics(
                project_id=project_id,
                total_vulnerabilities=len(self.sharing_pool.get_project_vulnerabilities(project_id)),
            )

            self.dashboard_manager.increment_member_contribution(
                project_id=project_id,
                member_id=member_id,
                member_name=member_name,
                vulnerabilities_found=1,
            )

            if severity in ("critical", "high"):
                await self.dashboard_manager.add_high_risk_alert(
                    project_id=project_id,
                    alert_message=f"[{severity.upper()}] {title} on {asset_id}",
                )

                await self.chat_manager.send_alert_message(
                    project_id=project_id,
                    alert_text=f"🚨 High-risk vulnerability found: {title} ({severity})",
                )

            await self.emit_event("vulnerability_found", {
                "project_id": project_id,
                "member_id": member_id,
                "vuln_id": vuln.vuln_id,
                "severity": severity,
                "title": title,
            })

        return vuln

    async def on_credential_obtained(
        self,
        project_id: str,
        member_id: str,
        member_name: str,
        cred_type: CredentialType,
        target: str,
        username: str,
        password: str,
        source_module: str,
        expires_at: float = 0.0,
    ) -> str:
        """Handle credential acquisition from C2 or exploitation module.

        Args:
            project_id: Target project ID.
            member_id: Member who obtained the credential.
            member_name: Display name of member.
            cred_type: Credential type.
            target: Target system/service.
            username: Username or account name.
            password: Password/hash value.
            source_module: Module that obtained this credential.
            expires_at: Expiration timestamp.

        Returns:
            New credential ID.
        """
        cred_id = await self.sharing_pool.share_credential(
            project_id=project_id,
            cred_type=cred_type,
            target=target,
            username=username,
            password=password,
            source_module=source_module,
            obtained_by=member_id,
            expires_at=expires_at,
        )

        await self.timeline_manager.add_entry(
            project_id=project_id,
            operator_id=member_id,
            operator_name=member_name,
            operation_type=OperationType.CREDENTIAL_OBTAINED,
            target=target,
            result_summary=f"Obtained {cred_type.value} for {username}",
            is_sensitive=True,
        )

        self.dashboard_manager.update_project_metrics(
            project_id=project_id,
            total_credentials=len(self.sharing_pool.get_project_credentials(project_id)),
        )

        self.dashboard_manager.increment_member_contribution(
            project_id=project_id,
            member_id=member_id,
            member_name=member_name,
            credentials_obtained=1,
        )

        await self.emit_event("credential_obtained", {
            "project_id": project_id,
            "member_id": member_id,
            "cred_id": cred_id,
            "target": target,
            "cred_type": cred_type.value,
        })

        return cred_id

    async def on_task_created(
        self,
        project_id: str,
        member_id: str,
        member_name: str,
        task_name: str,
        description: str,
        target_scope: Optional[List[str]] = None,
        priority: TaskPriority = TaskPriority.NORMAL,
        assigned_to: str = "",
        deadline: float = 0.0,
        sub_task_names: Optional[List[Tuple[str, str]]] = None,
    ) -> str:
        """Handle task creation from task management module.

        Args:
            project_id: Target project ID.
            member_id: Member who created the task.
            member_name: Display name of member.
            task_name: Task name.
            description: Task description.
            target_scope: Target scope.
            priority: Task priority.
            assigned_to: Member to assign.
            deadline: Deadline timestamp.
            sub_task_names: Optional sub-task definitions.

        Returns:
            New task ID.
        """
        task_id = await self.task_manager.create_task(
            project_id=project_id,
            name=task_name,
            description=description,
            created_by=member_id,
            target_scope=target_scope,
            priority=priority,
            assigned_to=assigned_to,
            deadline=deadline,
            sub_task_names=sub_task_names,
        )

        await self.timeline_manager.add_entry(
            project_id=project_id,
            operator_id=member_id,
            operator_name=member_name,
            operation_type=OperationType.TASK_CREATED,
            result_summary=f"Created task: {task_name}",
        )

        self.dashboard_manager.update_project_metrics(
            project_id=project_id,
            total_tasks=len(self.task_manager.get_project_tasks(project_id)),
        )

        if assigned_to:
            await self.chat_manager.send_message(
                project_id=project_id,
                sender_id="system",
                sender_name="System",
                content=f"Task assigned to you: {task_name}",
                message_type=MessageType.TASK_NOTIFICATION,
                metadata={"task_id": task_id},
            )

        return task_id

    async def on_exploit_executed(
        self,
        project_id: str,
        member_id: str,
        member_name: str,
        target: str,
        exploit_name: str,
        success: bool,
        requires_confirmation: bool = True,
    ) -> bool:
        """Handle exploit execution from exploitation module.

        Args:
            project_id: Target project ID.
            member_id: Member who executed the exploit.
            member_name: Display name of member.
            target: Target of the exploit.
            exploit_name: Exploit name.
            success: Whether exploit succeeded.
            requires_confirmation: Whether secondary confirmation is needed.

        Returns:
            True if execution was allowed.
        """
        if requires_confirmation:
            request = await self.audit_manager.request_sensitive_operation(
                project_id=project_id,
                operator_id=member_id,
                operator_name=member_name,
                operation_type=AuditEventType.EXPLOIT_EXECUTION,
                target=target,
                parameters={"exploit": exploit_name},
            )

            if request.status != "approved":
                return False

        await self.timeline_manager.add_entry(
            project_id=project_id,
            operator_id=member_id,
            operator_name=member_name,
            operation_type=OperationType.EXPLOIT_RUN,
            target=target,
            result_summary=f"Executed {exploit_name}: {'success' if success else 'failed'}",
            is_sensitive=True,
        )

        await self.audit_manager.log_operation(
            project_id=project_id,
            operator_id=member_id,
            operator_name=member_name,
            event_type=AuditEventType.EXPLOIT_EXECUTION,
            target=target,
            parameters={"exploit": exploit_name, "success": success},
            result="success" if success else "failed",
        )

        return True

    async def on_lateral_movement(
        self,
        project_id: str,
        member_id: str,
        member_name: str,
        source_host: str,
        target_host: str,
        technique: str,
        credential_id: str = "",
        success: bool = False,
    ) -> bool:
        """Handle lateral movement from lateral movement module.

        Args:
            project_id: Target project ID.
            member_id: Member performing lateral movement.
            member_name: Display name of member.
            source_host: Source host.
            target_host: Target host.
            technique: Lateral movement technique.
            credential_id: Credential used.
            success: Whether movement succeeded.

        Returns:
            True if movement was allowed.
        """
        request = await self.audit_manager.request_sensitive_operation(
            project_id=project_id,
            operator_id=member_id,
            operator_name=member_name,
            operation_type=AuditEventType.LATERAL_MOVEMENT,
            target=target_host,
            parameters={"source": source_host, "technique": technique},
        )

        if request.status != "approved":
            return False

        await self.timeline_manager.add_entry(
            project_id=project_id,
            operator_id=member_id,
            operator_name=member_name,
            operation_type=OperationType.LATERAL_MOVE,
            target=f"{source_host} -> {target_host}",
            result_summary=f"Lateral movement via {technique}: {'success' if success else 'failed'}",
            is_sensitive=True,
        )

        await self.audit_manager.log_operation(
            project_id=project_id,
            operator_id=member_id,
            operator_name=member_name,
            event_type=AuditEventType.LATERAL_MOVEMENT,
            target=target_host,
            parameters={
                "source": source_host,
                "technique": technique,
                "credential_id": credential_id,
                "success": success,
            },
            result="success" if success else "failed",
        )

        if credential_id:
            await self.sharing_pool.use_credential(credential_id)

        return True

    async def generate_project_report(
        self,
        project_id: str,
        report_type: str = "full",
    ) -> Dict[str, Any]:
        """Generate comprehensive project report for report module.

        Args:
            project_id: Target project ID.
            report_type: Report type (full, timeline, audit, assets, vulnerabilities).

        Returns:
            Report data dictionary.
        """
        report: Dict[str, Any] = {
            "project_id": project_id,
            "generated_at": time.time(),
            "report_type": report_type,
        }

        if report_type in ("full", "assets"):
            assets = self.sharing_pool.get_project_assets(project_id)
            report["assets"] = {
                "total": len(assets),
                "claimed": len([a for a in assets if a.claim_status != AssetClaimStatus.UNCLAIMED]),
                "items": [
                    {
                        "asset_id": a.asset_id,
                        "ip": a.ip,
                        "port": a.port,
                        "protocol": a.protocol,
                        "service": a.service,
                        "discovered_by": a.discovered_by,
                        "claim_status": a.claim_status.value,
                        "tags": a.tags,
                    }
                    for a in assets
                ],
            }

        if report_type in ("full", "vulnerabilities"):
            vulns = self.sharing_pool.get_project_vulnerabilities(project_id)
            report["vulnerabilities"] = {
                "total": len(vulns),
                "confirmed": len([v for v in vulns if v.status == VulnerabilityStatus.CONFIRMED]),
                "items": [
                    {
                        "vuln_id": v.vuln_id,
                        "title": v.title,
                        "severity": v.severity,
                        "status": v.status.value,
                        "discovered_by": v.discovered_by,
                    }
                    for v in vulns
                ],
            }

        if report_type in ("full", "timeline"):
            report["timeline_export"] = self.timeline_manager.export_timeline_json(project_id)

        if report_type in ("full", "audit"):
            report["audit_export"] = self.audit_manager.export_audit_report(project_id)

        if report_type in ("full", "tasks"):
            tasks = self.task_manager.get_project_tasks(project_id)
            report["tasks"] = {
                "total": len(tasks),
                "completed": len([t for t in tasks if t.status == TaskStatus.COMPLETED]),
                "in_progress": len([t for t in tasks if t.status == TaskStatus.IN_PROGRESS]),
            }

        if report_type == "full":
            report["dashboard"] = self.dashboard_manager.get_dashboard(project_id)
            report["chat_archive"] = self.chat_manager.archive_project_messages(project_id)

        return report

    async def _on_asset_shared(self, project_id: str, asset: SharedAsset) -> None:
        """Handle asset shared event."""
        await self.emit_event("internal_asset_shared", {
            "project_id": project_id,
            "asset_id": asset.asset_id,
        })

    async def _on_credential_shared(self, project_id: str, cred: SharedCredential) -> None:
        """Handle credential shared event."""
        await self.emit_event("internal_credential_shared", {
            "project_id": project_id,
            "cred_id": cred.cred_id,
        })

    async def _on_vulnerability_shared(self, project_id: str, vuln: SharedVulnerability) -> None:
        """Handle vulnerability shared event."""
        await self.emit_event("internal_vulnerability_shared", {
            "project_id": project_id,
            "vuln_id": vuln.vuln_id,
        })

    async def _on_task_progress(self, project_id: str, task: CollaborationTask) -> None:
        """Handle task progress update event."""
        await self.emit_event("internal_task_progress", {
            "project_id": project_id,
            "task_id": task.task_id,
            "progress": task.progress,
        })

    async def _on_timeline_entry(self, project_id: str, entry: TimelineEntry) -> None:
        """Handle timeline entry event."""
        await self.emit_event("internal_timeline_entry", {
            "project_id": project_id,
            "entry_id": entry.entry_id,
        })

    async def _on_dashboard_alert(self, project_id: str, alert: str) -> None:
        """Handle dashboard alert event."""
        await self.emit_event("internal_dashboard_alert", {
            "project_id": project_id,
            "alert": alert,
        })

    async def _on_dashboard_update(self, project_id: str, dashboard: DashboardData) -> None:
        """Handle dashboard update event."""
        await self.emit_event("internal_dashboard_update", {
            "project_id": project_id,
            "updated_at": dashboard.updated_at,
        })

    async def _on_chat_message(self, project_id: str, message: ChatMessage) -> None:
        """Handle chat message event."""
        await self.emit_event("internal_chat_message", {
            "project_id": project_id,
            "message_id": message.message_id,
        })

    async def _on_sensitive_request(self, project_id: str, request: SensitiveOperationRequest) -> None:
        """Handle sensitive operation request event."""
        await self.emit_event("internal_sensitive_request", {
            "project_id": project_id,
            "request_id": request.request_id,
        })
