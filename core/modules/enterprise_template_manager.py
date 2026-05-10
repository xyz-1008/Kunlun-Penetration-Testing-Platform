"""Enterprise Template Manager: Enterprise private library, usage audit, policy control.

Provides:
- Enterprise private template library: Internal templates that don't leave enterprise network
- Usage audit: Enterprise admin can view team member template usage history
- Policy control: Enterprise can restrict available template sources (official certified only, internal only)
"""

import asyncio
import json
import logging
import os
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


class TemplateSource(Enum):
    """Template source types."""
    OFFICIAL = "official"
    COMMUNITY = "community"
    INTERNAL = "internal"
    PARTNER = "partner"


class PolicyAction(Enum):
    """Policy actions."""
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"


class AuditEventType(Enum):
    """Audit event types."""
    TEMPLATE_VIEW = "template_view"
    TEMPLATE_DOWNLOAD = "template_download"
    TEMPLATE_EXECUTE = "template_execute"
    TEMPLATE_SHARE = "template_share"
    TEMPLATE_DELETE = "template_delete"
    POLICY_CHANGE = "policy_change"


@dataclass
class EnterpriseTemplate:
    """Enterprise private template.

    Attributes:
        template_id: Unique template identifier
        name: Template name
        description: Template description
        source: Template source
        author_id: Author identifier
        created_at: Creation timestamp
        updated_at: Last update timestamp
        is_active: Whether template is active
        classification: Security classification
        approved_by: Approver identifier
        approval_date: Approval timestamp
        tags: Template tags
        version: Template version
    """
    template_id: str = ""
    name: str = ""
    description: str = ""
    source: TemplateSource = TemplateSource.INTERNAL
    author_id: str = ""
    created_at: float = 0.0
    updated_at: float = 0.0
    is_active: bool = True
    classification: str = "internal"
    approved_by: str = ""
    approval_date: float = 0.0
    tags: List[str] = field(default_factory=list)
    version: str = "1.0.0"


@dataclass
class UsageAuditRecord:
    """Template usage audit record.

    Attributes:
        audit_id: Unique audit identifier
        enterprise_id: Enterprise identifier
        user_id: User identifier
        template_id: Template identifier
        event_type: Event type
        timestamp: Event timestamp
        details: Event details
        ip_address: User IP address
        session_id: Session identifier
    """
    audit_id: str = ""
    enterprise_id: str = ""
    user_id: str = ""
    template_id: str = ""
    event_type: AuditEventType = AuditEventType.TEMPLATE_VIEW
    timestamp: float = 0.0
    details: Dict[str, Any] = field(default_factory=dict)
    ip_address: str = ""
    session_id: str = ""


@dataclass
class TemplatePolicy:
    """Enterprise template policy.

    Attributes:
        policy_id: Unique policy identifier
        enterprise_id: Enterprise identifier
        allowed_sources: List of allowed template sources
        require_approval: Whether approval is required for template use
        approved_templates: List of pre-approved template IDs
        denied_templates: List of denied template IDs
        max_downloads_per_user: Maximum downloads per user per day
        require_classification: Whether classification is required
        allowed_classifications: List of allowed classifications
        auto_audit: Whether to auto-audit template usage
        created_at: Creation timestamp
        updated_at: Last update timestamp
    """
    policy_id: str = ""
    enterprise_id: str = ""
    allowed_sources: List[TemplateSource] = field(default_factory=lambda: [TemplateSource.OFFICIAL, TemplateSource.INTERNAL])
    require_approval: bool = True
    approved_templates: List[str] = field(default_factory=list)
    denied_templates: List[str] = field(default_factory=list)
    max_downloads_per_user: int = 10
    require_classification: bool = True
    allowed_classifications: List[str] = field(default_factory=lambda: ["public", "internal", "confidential"])
    auto_audit: bool = True
    created_at: float = 0.0
    updated_at: float = 0.0


@dataclass
class ApprovalRequest:
    """Template approval request.

    Attributes:
        request_id: Unique request identifier
        enterprise_id: Enterprise identifier
        user_id: User identifier
        template_id: Template identifier
        reason: Request reason
        status: Request status
        created_at: Creation timestamp
        reviewed_at: Review timestamp
        reviewer_id: Reviewer identifier
        review_comment: Review comment
    """
    request_id: str = ""
    enterprise_id: str = ""
    user_id: str = ""
    template_id: str = ""
    reason: str = ""
    status: str = "pending"
    created_at: float = 0.0
    reviewed_at: float = 0.0
    reviewer_id: str = ""
    review_comment: str = ""


class EnterpriseTemplateManager:
    """Enterprise template management system.

    Manages enterprise private template libraries, usage audits,
    and policy controls.
    """

    def __init__(self, storage_path: str = "") -> None:
        """Initialize enterprise template manager.

        Args:
            storage_path: Directory path for storage.
        """
        self.storage_path = storage_path
        self._enterprise_templates: Dict[str, List[EnterpriseTemplate]] = {}
        self._policies: Dict[str, TemplatePolicy] = {}
        self._audit_records: Dict[str, List[UsageAuditRecord]] = {}
        self._approval_requests: Dict[str, ApprovalRequest] = {}
        self._user_download_counts: Dict[str, Dict[str, int]] = {}

        if storage_path:
            os.makedirs(storage_path, exist_ok=True)
            self._load_data()

    async def add_template_to_enterprise(
        self,
        enterprise_id: str,
        template_id: str,
        name: str,
        description: str,
        author_id: str,
        source: TemplateSource = TemplateSource.INTERNAL,
        classification: str = "internal",
        tags: Optional[List[str]] = None,
    ) -> EnterpriseTemplate:
        """Add template to enterprise private library.

        Args:
            enterprise_id: Enterprise identifier.
            template_id: Template identifier.
            name: Template name.
            description: Template description.
            author_id: Author identifier.
            source: Template source.
            classification: Security classification.
            tags: Template tags.

        Returns:
            Created EnterpriseTemplate.
        """
        if enterprise_id not in self._enterprise_templates:
            self._enterprise_templates[enterprise_id] = []

        template = EnterpriseTemplate(
            template_id=template_id,
            name=name,
            description=description,
            source=source,
            author_id=author_id,
            created_at=time.time(),
            updated_at=time.time(),
            classification=classification,
            tags=tags or [],
        )

        self._enterprise_templates[enterprise_id].append(template)

        await self._record_audit(
            enterprise_id,
            author_id,
            template_id,
            AuditEventType.TEMPLATE_SHARE,
            {"action": "add_to_enterprise"},
        )

        self._save_data()

        return template

    async def remove_template_from_enterprise(
        self,
        enterprise_id: str,
        template_id: str,
        user_id: str,
    ) -> bool:
        """Remove template from enterprise library.

        Args:
            enterprise_id: Enterprise identifier.
            template_id: Template identifier.
            user_id: User identifier.

        Returns:
            True if removed successfully.
        """
        templates = self._enterprise_templates.get(enterprise_id, [])

        for i, template in enumerate(templates):
            if template.template_id == template_id:
                templates.pop(i)
                template.is_active = False

                await self._record_audit(
                    enterprise_id,
                    user_id,
                    template_id,
                    AuditEventType.TEMPLATE_DELETE,
                    {"action": "remove_from_enterprise"},
                )

                self._save_data()

                return True

        return False

    async def get_enterprise_templates(
        self,
        enterprise_id: str,
        source: Optional[TemplateSource] = None,
        classification: Optional[str] = None,
    ) -> List[EnterpriseTemplate]:
        """Get enterprise templates.

        Args:
            enterprise_id: Enterprise identifier.
            source: Filter by source.
            classification: Filter by classification.

        Returns:
            List of EnterpriseTemplate objects.
        """
        templates = self._enterprise_templates.get(enterprise_id, [])

        if source:
            templates = [t for t in templates if t.source == source]

        if classification:
            templates = [t for t in templates if t.classification == classification]

        return [t for t in templates if t.is_active]

    async def set_policy(
        self,
        enterprise_id: str,
        policy: TemplatePolicy,
    ) -> TemplatePolicy:
        """Set enterprise template policy.

        Args:
            enterprise_id: Enterprise identifier.
            policy: Template policy.

        Returns:
            Updated TemplatePolicy.
        """
        policy.enterprise_id = enterprise_id
        policy.updated_at = time.time()

        if not policy.policy_id:
            policy.policy_id = f"policy_{enterprise_id}_{int(time.time())}"
            policy.created_at = time.time()

        self._policies[enterprise_id] = policy

        await self._record_audit(
            enterprise_id,
            "admin",
            "",
            AuditEventType.POLICY_CHANGE,
            {"action": "set_policy", "policy_id": policy.policy_id},
        )

        self._save_data()

        return policy

    async def get_policy(self, enterprise_id: str) -> Optional[TemplatePolicy]:
        """Get enterprise template policy.

        Args:
            enterprise_id: Enterprise identifier.

        Returns:
            TemplatePolicy or None.
        """
        return self._policies.get(enterprise_id)

    async def check_template_access(
        self,
        enterprise_id: str,
        user_id: str,
        template_id: str,
        source: TemplateSource,
    ) -> Tuple[bool, str]:
        """Check if user can access template based on policy.

        Args:
            enterprise_id: Enterprise identifier.
            user_id: User identifier.
            template_id: Template identifier.
            source: Template source.

        Returns:
            Tuple of (allowed, reason).
        """
        policy = self._policies.get(enterprise_id)
        if not policy:
            return True, "No policy configured"

        if template_id in policy.denied_templates:
            return False, "Template is explicitly denied by policy"

        if source not in policy.allowed_sources:
            return False, f"Template source {source.value} is not allowed"

        if policy.require_approval and template_id not in policy.approved_templates:
            return False, "Template requires approval"

        daily_count = self._get_user_daily_downloads(enterprise_id, user_id)
        if daily_count >= policy.max_downloads_per_user:
            return False, "Daily download limit reached"

        return True, "Access allowed"

    async def request_template_approval(
        self,
        enterprise_id: str,
        user_id: str,
        template_id: str,
        reason: str,
    ) -> ApprovalRequest:
        """Request template approval.

        Args:
            enterprise_id: Enterprise identifier.
            user_id: User identifier.
            template_id: Template identifier.
            reason: Request reason.

        Returns:
            Created ApprovalRequest.
        """
        request_id = f"approval_{enterprise_id}_{template_id}_{int(time.time())}"

        request = ApprovalRequest(
            request_id=request_id,
            enterprise_id=enterprise_id,
            user_id=user_id,
            template_id=template_id,
            reason=reason,
            created_at=time.time(),
        )

        self._approval_requests[request_id] = request

        await self._record_audit(
            enterprise_id,
            user_id,
            template_id,
            AuditEventType.TEMPLATE_VIEW,
            {"action": "request_approval", "request_id": request_id},
        )

        self._save_data()

        return request

    async def approve_template(
        self,
        request_id: str,
        reviewer_id: str,
        comment: str = "",
    ) -> bool:
        """Approve template request.

        Args:
            request_id: Request identifier.
            reviewer_id: Reviewer identifier.
            comment: Review comment.

        Returns:
            True if approved successfully.
        """
        request = self._approval_requests.get(request_id)
        if not request:
            return False

        request.status = "approved"
        request.reviewed_at = time.time()
        request.reviewer_id = reviewer_id
        request.review_comment = comment

        policy = self._policies.get(request.enterprise_id)
        if policy:
            if request.template_id not in policy.approved_templates:
                policy.approved_templates.append(request.template_id)
            policy.updated_at = time.time()

        await self._record_audit(
            request.enterprise_id,
            reviewer_id,
            request.template_id,
            AuditEventType.POLICY_CHANGE,
            {"action": "approve_template", "request_id": request_id},
        )

        self._save_data()

        return True

    async def deny_template(
        self,
        request_id: str,
        reviewer_id: str,
        comment: str = "",
    ) -> bool:
        """Deny template request.

        Args:
            request_id: Request identifier.
            reviewer_id: Reviewer identifier.
            comment: Review comment.

        Returns:
            True if denied successfully.
        """
        request = self._approval_requests.get(request_id)
        if not request:
            return False

        request.status = "denied"
        request.reviewed_at = time.time()
        request.reviewer_id = reviewer_id
        request.review_comment = comment

        await self._record_audit(
            request.enterprise_id,
            reviewer_id,
            request.template_id,
            AuditEventType.POLICY_CHANGE,
            {"action": "deny_template", "request_id": request_id},
        )

        self._save_data()

        return True

    async def get_usage_audit(
        self,
        enterprise_id: str,
        user_id: str = "",
        template_id: str = "",
        start_time: float = 0.0,
        end_time: float = 0.0,
        limit: int = 100,
    ) -> List[UsageAuditRecord]:
        """Get usage audit records.

        Args:
            enterprise_id: Enterprise identifier.
            user_id: Filter by user.
            template_id: Filter by template.
            start_time: Start timestamp.
            end_time: End timestamp.
            limit: Maximum records.

        Returns:
            List of UsageAuditRecord objects.
        """
        records = self._audit_records.get(enterprise_id, [])

        if user_id:
            records = [r for r in records if r.user_id == user_id]

        if template_id:
            records = [r for r in records if r.template_id == template_id]

        if start_time:
            records = [r for r in records if r.timestamp >= start_time]

        if end_time:
            records = [r for r in records if r.timestamp <= end_time]

        records.sort(key=lambda r: r.timestamp, reverse=True)

        return records[:limit]

    async def get_pending_approvals(self, enterprise_id: str) -> List[ApprovalRequest]:
        """Get pending approval requests.

        Args:
            enterprise_id: Enterprise identifier.

        Returns:
            List of pending ApprovalRequest objects.
        """
        return [
            req for req in self._approval_requests.values()
            if req.enterprise_id == enterprise_id and req.status == "pending"
        ]

    async def get_usage_summary(self, enterprise_id: str) -> Dict[str, Any]:
        """Get usage summary for enterprise.

        Args:
            enterprise_id: Enterprise identifier.

        Returns:
            Usage summary dict.
        """
        records = self._audit_records.get(enterprise_id, [])

        templates_used: Dict[str, int] = {}
        users_active: Set[str] = set()
        events_by_type: Dict[str, int] = {}

        for record in records:
            templates_used[record.template_id] = templates_used.get(record.template_id, 0) + 1
            users_active.add(record.user_id)
            events_by_type[record.event_type.value] = events_by_type.get(record.event_type.value, 0) + 1

        return {
            "total_events": len(records),
            "unique_users": len(users_active),
            "templates_used": templates_used,
            "events_by_type": events_by_type,
            "recent_activity": [
                {
                    "user_id": r.user_id,
                    "template_id": r.template_id,
                    "event_type": r.event_type.value,
                    "timestamp": r.timestamp,
                }
                for r in sorted(records, key=lambda x: x.timestamp, reverse=True)[:10]
            ],
        }

    async def _record_audit(
        self,
        enterprise_id: str,
        user_id: str,
        template_id: str,
        event_type: AuditEventType,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Record audit event.

        Args:
            enterprise_id: Enterprise identifier.
            user_id: User identifier.
            template_id: Template identifier.
            event_type: Event type.
            details: Event details.
        """
        if enterprise_id not in self._audit_records:
            self._audit_records[enterprise_id] = []

        audit_id = f"audit_{enterprise_id}_{int(time.time())}"

        record = UsageAuditRecord(
            audit_id=audit_id,
            enterprise_id=enterprise_id,
            user_id=user_id,
            template_id=template_id,
            event_type=event_type,
            timestamp=time.time(),
            details=details or {},
        )

        self._audit_records[enterprise_id].append(record)

    def _get_user_daily_downloads(self, enterprise_id: str, user_id: str) -> int:
        """Get user's daily download count.

        Args:
            enterprise_id: Enterprise identifier.
            user_id: User identifier.

        Returns:
            Download count.
        """
        key = f"{enterprise_id}_{user_id}"
        today = time.strftime("%Y-%m-%d")

        user_counts = self._user_download_counts.get(key, {})

        return user_counts.get(today, 0)

    def _load_data(self) -> None:
        """Load data from storage."""
        if not self.storage_path:
            return

        try:
            data_file = os.path.join(self.storage_path, "enterprise_data.json")
            if os.path.exists(data_file):
                with open(data_file, "r", encoding="utf-8") as f:
                    data = json.load(f)

                    for ent_id, templates_data in data.get("enterprise_templates", {}).items():
                        templates = []
                        for tpl_data in templates_data:
                            template = EnterpriseTemplate(
                                template_id=tpl_data.get("template_id", ""),
                                name=tpl_data.get("name", ""),
                                description=tpl_data.get("description", ""),
                                source=TemplateSource(tpl_data.get("source", "internal")),
                                author_id=tpl_data.get("author_id", ""),
                                created_at=tpl_data.get("created_at", 0.0),
                                updated_at=tpl_data.get("updated_at", 0.0),
                                is_active=tpl_data.get("is_active", True),
                                classification=tpl_data.get("classification", "internal"),
                                approved_by=tpl_data.get("approved_by", ""),
                                approval_date=tpl_data.get("approval_date", 0.0),
                                tags=tpl_data.get("tags", []),
                                version=tpl_data.get("version", "1.0.0"),
                            )
                            templates.append(template)
                        self._enterprise_templates[ent_id] = templates

                    for ent_id, policy_data in data.get("policies", {}).items():
                        policy = TemplatePolicy(
                            policy_id=policy_data.get("policy_id", ""),
                            enterprise_id=ent_id,
                            allowed_sources=[
                                TemplateSource(s) for s in policy_data.get("allowed_sources", ["official", "internal"])
                            ],
                            require_approval=policy_data.get("require_approval", True),
                            approved_templates=policy_data.get("approved_templates", []),
                            denied_templates=policy_data.get("denied_templates", []),
                            max_downloads_per_user=policy_data.get("max_downloads_per_user", 10),
                            require_classification=policy_data.get("require_classification", True),
                            allowed_classifications=policy_data.get("allowed_classifications", ["public", "internal", "confidential"]),
                            auto_audit=policy_data.get("auto_audit", True),
                            created_at=policy_data.get("created_at", 0.0),
                            updated_at=policy_data.get("updated_at", 0.0),
                        )
                        self._policies[ent_id] = policy

                    for ent_id, records_data in data.get("audit_records", {}).items():
                        records = []
                        for rec_data in records_data:
                            record = UsageAuditRecord(
                                audit_id=rec_data.get("audit_id", ""),
                                enterprise_id=rec_data.get("enterprise_id", ""),
                                user_id=rec_data.get("user_id", ""),
                                template_id=rec_data.get("template_id", ""),
                                event_type=AuditEventType(rec_data.get("event_type", "template_view")),
                                timestamp=rec_data.get("timestamp", 0.0),
                                details=rec_data.get("details", {}),
                                ip_address=rec_data.get("ip_address", ""),
                                session_id=rec_data.get("session_id", ""),
                            )
                            records.append(record)
                        self._audit_records[ent_id] = records

                    for req_id, req_data in data.get("approval_requests", {}).items():
                        request = ApprovalRequest(
                            request_id=req_id,
                            enterprise_id=req_data.get("enterprise_id", ""),
                            user_id=req_data.get("user_id", ""),
                            template_id=req_data.get("template_id", ""),
                            reason=req_data.get("reason", ""),
                            status=req_data.get("status", "pending"),
                            created_at=req_data.get("created_at", 0.0),
                            reviewed_at=req_data.get("reviewed_at", 0.0),
                            reviewer_id=req_data.get("reviewer_id", ""),
                            review_comment=req_data.get("review_comment", ""),
                        )
                        self._approval_requests[request.request_id] = request

                    self._user_download_counts = data.get("user_download_counts", {})

        except Exception as e:
            logger.error(f"Failed to load enterprise data: {e}")

    def _save_data(self) -> None:
        """Save data to storage."""
        if not self.storage_path:
            return

        try:
            data_file = os.path.join(self.storage_path, "enterprise_data.json")

            data = {
                "enterprise_templates": {
                    ent_id: [
                        {
                            "template_id": t.template_id,
                            "name": t.name,
                            "description": t.description,
                            "source": t.source.value,
                            "author_id": t.author_id,
                            "created_at": t.created_at,
                            "updated_at": t.updated_at,
                            "is_active": t.is_active,
                            "classification": t.classification,
                            "approved_by": t.approved_by,
                            "approval_date": t.approval_date,
                            "tags": t.tags,
                            "version": t.version,
                        }
                        for t in templates
                    ]
                    for ent_id, templates in self._enterprise_templates.items()
                },
                "policies": {
                    ent_id: {
                        "policy_id": p.policy_id,
                        "enterprise_id": p.enterprise_id,
                        "allowed_sources": [s.value for s in p.allowed_sources],
                        "require_approval": p.require_approval,
                        "approved_templates": p.approved_templates,
                        "denied_templates": p.denied_templates,
                        "max_downloads_per_user": p.max_downloads_per_user,
                        "require_classification": p.require_classification,
                        "allowed_classifications": p.allowed_classifications,
                        "auto_audit": p.auto_audit,
                        "created_at": p.created_at,
                        "updated_at": p.updated_at,
                    }
                    for ent_id, p in self._policies.items()
                },
                "audit_records": {
                    ent_id: [
                        {
                            "audit_id": r.audit_id,
                            "enterprise_id": r.enterprise_id,
                            "user_id": r.user_id,
                            "template_id": r.template_id,
                            "event_type": r.event_type.value,
                            "timestamp": r.timestamp,
                            "details": r.details,
                            "ip_address": r.ip_address,
                            "session_id": r.session_id,
                        }
                        for r in records
                    ]
                    for ent_id, records in self._audit_records.items()
                },
                "approval_requests": {
                    req_id: {
                        "enterprise_id": r.enterprise_id,
                        "user_id": r.user_id,
                        "template_id": r.template_id,
                        "reason": r.reason,
                        "status": r.status,
                        "created_at": r.created_at,
                        "reviewed_at": r.reviewed_at,
                        "reviewer_id": r.reviewer_id,
                        "review_comment": r.review_comment,
                    }
                    for req_id, r in self._approval_requests.items()
                },
                "user_download_counts": self._user_download_counts,
            }

            with open(data_file, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)

        except Exception as e:
            logger.error(f"Failed to save enterprise data: {e}")
