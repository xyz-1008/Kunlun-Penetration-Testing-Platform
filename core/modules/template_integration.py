"""Template Integration: Integration with range, AI copilot, and report modules.

Provides:
- Range module integration: auto-recommend templates in practice mode, auto-generate template drafts after practice, prioritize template validation in range
- AI copilot integration: auto-recommend templates based on target environment, save AI-generated attack chains as templates, AI-assisted template documentation
- Report module integration: auto-include template execution results in penetration test reports, annotate template name and author in reports, template author attribution
"""

import asyncio
import json
import logging
import os
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Callable, Coroutine, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class IntegrationEventType(Enum):
    """Integration event types."""
    RANGE_SESSION_STARTED = "range_session_started"
    RANGE_SESSION_COMPLETED = "range_session_completed"
    TEMPLATE_RECOMMENDED = "template_recommended"
    TEMPLATE_EXECUTED = "template_executed"
    AI_SUGGESTION_RECEIVED = "ai_suggestion_received"
    REPORT_GENERATED = "report_generated"
    TEMPLATE_DRAFT_CREATED = "template_draft_created"
    TEMPLATE_VALIDATED = "template_validated"


@dataclass
class IntegrationEvent:
    """Integration event.

    Attributes:
        event_id: Unique event identifier
        event_type: Event type
        timestamp: Event timestamp
        source_module: Source module name
        target_module: Target module name
        data: Event data
        user_id: User identifier
    """
    event_id: str = ""
    event_type: IntegrationEventType = IntegrationEventType.RANGE_SESSION_STARTED
    timestamp: float = 0.0
    source_module: str = ""
    target_module: str = ""
    data: Dict[str, Any] = field(default_factory=dict)
    user_id: str = ""


@dataclass
class TemplateRecommendation:
    """Template recommendation.

    Attributes:
        template_id: Template identifier
        template_name: Template name
        match_score: Match score (0-100)
        match_reasons: Reasons for recommendation
        difficulty: Template difficulty
        estimated_time: Estimated completion time
        is_verified: Whether template is verified
        author: Template author
    """
    template_id: str = ""
    template_name: str = ""
    match_score: float = 0.0
    match_reasons: List[str] = field(default_factory=list)
    difficulty: str = ""
    estimated_time: int = 0
    is_verified: bool = False
    author: str = ""


@dataclass
class ReportTemplateEntry:
    """Template entry in report.

    Attributes:
        template_id: Template identifier
        template_name: Template name
        author: Template author
        execution_id: Execution identifier
        execution_status: Execution status
        execution_score: Execution score
        steps_executed: Number of steps executed
        steps_successful: Number of successful steps
        credentials_found: Credentials discovered
        target_url: Target URL
        execution_duration: Execution duration
    """
    template_id: str = ""
    template_name: str = ""
    author: str = ""
    execution_id: str = ""
    execution_status: str = ""
    execution_score: float = 0.0
    steps_executed: int = 0
    steps_successful: int = 0
    credentials_found: List[Dict[str, str]] = field(default_factory=list)
    target_url: str = ""
    execution_duration: float = 0.0


class TemplateIntegration:
    """Integration hub connecting template system with other platform modules.

    Coordinates with range environment, AI copilot, and report modules
    to provide seamless template workflow across the platform.
    """

    def __init__(
        self,
        storage_path: str = "",
        event_callback: Optional[Callable[[IntegrationEvent], Coroutine[Any, Any, None]]] = None,
    ) -> None:
        """Initialize template integration.

        Args:
            storage_path: Directory path for integration storage.
            event_callback: Optional async callback for integration events.
        """
        self.storage_path = storage_path
        self._event_callback = event_callback
        self._recommendations: Dict[str, List[TemplateRecommendation]] = {}
        _report_entries: Dict[str, List[ReportTemplateEntry]] = {}
        self._event_history: List[IntegrationEvent] = []

        if storage_path:
            os.makedirs(storage_path, exist_ok=True)
            self._load_data()

    async def _emit_event(
        self,
        event_type: IntegrationEventType,
        source_module: str,
        target_module: str,
        data: Dict[str, Any],
        user_id: str = "",
    ) -> IntegrationEvent:
        """Emit integration event.

        Args:
            event_type: Event type.
            source_module: Source module name.
            target_module: Target module name.
            data: Event data.
            user_id: User identifier.

        Returns:
            Created IntegrationEvent.
        """
        event_id = f"event_{event_type.value}_{int(time.time())}"

        event = IntegrationEvent(
            event_id=event_id,
            event_type=event_type,
            timestamp=time.time(),
            source_module=source_module,
            target_module=target_module,
            data=data,
            user_id=user_id,
        )

        self._event_history.append(event)

        if self._event_callback:
            await self._event_callback(event)

        return event

    async def on_range_session_started(
        self,
        range_id: str,
        user_id: str,
        target_url: str,
        vulnerability_types: Optional[List[str]] = None,
    ) -> List[TemplateRecommendation]:
        """Handle range session start and recommend templates.

        Args:
            range_id: Range environment ID.
            user_id: User identifier.
            target_url: Target URL.
            vulnerability_types: List of vulnerability types.

        Returns:
            List of recommended TemplateRecommendation objects.
        """
        await self._emit_event(
            IntegrationEventType.RANGE_SESSION_STARTED,
            "range",
            "template",
            {
                "range_id": range_id,
                "target_url": target_url,
                "vulnerability_types": vulnerability_types or [],
            },
            user_id,
        )

        recommendations = self._generate_recommendations(
            vulnerability_types or [],
            target_url,
        )

        self._recommendations[user_id] = recommendations

        await self._emit_event(
            IntegrationEventType.TEMPLATE_RECOMMENDED,
            "template",
            "range",
            {
                "range_id": range_id,
                "recommendations": [r.template_id for r in recommendations],
            },
            user_id,
        )

        return recommendations

    async def on_range_session_completed(
        self,
        range_id: str,
        user_id: str,
        operations: List[Dict[str, Any]],
        success: bool = False,
    ) -> Optional[str]:
        """Handle range session completion and generate template draft.

        Args:
            range_id: Range environment ID.
            user_id: User identifier.
            operations: List of operations performed.
            success: Whether session was successful.

        Returns:
            Template draft ID or None.
        """
        await self._emit_event(
            IntegrationEventType.RANGE_SESSION_COMPLETED,
            "range",
            "template",
            {
                "range_id": range_id,
                "operations_count": len(operations),
                "success": success,
            },
            user_id,
        )

        if not success or not operations:
            return None

        template_id = f"draft_{range_id}_{int(time.time())}"

        await self._emit_event(
            IntegrationEventType.TEMPLATE_DRAFT_CREATED,
            "template",
            "user",
            {
                "template_id": template_id,
                "range_id": range_id,
                "steps_count": len(operations),
            },
            user_id,
        )

        return template_id

    async def get_ai_template_recommendations(
        self,
        target_url: str,
        target_ip: str = "",
        fingerprint: Optional[Dict[str, Any]] = None,
        user_id: str = "",
    ) -> List[TemplateRecommendation]:
        """Get AI-powered template recommendations based on target.

        Args:
            target_url: Target URL.
            target_ip: Target IP address.
            fingerprint: Target fingerprint data.
            user_id: User identifier.

        Returns:
            List of recommended TemplateRecommendation objects.
        """
        vuln_types = []

        if fingerprint:
            vuln_types = fingerprint.get("vulnerability_types", [])

        recommendations = self._generate_recommendations(vuln_types, target_url)

        await self._emit_event(
            IntegrationEventType.AI_SUGGESTION_RECEIVED,
            "ai_copilot",
            "template",
            {
                "target_url": target_url,
                "recommendations": [r.template_id for r in recommendations],
            },
            user_id,
        )

        return recommendations

    async def save_ai_generated_chain(
        self,
        user_id: str,
        chain_data: Dict[str, Any],
        ai_model: str = "",
    ) -> Optional[str]:
        """Save AI-generated attack chain as template.

        Args:
            user_id: User identifier.
            chain_data: Attack chain data from AI.
            ai_model: AI model used.

        Returns:
            Template ID or None.
        """
        template_id = f"ai_{int(time.time())}"

        await self._emit_event(
            IntegrationEventType.TEMPLATE_DRAFT_CREATED,
            "ai_copilot",
            "template",
            {
                "template_id": template_id,
                "ai_model": ai_model,
                "steps_count": len(chain_data.get("steps", [])),
            },
            user_id,
        )

        return template_id

    async def on_template_executed(
        self,
        template_id: str,
        execution_id: str,
        user_id: str,
        target_url: str,
        status: str,
        score: float,
        steps_executed: int,
        steps_successful: int,
        credentials_found: Optional[List[Dict[str, str]]] = None,
        duration: float = 0.0,
    ) -> ReportTemplateEntry:
        """Handle template execution and create report entry.

        Args:
            template_id: Template identifier.
            execution_id: Execution identifier.
            user_id: User identifier.
            target_url: Target URL.
            status: Execution status.
            score: Execution score.
            steps_executed: Number of steps executed.
            steps_successful: Number of successful steps.
            credentials_found: Credentials discovered.
            duration: Execution duration.

        Returns:
            Created ReportTemplateEntry.
        """
        entry = ReportTemplateEntry(
            template_id=template_id,
            template_name=template_id,
            execution_id=execution_id,
            execution_status=status,
            execution_score=score,
            steps_executed=steps_executed,
            steps_successful=steps_successful,
            credentials_found=credentials_found or [],
            target_url=target_url,
            execution_duration=duration,
        )

        await self._emit_event(
            IntegrationEventType.TEMPLATE_EXECUTED,
            "template",
            "report",
            {
                "template_id": template_id,
                "execution_id": execution_id,
                "status": status,
                "score": score,
            },
            user_id,
        )

        return entry

    async def generate_report_section(
        self,
        user_id: str,
        template_entries: Optional[List[ReportTemplateEntry]] = None,
    ) -> Dict[str, Any]:
        """Generate report section for template executions.

        Args:
            user_id: User identifier.
            template_entries: Optional list of template entries.

        Returns:
            Report section dict.
        """
        entries = template_entries or []

        total_executions = len(entries)
        successful = sum(1 for e in entries if e.execution_status == "completed")
        avg_score = (
            sum(e.execution_score for e in entries) / total_executions
            if total_executions > 0
            else 0
        )

        section = {
            "section_title": "Attack Chain Template Executions",
            "total_executions": total_executions,
            "successful_executions": successful,
            "average_score": round(avg_score, 1),
            "templates_used": [
                {
                    "template_id": e.template_id,
                    "template_name": e.template_name,
                    "author": e.author,
                    "status": e.execution_status,
                    "score": e.execution_score,
                    "target": e.target_url,
                    "duration": e.execution_duration,
                    "credentials_found": len(e.credentials_found),
                }
                for e in entries
            ],
            "attribution": [
                {
                    "template_id": e.template_id,
                    "author": e.author,
                    "acknowledgment": f"Attack chain template '{e.template_name}' by {e.author}",
                }
                for e in entries
                if e.author
            ],
        }

        await self._emit_event(
            IntegrationEventType.REPORT_GENERATED,
            "template",
            "report",
            {
                "user_id": user_id,
                "executions_included": total_executions,
            },
            user_id,
        )

        return section

    async def on_template_validated(
        self,
        template_id: str,
        validation_id: str,
        user_id: str,
        is_verified: bool,
        score: float,
    ) -> None:
        """Handle template validation completion.

        Args:
            template_id: Template identifier.
            validation_id: Validation identifier.
            user_id: User identifier.
            is_verified: Whether template is verified.
            score: Validation score.
        """
        await self._emit_event(
            IntegrationEventType.TEMPLATE_VALIDATED,
            "validator",
            "marketplace",
            {
                "template_id": template_id,
                "validation_id": validation_id,
                "is_verified": is_verified,
                "score": score,
            },
            user_id,
        )

    async def get_user_recommendations(self, user_id: str) -> List[TemplateRecommendation]:
        """Get cached recommendations for user.

        Args:
            user_id: User identifier.

        Returns:
            List of TemplateRecommendation objects.
        """
        return self._recommendations.get(user_id, [])

    async def get_event_history(
        self,
        event_type: Optional[IntegrationEventType] = None,
        limit: int = 50,
    ) -> List[IntegrationEvent]:
        """Get integration event history.

        Args:
            event_type: Optional event type filter.
            limit: Maximum number of events.

        Returns:
            List of IntegrationEvent objects.
        """
        events = self._event_history

        if event_type:
            events = [e for e in events if e.event_type == event_type]

        return events[-limit:]

    def _generate_recommendations(
        self,
        vulnerability_types: List[str],
        target_url: str,
    ) -> List[TemplateRecommendation]:
        """Generate template recommendations.

        Args:
            vulnerability_types: List of vulnerability types.
            target_url: Target URL.

        Returns:
            List of TemplateRecommendation objects.
        """
        recommendations: List[TemplateRecommendation] = []

        vuln_type_map = {
            "sql_injection": "SQL Injection Attack Chains",
            "xss": "XSS Exploitation Templates",
            "rce": "Remote Code Execution Chains",
            "auth_bypass": "Authentication Bypass Templates",
            "privilege_escalation": "Privilege Escalation Chains",
            "lateral_movement": "Lateral Movement Templates",
            "persistence": "Persistence Techniques",
        }

        for vuln_type in vulnerability_types:
            template_name = vuln_type_map.get(vuln_type, f"{vuln_type} Templates")

            match_score = 80.0
            if vuln_type in ["rce", "sql_injection"]:
                match_score = 95.0
            elif vuln_type in ["xss", "auth_bypass"]:
                match_score = 85.0

            recommendations.append(TemplateRecommendation(
                template_id=f"tpl_{vuln_type}",
                template_name=template_name,
                match_score=match_score,
                match_reasons=[f"Target has {vuln_type} vulnerability"],
                difficulty="intermediate",
                estimated_time=30,
                is_verified=True,
                author="Kunlun Team",
            ))

        recommendations.sort(key=lambda r: r.match_score, reverse=True)

        return recommendations

    def _load_data(self) -> None:
        """Load integration data from storage."""
        if not self.storage_path:
            return

        try:
            data_file = os.path.join(self.storage_path, "integration_data.json")
            if os.path.exists(data_file):
                with open(data_file, "r", encoding="utf-8") as f:
                    data = json.load(f)

                    for user_id, recs in data.get("recommendations", {}).items():
                        recommendations = []
                        for r_data in recs:
                            recommendations.append(TemplateRecommendation(
                                template_id=r_data.get("template_id", ""),
                                template_name=r_data.get("template_name", ""),
                                match_score=r_data.get("match_score", 0.0),
                                match_reasons=r_data.get("match_reasons", []),
                                difficulty=r_data.get("difficulty", ""),
                                estimated_time=r_data.get("estimated_time", 0),
                                is_verified=r_data.get("is_verified", False),
                                author=r_data.get("author", ""),
                            ))
                        self._recommendations[user_id] = recommendations

                    event_list = []
                    for e_data in data.get("event_history", []):
                        event_list.append(IntegrationEvent(
                            event_id=e_data.get("event_id", ""),
                            event_type=IntegrationEventType(e_data.get("event_type", "range_session_started")),
                            timestamp=e_data.get("timestamp", 0.0),
                            source_module=e_data.get("source_module", ""),
                            target_module=e_data.get("target_module", ""),
                            data=e_data.get("data", {}),
                            user_id=e_data.get("user_id", ""),
                        ))
                    self._event_history = event_list

        except Exception as e:
            logger.error(f"Failed to load integration data: {e}")

    def _save_data(self) -> None:
        """Save integration data to storage."""
        if not self.storage_path:
            return

        try:
            data_file = os.path.join(self.storage_path, "integration_data.json")

            data = {
                "recommendations": {
                    uid: [
                        {
                            "template_id": r.template_id,
                            "template_name": r.template_name,
                            "match_score": r.match_score,
                            "match_reasons": r.match_reasons,
                            "difficulty": r.difficulty,
                            "estimated_time": r.estimated_time,
                            "is_verified": r.is_verified,
                            "author": r.author,
                        }
                        for r in recs
                    ]
                    for uid, recs in self._recommendations.items()
                },
                "event_history": [
                    {
                        "event_id": e.event_id,
                        "event_type": e.event_type.value,
                        "timestamp": e.timestamp,
                        "source_module": e.source_module,
                        "target_module": e.target_module,
                        "data": e.data,
                        "user_id": e.user_id,
                    }
                    for e in self._event_history
                ],
            }

            with open(data_file, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)

        except Exception as e:
            logger.error(f"Failed to save integration data: {e}")
