"""Attack Chain Template: Automatic attack chain extraction, desensitization, and template saving.

Provides:
- Automatic recording of all operation steps after successful attack (request sequences, tool usage, command execution)
- Automatic generation of desensitized attack chain templates (removing range-specific IPs/URLs)
- Template saving with step descriptions, Kunlun modules used, key payloads, and expected results
- Template versioning and metadata management
"""

import asyncio
import hashlib
import json
import logging
import os
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum, auto
from typing import Any, Callable, Coroutine, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


class StepType(Enum):
    """Attack chain step types."""
    RECONNAISSANCE = "reconnaissance"
    SCANNING = "scanning"
    EXPLOITATION = "exploitation"
    POST_EXPLOITATION = "post_exploitation"
    LATERAL_MOVEMENT = "lateral_movement"
    PERSISTENCE = "persistence"
    EXFILTRATION = "exfiltration"
    CLEANUP = "cleanup"


class StepStatus(Enum):
    """Step execution status."""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"


class TemplateSource(Enum):
    """Template source types."""
    MANUAL = "manual"
    AUTO_EXTRACTED = "auto_extracted"
    COMMUNITY = "community"


@dataclass
class AttackStep:
    """Single step in an attack chain.

    Attributes:
        step_id: Unique step identifier
        step_number: Step sequence number
        step_type: Type of attack step
        description: Step description
        module_used: Kunlun module used for this step
        target_pattern: Target pattern (e.g., URL, IP pattern)
        request_data: HTTP request data (if applicable)
        payload: Key payload used
        expected_result: Expected outcome description
        actual_result: Actual outcome (from execution)
        status: Step execution status
        mitre_technique: MITRE ATT&CK technique ID
        risk_level: Risk level (low/medium/high/critical)
        notes: Additional notes
        timestamp: Step timestamp
    """
    step_id: str = ""
    step_number: int = 0
    step_type: StepType = StepType.RECONNAISSANCE
    description: str = ""
    module_used: str = ""
    target_pattern: str = ""
    request_data: Dict[str, Any] = field(default_factory=dict)
    payload: str = ""
    expected_result: str = ""
    actual_result: str = ""
    status: StepStatus = StepStatus.PENDING
    mitre_technique: str = ""
    risk_level: str = "medium"
    notes: str = ""
    timestamp: float = 0.0


@dataclass
class AttackChainRecord:
    """Complete attack chain record from a session.

    Attributes:
        record_id: Unique record identifier
        session_id: Session identifier
        target_url: Original target URL
        target_ip: Original target IP
        range_id: Range ID (if from range practice)
        steps: List of attack steps
        start_time: Attack chain start time
        end_time: Attack chain end time
        success: Whether attack chain was successful
        vulnerabilities_found: List of vulnerabilities discovered
        flags_captured: List of flags captured
        modules_used: List of all modules used
        raw_requests: List of raw HTTP requests
        raw_commands: List of raw commands executed
    """
    record_id: str = ""
    session_id: str = ""
    target_url: str = ""
    target_ip: str = ""
    range_id: str = ""
    steps: List[AttackStep] = field(default_factory=list)
    start_time: float = 0.0
    end_time: float = 0.0
    success: bool = False
    vulnerabilities_found: List[str] = field(default_factory=list)
    flags_captured: List[str] = field(default_factory=list)
    modules_used: List[str] = field(default_factory=list)
    raw_requests: List[Dict[str, Any]] = field(default_factory=list)
    raw_commands: List[str] = field(default_factory=list)


@dataclass
class AttackChainTemplate:
    """Reusable attack chain template.

    Attributes:
        template_id: Unique template identifier
        name: Template name
        description: Template description
        source: Template source
        author: Template author
        version: Template version
        target_fingerprint: Target fingerprint requirements
        steps: List of template steps
        expected_vulnerabilities: Expected vulnerability types
        success_criteria: Criteria for successful execution
        mitre_techniques: List of MITRE ATT&CK technique IDs
        difficulty: Difficulty level
        estimated_time_minutes: Estimated execution time
        tags: Template tags
        created_at: Creation timestamp
        updated_at: Last update timestamp
        is_public: Whether template is shared publicly
        community_rating: Community rating (0-5)
        usage_count: Number of times template was used
    """
    template_id: str = ""
    name: str = ""
    description: str = ""
    source: TemplateSource = TemplateSource.MANUAL
    author: str = ""
    version: str = "1.0"
    target_fingerprint: Dict[str, Any] = field(default_factory=dict)
    steps: List[AttackStep] = field(default_factory=list)
    expected_vulnerabilities: List[str] = field(default_factory=list)
    success_criteria: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    difficulty: str = "intermediate"
    estimated_time_minutes: int = 60
    tags: List[str] = field(default_factory=list)
    created_at: float = 0.0
    updated_at: float = 0.0
    is_public: bool = False
    community_rating: float = 0.0
    usage_count: int = 0


@dataclass
class TemplateMatch:
    """Template match result for a target.

    Attributes:
        template: Matched template
        match_score: Match score (0-100)
        matched_fingerprints: List of matched fingerprint criteria
        missing_fingerprints: List of missing fingerprint criteria
        adaptation_needed: Whether adaptation is needed
        adaptation_notes: Notes on required adaptations
    """
    template: AttackChainTemplate = field(default_factory=AttackChainTemplate)
    match_score: float = 0.0
    matched_fingerprints: List[str] = field(default_factory=list)
    missing_fingerprints: List[str] = field(default_factory=list)
    adaptation_needed: bool = False
    adaptation_notes: str = ""


class SensitiveDataSanitizer:
    """Sanitizes sensitive data from attack chain records.

    Removes or replaces IPs, URLs, credentials, and other
    sensitive information to create shareable templates.
    """

    IP_PATTERN = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    URL_PATTERN = re.compile(r'https?://[^\s/$.?#].[^\s]*', re.IGNORECASE)
    EMAIL_PATTERN = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
    PORT_PATTERN = re.compile(r':(\d{2,5})\b')

    def __init__(self) -> None:
        """Initialize sanitizer."""
        self._replacement_map: Dict[str, str] = {
            "ip": "{{TARGET_IP}}",
            "url": "{{TARGET_URL}}",
            "port": "{{TARGET_PORT}}",
            "email": "{{EMAIL}}",
            "username": "{{USERNAME}}",
            "password": "{{PASSWORD}}",
            "token": "{{TOKEN}}",
            "session_id": "{{SESSION_ID}}",
        }

    def sanitize_record(self, record: AttackChainRecord) -> AttackChainRecord:
        """Sanitize sensitive data from attack chain record.

        Args:
            record: Attack chain record to sanitize.

        Returns:
            Sanitized AttackChainRecord.
        """
        sanitized = AttackChainRecord(
            record_id=record.record_id,
            session_id=record.session_id,
            target_url=self._sanitize_url(record.target_url),
            target_ip=self._sanitize_ip(record.target_ip),
            range_id=record.range_id,
            steps=[self._sanitize_step(step) for step in record.steps],
            start_time=record.start_time,
            end_time=record.end_time,
            success=record.success,
            vulnerabilities_found=record.vulnerabilities_found,
            flags_captured=record.flags_captured,
            modules_used=record.modules_used,
            raw_requests=[self._sanitize_request(req) for req in record.raw_requests],
            raw_commands=[self._sanitize_command(cmd) for cmd in record.raw_commands],
        )

        return sanitized

    def _sanitize_url(self, url: str) -> str:
        """Sanitize URL.

        Args:
            url: URL to sanitize.

        Returns:
            Sanitized URL.
        """
        if not url:
            return url
        return self.URL_PATTERN.sub(self._replacement_map["url"], url)

    def _sanitize_ip(self, ip: str) -> str:
        """Sanitize IP address.

        Args:
            ip: IP address to sanitize.

        Returns:
            Sanitized IP.
        """
        if not ip:
            return ip
        return self.IP_PATTERN.sub(self._replacement_map["ip"], ip)

    def _sanitize_step(self, step: AttackStep) -> AttackStep:
        """Sanitize attack step.

        Args:
            step: Attack step to sanitize.

        Returns:
            Sanitized AttackStep.
        """
        sanitized_step = AttackStep(
            step_id=step.step_id,
            step_number=step.step_number,
            step_type=step.step_type,
            description=self._sanitize_text(step.description),
            module_used=step.module_used,
            target_pattern=self._sanitize_text(step.target_pattern),
            request_data=self._sanitize_dict(step.request_data),
            payload=self._sanitize_text(step.payload),
            expected_result=self._sanitize_text(step.expected_result),
            actual_result=self._sanitize_text(step.actual_result),
            status=step.status,
            mitre_technique=step.mitre_technique,
            risk_level=step.risk_level,
            notes=self._sanitize_text(step.notes),
            timestamp=step.timestamp,
        )

        return sanitized_step

    def _sanitize_request(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Sanitize HTTP request data.

        Args:
            request: Request data to sanitize.

        Returns:
            Sanitized request data.
        """
        sanitized: Dict[str, Any] = {}
        for key, value in request.items():
            if isinstance(value, str):
                sanitized[key] = self._sanitize_text(value)
            elif isinstance(value, dict):
                sanitized[key] = self._sanitize_dict(value)
            else:
                sanitized[key] = value
        return sanitized

    def _sanitize_command(self, command: str) -> str:
        """Sanitize command string.

        Args:
            command: Command to sanitize.

        Returns:
            Sanitized command.
        """
        return self._sanitize_text(command)

    def _sanitize_text(self, text: str) -> str:
        """Sanitize text by replacing sensitive patterns.

        Args:
            text: Text to sanitize.

        Returns:
            Sanitized text.
        """
        if not text:
            return text

        text = self.IP_PATTERN.sub(self._replacement_map["ip"], text)
        text = self.URL_PATTERN.sub(self._replacement_map["url"], text)
        text = self.EMAIL_PATTERN.sub(self._replacement_map["email"], text)

        return text

    def _sanitize_dict(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Sanitize dictionary values.

        Args:
            data: Dictionary to sanitize.

        Returns:
            Sanitized dictionary.
        """
        sanitized: Dict[str, Any] = {}
        for key, value in data.items():
            if isinstance(value, str):
                sanitized[key] = self._sanitize_text(value)
            elif isinstance(value, dict):
                sanitized[key] = self._sanitize_dict(value)
            elif isinstance(value, list):
                sanitized[key] = [
                    self._sanitize_text(item) if isinstance(item, str) else item
                    for item in value
                ]
            else:
                sanitized[key] = value
        return sanitized


class AttackChainExtractor:
    """Extracts attack chain templates from execution records.

    Automatically records all operation steps and generates
    desensitized templates for reuse.
    """

    def __init__(self, storage_path: str = "") -> None:
        """Initialize attack chain extractor.

        Args:
            storage_path: Directory path for template storage.
        """
        self.storage_path = storage_path
        self._sanitizer = SensitiveDataSanitizer()
        self._records: List[AttackChainRecord] = []
        self._templates: List[AttackChainTemplate] = []

        if storage_path:
            os.makedirs(storage_path, exist_ok=True)
            self._load_templates()

    def start_recording(self, session_id: str, target_url: str, target_ip: str = "", range_id: str = "") -> str:
        """Start recording attack chain.

        Args:
            session_id: Session identifier.
            target_url: Target URL.
            target_ip: Target IP address.
            range_id: Range ID (if applicable).

        Returns:
            Record ID for the new recording.
        """
        record_id = f"record_{session_id}_{int(time.time())}"
        record = AttackChainRecord(
            record_id=record_id,
            session_id=session_id,
            target_url=target_url,
            target_ip=target_ip,
            range_id=range_id,
            start_time=time.time(),
        )

        self._records.append(record)
        return record_id

    def add_step(
        self,
        record_id: str,
        step_type: StepType,
        description: str,
        module_used: str,
        payload: str = "",
        request_data: Optional[Dict[str, Any]] = None,
        expected_result: str = "",
        actual_result: str = "",
        status: StepStatus = StepStatus.SUCCESS,
        mitre_technique: str = "",
        risk_level: str = "medium",
        notes: str = "",
    ) -> Optional[AttackStep]:
        """Add step to attack chain record.

        Args:
            record_id: Record identifier.
            step_type: Type of attack step.
            description: Step description.
            module_used: Kunlun module used.
            payload: Key payload used.
            request_data: HTTP request data.
            expected_result: Expected outcome.
            actual_result: Actual outcome.
            status: Step execution status.
            mitre_technique: MITRE ATT&CK technique ID.
            risk_level: Risk level.
            notes: Additional notes.

        Returns:
            Created AttackStep or None if record not found.
        """
        record = self._find_record(record_id)
        if not record:
            return None

        step_number = len(record.steps) + 1
        step_id = f"{record_id}_step_{step_number}"

        step = AttackStep(
            step_id=step_id,
            step_number=step_number,
            step_type=step_type,
            description=description,
            module_used=module_used,
            payload=payload,
            request_data=request_data or {},
            expected_result=expected_result,
            actual_result=actual_result,
            status=status,
            mitre_technique=mitre_technique,
            risk_level=risk_level,
            notes=notes,
            timestamp=time.time(),
        )

        record.steps.append(step)

        if module_used and module_used not in record.modules_used:
            record.modules_used.append(module_used)

        return step

    def add_raw_request(self, record_id: str, request: Dict[str, Any]) -> bool:
        """Add raw HTTP request to record.

        Args:
            record_id: Record identifier.
            request: HTTP request data.

        Returns:
            True if added successfully.
        """
        record = self._find_record(record_id)
        if not record:
            return False

        record.raw_requests.append(request)
        return True

    def add_raw_command(self, record_id: str, command: str) -> bool:
        """Add raw command to record.

        Args:
            record_id: Record identifier.
            command: Command string.

        Returns:
            True if added successfully.
        """
        record = self._find_record(record_id)
        if not record:
            return False

        record.raw_commands.append(command)
        return True

    def complete_recording(
        self,
        record_id: str,
        success: bool = False,
        vulnerabilities_found: Optional[List[str]] = None,
        flags_captured: Optional[List[str]] = None,
    ) -> Optional[AttackChainRecord]:
        """Complete attack chain recording.

        Args:
            record_id: Record identifier.
            success: Whether attack chain was successful.
            vulnerabilities_found: List of vulnerabilities discovered.
            flags_captured: List of flags captured.

        Returns:
            Completed AttackChainRecord or None.
        """
        record = self._find_record(record_id)
        if not record:
            return None

        record.end_time = time.time()
        record.success = success

        if vulnerabilities_found:
            record.vulnerabilities_found = vulnerabilities_found
        if flags_captured:
            record.flags_captured = flags_captured

        return record

    def extract_template(
        self,
        record_id: str,
        template_name: str = "",
        template_description: str = "",
        author: str = "",
        is_public: bool = False,
    ) -> Optional[AttackChainTemplate]:
        """Extract desensitized template from attack chain record.

        Args:
            record_id: Record identifier.
            template_name: Template name.
            template_description: Template description.
            author: Template author.
            is_public: Whether template is public.

        Returns:
            Created AttackChainTemplate or None.
        """
        record = self._find_record(record_id)
        if not record:
            return None

        sanitized_record = self._sanitizer.sanitize_record(record)

        template_id = f"template_{record_id}_{int(time.time())}"

        steps = []
        for sanitized_step in sanitized_record.steps:
            step = AttackStep(
                step_id=sanitized_step.step_id,
                step_number=sanitized_step.step_number,
                step_type=sanitized_step.step_type,
                description=sanitized_step.description,
                module_used=sanitized_step.module_used,
                target_pattern=sanitized_step.target_pattern,
                request_data=sanitized_step.request_data,
                payload=sanitized_step.payload,
                expected_result=sanitized_step.expected_result,
                status=StepStatus.PENDING,
                mitre_technique=sanitized_step.mitre_technique,
                risk_level=sanitized_step.risk_level,
                notes=sanitized_step.notes,
                timestamp=0.0,
            )
            steps.append(step)

        mitre_techniques = list(set(
            step.mitre_technique
            for step in steps
            if step.mitre_technique
        ))

        total_time = record.end_time - record.start_time if record.end_time > 0 else 0
        estimated_minutes = int(total_time / 60) if total_time > 0 else 60

        template = AttackChainTemplate(
            template_id=template_id,
            name=template_name or f"Template from {record.session_id}",
            description=template_description or f"Auto-extracted from session {record.session_id}",
            source=TemplateSource.AUTO_EXTRACTED,
            author=author or "auto",
            version="1.0",
            target_fingerprint=self._extract_fingerprint(record),
            steps=steps,
            expected_vulnerabilities=record.vulnerabilities_found,
            success_criteria=[
                f"Vulnerability confirmed: {vuln}"
                for vuln in record.vulnerabilities_found
            ],
            mitre_techniques=mitre_techniques,
            difficulty=self._estimate_difficulty(steps),
            estimated_time_minutes=estimated_minutes,
            tags=self._generate_tags(record),
            created_at=time.time(),
            updated_at=time.time(),
            is_public=is_public,
        )

        self._templates.append(template)
        self._save_template(template)

        return template

    def get_templates(self, filter_public: bool = False) -> List[AttackChainTemplate]:
        """Get all templates.

        Args:
            filter_public: Whether to return only public templates.

        Returns:
            List of AttackChainTemplate objects.
        """
        if filter_public:
            return [t for t in self._templates if t.is_public]
        return self._templates

    def get_template(self, template_id: str) -> Optional[AttackChainTemplate]:
        """Get template by ID.

        Args:
            template_id: Template identifier.

        Returns:
            AttackChainTemplate or None.
        """
        for template in self._templates:
            if template.template_id == template_id:
                return template
        return None

    def delete_template(self, template_id: str) -> bool:
        """Delete template.

        Args:
            template_id: Template identifier.

        Returns:
            True if deleted.
        """
        for i, template in enumerate(self._templates):
            if template.template_id == template_id:
                del self._templates[i]
                return True
        return False

    def _find_record(self, record_id: str) -> Optional[AttackChainRecord]:
        """Find record by ID.

        Args:
            record_id: Record identifier.

        Returns:
            AttackChainRecord or None.
        """
        for record in self._records:
            if record.record_id == record_id:
                return record
        return None

    def _extract_fingerprint(self, record: AttackChainRecord) -> Dict[str, Any]:
        """Extract target fingerprint from record.

        Args:
            record: Attack chain record.

        Returns:
            Target fingerprint dictionary.
        """
        fingerprint = {
            "has_web_server": True,
            "vulnerabilities": record.vulnerabilities_found,
            "modules_required": record.modules_used,
        }

        return fingerprint

    def _estimate_difficulty(self, steps: List[AttackStep]) -> str:
        """Estimate template difficulty from steps.

        Args:
            steps: List of attack steps.

        Returns:
            Difficulty string.
        """
        if len(steps) <= 2:
            return "beginner"
        elif len(steps) <= 5:
            return "intermediate"
        else:
            return "advanced"

    def _generate_tags(self, record: AttackChainRecord) -> List[str]:
        """Generate template tags from record.

        Args:
            record: Attack chain record.

        Returns:
            List of tags.
        """
        tags = []

        for vuln in record.vulnerabilities_found:
            tags.append(vuln.lower().replace(" ", "_"))

        for module in record.modules_used:
            tags.append(module.lower())

        return list(set(tags))

    def _load_templates(self) -> None:
        """Load templates from storage."""
        if not self.storage_path:
            return

        try:
            templates_file = os.path.join(self.storage_path, "templates.json")
            if os.path.exists(templates_file):
                with open(templates_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    for template_data in data:
                        steps = []
                        for step_data in template_data.get("steps", []):
                            steps.append(AttackStep(
                                step_id=step_data.get("step_id", ""),
                                step_number=step_data.get("step_number", 0),
                                step_type=StepType(step_data.get("step_type", "reconnaissance")),
                                description=step_data.get("description", ""),
                                module_used=step_data.get("module_used", ""),
                                target_pattern=step_data.get("target_pattern", ""),
                                request_data=step_data.get("request_data", {}),
                                payload=step_data.get("payload", ""),
                                expected_result=step_data.get("expected_result", ""),
                                status=StepStatus(step_data.get("status", "pending")),
                                mitre_technique=step_data.get("mitre_technique", ""),
                                risk_level=step_data.get("risk_level", "medium"),
                                notes=step_data.get("notes", ""),
                                timestamp=step_data.get("timestamp", 0.0),
                            ))

                        template = AttackChainTemplate(
                            template_id=template_data.get("template_id", ""),
                            name=template_data.get("name", ""),
                            description=template_data.get("description", ""),
                            source=TemplateSource(template_data.get("source", "manual")),
                            author=template_data.get("author", ""),
                            version=template_data.get("version", "1.0"),
                            target_fingerprint=template_data.get("target_fingerprint", {}),
                            steps=steps,
                            expected_vulnerabilities=template_data.get("expected_vulnerabilities", []),
                            success_criteria=template_data.get("success_criteria", []),
                            mitre_techniques=template_data.get("mitre_techniques", []),
                            difficulty=template_data.get("difficulty", "intermediate"),
                            estimated_time_minutes=template_data.get("estimated_time_minutes", 60),
                            tags=template_data.get("tags", []),
                            created_at=template_data.get("created_at", time.time()),
                            updated_at=template_data.get("updated_at", time.time()),
                            is_public=template_data.get("is_public", False),
                            community_rating=template_data.get("community_rating", 0.0),
                            usage_count=template_data.get("usage_count", 0),
                        )

                        self._templates.append(template)

        except Exception as e:
            logger.error(f"Failed to load templates: {e}")

    def _save_template(self, template: AttackChainTemplate) -> None:
        """Save template to storage.

        Args:
            template: Template to save.
        """
        if not self.storage_path:
            return

        try:
            templates_file = os.path.join(self.storage_path, "templates.json")

            templates_data = []
            if os.path.exists(templates_file):
                with open(templates_file, "r", encoding="utf-8") as f:
                    templates_data = json.load(f)

            template_dict = {
                "template_id": template.template_id,
                "name": template.name,
                "description": template.description,
                "source": template.source.value,
                "author": template.author,
                "version": template.version,
                "target_fingerprint": template.target_fingerprint,
                "steps": [
                    {
                        "step_id": s.step_id,
                        "step_number": s.step_number,
                        "step_type": s.step_type.value,
                        "description": s.description,
                        "module_used": s.module_used,
                        "target_pattern": s.target_pattern,
                        "request_data": s.request_data,
                        "payload": s.payload,
                        "expected_result": s.expected_result,
                        "status": s.status.value,
                        "mitre_technique": s.mitre_technique,
                        "risk_level": s.risk_level,
                        "notes": s.notes,
                        "timestamp": s.timestamp,
                    }
                    for s in template.steps
                ],
                "expected_vulnerabilities": template.expected_vulnerabilities,
                "success_criteria": template.success_criteria,
                "mitre_techniques": template.mitre_techniques,
                "difficulty": template.difficulty,
                "estimated_time_minutes": template.estimated_time_minutes,
                "tags": template.tags,
                "created_at": template.created_at,
                "updated_at": template.updated_at,
                "is_public": template.is_public,
                "community_rating": template.community_rating,
                "usage_count": template.usage_count,
            }

            templates_data.append(template_dict)

            with open(templates_file, "w", encoding="utf-8") as f:
                json.dump(templates_data, f, ensure_ascii=False, indent=2)

        except Exception as e:
            logger.error(f"Failed to save template: {e}")
