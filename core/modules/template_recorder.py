"""Template Recorder: Operation recording, step serialization, and parameter extraction.

Provides:
- One-click recording mode for all Kunlun operations (proxy requests, Fuzzer tests, PoC execution, C2 commands, lateral movement, etc.)
- Recording content: operation type, timestamp, target info, request/response content, commands and output, current privilege status
- Start/pause/stop recording with red recording indicator on interface
- Automatic generation of raw operation sequence after stopping recording
- Sensitive parameter extraction and variable replacement suggestions
"""

import asyncio
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


class RecordingStatus(Enum):
    """Recording status."""
    IDLE = "idle"
    RECORDING = "recording"
    PAUSED = "paused"
    STOPPED = "stopped"


class OperationType(Enum):
    """Operation types that can be recorded."""
    PROXY_REQUEST = "proxy_request"
    FUZZER_TEST = "fuzzer_test"
    POC_EXECUTION = "poc_execution"
    C2_COMMAND = "c2_command"
    LATERAL_MOVEMENT = "lateral_movement"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    RECONNAISSANCE = "reconnaissance"
    EXPLOITATION = "exploitation"
    POST_EXPLOITATION = "post_exploitation"
    CUSTOM = "custom"


class PrivilegeLevel(Enum):
    """Current privilege level."""
    NONE = "none"
    USER = "user"
    ADMIN = "admin"
    ROOT = "root"
    SYSTEM = "system"
    DOMAIN_ADMIN = "domain_admin"


@dataclass
class RecordedStep:
    """Single recorded operation step.

    Attributes:
        step_id: Unique step identifier
        step_number: Step sequence number
        operation_type: Type of operation
        timestamp: Operation timestamp
        target_url: Target URL
        target_ip: Target IP address
        request_data: HTTP request data (if applicable)
        response_data: HTTP response data (if applicable)
        command: Command executed (if applicable)
        command_output: Command output (if applicable)
        privilege_level: Current privilege level
        success: Whether operation was successful
        duration_ms: Operation duration in milliseconds
        notes: Additional notes
        extracted_parameters: List of extracted parameter names
    """
    step_id: str = ""
    step_number: int = 0
    operation_type: OperationType = OperationType.CUSTOM
    timestamp: float = 0.0
    target_url: str = ""
    target_ip: str = ""
    request_data: Dict[str, Any] = field(default_factory=dict)
    response_data: Dict[str, Any] = field(default_factory=dict)
    command: str = ""
    command_output: str = ""
    privilege_level: PrivilegeLevel = PrivilegeLevel.NONE
    success: bool = False
    duration_ms: float = 0.0
    notes: str = ""
    extracted_parameters: List[str] = field(default_factory=list)


@dataclass
class RecordingSession:
    """Complete recording session.

    Attributes:
        session_id: Unique session identifier
        name: Recording session name
        description: Session description
        status: Current recording status
        target_url: Primary target URL
        target_ip: Primary target IP
        steps: List of recorded steps
        start_time: Recording start time
        end_time: Recording end time
        total_steps: Total number of recorded steps
        successful_steps: Number of successful steps
        failed_steps: Number of failed steps
        total_duration_seconds: Total recording duration
        metadata: Additional session metadata
    """
    session_id: str = ""
    name: str = ""
    description: str = ""
    status: RecordingStatus = RecordingStatus.IDLE
    target_url: str = ""
    target_ip: str = ""
    steps: List[RecordedStep] = field(default_factory=list)
    start_time: float = 0.0
    end_time: float = 0.0
    total_steps: int = 0
    successful_steps: int = 0
    failed_steps: int = 0
    total_duration_seconds: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ParameterExtraction:
    """Extracted parameter from recording.

    Attributes:
        parameter_name: Parameter name
        parameter_type: Parameter type (ip/url/credential/port/etc.)
        original_value: Original value found in recording
        occurrences: Number of occurrences in recording
        suggested_variable: Suggested template variable name
        steps_affected: List of step IDs where parameter appears
    """
    parameter_name: str = ""
    parameter_type: str = ""
    original_value: str = ""
    occurrences: int = 0
    suggested_variable: str = ""
    steps_affected: List[str] = field(default_factory=list)


class SensitiveDataDetector:
    """Detects sensitive data in recorded operations.

    Identifies IPs, URLs, credentials, tokens, and other
    sensitive information that should be parameterized.
    """

    IP_PATTERN = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    URL_PATTERN = re.compile(r'https?://[^\s/$.?#].[^\s]*', re.IGNORECASE)
    EMAIL_PATTERN = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
    JWT_PATTERN = re.compile(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+')
    API_KEY_PATTERN = re.compile(r'(?:api[_-]?key|apikey|access[_-]?token)\s*[:=]\s*["\']?([A-Za-z0-9_-]{16,})["\']?', re.IGNORECASE)
    PASSWORD_PATTERN = re.compile(r'(?:password|passwd|pwd)\s*[:=]\s*["\']?([^\s"\']{4,})["\']?', re.IGNORECASE)

    def __init__(self) -> None:
        """Initialize sensitive data detector."""
        self._detected_items: List[ParameterExtraction] = []

    def detect_in_text(self, text: str, step_id: str) -> List[ParameterExtraction]:
        """Detect sensitive data in text.

        Args:
            text: Text to analyze.
            step_id: Step ID where text was found.

        Returns:
            List of detected ParameterExtraction objects.
        """
        results: List[ParameterExtraction] = []

        for match in self.IP_PATTERN.finditer(text):
            value = match.group()
            results.append(ParameterExtraction(
                parameter_name=f"ip_{value.replace('.', '_')}",
                parameter_type="ip",
                original_value=value,
                occurrences=1,
                suggested_variable="{{target_ip}}",
                steps_affected=[step_id],
            ))

        for match in self.URL_PATTERN.finditer(text):
            value = match.group()
            results.append(ParameterExtraction(
                parameter_name=f"url_{hash(value) % 10000}",
                parameter_type="url",
                original_value=value,
                occurrences=1,
                suggested_variable="{{target_url}}",
                steps_affected=[step_id],
            ))

        for match in self.EMAIL_PATTERN.finditer(text):
            value = match.group()
            results.append(ParameterExtraction(
                parameter_name=f"email_{value.split('@')[0]}",
                parameter_type="email",
                original_value=value,
                occurrences=1,
                suggested_variable="{{email}}",
                steps_affected=[step_id],
            ))

        for match in self.JWT_PATTERN.finditer(text):
            value = match.group()
            results.append(ParameterExtraction(
                parameter_name="jwt_token",
                parameter_type="token",
                original_value=value[:20] + "...",
                occurrences=1,
                suggested_variable="{{jwt_token}}",
                steps_affected=[step_id],
            ))

        for match in self.API_KEY_PATTERN.finditer(text):
            value = match.group(1)
            results.append(ParameterExtraction(
                parameter_name="api_key",
                parameter_type="credential",
                original_value=value[:8] + "...",
                occurrences=1,
                suggested_variable="{{api_key}}",
                steps_affected=[step_id],
            ))

        for match in self.PASSWORD_PATTERN.finditer(text):
            value = match.group(1)
            results.append(ParameterExtraction(
                parameter_name="password",
                parameter_type="credential",
                original_value="***",
                occurrences=1,
                suggested_variable="{{password}}",
                steps_affected=[step_id],
            ))

        return results

    def detect_in_step(self, step: RecordedStep) -> List[ParameterExtraction]:
        """Detect sensitive data in recorded step.

        Args:
            step: Recorded step to analyze.

        Returns:
            List of detected ParameterExtraction objects.
        """
        results: List[ParameterExtraction] = []

        texts_to_check = [
            step.target_url,
            step.target_ip,
            step.command,
            step.command_output,
            step.notes,
            json.dumps(step.request_data),
            json.dumps(step.response_data),
        ]

        for text in texts_to_check:
            if text:
                results.extend(self.detect_in_text(text, step.step_id))

        return results


class TemplateRecorder:
    """Main template recorder for capturing Kunlun operations.

    Records all user operations during penetration testing
    sessions and generates raw operation sequences for
    template creation.
    """

    def __init__(
        self,
        storage_path: str = "",
        status_callback: Optional[Callable[[RecordingStatus, int], Coroutine[Any, Any, None]]] = None,
    ) -> None:
        """Initialize template recorder.

        Args:
            storage_path: Directory path for recording storage.
            status_callback: Optional async callback for recording status updates.
        """
        self.storage_path = storage_path
        self._status_callback = status_callback
        self._current_session: Optional[RecordingSession] = None
        self._detector = SensitiveDataDetector()
        self._sessions: Dict[str, RecordingSession] = {}

        if storage_path:
            os.makedirs(storage_path, exist_ok=True)
            self._load_sessions()

    async def _notify_status(self, status: RecordingStatus, step_count: int) -> None:
        """Notify recording status update.

        Args:
            status: Current recording status.
            step_count: Number of recorded steps.
        """
        if self._status_callback:
            await self._status_callback(status, step_count)

    async def start_recording(
        self,
        target_url: str,
        target_ip: str = "",
        name: str = "",
        description: str = "",
    ) -> str:
        """Start recording operations.

        Args:
            target_url: Primary target URL.
            target_ip: Primary target IP address.
            name: Recording session name.
            description: Session description.

        Returns:
            Session ID for the new recording.
        """
        session_id = f"recording_{int(time.time())}"

        self._current_session = RecordingSession(
            session_id=session_id,
            name=name or f"Recording {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')}",
            description=description,
            status=RecordingStatus.RECORDING,
            target_url=target_url,
            target_ip=target_ip,
            start_time=time.time(),
        )

        await self._notify_status(RecordingStatus.RECORDING, 0)
        return session_id

    async def pause_recording(self) -> bool:
        """Pause current recording.

        Returns:
            True if paused successfully.
        """
        if self._current_session and self._current_session.status == RecordingStatus.RECORDING:
            self._current_session.status = RecordingStatus.PAUSED
            await self._notify_status(RecordingStatus.PAUSED, len(self._current_session.steps))
            return True
        return False

    async def resume_recording(self) -> bool:
        """Resume paused recording.

        Returns:
            True if resumed successfully.
        """
        if self._current_session and self._current_session.status == RecordingStatus.PAUSED:
            self._current_session.status = RecordingStatus.RECORDING
            await self._notify_status(RecordingStatus.RECORDING, len(self._current_session.steps))
            return True
        return False

    async def stop_recording(self) -> Optional[RecordingSession]:
        """Stop current recording.

        Returns:
            Completed RecordingSession or None.
        """
        if not self._current_session:
            return None

        self._current_session.status = RecordingStatus.STOPPED
        self._current_session.end_time = time.time()
        self._current_session.total_duration_seconds = (
            self._current_session.end_time - self._current_session.start_time
        )
        self._current_session.total_steps = len(self._current_session.steps)
        self._current_session.successful_steps = sum(
            1 for s in self._current_session.steps if s.success
        )
        self._current_session.failed_steps = sum(
            1 for s in self._current_session.steps if not s.success
        )

        session = self._current_session
        self._sessions[session.session_id] = session
        self._current_session = None

        await self._notify_status(RecordingStatus.STOPPED, session.total_steps)
        self._save_session(session)

        return session

    async def record_step(
        self,
        operation_type: OperationType,
        target_url: str = "",
        target_ip: str = "",
        request_data: Optional[Dict[str, Any]] = None,
        response_data: Optional[Dict[str, Any]] = None,
        command: str = "",
        command_output: str = "",
        privilege_level: PrivilegeLevel = PrivilegeLevel.NONE,
        success: bool = False,
        duration_ms: float = 0.0,
        notes: str = "",
    ) -> Optional[RecordedStep]:
        """Record a single operation step.

        Args:
            operation_type: Type of operation.
            target_url: Target URL for this step.
            target_ip: Target IP for this step.
            request_data: HTTP request data.
            response_data: HTTP response data.
            command: Command executed.
            command_output: Command output.
            privilege_level: Current privilege level.
            success: Whether operation was successful.
            duration_ms: Operation duration.
            notes: Additional notes.

        Returns:
            Created RecordedStep or None if not recording.
        """
        if not self._current_session or self._current_session.status != RecordingStatus.RECORDING:
            return None

        step_number = len(self._current_session.steps) + 1
        step_id = f"{self._current_session.session_id}_step_{step_number}"

        step = RecordedStep(
            step_id=step_id,
            step_number=step_number,
            operation_type=operation_type,
            timestamp=time.time(),
            target_url=target_url or self._current_session.target_url,
            target_ip=target_ip or self._current_session.target_ip,
            request_data=request_data or {},
            response_data=response_data or {},
            command=command,
            command_output=command_output,
            privilege_level=privilege_level,
            success=success,
            duration_ms=duration_ms,
            notes=notes,
        )

        extracted_params = self._extract_parameters(step)
        step.extracted_parameters = extracted_params

        self._current_session.steps.append(step)

        await self._notify_status(RecordingStatus.RECORDING, len(self._current_session.steps))

        return step

    async def get_current_session(self) -> Optional[RecordingSession]:
        """Get current recording session.

        Returns:
            Current RecordingSession or None.
        """
        return self._current_session

    async def get_session(self, session_id: str) -> Optional[RecordingSession]:
        """Get recording session by ID.

        Args:
            session_id: Session identifier.

        Returns:
            RecordingSession or None.
        """
        return self._sessions.get(session_id)

    async def list_sessions(self) -> List[RecordingSession]:
        """List all recording sessions.

        Returns:
            List of RecordingSession objects.
        """
        return list(self._sessions.values())

    async def delete_session(self, session_id: str) -> bool:
        """Delete recording session.

        Args:
            session_id: Session identifier.

        Returns:
            True if deleted successfully.
        """
        if session_id in self._sessions:
            del self._sessions[session_id]
            return True
        return False

    async def extract_parameters(self, session_id: str) -> List[ParameterExtraction]:
        """Extract all sensitive parameters from session.

        Args:
            session_id: Session identifier.

        Returns:
            List of ParameterExtraction objects.
        """
        session = self._sessions.get(session_id)
        if not session:
            return []

        all_params: Dict[str, ParameterExtraction] = {}

        for step in session.steps:
            detected = self._detector.detect_in_step(step)
            for param in detected:
                if param.parameter_name in all_params:
                    all_params[param.parameter_name].occurrences += 1
                    if step.step_id not in all_params[param.parameter_name].steps_affected:
                        all_params[param.parameter_name].steps_affected.append(step.step_id)
                else:
                    all_params[param.parameter_name] = param

        return list(all_params.values())

    def _extract_parameters(self, step: RecordedStep) -> List[str]:
        """Extract parameter names from step.

        Args:
            step: Recorded step.

        Returns:
            List of parameter names.
        """
        params = []

        detected = self._detector.detect_in_step(step)
        for param in detected:
            params.append(param.suggested_variable)

        return list(set(params))

    def _load_sessions(self) -> None:
        """Load sessions from storage."""
        if not self.storage_path:
            return

        try:
            sessions_file = os.path.join(self.storage_path, "recordings.json")
            if os.path.exists(sessions_file):
                with open(sessions_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    for session_data in data:
                        steps = []
                        for step_data in session_data.get("steps", []):
                            steps.append(RecordedStep(
                                step_id=step_data.get("step_id", ""),
                                step_number=step_data.get("step_number", 0),
                                operation_type=OperationType(step_data.get("operation_type", "custom")),
                                timestamp=step_data.get("timestamp", 0.0),
                                target_url=step_data.get("target_url", ""),
                                target_ip=step_data.get("target_ip", ""),
                                request_data=step_data.get("request_data", {}),
                                response_data=step_data.get("response_data", {}),
                                command=step_data.get("command", ""),
                                command_output=step_data.get("command_output", ""),
                                privilege_level=PrivilegeLevel(step_data.get("privilege_level", "none")),
                                success=step_data.get("success", False),
                                duration_ms=step_data.get("duration_ms", 0.0),
                                notes=step_data.get("notes", ""),
                                extracted_parameters=step_data.get("extracted_parameters", []),
                            ))

                        session = RecordingSession(
                            session_id=session_data.get("session_id", ""),
                            name=session_data.get("name", ""),
                            description=session_data.get("description", ""),
                            status=RecordingStatus(session_data.get("status", "stopped")),
                            target_url=session_data.get("target_url", ""),
                            target_ip=session_data.get("target_ip", ""),
                            steps=steps,
                            start_time=session_data.get("start_time", 0.0),
                            end_time=session_data.get("end_time", 0.0),
                            total_steps=session_data.get("total_steps", 0),
                            successful_steps=session_data.get("successful_steps", 0),
                            failed_steps=session_data.get("failed_steps", 0),
                            total_duration_seconds=session_data.get("total_duration_seconds", 0.0),
                            metadata=session_data.get("metadata", {}),
                        )

                        self._sessions[session.session_id] = session

        except Exception as e:
            logger.error(f"Failed to load sessions: {e}")

    def _save_session(self, session: RecordingSession) -> None:
        """Save session to storage.

        Args:
            session: Session to save.
        """
        if not self.storage_path:
            return

        try:
            sessions_file = os.path.join(self.storage_path, "recordings.json")

            sessions_data = []
            if os.path.exists(sessions_file):
                with open(sessions_file, "r", encoding="utf-8") as f:
                    sessions_data = json.load(f)

            session_dict = {
                "session_id": session.session_id,
                "name": session.name,
                "description": session.description,
                "status": session.status.value,
                "target_url": session.target_url,
                "target_ip": session.target_ip,
                "steps": [
                    {
                        "step_id": s.step_id,
                        "step_number": s.step_number,
                        "operation_type": s.operation_type.value,
                        "timestamp": s.timestamp,
                        "target_url": s.target_url,
                        "target_ip": s.target_ip,
                        "request_data": s.request_data,
                        "response_data": s.response_data,
                        "command": s.command,
                        "command_output": s.command_output,
                        "privilege_level": s.privilege_level.value,
                        "success": s.success,
                        "duration_ms": s.duration_ms,
                        "notes": s.notes,
                        "extracted_parameters": s.extracted_parameters,
                    }
                    for s in session.steps
                ],
                "start_time": session.start_time,
                "end_time": session.end_time,
                "total_steps": session.total_steps,
                "successful_steps": session.successful_steps,
                "failed_steps": session.failed_steps,
                "total_duration_seconds": session.total_duration_seconds,
                "metadata": session.metadata,
            }

            sessions_data.append(session_dict)

            with open(sessions_file, "w", encoding="utf-8") as f:
                json.dump(sessions_data, f, ensure_ascii=False, indent=2)

        except Exception as e:
            logger.error(f"Failed to save session: {e}")
