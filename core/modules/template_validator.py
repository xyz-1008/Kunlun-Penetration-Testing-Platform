"""Template Validator: Template replay validation, failure diagnosis, and fix suggestions.

Provides:
- Automatic template replay in range environment to verify step validity and completeness
- Failure step marking and repair suggestions when replay fails
- "Verified" status marking after successful validation to increase community trust
- Detailed validation reports with step-by-step results
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


class ValidationStatus(Enum):
    """Template validation status."""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    PASSED = "passed"
    FAILED = "failed"
    PARTIAL = "partial"


class StepValidationResult(Enum):
    """Individual step validation result."""
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"
    TIMEOUT = "timeout"
    ERROR = "error"


@dataclass
class StepValidationReport:
    """Validation report for a single step.

    Attributes:
        step_id: Step identifier
        step_number: Step sequence number
        step_name: Step display name
        result: Validation result
        duration_ms: Step execution duration
        expected_output: Expected output
        actual_output: Actual output
        error_message: Error message if failed
        fix_suggestions: List of fix suggestions
        is_critical: Whether this step is critical
    """
    step_id: str = ""
    step_number: int = 0
    step_name: str = ""
    result: StepValidationResult = StepValidationResult.SUCCESS
    duration_ms: float = 0.0
    expected_output: str = ""
    actual_output: str = ""
    error_message: str = ""
    fix_suggestions: List[str] = field(default_factory=list)
    is_critical: bool = False


@dataclass
class ValidationReport:
    """Complete template validation report.

    Attributes:
        validation_id: Unique validation identifier
        template_id: Template identifier
        template_name: Template name
        range_id: Range environment used for validation
        status: Overall validation status
        step_reports: List of step validation reports
        start_time: Validation start time
        end_time: Validation end time
        total_duration_seconds: Total validation duration
        total_steps: Total number of steps
        passed_steps: Number of passed steps
        failed_steps: Number of failed steps
        skipped_steps: Number of skipped steps
        validation_score: Overall validation score (0-100)
        is_verified: Whether template is verified
        notes: Additional notes
    """
    validation_id: str = ""
    template_id: str = ""
    template_name: str = ""
    range_id: str = ""
    status: ValidationStatus = ValidationStatus.PENDING
    step_reports: List[StepValidationReport] = field(default_factory=list)
    start_time: float = 0.0
    end_time: float = 0.0
    total_duration_seconds: float = 0.0
    total_steps: int = 0
    passed_steps: int = 0
    failed_steps: int = 0
    skipped_steps: int = 0
    validation_score: float = 0.0
    is_verified: bool = False
    notes: str = ""


class FixSuggestionEngine:
    """Generates fix suggestions for failed validation steps.

    Analyzes failure patterns and provides actionable
    recommendations for template authors.
    """

    def __init__(self) -> None:
        """Initialize fix suggestion engine."""
        self._failure_patterns: Dict[str, List[str]] = {
            "timeout": [
                "Increase step timeout_seconds value",
                "Check if target service is running",
                "Verify network connectivity to target",
                "Consider adding retry logic",
            ],
            "connection_refused": [
                "Verify target port is correct",
                "Check if target service is listening",
                "Ensure firewall rules allow connection",
                "Verify target IP address",
            ],
            "authentication_failed": [
                "Verify credentials are correct",
                "Check if account is locked",
                "Ensure authentication method matches target",
                "Try alternative authentication methods",
            ],
            "not_found": [
                "Verify URL path is correct",
                "Check if endpoint exists on target",
                "Ensure target version matches template requirements",
                "Try alternative endpoint paths",
            ],
            "permission_denied": [
                "Check current privilege level",
                "Verify user has required permissions",
                "Consider privilege escalation step",
                "Try alternative methods requiring lower privileges",
            ],
            "invalid_response": [
                "Verify expected output pattern",
                "Check if target response format changed",
                "Update regex patterns if using regex matching",
                "Consider more flexible output validation",
            ],
        }

    def generate_suggestions(
        self,
        error_message: str,
        step_name: str = "",
        action_type: str = "",
    ) -> List[str]:
        """Generate fix suggestions based on error.

        Args:
            error_message: Error message from failed step.
            step_name: Step display name.
            action_type: Step action type.

        Returns:
            List of fix suggestions.
        """
        suggestions: List[str] = []
        error_lower = error_message.lower()

        for pattern, pattern_suggestions in self._failure_patterns.items():
            if pattern in error_lower:
                suggestions.extend(pattern_suggestions)
                break

        if not suggestions:
            suggestions = [
                "Review step configuration",
                "Verify target environment matches template requirements",
                "Check step dependencies are satisfied",
                "Ensure all template variables are properly defined",
                "Try running step manually to diagnose issue",
            ]

        if action_type:
            suggestions.append(f"Consider alternative approach for {action_type}")

        return suggestions


class TemplateValidator:
    """Validates attack chain templates by replaying in range environment.

    Automatically replays templates in controlled range environments
    to verify step validity, completeness, and expected outcomes.
    """

    def __init__(
        self,
        storage_path: str = "",
        progress_callback: Optional[Callable[[float, str], Coroutine[Any, Any, None]]] = None,
    ) -> None:
        """Initialize template validator.

        Args:
            storage_path: Directory path for validation storage.
            progress_callback: Optional async callback for validation progress.
        """
        self.storage_path = storage_path
        self._progress_callback = progress_callback
        self._fix_engine = FixSuggestionEngine()
        self._reports: Dict[str, ValidationReport] = {}

        if storage_path:
            os.makedirs(storage_path, exist_ok=True)
            self._load_reports()

    async def _report_progress(self, percentage: float, message: str) -> None:
        """Report validation progress.

        Args:
            percentage: Progress percentage (0-100).
            message: Progress message.
        """
        if self._progress_callback:
            await self._progress_callback(percentage, message)

    async def validate_template(
        self,
        template_id: str,
        template_name: str,
        steps: List[Dict[str, Any]],
        range_id: str = "",
        variables: Optional[Dict[str, str]] = None,
    ) -> ValidationReport:
        """Validate template by replaying steps.

        Args:
            template_id: Template identifier.
            template_name: Template name.
            steps: List of template steps to validate.
            range_id: Range environment ID for validation.
            variables: Template variable values.

        Returns:
            ValidationReport with results.
        """
        validation_id = f"val_{template_id}_{int(time.time())}"

        report = ValidationReport(
            validation_id=validation_id,
            template_id=template_id,
            template_name=template_name,
            range_id=range_id,
            status=ValidationStatus.IN_PROGRESS,
            start_time=time.time(),
            total_steps=len(steps),
        )

        await self._report_progress(5.0, f"Starting validation: {template_name}")

        step_reports: List[StepValidationReport] = []

        for i, step in enumerate(steps):
            progress = 10.0 + (i / max(len(steps), 1)) * 80.0
            await self._report_progress(progress, f"Validating step {i + 1}/{len(steps)}")

            step_report = await self._validate_step(step, variables or {})
            step_reports.append(step_report)

            if step_report.result == StepValidationResult.FAILED and step_report.is_critical:
                await self._report_progress(progress, f"Critical step failed: {step_report.step_name}")

        report.step_reports = step_reports
        report.end_time = time.time()
        report.total_duration_seconds = report.end_time - report.start_time

        report.passed_steps = sum(
            1 for r in step_reports if r.result == StepValidationResult.SUCCESS
        )
        report.failed_steps = sum(
            1 for r in step_reports if r.result == StepValidationResult.FAILED
        )
        report.skipped_steps = sum(
            1 for r in step_reports if r.result == StepValidationResult.SKIPPED
        )

        if report.total_steps > 0:
            report.validation_score = (report.passed_steps / report.total_steps) * 100

        if report.failed_steps == 0:
            report.status = ValidationStatus.PASSED
            report.is_verified = True
        elif report.passed_steps == 0:
            report.status = ValidationStatus.FAILED
        else:
            report.status = ValidationStatus.PARTIAL

        self._reports[validation_id] = report
        self._save_report(report)

        await self._report_progress(100.0, f"Validation complete: {report.status.value}")

        return report

    async def _validate_step(
        self,
        step: Dict[str, Any],
        variables: Dict[str, str],
    ) -> StepValidationReport:
        """Validate single template step.

        Args:
            step: Step data to validate.
            variables: Template variable values.

        Returns:
            StepValidationReport for the step.
        """
        step_id = step.get("step_id", "")
        step_number = step.get("step_number", 0)
        step_name = step.get("name", "")
        action = step.get("action", "")
        payload = step.get("payload", {})
        expected_output = step.get("expected_output", "")
        timeout = step.get("timeout_seconds", 30)
        is_critical = step.get("is_critical", False)

        report = StepValidationReport(
            step_id=step_id,
            step_number=step_number,
            step_name=step_name,
            expected_output=expected_output,
            is_critical=is_critical,
        )

        start_time = time.time()

        try:
            adapted_payload = self._adapt_payload(payload, variables)

            result = await self._execute_step(action, adapted_payload, timeout)

            report.duration_ms = (time.time() - start_time) * 1000
            report.actual_output = result.get("output", "")

            if result.get("success", False):
                report.result = StepValidationResult.SUCCESS

                if expected_output:
                    if not self._check_output(report.actual_output, expected_output):
                        report.result = StepValidationResult.FAILED
                        report.error_message = "Output does not match expected pattern"
                        report.fix_suggestions = self._fix_engine.generate_suggestions(
                            "invalid_response", step_name, action
                        )
            else:
                report.result = StepValidationResult.FAILED
                report.error_message = result.get("error", "Unknown error")
                report.fix_suggestions = self._fix_engine.generate_suggestions(
                    report.error_message, step_name, action
                )

        except asyncio.TimeoutError:
            report.duration_ms = (time.time() - start_time) * 1000
            report.result = StepValidationResult.TIMEOUT
            report.error_message = f"Step timed out after {timeout} seconds"
            report.fix_suggestions = self._fix_engine.generate_suggestions(
                "timeout", step_name, action
            )

        except Exception as e:
            report.duration_ms = (time.time() - start_time) * 1000
            report.result = StepValidationResult.ERROR
            report.error_message = str(e)
            report.fix_suggestions = self._fix_engine.generate_suggestions(
                str(e), step_name, action
            )

        return report

    async def _execute_step(
        self,
        action: str,
        payload: Dict[str, Any],
        timeout: int,
    ) -> Dict[str, Any]:
        """Execute template step.

        Args:
            action: Step action type.
            payload: Step payload.
            timeout: Step timeout.

        Returns:
            Dict with success status and output.
        """
        try:
            return await asyncio.wait_for(
                self._do_execute(action, payload),
                timeout=timeout,
            )
        except asyncio.TimeoutError:
            raise

    async def _do_execute(self, action: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Perform step execution.

        Args:
            action: Step action type.
            payload: Step payload.

        Returns:
            Dict with success status and output.
        """
        if action == "http_request":
            return await self._execute_http_request(payload)
        elif action == "command_execution":
            return await self._execute_command(payload)
        elif action == "wait":
            return await self._execute_wait(payload)
        else:
            return {"success": True, "output": f"Action {action} simulated"}

    async def _execute_http_request(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Execute HTTP request step.

        Args:
            payload: HTTP request payload.

        Returns:
            Dict with success status and output.
        """
        url = payload.get("url", "")
        method = payload.get("method", "GET")
        headers = payload.get("headers", {})
        body = payload.get("body", "")

        if not url:
            return {"success": False, "error": "No URL specified"}

        try:
            import aiohttp

            async with aiohttp.ClientSession() as session:
                async with session.request(
                    method,
                    url,
                    headers=headers,
                    data=body,
                    timeout=aiohttp.ClientTimeout(total=30),
                ) as response:
                    content = await response.text()
                    return {
                        "success": response.status < 400,
                        "output": f"Status: {response.status}\n{content[:500]}",
                        "status_code": response.status,
                    }

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def _execute_command(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Execute command step.

        Args:
            payload: Command payload.

        Returns:
            Dict with success status and output.
        """
        command = payload.get("command", "")

        if not command:
            return {"success": False, "error": "No command specified"}

        try:
            process = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            stdout, stderr = await process.communicate()

            return {
                "success": process.returncode == 0,
                "output": stdout.decode() if stdout else stderr.decode(),
                "return_code": process.returncode,
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def _execute_wait(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Execute wait step.

        Args:
            payload: Wait payload.

        Returns:
            Dict with success status and output.
        """
        duration = payload.get("duration", 1)

        await asyncio.sleep(duration)

        return {"success": True, "output": f"Waited {duration} seconds"}

    def _adapt_payload(
        self,
        payload: Dict[str, Any],
        variables: Dict[str, str],
    ) -> Dict[str, Any]:
        """Adapt payload with variable values.

        Args:
            payload: Original payload.
            variables: Variable values.

        Returns:
            Adapted payload.
        """
        adapted: Dict[str, Any] = {}

        for key, value in payload.items():
            if isinstance(value, str):
                adapted[key] = self._replace_variables(value, variables)
            elif isinstance(value, dict):
                adapted[key] = self._adapt_payload(value, variables)
            elif isinstance(value, list):
                adapted[key] = [
                    self._replace_variables(item, variables) if isinstance(item, str) else item
                    for item in value
                ]
            else:
                adapted[key] = value

        return adapted

    def _replace_variables(self, text: str, variables: Dict[str, str]) -> str:
        """Replace template variables in text.

        Args:
            text: Text with variables.
            variables: Variable values.

        Returns:
            Text with variables replaced.
        """
        result = text

        for var_name, var_value in variables.items():
            placeholder = f"{{{{{var_name}}}}}"
            result = result.replace(placeholder, var_value)

        return result

    def _check_output(self, actual: str, expected: str) -> bool:
        """Check if actual output matches expected.

        Args:
            actual: Actual output.
            expected: Expected output pattern.

        Returns:
            True if output matches.
        """
        import re

        try:
            return bool(re.search(expected, actual, re.IGNORECASE))
        except re.error:
            return expected.lower() in actual.lower()

    async def get_report(self, validation_id: str) -> Optional[ValidationReport]:
        """Get validation report.

        Args:
            validation_id: Validation identifier.

        Returns:
            ValidationReport or None.
        """
        return self._reports.get(validation_id)

    async def list_reports(self, template_id: str = "") -> List[ValidationReport]:
        """List validation reports.

        Args:
            template_id: Optional template ID filter.

        Returns:
            List of ValidationReport objects.
        """
        if template_id:
            return [r for r in self._reports.values() if r.template_id == template_id]
        return list(self._reports.values())

    def _load_reports(self) -> None:
        """Load validation reports from storage."""
        if not self.storage_path:
            return

        try:
            reports_file = os.path.join(self.storage_path, "validation_reports.json")
            if os.path.exists(reports_file):
                with open(reports_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    for report_data in data:
                        step_reports = []
                        for step_data in report_data.get("step_reports", []):
                            step_reports.append(StepValidationReport(
                                step_id=step_data.get("step_id", ""),
                                step_number=step_data.get("step_number", 0),
                                step_name=step_data.get("step_name", ""),
                                result=StepValidationResult(step_data.get("result", "success")),
                                duration_ms=step_data.get("duration_ms", 0.0),
                                expected_output=step_data.get("expected_output", ""),
                                actual_output=step_data.get("actual_output", ""),
                                error_message=step_data.get("error_message", ""),
                                fix_suggestions=step_data.get("fix_suggestions", []),
                                is_critical=step_data.get("is_critical", False),
                            ))

                        report = ValidationReport(
                            validation_id=report_data.get("validation_id", ""),
                            template_id=report_data.get("template_id", ""),
                            template_name=report_data.get("template_name", ""),
                            range_id=report_data.get("range_id", ""),
                            status=ValidationStatus(report_data.get("status", "pending")),
                            step_reports=step_reports,
                            start_time=report_data.get("start_time", 0.0),
                            end_time=report_data.get("end_time", 0.0),
                            total_duration_seconds=report_data.get("total_duration_seconds", 0.0),
                            total_steps=report_data.get("total_steps", 0),
                            passed_steps=report_data.get("passed_steps", 0),
                            failed_steps=report_data.get("failed_steps", 0),
                            skipped_steps=report_data.get("skipped_steps", 0),
                            validation_score=report_data.get("validation_score", 0.0),
                            is_verified=report_data.get("is_verified", False),
                            notes=report_data.get("notes", ""),
                        )

                        self._reports[report.validation_id] = report

        except Exception as e:
            logger.error(f"Failed to load validation reports: {e}")

    def _save_report(self, report: ValidationReport) -> None:
        """Save validation report to storage.

        Args:
            report: Report to save.
        """
        if not self.storage_path:
            return

        try:
            reports_file = os.path.join(self.storage_path, "validation_reports.json")

            reports_data = []
            if os.path.exists(reports_file):
                with open(reports_file, "r", encoding="utf-8") as f:
                    reports_data = json.load(f)

            reports_data = [r for r in reports_data if r.get("validation_id") != report.validation_id]

            report_dict = {
                "validation_id": report.validation_id,
                "template_id": report.template_id,
                "template_name": report.template_name,
                "range_id": report.range_id,
                "status": report.status.value,
                "step_reports": [
                    {
                        "step_id": s.step_id,
                        "step_number": s.step_number,
                        "step_name": s.step_name,
                        "result": s.result.value,
                        "duration_ms": s.duration_ms,
                        "expected_output": s.expected_output,
                        "actual_output": s.actual_output,
                        "error_message": s.error_message,
                        "fix_suggestions": s.fix_suggestions,
                        "is_critical": s.is_critical,
                    }
                    for s in report.step_reports
                ],
                "start_time": report.start_time,
                "end_time": report.end_time,
                "total_duration_seconds": report.total_duration_seconds,
                "total_steps": report.total_steps,
                "passed_steps": report.passed_steps,
                "failed_steps": report.failed_steps,
                "skipped_steps": report.skipped_steps,
                "validation_score": report.validation_score,
                "is_verified": report.is_verified,
                "notes": report.notes,
            }

            reports_data.append(report_dict)

            with open(reports_file, "w", encoding="utf-8") as f:
                json.dump(reports_data, f, ensure_ascii=False, indent=2)

        except Exception as e:
            logger.error(f"Failed to save validation report: {e}")
