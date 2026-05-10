"""Template Executor: Template loading, variable adaptation, and three execution modes.

Provides:
- Template loading and variable adaptation
- Three execution modes: manual (user executes each step), semi-automatic (auto for basic operations, confirmation for critical), fully automatic (full execution with pre-authorization)
- Real-time progress and intermediate results display
- Automatic pause on step failure with alternative suggestions
- Result comparison with template expectations
- Execution report generation with timeline, step results, and credentials/privileges obtained
"""

import asyncio
import json
import logging
import os
import re
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Callable, Coroutine, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class ExecutionMode(Enum):
    """Template execution modes."""
    MANUAL = "manual"
    SEMI_AUTOMATIC = "semi_automatic"
    FULL_AUTOMATIC = "full_automatic"


class ExecutionStatus(Enum):
    """Template execution status."""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class StepStatus(Enum):
    """Individual step execution status."""
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"
    WAITING_CONFIRMATION = "waiting_confirmation"


@dataclass
class ExecutionStepResult:
    """Result of executing a single template step.

    Attributes:
        step_id: Step identifier
        step_number: Step sequence number
        step_name: Step display name
        status: Step execution status
        start_time: Step start time
        end_time: Step end time
        duration_ms: Step execution duration
        output: Step output
        error_message: Error message if failed
        credentials_found: Credentials discovered in this step
        privileges_achieved: Privilege level achieved
        alternative_suggestions: Alternative approaches if failed
        matches_expected: Whether output matches expected
    """
    step_id: str = ""
    step_number: int = 0
    step_name: str = ""
    status: StepStatus = StepStatus.PENDING
    start_time: float = 0.0
    end_time: float = 0.0
    duration_ms: float = 0.0
    output: str = ""
    error_message: str = ""
    credentials_found: List[Dict[str, str]] = field(default_factory=list)
    privileges_achieved: str = ""
    alternative_suggestions: List[str] = field(default_factory=list)
    matches_expected: bool = False


@dataclass
class ExecutionReport:
    """Complete template execution report.

    Attributes:
        execution_id: Unique execution identifier
        template_id: Template identifier
        template_name: Template name
        target_url: Target URL
        target_ip: Target IP
        mode: Execution mode
        status: Overall execution status
        step_results: List of step execution results
        start_time: Execution start time
        end_time: Execution end time
        total_duration_seconds: Total execution duration
        total_steps: Total number of steps
        successful_steps: Number of successful steps
        failed_steps: Number of failed steps
        skipped_steps: Number of skipped steps
        credentials_obtained: All credentials obtained
        privileges_achieved: Final privilege level
        execution_score: Execution success score (0-100)
        notes: Additional notes
        exported_to_pdf: Whether report was exported to PDF
    """
    execution_id: str = ""
    template_id: str = ""
    template_name: str = ""
    target_url: str = ""
    target_ip: str = ""
    mode: ExecutionMode = ExecutionMode.MANUAL
    status: ExecutionStatus = ExecutionStatus.PENDING
    step_results: List[ExecutionStepResult] = field(default_factory=list)
    start_time: float = 0.0
    end_time: float = 0.0
    total_duration_seconds: float = 0.0
    total_steps: int = 0
    successful_steps: int = 0
    failed_steps: int = 0
    skipped_steps: int = 0
    credentials_obtained: List[Dict[str, str]] = field(default_factory=list)
    privileges_achieved: str = ""
    execution_score: float = 0.0
    notes: str = ""
    exported_to_pdf: bool = False


@dataclass
class ExecutionConfig:
    """Configuration for template execution.

    Attributes:
        template_id: Template identifier
        target_url: Target URL
        target_ip: Target IP
        mode: Execution mode
        variables: Template variable values
        auto_confirm: Whether to auto-confirm steps (for semi-automatic)
        skip_failed: Whether to skip failed steps
        max_retries: Maximum retries per step
        timeout_seconds: Global timeout
        stop_on_failure: Whether to stop on first failure
    """
    template_id: str = ""
    target_url: str = ""
    target_ip: str = ""
    mode: ExecutionMode = ExecutionMode.MANUAL
    variables: Dict[str, str] = field(default_factory=dict)
    auto_confirm: bool = False
    skip_failed: bool = False
    max_retries: int = 0
    timeout_seconds: int = 300
    stop_on_failure: bool = True


class TemplateExecutor:
    """Executes attack chain templates with variable adaptation and multiple modes.

    Supports manual, semi-automatic, and fully automatic execution modes
    with real-time progress reporting and result comparison.
    """

    VARIABLE_PATTERN = re.compile(r'\{\{([^}]+)\}\}')

    def __init__(
        self,
        storage_path: str = "",
        progress_callback: Optional[Callable[[float, str, Dict[str, Any]], Coroutine[Any, Any, None]]] = None,
        confirmation_callback: Optional[Callable[[Dict[str, Any]], Coroutine[Any, Any, bool]]] = None,
    ) -> None:
        """Initialize template executor.

        Args:
            storage_path: Directory path for execution storage.
            progress_callback: Optional async callback for execution progress.
            confirmation_callback: Optional async callback for step confirmation.
        """
        self.storage_path = storage_path
        self._progress_callback = progress_callback
        self._confirmation_callback = confirmation_callback
        self._executions: Dict[str, ExecutionReport] = {}
        self._active_execution: Optional[ExecutionReport] = None
        self._is_cancelled = False

        if storage_path:
            os.makedirs(storage_path, exist_ok=True)
            self._load_executions()

    async def _report_progress(
        self,
        percentage: float,
        message: str,
        step_data: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Report execution progress.

        Args:
            percentage: Progress percentage (0-100).
            message: Progress message.
            step_data: Optional step data.
        """
        if self._progress_callback:
            await self._progress_callback(percentage, message, step_data or {})

    async def _request_confirmation(self, step_data: Dict[str, Any]) -> bool:
        """Request user confirmation for step.

        Args:
            step_data: Step data for confirmation.

        Returns:
            True if confirmed.
        """
        if self._confirmation_callback:
            return await self._confirmation_callback(step_data)
        return True

    async def execute_template(
        self,
        config: ExecutionConfig,
        steps: List[Dict[str, Any]],
    ) -> ExecutionReport:
        """Execute template with configuration.

        Args:
            config: Execution configuration.
            steps: Template steps to execute.

        Returns:
            ExecutionReport with results.
        """
        execution_id = f"exec_{config.template_id}_{int(time.time())}"

        report = ExecutionReport(
            execution_id=execution_id,
            template_id=config.template_id,
            template_name=config.template_id,
            target_url=config.target_url,
            target_ip=config.target_ip,
            mode=config.mode,
            status=ExecutionStatus.IN_PROGRESS,
            start_time=time.time(),
            total_steps=len(steps),
        )

        self._active_execution = report
        self._is_cancelled = False

        await self._report_progress(5.0, f"Starting execution: {config.template_id}")

        for i, step in enumerate(steps):
            if self._is_cancelled:
                report.status = ExecutionStatus.CANCELLED
                break

            if report.status == ExecutionStatus.FAILED and config.stop_on_failure:
                break

            progress = 10.0 + (i / max(len(steps), 1)) * 85.0
            await self._report_progress(progress, f"Executing step {i + 1}/{len(steps)}", {
                "step_id": step.get("step_id", ""),
                "step_name": step.get("name", ""),
                "step_number": i + 1,
            })

            step_result = await self._execute_step(step, config, report)
            report.step_results.append(step_result)

            if step_result.status == StepStatus.SUCCESS:
                report.credentials_obtained.extend(step_result.credentials_found)
                if step_result.privileges_achieved:
                    report.privileges_achieved = step_result.privileges_achieved

            elif step_result.status == StepStatus.FAILED:
                if config.stop_on_failure:
                    report.status = ExecutionStatus.FAILED
                    await self._report_progress(progress, f"Step failed: {step_result.step_name}", {
                        "error": step_result.error_message,
                        "suggestions": step_result.alternative_suggestions,
                    })

        report.end_time = time.time()
        report.total_duration_seconds = report.end_time - report.start_time

        report.successful_steps = sum(
            1 for r in report.step_results if r.status == StepStatus.SUCCESS
        )
        report.failed_steps = sum(
            1 for r in report.step_results if r.status == StepStatus.FAILED
        )
        report.skipped_steps = sum(
            1 for r in report.step_results if r.status == StepStatus.SKIPPED
        )

        if report.total_steps > 0:
            report.execution_score = (report.successful_steps / report.total_steps) * 100

        if report.status == ExecutionStatus.IN_PROGRESS:
            report.status = ExecutionStatus.COMPLETED

        self._executions[execution_id] = report
        self._active_execution = None

        await self._report_progress(100.0, f"Execution complete: {report.status.value}")
        self._save_execution(report)

        return report

    async def _execute_step(
        self,
        step: Dict[str, Any],
        config: ExecutionConfig,
        report: ExecutionReport,
    ) -> ExecutionStepResult:
        """Execute single template step.

        Args:
            step: Step data.
            config: Execution configuration.
            report: Current execution report.

        Returns:
            ExecutionStepResult for the step.
        """
        step_id = step.get("step_id", "")
        step_number = step.get("step_number", 0)
        step_name = step.get("name", "")
        action = step.get("action", "")
        payload = step.get("payload", {})
        expected_output = step.get("expected_output", "")
        timeout = step.get("timeout_seconds", 30)
        retry_count = step.get("retry_count", 0)

        result = ExecutionStepResult(
            step_id=step_id,
            step_number=step_number,
            step_name=step_name,
            start_time=time.time(),
        )

        adapted_payload = self._adapt_payload(payload, config.variables)

        if config.mode == ExecutionMode.MANUAL:
            result.status = StepStatus.WAITING_CONFIRMATION
            confirmed = await self._request_confirmation({
                "step_id": step_id,
                "step_name": step_name,
                "action": action,
                "payload": adapted_payload,
                "description": step.get("description", ""),
            })

            if not confirmed:
                result.status = StepStatus.SKIPPED
                result.end_time = time.time()
                result.duration_ms = (result.end_time - result.start_time) * 1000
                return result

        elif config.mode == ExecutionMode.SEMI_AUTOMATIC:
            is_critical = self._is_critical_action(action)

            if is_critical and not config.auto_confirm:
                result.status = StepStatus.WAITING_CONFIRMATION
                confirmed = await self._request_confirmation({
                    "step_id": step_id,
                    "step_name": step_name,
                    "action": action,
                    "payload": adapted_payload,
                    "is_critical": True,
                })

                if not confirmed:
                    result.status = StepStatus.SKIPPED
                    result.end_time = time.time()
                    result.duration_ms = (result.end_time - result.start_time) * 1000
                    return result

        retries = 0
        max_retries = config.max_retries + retry_count

        while retries <= max_retries:
            try:
                result.status = StepStatus.RUNNING

                execution_result = await asyncio.wait_for(
                    self._do_execute_step(action, adapted_payload),
                    timeout=timeout,
                )

                result.output = execution_result.get("output", "")
                result.end_time = time.time()
                result.duration_ms = (result.end_time - result.start_time) * 1000

                if execution_result.get("success", False):
                    result.status = StepStatus.SUCCESS

                    if expected_output:
                        result.matches_expected = self._check_output(result.output, expected_output)

                    credentials = self._extract_credentials(result.output)
                    result.credentials_found = credentials

                    privilege = self._detect_privilege(result.output)
                    if privilege:
                        result.privileges_achieved = privilege

                else:
                    result.status = StepStatus.FAILED
                    result.error_message = execution_result.get("error", "Unknown error")

                    if retries < max_retries:
                        retries += 1
                        await asyncio.sleep(1)
                        continue

                    result.alternative_suggestions = self._generate_alternatives(
                        action, result.error_message
                    )

                break

            except asyncio.TimeoutError:
                result.status = StepStatus.FAILED
                result.error_message = f"Step timed out after {timeout} seconds"
                result.end_time = time.time()
                result.duration_ms = (result.end_time - result.start_time) * 1000

                if retries < max_retries:
                    retries += 1
                    continue

                result.alternative_suggestions = [
                    "Increase timeout value",
                    "Check target connectivity",
                    "Verify service is running",
                ]
                break

            except Exception as e:
                result.status = StepStatus.FAILED
                result.error_message = str(e)
                result.end_time = time.time()
                result.duration_ms = (result.end_time - result.start_time) * 1000

                if retries < max_retries:
                    retries += 1
                    continue

                result.alternative_suggestions = self._generate_alternatives(action, str(e))
                break

        if not result.end_time:
            result.end_time = time.time()
            result.duration_ms = (result.end_time - result.start_time) * 1000

        return result

    async def _do_execute_step(
        self,
        action: str,
        payload: Dict[str, Any],
    ) -> Dict[str, Any]:
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
        """Execute HTTP request.

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
                        "output": f"Status: {response.status}\n{content[:1000]}",
                        "status_code": response.status,
                    }

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def _execute_command(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Execute command.

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
        """Execute wait.

        Args:
            payload: Wait payload.

        Returns:
            Dict with success status and output.
        """
        duration = payload.get("duration", 1)
        await asyncio.sleep(duration)
        return {"success": True, "output": f"Waited {duration} seconds"}

    async def cancel_execution(self) -> bool:
        """Cancel active execution.

        Returns:
            True if cancelled successfully.
        """
        if self._active_execution:
            self._is_cancelled = True
            return True
        return False

    async def pause_execution(self) -> bool:
        """Pause active execution.

        Returns:
            True if paused successfully.
        """
        if self._active_execution:
            self._active_execution.status = ExecutionStatus.PAUSED
            return True
        return False

    async def resume_execution(self) -> bool:
        """Resume paused execution.

        Returns:
            True if resumed successfully.
        """
        if self._active_execution and self._active_execution.status == ExecutionStatus.PAUSED:
            self._active_execution.status = ExecutionStatus.IN_PROGRESS
            return True
        return False

    async def get_execution(self, execution_id: str) -> Optional[ExecutionReport]:
        """Get execution report.

        Args:
            execution_id: Execution identifier.

        Returns:
            ExecutionReport or None.
        """
        return self._executions.get(execution_id)

    async def list_executions(self, template_id: str = "") -> List[ExecutionReport]:
        """List execution reports.

        Args:
            template_id: Optional template ID filter.

        Returns:
            List of ExecutionReport objects.
        """
        if template_id:
            return [e for e in self._executions.values() if e.template_id == template_id]
        return list(self._executions.values())

    async def export_report_to_pdf(self, execution_id: str) -> bool:
        """Export execution report to PDF.

        Args:
            execution_id: Execution identifier.

        Returns:
            True if exported successfully.
        """
        report = self._executions.get(execution_id)
        if not report:
            return False

        try:
            from reportlab.lib.pagesizes import letter
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
            from reportlab.lib.styles import getSampleStyleSheet
            from reportlab.lib.colors import black, blue, red, green, white
            from reportlab.lib.units import inch

            if not self.storage_path:
                return False

            pdf_path = os.path.join(self.storage_path, f"execution_{execution_id}.pdf")

            doc = SimpleDocTemplate(pdf_path, pagesize=letter)
            styles = getSampleStyleSheet()

            story = []

            story.append(Paragraph(f"Execution Report: {report.template_name}", styles["Title"]))
            story.append(Spacer(1, 12))

            story.append(Paragraph(f"Execution ID: {report.execution_id}", styles["Normal"]))
            story.append(Paragraph(f"Target: {report.target_url}", styles["Normal"]))
            story.append(Paragraph(f"Mode: {report.mode.value}", styles["Normal"]))
            story.append(Paragraph(f"Status: {report.status.value}", styles["Normal"]))
            story.append(Paragraph(f"Score: {report.execution_score:.1f}%", styles["Normal"]))
            story.append(Spacer(1, 12))

            story.append(Paragraph("Step Results", styles["Heading2"]))
            story.append(Spacer(1, 6))

            table_data = [["Step", "Name", "Status", "Duration"]]

            for step_result in report.step_results:
                table_data.append([
                    str(step_result.step_number),
                    step_result.step_name,
                    step_result.status.value,
                    f"{step_result.duration_ms:.0f}ms",
                ])

            table = Table(table_data, colWidths=[0.5*inch, 3*inch, 1.5*inch, 1*inch])
            table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), black),
                ("TEXTCOLOR", (0, 0), (-1, 0), white),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, 0), 10),
                ("BOTTOMPADDING", (0, 0), (-1, 0), 12),
                ("BACKGROUND", (0, 1), (-1, -1), white),
                ("TEXTCOLOR", (0, 1), (-1, -1), black),
                ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
                ("FONTSIZE", (0, 1), (-1, -1), 8),
                ("GRID", (0, 0), (-1, -1), 1, black),
            ]))

            story.append(table)

            doc.build(story)

            report.exported_to_pdf = True
            self._save_execution(report)

            return True

        except ImportError:
            logger.warning("reportlab not installed, cannot export to PDF")
            return False
        except Exception as e:
            logger.error(f"Failed to export PDF: {e}")
            return False

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

    def _is_critical_action(self, action: str) -> bool:
        """Check if action is critical and requires confirmation.

        Args:
            action: Action type.

        Returns:
            True if action is critical.
        """
        critical_actions = {
            "exploitation",
            "privilege_escalation",
            "lateral_movement",
            "persistence",
            "data_exfiltration",
        }
        return action.lower() in critical_actions

    def _check_output(self, actual: str, expected: str) -> bool:
        """Check if actual output matches expected.

        Args:
            actual: Actual output.
            expected: Expected output pattern.

        Returns:
            True if output matches.
        """
        try:
            return bool(re.search(expected, actual, re.IGNORECASE))
        except re.error:
            return expected.lower() in actual.lower()

    def _extract_credentials(self, output: str) -> List[Dict[str, str]]:
        """Extract credentials from output.

        Args:
            output: Command/output text.

        Returns:
            List of credential dicts.
        """
        credentials: List[Dict[str, str]] = []

        patterns = [
            re.compile(r'(?:username|user|login)\s*[:=]\s*(\S+)', re.IGNORECASE),
            re.compile(r'(?:password|passwd|pwd)\s*[:=]\s*(\S+)', re.IGNORECASE),
            re.compile(r'(?:token|api[_-]?key)\s*[:=]\s*([A-Za-z0-9_-]{16,})', re.IGNORECASE),
        ]

        for pattern in patterns:
            for match in pattern.finditer(output):
                credentials.append({
                    "type": pattern.pattern.split("(")[0].strip("?:").replace("|", "/"),
                    "value": match.group(1),
                })

        return credentials

    def _detect_privilege(self, output: str) -> str:
        """Detect privilege level from output.

        Args:
            output: Command/output text.

        Returns:
            Detected privilege level.
        """
        output_lower = output.lower()

        if "root" in output_lower or "system" in output_lower:
            return "root/system"
        elif "admin" in output_lower or "administrator" in output_lower:
            return "admin"
        elif "user" in output_lower:
            return "user"

        return ""

    def _generate_alternatives(self, action: str, error: str) -> List[str]:
        """Generate alternative approaches for failed step.

        Args:
            action: Step action type.
            error: Error message.

        Returns:
            List of alternative suggestions.
        """
        alternatives: List[str] = []

        error_lower = error.lower()

        if "timeout" in error_lower:
            alternatives = [
                "Increase step timeout value",
                "Check network connectivity to target",
                "Verify target service is running",
                "Try with reduced payload size",
            ]
        elif "connection" in error_lower:
            alternatives = [
                "Verify target IP and port",
                "Check firewall rules",
                "Ensure target service is listening",
                "Try alternative ports",
            ]
        elif "auth" in error_lower or "permission" in error_lower:
            alternatives = [
                "Verify credentials are correct",
                "Try alternative authentication methods",
                "Check if account is locked",
                "Consider privilege escalation first",
            ]
        else:
            alternatives = [
                "Review step configuration",
                "Verify target environment matches requirements",
                "Try running step manually",
                "Check step dependencies are satisfied",
            ]

        return alternatives

    def _load_executions(self) -> None:
        """Load execution reports from storage."""
        if not self.storage_path:
            return

        try:
            executions_file = os.path.join(self.storage_path, "executions.json")
            if os.path.exists(executions_file):
                with open(executions_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    for exec_data in data:
                        step_results = []
                        for sr_data in exec_data.get("step_results", []):
                            step_results.append(ExecutionStepResult(
                                step_id=sr_data.get("step_id", ""),
                                step_number=sr_data.get("step_number", 0),
                                step_name=sr_data.get("step_name", ""),
                                status=StepStatus(sr_data.get("status", "pending")),
                                start_time=sr_data.get("start_time", 0.0),
                                end_time=sr_data.get("end_time", 0.0),
                                duration_ms=sr_data.get("duration_ms", 0.0),
                                output=sr_data.get("output", ""),
                                error_message=sr_data.get("error_message", ""),
                                credentials_found=sr_data.get("credentials_found", []),
                                privileges_achieved=sr_data.get("privileges_achieved", ""),
                                alternative_suggestions=sr_data.get("alternative_suggestions", []),
                                matches_expected=sr_data.get("matches_expected", False),
                            ))

                        report = ExecutionReport(
                            execution_id=exec_data.get("execution_id", ""),
                            template_id=exec_data.get("template_id", ""),
                            template_name=exec_data.get("template_name", ""),
                            target_url=exec_data.get("target_url", ""),
                            target_ip=exec_data.get("target_ip", ""),
                            mode=ExecutionMode(exec_data.get("mode", "manual")),
                            status=ExecutionStatus(exec_data.get("status", "pending")),
                            step_results=step_results,
                            start_time=exec_data.get("start_time", 0.0),
                            end_time=exec_data.get("end_time", 0.0),
                            total_duration_seconds=exec_data.get("total_duration_seconds", 0.0),
                            total_steps=exec_data.get("total_steps", 0),
                            successful_steps=exec_data.get("successful_steps", 0),
                            failed_steps=exec_data.get("failed_steps", 0),
                            skipped_steps=exec_data.get("skipped_steps", 0),
                            credentials_obtained=exec_data.get("credentials_obtained", []),
                            privileges_achieved=exec_data.get("privileges_achieved", ""),
                            execution_score=exec_data.get("execution_score", 0.0),
                            notes=exec_data.get("notes", ""),
                            exported_to_pdf=exec_data.get("exported_to_pdf", False),
                        )

                        self._executions[report.execution_id] = report

        except Exception as e:
            logger.error(f"Failed to load executions: {e}")

    def _save_execution(self, report: ExecutionReport) -> None:
        """Save execution report to storage.

        Args:
            report: Report to save.
        """
        if not self.storage_path:
            return

        try:
            executions_file = os.path.join(self.storage_path, "executions.json")

            executions_data = []
            if os.path.exists(executions_file):
                with open(executions_file, "r", encoding="utf-8") as f:
                    executions_data = json.load(f)

            executions_data = [e for e in executions_data if e.get("execution_id") != report.execution_id]

            report_dict = {
                "execution_id": report.execution_id,
                "template_id": report.template_id,
                "template_name": report.template_name,
                "target_url": report.target_url,
                "target_ip": report.target_ip,
                "mode": report.mode.value,
                "status": report.status.value,
                "step_results": [
                    {
                        "step_id": s.step_id,
                        "step_number": s.step_number,
                        "step_name": s.step_name,
                        "status": s.status.value,
                        "start_time": s.start_time,
                        "end_time": s.end_time,
                        "duration_ms": s.duration_ms,
                        "output": s.output,
                        "error_message": s.error_message,
                        "credentials_found": s.credentials_found,
                        "privileges_achieved": s.privileges_achieved,
                        "alternative_suggestions": s.alternative_suggestions,
                        "matches_expected": s.matches_expected,
                    }
                    for s in report.step_results
                ],
                "start_time": report.start_time,
                "end_time": report.end_time,
                "total_duration_seconds": report.total_duration_seconds,
                "total_steps": report.total_steps,
                "successful_steps": report.successful_steps,
                "failed_steps": report.failed_steps,
                "skipped_steps": report.skipped_steps,
                "credentials_obtained": report.credentials_obtained,
                "privileges_achieved": report.privileges_achieved,
                "execution_score": report.execution_score,
                "notes": report.notes,
                "exported_to_pdf": report.exported_to_pdf,
            }

            executions_data.append(report_dict)

            with open(executions_file, "w", encoding="utf-8") as f:
                json.dump(executions_data, f, ensure_ascii=False, indent=2)

        except Exception as e:
            logger.error(f"Failed to save execution: {e}")
