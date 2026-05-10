"""GraphQL attack pipeline: automated penetration testing pipeline, smart prioritization, and scheduled tasks.

Provides:
- Full automated attack pipeline: discovery → introspection → schema analysis → auth testing → injection → DoS → subscription → report
- Breakpoint resume and retry support
- Smart priority ranking based on risk assessment
- Scheduled task integration with Kunlun task management system
- YAML pipeline template import/export
"""

import asyncio
import json
import logging
import time
import uuid
import yaml
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Coroutine, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


class PipelineStage(Enum):
    """Pipeline execution stages."""
    ENDPOINT_DISCOVERY = "endpoint_discovery"
    INTROSPECTION = "introspection"
    SCHEMA_ANALYSIS = "schema_analysis"
    SENSITIVE_MARKING = "sensitive_marking"
    AUTHZ_TESTING = "authz_testing"
    INJECTION_TESTING = "injection_testing"
    DOS_TESTING = "dos_testing"
    SUBSCRIPTION_TESTING = "subscription_testing"
    REPORT_GENERATION = "report_generation"


class PipelineStatus(Enum):
    """Pipeline execution status."""
    PENDING = "pending"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class PriorityLevel(Enum):
    """Priority levels for attack targets."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class PipelineCheckpoint:
    """Pipeline execution checkpoint for resume.

    Attributes:
        checkpoint_id: Checkpoint ID
        timestamp: Checkpoint timestamp
        stage: Current stage
        stage_data: Stage-specific data
        completed_stages: Completed stages
        target_url: Target URL
    """
    checkpoint_id: str = ""
    timestamp: float = 0.0
    stage: PipelineStage = PipelineStage.ENDPOINT_DISCOVERY
    stage_data: Dict[str, Any] = field(default_factory=dict)
    completed_stages: List[str] = field(default_factory=list)
    target_url: str = ""


@dataclass
class ScheduledTask:
    """Scheduled task definition.

    Attributes:
        task_id: Task ID
        name: Task name
        target_url: Target URL
        schedule: Cron expression or interval
        enabled: Whether enabled
        last_run: Last run timestamp
        next_run: Next run timestamp
        pipeline_config: Pipeline configuration
    """
    task_id: str = ""
    name: str = ""
    target_url: str = ""
    schedule: str = ""
    enabled: bool = True
    last_run: float = 0.0
    next_run: float = 0.0
    pipeline_config: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PipelineResult:
    """Pipeline execution result.

    Attributes:
        pipeline_id: Pipeline ID
        timestamp: Execution timestamp
        target_url: Target URL
        status: Pipeline status
        stages_completed: Completed stages
        total_stages: Total stages
        vulnerabilities_found: Vulnerabilities found
        report_data: Report data
        execution_time_ms: Execution time
    """
    pipeline_id: str = ""
    timestamp: float = 0.0
    target_url: str = ""
    status: PipelineStatus = PipelineStatus.PENDING
    stages_completed: List[str] = field(default_factory=list)
    total_stages: int = 0
    vulnerabilities_found: int = 0
    report_data: Dict[str, Any] = field(default_factory=dict)
    execution_time_ms: float = 0.0


@dataclass
class AttackTarget:
    """Attack target with priority.

    Attributes:
        target_id: Target ID
        field_name: Field name
        type_name: Type name
        operation_type: Operation type (query/mutation/subscription)
        priority: Priority level
        risk_score: Risk score (0-100)
        estimated_time_ms: Estimated test time
        sensitive_indicators: Sensitive indicators
    """
    target_id: str = ""
    field_name: str = ""
    type_name: str = ""
    operation_type: str = "query"
    priority: PriorityLevel = PriorityLevel.MEDIUM
    risk_score: float = 0.0
    estimated_time_ms: float = 0.0
    sensitive_indicators: List[str] = field(default_factory=list)


class GraphQLAttackPipeline:
    """GraphQL automated attack pipeline.

    Provides full automated penetration testing pipeline with
    smart prioritization and scheduled task support.
    """

    SENSITIVE_FIELD_PATTERNS: List[str] = [
        "password", "token", "secret", "apiKey", "creditCard",
        "ssn", "socialSecurity", "bankAccount", "cvv", "pin",
        "privateKey", "authToken", "refreshToken", "accessToken",
    ]

    SENSITIVE_OPERATION_PATTERNS: List[str] = [
        "delete", "export", "admin", "execute", "impersonate",
        "resetPassword", "changeEmail", "transfer", "withdraw",
        "createUser", "updateUser", "grantAccess", "revokeAccess",
    ]

    PIPELINE_TEMPLATE: Dict[str, Any] = {
        "name": "GraphQL Full Attack Pipeline",
        "version": "1.0",
        "stages": [
            {"name": "endpoint_discovery", "enabled": True, "timeout": 60},
            {"name": "introspection", "enabled": True, "timeout": 120},
            {"name": "schema_analysis", "enabled": True, "timeout": 60},
            {"name": "sensitive_marking", "enabled": True, "timeout": 30},
            {"name": "authz_testing", "enabled": True, "timeout": 300},
            {"name": "injection_testing", "enabled": True, "timeout": 300},
            {"name": "dos_testing", "enabled": True, "timeout": 180},
            {"name": "subscription_testing", "enabled": True, "timeout": 120},
            {"name": "report_generation", "enabled": True, "timeout": 60},
        ],
    }

    def __init__(
        self,
        detector: Optional[Any] = None,
        introspector: Optional[Any] = None,
        authz_tester: Optional[Any] = None,
        injection_tester: Optional[Any] = None,
        advanced_attacks: Optional[Any] = None,
        subscription_tester: Optional[Any] = None,
        event_bus: Optional[Any] = None,
    ) -> None:
        """Initialize attack pipeline.

        Args:
            detector: GraphQL detector module.
            introspector: GraphQL introspector module.
            authz_tester: GraphQL authorization tester.
            injection_tester: GraphQL injection tester.
            advanced_attacks: GraphQL advanced attacks module.
            subscription_tester: GraphQL subscription tester.
            event_bus: Event bus for broadcasting events.
        """
        self.detector = detector
        self.introspector = introspector
        self.authz_tester = authz_tester
        self.injection_tester = injection_tester
        self.advanced_attacks = advanced_attacks
        self.subscription_tester = subscription_tester
        self.event_bus = event_bus

        self._progress_callback: Optional[Callable[[str, float], Coroutine[Any, Any, None]]] = None
        self._log_callback: Optional[Callable[[str], Coroutine[Any, Any, None]]] = None
        self._vulnerability_callback: Optional[Callable[[Dict[str, Any]], Coroutine[Any, Any, None]]] = None

        self._checkpoints: Dict[str, PipelineCheckpoint] = {}
        self._scheduled_tasks: Dict[str, ScheduledTask] = {}
        self._pipeline_results: List[PipelineResult] = []

        self._max_retries = 3
        self._retry_delay = 5.0
        self._is_running = False
        self._current_pipeline_id: Optional[str] = None

    def set_callbacks(
        self,
        progress_cb: Optional[Callable[[str, float], Coroutine[Any, Any, None]]] = None,
        log_cb: Optional[Callable[[str], Coroutine[Any, Any, None]]] = None,
        vuln_cb: Optional[Callable[[Dict[str, Any]], Coroutine[Any, Any, None]]] = None,
    ) -> None:
        """Set pipeline callbacks.

        Args:
            progress_cb: Callback for progress updates.
            log_cb: Callback for log messages.
            vuln_cb: Callback for vulnerability reports.
        """
        self._progress_callback = progress_cb
        self._log_callback = log_cb
        self._vulnerability_callback = vuln_cb

    def set_retry_config(
        self,
        max_retries: int = 3,
        retry_delay: float = 5.0,
    ) -> None:
        """Set retry configuration.

        Args:
            max_retries: Maximum retries per stage.
            retry_delay: Delay between retries.
        """
        self._max_retries = max_retries
        self._retry_delay = retry_delay

    async def _report_progress(self, message: str, percentage: float) -> None:
        """Report progress via callback.

        Args:
            message: Progress message.
            percentage: Progress percentage (0-100).
        """
        if self._progress_callback:
            await self._progress_callback(message, percentage)
        logger.info("Pipeline Progress: %.1f%% - %s", percentage, message)

    async def _report_log(self, message: str) -> None:
        """Report log via callback.

        Args:
            message: Log message.
        """
        if self._log_callback:
            await self._log_callback(message)
        logger.info("Pipeline: %s", message)

    async def _report_vulnerability(self, vuln_data: Dict[str, Any]) -> None:
        """Report vulnerability via callback.

        Args:
            vuln_data: Vulnerability data.
        """
        if self._vulnerability_callback:
            await self._vulnerability_callback(vuln_data)
        logger.info("Pipeline Vulnerability: %s", json.dumps(vuln_data))

    async def run_full_pipeline(
        self,
        target_url: str,
        headers: Optional[Dict[str, str]] = None,
        tokens: Optional[List[str]] = None,
        checkpoint_id: Optional[str] = None,
    ) -> PipelineResult:
        """Run full attack pipeline.

        Args:
            target_url: Target URL.
            headers: HTTP headers.
            tokens: Authentication tokens.
            checkpoint_id: Checkpoint ID for resume.

        Returns:
            PipelineResult.
        """
        start_time = time.time()

        pipeline_id = checkpoint_id or f"pipeline_{uuid.uuid4().hex[:8]}"
        self._current_pipeline_id = pipeline_id
        self._is_running = True

        result = PipelineResult(
            pipeline_id=pipeline_id,
            timestamp=time.time(),
            target_url=target_url,
            status=PipelineStatus.RUNNING,
            total_stages=len(self.PIPELINE_TEMPLATE["stages"]),
        )

        checkpoint = self._checkpoints.get(pipeline_id)
        start_stage = 0

        if checkpoint:
            start_stage = len(checkpoint.completed_stages)
            await self._report_log(f"从断点恢复: {checkpoint.stage.value}")

        schema_data: Dict[str, Any] = {}
        sensitive_targets: List[AttackTarget] = []
        vulnerabilities: List[Dict[str, Any]] = []

        stages = self.PIPELINE_TEMPLATE["stages"]

        for i in range(start_stage, len(stages)):
            if not self._is_running:
                result.status = PipelineStatus.CANCELLED
                break

            stage = stages[i]
            stage_name = stage["name"]
            stage_enum = PipelineStage(stage_name)

            await self._report_progress(f"阶段: {stage_name}", (i / len(stages)) * 100)

            try:
                stage_result = await self._execute_stage_with_retry(
                    stage_enum, target_url, headers, tokens, schema_data, sensitive_targets
                )

                if stage_result.get("success"):
                    result.stages_completed.append(stage_name)

                    if "schema_data" in stage_result:
                        schema_data = stage_result["schema_data"]

                    if "sensitive_targets" in stage_result:
                        sensitive_targets = stage_result["sensitive_targets"]

                    if "vulnerabilities" in stage_result:
                        vulnerabilities.extend(stage_result["vulnerabilities"])

                        for vuln in stage_result["vulnerabilities"]:
                            await self._report_vulnerability(vuln)

                    self._save_checkpoint(
                        pipeline_id, stage_enum, stage_result, target_url
                    )
                else:
                    result.status = PipelineStatus.FAILED
                    await self._report_log(f"阶段失败: {stage_name}")
                    break

            except Exception as e:
                result.status = PipelineStatus.FAILED
                await self._report_log(f"阶段异常: {stage_name} - {e}")
                break

        result.vulnerabilities_found = len(vulnerabilities)
        result.report_data = {
            "schema_summary": schema_data,
            "sensitive_targets": [
                {
                    "field": t.field_name,
                    "type": t.type_name,
                    "priority": t.priority.value,
                    "risk_score": t.risk_score,
                }
                for t in sensitive_targets
            ],
            "vulnerabilities": vulnerabilities,
        }
        result.execution_time_ms = (time.time() - start_time) * 1000

        if result.status == PipelineStatus.RUNNING:
            result.status = PipelineStatus.COMPLETED

        self._pipeline_results.append(result)
        self._is_running = False

        await self._report_log(
            f"流水线完成: {len(result.stages_completed)}/{result.total_stages} 阶段, "
            f"{result.vulnerabilities_found} 漏洞"
        )

        return result

    async def _execute_stage_with_retry(
        self,
        stage: PipelineStage,
        target_url: str,
        headers: Optional[Dict[str, str]],
        tokens: Optional[List[str]],
        schema_data: Dict[str, Any],
        sensitive_targets: List[AttackTarget],
    ) -> Dict[str, Any]:
        """Execute stage with retry support.

        Args:
            stage: Pipeline stage.
            target_url: Target URL.
            headers: HTTP headers.
            tokens: Authentication tokens.
            schema_data: Schema data.
            sensitive_targets: Sensitive targets.

        Returns:
            Stage result dictionary.
        """
        for attempt in range(self._max_retries):
            try:
                result = await self._execute_stage(
                    stage, target_url, headers, tokens, schema_data, sensitive_targets
                )
                return result
            except Exception as e:
                if attempt < self._max_retries - 1:
                    await self._report_log(
                        f"阶段 {stage.value} 失败，重试 {attempt + 1}/{self._max_retries}"
                    )
                    await asyncio.sleep(self._retry_delay)
                else:
                    raise

        return {"success": False, "error": "Max retries exceeded"}

    async def _execute_stage(
        self,
        stage: PipelineStage,
        target_url: str,
        headers: Optional[Dict[str, str]],
        tokens: Optional[List[str]],
        schema_data: Dict[str, Any],
        sensitive_targets: List[AttackTarget],
    ) -> Dict[str, Any]:
        """Execute single pipeline stage.

        Args:
            stage: Pipeline stage.
            target_url: Target URL.
            headers: HTTP headers.
            tokens: Authentication tokens.
            schema_data: Schema data.
            sensitive_targets: Sensitive targets.

        Returns:
            Stage result dictionary.
        """
        if stage == PipelineStage.ENDPOINT_DISCOVERY:
            return await self._stage_endpoint_discovery(target_url, headers)
        elif stage == PipelineStage.INTROSPECTION:
            return await self._stage_introspection(target_url, headers)
        elif stage == PipelineStage.SCHEMA_ANALYSIS:
            return await self._stage_schema_analysis(schema_data)
        elif stage == PipelineStage.SENSITIVE_MARKING:
            return await self._stage_sensitive_marking(schema_data)
        elif stage == PipelineStage.AUTHZ_TESTING:
            return await self._stage_authz_testing(target_url, headers, tokens, schema_data)
        elif stage == PipelineStage.INJECTION_TESTING:
            return await self._stage_injection_testing(target_url, headers, schema_data)
        elif stage == PipelineStage.DOS_TESTING:
            return await self._stage_dos_testing(target_url, headers, schema_data)
        elif stage == PipelineStage.SUBSCRIPTION_TESTING:
            return await self._stage_subscription_testing(target_url, headers)
        elif stage == PipelineStage.REPORT_GENERATION:
            return await self._stage_report_generation(
                target_url, schema_data, sensitive_targets
            )

        return {"success": False, "error": "Unknown stage"}

    async def _stage_endpoint_discovery(
        self,
        target_url: str,
        headers: Optional[Dict[str, str]],
    ) -> Dict[str, Any]:
        """Execute endpoint discovery stage.

        Args:
            target_url: Target URL.
            headers: HTTP headers.

        Returns:
            Stage result.
        """
        if self.detector:
            endpoints = await self.detector.discover_endpoints(target_url, headers)
            return {
                "success": True,
                "endpoints": endpoints,
            }

        return {"success": True, "endpoints": [target_url]}

    async def _stage_introspection(
        self,
        target_url: str,
        headers: Optional[Dict[str, str]],
    ) -> Dict[str, Any]:
        """Execute introspection stage.

        Args:
            target_url: Target URL.
            headers: HTTP headers.

        Returns:
            Stage result.
        """
        if self.introspector:
            schema_data = await self.introspector.introspect(target_url, headers)
            return {
                "success": True,
                "schema_data": schema_data,
            }

        return {"success": True, "schema_data": {}}

    async def _stage_schema_analysis(
        self,
        schema_data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Execute schema analysis stage.

        Args:
            schema_data: Schema data.

        Returns:
            Stage result.
        """
        return {
            "success": True,
            "schema_data": schema_data,
        }

    async def _stage_sensitive_marking(
        self,
        schema_data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Execute sensitive marking stage.

        Args:
            schema_data: Schema data.

        Returns:
            Stage result.
        """
        sensitive_targets = self._identify_sensitive_targets(schema_data)

        return {
            "success": True,
            "sensitive_targets": sensitive_targets,
        }

    async def _stage_authz_testing(
        self,
        target_url: str,
        headers: Optional[Dict[str, str]],
        tokens: Optional[List[str]],
        schema_data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Execute authorization testing stage.

        Args:
            target_url: Target URL.
            headers: HTTP headers.
            tokens: Authentication tokens.
            schema_data: Schema data.

        Returns:
            Stage result.
        """
        vulnerabilities: List[Dict[str, Any]] = []

        if self.authz_tester and tokens:
            authz_results = await self.authz_tester.run_full_authz_suite(
                target_url, schema_data, tokens, headers
            )

            for vuln in authz_results.get("vulnerabilities", []):
                vulnerabilities.append(vuln)

        return {
            "success": True,
            "vulnerabilities": vulnerabilities,
        }

    async def _stage_injection_testing(
        self,
        target_url: str,
        headers: Optional[Dict[str, str]],
        schema_data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Execute injection testing stage.

        Args:
            target_url: Target URL.
            headers: HTTP headers.
            schema_data: Schema data.

        Returns:
            Stage result.
        """
        vulnerabilities: List[Dict[str, Any]] = []

        if self.injection_tester:
            injection_results = await self.injection_tester.run_full_injection_suite(
                target_url, schema_data, headers
            )

            for vuln in injection_results.results:
                if vuln.is_vulnerable:
                    vulnerabilities.append({
                        "type": "injection",
                        "field": vuln.target_field,
                        "parameter": vuln.parameter_name,
                        "payload": vuln.payload,
                        "severity": "high",
                    })

        return {
            "success": True,
            "vulnerabilities": vulnerabilities,
        }

    async def _stage_dos_testing(
        self,
        target_url: str,
        headers: Optional[Dict[str, str]],
        schema_data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Execute DoS testing stage.

        Args:
            target_url: Target URL.
            headers: HTTP headers.
            schema_data: Schema data.

        Returns:
            Stage result.
        """
        vulnerabilities: List[Dict[str, Any]] = []

        if self.advanced_attacks:
            dos_results = await self.advanced_attacks.run_full_advanced_suite(
                target_url, schema_data, headers=headers
            )

            if dos_results.dos_assessment.get("risk_level") in ("medium", "high"):
                vulnerabilities.append({
                    "type": "dos",
                    "risk_level": dos_results.dos_assessment["risk_level"],
                    "recommendation": dos_results.dos_assessment["recommendation"],
                    "severity": "high",
                })

        return {
            "success": True,
            "vulnerabilities": vulnerabilities,
        }

    async def _stage_subscription_testing(
        self,
        target_url: str,
        headers: Optional[Dict[str, str]],
    ) -> Dict[str, Any]:
        """Execute subscription testing stage.

        Args:
            target_url: Target URL.
            headers: HTTP headers.

        Returns:
            Stage result.
        """
        vulnerabilities: List[Dict[str, Any]] = []

        if self.subscription_tester:
            sub_results = await self.subscription_tester.run_full_subscription_suite(
                target_url, headers=headers
            )

            for vuln in sub_results.results:
                if vuln.is_vulnerable:
                    vulnerabilities.append({
                        "type": "subscription",
                        "test_type": vuln.test_type.value,
                        "endpoint": vuln.endpoint_url,
                        "severity": "high",
                    })

        return {
            "success": True,
            "vulnerabilities": vulnerabilities,
        }

    async def _stage_report_generation(
        self,
        target_url: str,
        schema_data: Dict[str, Any],
        sensitive_targets: List[AttackTarget],
    ) -> Dict[str, Any]:
        """Execute report generation stage.

        Args:
            target_url: Target URL.
            schema_data: Schema data.
            sensitive_targets: Sensitive targets.

        Returns:
            Stage result.
        """
        return {
            "success": True,
            "report": {
                "target": target_url,
                "schema_summary": schema_data,
                "sensitive_targets": len(sensitive_targets),
            },
        }

    def _identify_sensitive_targets(
        self,
        schema_data: Dict[str, Any],
    ) -> List[AttackTarget]:
        """Identify sensitive targets from schema.

        Args:
            schema_data: Schema data.

        Returns:
            List of AttackTarget.
        """
        targets: List[AttackTarget] = []

        types = schema_data.get("types", {})

        for type_name, type_data in types.items():
            for field_data in type_data.get("fields", []):
                field_name = field_data.get("name", "").lower()

                risk_score = 0.0
                sensitive_indicators: List[str] = []

                for pattern in self.SENSITIVE_FIELD_PATTERNS:
                    if pattern.lower() in field_name:
                        risk_score += 30
                        sensitive_indicators.append(pattern)

                for pattern in self.SENSITIVE_OPERATION_PATTERNS:
                    if pattern.lower() in field_name:
                        risk_score += 40
                        sensitive_indicators.append(pattern)

                if risk_score > 0:
                    priority = PriorityLevel.LOW
                    if risk_score >= 70:
                        priority = PriorityLevel.CRITICAL
                    elif risk_score >= 50:
                        priority = PriorityLevel.HIGH
                    elif risk_score >= 30:
                        priority = PriorityLevel.MEDIUM

                    target = AttackTarget(
                        target_id=f"target_{uuid.uuid4().hex[:8]}",
                        field_name=field_data.get("name", ""),
                        type_name=type_name,
                        operation_type=type_data.get("operation_type", "query"),
                        priority=priority,
                        risk_score=min(risk_score, 100),
                        estimated_time_ms=self._estimate_test_time(field_data),
                        sensitive_indicators=sensitive_indicators,
                    )
                    targets.append(target)

        targets.sort(key=lambda t: t.risk_score, reverse=True)

        return targets

    def _estimate_test_time(
        self,
        field_data: Dict[str, Any],
    ) -> float:
        """Estimate test time for field.

        Args:
            field_data: Field data.

        Returns:
            Estimated test time in milliseconds.
        """
        base_time = 100.0

        arg_count = len(field_data.get("args", []))
        base_time += arg_count * 50

        return base_time

    def _save_checkpoint(
        self,
        pipeline_id: str,
        stage: PipelineStage,
        stage_data: Dict[str, Any],
        target_url: str,
    ) -> None:
        """Save pipeline checkpoint.

        Args:
            pipeline_id: Pipeline ID.
            stage: Current stage.
            stage_data: Stage data.
            target_url: Target URL.
        """
        checkpoint = PipelineCheckpoint(
            checkpoint_id=pipeline_id,
            timestamp=time.time(),
            stage=stage,
            stage_data=stage_data,
            completed_stages=[],
            target_url=target_url,
        )

        self._checkpoints[pipeline_id] = checkpoint

    def export_pipeline_template(
        self,
        file_path: str,
        template: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Export pipeline template to YAML.

        Args:
            file_path: Output file path.
            template: Pipeline template (default: PIPELINE_TEMPLATE).
        """
        template_data = template or self.PIPELINE_TEMPLATE

        with open(file_path, "w", encoding="utf-8") as f:
            yaml.dump(template_data, f, default_flow_style=False, allow_unicode=True)

    def import_pipeline_template(
        self,
        file_path: str,
    ) -> Dict[str, Any]:
        """Import pipeline template from YAML.

        Args:
            file_path: Input file path.

        Returns:
            Pipeline template dictionary.
        """
        with open(file_path, "r", encoding="utf-8") as f:
            template: Dict[str, Any] = yaml.safe_load(f)

        return template

    def create_scheduled_task(
        self,
        name: str,
        target_url: str,
        schedule: str,
        pipeline_config: Optional[Dict[str, Any]] = None,
    ) -> ScheduledTask:
        """Create scheduled task.

        Args:
            name: Task name.
            target_url: Target URL.
            schedule: Cron expression or interval.
            pipeline_config: Pipeline configuration.

        Returns:
            ScheduledTask.
        """
        task = ScheduledTask(
            task_id=f"task_{uuid.uuid4().hex[:8]}",
            name=name,
            target_url=target_url,
            schedule=schedule,
            pipeline_config=pipeline_config or {},
        )

        self._scheduled_tasks[task.task_id] = task

        return task

    async def run_scheduled_task(
        self,
        task_id: str,
    ) -> PipelineResult:
        """Run scheduled task.

        Args:
            task_id: Task ID.

        Returns:
            PipelineResult.
        """
        task = self._scheduled_tasks.get(task_id)

        if not task:
            raise ValueError(f"Task not found: {task_id}")

        task.last_run = time.time()

        result = await self.run_full_pipeline(
            task.target_url,
        )

        return result

    def get_scheduled_tasks(
        self,
        enabled_only: bool = False,
    ) -> List[ScheduledTask]:
        """Get scheduled tasks.

        Args:
            enabled_only: Only return enabled tasks.

        Returns:
            List of ScheduledTask.
        """
        tasks = list(self._scheduled_tasks.values())

        if enabled_only:
            tasks = [t for t in tasks if t.enabled]

        return tasks

    def cancel_pipeline(
        self,
        pipeline_id: Optional[str] = None,
    ) -> None:
        """Cancel running pipeline.

        Args:
            pipeline_id: Pipeline ID to cancel (default: current).
        """
        target_id = pipeline_id or self._current_pipeline_id

        if target_id:
            self._is_running = False
            logger.info("Pipeline cancelled: %s", target_id)

    def get_pipeline_results(
        self,
        limit: int = 10,
    ) -> List[PipelineResult]:
        """Get pipeline results.

        Args:
            limit: Maximum results.

        Returns:
            List of PipelineResult.
        """
        return self._pipeline_results[-limit:]

    def get_stats(self) -> Dict[str, Any]:
        """Get pipeline statistics.

        Returns:
            Statistics dictionary.
        """
        return {
            "total_pipelines": len(self._pipeline_results),
            "completed_pipelines": sum(
                1 for r in self._pipeline_results
                if r.status == PipelineStatus.COMPLETED
            ),
            "failed_pipelines": sum(
                1 for r in self._pipeline_results
                if r.status == PipelineStatus.FAILED
            ),
            "scheduled_tasks": len(self._scheduled_tasks),
            "enabled_tasks": sum(
                1 for t in self._scheduled_tasks.values()
                if t.enabled
            ),
        }
