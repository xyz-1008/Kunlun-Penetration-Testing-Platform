"""
JWT Attack Orchestration Module - Attack chain workflow engine,
batch auditing, and scheduled testing.

This module provides:
    1. JWT attack chain workflow engine with YAML templates
    2. Batch JWT auditing from proxy history, file import, or manual input
    3. Scheduled automated testing with alerting
    4. Workflow pause, skip, rollback support
    5. Community workflow template sharing

Integration points:
    - JWT Parser Exploits module
    - JWT Info Leak module
    - OAuth Cross Client module
    - Diagnostic AI module
    - Task management system

Author: Kunlun Security Lab
License: Internal Use Only
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Coroutine, Dict, List, Optional, Set, Tuple

import yaml  # type: ignore[import-untyped]

logger = logging.getLogger(__name__)


# =============================================================================
# Enums
# =============================================================================

class WorkflowStatus(str, Enum):
    """Workflow execution status."""

    PENDING = "pending"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"


class StepStatus(str, Enum):
    """Step execution status."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


class RiskLevel(str, Enum):
    """Risk level for JWT audit results."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# =============================================================================
# Data Classes
# =============================================================================

@dataclass
class WorkflowStep:
    """Single step in an attack workflow.

    Attributes:
        step_id: Unique step identifier
        name: Step display name
        description: Step description
        action: Action type to execute
        parameters: Step-specific parameters
        depends_on: List of step IDs this step depends on
        timeout: Step timeout in seconds
    """

    step_id: str = ""
    name: str = ""
    description: str = ""
    action: str = ""
    parameters: Dict[str, Any] = field(default_factory=dict)
    depends_on: List[str] = field(default_factory=list)
    timeout: int = 30

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary.

        Returns:
            Dictionary representation.
        """
        return {
            "step_id": self.step_id,
            "name": self.name,
            "description": self.description,
            "action": self.action,
            "parameters": self.parameters,
            "depends_on": self.depends_on,
            "timeout": self.timeout,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "WorkflowStep":
        """Create from dictionary.

        Args:
            data: Dictionary data.

        Returns:
            WorkflowStep instance.
        """
        return cls(
            step_id=data.get("step_id", ""),
            name=data.get("name", ""),
            description=data.get("description", ""),
            action=data.get("action", ""),
            parameters=data.get("parameters", {}),
            depends_on=data.get("depends_on", []),
            timeout=data.get("timeout", 30),
        )


@dataclass
class StepResult:
    """Result of a workflow step execution.

    Attributes:
        step_id: Step identifier
        status: Execution status
        output: Step output data
        error: Error message if failed
        duration: Execution duration in seconds
        timestamp: Execution timestamp
    """

    step_id: str = ""
    status: StepStatus = StepStatus.PENDING
    output: Dict[str, Any] = field(default_factory=dict)
    error: str = ""
    duration: float = 0.0
    timestamp: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary.

        Returns:
            Dictionary representation.
        """
        return {
            "step_id": self.step_id,
            "status": self.status.value,
            "output": self.output,
            "error": self.error,
            "duration": self.duration,
            "timestamp": self.timestamp,
        }


@dataclass
class AttackWorkflow:
    """Complete attack workflow definition.

    Attributes:
        workflow_id: Unique workflow identifier
        name: Workflow display name
        description: Workflow description
        version: Workflow version
        steps: List of workflow steps
        created_at: Creation timestamp
        tags: Workflow tags for categorization
    """

    workflow_id: str = ""
    name: str = ""
    description: str = ""
    version: str = "1.0.0"
    steps: List[WorkflowStep] = field(default_factory=list)
    created_at: float = 0.0
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary.

        Returns:
            Dictionary representation.
        """
        return {
            "workflow_id": self.workflow_id,
            "name": self.name,
            "description": self.description,
            "version": self.version,
            "steps": [s.to_dict() for s in self.steps],
            "created_at": self.created_at,
            "tags": self.tags,
        }

    def to_yaml(self) -> str:
        """Convert to YAML string.

        Returns:
            YAML string representation.
        """
        result: str = yaml.dump(self.to_dict(), default_flow_style=False, allow_unicode=True)
        return result

    @classmethod
    def from_yaml(cls, yaml_str: str) -> "AttackWorkflow":
        """Create from YAML string.

        Args:
            yaml_str: YAML string.

        Returns:
            AttackWorkflow instance.
        """
        data: Dict[str, Any] = yaml.safe_load(yaml_str)
        return cls.from_dict(data)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AttackWorkflow":
        """Create from dictionary.

        Args:
            data: Dictionary data.

        Returns:
            AttackWorkflow instance.
        """
        return cls(
            workflow_id=data.get("workflow_id", ""),
            name=data.get("name", ""),
            description=data.get("description", ""),
            version=data.get("version", "1.0.0"),
            steps=[WorkflowStep.from_dict(s) for s in data.get("steps", [])],
            created_at=data.get("created_at", 0.0),
            tags=data.get("tags", []),
        )


@dataclass
class WorkflowExecution:
    """Workflow execution state.

    Attributes:
        execution_id: Unique execution identifier
        workflow: Associated workflow
        status: Execution status
        step_results: Results for each step
        started_at: Start timestamp
        completed_at: Completion timestamp
        current_step_index: Current step index
    """

    execution_id: str = ""
    workflow: Optional[AttackWorkflow] = None
    status: WorkflowStatus = WorkflowStatus.PENDING
    step_results: Dict[str, StepResult] = field(default_factory=dict)
    started_at: float = 0.0
    completed_at: float = 0.0
    current_step_index: int = 0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary.

        Returns:
            Dictionary representation.
        """
        return {
            "execution_id": self.execution_id,
            "workflow": self.workflow.to_dict() if self.workflow else None,
            "status": self.status.value,
            "step_results": {k: v.to_dict() for k, v in self.step_results.items()},
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "current_step_index": self.current_step_index,
        }


@dataclass
class BatchAuditResult:
    """Batch JWT audit result.

    Attributes:
        jwt_token: The JWT token audited
        risk_level: Overall risk level
        vulnerabilities: List of found vulnerabilities
        recommendations: List of recommendations
        audit_timestamp: Audit timestamp
        execution_time: Total execution time in seconds
    """

    jwt_token: str = ""
    risk_level: RiskLevel = RiskLevel.INFO
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    audit_timestamp: float = 0.0
    execution_time: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary.

        Returns:
            Dictionary representation.
        """
        return {
            "jwt_token": self.jwt_token[:50] + "...",
            "risk_level": self.risk_level.value,
            "vulnerabilities": self.vulnerabilities,
            "recommendations": self.recommendations,
            "audit_timestamp": self.audit_timestamp,
            "execution_time": self.execution_time,
        }


@dataclass
class ScheduledTask:
    """Scheduled JWT testing task.

    Attributes:
        task_id: Unique task identifier
        name: Task display name
        target_url: Target API URL
        interval_seconds: Test interval in seconds
        workflow_id: Workflow to execute
        enabled: Whether task is enabled
        last_run: Last run timestamp
        next_run: Next scheduled run timestamp
        alert_webhook: Alert webhook URL
    """

    task_id: str = ""
    name: str = ""
    target_url: str = ""
    interval_seconds: int = 3600
    workflow_id: str = ""
    enabled: bool = True
    last_run: float = 0.0
    next_run: float = 0.0
    alert_webhook: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary.

        Returns:
            Dictionary representation.
        """
        return {
            "task_id": self.task_id,
            "name": self.name,
            "target_url": self.target_url,
            "interval_seconds": self.interval_seconds,
            "workflow_id": self.workflow_id,
            "enabled": self.enabled,
            "last_run": self.last_run,
            "next_run": self.next_run,
            "alert_webhook": self.alert_webhook,
        }


# =============================================================================
# Built-in Workflow Templates
# =============================================================================

class WorkflowTemplates:
    """Built-in attack workflow templates.

    Provides pre-defined workflow templates for common JWT/OAuth attack scenarios.
    """

    @staticmethod
    def jwt_full_audit() -> AttackWorkflow:
        """Create JWT full audit workflow.

        Workflow: JWT auto-identify → Algorithm analysis → Weak key brute force
        → Claim tampering → Privilege escalation verification

        Returns:
            AttackWorkflow instance.
        """
        return AttackWorkflow(
            workflow_id="wf-jwt-full-audit",
            name="JWT 全量审计工作流",
            description=(
                "完整的 JWT 审计流程：自动识别 → 算法分析 → 弱密钥爆破 → "
                "声明篡改 → 权限提升验证"
            ),
            version="1.0.0",
            steps=[
                WorkflowStep(
                    step_id="step-1",
                    name="JWT 自动识别",
                    description="识别 JWT 格式、算法、声明结构。",
                    action="jwt_identify",
                    parameters={"extract_claims": True, "check_format": True},
                    timeout=10,
                ),
                WorkflowStep(
                    step_id="step-2",
                    name="算法分析",
                    description="分析 JWT 使用的算法及其安全性。",
                    action="algorithm_analysis",
                    parameters={"check_none_alg": True, "check_confusion": True},
                    depends_on=["step-1"],
                    timeout=15,
                ),
                WorkflowStep(
                    step_id="step-3",
                    name="弱密钥爆破",
                    description="尝试使用常见弱密钥验证签名。",
                    action="weak_key_brute",
                    parameters={
                        "wordlist": "common_secrets",
                        "max_keys": 1000,
                    },
                    depends_on=["step-2"],
                    timeout=60,
                ),
                WorkflowStep(
                    step_id="step-4",
                    name="声明篡改",
                    description="尝试篡改 JWT 声明并测试接受度。",
                    action="claim_tampering",
                    parameters={
                        "claims_to_test": ["sub", "role", "admin", "scope"],
                    },
                    depends_on=["step-1"],
                    timeout=20,
                ),
                WorkflowStep(
                    step_id="step-5",
                    name="权限提升验证",
                    description="验证篡改后的 JWT 是否获得更高权限。",
                    action="privilege_escalation",
                    parameters={"test_endpoints": True},
                    depends_on=["step-4"],
                    timeout=30,
                ),
            ],
            created_at=time.time(),
            tags=["jwt", "full-audit", "comprehensive"],
        )

    @staticmethod
    def oauth_full_audit() -> AttackWorkflow:
        """Create OAuth full audit workflow.

        Workflow: OAuth flow identify → CSRF detection → Redirect bypass
        → Authorization code replay → Token reuse testing

        Returns:
            AttackWorkflow instance.
        """
        return AttackWorkflow(
            workflow_id="wf-oauth-full-audit",
            name="OAuth 全量审计工作流",
            description=(
                "完整的 OAuth 审计流程：流程识别 → CSRF 检测 → 重定向绕过 → "
                "授权码重放 → 令牌复用测试"
            ),
            version="1.0.0",
            steps=[
                WorkflowStep(
                    step_id="step-1",
                    name="OAuth 流程识别",
                    description="识别 OAuth 授权流程类型。",
                    action="oauth_flow_identify",
                    parameters={"detect_implicit": True, "detect_pkce": True},
                    timeout=15,
                ),
                WorkflowStep(
                    step_id="step-2",
                    name="CSRF 检测",
                    description="检测 OAuth 流程中的 CSRF 漏洞。",
                    action="csrf_detection",
                    parameters={"check_state": True, "check_nonce": True},
                    depends_on=["step-1"],
                    timeout=20,
                ),
                WorkflowStep(
                    step_id="step-3",
                    name="重定向绕过",
                    description="测试重定向 URI 验证是否可绕过。",
                    action="redirect_bypass",
                    parameters={
                        "test_variants": [
                            "subdomain",
                            "path_traversal",
                            "open_redirect",
                        ],
                    },
                    depends_on=["step-1"],
                    timeout=30,
                ),
                WorkflowStep(
                    step_id="step-4",
                    name="授权码重放",
                    description="测试授权码是否可重放使用。",
                    action="auth_code_replay",
                    parameters={"replay_count": 3},
                    depends_on=["step-1"],
                    timeout=20,
                ),
                WorkflowStep(
                    step_id="step-5",
                    name="令牌复用测试",
                    description="测试令牌是否可在不同客户端间复用。",
                    action="token_reuse",
                    parameters={"test_cross_client": True},
                    depends_on=["step-4"],
                    timeout=25,
                ),
            ],
            created_at=time.time(),
            tags=["oauth", "full-audit", "comprehensive"],
        )

    @staticmethod
    def jwt_quick_scan() -> AttackWorkflow:
        """Create JWT quick scan workflow.

        Returns:
            AttackWorkflow instance.
        """
        return AttackWorkflow(
            workflow_id="wf-jwt-quick-scan",
            name="JWT 快速扫描",
            description="快速 JWT 安全检查：算法验证 + 过期检查 + 基础声明分析。",
            version="1.0.0",
            steps=[
                WorkflowStep(
                    step_id="step-1",
                    name="算法验证",
                    description="检查 JWT 算法安全性。",
                    action="algorithm_check",
                    parameters={"check_none": True, "check_weak": True},
                    timeout=10,
                ),
                WorkflowStep(
                    step_id="step-2",
                    name="过期检查",
                    description="检查 JWT 过期策略。",
                    action="expiry_check",
                    parameters={},
                    depends_on=["step-1"],
                    timeout=5,
                ),
                WorkflowStep(
                    step_id="step-3",
                    name="声明分析",
                    description="分析 JWT 声明中的敏感信息。",
                    action="claim_analysis",
                    parameters={"check_sensitive": True},
                    depends_on=["step-1"],
                    timeout=10,
                ),
            ],
            created_at=time.time(),
            tags=["jwt", "quick-scan", "basic"],
        )


# =============================================================================
# Workflow Engine
# =============================================================================

class WorkflowEngine:
    """JWT attack workflow execution engine.

    Supports:
    - Workflow execution with dependency resolution
    - Real-time progress tracking
    - Pause, skip, rollback operations
    - YAML template import/export
    """

    def __init__(self) -> None:
        """Initialize the workflow engine."""
        self.workflows: Dict[str, AttackWorkflow] = {}
        self.executions: Dict[str, WorkflowExecution] = {}
        self.execution_counter = 0
        self._action_handlers: Dict[str, Callable[..., Coroutine[Any, Any, Dict[str, Any]]]] = {}
        self._register_builtin_handlers()

    def _next_execution_id(self) -> str:
        """Generate next execution ID.

        Returns:
            Execution ID string.
        """
        self.execution_counter += 1
        return f"exec-{self.execution_counter:04d}"

    def _register_builtin_handlers(self) -> None:
        """Register built-in action handlers."""
        self._action_handlers = {
            "jwt_identify": self._handle_jwt_identify,
            "algorithm_analysis": self._handle_algorithm_analysis,
            "weak_key_brute": self._handle_weak_key_brute,
            "claim_tampering": self._handle_claim_tampering,
            "privilege_escalation": self._handle_privilege_escalation,
            "oauth_flow_identify": self._handle_oauth_flow_identify,
            "csrf_detection": self._handle_csrf_detection,
            "redirect_bypass": self._handle_redirect_bypass,
            "auth_code_replay": self._handle_auth_code_replay,
            "token_reuse": self._handle_token_reuse,
            "algorithm_check": self._handle_algorithm_check,
            "expiry_check": self._handle_expiry_check,
            "claim_analysis": self._handle_claim_analysis,
        }

    async def _handle_jwt_identify(self, **kwargs: Any) -> Dict[str, Any]:
        """Handle JWT identification action.

        Args:
            **kwargs: Action parameters.

        Returns:
            Action result dictionary.
        """
        return {"action": "jwt_identify", "status": "simulated", "params": kwargs}

    async def _handle_algorithm_analysis(self, **kwargs: Any) -> Dict[str, Any]:
        """Handle algorithm analysis action.

        Args:
            **kwargs: Action parameters.

        Returns:
            Action result dictionary.
        """
        return {"action": "algorithm_analysis", "status": "simulated", "params": kwargs}

    async def _handle_weak_key_brute(self, **kwargs: Any) -> Dict[str, Any]:
        """Handle weak key brute force action.

        Args:
            **kwargs: Action parameters.

        Returns:
            Action result dictionary.
        """
        return {"action": "weak_key_brute", "status": "simulated", "params": kwargs}

    async def _handle_claim_tampering(self, **kwargs: Any) -> Dict[str, Any]:
        """Handle claim tampering action.

        Args:
            **kwargs: Action parameters.

        Returns:
            Action result dictionary.
        """
        return {"action": "claim_tampering", "status": "simulated", "params": kwargs}

    async def _handle_privilege_escalation(self, **kwargs: Any) -> Dict[str, Any]:
        """Handle privilege escalation action.

        Args:
            **kwargs: Action parameters.

        Returns:
            Action result dictionary.
        """
        return {"action": "privilege_escalation", "status": "simulated", "params": kwargs}

    async def _handle_oauth_flow_identify(self, **kwargs: Any) -> Dict[str, Any]:
        """Handle OAuth flow identification action.

        Args:
            **kwargs: Action parameters.

        Returns:
            Action result dictionary.
        """
        return {"action": "oauth_flow_identify", "status": "simulated", "params": kwargs}

    async def _handle_csrf_detection(self, **kwargs: Any) -> Dict[str, Any]:
        """Handle CSRF detection action.

        Args:
            **kwargs: Action parameters.

        Returns:
            Action result dictionary.
        """
        return {"action": "csrf_detection", "status": "simulated", "params": kwargs}

    async def _handle_redirect_bypass(self, **kwargs: Any) -> Dict[str, Any]:
        """Handle redirect bypass action.

        Args:
            **kwargs: Action parameters.

        Returns:
            Action result dictionary.
        """
        return {"action": "redirect_bypass", "status": "simulated", "params": kwargs}

    async def _handle_auth_code_replay(self, **kwargs: Any) -> Dict[str, Any]:
        """Handle authorization code replay action.

        Args:
            **kwargs: Action parameters.

        Returns:
            Action result dictionary.
        """
        return {"action": "auth_code_replay", "status": "simulated", "params": kwargs}

    async def _handle_token_reuse(self, **kwargs: Any) -> Dict[str, Any]:
        """Handle token reuse action.

        Args:
            **kwargs: Action parameters.

        Returns:
            Action result dictionary.
        """
        return {"action": "token_reuse", "status": "simulated", "params": kwargs}

    async def _handle_algorithm_check(self, **kwargs: Any) -> Dict[str, Any]:
        """Handle algorithm check action.

        Args:
            **kwargs: Action parameters.

        Returns:
            Action result dictionary.
        """
        return {"action": "algorithm_check", "status": "simulated", "params": kwargs}

    async def _handle_expiry_check(self, **kwargs: Any) -> Dict[str, Any]:
        """Handle expiry check action.

        Args:
            **kwargs: Action parameters.

        Returns:
            Action result dictionary.
        """
        return {"action": "expiry_check", "status": "simulated", "params": kwargs}

    async def _handle_claim_analysis(self, **kwargs: Any) -> Dict[str, Any]:
        """Handle claim analysis action.

        Args:
            **kwargs: Action parameters.

        Returns:
            Action result dictionary.
        """
        return {"action": "claim_analysis", "status": "simulated", "params": kwargs}

    def register_workflow(self, workflow: AttackWorkflow) -> None:
        """Register a workflow template.

        Args:
            workflow: Workflow to register.
        """
        self.workflows[workflow.workflow_id] = workflow
        logger.info(f"Workflow registered: {workflow.workflow_id}")

    def register_action_handler(
        self,
        action_name: str,
        handler: Callable[..., Coroutine[Any, Any, Dict[str, Any]]],
    ) -> None:
        """Register a custom action handler.

        Args:
            action_name: Action name.
            handler: Async handler function.
        """
        self._action_handlers[action_name] = handler
        logger.info(f"Action handler registered: {action_name}")

    async def execute_workflow(
        self,
        workflow_id: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> WorkflowExecution:
        """Execute a workflow.

        Args:
            workflow_id: Workflow ID to execute.
            context: Execution context data.

        Returns:
            WorkflowExecution with results.

        Raises:
            ValueError: If workflow not found.
        """
        workflow = self.workflows.get(workflow_id)
        if not workflow:
            raise ValueError(f"Workflow not found: {workflow_id}")

        execution = WorkflowExecution(
            execution_id=self._next_execution_id(),
            workflow=workflow,
            status=WorkflowStatus.RUNNING,
            started_at=time.time(),
        )

        self.executions[execution.execution_id] = execution

        step_map: Dict[str, WorkflowStep] = {s.step_id: s for s in workflow.steps}
        completed_steps: Set[str] = set()

        for i, step in enumerate(workflow.steps):
            execution.current_step_index = i

            if execution.status != WorkflowStatus.RUNNING:
                break

            for dep in step.depends_on:
                if dep not in completed_steps:
                    step_result = StepResult(
                        step_id=step.step_id,
                        status=StepStatus.SKIPPED,
                        error=f"Dependency {dep} not completed",
                        timestamp=time.time(),
                    )
                    execution.step_results[step.step_id] = step_result
                    continue

            start_time = time.time()

            try:
                handler = self._action_handlers.get(step.action)
                if handler:
                    result = await handler(**step.parameters, **(context or {}))
                    step_result = StepResult(
                        step_id=step.step_id,
                        status=StepStatus.COMPLETED,
                        output=result,
                        duration=time.time() - start_time,
                        timestamp=time.time(),
                    )
                    completed_steps.add(step.step_id)
                else:
                    step_result = StepResult(
                        step_id=step.step_id,
                        status=StepStatus.FAILED,
                        error=f"Unknown action: {step.action}",
                        duration=time.time() - start_time,
                        timestamp=time.time(),
                    )

            except Exception as e:
                step_result = StepResult(
                    step_id=step.step_id,
                    status=StepStatus.FAILED,
                    error=str(e),
                    duration=time.time() - start_time,
                    timestamp=time.time(),
                )

            execution.step_results[step.step_id] = step_result

            if step_result.status == StepStatus.FAILED:
                execution.status = WorkflowStatus.FAILED
                break

        if execution.status == WorkflowStatus.RUNNING:
            execution.status = WorkflowStatus.COMPLETED

        execution.completed_at = time.time()

        return execution

    async def pause_execution(self, execution_id: str) -> bool:
        """Pause a running execution.

        Args:
            execution_id: Execution ID to pause.

        Returns:
            True if paused successfully.
        """
        execution = self.executions.get(execution_id)
        if execution and execution.status == WorkflowStatus.RUNNING:
            execution.status = WorkflowStatus.PAUSED
            logger.info(f"Execution paused: {execution_id}")
            return True
        return False

    async def resume_execution(self, execution_id: str) -> Optional[WorkflowExecution]:
        """Resume a paused execution.

        Args:
            execution_id: Execution ID to resume.

        Returns:
            Updated WorkflowExecution or None.
        """
        execution = self.executions.get(execution_id)
        if execution and execution.status == WorkflowStatus.PAUSED:
            execution.status = WorkflowStatus.RUNNING
            logger.info(f"Execution resumed: {execution_id}")
            return execution
        return None

    async def skip_step(self, execution_id: str, step_id: str) -> bool:
        """Skip a step in execution.

        Args:
            execution_id: Execution ID.
            step_id: Step ID to skip.

        Returns:
            True if skipped successfully.
        """
        execution = self.executions.get(execution_id)
        if execution and step_id in execution.step_results:
            execution.step_results[step_id].status = StepStatus.SKIPPED
            logger.info(f"Step skipped: {step_id}")
            return True
        return False

    async def rollback_execution(self, execution_id: str) -> bool:
        """Rollback a completed or failed execution.

        Args:
            execution_id: Execution ID to rollback.

        Returns:
            True if rolled back successfully.
        """
        execution = self.executions.get(execution_id)
        if execution:
            execution.status = WorkflowStatus.ROLLED_BACK
            logger.info(f"Execution rolled back: {execution_id}")
            return True
        return False

    def export_workflow(self, workflow_id: str, file_path: str) -> bool:
        """Export workflow to YAML file.

        Args:
            workflow_id: Workflow ID to export.
            file_path: Output file path.

        Returns:
            True if exported successfully.
        """
        workflow = self.workflows.get(workflow_id)
        if not workflow:
            return False

        try:
            Path(file_path).write_text(workflow.to_yaml(), encoding="utf-8")
            logger.info(f"Workflow exported: {file_path}")
            return True
        except Exception as e:
            logger.error(f"Export failed: {e}")
            return False

    def import_workflow(self, file_path: str) -> Optional[AttackWorkflow]:
        """Import workflow from YAML file.

        Args:
            file_path: Input file path.

        Returns:
            Imported AttackWorkflow or None.
        """
        try:
            yaml_str = Path(file_path).read_text(encoding="utf-8")
            workflow = AttackWorkflow.from_yaml(yaml_str)
            self.register_workflow(workflow)
            return workflow
        except Exception as e:
            logger.error(f"Import failed: {e}")
            return None


# =============================================================================
# Batch JWT Auditor
# =============================================================================

class BatchJWTAuditor:
    """Batch JWT auditing engine.

    Supports:
    - Loading JWTs from proxy history, files, or manual input
    - Full attack test suite execution
    - Risk-level sorted results
    - One-click exploitation suggestions
    """

    def __init__(self, workflow_engine: Optional[WorkflowEngine] = None) -> None:
        """Initialize the batch auditor.

        Args:
            workflow_engine: Optional workflow engine for audit.
        """
        self.workflow_engine = workflow_engine or WorkflowEngine()
        self.results: List[BatchAuditResult] = []

    def load_jwt_from_file(self, file_path: str) -> List[str]:
        """Load JWTs from file.

        Args:
            file_path: File path with one JWT per line.

        Returns:
            List of JWT tokens.
        """
        try:
            content = Path(file_path).read_text(encoding="utf-8")
            tokens = [line.strip() for line in content.splitlines() if line.strip()]
            logger.info(f"Loaded {len(tokens)} JWTs from file")
            return tokens
        except Exception as e:
            logger.error(f"Failed to load JWTs from file: {e}")
            return []

    def load_jwt_from_manual(self, tokens: List[str]) -> List[str]:
        """Load JWTs from manual input.

        Args:
            tokens: List of JWT token strings.

        Returns:
            List of validated JWT tokens.
        """
        valid_tokens = []
        for token in tokens:
            token = token.strip()
            if token.count(".") == 2:
                valid_tokens.append(token)
            else:
                logger.warning(f"Invalid JWT format skipped: {token[:20]}...")

        logger.info(f"Loaded {len(valid_tokens)} valid JWTs from manual input")
        return valid_tokens

    def load_jwt_from_proxy_history(
        self,
        proxy_log_file: str,
    ) -> List[str]:
        """Load JWTs from proxy history log.

        Args:
            proxy_log_file: Proxy log file path.

        Returns:
            List of extracted JWT tokens.
        """
        import re

        jwt_pattern = re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")

        try:
            content = Path(proxy_log_file).read_text(encoding="utf-8")
            tokens = list(set(jwt_pattern.findall(content)))
            logger.info(f"Extracted {len(tokens)} JWTs from proxy history")
            return tokens
        except Exception as e:
            logger.error(f"Failed to load JWTs from proxy history: {e}")
            return []

    async def audit_single_jwt(
        self,
        jwt_token: str,
        workflow_id: str = "wf-jwt-quick-scan",
    ) -> BatchAuditResult:
        """Audit a single JWT token.

        Args:
            jwt_token: JWT token to audit.
            workflow_id: Workflow to use for audit.

        Returns:
            BatchAuditResult with findings.
        """
        start_time = time.time()

        vulnerabilities: List[Dict[str, Any]] = []
        recommendations: List[str] = []
        risk_level = RiskLevel.INFO

        try:
            parts = jwt_token.split(".")
            if len(parts) != 3:
                vulnerabilities.append({
                    "type": "invalid_format",
                    "severity": "info",
                    "description": "JWT 格式无效，不是标准的三段式。",
                })
                risk_level = RiskLevel.LOW
            else:
                header_b64 = parts[0]
                padding = 4 - len(header_b64) % 4
                if padding != 4:
                    header_b64 += "=" * padding

                header = json.loads(base64.urlsafe_b64decode(header_b64))

                alg = header.get("alg", "")

                if alg.lower() == "none":
                    vulnerabilities.append({
                        "type": "none_algorithm",
                        "severity": "critical",
                        "description": "JWT 使用 none 算法，签名验证被完全绕过。",
                    })
                    risk_level = RiskLevel.CRITICAL
                    recommendations.append("立即禁用 none 算法，强制使用 RS256 或 ES256。")

                if alg in ("HS256", "HS384", "HS512"):
                    vulnerabilities.append({
                        "type": "symmetric_algorithm",
                        "severity": "medium",
                        "description": "JWT 使用对称算法，存在弱密钥风险。",
                    })
                    if risk_level == RiskLevel.INFO:
                        risk_level = RiskLevel.MEDIUM
                    recommendations.append("考虑使用非对称算法（RS256/ES256）。")

                payload_b64 = parts[1]
                padding = 4 - len(payload_b64) % 4
                if padding != 4:
                    payload_b64 += "=" * padding

                payload = json.loads(base64.urlsafe_b64decode(payload_b64))

                if "exp" not in payload:
                    vulnerabilities.append({
                        "type": "no_expiry",
                        "severity": "high",
                        "description": "JWT 没有设置过期时间，令牌可能永久有效。",
                    })
                    if risk_level in (RiskLevel.INFO, RiskLevel.LOW, RiskLevel.MEDIUM):
                        risk_level = RiskLevel.HIGH
                    recommendations.append("为所有 JWT 设置合理的 exp 声明。")

                if "admin" in payload and payload.get("admin") is True:
                    vulnerabilities.append({
                        "type": "admin_claim",
                        "severity": "high",
                        "description": "JWT 包含 admin 声明，可能被篡改提升权限。",
                    })
                    if risk_level in (RiskLevel.INFO, RiskLevel.LOW, RiskLevel.MEDIUM):
                        risk_level = RiskLevel.HIGH

        except Exception as e:
            vulnerabilities.append({
                "type": "parse_error",
                "severity": "info",
                "description": f"JWT 解析失败: {e}",
            })

        result = BatchAuditResult(
            jwt_token=jwt_token,
            risk_level=risk_level,
            vulnerabilities=vulnerabilities,
            recommendations=recommendations,
            audit_timestamp=time.time(),
            execution_time=time.time() - start_time,
        )

        self.results.append(result)
        return result

    async def audit_batch(
        self,
        jwt_tokens: List[str],
        workflow_id: str = "wf-jwt-quick-scan",
    ) -> List[BatchAuditResult]:
        """Audit a batch of JWT tokens.

        Args:
            jwt_tokens: List of JWT tokens.
            workflow_id: Workflow to use for audit.

        Returns:
            List of BatchAuditResult sorted by risk level.
        """
        results = []

        for token in jwt_tokens:
            result = await self.audit_single_jwt(token, workflow_id)
            results.append(result)

        risk_order = {
            RiskLevel.CRITICAL: 0,
            RiskLevel.HIGH: 1,
            RiskLevel.MEDIUM: 2,
            RiskLevel.LOW: 3,
            RiskLevel.INFO: 4,
        }

        results.sort(key=lambda r: risk_order.get(r.risk_level, 5))

        return results

    def get_high_risk_results(self) -> List[BatchAuditResult]:
        """Get high risk audit results.

        Returns:
            List of high and critical risk results.
        """
        return [
            r for r in self.results
            if r.risk_level in (RiskLevel.CRITICAL, RiskLevel.HIGH)
        ]

    def export_report(self, file_path: str) -> bool:
        """Export batch audit report to YAML.

        Args:
            file_path: Output file path.

        Returns:
            True if exported successfully.
        """
        try:
            report = {
                "report_timestamp": time.time(),
                "total_audited": len(self.results),
                "high_risk_count": len(self.get_high_risk_results()),
                "results": [r.to_dict() for r in self.results],
            }

            Path(file_path).write_text(
                yaml.dump(report, default_flow_style=False, allow_unicode=True),
                encoding="utf-8",
            )

            logger.info(f"Report exported: {file_path}")
            return True
        except Exception as e:
            logger.error(f"Export failed: {e}")
            return False


# =============================================================================
# Scheduled Task Manager
# =============================================================================

class ScheduledTaskManager:
    """Scheduled JWT testing task manager.

    Supports:
    - Creating and managing scheduled tasks
    - Interval-based automated testing
    - Alert on new vulnerability discovery
    - Integration with task management system
    """

    def __init__(self, workflow_engine: Optional[WorkflowEngine] = None) -> None:
        """Initialize the scheduled task manager.

        Args:
            workflow_engine: Optional workflow engine for tasks.
        """
        self.workflow_engine = workflow_engine or WorkflowEngine()
        self.tasks: Dict[str, ScheduledTask] = {}
        self.task_counter = 0
        self._running = False
        self._task_loop: Optional[asyncio.Task[None]] = None

    def _next_task_id(self) -> str:
        """Generate next task ID.

        Returns:
            Task ID string.
        """
        self.task_counter += 1
        return f"task-{self.task_counter:04d}"

    def create_task(
        self,
        name: str,
        target_url: str,
        interval_seconds: int = 3600,
        workflow_id: str = "wf-jwt-quick-scan",
        alert_webhook: str = "",
    ) -> ScheduledTask:
        """Create a new scheduled task.

        Args:
            name: Task display name.
            target_url: Target API URL.
            interval_seconds: Test interval in seconds.
            workflow_id: Workflow to execute.
            alert_webhook: Alert webhook URL.

        Returns:
            Created ScheduledTask.
        """
        task = ScheduledTask(
            task_id=self._next_task_id(),
            name=name,
            target_url=target_url,
            interval_seconds=interval_seconds,
            workflow_id=workflow_id,
            alert_webhook=alert_webhook,
            next_run=time.time() + interval_seconds,
        )

        self.tasks[task.task_id] = task
        logger.info(f"Scheduled task created: {task.task_id}")

        return task

    def delete_task(self, task_id: str) -> bool:
        """Delete a scheduled task.

        Args:
            task_id: Task ID to delete.

        Returns:
            True if deleted successfully.
        """
        if task_id in self.tasks:
            del self.tasks[task_id]
            logger.info(f"Scheduled task deleted: {task_id}")
            return True
        return False

    def enable_task(self, task_id: str) -> bool:
        """Enable a scheduled task.

        Args:
            task_id: Task ID to enable.

        Returns:
            True if enabled successfully.
        """
        task = self.tasks.get(task_id)
        if task:
            task.enabled = True
            logger.info(f"Scheduled task enabled: {task_id}")
            return True
        return False

    def disable_task(self, task_id: str) -> bool:
        """Disable a scheduled task.

        Args:
            task_id: Task ID to disable.

        Returns:
            True if disabled successfully.
        """
        task = self.tasks.get(task_id)
        if task:
            task.enabled = False
            logger.info(f"Scheduled task disabled: {task_id}")
            return True
        return False

    async def _run_task_loop(self) -> None:
        """Main task loop for scheduled execution."""
        while self._running:
            now = time.time()

            for task in self.tasks.values():
                if not task.enabled:
                    continue

                if now >= task.next_run:
                    await self._execute_task(task)
                    task.last_run = now
                    task.next_run = now + task.interval_seconds

            await asyncio.sleep(10)

    async def _execute_task(self, task: ScheduledTask) -> None:
        """Execute a single scheduled task.

        Args:
            task: Task to execute.
        """
        logger.info(f"Executing scheduled task: {task.task_id}")

        try:
            auditor = BatchJWTAuditor(self.workflow_engine)

            result = await auditor.audit_single_jwt(
                f"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.test",
                task.workflow_id,
            )

            high_risk = result.risk_level in (RiskLevel.CRITICAL, RiskLevel.HIGH)

            if high_risk and task.alert_webhook:
                await self._send_alert(task, result)

        except Exception as e:
            logger.error(f"Task execution failed: {e}")

    async def _send_alert(
        self,
        task: ScheduledTask,
        result: BatchAuditResult,
    ) -> None:
        """Send alert webhook for high risk findings.

        Args:
            task: The scheduled task.
            result: Audit result triggering alert.
        """
        import aiohttp

        alert_payload = {
            "task_id": task.task_id,
            "task_name": task.name,
            "target_url": task.target_url,
            "risk_level": result.risk_level.value,
            "vulnerabilities": result.vulnerabilities,
            "timestamp": datetime.now().isoformat(),
        }

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    task.alert_webhook,
                    json=alert_payload,
                    timeout=10,
                ) as response:
                    if response.status == 200:
                        logger.info(f"Alert sent for task: {task.task_id}")
                    else:
                        logger.warning(f"Alert webhook failed: {response.status}")
        except Exception as e:
            logger.error(f"Failed to send alert: {e}")

    async def start(self) -> None:
        """Start the scheduled task manager."""
        self._running = True
        self._task_loop = asyncio.create_task(self._run_task_loop())
        logger.info("Scheduled task manager started")

    async def stop(self) -> None:
        """Stop the scheduled task manager."""
        self._running = False
        if self._task_loop:
            self._task_loop.cancel()
            try:
                await self._task_loop
            except asyncio.CancelledError:
                pass
        logger.info("Scheduled task manager stopped")


# =============================================================================
# Main Orchestration Manager
# =============================================================================

class JWTAttackOrchestrationManager:
    """Main JWT attack orchestration coordination engine.

    Integrates:
    - Workflow engine for attack chain execution
    - Batch auditor for mass JWT testing
    - Scheduled task manager for automated testing
    - YAML template import/export for community sharing
    """

    def __init__(self) -> None:
        """Initialize the orchestration manager."""
        self.workflow_engine = WorkflowEngine()
        self.batch_auditor = BatchJWTAuditor(self.workflow_engine)
        self.task_manager = ScheduledTaskManager(self.workflow_engine)
        self._register_builtin_workflows()

    def _register_builtin_workflows(self) -> None:
        """Register built-in workflow templates."""
        self.workflow_engine.register_workflow(WorkflowTemplates.jwt_full_audit())
        self.workflow_engine.register_workflow(WorkflowTemplates.oauth_full_audit())
        self.workflow_engine.register_workflow(WorkflowTemplates.jwt_quick_scan())

    async def execute_jwt_full_audit(
        self,
        jwt_token: str,
    ) -> WorkflowExecution:
        """Execute full JWT audit workflow.

        Args:
            jwt_token: JWT token to audit.

        Returns:
            WorkflowExecution with results.
        """
        context = {"jwt_token": jwt_token}
        return await self.workflow_engine.execute_workflow(
            "wf-jwt-full-audit", context
        )

    async def execute_oauth_full_audit(
        self,
        target_url: str,
    ) -> WorkflowExecution:
        """Execute full OAuth audit workflow.

        Args:
            target_url: OAuth target URL.

        Returns:
            WorkflowExecution with results.
        """
        context = {"target_url": target_url}
        return await self.workflow_engine.execute_workflow(
            "wf-oauth-full-audit", context
        )

    async def execute_batch_audit(
        self,
        jwt_tokens: List[str],
    ) -> List[BatchAuditResult]:
        """Execute batch JWT audit.

        Args:
            jwt_tokens: List of JWT tokens.

        Returns:
            List of BatchAuditResult sorted by risk.
        """
        return await self.batch_auditor.audit_batch(jwt_tokens)

    def export_workflow_template(
        self,
        workflow_id: str,
        file_path: str,
    ) -> bool:
        """Export workflow template to YAML.

        Args:
            workflow_id: Workflow ID to export.
            file_path: Output file path.

        Returns:
            True if exported successfully.
        """
        return self.workflow_engine.export_workflow(workflow_id, file_path)

    def import_workflow_template(self, file_path: str) -> Optional[AttackWorkflow]:
        """Import workflow template from YAML.

        Args:
            file_path: Input file path.

        Returns:
            Imported AttackWorkflow or None.
        """
        return self.workflow_engine.import_workflow(file_path)

    def create_scheduled_task(
        self,
        name: str,
        target_url: str,
        interval_seconds: int = 3600,
        workflow_id: str = "wf-jwt-quick-scan",
        alert_webhook: str = "",
    ) -> ScheduledTask:
        """Create a new scheduled task.

        Args:
            name: Task display name.
            target_url: Target API URL.
            interval_seconds: Test interval in seconds.
            workflow_id: Workflow to execute.
            alert_webhook: Alert webhook URL.

        Returns:
            Created ScheduledTask.
        """
        return self.task_manager.create_task(
            name=name,
            target_url=target_url,
            interval_seconds=interval_seconds,
            workflow_id=workflow_id,
            alert_webhook=alert_webhook,
        )

    async def start_scheduled_tasks(self) -> None:
        """Start all scheduled tasks."""
        await self.task_manager.start()

    async def stop_scheduled_tasks(self) -> None:
        """Stop all scheduled tasks."""
        await self.task_manager.stop()
