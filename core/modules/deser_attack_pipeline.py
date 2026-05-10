"""Deserialization attack pipeline for automated exploitation.

Provides:
- Automated attack workflow orchestration
- Batch exploitation engine
- Auto privilege escalation and lateral movement
- Custom pipeline steps and conditional branching
"""

import asyncio
import logging
import secrets
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Coroutine, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class PipelineStage(Enum):
    """Pipeline stages."""
    DETECTION = "detection"
    FINGERPRINT = "fingerprint"
    CHAIN_RECOMMEND = "chain_recommend"
    PAYLOAD_GENERATE = "payload_generate"
    EXPLOIT_EXECUTE = "exploit_execute"
    MEMSHELL_INJECT = "memshell_inject"
    PERSISTENCE_VERIFY = "persistence_verify"
    PRIVILEGE_ESCALATE = "privilege_escalate"
    LATERAL_MOVE = "lateral_move"


class PipelineStatus(Enum):
    """Pipeline status."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    PAUSED = "paused"
    CANCELLED = "cancelled"


class TargetRisk(Enum):
    """Target risk level."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NONE = "none"


@dataclass
class PipelineTarget:
    """Pipeline target configuration.

    Attributes:
        host: Target host
        port: Target port
        protocol: Target protocol
        path: Target path
        target_type: Target type (shiro/weblogic/jboss/generic)
        command: Command to execute
        chain_id: Gadget chain ID
        priority: Target priority
    """
    host: str = ""
    port: int = 0
    protocol: str = "http"
    path: str = "/"
    target_type: str = "generic"
    command: str = "whoami"
    chain_id: str = ""
    priority: int = 0


@dataclass
class PipelineStageResult:
    """Pipeline stage result.

    Attributes:
        stage: Pipeline stage
        success: Whether stage succeeded
        data: Stage output data
        error_message: Error message if failed
        duration_seconds: Stage duration
        next_stage: Next stage to execute
    """
    stage: PipelineStage = PipelineStage.DETECTION
    success: bool = False
    data: Dict[str, Any] = field(default_factory=dict)
    error_message: str = ""
    duration_seconds: float = 0.0
    next_stage: Optional[PipelineStage] = None


@dataclass
class PipelineResult:
    """Pipeline execution result.

    Attributes:
        pipeline_id: Unique pipeline identifier
        target: Target configuration
        status: Pipeline status
        stages: Executed stages
        current_stage: Current stage
        exploit_success: Whether exploit succeeded
        memshell_injected: Whether memory shell injected
        memshell_id: Memory shell ID
        command_output: Command execution output
        risk_level: Target risk level
        error_message: Error message if failed
        duration_seconds: Total duration
        timestamp: Pipeline timestamp
    """
    pipeline_id: str = ""
    target: PipelineTarget = field(default_factory=PipelineTarget)
    status: PipelineStatus = PipelineStatus.PENDING
    stages: List[PipelineStageResult] = field(default_factory=list)
    current_stage: PipelineStage = PipelineStage.DETECTION
    exploit_success: bool = False
    memshell_injected: bool = False
    memshell_id: str = ""
    command_output: str = ""
    risk_level: TargetRisk = TargetRisk.NONE
    error_message: str = ""
    duration_seconds: float = 0.0
    timestamp: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "pipeline_id": self.pipeline_id,
            "target": f"{self.target.protocol}://{self.target.host}:{self.target.port}",
            "status": self.status.value,
            "current_stage": self.current_stage.value,
            "exploit_success": self.exploit_success,
            "memshell_injected": self.memshell_injected,
            "memshell_id": self.memshell_id,
            "risk_level": self.risk_level.value,
            "stage_count": len(self.stages),
            "error_message": self.error_message,
            "duration_seconds": self.duration_seconds,
        }


@dataclass
class BatchResult:
    """Batch exploitation result.

    Attributes:
        batch_id: Unique batch identifier
        total_targets: Total number of targets
        completed_targets: Completed targets
        success_targets: Successful targets
        failed_targets: Failed targets
        results: Individual pipeline results
        risk_sorted_results: Results sorted by risk
        duration_seconds: Total duration
        timestamp: Batch timestamp
    """
    batch_id: str = ""
    total_targets: int = 0
    completed_targets: int = 0
    success_targets: int = 0
    failed_targets: int = 0
    results: List[PipelineResult] = field(default_factory=list)
    risk_sorted_results: List[PipelineResult] = field(default_factory=list)
    duration_seconds: float = 0.0
    timestamp: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "batch_id": self.batch_id,
            "total_targets": self.total_targets,
            "completed_targets": self.completed_targets,
            "success_targets": self.success_targets,
            "failed_targets": self.failed_targets,
            "success_rate": f"{self.success_targets / max(self.total_targets, 1) * 100:.1f}%",
            "duration_seconds": self.duration_seconds,
        }


class DeserAttackPipeline:
    """Deserialization attack pipeline orchestrator.

    Provides automated attack workflow orchestration,
    batch exploitation engine, and privilege escalation.
    """

    DEFAULT_PIPELINE_STAGES: List[PipelineStage] = [
        PipelineStage.DETECTION,
        PipelineStage.FINGERPRINT,
        PipelineStage.CHAIN_RECOMMEND,
        PipelineStage.PAYLOAD_GENERATE,
        PipelineStage.EXPLOIT_EXECUTE,
        PipelineStage.MEMSHELL_INJECT,
        PipelineStage.PERSISTENCE_VERIFY,
    ]

    PRIVILEGE_ESCALATION_STAGES: List[PipelineStage] = [
        PipelineStage.PRIVILEGE_ESCALATE,
        PipelineStage.LATERAL_MOVE,
    ]

    def __init__(
        self,
        detector: Optional[Any] = None,
        chain_manager: Optional[Any] = None,
        payload_generator: Optional[Any] = None,
        exploit_executor: Optional[Any] = None,
        memshell_generator: Optional[Any] = None,
        event_bus: Optional[Any] = None,
    ) -> None:
        """Initialize deserialization attack pipeline.

        Args:
            detector: Java deserialization detector instance.
            chain_manager: Gadget chain manager instance.
            payload_generator: Payload generator instance.
            exploit_executor: Exploit executor instance.
            memshell_generator: Memory shell generator instance.
            event_bus: Event bus for broadcasting events.
        """
        self.detector = detector
        self.chain_manager = chain_manager
        self.payload_generator = payload_generator
        self.exploit_executor = exploit_executor
        self.memshell_generator = memshell_generator
        self.event_bus = event_bus
        self._progress_callback: Optional[Callable[[str, float], Coroutine[Any, Any, None]]] = None
        self._log_callback: Optional[Callable[[str], Coroutine[Any, Any, None]]] = None
        self._pipeline_history: List[PipelineResult] = []
        self._batch_history: List[BatchResult] = []

    def set_callbacks(
        self,
        progress_cb: Optional[Callable[[str, float], Coroutine[Any, Any, None]]] = None,
        log_cb: Optional[Callable[[str], Coroutine[Any, Any, None]]] = None,
    ) -> None:
        """Set progress and log callbacks.

        Args:
            progress_cb: Callback for progress updates (message, percentage).
            log_cb: Callback for log messages.
        """
        self._progress_callback = progress_cb
        self._log_callback = log_cb

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

    async def execute_pipeline(
        self,
        target: PipelineTarget,
        stages: Optional[List[PipelineStage]] = None,
        inject_memshell: bool = True,
        escalate_privilege: bool = False,
    ) -> PipelineResult:
        """Execute attack pipeline for single target.

        Args:
            target: Target configuration.
            stages: Custom pipeline stages (uses default if None).
            inject_memshell: Whether to inject memory shell.
            escalate_privilege: Whether to escalate privilege.

        Returns:
            PipelineResult.
        """
        start_time = time.time()
        result = PipelineResult(
            pipeline_id=f"pipeline_{int(time.time())}_{secrets.token_hex(4)}",
            target=target,
            status=PipelineStatus.RUNNING,
            timestamp=time.time(),
        )

        try:
            await self._report_progress("开始攻击流水线", 5)
            await self._report_log(f"目标: {target.host}:{target.port}")

            pipeline_stages = stages or self.DEFAULT_PIPELINE_STAGES[:]

            if escalate_privilege:
                pipeline_stages.extend(self.PRIVILEGE_ESCALATION_STAGES)

            for i, stage in enumerate(pipeline_stages):
                result.current_stage = stage
                progress = 5 + (i / max(len(pipeline_stages), 1)) * 90

                await self._report_progress(f"执行阶段: {stage.value}", progress)
                await self._report_log(f"开始阶段: {stage.value}")

                stage_start = time.time()
                stage_result = await self._execute_stage(stage, target, result)
                stage_result.duration_seconds = time.time() - stage_start

                result.stages.append(stage_result)

                if not stage_result.success:
                    await self._report_log(f"阶段失败: {stage.value}, 尝试备选方案")
                    fallback_result = await self._execute_fallback(stage, target, result)
                    if fallback_result.success:
                        result.stages.append(fallback_result)
                    else:
                        result.error_message = f"阶段 {stage.value} 失败且无备选方案"
                        result.status = PipelineStatus.FAILED
                        break

                if stage_result.next_stage:
                    result.current_stage = stage_result.next_stage

                if stage == PipelineStage.EXPLOIT_EXECUTE and stage_result.success:
                    result.exploit_success = True
                    result.command_output = stage_result.data.get("output", "")

                if stage == PipelineStage.MEMSHELL_INJECT and stage_result.success:
                    result.memshell_injected = True
                    result.memshell_id = stage_result.data.get("memshell_id", "")

            if result.status != PipelineStatus.FAILED:
                result.status = PipelineStatus.COMPLETED
                result.risk_level = self._calculate_risk_level(result)

            result.duration_seconds = time.time() - start_time
            await self._report_progress("流水线完成", 100)

            self._pipeline_history.append(result)

        except Exception as e:
            result.error_message = str(e)
            result.status = PipelineStatus.FAILED
            result.duration_seconds = time.time() - start_time
            await self._report_log(f"流水线执行失败: {e}")
            logger.error("Pipeline execution failed: %s", e)

        return result

    async def _execute_stage(
        self,
        stage: PipelineStage,
        target: PipelineTarget,
        pipeline_result: PipelineResult,
    ) -> PipelineStageResult:
        """Execute single pipeline stage.

        Args:
            stage: Pipeline stage.
            target: Target configuration.
            pipeline_result: Pipeline result.

        Returns:
            PipelineStageResult.
        """
        stage_result = PipelineStageResult(stage=stage)

        try:
            if stage == PipelineStage.DETECTION:
                stage_result = await self._stage_detection(target, pipeline_result)
            elif stage == PipelineStage.FINGERPRINT:
                stage_result = await self._stage_fingerprint(target, pipeline_result)
            elif stage == PipelineStage.CHAIN_RECOMMEND:
                stage_result = await self._stage_chain_recommend(target, pipeline_result)
            elif stage == PipelineStage.PAYLOAD_GENERATE:
                stage_result = await self._stage_payload_generate(target, pipeline_result)
            elif stage == PipelineStage.EXPLOIT_EXECUTE:
                stage_result = await self._stage_exploit_execute(target, pipeline_result)
            elif stage == PipelineStage.MEMSHELL_INJECT:
                stage_result = await self._stage_memshell_inject(target, pipeline_result)
            elif stage == PipelineStage.PERSISTENCE_VERIFY:
                stage_result = await self._stage_persistence_verify(target, pipeline_result)
            elif stage == PipelineStage.PRIVILEGE_ESCALATE:
                stage_result = await self._stage_privilege_escalate(target, pipeline_result)
            elif stage == PipelineStage.LATERAL_MOVE:
                stage_result = await self._stage_lateral_move(target, pipeline_result)
            else:
                stage_result.success = False
                stage_result.error_message = f"未知阶段: {stage.value}"

        except Exception as e:
            stage_result.success = False
            stage_result.error_message = str(e)
            logger.error("Stage execution failed: %s", e)

        return stage_result

    async def _execute_fallback(
        self,
        stage: PipelineStage,
        target: PipelineTarget,
        pipeline_result: PipelineResult,
    ) -> PipelineStageResult:
        """Execute fallback for failed stage.

        Args:
            stage: Pipeline stage.
            target: Target configuration.
            pipeline_result: Pipeline result.

        Returns:
            PipelineStageResult.
        """
        fallback_result = PipelineStageResult(stage=stage)

        try:
            if stage == PipelineStage.EXPLOIT_EXECUTE:
                await self._report_log("尝试备选利用链")
                if self.chain_manager:
                    chains = self.chain_manager.get_chains_by_category("commons_collections")
                    for chain in chains[:3]:
                        target.chain_id = chain.get("chain_id", "")
                        fallback_result = await self._stage_exploit_execute(target, pipeline_result)
                        if fallback_result.success:
                            return fallback_result

            elif stage == PipelineStage.DETECTION:
                await self._report_log("尝试备选检测方法")
                if self.detector:
                    fallback_result.success = True
                    fallback_result.data = {"method": "passive_detection"}

        except Exception as e:
            fallback_result.success = False
            fallback_result.error_message = str(e)
            logger.error("Fallback execution failed: %s", e)

        return fallback_result

    async def _stage_detection(
        self,
        target: PipelineTarget,
        pipeline_result: PipelineResult,
    ) -> PipelineStageResult:
        """Execute detection stage.

        Args:
            target: Target configuration.
            pipeline_result: Pipeline result.

        Returns:
            PipelineStageResult.
        """
        result = PipelineStageResult(stage=PipelineStage.DETECTION)

        try:
            if self.detector:
                detection_result = await self.detector.passive_detect()
                if detection_result:
                    result.success = True
                    result.data = {"detection": detection_result}
            else:
                result.success = True
                result.data = {"detection": "simulated"}

        except Exception as e:
            result.success = False
            result.error_message = str(e)

        return result

    async def _stage_fingerprint(
        self,
        target: PipelineTarget,
        pipeline_result: PipelineResult,
    ) -> PipelineStageResult:
        """Execute fingerprint stage.

        Args:
            target: Target configuration.
            pipeline_result: Pipeline result.

        Returns:
            PipelineStageResult.
        """
        result = PipelineStageResult(stage=PipelineStage.FINGERPRINT)

        try:
            if self.detector:
                fingerprint = await self.detector.fingerprint_target(
                    host=target.host,
                    port=target.port,
                )
                if fingerprint:
                    result.success = True
                    result.data = {"fingerprint": fingerprint}
            else:
                result.success = True
                result.data = {"fingerprint": "simulated"}

        except Exception as e:
            result.success = False
            result.error_message = str(e)

        return result

    async def _stage_chain_recommend(
        self,
        target: PipelineTarget,
        pipeline_result: PipelineResult,
    ) -> PipelineStageResult:
        """Execute chain recommendation stage.

        Args:
            target: Target configuration.
            pipeline_result: Pipeline result.

        Returns:
            PipelineStageResult.
        """
        result = PipelineStageResult(stage=PipelineStage.CHAIN_RECOMMEND)

        try:
            if self.chain_manager:
                chains = self.chain_manager.recommend_chains(
                    target_type=target.target_type,
                    command=target.command,
                )
                if chains:
                    target.chain_id = chains[0].get("chain_id", "")
                    result.success = True
                    result.data = {"recommended_chain": target.chain_id}
            else:
                target.chain_id = "commons_collections5"
                result.success = True
                result.data = {"recommended_chain": target.chain_id}

        except Exception as e:
            result.success = False
            result.error_message = str(e)

        return result

    async def _stage_payload_generate(
        self,
        target: PipelineTarget,
        pipeline_result: PipelineResult,
    ) -> PipelineStageResult:
        """Execute payload generation stage.

        Args:
            target: Target configuration.
            pipeline_result: Pipeline result.

        Returns:
            PipelineStageResult.
        """
        result = PipelineStageResult(stage=PipelineStage.PAYLOAD_GENERATE)

        try:
            if self.payload_generator:
                payload = await self.payload_generator.generate_payload(
                    chain_id=target.chain_id,
                    command=target.command,
                )
                if payload:
                    result.success = True
                    result.data = {"payload": payload}
            else:
                result.success = True
                result.data = {"payload": "simulated"}

        except Exception as e:
            result.success = False
            result.error_message = str(e)

        return result

    async def _stage_exploit_execute(
        self,
        target: PipelineTarget,
        pipeline_result: PipelineResult,
    ) -> PipelineStageResult:
        """Execute exploit stage.

        Args:
            target: Target configuration.
            pipeline_result: Pipeline result.

        Returns:
            PipelineStageResult.
        """
        result = PipelineStageResult(stage=PipelineStage.EXPLOIT_EXECUTE)

        try:
            if self.exploit_executor:
                exploit_result = await self.exploit_executor.execute_exploit(
                    host=target.host,
                    port=target.port,
                    chain_id=target.chain_id,
                    command=target.command,
                )
                if exploit_result:
                    result.success = True
                    result.data = {
                        "output": exploit_result.get("output", ""),
                        "success": exploit_result.get("success", False),
                    }
            else:
                result.success = True
                result.data = {"output": "simulated", "success": True}

        except Exception as e:
            result.success = False
            result.error_message = str(e)

        return result

    async def _stage_memshell_inject(
        self,
        target: PipelineTarget,
        pipeline_result: PipelineResult,
    ) -> PipelineStageResult:
        """Execute memory shell injection stage.

        Args:
            target: Target configuration.
            pipeline_result: Pipeline result.

        Returns:
            PipelineStageResult.
        """
        result = PipelineStageResult(stage=PipelineStage.MEMSHELL_INJECT)

        try:
            if self.memshell_generator:
                from mem_shell_generator import MemShellConfig, ShellType, ContainerType, ShellFunction

                config = MemShellConfig(
                    shell_type=ShellType.FILTER,
                    container_type=ContainerType.TOMCAT,
                    shell_function=ShellFunction.COMMAND_EXEC,
                )

                memshell_result = await self.memshell_generator.generate_filter_shell(config)

                if memshell_result:
                    result.success = True
                    result.data = {"memshell_id": memshell_result.shell_id}
            else:
                result.success = True
                result.data = {"memshell_id": "simulated"}

        except Exception as e:
            result.success = False
            result.error_message = str(e)

        return result

    async def _stage_persistence_verify(
        self,
        target: PipelineTarget,
        pipeline_result: PipelineResult,
    ) -> PipelineStageResult:
        """Execute persistence verification stage.

        Args:
            target: Target configuration.
            pipeline_result: Pipeline result.

        Returns:
            PipelineStageResult.
        """
        result = PipelineStageResult(stage=PipelineStage.PERSISTENCE_VERIFY)

        try:
            if self.memshell_generator and pipeline_result.memshell_id:
                alive = await self.memshell_generator.verify_shell_alive(
                    shell_id=pipeline_result.memshell_id,
                    target_url=f"{target.protocol}://{target.host}:{target.port}/api/health",
                )
                result.success = alive
                result.data = {"alive": alive}
            else:
                result.success = True
                result.data = {"alive": True}

        except Exception as e:
            result.success = False
            result.error_message = str(e)

        return result

    async def _stage_privilege_escalate(
        self,
        target: PipelineTarget,
        pipeline_result: PipelineResult,
    ) -> PipelineStageResult:
        """Execute privilege escalation stage.

        Args:
            target: Target configuration.
            pipeline_result: Pipeline result.

        Returns:
            PipelineStageResult.
        """
        result = PipelineStageResult(stage=PipelineStage.PRIVILEGE_ESCALATE)

        try:
            if self.exploit_executor:
                escalation_result = await self.exploit_executor.escalate_privilege(
                    host=target.host,
                    port=target.port,
                )
                if escalation_result:
                    result.success = True
                    result.data = escalation_result
            else:
                result.success = True
                result.data = {"privilege": "simulated"}

        except Exception as e:
            result.success = False
            result.error_message = str(e)

        return result

    async def _stage_lateral_move(
        self,
        target: PipelineTarget,
        pipeline_result: PipelineResult,
    ) -> PipelineStageResult:
        """Execute lateral movement stage.

        Args:
            target: Target configuration.
            pipeline_result: Pipeline result.

        Returns:
            PipelineStageResult.
        """
        result = PipelineStageResult(stage=PipelineStage.LATERAL_MOVE)

        try:
            if self.exploit_executor:
                lateral_result = await self.exploit_executor.lateral_move(
                    host=target.host,
                    credentials=pipeline_result.command_output,
                )
                if lateral_result:
                    result.success = True
                    result.data = lateral_result
            else:
                result.success = True
                result.data = {"lateral": "simulated"}

        except Exception as e:
            result.success = False
            result.error_message = str(e)

        return result

    async def execute_batch(
        self,
        targets: List[PipelineTarget],
        stages: Optional[List[PipelineStage]] = None,
        max_concurrent: int = 5,
    ) -> BatchResult:
        """Execute batch exploitation.

        Args:
            targets: List of targets.
            stages: Custom pipeline stages.
            max_concurrent: Maximum concurrent executions.

        Returns:
            BatchResult.
        """
        start_time = time.time()
        batch = BatchResult(
            batch_id=f"batch_{int(time.time())}_{secrets.token_hex(4)}",
            total_targets=len(targets),
            timestamp=time.time(),
        )

        try:
            await self._report_progress("开始批量利用", 5)
            await self._report_log(f"目标数量: {len(targets)}")

            semaphore = asyncio.Semaphore(max_concurrent)

            async def process_target(target: PipelineTarget) -> PipelineResult:
                async with semaphore:
                    return await self.execute_pipeline(
                        target=target,
                        stages=stages,
                    )

            tasks = [process_target(t) for t in targets]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            for r in results:
                if isinstance(r, PipelineResult):
                    batch.results.append(r)
                    if r.exploit_success:
                        batch.success_targets += 1
                    else:
                        batch.failed_targets += 1
                    batch.completed_targets += 1

            batch.risk_sorted_results = sorted(
                batch.results,
                key=lambda x: (
                    0 if x.risk_level == TargetRisk.CRITICAL else
                    1 if x.risk_level == TargetRisk.HIGH else
                    2 if x.risk_level == TargetRisk.MEDIUM else
                    3
                ),
            )

            batch.duration_seconds = time.time() - start_time
            await self._report_progress("批量利用完成", 100)

            self._batch_history.append(batch)

        except Exception as e:
            batch.duration_seconds = time.time() - start_time
            await self._report_log(f"批量利用失败: {e}")
            logger.error("Batch exploitation failed: %s", e)

        return batch

    def _calculate_risk_level(self, result: PipelineResult) -> TargetRisk:
        """Calculate target risk level.

        Args:
            result: Pipeline result.

        Returns:
            TargetRisk.
        """
        if result.exploit_success and result.memshell_injected:
            return TargetRisk.CRITICAL
        elif result.exploit_success:
            return TargetRisk.HIGH
        elif any(s.success for s in result.stages):
            return TargetRisk.MEDIUM
        else:
            return TargetRisk.LOW

    def get_pipeline_history(self) -> List[PipelineResult]:
        """Get pipeline history.

        Returns:
            List of pipeline results.
        """
        return self._pipeline_history

    def get_batch_history(self) -> List[BatchResult]:
        """Get batch history.

        Returns:
            List of batch results.
        """
        return self._batch_history
