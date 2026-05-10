"""Range Integration: Integration with proxy, Fuzzer, PoC engine, and AI copilot.

Provides:
- Integration between range environments and Kunlun's proxy module for traffic capture
- Integration with Fuzzer module for automated vulnerability testing in ranges
- Integration with PoC engine for exploit verification in range environments
- Integration with AI copilot for progressive hints and real-time guidance
- Seamless switching between range practice and real target testing
- Attack chain template application from range to real targets
"""

import asyncio
import json
import logging
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum, auto
from typing import Any, Callable, Coroutine, Dict, List, Optional, Set, Tuple

from .attack_chain_template import (
    AttackChainExtractor,
    AttackChainTemplate,
    AttackStep,
    StepStatus,
    StepType,
)
from .learning_path import (
    HintLevel,
    LearningPathManager,
    TaskCategory,
    TaskDefinition,
    TaskProgress,
    TaskStatus,
)
from .range_deployer import DeploymentResult, DeploymentStatus, RangeDeployer
from .range_manager import (
    ContainerStatus,
    DifficultyLevel,
    DockerConfig,
    DockerManager,
    RangeInstance,
    RangeLibrary,
    RangeMetadata,
    VulnerabilityType,
)
from .skill_evaluator import AssessmentType, SkillEvaluator
from .template_replay import (
    ReplayConfig,
    ReplayMode,
    ReplayResult,
    ReplayStatus,
    TemplateMatcher,
    TemplateReplayer,
)

logger = logging.getLogger(__name__)


class IntegrationMode(Enum):
    """Integration operation modes."""
    RANGE_PRACTICE = "range_practice"
    REAL_TARGET = "real_target"
    HYBRID = "hybrid"


@dataclass
class IntegrationConfig:
    """Configuration for range integration.

    Attributes:
        mode: Integration operation mode
        auto_start_proxy: Whether to auto-start proxy for range
        auto_configure_fuzzer: Whether to auto-configure fuzzer scope
        enable_ai_copilot: Whether to enable AI copilot integration
        ai_hint_level: AI hint detail level
        record_attack_chains: Whether to record attack chains
        auto_extract_templates: Whether to auto-extract templates on success
        enable_skill_evaluation: Whether to enable skill evaluation
        user_id: User identifier for progress tracking
        storage_path: Storage path for all range data
    """
    mode: IntegrationMode = IntegrationMode.RANGE_PRACTICE
    auto_start_proxy: bool = True
    auto_configure_fuzzer: bool = True
    enable_ai_copilot: bool = True
    ai_hint_level: HintLevel = HintLevel.VAGUE
    record_attack_chains: bool = True
    auto_extract_templates: bool = True
    enable_skill_evaluation: bool = True
    user_id: str = "default"
    storage_path: str = ""


@dataclass
class ProxyIntegrationState:
    """Proxy integration state for range.

    Attributes:
        proxy_enabled: Whether proxy is enabled
        intercept_scope: URL scope for interception
        captured_requests: Number of captured requests
        interesting_requests: List of interesting request summaries
        ssl_interception: Whether SSL interception is enabled
    """
    proxy_enabled: bool = False
    intercept_scope: str = ""
    captured_requests: int = 0
    interesting_requests: List[str] = field(default_factory=list)
    ssl_interception: bool = False


@dataclass
class FuzzerIntegrationState:
    """Fuzzer integration state for range.

    Attributes:
        fuzzer_enabled: Whether fuzzer is enabled
        target_scope: Fuzzer target scope
        payload_sets: List of payload sets configured
        tests_run: Number of tests run
        vulnerabilities_found: Number of vulnerabilities found
    """
    fuzzer_enabled: bool = False
    target_scope: str = ""
    payload_sets: List[str] = field(default_factory=list)
    tests_run: int = 0
    vulnerabilities_found: int = 0


@dataclass
class PoCIntegrationState:
    """PoC engine integration state for range.

    Attributes:
        poc_engine_enabled: Whether PoC engine is enabled
        loaded_pocs: Number of PoCs loaded for target
        pocs_executed: Number of PoCs executed
        pocs_successful: Number of successful PoCs
        vulnerabilities_confirmed: List of confirmed vulnerabilities
    """
    poc_engine_enabled: bool = False
    loaded_pocs: int = 0
    pocs_executed: int = 0
    pocs_successful: int = 0
    vulnerabilities_confirmed: List[str] = field(default_factory=list)


@dataclass
class AICopilotState:
    """AI copilot integration state.

    Attributes:
        copilot_enabled: Whether AI copilot is enabled
        current_hint_level: Current hint detail level
        hints_provided: Number of hints provided
        suggestions_made: List of AI suggestions
        questions_answered: Number of user questions answered
    """
    copilot_enabled: bool = False
    current_hint_level: HintLevel = HintLevel.VAGUE
    hints_provided: int = 0
    suggestions_made: List[str] = field(default_factory=list)
    questions_answered: int = 0


class RangeIntegration:
    """Main integration orchestrator for range environments.

    Integrates range environments with Kunlun's proxy, Fuzzer,
    PoC engine, and AI copilot modules for seamless practice
    and real target testing.
    """

    def __init__(
        self,
        config: Optional[IntegrationConfig] = None,
        deployer: Optional[RangeDeployer] = None,
        learning_path_manager: Optional[LearningPathManager] = None,
        skill_evaluator: Optional[SkillEvaluator] = None,
        chain_extractor: Optional[AttackChainExtractor] = None,
        template_replayer: Optional[TemplateReplayer] = None,
    ) -> None:
        """Initialize range integration.

        Args:
            config: Integration configuration. Uses defaults if None.
            deployer: Range deployer instance. Creates new if None.
            learning_path_manager: Learning path manager. Creates new if None.
            skill_evaluator: Skill evaluator instance. Creates new if None.
            chain_extractor: Attack chain extractor. Creates new if None.
            template_replayer: Template replayer instance. Creates new if None.
        """
        self.config = config or IntegrationConfig()
        self.deployer = deployer or RangeDeployer()
        self.learning_path_manager = learning_path_manager or LearningPathManager(
            storage_path=self.config.storage_path,
        )
        self.skill_evaluator = skill_evaluator or SkillEvaluator(
            learning_path_manager=self.learning_path_manager,
            storage_path=self.config.storage_path,
        )
        self.chain_extractor = chain_extractor or AttackChainExtractor(
            storage_path=self.config.storage_path,
        )
        self.template_replayer = template_replayer or TemplateReplayer(
            extractor=self.chain_extractor,
            storage_path=self.config.storage_path,
        )

        self._proxy_state = ProxyIntegrationState()
        self._fuzzer_state = FuzzerIntegrationState()
        self._poc_state = PoCIntegrationState()
        self._ai_state = AICopilotState()

        self._active_session: Optional[str] = None
        self._current_instance: Optional[RangeInstance] = None

    async def start_range_session(
        self,
        range_id: str,
        user_id: Optional[str] = None,
    ) -> Optional[DeploymentResult]:
        """Start a range practice session.

        Args:
            range_id: Range identifier to deploy.
            user_id: Optional user identifier override.

        Returns:
            DeploymentResult or None if failed.
        """
        if user_id:
            self.config.user_id = user_id

        result = await self.deployer.deploy_range(
            range_id=range_id,
            configure_proxy=self.config.auto_start_proxy,
        )

        if result.status == DeploymentStatus.COMPLETED and result.instance:
            self._current_instance = result.instance
            self._active_session = f"session_{range_id}_{int(time.time())}"

            await self._configure_proxy(result.instance)
            await self._configure_fuzzer(result.instance)
            await self._configure_poc_engine(result.instance)
            await self._configure_ai_copilot()

            if self.config.record_attack_chains:
                self.chain_extractor.start_recording(
                    session_id=self._active_session,
                    target_url=result.access_url,
                    range_id=range_id,
                )

        return result

    async def end_range_session(
        self,
        extract_template: bool = True,
        evaluate_skills: bool = True,
    ) -> Dict[str, Any]:
        """End range practice session.

        Args:
            extract_template: Whether to extract attack chain template.
            evaluate_skills: Whether to evaluate skills.

        Returns:
            Dictionary with session summary.
        """
        summary: Dict[str, Any] = {
            "session_id": self._active_session,
            "range_id": self._current_instance.range_id if self._current_instance else "",
            "duration_seconds": 0.0,
            "template_extracted": False,
            "skills_evaluated": False,
        }

        if self._active_session and self.config.record_attack_chains:
            record = self.chain_extractor.complete_recording(
                record_id=self._active_session,
                success=True,
            )

            if record and extract_template and self.config.auto_extract_templates:
                template = self.chain_extractor.extract_template(
                    record_id=self._active_session,
                    author=self.config.user_id,
                )
                summary["template_extracted"] = template is not None
                if template:
                    summary["template_id"] = template.template_id

        if evaluate_skills and self.config.enable_skill_evaluation:
            assessment = await self.skill_evaluator.evaluate_skills(
                self.config.user_id,
                AssessmentType.COMPREHENSIVE,
            )
            summary["skills_evaluated"] = True
            summary["overall_score"] = assessment.overall_score
            summary["skill_level"] = assessment.overall_level.value

        if self._current_instance:
            await self.deployer.destroy_range(self._current_instance.instance_id)

        self._active_session = None
        self._current_instance = None

        self._reset_integration_states()

        return summary

    async def _configure_proxy(self, instance: RangeInstance) -> None:
        """Configure proxy for range instance.

        Args:
            instance: Range instance to configure.
        """
        if not self.config.auto_start_proxy:
            return

        self._proxy_state.proxy_enabled = True
        self._proxy_state.intercept_scope = instance.access_url
        self._proxy_state.ssl_interception = True

    async def _configure_fuzzer(self, instance: RangeInstance) -> None:
        """Configure Fuzzer for range instance.

        Args:
            instance: Range instance to configure.
        """
        if not self.config.auto_configure_fuzzer:
            return

        range_meta = self.deployer.range_library.get_range(instance.range_id)
        if not range_meta:
            return

        self._fuzzer_state.fuzzer_enabled = True
        self._fuzzer_state.target_scope = instance.access_url

        payload_sets = []
        for vuln_type in range_meta.vulnerability_types:
            payload_sets.append(vuln_type.value)

        self._fuzzer_state.payload_sets = payload_sets

    async def _configure_poc_engine(self, instance: RangeInstance) -> None:
        """Configure PoC engine for range instance.

        Args:
            instance: Range instance to configure.
        """
        range_meta = self.deployer.range_library.get_range(instance.range_id)
        if not range_meta:
            return

        self._poc_state.poc_engine_enabled = True
        self._poc_state.loaded_pocs = len(range_meta.vulnerability_types)

    async def _configure_ai_copilot(self) -> None:
        """Configure AI copilot for range session."""
        if not self.config.enable_ai_copilot:
            return

        self._ai_state.copilot_enabled = True
        self._ai_state.current_hint_level = self.config.ai_hint_level

    def _reset_integration_states(self) -> None:
        """Reset all integration states."""
        self._proxy_state = ProxyIntegrationState()
        self._fuzzer_state = FuzzerIntegrationState()
        self._poc_state = PoCIntegrationState()
        self._ai_state = AICopilotState()

    async def record_attack_step(
        self,
        step_type: StepType,
        description: str,
        module_used: str,
        payload: str = "",
        expected_result: str = "",
        actual_result: str = "",
        status: StepStatus = StepStatus.SUCCESS,
        mitre_technique: str = "",
    ) -> Optional[AttackStep]:
        """Record an attack step during range session.

        Args:
            step_type: Type of attack step.
            description: Step description.
            module_used: Kunlun module used.
            payload: Key payload used.
            expected_result: Expected outcome.
            actual_result: Actual outcome.
            status: Step execution status.
            mitre_technique: MITRE ATT&CK technique ID.

        Returns:
            Created AttackStep or None.
        """
        if not self._active_session:
            return None

        return self.chain_extractor.add_step(
            record_id=self._active_session,
            step_type=step_type,
            description=description,
            module_used=module_used,
            payload=payload,
            expected_result=expected_result,
            actual_result=actual_result,
            status=status,
            mitre_technique=mitre_technique,
        )

    async def get_ai_hint(
        self,
        task_id: str,
        hint_level: Optional[HintLevel] = None,
    ) -> Optional[str]:
        """Get AI copilot hint for current task.

        Args:
            task_id: Task identifier.
            hint_level: Optional hint level override.

        Returns:
            Hint content or None.
        """
        if not self._ai_state.copilot_enabled:
            return None

        level = hint_level or self._ai_state.current_hint_level

        hint = self.learning_path_manager.get_hint(
            self.config.user_id,
            task_id,
            level,
        )

        if hint:
            self._ai_state.hints_provided += 1
            return hint.content

        return None

    async def get_ai_suggestion(self, context: str) -> str:
        """Get AI copilot suggestion based on context.

        Args:
            context: Current context description.

        Returns:
            AI suggestion string.
        """
        if not self._ai_state.copilot_enabled:
            return "AI copilot is not enabled for this session."

        suggestions = {
            "sql_injection": "Try using Kunlun's SQL injection module with the target URL. Start with basic payloads like ' OR '1'='1 and observe the response.",
            "xss": "Use Kunlun's Fuzzer module to test for XSS vulnerabilities. Try payloads like <script>alert(1)</script> in input fields.",
            "file_upload": "Try uploading a simple PHP file through the upload functionality. Use Kunlun's proxy to intercept and modify the upload request.",
            "auth_bypass": "Check if the login form is vulnerable to SQL injection. Try common bypass payloads in the username field.",
            "idor": "Look for numeric IDs in API requests. Use Kunlun's Repeater to modify these IDs and check if you can access other users' data.",
            "default": "Continue exploring the target. Use Kunlun's proxy to intercept all traffic and look for interesting endpoints or parameters.",
        }

        context_lower = context.lower()
        for key, suggestion in suggestions.items():
            if key in context_lower:
                self._ai_state.suggestions_made.append(suggestion)
                return suggestion

        self._ai_state.suggestions_made.append(suggestions["default"])
        return suggestions["default"]

    async def answer_question(self, question: str) -> str:
        """Answer user question during range practice.

        Args:
            question: User question.

        Returns:
            Answer string.
        """
        self._ai_state.questions_answered += 1

        question_lower = question.lower()

        if "what is" in question_lower or "what does" in question_lower:
            return "That's a great question! Let me explain the concept and show you how to test for it using Kunlun's modules."

        if "how do" in question_lower or "how to" in question_lower:
            return "Here's how you can approach this: First, use Kunlun's proxy to intercept the relevant request. Then, use the appropriate module to test for vulnerabilities."

        if "why" in question_lower:
            return "The reason this works is because the application doesn't properly validate or sanitize user input. This is a common security oversight."

        if "next" in question_lower or "what now" in question_lower:
            return "Based on your progress, I recommend moving to the next task in your learning path. You've mastered the current concept and are ready for the next challenge."

        return "That's an interesting question. Let me provide some guidance based on best practices for penetration testing."

    async def switch_to_real_target(
        self,
        target_url: str,
        target_ip: str = "",
        template_id: Optional[str] = None,
    ) -> Optional[ReplayResult]:
        """Switch from range practice to real target testing.

        Args:
            target_url: Real target URL.
            target_ip: Real target IP.
            template_id: Optional template to apply.

        Returns:
            ReplayResult or None.
        """
        if not template_id:
            return None

        config = ReplayConfig(
            mode=ReplayMode.GUIDED,
            target_url=target_url,
            target_ip=target_ip,
            adapt_payloads=True,
        )

        return await self.template_replayer.start_replay(template_id, config)

    async def find_templates_for_target(
        self,
        target_fingerprint: Dict[str, Any],
        min_score: float = 50.0,
    ) -> List[Dict[str, Any]]:
        """Find attack chain templates suitable for target.

        Args:
            target_fingerprint: Target fingerprint data.
            min_score: Minimum match score threshold.

        Returns:
            List of matching template summaries.
        """
        matches = await self.template_replayer.find_matching_templates(
            target_fingerprint,
            min_score,
        )

        result = []
        for match in matches:
            result.append({
                "template_id": match.template.template_id,
                "template_name": match.template.name,
                "match_score": match.match_score,
                "adaptation_needed": match.adaptation_needed,
                "adaptation_notes": match.adaptation_notes,
                "steps_count": len(match.template.steps),
                "difficulty": match.template.difficulty,
                "estimated_time_minutes": match.template.estimated_time_minutes,
            })

        return result

    async def get_session_status(self) -> Dict[str, Any]:
        """Get current session status.

        Returns:
            Dictionary with session status.
        """
        return {
            "active_session": self._active_session,
            "current_range": self._current_instance.range_id if self._current_instance else "",
            "access_url": self._current_instance.access_url if self._current_instance else "",
            "proxy_enabled": self._proxy_state.proxy_enabled,
            "fuzzer_enabled": self._fuzzer_state.fuzzer_enabled,
            "poc_engine_enabled": self._poc_state.poc_engine_enabled,
            "ai_copilot_enabled": self._ai_state.copilot_enabled,
            "user_id": self.config.user_id,
        }

    async def get_integration_states(self) -> Dict[str, Any]:
        """Get all integration module states.

        Returns:
            Dictionary with all integration states.
        """
        return {
            "proxy": {
                "enabled": self._proxy_state.proxy_enabled,
                "intercept_scope": self._proxy_state.intercept_scope,
                "captured_requests": self._proxy_state.captured_requests,
                "ssl_interception": self._proxy_state.ssl_interception,
            },
            "fuzzer": {
                "enabled": self._fuzzer_state.fuzzer_enabled,
                "target_scope": self._fuzzer_state.target_scope,
                "payload_sets": self._fuzzer_state.payload_sets,
                "tests_run": self._fuzzer_state.tests_run,
                "vulnerabilities_found": self._fuzzer_state.vulnerabilities_found,
            },
            "poc_engine": {
                "enabled": self._poc_state.poc_engine_enabled,
                "loaded_pocs": self._poc_state.loaded_pocs,
                "pocs_executed": self._poc_state.pocs_executed,
                "pocs_successful": self._poc_state.pocs_successful,
                "vulnerabilities_confirmed": self._poc_state.vulnerabilities_confirmed,
            },
            "ai_copilot": {
                "enabled": self._ai_state.copilot_enabled,
                "hint_level": self._ai_state.current_hint_level.value,
                "hints_provided": self._ai_state.hints_provided,
                "questions_answered": self._ai_state.questions_answered,
            },
        }
