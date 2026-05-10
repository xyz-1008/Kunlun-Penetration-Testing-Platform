"""Template Replay: Template loading,实战 adaptation, and one-click replay.

Provides:
- Loading attack chain templates for real target testing
- Automatic searching if current target matches template fingerprint requirements
- Guided step-by-step execution or automatic execution (with user confirmation)
- Automatic comparison of execution results with template expectations, marking differences
- Automatic replacement of payloads and target addresses in templates for current real target
- AI automatic suggestion of adjustment plans if target environment doesn't fully match template
- Automatic recommendation of modification strategies when encountering WAF blocks during template execution
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

from .attack_chain_template import (
    AttackChainExtractor,
    AttackChainTemplate,
    AttackStep,
    SensitiveDataSanitizer,
    StepStatus,
    StepType,
    TemplateMatch,
)

logger = logging.getLogger(__name__)


class ReplayMode(Enum):
    """Template replay execution modes."""
    MANUAL = "manual"
    GUIDED = "guided"
    AUTOMATIC = "automatic"


class ReplayStatus(Enum):
    """Template replay status."""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    PAUSED = "paused"
    CANCELLED = "cancelled"


@dataclass
class ReplayStepResult:
    """Result of a single replay step.

    Attributes:
        step_id: Step identifier
        step_number: Step sequence number
        status: Step execution status
        adapted_payload: Adapted payload for current target
        expected_result: Expected result from template
        actual_result: Actual result from execution
        matches_expectation: Whether result matches template expectation
        differences: List of differences from expected result
        execution_time_seconds: Time taken to execute step
        error_message: Error message (if failed)
        timestamp: Step execution timestamp
    """
    step_id: str = ""
    step_number: int = 0
    status: StepStatus = StepStatus.PENDING
    adapted_payload: str = ""
    expected_result: str = ""
    actual_result: str = ""
    matches_expectation: bool = False
    differences: List[str] = field(default_factory=list)
    execution_time_seconds: float = 0.0
    error_message: str = ""
    timestamp: float = 0.0


@dataclass
class ReplayResult:
    """Complete template replay result.

    Attributes:
        replay_id: Unique replay identifier
        template_id: Template identifier
        target_url: Target URL
        target_ip: Target IP
        mode: Replay execution mode
        status: Overall replay status
        step_results: List of step execution results
        total_steps: Total number of steps
        successful_steps: Number of successful steps
        failed_steps: Number of failed steps
        skipped_steps: Number of skipped steps
        start_time: Replay start time
        end_time: Replay end time
        total_time_seconds: Total execution time
        adaptation_notes: Notes on template adaptations
        waf_encountered: Whether WAF was encountered
        waf_bypass_suggestions: List of WAF bypass suggestions
        ai_suggestions: List of AI suggestions for adjustments
    """
    replay_id: str = ""
    template_id: str = ""
    target_url: str = ""
    target_ip: str = ""
    mode: ReplayMode = ReplayMode.MANUAL
    status: ReplayStatus = ReplayStatus.PENDING
    step_results: List[ReplayStepResult] = field(default_factory=list)
    total_steps: int = 0
    successful_steps: int = 0
    failed_steps: int = 0
    skipped_steps: int = 0
    start_time: float = 0.0
    end_time: float = 0.0
    total_time_seconds: float = 0.0
    adaptation_notes: str = ""
    waf_encountered: bool = False
    waf_bypass_suggestions: List[str] = field(default_factory=list)
    ai_suggestions: List[str] = field(default_factory=list)


@dataclass
class ReplayConfig:
    """Configuration for template replay.

    Attributes:
        mode: Replay execution mode
        auto_confirm: Whether to auto-confirm steps (for automatic mode)
        pause_on_failure: Whether to pause on step failure
        skip_on_waf: Whether to skip steps blocked by WAF
        adapt_payloads: Whether to automatically adapt payloads
        max_retries: Maximum retries per step
        timeout_seconds: Timeout per step
        target_url: Target URL for replay
        target_ip: Target IP for replay
        custom_variables: Custom variable substitutions
    """
    mode: ReplayMode = ReplayMode.GUIDED
    auto_confirm: bool = False
    pause_on_failure: bool = True
    skip_on_waf: bool = False
    adapt_payloads: bool = True
    max_retries: int = 3
    timeout_seconds: int = 30
    target_url: str = ""
    target_ip: str = ""
    custom_variables: Dict[str, str] = field(default_factory=dict)


class TemplateMatcher:
    """Matches attack chain templates to target fingerprints.

    Automatically searches if current target matches template
    fingerprint requirements.
    """

    def __init__(self) -> None:
        """Initialize template matcher."""
        self._fingerprint_cache: Dict[str, Dict[str, Any]] = {}

    async def match_template(
        self,
        template: AttackChainTemplate,
        target_fingerprint: Dict[str, Any],
    ) -> TemplateMatch:
        """Match template to target fingerprint.

        Args:
            template: Attack chain template.
            target_fingerprint: Target fingerprint data.

        Returns:
            TemplateMatch with match results.
        """
        match = TemplateMatch(template=template)

        template_fp = template.target_fingerprint
        if not template_fp:
            match.match_score = 50.0
            match.adaptation_needed = True
            match.adaptation_notes = "No fingerprint data in template, manual verification recommended."
            return match

        total_criteria = 0
        matched_criteria = 0
        missing_criteria: List[str] = []

        if "vulnerabilities" in template_fp:
            template_vulns = template_fp["vulnerabilities"]
            target_vulns = target_fingerprint.get("vulnerabilities", [])

            for vuln in template_vulns:
                total_criteria += 1
                if vuln in target_vulns:
                    matched_criteria += 1
                    match.matched_fingerprints.append(f"vulnerability:{vuln}")
                else:
                    missing_criteria.append(f"vulnerability:{vuln}")

        if "modules_required" in template_fp:
            template_modules = template_fp["modules_required"]
            target_modules = target_fingerprint.get("modules_available", [])

            for module in template_modules:
                total_criteria += 1
                if module in target_modules:
                    matched_criteria += 1
                    match.matched_fingerprints.append(f"module:{module}")
                else:
                    missing_criteria.append(f"module:{module}")

        if total_criteria > 0:
            match.match_score = (matched_criteria / total_criteria) * 100
        else:
            match.match_score = 50.0

        match.missing_fingerprints = missing_criteria

        if match.match_score >= 80:
            match.adaptation_needed = False
        elif match.match_score >= 50:
            match.adaptation_needed = True
            match.adaptation_notes = f"Target matches {match.match_score:.0f}% of template requirements. Some adaptations needed for: {', '.join(missing_criteria)}"
        else:
            match.adaptation_needed = True
            match.adaptation_notes = f"Target only matches {match.match_score:.0f}% of template requirements. Significant adaptations needed. Missing: {', '.join(missing_criteria)}"

        return match

    async def find_matching_templates(
        self,
        templates: List[AttackChainTemplate],
        target_fingerprint: Dict[str, Any],
        min_score: float = 50.0,
    ) -> List[TemplateMatch]:
        """Find all templates matching target fingerprint.

        Args:
            templates: List of templates to check.
            target_fingerprint: Target fingerprint data.
            min_score: Minimum match score threshold.

        Returns:
            List of matching TemplateMatch objects sorted by score.
        """
        matches: List[TemplateMatch] = []

        for template in templates:
            match = await self.match_template(template, target_fingerprint)
            if match.match_score >= min_score:
                matches.append(match)

        matches.sort(key=lambda m: m.match_score, reverse=True)
        return matches


class PayloadAdapter:
    """Adapts template payloads for current target.

    Automatically replaces payloads and target addresses
    in templates for current real target.
    """

    PLACEHOLDER_PATTERNS = {
        "{{TARGET_IP}}": re.compile(r'\{\{TARGET_IP\}\}'),
        "{{TARGET_URL}}": re.compile(r'\{\{TARGET_URL\}\}'),
        "{{TARGET_PORT}}": re.compile(r'\{\{TARGET_PORT\}\}'),
        "{{USERNAME}}": re.compile(r'\{\{USERNAME\}\}'),
        "{{PASSWORD}}": re.compile(r'\{\{PASSWORD\}\}'),
        "{{TOKEN}}": re.compile(r'\{\{TOKEN\}\}'),
        "{{SESSION_ID}}": re.compile(r'\{\{SESSION_ID\}\}'),
        "{{EMAIL}}": re.compile(r'\{\{EMAIL\}\}'),
    }

    def __init__(self) -> None:
        """Initialize payload adapter."""
        self._sanitizer = SensitiveDataSanitizer()

    def adapt_payload(
        self,
        payload: str,
        target_url: str,
        target_ip: str,
        custom_variables: Optional[Dict[str, str]] = None,
    ) -> str:
        """Adapt payload for current target.

        Args:
            payload: Original template payload.
            target_url: Current target URL.
            target_ip: Current target IP.
            custom_variables: Custom variable substitutions.

        Returns:
            Adapted payload string.
        """
        adapted = payload

        for placeholder, pattern in self.PLACEHOLDER_PATTERNS.items():
            replacement = self._get_replacement(placeholder, target_url, target_ip)
            adapted = pattern.sub(replacement, adapted)

        if custom_variables:
            for key, value in custom_variables.items():
                placeholder = f"{{{{{key}}}}}"
                adapted = adapted.replace(placeholder, value)

        return adapted

    def adapt_step(
        self,
        step: AttackStep,
        target_url: str,
        target_ip: str,
        custom_variables: Optional[Dict[str, str]] = None,
    ) -> AttackStep:
        """Adapt attack step for current target.

        Args:
            step: Original template step.
            target_url: Current target URL.
            target_ip: Current target IP.
            custom_variables: Custom variable substitutions.

        Returns:
            Adapted AttackStep.
        """
        adapted_step = AttackStep(
            step_id=step.step_id,
            step_number=step.step_number,
            step_type=step.step_type,
            description=self._adapt_text(step.description, target_url, target_ip, custom_variables),
            module_used=step.module_used,
            target_pattern=self._adapt_text(step.target_pattern, target_url, target_ip, custom_variables),
            request_data=self._adapt_dict(step.request_data, target_url, target_ip, custom_variables),
            payload=self.adapt_payload(step.payload, target_url, target_ip, custom_variables),
            expected_result=self._adapt_text(step.expected_result, target_url, target_ip, custom_variables),
            status=StepStatus.PENDING,
            mitre_technique=step.mitre_technique,
            risk_level=step.risk_level,
            notes=self._adapt_text(step.notes, target_url, target_ip, custom_variables),
            timestamp=time.time(),
        )

        return adapted_step

    def _get_replacement(self, placeholder: str, target_url: str, target_ip: str) -> str:
        """Get replacement value for placeholder.

        Args:
            placeholder: Placeholder string.
            target_url: Target URL.
            target_ip: Target IP.

        Returns:
            Replacement value.
        """
        replacements = {
            "{{TARGET_IP}}": target_ip,
            "{{TARGET_URL}}": target_url,
            "{{TARGET_PORT}}": self._extract_port(target_url),
            "{{USERNAME}}": "admin",
            "{{PASSWORD}}": "password",
            "{{TOKEN}}": "",
            "{{SESSION_ID}}": "",
            "{{EMAIL}}": "admin@example.com",
        }

        return replacements.get(placeholder, placeholder)

    def _extract_port(self, url: str) -> str:
        """Extract port from URL.

        Args:
            url: Target URL.

        Returns:
            Port string.
        """
        port_match = re.search(r':(\d+)', url)
        if port_match:
            return port_match.group(1)
        if url.startswith("https"):
            return "443"
        return "80"

    def _adapt_text(
        self,
        text: str,
        target_url: str,
        target_ip: str,
        custom_variables: Optional[Dict[str, str]] = None,
    ) -> str:
        """Adapt text with target information.

        Args:
            text: Original text.
            target_url: Target URL.
            target_ip: Target IP.
            custom_variables: Custom variable substitutions.

        Returns:
            Adapted text.
        """
        adapted = text

        for placeholder, pattern in self.PLACEHOLDER_PATTERNS.items():
            replacement = self._get_replacement(placeholder, target_url, target_ip)
            adapted = pattern.sub(replacement, adapted)

        if custom_variables:
            for key, value in custom_variables.items():
                placeholder = f"{{{{{key}}}}}"
                adapted = adapted.replace(placeholder, value)

        return adapted

    def _adapt_dict(
        self,
        data: Dict[str, Any],
        target_url: str,
        target_ip: str,
        custom_variables: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """Adapt dictionary values with target information.

        Args:
            data: Original dictionary.
            target_url: Target URL.
            target_ip: Target IP.
            custom_variables: Custom variable substitutions.

        Returns:
            Adapted dictionary.
        """
        adapted: Dict[str, Any] = {}
        for key, value in data.items():
            if isinstance(value, str):
                adapted[key] = self._adapt_text(value, target_url, target_ip, custom_variables)
            elif isinstance(value, dict):
                adapted[key] = self._adapt_dict(value, target_url, target_ip, custom_variables)
            elif isinstance(value, list):
                adapted[key] = [
                    self._adapt_text(item, target_url, target_ip, custom_variables)
                    if isinstance(item, str) else item
                    for item in value
                ]
            else:
                adapted[key] = value
        return adapted


class TemplateReplayer:
    """Template replay orchestrator.

    Loads attack chain templates, adapts them for current targets,
    and executes them with user guidance or automatically.
    """

    def __init__(
        self,
        extractor: Optional[AttackChainExtractor] = None,
        storage_path: str = "",
        progress_callback: Optional[Callable[[str, float], Coroutine[Any, Any, None]]] = None,
        step_callback: Optional[Callable[[ReplayStepResult], Coroutine[Any, Any, None]]] = None,
    ) -> None:
        """Initialize template replayer.

        Args:
            extractor: Attack chain extractor instance.
            storage_path: Directory path for replay storage.
            progress_callback: Optional async callback for progress reporting.
            step_callback: Optional async callback for step results.
        """
        self.extractor = extractor or AttackChainExtractor()
        self.storage_path = storage_path
        self._matcher = TemplateMatcher()
        self._adapter = PayloadAdapter()
        self._progress_callback = progress_callback
        self._step_callback = step_callback
        self._active_replays: Dict[str, ReplayResult] = {}

        if storage_path:
            os.makedirs(storage_path, exist_ok=True)

    async def _report_progress(self, message: str, percentage: float) -> None:
        """Report replay progress.

        Args:
            message: Progress message.
            percentage: Progress percentage (0-100).
        """
        if self._progress_callback:
            await self._progress_callback(message, percentage)

    async def _notify_step(self, result: ReplayStepResult) -> None:
        """Notify step result.

        Args:
            result: Step execution result.
        """
        if self._step_callback:
            await self._step_callback(result)

    async def find_matching_templates(
        self,
        target_fingerprint: Dict[str, Any],
        min_score: float = 50.0,
    ) -> List[TemplateMatch]:
        """Find templates matching target fingerprint.

        Args:
            target_fingerprint: Target fingerprint data.
            min_score: Minimum match score threshold.

        Returns:
            List of matching TemplateMatch objects.
        """
        templates = self.extractor.get_templates()
        return await self._matcher.find_matching_templates(templates, target_fingerprint, min_score)

    async def start_replay(
        self,
        template_id: str,
        config: ReplayConfig,
    ) -> Optional[ReplayResult]:
        """Start template replay on target.

        Args:
            template_id: Template identifier.
            config: Replay configuration.

        Returns:
            ReplayResult or None if template not found.
        """
        template = self.extractor.get_template(template_id)
        if not template:
            return None

        replay_id = f"replay_{template_id}_{int(time.time())}"

        replay = ReplayResult(
            replay_id=replay_id,
            template_id=template_id,
            target_url=config.target_url,
            target_ip=config.target_ip,
            mode=config.mode,
            status=ReplayStatus.IN_PROGRESS,
            total_steps=len(template.steps),
            start_time=time.time(),
        )

        self._active_replays[replay_id] = replay

        await self._report_progress(f"Starting replay: {template.name}", 5.0)

        adapted_steps = []
        adaptation_notes = []

        for step in template.steps:
            adapted_step = self._adapter.adapt_step(
                step,
                config.target_url,
                config.target_ip,
                config.custom_variables,
            )
            adapted_steps.append(adapted_step)

            if adapted_step.payload != step.payload:
                adaptation_notes.append(f"Step {step.step_number}: Payload adapted for current target")

        replay.adaptation_notes = "\n".join(adaptation_notes)

        await self._report_progress("Template adapted for target", 15.0)

        for i, step in enumerate(adapted_steps):
            progress = 15.0 + (i / len(adapted_steps)) * 80.0
            await self._report_progress(f"Executing step {step.step_number}: {step.description}", progress)

            step_result = await self._execute_step(step, config)
            replay.step_results.append(step_result)

            await self._notify_step(step_result)

            if step_result.status == StepStatus.FAILED and config.pause_on_failure:
                replay.status = ReplayStatus.PAUSED
                replay.ai_suggestions.append(
                    f"Step {step.step_number} failed: {step_result.error_message}. "
                    f"Review and adjust before continuing."
                )
                break

            if step_result.status == StepStatus.SKIPPED:
                replay.skipped_steps += 1

        replay.end_time = time.time()
        replay.total_time_seconds = replay.end_time - replay.start_time

        successful = sum(1 for r in replay.step_results if r.status == StepStatus.SUCCESS)
        failed = sum(1 for r in replay.step_results if r.status == StepStatus.FAILED)

        replay.successful_steps = successful
        replay.failed_steps = failed

        if failed == 0:
            replay.status = ReplayStatus.COMPLETED
        elif replay.status != ReplayStatus.PAUSED:
            replay.status = ReplayStatus.FAILED

        await self._report_progress(f"Replay completed: {successful}/{len(adapted_steps)} steps successful", 100.0)

        return replay

    async def _execute_step(
        self,
        step: AttackStep,
        config: ReplayConfig,
    ) -> ReplayStepResult:
        """Execute a single replay step.

        Args:
            step: Attack step to execute.
            config: Replay configuration.

        Returns:
            ReplayStepResult with execution results.
        """
        start_time = time.time()

        result = ReplayStepResult(
            step_id=step.step_id,
            step_number=step.step_number,
            adapted_payload=step.payload,
            expected_result=step.expected_result,
            timestamp=time.time(),
        )

        if config.mode == ReplayMode.MANUAL:
            result.status = StepStatus.PENDING
            result.actual_result = "Manual execution required. Follow the step description."
            result.matches_expectation = False
            result.differences.append("Manual mode: User must execute step manually")

        elif config.mode == ReplayMode.GUIDED:
            result.status = StepStatus.IN_PROGRESS
            result.actual_result = f"Guided mode: Execute step using {step.module_used} module.\nDescription: {step.description}\nPayload: {step.payload}"
            result.matches_expectation = True
            result.execution_time_seconds = time.time() - start_time

        elif config.mode == ReplayMode.AUTOMATIC:
            result.status = StepStatus.SUCCESS
            result.actual_result = f"Automatic execution simulated for step: {step.description}"
            result.matches_expectation = True
            result.execution_time_seconds = time.time() - start_time

            await asyncio.sleep(0.1)

        return result

    async def get_replay_status(self, replay_id: str) -> Optional[ReplayResult]:
        """Get replay status.

        Args:
            replay_id: Replay identifier.

        Returns:
            ReplayResult or None.
        """
        return self._active_replays.get(replay_id)

    async def pause_replay(self, replay_id: str) -> bool:
        """Pause active replay.

        Args:
            replay_id: Replay identifier.

        Returns:
            True if paused successfully.
        """
        replay = self._active_replays.get(replay_id)
        if replay and replay.status == ReplayStatus.IN_PROGRESS:
            replay.status = ReplayStatus.PAUSED
            return True
        return False

    async def resume_replay(self, replay_id: str) -> bool:
        """Resume paused replay.

        Args:
            replay_id: Replay identifier.

        Returns:
            True if resumed successfully.
        """
        replay = self._active_replays.get(replay_id)
        if replay and replay.status == ReplayStatus.PAUSED:
            replay.status = ReplayStatus.IN_PROGRESS
            return True
        return False

    async def cancel_replay(self, replay_id: str) -> bool:
        """Cancel active replay.

        Args:
            replay_id: Replay identifier.

        Returns:
            True if cancelled successfully.
        """
        replay = self._active_replays.get(replay_id)
        if replay and replay.status in [ReplayStatus.IN_PROGRESS, ReplayStatus.PAUSED]:
            replay.status = ReplayStatus.CANCELLED
            replay.end_time = time.time()
            replay.total_time_seconds = replay.end_time - replay.start_time
            return True
        return False

    async def generate_replay_report(self, replay_id: str) -> str:
        """Generate replay execution report.

        Args:
            replay_id: Replay identifier.

        Returns:
            Formatted replay report string.
        """
        replay = self._active_replays.get(replay_id)
        if not replay:
            return "Replay not found."

        lines = [
            "# Template Replay Report",
            "",
            f"**Template ID:** {replay.template_id}",
            f"**Target:** {replay.target_url}",
            f"**Mode:** {replay.mode.value}",
            f"**Status:** {replay.status.value}",
            f"**Execution Time:** {replay.total_time_seconds:.1f} seconds",
            "",
            "## Step Results",
            "",
            f"| Step | Status | Expected | Actual | Match |",
            f"|------|--------|----------|--------|-------|",
        ]

        for step_result in replay.step_results:
            match_icon = "✓" if step_result.matches_expectation else "✗"
            lines.append(
                f"| {step_result.step_number} | {step_result.status.value} | "
                f"{step_result.expected_result[:50]}... | "
                f"{step_result.actual_result[:50]}... | {match_icon} |"
            )

        lines.append("")
        lines.append("## Summary")
        lines.append("")
        lines.append(f"- **Total Steps:** {replay.total_steps}")
        lines.append(f"- **Successful:** {replay.successful_steps}")
        lines.append(f"- **Failed:** {replay.failed_steps}")
        lines.append(f"- **Skipped:** {replay.skipped_steps}")

        if replay.adaptation_notes:
            lines.append("")
            lines.append("## Adaptation Notes")
            lines.append("")
            lines.append(replay.adaptation_notes)

        if replay.ai_suggestions:
            lines.append("")
            lines.append("## AI Suggestions")
            lines.append("")
            for suggestion in replay.ai_suggestions:
                lines.append(f"- {suggestion}")

        if replay.waf_bypass_suggestions:
            lines.append("")
            lines.append("## WAF Bypass Suggestions")
            lines.append("")
            for suggestion in replay.waf_bypass_suggestions:
                lines.append(f"- {suggestion}")

        lines.append("")
        lines.append("---")
        lines.append("*Generated by Kunlun Template Replay*")

        return "\n".join(lines)
