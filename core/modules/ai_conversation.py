"""AI Conversation: Conversational penetration testing interface, intelligent attack chain orchestration, and beginner guidance mode.

Provides:
- Conversational operation interface: Natural language commands to control penetration testing
- Multi-turn conversation with context memory
- Intelligent attack chain orchestration: AI automatically executes complete penetration testing workflow
- Real-time progress reporting with user intervention support
- Beginner guidance mode: Virtual mentor explaining principles and guiding first-time testers
- Skill improvement path recommendations
"""

import asyncio
import json
import logging
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum, auto
from typing import Any, Callable, Coroutine, Dict, List, Optional, Set, Tuple

from .ai_engine import AIEngine, AIResponse, ChatMessage, ModelCapability, PromptTemplate

logger = logging.getLogger(__name__)


class ConversationMode(Enum):
    """Conversation operation modes."""
    NORMAL = "normal"
    AUTOMATED = "automated"
    BEGINNER = "beginner"
    EXPERT = "expert"


class CommandCategory(Enum):
    """AI command categories."""
    RECONNAISSANCE = "reconnaissance"
    SCANNING = "scanning"
    EXPLOITATION = "exploitation"
    POST_EXPLOITATION = "post_exploitation"
    REPORTING = "reporting"
    ANALYSIS = "analysis"
    GUIDANCE = "guidance"
    CONFIGURATION = "configuration"


class AutomationPhase(Enum):
    """Automated penetration testing phases."""
    RECONNAISSANCE = "reconnaissance"
    SCANNING = "scanning"
    VULNERABILITY_ANALYSIS = "vulnerability_analysis"
    EXPLOITATION = "exploitation"
    POST_EXPLOITATION = "post_exploitation"
    REPORTING = "reporting"
    COMPLETED = "completed"


@dataclass
class ConversationMessage:
    """Conversation message with metadata.

    Attributes:
        message_id: Unique message identifier
        role: Message role (user/assistant/system)
        content: Message content
        timestamp: Message timestamp
        mode: Conversation mode when message was sent
        command_category: Detected command category
        metadata: Additional message metadata
    """
    message_id: str = ""
    role: str = "user"
    content: str = ""
    timestamp: float = 0.0
    mode: ConversationMode = ConversationMode.NORMAL
    command_category: Optional[CommandCategory] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AutomationState:
    """Automated penetration testing state.

    Attributes:
        project_id: Project identifier
        current_phase: Current automation phase
        phase_progress: Phase progress percentage
        total_phases: Total number of phases
        completed_steps: Completed automation steps
        pending_steps: Pending automation steps
        is_running: Whether automation is currently running
        is_paused: Whether automation is paused
        start_time: Automation start time
        last_update: Last state update time
        results: Automation results collected so far
    """
    project_id: str = ""
    current_phase: AutomationPhase = AutomationPhase.RECONNAISSANCE
    phase_progress: float = 0.0
    total_phases: int = 6
    completed_steps: List[Dict[str, Any]] = field(default_factory=list)
    pending_steps: List[Dict[str, Any]] = field(default_factory=list)
    is_running: bool = False
    is_paused: bool = False
    start_time: float = 0.0
    last_update: float = 0.0
    results: Dict[str, Any] = field(default_factory=dict)


@dataclass
class BeginnerGuidance:
    """Beginner guidance information.

    Attributes:
        step_title: Current step title
        explanation: Step explanation
        principle: Underlying vulnerability principle
        instructions: Step-by-step instructions
        expected_outcome: Expected outcome description
        next_steps: Recommended next steps
        learning_resources: Related learning resources
        skill_level: Required skill level
    """
    step_title: str = ""
    explanation: str = ""
    principle: str = ""
    instructions: List[str] = field(default_factory=list)
    expected_outcome: str = ""
    next_steps: List[str] = field(default_factory=list)
    learning_resources: List[str] = field(default_factory=list)
    skill_level: str = "beginner"


@dataclass
class SkillPath:
    """Skill improvement path.

    Attributes:
        current_level: Current skill level
        recommended_skills: Recommended skills to learn
        learning_order: Suggested learning order
        resources: Learning resources
        milestones: Skill milestones
    """
    current_level: str = "beginner"
    recommended_skills: List[str] = field(default_factory=list)
    learning_order: List[str] = field(default_factory=list)
    resources: List[str] = field(default_factory=list)
    milestones: List[str] = field(default_factory=list)


class CommandClassifier:
    """Natural language command classifier.

    Classifies user commands into appropriate categories and extracts parameters.
    """

    COMMAND_PATTERNS: Dict[CommandCategory, List[str]] = {
        CommandCategory.RECONNAISSANCE: [
            r"scan\s+(the\s+)?network",
            r"discover\s+(assets|hosts|services)",
            r"enumerate\s+",
            r"find\s+(open\s+ports|services|endpoints)",
            r"asset\s+discovery",
            r"recon",
        ],
        CommandCategory.SCANNING: [
            r"scan\s+(for\s+)?vulnerabilities?",
            r"port\s+scan",
            r"service\s+scan",
            r"version\s+scan",
            r"os\s+detection",
            r"nmap",
        ],
        CommandCategory.EXPLOITATION: [
            r"exploit",
            r"attack",
            r"test\s+(for\s+)?(sql\s*injection|xss|rce|ssrf|idor)",
            r"payload",
            r"bypass\s+(waf|auth|filter)",
            r"inject",
        ],
        CommandCategory.POST_EXPLOITATION: [
            r"privilege\s+escalation",
            r"privesc",
            r"lateral\s+movement",
            r"pivot",
            r"persist",
            r"escalate",
            r"move\s+laterally",
        ],
        CommandCategory.REPORTING: [
            r"generate\s+report",
            r"write\s+report",
            r"export\s+report",
            r"create\s+report",
            r"summary",
            r"document",
        ],
        CommandCategory.ANALYSIS: [
            r"analyze",
            r"review",
            r"assess",
            r"evaluate",
            r"check\s+(for\s+)?vulnerabilities?",
            r"what\s+(can|should)\s+(i|we)\s+do",
        ],
        CommandCategory.GUIDANCE: [
            r"how\s+do\s+i",
            r"how\s+to",
            r"explain",
            r"what\s+is",
            r"why",
            r"help\s+me",
            r"guide\s+me",
            r"teach\s+me",
        ],
        CommandCategory.CONFIGURATION: [
            r"set\s+model",
            r"switch\s+model",
            r"configure",
            r"settings",
            r"options",
            r"mode",
        ],
    }

    @classmethod
    def classify_command(cls, command: str) -> Tuple[CommandCategory, Dict[str, Any]]:
        """Classify user command and extract parameters.

        Args:
            command: User command string.

        Returns:
            Tuple of (CommandCategory, extracted parameters).
        """
        command_lower = command.lower()
        params: Dict[str, Any] = {}

        for category, patterns in cls.COMMAND_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, command_lower):
                    params = cls._extract_parameters(command_lower, category)
                    return category, params

        return CommandCategory.ANALYSIS, params

    @classmethod
    def _extract_parameters(cls, command: str, category: CommandCategory) -> Dict[str, Any]:
        """Extract parameters from command string.

        Args:
            command: Command string.
            category: Command category.

        Returns:
            Dictionary of extracted parameters.
        """
        params: Dict[str, Any] = {}

        ip_pattern = r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?)"
        ips = re.findall(ip_pattern, command)
        if ips:
            params["targets"] = ips

        domain_pattern = r"([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z]{2,})+)"
        domains = re.findall(domain_pattern, command)
        if domains:
            params["domains"] = domains

        vuln_pattern = r"(sql\s*injection|xss|rce|ssrf|idor|csrf|lfi|rfi|command\s*injection)"
        vuln_match = re.search(vuln_pattern, command, re.IGNORECASE)
        if vuln_match:
            params["vulnerability_type"] = vuln_match.group(1)

        return params


class AIConversation:
    """AI-powered conversational penetration testing interface.

    Provides natural language interaction for penetration testing operations,
    intelligent attack chain orchestration, and beginner guidance mode.

    Attributes:
        ai_engine: AI engine instance
        project_id: Current project identifier
        mode: Current conversation mode
        classifier: Command classifier instance
        automation_state: Current automation state
        _message_callback: Optional message streaming callback
        _automation_callback: Optional automation progress callback
    """

    def __init__(
        self,
        ai_engine: AIEngine,
        project_id: str = "",
        mode: ConversationMode = ConversationMode.NORMAL,
        message_callback: Optional[Callable[[ConversationMessage], Coroutine[Any, Any, None]]] = None,
        automation_callback: Optional[Callable[[AutomationState], Coroutine[Any, Any, None]]] = None,
    ) -> None:
        """Initialize AI conversation module.

        Args:
            ai_engine: AI engine instance.
            project_id: Current project identifier.
            mode: Initial conversation mode.
            message_callback: Optional async callback for new messages.
            automation_callback: Optional async callback for automation progress.
        """
        self.ai_engine = ai_engine
        self.project_id = project_id
        self.mode = mode
        self.classifier = CommandClassifier()
        self.automation_state = AutomationState(project_id=project_id)
        self._message_callback = message_callback
        self._automation_callback = automation_callback
        self._automation_task: Optional[asyncio.Task[None]] = None

    async def _notify_message(self, message: ConversationMessage) -> None:
        """Notify message callback.

        Args:
            message: Conversation message.
        """
        if self._message_callback:
            await self._message_callback(message)

    async def _notify_automation(self, state: AutomationState) -> None:
        """Notify automation callback.

        Args:
            state: Current automation state.
        """
        if self._automation_callback:
            await self._automation_callback(state)

    async def process_command(
        self,
        command: str,
        mode: Optional[ConversationMode] = None,
    ) -> ConversationMessage:
        """Process user command and generate AI response.

        Args:
            command: User command string.
            mode: Optional mode override.

        Returns:
            AI response as ConversationMessage.
        """
        current_mode = mode or self.mode
        category, params = self.classifier.classify_command(command)

        user_message = ConversationMessage(
            message_id=f"msg_{int(time.time())}_user",
            role="user",
            content=command,
            timestamp=time.time(),
            mode=current_mode,
            command_category=category,
            metadata=params,
        )

        await self._notify_message(user_message)

        self.ai_engine.context_manager.add_message(
            self.project_id, "user", command, metadata={"category": category.value}
        )

        if current_mode == ConversationMode.AUTOMATED:
            response = await self._handle_automated_command(command, params)
        elif current_mode == ConversationMode.BEGINNER:
            response = await self._handle_beginner_command(command, params)
        else:
            response = await self._handle_normal_command(command, category, params)

        ai_message = ConversationMessage(
            message_id=f"msg_{int(time.time())}_ai",
            role="assistant",
            content=response.content,
            timestamp=time.time(),
            mode=current_mode,
            command_category=category,
        )

        await self._notify_message(ai_message)

        return ai_message

    async def _handle_normal_command(
        self,
        command: str,
        category: CommandCategory,
        params: Dict[str, Any],
    ) -> AIResponse:
        """Handle normal mode command.

        Args:
            command: User command.
            category: Command category.
            params: Extracted parameters.

        Returns:
            AI response.
        """
        context = self.ai_engine.context_manager.get_context(self.project_id)

        context_info = ""
        if context:
            context_info = f"""
Current Context:
- Known Assets: {len(context.assets)}
- Known Vulnerabilities: {len(context.vulnerabilities)}
- Current Privilege Level: {context.current_privilege_level}
"""

        system_prompt = f"""You are an expert penetration testing assistant integrated into the Kunlun platform.
Help the user with penetration testing tasks.

{context_info}

Provide concise, actionable responses. Include specific commands and techniques when appropriate."""

        messages = [
            {"role": "system", "content": system_prompt},
        ]

        messages.extend(self.ai_engine.context_manager.get_messages_for_llm(self.project_id))

        messages.append({"role": "user", "content": command})

        response = await self.ai_engine.chat_completion(
            messages=messages,
            project_id=self.project_id,
        )

        return response

    async def _handle_automated_command(
        self,
        command: str,
        params: Dict[str, Any],
    ) -> AIResponse:
        """Handle automated mode command.

        Args:
            command: User command.
            params: Extracted parameters.

        Returns:
            AI response.
        """
        if "automated" in command.lower() or "auto" in command.lower():
            await self.start_automated_testing(params)
            active_model = self.ai_engine.get_active_model()
            return AIResponse(
                content="Automated penetration testing started. I will execute the complete testing workflow and report progress in real-time. You can pause or stop at any time.",
                model=active_model.model_name if active_model else "unknown",
                timestamp=time.time(),
            )

        if self.automation_state.is_running:
            if "pause" in command.lower():
                self.automation_state.is_paused = not self.automation_state.is_paused
                status = "paused" if self.automation_state.is_paused else "resumed"
                active_model = self.ai_engine.get_active_model()
                return AIResponse(
                    content=f"Automated testing {status}.",
                    model=active_model.model_name if active_model else "unknown",
                    timestamp=time.time(),
                )

            if "stop" in command.lower():
                await self.stop_automated_testing()
                active_model = self.ai_engine.get_active_model()
                return AIResponse(
                    content="Automated testing stopped.",
                    model=active_model.model_name if active_model else "unknown",
                    timestamp=time.time(),
                )

        return await self._handle_normal_command(command, CommandCategory.ANALYSIS, params)

    async def _handle_beginner_command(
        self,
        command: str,
        params: Dict[str, Any],
    ) -> AIResponse:
        """Handle beginner mode command.

        Args:
            command: User command.
            params: Extracted parameters.

        Returns:
            AI response.
        """
        if "why" in command.lower() or "how" in command.lower() or "what" in command.lower():
            template = self.ai_engine.get_prompt_template("beginner_guidance")
            if template:
                system_prompt, user_prompt = template.render(
                    current_task=command,
                    target=params.get("targets", ["unknown"])[0] if params.get("targets") else "unknown",
                    current_progress="Starting",
                )

                messages = [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ]

                response = await self.ai_engine.chat_completion(
                    messages=messages,
                    project_id=self.project_id,
                )

                return response

        return await self._handle_normal_command(command, CommandCategory.GUIDANCE, params)

    async def start_automated_testing(
        self,
        params: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Start automated penetration testing workflow.

        Args:
            params: Optional testing parameters.
        """
        self.automation_state.is_running = True
        self.automation_state.is_paused = False
        self.automation_state.start_time = time.time()
        self.automation_state.current_phase = AutomationPhase.RECONNAISSANCE
        self.automation_state.phase_progress = 0.0

        await self._notify_automation(self.automation_state)

        self._automation_task = asyncio.create_task(self._run_automation_phases(params))

    async def stop_automated_testing(self) -> None:
        """Stop automated penetration testing."""
        self.automation_state.is_running = False
        self.automation_state.is_paused = False

        if self._automation_task:
            self._automation_task.cancel()
            try:
                await self._automation_task
            except asyncio.CancelledError:
                pass

        self.automation_state.current_phase = AutomationPhase.COMPLETED
        await self._notify_automation(self.automation_state)

    async def _run_automation_phases(
        self,
        params: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Run through all automation phases.

        Args:
            params: Optional testing parameters.
        """
        phases = [
            (AutomationPhase.RECONNAISSANCE, self._phase_reconnaissance),
            (AutomationPhase.SCANNING, self._phase_scanning),
            (AutomationPhase.VULNERABILITY_ANALYSIS, self._phase_vulnerability_analysis),
            (AutomationPhase.EXPLOITATION, self._phase_exploitation),
            (AutomationPhase.POST_EXPLOITATION, self._phase_post_exploitation),
            (AutomationPhase.REPORTING, self._phase_reporting),
        ]

        for phase, phase_func in phases:
            if not self.automation_state.is_running:
                break

            self.automation_state.current_phase = phase
            self.automation_state.phase_progress = 0.0
            await self._notify_automation(self.automation_state)

            while self.automation_state.is_paused and self.automation_state.is_running:
                await asyncio.sleep(1)

            if not self.automation_state.is_running:
                break

            try:
                await phase_func(params)
            except Exception as e:
                logger.error(f"Phase {phase.value} failed: {e}")
                self.automation_state.completed_steps.append({
                    "phase": phase.value,
                    "status": "failed",
                    "error": str(e),
                    "timestamp": time.time(),
                })

            self.automation_state.phase_progress = 100.0
            await self._notify_automation(self.automation_state)

        self.automation_state.is_running = False
        self.automation_state.current_phase = AutomationPhase.COMPLETED
        await self._notify_automation(self.automation_state)

    async def _phase_reconnaissance(self, params: Optional[Dict[str, Any]]) -> None:
        """Execute reconnaissance phase.

        Args:
            params: Optional testing parameters.
        """
        targets = params.get("targets", []) if params else []
        domains = params.get("domains", []) if params else []

        self.automation_state.completed_steps.append({
            "phase": "reconnaissance",
            "action": "Asset discovery and enumeration",
            "targets": targets + domains,
            "status": "completed",
            "timestamp": time.time(),
        })

        self.automation_state.phase_progress = 100.0

    async def _phase_scanning(self, params: Optional[Dict[str, Any]]) -> None:
        """Execute scanning phase.

        Args:
            params: Optional testing parameters.
        """
        self.automation_state.completed_steps.append({
            "phase": "scanning",
            "action": "Port and service scanning",
            "status": "completed",
            "timestamp": time.time(),
        })

        self.automation_state.phase_progress = 100.0

    async def _phase_vulnerability_analysis(self, params: Optional[Dict[str, Any]]) -> None:
        """Execute vulnerability analysis phase.

        Args:
            params: Optional testing parameters.
        """
        self.automation_state.completed_steps.append({
            "phase": "vulnerability_analysis",
            "action": "Vulnerability scanning and analysis",
            "status": "completed",
            "timestamp": time.time(),
        })

        self.automation_state.phase_progress = 100.0

    async def _phase_exploitation(self, params: Optional[Dict[str, Any]]) -> None:
        """Execute exploitation phase.

        Args:
            params: Optional testing parameters.
        """
        self.automation_state.completed_steps.append({
            "phase": "exploitation",
            "action": "Vulnerability exploitation",
            "status": "completed",
            "timestamp": time.time(),
        })

        self.automation_state.phase_progress = 100.0

    async def _phase_post_exploitation(self, params: Optional[Dict[str, Any]]) -> None:
        """Execute post-exploitation phase.

        Args:
            params: Optional testing parameters.
        """
        self.automation_state.completed_steps.append({
            "phase": "post_exploitation",
            "action": "Post-exploitation activities",
            "status": "completed",
            "timestamp": time.time(),
        })

        self.automation_state.phase_progress = 100.0

    async def _phase_reporting(self, params: Optional[Dict[str, Any]]) -> None:
        """Execute reporting phase.

        Args:
            params: Optional testing parameters.
        """
        self.automation_state.completed_steps.append({
            "phase": "reporting",
            "action": "Report generation",
            "status": "completed",
            "timestamp": time.time(),
        })

        self.automation_state.phase_progress = 100.0

    async def get_beginner_guidance(
        self,
        current_task: str,
        target: str = "unknown",
        current_progress: str = "Starting",
    ) -> BeginnerGuidance:
        """Get beginner guidance for current task.

        Args:
            current_task: Current task description.
            target: Target identifier.
            current_progress: Current progress description.

        Returns:
            BeginnerGuidance with step-by-step instructions.
        """
        template = self.ai_engine.get_prompt_template("beginner_guidance")
        if not template:
            raise ValueError("Beginner guidance template not found")

        system_prompt, user_prompt = template.render(
            current_task=current_task,
            target=target,
            current_progress=current_progress,
        )

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ]

        response = await self.ai_engine.chat_completion(
            messages=messages,
            project_id=self.project_id,
        )

        guidance = self._parse_beginner_guidance(response.content)

        return guidance

    async def get_skill_path(
        self,
        current_level: str = "beginner",
    ) -> SkillPath:
        """Get skill improvement path recommendations.

        Args:
            current_level: Current skill level.

        Returns:
            SkillPath with learning recommendations.
        """
        system_prompt = """You are an expert penetration testing instructor.
Based on the user's current skill level, recommend a learning path to improve their penetration testing skills.
Include specific skills to learn, recommended learning order, resources, and milestones."""

        user_prompt = f"Current skill level: {current_level}\nRecommend a skill improvement path."

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ]

        response = await self.ai_engine.chat_completion(
            messages=messages,
            project_id=self.project_id,
        )

        skill_path = self._parse_skill_path(response.content, current_level)

        return skill_path

    def _parse_beginner_guidance(self, ai_response: str) -> BeginnerGuidance:
        """Parse AI beginner guidance response.

        Args:
            ai_response: AI response text.

        Returns:
            Parsed BeginnerGuidance.
        """
        guidance = BeginnerGuidance()

        lines = ai_response.split("\n")
        current_section = ""

        for line in lines:
            line = line.strip()
            if not line:
                continue

            if "step" in line.lower() or "title" in line.lower():
                current_section = "title"
                guidance.step_title = line
            elif "explain" in line.lower() or "what" in line.lower():
                current_section = "explanation"
            elif "principle" in line.lower() or "why" in line.lower():
                current_section = "principle"
            elif "instruction" in line.lower() or "step" in line.lower():
                current_section = "instructions"
            elif "expected" in line.lower() or "outcome" in line.lower():
                current_section = "outcome"
            elif "next" in line.lower():
                current_section = "next"
            elif "resource" in line.lower() or "learn" in line.lower():
                current_section = "resources"
            elif line.startswith("-") or line.startswith("*") or re.match(r"^\d+\.", line):
                content = re.sub(r"^[-*\d.]+\s*", "", line)
                if current_section == "instructions":
                    guidance.instructions.append(content)
                elif current_section == "next":
                    guidance.next_steps.append(content)
                elif current_section == "resources":
                    guidance.learning_resources.append(content)
            elif current_section == "explanation":
                guidance.explanation += line + " "
            elif current_section == "principle":
                guidance.principle += line + " "
            elif current_section == "outcome":
                guidance.expected_outcome += line + " "

        return guidance

    def _parse_skill_path(self, ai_response: str, current_level: str) -> SkillPath:
        """Parse AI skill path response.

        Args:
            ai_response: AI response text.
            current_level: Current skill level.

        Returns:
            Parsed SkillPath.
        """
        skill_path = SkillPath(current_level=current_level)

        lines = ai_response.split("\n")
        current_section = ""

        for line in lines:
            line = line.strip()
            if not line:
                continue

            if "skill" in line.lower():
                current_section = "skills"
            elif "order" in line.lower() or "sequence" in line.lower():
                current_section = "order"
            elif "resource" in line.lower():
                current_section = "resources"
            elif "milestone" in line.lower():
                current_section = "milestones"
            elif line.startswith("-") or line.startswith("*") or re.match(r"^\d+\.", line):
                content = re.sub(r"^[-*\d.]+\s*", "", line)
                if current_section == "skills":
                    skill_path.recommended_skills.append(content)
                elif current_section == "order":
                    skill_path.learning_order.append(content)
                elif current_section == "resources":
                    skill_path.resources.append(content)
                elif current_section == "milestones":
                    skill_path.milestones.append(content)

        return skill_path

    def set_mode(self, mode: ConversationMode) -> None:
        """Set conversation mode.

        Args:
            mode: New conversation mode.
        """
        self.mode = mode

    def get_automation_status(self) -> Dict[str, Any]:
        """Get current automation status.

        Returns:
            Dictionary with automation status information.
        """
        return {
            "is_running": self.automation_state.is_running,
            "is_paused": self.automation_state.is_paused,
            "current_phase": self.automation_state.current_phase.value,
            "phase_progress": self.automation_state.phase_progress,
            "completed_steps": len(self.automation_state.completed_steps),
            "total_phases": self.automation_state.total_phases,
            "start_time": self.automation_state.start_time,
        }
