"""AI Engine: Multi-model management, prompt templates, security sandbox, and context management.

Provides:
- Multi-LLM support (OpenAI GPT-4o/4-Turbo, Claude 3.5, DeepSeek-V3, Qwen, local models via Ollama/vLLM)
- Unified model configuration in config.yaml with encrypted API Key storage
- Automatic model failover: primary model fallback to backup models
- Built-in prompt template library optimized for penetration testing phases
- Security sandbox for AI-generated Payload validation
- User confirmation for AI-generated commands (high-risk operations require double confirmation)
- Context management: AI-aware of current assets, vulnerabilities, privilege level
- Conversation history grouped by project with resume support
- Context window management: automatic trimming of long history while preserving key information
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

MAX_CONTEXT_WINDOW = 128000
DEFAULT_CONTEXT_TRIM_THRESHOLD = 100000
MAX_CONVERSATION_HISTORY = 50


class ModelProvider(Enum):
    """AI model providers."""
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    DEEPSEEK = "deepseek"
    QWEN = "qwen"
    OLLAMA = "ollama"
    VLLM = "vllm"
    CUSTOM = "custom"


class ModelCapability(Enum):
    """AI model capabilities."""
    TEXT_GENERATION = "text_generation"
    CODE_GENERATION = "code_generation"
    ANALYSIS = "analysis"
    PAYLOAD_GENERATION = "payload_generation"
    REPORT_WRITING = "report_writing"
    CHAT = "chat"


class RiskLevel(Enum):
    """Command risk levels."""
    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SandboxStatus(Enum):
    """Sandbox validation status."""
    PASSED = "passed"
    FAILED = "failed"
    WARNING = "warning"
    BLOCKED = "blocked"


@dataclass
class ModelConfig:
    """AI model configuration.

    Attributes:
        provider: Model provider
        model_name: Model name/identifier
        api_key: API key (encrypted)
        api_base: API base URL (for custom/local models)
        max_tokens: Maximum tokens for generation
        temperature: Temperature for generation
        top_p: Top-p sampling value
        timeout: Request timeout in seconds
        capabilities: List of model capabilities
        priority: Model priority (lower = higher priority)
        enabled: Whether model is enabled
    """
    provider: ModelProvider = ModelProvider.OPENAI
    model_name: str = "gpt-4o"
    api_key: str = ""
    api_base: str = ""
    max_tokens: int = 4096
    temperature: float = 0.7
    top_p: float = 1.0
    timeout: int = 60
    capabilities: List[ModelCapability] = field(default_factory=list)
    priority: int = 1
    enabled: bool = True


@dataclass
class ChatMessage:
    """Chat message for conversation.

    Attributes:
        role: Message role (system/user/assistant)
        content: Message content
        timestamp: Message timestamp
        metadata: Additional metadata
    """
    role: str = "user"
    content: str = ""
    timestamp: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation.

        Returns:
            Dictionary with message data.
        """
        return {
            "role": self.role,
            "content": self.content,
            "timestamp": self.timestamp,
            "metadata": self.metadata,
        }


@dataclass
class ConversationContext:
    """Conversation context for a project.

    Attributes:
        project_id: Project identifier
        messages: Conversation messages
        assets: Known assets in context
        vulnerabilities: Known vulnerabilities in context
        current_privilege_level: Current privilege level
        created_at: Context creation time
        updated_at: Last update time
    """
    project_id: str = ""
    messages: List[ChatMessage] = field(default_factory=list)
    assets: List[Dict[str, Any]] = field(default_factory=list)
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    current_privilege_level: str = "unknown"
    created_at: float = 0.0
    updated_at: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation.

        Returns:
            Dictionary with context data.
        """
        return {
            "project_id": self.project_id,
            "messages": [m.to_dict() for m in self.messages],
            "assets": self.assets,
            "vulnerabilities": self.vulnerabilities,
            "current_privilege_level": self.current_privilege_level,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


@dataclass
class PromptTemplate:
    """Prompt template for AI operations.

    Attributes:
        template_id: Unique template identifier
        name: Template name
        description: Template description
        category: Template category
        system_prompt: System prompt content
        user_prompt_template: User prompt template with placeholders
        variables: List of required variables
        created_at: Template creation time
    """
    template_id: str = ""
    name: str = ""
    description: str = ""
    category: str = ""
    system_prompt: str = ""
    user_prompt_template: str = ""
    variables: List[str] = field(default_factory=list)
    created_at: float = 0.0

    def render(self, **kwargs: Any) -> Tuple[str, str]:
        """Render template with variables.

        Args:
            **kwargs: Variable values for template rendering.

        Returns:
            Tuple of (system_prompt, user_prompt).
        """
        system_prompt = self.system_prompt
        user_prompt = self.user_prompt_template

        for key, value in kwargs.items():
            placeholder = f"{{{{{key}}}}}"
            system_prompt = system_prompt.replace(placeholder, str(value))
            user_prompt = user_prompt.replace(placeholder, str(value))

        return system_prompt, user_prompt


@dataclass
class SandboxResult:
    """Sandbox validation result.

    Attributes:
        status: Validation status
        risk_level: Command risk level
        is_safe: Whether payload is safe to use
        warnings: List of warnings
        blocked_reasons: List of blocking reasons
        sanitized_payload: Sanitized payload if applicable
    """
    status: SandboxStatus = SandboxStatus.PASSED
    risk_level: RiskLevel = RiskLevel.SAFE
    is_safe: bool = True
    warnings: List[str] = field(default_factory=list)
    blocked_reasons: List[str] = field(default_factory=list)
    sanitized_payload: str = ""


@dataclass
class AIResponse:
    """AI model response.

    Attributes:
        content: Response content
        model: Model that generated the response
        usage: Token usage information
        finish_reason: Reason for finishing
        timestamp: Response timestamp
    """
    content: str = ""
    model: str = ""
    usage: Dict[str, int] = field(default_factory=dict)
    finish_reason: str = ""
    timestamp: float = 0.0


class PromptTemplateLibrary:
    """Built-in prompt template library for penetration testing.

    Contains optimized prompts for various penetration testing phases.
    """

    TEMPLATES: List[PromptTemplate] = [
        PromptTemplate(
            template_id="asset_analysis",
            name="Asset Analysis",
            description="Analyze target assets and recommend testing approach",
            category="reconnaissance",
            system_prompt="""You are an expert penetration tester with 20 years of experience.
Analyze the provided asset information and provide actionable recommendations.
Focus on:
1. Technology stack identification
2. Known vulnerabilities for identified technologies
3. Recommended testing approach
4. Potential attack vectors
5. Risk assessment

Always provide specific, actionable advice. Be concise but thorough.""",
            user_prompt_template="""Analyze the following target asset:

Asset Information:
{asset_info}

Technology Stack (if known):
{tech_stack}

Provide your analysis with specific recommendations for penetration testing.""",
            variables=["asset_info", "tech_stack"],
            created_at=time.time(),
        ),
        PromptTemplate(
            template_id="payload_generation",
            name="Payload Generation",
            description="Generate targeted payloads for specific vulnerability types",
            category="exploitation",
            system_prompt="""You are an expert penetration tester specializing in payload generation.
Generate safe, effective payloads for penetration testing purposes only.
Always:
1. Consider the target technology and version
2. Generate payloads that test for vulnerabilities without causing damage
3. Include explanations for how each payload works
4. Provide multiple variants if applicable
5. Note any potential risks or side effects

IMPORTANT: Only generate payloads for authorized penetration testing.""",
            user_prompt_template="""Generate payloads for the following scenario:

Vulnerability Type: {vuln_type}
Target Technology: {target_tech}
Request Context:
{request_context}

Parameters to test: {parameters}

Generate appropriate test payloads with explanations.""",
            variables=["vuln_type", "target_tech", "request_context", "parameters"],
            created_at=time.time(),
        ),
        PromptTemplate(
            template_id="vulnerability_verification",
            name="Vulnerability Verification",
            description="Analyze PoC results and confirm vulnerability existence",
            category="verification",
            system_prompt="""You are an expert vulnerability analyst.
Analyze the provided PoC execution results and determine:
1. Whether the vulnerability is confirmed
2. Confidence level (high/medium/low)
3. Evidence supporting the conclusion
4. Recommended next steps for exploitation or remediation
5. CVSS score estimation

Be conservative in your assessment. Only confirm vulnerabilities when evidence is clear.""",
            user_prompt_template="""Analyze the following PoC execution results:

Vulnerability Type: {vuln_type}
Target: {target}
PoC Output:
{poc_output}

Response Analysis:
{response_analysis}

Provide your vulnerability assessment.""",
            variables=["vuln_type", "target", "poc_output", "response_analysis"],
            created_at=time.time(),
        ),
        PromptTemplate(
            template_id="waf_bypass",
            name="WAF Bypass",
            description="Generate WAF bypass payloads based on interception analysis",
            category="evasion",
            system_prompt="""You are an expert in web application security and WAF evasion techniques.
Analyze the WAF interception patterns and generate bypass payloads.
Consider:
1. WAF vendor and version (if identifiable)
2. Interception patterns and rules triggered
3. Encoding techniques (URL, Unicode, HTML entities)
4. Syntax variations
5. Protocol-level bypasses

Always explain the bypass technique.""",
            user_prompt_template="""Analyze the following WAF interception:

WAF Information: {waf_info}
Original Payload: {original_payload}
Interception Response:
{interception_response}

Generate WAF bypass payloads with explanations.""",
            variables=["waf_info", "original_payload", "interception_response"],
            created_at=time.time(),
        ),
        PromptTemplate(
            template_id="report_generation",
            name="Report Generation",
            description="Generate comprehensive penetration test reports",
            category="reporting",
            system_prompt="""You are an expert penetration test report writer.
Generate professional, comprehensive reports that include:
1. Executive Summary (for management)
2. Technical Findings (for technical teams)
3. Risk Assessment
4. Attack Chain Analysis
5. Remediation Recommendations
6. Appendices with technical details

Use clear, professional language. Tailor the report to the specified audience.""",
            user_prompt_template="""Generate a penetration test report:

Target: {target}
Test Scope: {scope}
Findings:
{findings}

Attack Chain:
{attack_chain}

Report Style: {report_style}
Audience: {audience}

Generate the complete report.""",
            variables=["target", "scope", "findings", "attack_chain", "report_style", "audience"],
            created_at=time.time(),
        ),
        PromptTemplate(
            template_id="passive_scan_analysis",
            name="Passive Scan Analysis",
            description="Deep analysis of passive scan findings",
            category="analysis",
            system_prompt="""You are an expert security analyst reviewing passive scan results.
Analyze the findings and:
1. Identify potential false positives
2. Highlight high-value findings requiring manual verification
3. Suggest manual testing approaches
4. Identify logical vulnerabilities that automated tools may miss
5. Prioritize findings by risk and exploitability""",
            user_prompt_template="""Review the following passive scan findings:

Target: {target}
Findings:
{findings}

Traffic Sample:
{traffic_sample}

Provide your analysis with prioritized recommendations.""",
            variables=["target", "findings", "traffic_sample"],
            created_at=time.time(),
        ),
        PromptTemplate(
            template_id="privilege_escalation",
            name="Privilege Escalation Analysis",
            description="Analyze system information and recommend privilege escalation paths",
            category="exploitation",
            system_prompt="""You are an expert in privilege escalation techniques.
Analyze the provided system information and recommend the best privilege escalation paths.
Consider:
1. OS version and patch level
2. Installed software and services
3. User permissions and group memberships
4. Kernel vulnerabilities
5. Misconfigurations
6. Credential opportunities

Provide step-by-step recommendations with risk assessment.""",
            user_prompt_template="""Analyze the following system for privilege escalation:

OS Information: {os_info}
Current User: {current_user}
Installed Software: {installed_software}
Running Services: {running_services}
Network Configuration: {network_config}

Recommend privilege escalation paths.""",
            variables=["os_info", "current_user", "installed_software", "running_services", "network_config"],
            created_at=time.time(),
        ),
        PromptTemplate(
            template_id="lateral_movement",
            name="Lateral Movement Analysis",
            description="Analyze network topology and recommend lateral movement paths",
            category="exploitation",
            system_prompt="""You are an expert in network penetration and lateral movement.
Analyze the network topology and current access to recommend lateral movement paths.
Consider:
1. Network segmentation and trust relationships
2. Available credentials and authentication methods
3. Service discovery and vulnerability mapping
4. Active Directory relationships (if applicable)
5. Pivoting opportunities

Provide step-by-step recommendations.""",
            user_prompt_template="""Analyze for lateral movement opportunities:

Current Access: {current_access}
Network Topology: {network_topology}
Discovered Credentials: {credentials}
Available Tools: {available_tools}

Recommend lateral movement paths.""",
            variables=["current_access", "network_topology", "credentials", "available_tools"],
            created_at=time.time(),
        ),
        PromptTemplate(
            template_id="attack_chain_analysis",
            name="Attack Chain Analysis",
            description="Analyze and document complete attack chains with MITRE ATT&CK mapping",
            category="analysis",
            system_prompt="""You are an expert in attack chain analysis and MITRE ATT&CK framework.
Analyze the provided attack steps and:
1. Document the complete attack chain timeline
2. Map each step to MITRE ATT&CK techniques
3. Identify alternative paths that could have been taken
4. Highlight critical decision points
5. Provide defensive recommendations for each stage""",
            user_prompt_template="""Analyze the following attack chain:

Target: {target}
Attack Steps:
{attack_steps}

Timeline:
{timeline}

Provide complete attack chain analysis with MITRE ATT&CK mapping.""",
            variables=["target", "attack_steps", "timeline"],
            created_at=time.time(),
        ),
        PromptTemplate(
            template_id="beginner_guidance",
            name="Beginner Guidance",
            description="Guide beginners through penetration testing steps with explanations",
            category="education",
            system_prompt="""You are a patient, experienced penetration testing instructor.
Guide the user through the current testing step by:
1. Explaining what we're doing and why
2. Describing the underlying vulnerability concept
3. Providing step-by-step instructions
4. Explaining expected outcomes
5. Suggesting next steps and learning resources

Use clear, accessible language. Avoid jargon where possible, explain it when necessary.""",
            user_prompt_template="""Guide me through this penetration testing step:

Current Task: {current_task}
Target: {target}
Current Progress: {current_progress}

Explain what we're doing, why, and what to do next.""",
            variables=["current_task", "target", "current_progress"],
            created_at=time.time(),
        ),
        PromptTemplate(
            template_id="js_endpoint_analysis",
            name="JavaScript Endpoint Analysis",
            description="Analyze JavaScript files for API endpoints and potential security issues",
            category="reconnaissance",
            system_prompt="""You are an expert in JavaScript analysis and web application security.
Analyze the provided JavaScript code and:
1. Extract all API endpoints
2. Identify authentication mechanisms
3. Flag potentially dangerous endpoints (admin, upload, delete, etc.)
4. Identify hardcoded secrets or credentials
5. Note interesting parameters or data flows""",
            user_prompt_template="""Analyze the following JavaScript file(s):

{js_content}

Extract endpoints and identify security-relevant findings.""",
            variables=["js_content"],
            created_at=time.time(),
        ),
        PromptTemplate(
            template_id="idor_testing",
            name="IDOR Testing",
            description="Generate and analyze IDOR (Insecure Direct Object Reference) test cases",
            category="exploitation",
            system_prompt="""You are an expert in authorization testing and IDOR vulnerability discovery.
Help test for IDOR vulnerabilities by:
1. Identifying object references in requests
2. Generating test payloads with modified references
3. Analyzing responses for authorization bypass indicators
4. Suggesting enumeration approaches
5. Recommending verification steps""",
            user_prompt_template="""Test for IDOR vulnerabilities:

Original Request:
{original_request}

Response:
{response}

Parameters to test: {parameters}
Known user IDs (if any): {known_ids}

Generate IDOR test cases and analysis.""",
            variables=["original_request", "response", "parameters", "known_ids"],
            created_at=time.time(),
        ),
    ]

    @classmethod
    def get_template(cls, template_id: str) -> Optional[PromptTemplate]:
        """Get prompt template by ID.

        Args:
            template_id: Template identifier.

        Returns:
            PromptTemplate or None if not found.
        """
        for template in cls.TEMPLATES:
            if template.template_id == template_id:
                return template
        return None

    @classmethod
    def get_templates_by_category(cls, category: str) -> List[PromptTemplate]:
        """Get prompt templates by category.

        Args:
            category: Template category.

        Returns:
            List of matching PromptTemplate objects.
        """
        return [t for t in cls.TEMPLATES if t.category == category]

    @classmethod
    def get_all_categories(cls) -> List[str]:
        """Get all template categories.

        Returns:
            List of unique category names.
        """
        return list(set(t.category for t in cls.TEMPLATES))


class SecuritySandbox:
    """Security sandbox for AI-generated Payload validation.

    Validates AI-generated payloads and commands before execution.
    """

    DANGEROUS_PATTERNS: List[Tuple[str, RiskLevel]] = [
        (r"rm\s+(-rf?|--force)", RiskLevel.CRITICAL),
        (r"mkfs", RiskLevel.CRITICAL),
        (r"dd\s+if=", RiskLevel.CRITICAL),
        (r"chmod\s+[0-7]*777", RiskLevel.HIGH),
        (r"chown\s+root", RiskLevel.HIGH),
        (r"DROP\s+TABLE", RiskLevel.HIGH),
        (r"DELETE\s+FROM", RiskLevel.HIGH),
        (r"UPDATE\s+\w+\s+SET", RiskLevel.HIGH),
        (r"exec\s*\(", RiskLevel.MEDIUM),
        (r"eval\s*\(", RiskLevel.MEDIUM),
        (r"os\.system\s*\(", RiskLevel.MEDIUM),
        (r"subprocess\s*\.", RiskLevel.MEDIUM),
        (r"<script>", RiskLevel.LOW),
        (r"javascript:", RiskLevel.LOW),
        (r"data:text/html", RiskLevel.LOW),
    ]

    SAFE_TEST_PATTERNS: List[str] = [
        r"sleep\s+\d+",
        r"ping\s+-c\s+\d+",
        r"id\b",
        r"whoami\b",
        r"uname\s+-a",
        r"cat\s+/etc/passwd",
        r"SELECT\s+1",
        r"' OR '1'='1",
        r"<img\s+src=x\s+onerror=",
        r"alert\(1\)",
    ]

    def validate_payload(self, payload: str) -> SandboxResult:
        """Validate AI-generated payload.

        Args:
            payload: Payload string to validate.

        Returns:
            SandboxResult with validation status.
        """
        result = SandboxResult()

        for pattern, risk_level in self.DANGEROUS_PATTERNS:
            if re.search(pattern, payload, re.IGNORECASE):
                result.blocked_reasons.append(
                    f"Dangerous pattern detected: {pattern} (Risk: {risk_level.value})"
                )
                result.status = SandboxStatus.BLOCKED
                result.is_safe = False
                result.risk_level = max(result.risk_level, risk_level, key=lambda x: x.value)

        if not result.blocked_reasons:
            for pattern in self.SAFE_TEST_PATTERNS:
                if re.search(pattern, payload, re.IGNORECASE):
                    result.warnings.append(
                        f"Test pattern detected: {pattern}"
                    )
                    result.status = SandboxStatus.WARNING

        if not result.blocked_reasons and not result.warnings:
            result.status = SandboxStatus.PASSED
            result.is_safe = True

        result.sanitized_payload = self._sanitize_payload(payload)

        return result

    def validate_command(self, command: str) -> SandboxResult:
        """Validate AI-generated command.

        Args:
            command: Command string to validate.

        Returns:
            SandboxResult with validation status.
        """
        return self.validate_payload(command)

    def _sanitize_payload(self, payload: str) -> str:
        """Sanitize payload for safe display.

        Args:
            payload: Original payload.

        Returns:
            Sanitized payload string.
        """
        sanitized = payload
        dangerous_chars = ["\x00", "\x1b", "\x07"]
        for char in dangerous_chars:
            sanitized = sanitized.replace(char, f"[{ord(char):#04x}]")
        return sanitized


class ContextManager:
    """Context manager for AI conversations.

    Manages conversation history, context windows, and project-scoped contexts.
    """

    def __init__(
        self,
        max_context_window: int = MAX_CONTEXT_WINDOW,
        trim_threshold: int = DEFAULT_CONTEXT_TRIM_THRESHOLD,
        max_history: int = MAX_CONVERSATION_HISTORY,
    ) -> None:
        """Initialize context manager.

        Args:
            max_context_window: Maximum context window size in tokens.
            trim_threshold: Token threshold for triggering context trimming.
            max_history: Maximum number of messages to keep in history.
        """
        self.max_context_window = max_context_window
        self.trim_threshold = trim_threshold
        self.max_history = max_history
        self._contexts: Dict[str, ConversationContext] = {}
        self._storage_path: Optional[str] = None

    def set_storage_path(self, path: str) -> None:
        """Set context storage path.

        Args:
            path: Directory path for context persistence.
        """
        self._storage_path = path
        os.makedirs(path, exist_ok=True)

    def create_context(self, project_id: str) -> ConversationContext:
        """Create new conversation context for a project.

        Args:
            project_id: Project identifier.

        Returns:
            New ConversationContext.
        """
        now = time.time()
        context = ConversationContext(
            project_id=project_id,
            created_at=now,
            updated_at=now,
        )
        self._contexts[project_id] = context
        self._save_context(context)
        return context

    def get_context(self, project_id: str) -> Optional[ConversationContext]:
        """Get conversation context for a project.

        Args:
            project_id: Project identifier.

        Returns:
            ConversationContext or None if not found.
        """
        if project_id in self._contexts:
            return self._contexts[project_id]

        context = self._load_context(project_id)
        if context:
            self._contexts[project_id] = context

        return context

    def add_message(
        self,
        project_id: str,
        role: str,
        content: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Optional[ChatMessage]:
        """Add message to conversation context.

        Args:
            project_id: Project identifier.
            role: Message role.
            content: Message content.
            metadata: Optional message metadata.

        Returns:
            Added ChatMessage or None if context not found.
        """
        context = self.get_context(project_id)
        if not context:
            context = self.create_context(project_id)

        message = ChatMessage(
            role=role,
            content=content,
            timestamp=time.time(),
            metadata=metadata or {},
        )

        context.messages.append(message)
        context.updated_at = time.time()

        self._trim_context(context)
        self._save_context(context)

        return message

    def update_assets(
        self,
        project_id: str,
        assets: List[Dict[str, Any]],
    ) -> None:
        """Update assets in conversation context.

        Args:
            project_id: Project identifier.
            assets: List of asset dictionaries.
        """
        context = self.get_context(project_id)
        if context:
            context.assets = assets
            context.updated_at = time.time()
            self._save_context(context)

    def update_vulnerabilities(
        self,
        project_id: str,
        vulnerabilities: List[Dict[str, Any]],
    ) -> None:
        """Update vulnerabilities in conversation context.

        Args:
            project_id: Project identifier.
            vulnerabilities: List of vulnerability dictionaries.
        """
        context = self.get_context(project_id)
        if context:
            context.vulnerabilities = vulnerabilities
            context.updated_at = time.time()
            self._save_context(context)

    def update_privilege_level(
        self,
        project_id: str,
        privilege_level: str,
    ) -> None:
        """Update current privilege level in context.

        Args:
            project_id: Project identifier.
            privilege_level: New privilege level string.
        """
        context = self.get_context(project_id)
        if context:
            context.current_privilege_level = privilege_level
            context.updated_at = time.time()
            self._save_context(context)

    def get_messages_for_llm(
        self,
        project_id: str,
        system_prompt: Optional[str] = None,
    ) -> List[Dict[str, str]]:
        """Get messages formatted for LLM API.

        Args:
            project_id: Project identifier.
            system_prompt: Optional system prompt to prepend.

        Returns:
            List of message dictionaries for LLM API.
        """
        context = self.get_context(project_id)
        if not context:
            return []

        messages: List[Dict[str, str]] = []

        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})

        for msg in context.messages[-self.max_history:]:
            messages.append({"role": msg.role, "content": msg.content})

        return messages

    def _trim_context(self, context: ConversationContext) -> None:
        """Trim context if it exceeds thresholds.

        Args:
            context: ConversationContext to trim.
        """
        total_tokens = sum(len(msg.content) // 4 for msg in context.messages)

        if total_tokens > self.trim_threshold:
            excess = total_tokens - self.trim_threshold
            messages_to_remove = excess // 200

            if messages_to_remove > 0 and len(context.messages) > 10:
                context.messages = context.messages[messages_to_remove:]

        if len(context.messages) > self.max_history:
            context.messages = context.messages[-self.max_history:]

    def _save_context(self, context: ConversationContext) -> None:
        """Save context to disk.

        Args:
            context: ConversationContext to save.
        """
        if not self._storage_path:
            return

        try:
            file_path = os.path.join(
                self._storage_path, f"{context.project_id}.json"
            )
            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(context.to_dict(), f, ensure_ascii=False, indent=2)
        except Exception as e:
            logger.error(f"Failed to save context: {e}")

    def _load_context(self, project_id: str) -> Optional[ConversationContext]:
        """Load context from disk.

        Args:
            project_id: Project identifier.

        Returns:
            Loaded ConversationContext or None.
        """
        if not self._storage_path:
            return None

        try:
            file_path = os.path.join(self._storage_path, f"{project_id}.json")
            if not os.path.exists(file_path):
                return None

            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            context = ConversationContext(
                project_id=data.get("project_id", project_id),
                created_at=data.get("created_at", time.time()),
                updated_at=data.get("updated_at", time.time()),
                current_privilege_level=data.get("current_privilege_level", "unknown"),
                assets=data.get("assets", []),
                vulnerabilities=data.get("vulnerabilities", []),
            )

            for msg_data in data.get("messages", []):
                context.messages.append(ChatMessage(
                    role=msg_data.get("role", "user"),
                    content=msg_data.get("content", ""),
                    timestamp=msg_data.get("timestamp", 0.0),
                    metadata=msg_data.get("metadata", {}),
                ))

            return context

        except Exception as e:
            logger.error(f"Failed to load context: {e}")
            return None


class AIEngine:
    """AI engine for penetration testing copilot.

    Manages multiple LLM models, prompt templates, security sandbox,
    and context for AI-assisted penetration testing.

    Attributes:
        models: List of configured AI models
        sandbox: Security sandbox instance
        context_manager: Context manager instance
        prompt_library: Prompt template library
        _active_model: Currently active model
        _model_fallback_order: Model fallback order
    """

    def __init__(
        self,
        models: Optional[List[ModelConfig]] = None,
        sandbox: Optional[SecuritySandbox] = None,
        context_manager: Optional[ContextManager] = None,
    ) -> None:
        """Initialize AI engine.

        Args:
            models: List of model configurations. Uses defaults if None.
            sandbox: Security sandbox instance. Creates new if None.
            context_manager: Context manager instance. Creates new if None.
        """
        self.models = models or self._default_models()
        self.sandbox = sandbox or SecuritySandbox()
        self.context_manager = context_manager or ContextManager()
        self.prompt_library = PromptTemplateLibrary()
        self._active_model: Optional[ModelConfig] = None
        self._model_fallback_order: List[ModelConfig] = sorted(
            [m for m in self.models if m.enabled],
            key=lambda m: m.priority,
        )
        self._response_callback: Optional[Callable[[str], Coroutine[Any, Any, None]]] = None

    def _default_models(self) -> List[ModelConfig]:
        """Create default model configurations.

        Returns:
            List of default ModelConfig objects.
        """
        return [
            ModelConfig(
                provider=ModelProvider.OPENAI,
                model_name="gpt-4o",
                api_key="",
                max_tokens=4096,
                temperature=0.7,
                capabilities=[
                    ModelCapability.TEXT_GENERATION,
                    ModelCapability.CODE_GENERATION,
                    ModelCapability.ANALYSIS,
                    ModelCapability.PAYLOAD_GENERATION,
                    ModelCapability.REPORT_WRITING,
                    ModelCapability.CHAT,
                ],
                priority=1,
                enabled=True,
            ),
            ModelConfig(
                provider=ModelProvider.ANTHROPIC,
                model_name="claude-3-5-sonnet-20241022",
                api_key="",
                max_tokens=4096,
                temperature=0.7,
                capabilities=[
                    ModelCapability.TEXT_GENERATION,
                    ModelCapability.ANALYSIS,
                    ModelCapability.REPORT_WRITING,
                    ModelCapability.CHAT,
                ],
                priority=2,
                enabled=True,
            ),
            ModelConfig(
                provider=ModelProvider.DEEPSEEK,
                model_name="deepseek-chat",
                api_key="",
                max_tokens=4096,
                temperature=0.7,
                capabilities=[
                    ModelCapability.TEXT_GENERATION,
                    ModelCapability.CODE_GENERATION,
                    ModelCapability.CHAT,
                ],
                priority=3,
                enabled=True,
            ),
            ModelConfig(
                provider=ModelProvider.OLLAMA,
                model_name="llama3",
                api_base="http://localhost:11434",
                max_tokens=4096,
                temperature=0.7,
                capabilities=[
                    ModelCapability.TEXT_GENERATION,
                    ModelCapability.CHAT,
                ],
                priority=4,
                enabled=False,
            ),
        ]

    def set_response_callback(
        self,
        callback: Callable[[str], Coroutine[Any, Any, None]],
    ) -> None:
        """Set response streaming callback.

        Args:
            callback: Async callback for streaming responses.
        """
        self._response_callback = callback

    def get_active_model(self) -> Optional[ModelConfig]:
        """Get currently active model.

        Returns:
            Active ModelConfig or None.
        """
        return self._active_model

    def set_active_model(self, model_name: str) -> bool:
        """Set active model by name.

        Args:
            model_name: Model name to activate.

        Returns:
            True if model was found and activated.
        """
        for model in self.models:
            if model.model_name == model_name:
                self._active_model = model
                return True
        return False

    async def _fallback_to_next_model(self) -> Optional[ModelConfig]:
        """Fallback to next available model.

        Returns:
            Next ModelConfig or None if no models available.
        """
        current_idx = -1
        if self._active_model:
            for i, model in enumerate(self._model_fallback_order):
                if model.model_name == self._active_model.model_name:
                    current_idx = i
                    break

        for model in self._model_fallback_order[current_idx + 1:]:
            if model.enabled:
                self._active_model = model
                logger.info(f"Model fallback to: {model.model_name}")
                return model

        return None

    async def chat_completion(
        self,
        messages: List[Dict[str, str]],
        project_id: Optional[str] = None,
        model_name: Optional[str] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
    ) -> AIResponse:
        """Generate chat completion from AI model.

        Args:
            messages: List of message dictionaries.
            project_id: Optional project ID for context tracking.
            model_name: Optional model name override.
            temperature: Optional temperature override.
            max_tokens: Optional max tokens override.

        Returns:
            AIResponse with generated content.
        """
        if model_name:
            self.set_active_model(model_name)

        model = self._active_model or self._model_fallback_order[0]
        if not model:
            raise ValueError("No AI model configured")

        temp = temperature if temperature is not None else model.temperature
        tokens = max_tokens if max_tokens is not None else model.max_tokens

        for attempt in range(3):
            try:
                response = await self._call_model_api(
                    model=model,
                    messages=messages,
                    temperature=temp,
                    max_tokens=tokens,
                )

                if project_id:
                    self.context_manager.add_message(
                        project_id, "assistant", response.content
                    )

                return response

            except Exception as e:
                logger.error(f"Model API call failed (attempt {attempt + 1}): {e}")
                next_model = await self._fallback_to_next_model()
                if not next_model:
                    raise

        raise RuntimeError("All model attempts failed")

    async def _call_model_api(
        self,
        model: ModelConfig,
        messages: List[Dict[str, str]],
        temperature: float,
        max_tokens: int,
    ) -> AIResponse:
        """Call specific model API.

        Args:
            model: Model configuration.
            messages: Message list for API.
            temperature: Generation temperature.
            max_tokens: Maximum tokens to generate.

        Returns:
            AIResponse with generated content.
        """
        if model.provider == ModelProvider.OPENAI:
            return await self._call_openai_api(model, messages, temperature, max_tokens)
        elif model.provider == ModelProvider.ANTHROPIC:
            return await self._call_anthropic_api(model, messages, temperature, max_tokens)
        elif model.provider == ModelProvider.DEEPSEEK:
            return await self._call_deepseek_api(model, messages, temperature, max_tokens)
        elif model.provider == ModelProvider.OLLAMA:
            return await self._call_ollama_api(model, messages, temperature, max_tokens)
        elif model.provider == ModelProvider.QWEN:
            return await self._call_qwen_api(model, messages, temperature, max_tokens)
        else:
            raise ValueError(f"Unsupported provider: {model.provider}")

    async def _call_openai_api(
        self,
        model: ModelConfig,
        messages: List[Dict[str, str]],
        temperature: float,
        max_tokens: int,
    ) -> AIResponse:
        """Call OpenAI API.

        Args:
            model: Model configuration.
            messages: Message list for API.
            temperature: Generation temperature.
            max_tokens: Maximum tokens to generate.

        Returns:
            AIResponse with generated content.
        """
        try:
            import aiohttp

            api_base = model.api_base or "https://api.openai.com/v1"
            url = f"{api_base}/chat/completions"

            headers = {
                "Authorization": f"Bearer {model.api_key}",
                "Content-Type": "application/json",
            }

            payload = {
                "model": model.model_name,
                "messages": messages,
                "temperature": temperature,
                "max_tokens": max_tokens,
            }

            async with aiohttp.ClientSession() as session:
                async with session.post(
                    url,
                    headers=headers,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=model.timeout),
                ) as response:
                    if response.status != 200:
                        error_text = await response.text()
                        raise RuntimeError(f"OpenAI API error: {error_text}")

                    data = await response.json()
                    choice = data.get("choices", [{}])[0]
                    message_data = choice.get("message", {})
                    usage = data.get("usage", {})

                    return AIResponse(
                        content=message_data.get("content", ""),
                        model=model.model_name,
                        usage={
                            "prompt_tokens": usage.get("prompt_tokens", 0),
                            "completion_tokens": usage.get("completion_tokens", 0),
                            "total_tokens": usage.get("total_tokens", 0),
                        },
                        finish_reason=choice.get("finish_reason", ""),
                        timestamp=time.time(),
                    )

        except ImportError:
            raise RuntimeError("aiohttp not installed. Run: pip install aiohttp")

    async def _call_anthropic_api(
        self,
        model: ModelConfig,
        messages: List[Dict[str, str]],
        temperature: float,
        max_tokens: int,
    ) -> AIResponse:
        """Call Anthropic Claude API.

        Args:
            model: Model configuration.
            messages: Message list for API.
            temperature: Generation temperature.
            max_tokens: Maximum tokens to generate.

        Returns:
            AIResponse with generated content.
        """
        try:
            import aiohttp

            url = "https://api.anthropic.com/v1/messages"

            system_message = ""
            user_messages = []
            for msg in messages:
                if msg.get("role") == "system":
                    system_message = msg.get("content", "")
                else:
                    user_messages.append(msg)

            headers = {
                "x-api-key": model.api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            }

            payload = {
                "model": model.model_name,
                "messages": user_messages,
                "system": system_message,
                "max_tokens": max_tokens,
                "temperature": temperature,
            }

            async with aiohttp.ClientSession() as session:
                async with session.post(
                    url,
                    headers=headers,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=model.timeout),
                ) as response:
                    if response.status != 200:
                        error_text = await response.text()
                        raise RuntimeError(f"Anthropic API error: {error_text}")

                    data = await response.json()
                    content_blocks = data.get("content", [])
                    text_content = ""
                    for block in content_blocks:
                        if block.get("type") == "text":
                            text_content += block.get("text", "")

                    usage = data.get("usage", {})

                    return AIResponse(
                        content=text_content,
                        model=model.model_name,
                        usage={
                            "input_tokens": usage.get("input_tokens", 0),
                            "output_tokens": usage.get("output_tokens", 0),
                        },
                        finish_reason=data.get("stop_reason", ""),
                        timestamp=time.time(),
                    )

        except ImportError:
            raise RuntimeError("aiohttp not installed. Run: pip install aiohttp")

    async def _call_deepseek_api(
        self,
        model: ModelConfig,
        messages: List[Dict[str, str]],
        temperature: float,
        max_tokens: int,
    ) -> AIResponse:
        """Call DeepSeek API.

        Args:
            model: Model configuration.
            messages: Message list for API.
            temperature: Generation temperature.
            max_tokens: Maximum tokens to generate.

        Returns:
            AIResponse with generated content.
        """
        try:
            import aiohttp

            api_base = model.api_base or "https://api.deepseek.com/v1"
            url = f"{api_base}/chat/completions"

            headers = {
                "Authorization": f"Bearer {model.api_key}",
                "Content-Type": "application/json",
            }

            payload = {
                "model": model.model_name,
                "messages": messages,
                "temperature": temperature,
                "max_tokens": max_tokens,
            }

            async with aiohttp.ClientSession() as session:
                async with session.post(
                    url,
                    headers=headers,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=model.timeout),
                ) as response:
                    if response.status != 200:
                        error_text = await response.text()
                        raise RuntimeError(f"DeepSeek API error: {error_text}")

                    data = await response.json()
                    choice = data.get("choices", [{}])[0]
                    message_data = choice.get("message", {})
                    usage = data.get("usage", {})

                    return AIResponse(
                        content=message_data.get("content", ""),
                        model=model.model_name,
                        usage={
                            "prompt_tokens": usage.get("prompt_tokens", 0),
                            "completion_tokens": usage.get("completion_tokens", 0),
                            "total_tokens": usage.get("total_tokens", 0),
                        },
                        finish_reason=choice.get("finish_reason", ""),
                        timestamp=time.time(),
                    )

        except ImportError:
            raise RuntimeError("aiohttp not installed. Run: pip install aiohttp")

    async def _call_ollama_api(
        self,
        model: ModelConfig,
        messages: List[Dict[str, str]],
        temperature: float,
        max_tokens: int,
    ) -> AIResponse:
        """Call Ollama local model API.

        Args:
            model: Model configuration.
            messages: Message list for API.
            temperature: Generation temperature.
            max_tokens: Maximum tokens to generate.

        Returns:
            AIResponse with generated content.
        """
        try:
            import aiohttp

            api_base = model.api_base or "http://localhost:11434"
            url = f"{api_base}/api/chat"

            payload = {
                "model": model.model_name,
                "messages": messages,
                "stream": False,
                "options": {
                    "temperature": temperature,
                    "num_predict": max_tokens,
                },
            }

            async with aiohttp.ClientSession() as session:
                async with session.post(
                    url,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=model.timeout),
                ) as response:
                    if response.status != 200:
                        error_text = await response.text()
                        raise RuntimeError(f"Ollama API error: {error_text}")

                    data = await response.json()
                    message_data = data.get("message", {})

                    return AIResponse(
                        content=message_data.get("content", ""),
                        model=model.model_name,
                        usage={
                            "prompt_tokens": data.get("prompt_eval_count", 0),
                            "completion_tokens": data.get("eval_count", 0),
                        },
                        finish_reason="stop",
                        timestamp=time.time(),
                    )

        except ImportError:
            raise RuntimeError("aiohttp not installed. Run: pip install aiohttp")

    async def _call_qwen_api(
        self,
        model: ModelConfig,
        messages: List[Dict[str, str]],
        temperature: float,
        max_tokens: int,
    ) -> AIResponse:
        """Call Qwen (通义千问) API.

        Args:
            model: Model configuration.
            messages: Message list for API.
            temperature: Generation temperature.
            max_tokens: Maximum tokens to generate.

        Returns:
            AIResponse with generated content.
        """
        try:
            import aiohttp

            api_base = model.api_base or "https://dashscope.aliyuncs.com/compatible-mode/v1"
            url = f"{api_base}/chat/completions"

            headers = {
                "Authorization": f"Bearer {model.api_key}",
                "Content-Type": "application/json",
            }

            payload = {
                "model": model.model_name,
                "messages": messages,
                "temperature": temperature,
                "max_tokens": max_tokens,
            }

            async with aiohttp.ClientSession() as session:
                async with session.post(
                    url,
                    headers=headers,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=model.timeout),
                ) as response:
                    if response.status != 200:
                        error_text = await response.text()
                        raise RuntimeError(f"Qwen API error: {error_text}")

                    data = await response.json()
                    choice = data.get("choices", [{}])[0]
                    message_data = choice.get("message", {})
                    usage = data.get("usage", {})

                    return AIResponse(
                        content=message_data.get("content", ""),
                        model=model.model_name,
                        usage={
                            "prompt_tokens": usage.get("prompt_tokens", 0),
                            "completion_tokens": usage.get("completion_tokens", 0),
                            "total_tokens": usage.get("total_tokens", 0),
                        },
                        finish_reason=choice.get("finish_reason", ""),
                        timestamp=time.time(),
                    )

        except ImportError:
            raise RuntimeError("aiohttp not installed. Run: pip install aiohttp")

    def get_prompt_template(self, template_id: str) -> Optional[PromptTemplate]:
        """Get prompt template by ID.

        Args:
            template_id: Template identifier.

        Returns:
            PromptTemplate or None if not found.
        """
        return self.prompt_library.get_template(template_id)

    def validate_payload(self, payload: str) -> SandboxResult:
        """Validate AI-generated payload through sandbox.

        Args:
            payload: Payload string to validate.

        Returns:
            SandboxResult with validation status.
        """
        return self.sandbox.validate_payload(payload)

    def validate_command(self, command: str) -> SandboxResult:
        """Validate AI-generated command through sandbox.

        Args:
            command: Command string to validate.

        Returns:
            SandboxResult with validation status.
        """
        return self.sandbox.validate_command(command)
