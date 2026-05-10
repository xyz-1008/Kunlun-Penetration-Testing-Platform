"""Template AI Generator: AI-driven template generation, natural language to template, and intelligent optimization.

Provides:
- Automatic conversion of real-world operations to templates: AI analyzes operation sequences, identifies attack chains, removes redundant operations, generates natural language descriptions, extracts parameters as template variables
- Natural language template generation: Users describe attack goals in natural language, AI generates complete attack chains with MITRE ATT&CK mapping
- Intelligent template optimization: AI analyzes execution history, identifies low-success steps, recommends alternatives, auto-adjusts parameters based on target environment
"""

import asyncio
import json
import logging
import os
import re
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Callable, Coroutine, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


class GenerationSource(Enum):
    """Template generation sources."""
    REAL_OPERATIONS = "real_operations"
    NATURAL_LANGUAGE = "natural_language"
    OPTIMIZATION = "optimization"
    AI_SUGGESTION = "ai_suggestion"


class OptimizationType(Enum):
    """Template optimization types."""
    STEP_REPLACEMENT = "step_replacement"
    PARAMETER_ADJUSTMENT = "parameter_adjustment"
    TIMEOUT_OPTIMIZATION = "timeout_optimization"
    RETRY_ADDITION = "retry_addition"
    CONDITION_ADDITION = "condition_addition"
    PARALLELIZATION = "parallelization"


@dataclass
class AttackChainStep:
    """AI-generated attack chain step.

    Attributes:
        step_id: Unique step identifier
        step_number: Step sequence number
        action: Step action type
        name: Step display name
        description: Natural language description
        payload: Step payload
        mitre_technique_id: MITRE ATT&CK technique ID
        expected_output: Expected output pattern
        success_rate: Historical success rate
        is_critical: Whether step is critical
        alternatives: Alternative approaches
    """
    step_id: str = ""
    step_number: int = 0
    action: str = ""
    name: str = ""
    description: str = ""
    payload: Dict[str, Any] = field(default_factory=dict)
    mitre_technique_id: str = ""
    expected_output: str = ""
    success_rate: float = 0.0
    is_critical: bool = False
    alternatives: List[str] = field(default_factory=list)


@dataclass
class GeneratedTemplate:
    """AI-generated template.

    Attributes:
        template_id: Unique template identifier
        name: Template name
        description: Template description
        source: Generation source
        steps: List of attack chain steps
        variables: Template variables
        mitre_techniques: List of MITRE ATT&CK techniques
        target_platform: Target platform
        difficulty: Difficulty level
        estimated_time_minutes: Estimated completion time
        confidence_score: AI confidence score (0-100)
        author: Template author
        created_at: Creation timestamp
        is_validated: Whether template has been validated
        validation_score: Validation score
    """
    template_id: str = ""
    name: str = ""
    description: str = ""
    source: GenerationSource = GenerationSource.REAL_OPERATIONS
    steps: List[AttackChainStep] = field(default_factory=list)
    variables: Dict[str, str] = field(default_factory=dict)
    mitre_techniques: List[str] = field(default_factory=list)
    target_platform: str = ""
    difficulty: str = "intermediate"
    estimated_time_minutes: int = 0
    confidence_score: float = 0.0
    author: str = ""
    created_at: float = 0.0
    is_validated: bool = False
    validation_score: float = 0.0


@dataclass
class OptimizationSuggestion:
    """Template optimization suggestion.

    Attributes:
        suggestion_id: Unique suggestion identifier
        template_id: Template identifier
        step_id: Step identifier (if applicable)
        optimization_type: Type of optimization
        description: Suggestion description
        current_value: Current value
        suggested_value: Suggested value
        expected_improvement: Expected improvement percentage
        confidence: Suggestion confidence (0-100)
        is_applied: Whether suggestion has been applied
    """
    suggestion_id: str = ""
    template_id: str = ""
    step_id: str = ""
    optimization_type: OptimizationType = OptimizationType.STEP_REPLACEMENT
    description: str = ""
    current_value: str = ""
    suggested_value: str = ""
    expected_improvement: float = 0.0
    confidence: float = 0.0
    is_applied: bool = False


@dataclass
class OperationRecord:
    """Recorded operation for AI analysis.

    Attributes:
        operation_id: Unique operation identifier
        operation_type: Type of operation
        timestamp: Operation timestamp
        target: Target URL/IP
        command: Command executed
        output: Command output
        success: Whether operation was successful
        duration_ms: Operation duration
        is_redundant: Whether operation is redundant
        is_core_step: Whether operation is core attack step
    """
    operation_id: str = ""
    operation_type: str = ""
    timestamp: float = 0.0
    target: str = ""
    command: str = ""
    output: str = ""
    success: bool = False
    duration_ms: float = 0.0
    is_redundant: bool = False
    is_core_step: bool = False


class TemplateAIGenerator:
    """AI-driven template generator for automatic template creation and optimization.

    Converts real-world operations to templates, generates templates from
    natural language descriptions, and provides intelligent optimization
    suggestions based on execution history.
    """

    ATTACK_CHAIN_PATTERNS = {
        "web_exploitation": {
            "patterns": ["nmap", "sqlmap", "nikto", "dirb", "gobuster"],
            "description": "Web application exploitation chain",
            "mitre_ids": ["T1595", "T1190", "T1059"],
        },
        "lateral_movement": {
            "patterns": ["psexec", "wmi", "smbexec", "mimikatz", "pass-the-hash"],
            "description": "Windows lateral movement chain",
            "mitre_ids": ["T1021", "T1550", "T1003"],
        },
        "privilege_escalation": {
            "patterns": ["sudo", "kernel exploit", "token", "uac bypass", "alwaysinstall"],
            "description": "Privilege escalation chain",
            "mitre_ids": ["T1068", "T1548", "T1134"],
        },
        "domain_attack": {
            "patterns": ["kerberoasting", "as-rep", "dcsync", "golden ticket", "silver ticket"],
            "description": "Active Directory attack chain",
            "mitre_ids": ["T1558", "T1550", "T1003"],
        },
    }

    def __init__(
        self,
        storage_path: str = "",
        ai_callback: Optional[Callable[[str, Dict[str, Any]], Coroutine[Any, Any, Dict[str, Any]]]] = None,
    ) -> None:
        """Initialize template AI generator.

        Args:
            storage_path: Directory path for storage.
            ai_callback: Optional async callback for AI model calls.
        """
        self.storage_path = storage_path
        self._ai_callback = ai_callback
        self._generated_templates: Dict[str, GeneratedTemplate] = {}
        self._optimization_suggestions: Dict[str, List[OptimizationSuggestion]] = {}
        self._execution_history: Dict[str, List[Dict[str, Any]]] = {}

        if storage_path:
            os.makedirs(storage_path, exist_ok=True)
            self._load_data()

    async def operations_to_template(
        self,
        operations: List[Dict[str, Any]],
        author: str = "",
        name: str = "",
    ) -> GeneratedTemplate:
        """Convert real-world operations to template.

        Automatically analyzes operation sequences, identifies complete
        attack chains, removes redundant operations, and generates
        a structured template.

        Args:
            operations: List of operation records.
            author: Template author.
            name: Template name.

        Returns:
            Generated template.
        """
        template_id = f"ai_ops_{int(time.time())}"

        core_steps = self._identify_core_steps(operations)
        descriptions = await self._generate_step_descriptions(core_steps)
        variables = self._extract_variables(core_steps)
        mitre_techniques = self._detect_mitre_techniques(core_steps)

        steps = []
        for i, (op, desc) in enumerate(zip(core_steps, descriptions)):
            step = AttackChainStep(
                step_id=f"{template_id}_step_{i + 1}",
                step_number=i + 1,
                action=self._classify_action(op.get("operation_type", "")),
                name=desc.get("name", f"Step {i + 1}"),
                description=desc.get("description", ""),
                payload=op.get("payload", {}),
                mitre_technique_id=desc.get("mitre_id", ""),
                expected_output=op.get("expected_output", ""),
                success_rate=op.get("success_rate", 0.0),
                is_critical=desc.get("is_critical", False),
                alternatives=desc.get("alternatives", []),
            )
            steps.append(step)

        template = GeneratedTemplate(
            template_id=template_id,
            name=name or f"Auto-generated from {len(operations)} operations",
            description=f"Template generated from {len(operations)} recorded operations, {len(core_steps)} core steps identified",
            source=GenerationSource.REAL_OPERATIONS,
            steps=steps,
            variables=variables,
            mitre_techniques=mitre_techniques,
            target_platform=self._detect_platform(core_steps),
            difficulty=self._estimate_difficulty(steps),
            estimated_time_minutes=len(steps) * 5,
            confidence_score=self._calculate_confidence(core_steps, operations),
            author=author,
            created_at=time.time(),
        )

        self._generated_templates[template_id] = template
        self._save_data()

        return template

    async def natural_language_to_template(
        self,
        description: str,
        author: str = "",
        target_platform: str = "",
    ) -> GeneratedTemplate:
        """Generate template from natural language description.

        Users describe attack goals in natural language, AI generates
        complete attack chains with MITRE ATT&CK mapping.

        Args:
            description: Natural language description of attack goal.
            author: Template author.
            target_platform: Target platform.

        Returns:
            Generated template.
        """
        template_id = f"ai_nl_{int(time.time())}"

        ai_prompt = {
            "task": "generate_attack_chain",
            "description": description,
            "target_platform": target_platform,
        }

        ai_result = await self._call_ai_model(ai_prompt)

        steps = []
        for i, step_data in enumerate(ai_result.get("steps", [])):
            step = AttackChainStep(
                step_id=f"{template_id}_step_{i + 1}",
                step_number=i + 1,
                action=step_data.get("action", "custom"),
                name=step_data.get("name", f"Step {i + 1}"),
                description=step_data.get("description", ""),
                payload=step_data.get("payload", {}),
                mitre_technique_id=step_data.get("mitre_id", ""),
                expected_output=step_data.get("expected_output", ""),
                success_rate=step_data.get("success_rate", 0.0),
                is_critical=step_data.get("is_critical", False),
                alternatives=step_data.get("alternatives", []),
            )
            steps.append(step)

        template = GeneratedTemplate(
            template_id=template_id,
            name=ai_result.get("name", f"AI-generated: {description[:50]}"),
            description=ai_result.get("description", description),
            source=GenerationSource.NATURAL_LANGUAGE,
            steps=steps,
            variables=ai_result.get("variables", {}),
            mitre_techniques=ai_result.get("mitre_techniques", []),
            target_platform=target_platform,
            difficulty=ai_result.get("difficulty", "intermediate"),
            estimated_time_minutes=len(steps) * 5,
            confidence_score=ai_result.get("confidence", 70.0),
            author=author,
            created_at=time.time(),
        )

        self._generated_templates[template_id] = template
        self._save_data()

        return template

    async def optimize_template(
        self,
        template_id: str,
        execution_history: Optional[List[Dict[str, Any]]] = None,
    ) -> List[OptimizationSuggestion]:
        """Generate optimization suggestions for template.

        AI analyzes execution history data, identifies low-success
        steps, and recommends alternatives.

        Args:
            template_id: Template identifier.
            execution_history: Optional execution history data.

        Returns:
            List of optimization suggestions.
        """
        template = self._generated_templates.get(template_id)
        if not template:
            return []

        history = execution_history or self._execution_history.get(template_id, [])

        suggestions: List[OptimizationSuggestion] = []

        step_stats = self._analyze_step_stats(template.steps, history)

        for step_id, stats in step_stats.items():
            if stats.get("success_rate", 100) < 70:
                suggestion = OptimizationSuggestion(
                    suggestion_id=f"suggest_{step_id}_{int(time.time())}",
                    template_id=template_id,
                    step_id=step_id,
                    optimization_type=OptimizationType.STEP_REPLACEMENT,
                    description=f"Step {step_id} has {stats['success_rate']:.0f}% success rate. Recommend alternative approach.",
                    current_value=stats.get("current_method", ""),
                    suggested_value=stats.get("alternative_method", ""),
                    expected_improvement=stats.get("expected_improvement", 15.0),
                    confidence=stats.get("confidence", 80.0),
                )
                suggestions.append(suggestion)

            if stats.get("avg_duration", 0) > 60000:
                suggestion = OptimizationSuggestion(
                    suggestion_id=f"suggest_timeout_{step_id}_{int(time.time())}",
                    template_id=template_id,
                    step_id=step_id,
                    optimization_type=OptimizationType.TIMEOUT_OPTIMIZATION,
                    description=f"Step {step_id} average duration is {stats['avg_duration']:.0f}ms. Consider increasing timeout.",
                    current_value=str(stats.get("current_timeout", 30)),
                    suggested_value=str(int(stats["avg_duration"] / 1000) + 30),
                    expected_improvement=10.0,
                    confidence=90.0,
                )
                suggestions.append(suggestion)

        if template_id not in self._optimization_suggestions:
            self._optimization_suggestions[template_id] = []

        self._optimization_suggestions[template_id].extend(suggestions)
        self._save_data()

        return suggestions

    async def validate_template(
        self,
        template_id: str,
        validation_score: float,
    ) -> bool:
        """Mark template as validated.

        Args:
            template_id: Template identifier.
            validation_score: Validation score.

        Returns:
            True if updated successfully.
        """
        template = self._generated_templates.get(template_id)
        if not template:
            return False

        template.is_validated = True
        template.validation_score = validation_score
        self._save_data()

        return True

    async def get_template(self, template_id: str) -> Optional[GeneratedTemplate]:
        """Get generated template.

        Args:
            template_id: Template identifier.

        Returns:
            GeneratedTemplate or None.
        """
        return self._generated_templates.get(template_id)

    async def get_suggestions(self, template_id: str) -> List[OptimizationSuggestion]:
        """Get optimization suggestions for template.

        Args:
            template_id: Template identifier.

        Returns:
            List of OptimizationSuggestion objects.
        """
        return self._optimization_suggestions.get(template_id, [])

    async def apply_suggestion(self, suggestion_id: str) -> bool:
        """Mark suggestion as applied.

        Args:
            suggestion_id: Suggestion identifier.

        Returns:
            True if updated successfully.
        """
        for suggestions in self._optimization_suggestions.values():
            for suggestion in suggestions:
                if suggestion.suggestion_id == suggestion_id:
                    suggestion.is_applied = True
                    self._save_data()
                    return True
        return False

    def _identify_core_steps(self, operations: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Identify core attack steps from operations.

        Removes redundant operations (misoperations, duplicate requests,
        invalid probes) and keeps core attack steps.

        Args:
            operations: List of operation records.

        Returns:
            List of core operation dicts.
        """
        core_steps: List[Dict[str, Any]] = []
        seen_commands: Set[str] = set()

        for op in operations:
            command = op.get("command", "")
            output = op.get("output", "")
            success = op.get("success", False)

            if not success and not op.get("is_recon", False):
                continue

            if command in seen_commands:
                continue

            seen_commands.add(command)

            op["is_core_step"] = self._is_core_step(op)
            core_steps.append(op)

        return core_steps

    def _is_core_step(self, operation: Dict[str, Any]) -> bool:
        """Check if operation is a core attack step.

        Args:
            operation: Operation record.

        Returns:
            True if operation is core step.
        """
        core_indicators = [
            "exploit", "payload", "shell", "reverse", "bind",
            "credential", "password", "hash", "token",
            "privilege", "escalat", "lateral", "persist",
            "exfiltrat", "download", "upload", "exec",
        ]

        command = operation.get("command", "").lower()
        output = operation.get("output", "").lower()
        op_type = operation.get("operation_type", "").lower()

        for indicator in core_indicators:
            if indicator in command or indicator in output or indicator in op_type:
                return True

        return False

    async def _generate_step_descriptions(
        self,
        steps: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """Generate natural language descriptions for steps.

        Args:
            steps: List of core operation dicts.

        Returns:
            List of description dicts.
        """
        descriptions: List[Dict[str, Any]] = []

        for step in steps:
            command = step.get("command", "")
            op_type = step.get("operation_type", "")
            output = step.get("output", "")

            description = self._generate_description(command, op_type, output)

            descriptions.append({
                "name": description.get("name", f"Step"),
                "description": description.get("description", ""),
                "mitre_id": description.get("mitre_id", ""),
                "is_critical": description.get("is_critical", False),
                "alternatives": description.get("alternatives", []),
            })

        return descriptions

    def _generate_description(
        self,
        command: str,
        op_type: str,
        output: str,
    ) -> Dict[str, Any]:
        """Generate natural language description for single step.

        Args:
            command: Command executed.
            op_type: Operation type.
            output: Command output.

        Returns:
            Description dict.
        """
        command_lower = command.lower()

        if "nmap" in command_lower:
            return {
                "name": "Port Scan",
                "description": f"Use Nmap to scan target ports and services",
                "mitre_id": "T1595",
                "is_critical": False,
                "alternatives": ["masscan", "rustscan"],
            }
        elif "sqlmap" in command_lower:
            return {
                "name": "SQL Injection Test",
                "description": f"Use SQLMap to test for SQL injection vulnerabilities",
                "mitre_id": "T1190",
                "is_critical": True,
                "alternatives": ["manual injection", "Burp Suite"],
            }
        elif "mimikatz" in command_lower or "sekurlsa" in command_lower:
            return {
                "name": "Credential Dumping",
                "description": f"Use Mimikatz to extract credentials from memory",
                "mitre_id": "T1003",
                "is_critical": True,
                "alternatives": ["Procdump", "LSASS dump"],
            }
        elif "psexec" in command_lower or "wmi" in command_lower:
            return {
                "name": "Lateral Movement",
                "description": f"Use remote execution for lateral movement",
                "mitre_id": "T1021",
                "is_critical": True,
                "alternatives": ["SMBExec", "WinRM", "DCOM"],
            }
        else:
            return {
                "name": f"Execute {op_type}",
                "description": f"Execute {op_type} operation",
                "mitre_id": "",
                "is_critical": False,
                "alternatives": [],
            }

    def _extract_variables(self, steps: List[Dict[str, Any]]) -> Dict[str, str]:
        """Extract template variables from steps.

        Args:
            steps: List of core operation dicts.

        Returns:
            Dict of variable names and default values.
        """
        variables: Dict[str, str] = {}
        ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        url_pattern = re.compile(r'https?://[^\s/$.?#].[^\s]*', re.IGNORECASE)

        for step in steps:
            command = step.get("command", "")
            output = step.get("output", "")
            target = step.get("target", "")

            for text in [command, output, target]:
                for match in ip_pattern.finditer(text):
                    ip = match.group()
                    if ip not in ["127.0.0.1", "0.0.0.0"]:
                        variables["target_ip"] = ip

                for match in url_pattern.finditer(text):
                    url = match.group()
                    variables["target_url"] = url

        return variables

    def _detect_mitre_techniques(self, steps: List[Dict[str, Any]]) -> List[str]:
        """Detect MITRE ATT&CK techniques from steps.

        Args:
            steps: List of core operation dicts.

        Returns:
            List of MITRE ATT&CK technique IDs.
        """
        techniques: Set[str] = set()

        for step in steps:
            command = step.get("command", "").lower()
            op_type = step.get("operation_type", "").lower()

            for chain_name, chain_info in self.ATTACK_CHAIN_PATTERNS.items():
                for pattern in chain_info["patterns"]:
                    if pattern in command or pattern in op_type:
                        techniques.update(chain_info["mitre_ids"])

        return list(techniques)

    def _detect_platform(self, steps: List[Dict[str, Any]]) -> str:
        """Detect target platform from steps.

        Args:
            steps: List of core operation dicts.

        Returns:
            Detected platform.
        """
        windows_indicators = ["windows", "psexec", "wmi", "mimikatz", "powershell", "ntlm"]
        linux_indicators = ["linux", "ssh", "bash", "sudo", "cron", "/etc/passwd"]
        web_indicators = ["http", "https", "web", "sql", "xss", "csrf"]

        for step in steps:
            text = f"{step.get('command', '')} {step.get('output', '')}".lower()

            for indicator in windows_indicators:
                if indicator in text:
                    return "windows"

            for indicator in linux_indicators:
                if indicator in text:
                    return "linux"

            for indicator in web_indicators:
                if indicator in text:
                    return "web"

        return "unknown"

    def _estimate_difficulty(self, steps: List[AttackChainStep]) -> str:
        """Estimate template difficulty.

        Args:
            steps: List of attack chain steps.

        Returns:
            Difficulty level.
        """
        critical_count = sum(1 for s in steps if s.is_critical)

        if len(steps) <= 3 and critical_count == 0:
            return "beginner"
        elif len(steps) <= 5 and critical_count <= 2:
            return "intermediate"
        elif len(steps) <= 10:
            return "advanced"
        else:
            return "expert"

    def _calculate_confidence(
        self,
        core_steps: List[Dict[str, Any]],
        all_operations: List[Dict[str, Any]],
    ) -> float:
        """Calculate AI confidence score.

        Args:
            core_steps: List of core steps.
            all_operations: List of all operations.

        Returns:
            Confidence score (0-100).
        """
        if not all_operations:
            return 0.0

        success_rate = sum(1 for op in all_operations if op.get("success", False)) / len(all_operations)
        core_ratio = len(core_steps) / max(len(all_operations), 1)

        confidence = (success_rate * 50) + (core_ratio * 30) + 20

        return min(confidence, 100.0)

    def _analyze_step_stats(
        self,
        steps: List[AttackChainStep],
        history: List[Dict[str, Any]],
    ) -> Dict[str, Dict[str, Any]]:
        """Analyze step statistics from execution history.

        Args:
            steps: List of attack chain steps.
            history: Execution history data.

        Returns:
            Dict of step stats.
        """
        stats: Dict[str, Dict[str, Any]] = {}

        for step in steps:
            step_history = [h for h in history if h.get("step_id") == step.step_id]

            if step_history:
                success_count = sum(1 for h in step_history if h.get("success", False))
                total_count = len(step_history)
                avg_duration = sum(h.get("duration_ms", 0) for h in step_history) / total_count

                stats[step.step_id] = {
                    "success_rate": (success_count / total_count) * 100,
                    "avg_duration": avg_duration,
                    "total_executions": total_count,
                    "current_method": step.name,
                    "alternative_method": step.alternatives[0] if step.alternatives else "",
                    "expected_improvement": 15.0,
                    "confidence": 80.0,
                    "current_timeout": step.payload.get("timeout", 30),
                }
            else:
                stats[step.step_id] = {
                    "success_rate": step.success_rate * 100,
                    "avg_duration": 0,
                    "total_executions": 0,
                    "current_method": step.name,
                    "alternative_method": step.alternatives[0] if step.alternatives else "",
                    "expected_improvement": 10.0,
                    "confidence": 50.0,
                    "current_timeout": step.payload.get("timeout", 30),
                }

        return stats

    async def _call_ai_model(self, prompt: Dict[str, Any]) -> Dict[str, Any]:
        """Call AI model for template generation.

        Args:
            prompt: AI prompt data.

        Returns:
            AI response dict.
        """
        if self._ai_callback:
            return await self._ai_callback("generate_template", prompt)

        return {
            "name": f"AI-generated: {prompt.get('description', '')[:50]}",
            "description": prompt.get("description", ""),
            "steps": [],
            "variables": {},
            "mitre_techniques": [],
            "difficulty": "intermediate",
            "confidence": 70.0,
        }

    def _classify_action(self, operation_type: str) -> str:
        """Classify operation type to action.

        Args:
            operation_type: Operation type string.

        Returns:
            Action type string.
        """
        type_map = {
            "reconnaissance": "reconnaissance",
            "scanning": "scanning",
            "exploitation": "exploitation",
            "post_exploitation": "post_exploitation",
            "lateral_movement": "lateral_movement",
            "privilege_escalation": "privilege_escalation",
            "persistence": "persistence",
            "data_exfiltration": "data_exfiltration",
        }

        return type_map.get(operation_type, "custom")

    def _load_data(self) -> None:
        """Load data from storage."""
        if not self.storage_path:
            return

        try:
            data_file = os.path.join(self.storage_path, "ai_generator_data.json")
            if os.path.exists(data_file):
                with open(data_file, "r", encoding="utf-8") as f:
                    data = json.load(f)

                    for tpl_id, tpl_data in data.get("generated_templates", {}).items():
                        steps = []
                        for step_data in tpl_data.get("steps", []):
                            steps.append(AttackChainStep(
                                step_id=step_data.get("step_id", ""),
                                step_number=step_data.get("step_number", 0),
                                action=step_data.get("action", ""),
                                name=step_data.get("name", ""),
                                description=step_data.get("description", ""),
                                payload=step_data.get("payload", {}),
                                mitre_technique_id=step_data.get("mitre_technique_id", ""),
                                expected_output=step_data.get("expected_output", ""),
                                success_rate=step_data.get("success_rate", 0.0),
                                is_critical=step_data.get("is_critical", False),
                                alternatives=step_data.get("alternatives", []),
                            ))

                        template = GeneratedTemplate(
                            template_id=tpl_id,
                            name=tpl_data.get("name", ""),
                            description=tpl_data.get("description", ""),
                            source=GenerationSource(tpl_data.get("source", "real_operations")),
                            steps=steps,
                            variables=tpl_data.get("variables", {}),
                            mitre_techniques=tpl_data.get("mitre_techniques", []),
                            target_platform=tpl_data.get("target_platform", ""),
                            difficulty=tpl_data.get("difficulty", "intermediate"),
                            estimated_time_minutes=tpl_data.get("estimated_time_minutes", 0),
                            confidence_score=tpl_data.get("confidence_score", 0.0),
                            author=tpl_data.get("author", ""),
                            created_at=tpl_data.get("created_at", 0.0),
                            is_validated=tpl_data.get("is_validated", False),
                            validation_score=tpl_data.get("validation_score", 0.0),
                        )

                        self._generated_templates[template.template_id] = template

                    for tpl_id, suggestions in data.get("optimization_suggestions", {}).items():
                        suggestion_list = []
                        for sug_data in suggestions:
                            suggestion_list.append(OptimizationSuggestion(
                                suggestion_id=sug_data.get("suggestion_id", ""),
                                template_id=sug_data.get("template_id", ""),
                                step_id=sug_data.get("step_id", ""),
                                optimization_type=OptimizationType(sug_data.get("optimization_type", "step_replacement")),
                                description=sug_data.get("description", ""),
                                current_value=sug_data.get("current_value", ""),
                                suggested_value=sug_data.get("suggested_value", ""),
                                expected_improvement=sug_data.get("expected_improvement", 0.0),
                                confidence=sug_data.get("confidence", 0.0),
                                is_applied=sug_data.get("is_applied", False),
                            ))
                        self._optimization_suggestions[tpl_id] = suggestion_list

                    self._execution_history = data.get("execution_history", {})

        except Exception as e:
            logger.error(f"Failed to load AI generator data: {e}")

    def _save_data(self) -> None:
        """Save data to storage."""
        if not self.storage_path:
            return

        try:
            data_file = os.path.join(self.storage_path, "ai_generator_data.json")

            data = {
                "generated_templates": {
                    tpl_id: {
                        "name": t.name,
                        "description": t.description,
                        "source": t.source.value,
                        "steps": [
                            {
                                "step_id": s.step_id,
                                "step_number": s.step_number,
                                "action": s.action,
                                "name": s.name,
                                "description": s.description,
                                "payload": s.payload,
                                "mitre_technique_id": s.mitre_technique_id,
                                "expected_output": s.expected_output,
                                "success_rate": s.success_rate,
                                "is_critical": s.is_critical,
                                "alternatives": s.alternatives,
                            }
                            for s in t.steps
                        ],
                        "variables": t.variables,
                        "mitre_techniques": t.mitre_techniques,
                        "target_platform": t.target_platform,
                        "difficulty": t.difficulty,
                        "estimated_time_minutes": t.estimated_time_minutes,
                        "confidence_score": t.confidence_score,
                        "author": t.author,
                        "created_at": t.created_at,
                        "is_validated": t.is_validated,
                        "validation_score": t.validation_score,
                    }
                    for tpl_id, t in self._generated_templates.items()
                },
                "optimization_suggestions": {
                    tpl_id: [
                        {
                            "suggestion_id": s.suggestion_id,
                            "template_id": s.template_id,
                            "step_id": s.step_id,
                            "optimization_type": s.optimization_type.value,
                            "description": s.description,
                            "current_value": s.current_value,
                            "suggested_value": s.suggested_value,
                            "expected_improvement": s.expected_improvement,
                            "confidence": s.confidence,
                            "is_applied": s.is_applied,
                        }
                        for s in suggestions
                    ]
                    for tpl_id, suggestions in self._optimization_suggestions.items()
                },
                "execution_history": self._execution_history,
            }

            with open(data_file, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)

        except Exception as e:
            logger.error(f"Failed to save AI generator data: {e}")
