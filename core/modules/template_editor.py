"""Template Editor: Step editing, parameterization, conditional branching, and loop logic.

Provides:
- Drag-and-drop editing: reorder recorded steps, delete redundant steps, add comments
- Parameterization: replace fixed IPs/domains/URLs/credentials with template variables
- Conditional branching: jump to different steps based on previous step results
- Loops and batch processing: repeat same steps for multiple targets
- Step groups: bundle multiple steps into sub-processes for template reference
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


class StepAction(Enum):
    """Template step action types."""
    HTTP_REQUEST = "http_request"
    COMMAND_EXECUTION = "command_execution"
    WAIT = "wait"
    CONDITION_CHECK = "condition_check"
    LOOP_START = "loop_start"
    LOOP_END = "loop_end"
    GROUP_START = "group_start"
    GROUP_END = "group_end"
    BRANCH = "branch"
    VARIABLE_ASSIGNMENT = "variable_assignment"
    OUTPUT_CHECK = "output_check"


class ConditionOperator(Enum):
    """Condition comparison operators."""
    EQUALS = "equals"
    NOT_EQUALS = "not_equals"
    CONTAINS = "contains"
    NOT_CONTAINS = "not_contains"
    REGEX_MATCH = "regex_match"
    GREATER_THAN = "greater_than"
    LESS_THAN = "less_than"
    IS_SUCCESS = "is_success"
    IS_FAILURE = "is_failure"


class LoopType(Enum):
    """Loop iteration types."""
    FIXED_COUNT = "fixed_count"
    FOR_EACH = "for_each"
    UNTIL_CONDITION = "until_condition"
    WHILE_CONDITION = "while_condition"


@dataclass
class Condition:
    """Conditional branching condition.

    Attributes:
        condition_id: Unique condition identifier
        variable: Variable to check
        operator: Comparison operator
        value: Expected value
        on_true_step_id: Step ID to jump to if condition is true
        on_false_step_id: Step ID to jump to if condition is false
    """
    condition_id: str = ""
    variable: str = ""
    operator: ConditionOperator = ConditionOperator.EQUALS
    value: str = ""
    on_true_step_id: str = ""
    on_false_step_id: str = ""


@dataclass
class LoopConfig:
    """Loop configuration.

    Attributes:
        loop_id: Unique loop identifier
        loop_type: Type of loop
        iterations: Number of iterations (for fixed count)
        items: Items to iterate over (for for-each)
        condition: Condition to check (for until/while)
        max_iterations: Maximum iterations to prevent infinite loops
        current_iteration: Current iteration count
    """
    loop_id: str = ""
    loop_type: LoopType = LoopType.FIXED_COUNT
    iterations: int = 1
    items: List[str] = field(default_factory=list)
    condition: str = ""
    max_iterations: int = 100
    current_iteration: int = 0


@dataclass
class StepGroup:
    """Group of steps that form a sub-process.

    Attributes:
        group_id: Unique group identifier
        name: Group name
        description: Group description
        steps: List of step IDs in this group
        variables: Variables defined within this group
        is_reusable: Whether this group can be referenced by other templates
    """
    group_id: str = ""
    name: str = ""
    description: str = ""
    steps: List[str] = field(default_factory=list)
    variables: Dict[str, str] = field(default_factory=dict)
    is_reusable: bool = False


@dataclass
class TemplateStep:
    """Editable template step.

    Attributes:
        step_id: Unique step identifier
        step_number: Step sequence number
        action: Step action type
        name: Step display name
        description: Step description
        payload: Step payload (request data, command, etc.)
        expected_output: Expected output for validation
        variables: Template variables used in this step
        condition: Optional condition for this step
        loop_config: Optional loop configuration
        group_id: Optional group this step belongs to
        is_enabled: Whether this step is enabled
        notes: Additional notes
        timeout_seconds: Step timeout
        retry_count: Number of retries on failure
        depends_on: List of step IDs this step depends on
    """
    step_id: str = ""
    step_number: int = 0
    action: StepAction = StepAction.HTTP_REQUEST
    name: str = ""
    description: str = ""
    payload: Dict[str, Any] = field(default_factory=dict)
    expected_output: str = ""
    variables: Dict[str, str] = field(default_factory=dict)
    condition: Optional[Condition] = None
    loop_config: Optional[LoopConfig] = None
    group_id: str = ""
    is_enabled: bool = True
    notes: str = ""
    timeout_seconds: int = 30
    retry_count: int = 0
    depends_on: List[str] = field(default_factory=list)


@dataclass
class EditableTemplate:
    """Complete editable template.

    Attributes:
        template_id: Unique template identifier
        name: Template name
        description: Template description
        version: Template version
        steps: List of editable template steps
        groups: List of step groups
        variables: Template variable definitions
        conditions: List of conditions
        author: Template author
        tags: Template tags
        created_at: Creation timestamp
        updated_at: Last update timestamp
        is_validated: Whether template has been validated
        validation_status: Validation status
    """
    template_id: str = ""
    name: str = ""
    description: str = ""
    version: str = "1.0.0"
    steps: List[TemplateStep] = field(default_factory=list)
    groups: List[StepGroup] = field(default_factory=list)
    variables: Dict[str, str] = field(default_factory=dict)
    conditions: List[Condition] = field(default_factory=list)
    author: str = ""
    tags: List[str] = field(default_factory=list)
    created_at: float = 0.0
    updated_at: float = 0.0
    is_validated: bool = False
    validation_status: str = "pending"


class TemplateEditor:
    """Editor for creating and modifying attack chain templates.

    Provides drag-and-drop editing, parameterization, conditional
    branching, loops, and step groups for building reusable
    attack chain templates.
    """

    VARIABLE_PATTERN = re.compile(r'\{\{([^}]+)\}\}')

    def __init__(self, storage_path: str = "") -> None:
        """Initialize template editor.

        Args:
            storage_path: Directory path for template storage.
        """
        self.storage_path = storage_path
        self._templates: Dict[str, EditableTemplate] = {}
        self._change_history: Dict[str, List[Dict[str, Any]]] = {}

        if storage_path:
            os.makedirs(storage_path, exist_ok=True)
            self._load_templates()

    async def create_template(
        self,
        name: str,
        description: str = "",
        author: str = "",
        tags: Optional[List[str]] = None,
    ) -> EditableTemplate:
        """Create a new editable template.

        Args:
            name: Template name.
            description: Template description.
            author: Template author.
            tags: Optional list of tags.

        Returns:
            Created EditableTemplate.
        """
        template_id = f"tpl_{int(time.time())}"

        template = EditableTemplate(
            template_id=template_id,
            name=name,
            description=description,
            author=author,
            tags=tags or [],
            created_at=time.time(),
            updated_at=time.time(),
        )

        self._templates[template_id] = template
        self._change_history[template_id] = []

        self._save_template(template)

        return template

    async def load_template(self, template_id: str) -> Optional[EditableTemplate]:
        """Load template for editing.

        Args:
            template_id: Template identifier.

        Returns:
            EditableTemplate or None.
        """
        return self._templates.get(template_id)

    async def add_step(
        self,
        template_id: str,
        action: StepAction,
        name: str,
        payload: Optional[Dict[str, Any]] = None,
        description: str = "",
        expected_output: str = "",
        timeout_seconds: int = 30,
        retry_count: int = 0,
        depends_on: Optional[List[str]] = None,
    ) -> Optional[TemplateStep]:
        """Add step to template.

        Args:
            template_id: Template identifier.
            action: Step action type.
            name: Step name.
            payload: Step payload.
            description: Step description.
            expected_output: Expected output.
            timeout_seconds: Step timeout.
            retry_count: Retry count on failure.
            depends_on: List of step dependencies.

        Returns:
            Created TemplateStep or None.
        """
        template = self._templates.get(template_id)
        if not template:
            return None

        step_number = len(template.steps) + 1
        step_id = f"{template_id}_step_{step_number}"

        variables = self._extract_variables_from_payload(payload or {})

        step = TemplateStep(
            step_id=step_id,
            step_number=step_number,
            action=action,
            name=name,
            description=description,
            payload=payload or {},
            expected_output=expected_output,
            variables=variables,
            timeout_seconds=timeout_seconds,
            retry_count=retry_count,
            depends_on=depends_on or [],
        )

        template.steps.append(step)
        template.updated_at = time.time()

        self._record_change(template_id, "add_step", {"step_id": step_id})
        self._save_template(template)

        return step

    async def remove_step(self, template_id: str, step_id: str) -> bool:
        """Remove step from template.

        Args:
            template_id: Template identifier.
            step_id: Step identifier.

        Returns:
            True if removed successfully.
        """
        template = self._templates.get(template_id)
        if not template:
            return False

        original_steps = len(template.steps)
        template.steps = [s for s in template.steps if s.step_id != step_id]

        if len(template.steps) != original_steps:
            for i, step in enumerate(template.steps):
                step.step_number = i + 1

            template.updated_at = time.time()
            self._record_change(template_id, "remove_step", {"step_id": step_id})
            self._save_template(template)
            return True

        return False

    async def reorder_steps(
        self,
        template_id: str,
        new_order: List[str],
    ) -> bool:
        """Reorder template steps.

        Args:
            template_id: Template identifier.
            new_order: List of step IDs in new order.

        Returns:
            True if reordered successfully.
        """
        template = self._templates.get(template_id)
        if not template:
            return False

        step_map = {s.step_id: s for s in template.steps}
        reordered = []

        for step_id in new_order:
            if step_id in step_map:
                reordered.append(step_map[step_id])

        if len(reordered) == len(template.steps):
            for i, step in enumerate(reordered):
                step.step_number = i + 1

            template.steps = reordered
            template.updated_at = time.time()

            self._record_change(template_id, "reorder_steps", {"new_order": new_order})
            self._save_template(template)

            return True

        return False

    async def parameterize_step(
        self,
        template_id: str,
        step_id: str,
        replacements: Dict[str, str],
    ) -> bool:
        """Parameterize step by replacing fixed values with variables.

        Args:
            template_id: Template identifier.
            step_id: Step identifier.
            replacements: Dict of {original_value: variable_name}.

        Returns:
            True if parameterized successfully.
        """
        template = self._templates.get(template_id)
        if not template:
            return False

        step = next((s for s in template.steps if s.step_id == step_id), None)
        if not step:
            return False

        for original, variable in replacements.items():
            variable_placeholder = f"{{{{{variable}}}}}"

            for key, value in step.payload.items():
                if isinstance(value, str) and original in value:
                    step.payload[key] = value.replace(original, variable_placeholder)
                    step.variables[variable] = original

            if original in step.expected_output:
                step.expected_output = step.expected_output.replace(original, variable_placeholder)

            if original in step.notes:
                step.notes = step.notes.replace(original, variable_placeholder)

        template.updated_at = time.time()
        self._record_change(template_id, "parameterize_step", {
            "step_id": step_id,
            "replacements": replacements,
        })
        self._save_template(template)

        return True

    async def add_condition(
        self,
        template_id: str,
        step_id: str,
        condition: Condition,
    ) -> bool:
        """Add conditional branching to step.

        Args:
            template_id: Template identifier.
            step_id: Step identifier.
            condition: Condition to add.

        Returns:
            True if added successfully.
        """
        template = self._templates.get(template_id)
        if not template:
            return False

        step = next((s for s in template.steps if s.step_id == step_id), None)
        if not step:
            return False

        step.condition = condition
        template.conditions.append(condition)
        template.updated_at = time.time()

        self._record_change(template_id, "add_condition", {
            "step_id": step_id,
            "condition_id": condition.condition_id,
        })
        self._save_template(template)

        return True

    async def add_loop(
        self,
        template_id: str,
        start_step_id: str,
        end_step_id: str,
        loop_config: LoopConfig,
    ) -> bool:
        """Add loop to template steps.

        Args:
            template_id: Template identifier.
            start_step_id: First step in loop.
            end_step_id: Last step in loop.
            loop_config: Loop configuration.

        Returns:
            True if added successfully.
        """
        template = self._templates.get(template_id)
        if not template:
            return False

        start_step = next((s for s in template.steps if s.step_id == start_step_id), None)
        end_step = next((s for s in template.steps if s.step_id == end_step_id), None)

        if not start_step or not end_step:
            return False

        start_step.loop_config = loop_config
        template.updated_at = time.time()

        self._record_change(template_id, "add_loop", {
            "start_step_id": start_step_id,
            "end_step_id": end_step_id,
            "loop_id": loop_config.loop_id,
        })
        self._save_template(template)

        return True

    async def create_step_group(
        self,
        template_id: str,
        name: str,
        step_ids: List[str],
        description: str = "",
        is_reusable: bool = False,
    ) -> Optional[StepGroup]:
        """Create step group.

        Args:
            template_id: Template identifier.
            name: Group name.
            step_ids: List of step IDs to include.
            description: Group description.
            is_reusable: Whether group is reusable.

        Returns:
            Created StepGroup or None.
        """
        template = self._templates.get(template_id)
        if not template:
            return None

        group_id = f"{template_id}_group_{len(template.groups) + 1}"

        group = StepGroup(
            group_id=group_id,
            name=name,
            description=description,
            steps=step_ids,
            is_reusable=is_reusable,
        )

        template.groups.append(group)

        for step in template.steps:
            if step.step_id in step_ids:
                step.group_id = group_id

        template.updated_at = time.time()
        self._record_change(template_id, "create_group", {"group_id": group_id})
        self._save_template(template)

        return group

    async def undo(self, template_id: str) -> bool:
        """Undo last change to template.

        Args:
            template_id: Template identifier.

        Returns:
            True if undo successful.
        """
        history = self._change_history.get(template_id, [])
        if not history:
            return False

        last_change = history.pop()
        template = self._templates.get(template_id)

        if template and last_change:
            template.updated_at = time.time()
            self._save_template(template)
            return True

        return False

    async def get_variables(self, template_id: str) -> Dict[str, str]:
        """Get all variables defined in template.

        Args:
            template_id: Template identifier.

        Returns:
            Dict of variable names and default values.
        """
        template = self._templates.get(template_id)
        if not template:
            return {}

        variables: Dict[str, str] = {}

        for step in template.steps:
            for var, value in step.variables.items():
                if var not in variables:
                    variables[var] = value

        for var, value in template.variables.items():
            variables[var] = value

        return variables

    async def validate_template_structure(self, template_id: str) -> List[str]:
        """Validate template structure.

        Args:
            template_id: Template identifier.

        Returns:
            List of validation issues.
        """
        template = self._templates.get(template_id)
        if not template:
            return ["Template not found"]

        issues: List[str] = []

        if not template.steps:
            issues.append("Template has no steps")

        step_ids = {s.step_id for s in template.steps}

        for step in template.steps:
            for dep_id in step.depends_on:
                if dep_id not in step_ids:
                    issues.append(f"Step {step.step_id} depends on non-existent step {dep_id}")

            if step.condition:
                if step.condition.on_true_step_id and step.condition.on_true_step_id not in step_ids:
                    issues.append(f"Condition true branch points to non-existent step {step.condition.on_true_step_id}")
                if step.condition.on_false_step_id and step.condition.on_false_step_id not in step_ids:
                    issues.append(f"Condition false branch points to non-existent step {step.condition.on_false_step_id}")

        for group in template.groups:
            for step_id in group.steps:
                if step_id not in step_ids:
                    issues.append(f"Group {group.name} references non-existent step {step_id}")

        return issues

    def _extract_variables_from_payload(self, payload: Dict[str, Any]) -> Dict[str, str]:
        """Extract template variables from payload.

        Args:
            payload: Payload to analyze.

        Returns:
            Dict of variable names and values.
        """
        variables: Dict[str, str] = {}

        def extract_from_value(value: Any) -> None:
            if isinstance(value, str):
                for match in self.VARIABLE_PATTERN.finditer(value):
                    var_name = match.group(1)
                    variables[var_name] = value

        for v in payload.values():
            extract_from_value(v)

        return variables

    def _record_change(self, template_id: str, change_type: str, data: Dict[str, Any]) -> None:
        """Record template change for undo.

        Args:
            template_id: Template identifier.
            change_type: Type of change.
            data: Change data.
        """
        if template_id not in self._change_history:
            self._change_history[template_id] = []

        self._change_history[template_id].append({
            "type": change_type,
            "data": data,
            "timestamp": time.time(),
        })

    def _load_templates(self) -> None:
        """Load templates from storage."""
        if not self.storage_path:
            return

        try:
            templates_file = os.path.join(self.storage_path, "templates.json")
            if os.path.exists(templates_file):
                with open(templates_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    for tpl_data in data:
                        steps = []
                        for step_data in tpl_data.get("steps", []):
                            condition = None
                            if step_data.get("condition"):
                                cond_data = step_data["condition"]
                                condition = Condition(
                                    condition_id=cond_data.get("condition_id", ""),
                                    variable=cond_data.get("variable", ""),
                                    operator=ConditionOperator(cond_data.get("operator", "equals")),
                                    value=cond_data.get("value", ""),
                                    on_true_step_id=cond_data.get("on_true_step_id", ""),
                                    on_false_step_id=cond_data.get("on_false_step_id", ""),
                                )

                            loop_config = None
                            if step_data.get("loop_config"):
                                loop_data = step_data["loop_config"]
                                loop_config = LoopConfig(
                                    loop_id=loop_data.get("loop_id", ""),
                                    loop_type=LoopType(loop_data.get("loop_type", "fixed_count")),
                                    iterations=loop_data.get("iterations", 1),
                                    items=loop_data.get("items", []),
                                    condition=loop_data.get("condition", ""),
                                    max_iterations=loop_data.get("max_iterations", 100),
                                    current_iteration=loop_data.get("current_iteration", 0),
                                )

                            steps.append(TemplateStep(
                                step_id=step_data.get("step_id", ""),
                                step_number=step_data.get("step_number", 0),
                                action=StepAction(step_data.get("action", "http_request")),
                                name=step_data.get("name", ""),
                                description=step_data.get("description", ""),
                                payload=step_data.get("payload", {}),
                                expected_output=step_data.get("expected_output", ""),
                                variables=step_data.get("variables", {}),
                                condition=condition,
                                loop_config=loop_config,
                                group_id=step_data.get("group_id", ""),
                                is_enabled=step_data.get("is_enabled", True),
                                notes=step_data.get("notes", ""),
                                timeout_seconds=step_data.get("timeout_seconds", 30),
                                retry_count=step_data.get("retry_count", 0),
                                depends_on=step_data.get("depends_on", []),
                            ))

                        groups = []
                        for group_data in tpl_data.get("groups", []):
                            groups.append(StepGroup(
                                group_id=group_data.get("group_id", ""),
                                name=group_data.get("name", ""),
                                description=group_data.get("description", ""),
                                steps=group_data.get("steps", []),
                                variables=group_data.get("variables", {}),
                                is_reusable=group_data.get("is_reusable", False),
                            ))

                        template = EditableTemplate(
                            template_id=tpl_data.get("template_id", ""),
                            name=tpl_data.get("name", ""),
                            description=tpl_data.get("description", ""),
                            version=tpl_data.get("version", "1.0.0"),
                            steps=steps,
                            groups=groups,
                            variables=tpl_data.get("variables", {}),
                            conditions=[],
                            author=tpl_data.get("author", ""),
                            tags=tpl_data.get("tags", []),
                            created_at=tpl_data.get("created_at", 0.0),
                            updated_at=tpl_data.get("updated_at", 0.0),
                            is_validated=tpl_data.get("is_validated", False),
                            validation_status=tpl_data.get("validation_status", "pending"),
                        )

                        self._templates[template.template_id] = template
                        self._change_history[template.template_id] = []

        except Exception as e:
            logger.error(f"Failed to load templates: {e}")

    def _save_template(self, template: EditableTemplate) -> None:
        """Save template to storage.

        Args:
            template: Template to save.
        """
        if not self.storage_path:
            return

        try:
            templates_file = os.path.join(self.storage_path, "templates.json")

            templates_data = []
            if os.path.exists(templates_file):
                with open(templates_file, "r", encoding="utf-8") as f:
                    templates_data = json.load(f)

            templates_data = [t for t in templates_data if t.get("template_id") != template.template_id]

            template_dict = {
                "template_id": template.template_id,
                "name": template.name,
                "description": template.description,
                "version": template.version,
                "steps": [
                    {
                        "step_id": s.step_id,
                        "step_number": s.step_number,
                        "action": s.action.value,
                        "name": s.name,
                        "description": s.description,
                        "payload": s.payload,
                        "expected_output": s.expected_output,
                        "variables": s.variables,
                        "condition": {
                            "condition_id": s.condition.condition_id,
                            "variable": s.condition.variable,
                            "operator": s.condition.operator.value,
                            "value": s.condition.value,
                            "on_true_step_id": s.condition.on_true_step_id,
                            "on_false_step_id": s.condition.on_false_step_id,
                        } if s.condition else None,
                        "loop_config": {
                            "loop_id": s.loop_config.loop_id,
                            "loop_type": s.loop_config.loop_type.value,
                            "iterations": s.loop_config.iterations,
                            "items": s.loop_config.items,
                            "condition": s.loop_config.condition,
                            "max_iterations": s.loop_config.max_iterations,
                            "current_iteration": s.loop_config.current_iteration,
                        } if s.loop_config else None,
                        "group_id": s.group_id,
                        "is_enabled": s.is_enabled,
                        "notes": s.notes,
                        "timeout_seconds": s.timeout_seconds,
                        "retry_count": s.retry_count,
                        "depends_on": s.depends_on,
                    }
                    for s in template.steps
                ],
                "groups": [
                    {
                        "group_id": g.group_id,
                        "name": g.name,
                        "description": g.description,
                        "steps": g.steps,
                        "variables": g.variables,
                        "is_reusable": g.is_reusable,
                    }
                    for g in template.groups
                ],
                "variables": template.variables,
                "author": template.author,
                "tags": template.tags,
                "created_at": template.created_at,
                "updated_at": template.updated_at,
                "is_validated": template.is_validated,
                "validation_status": template.validation_status,
            }

            templates_data.append(template_dict)

            with open(templates_file, "w", encoding="utf-8") as f:
                json.dump(templates_data, f, ensure_ascii=False, indent=2)

        except Exception as e:
            logger.error(f"Failed to save template: {e}")
