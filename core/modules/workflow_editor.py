"""Workflow Editor: Visual DAG editor for attack chain templates.

Provides:
- Visual DAG (Directed Acyclic Graph) editor: Node drag-and-drop, conditional branching, loop logic, sub-process references
- Node types: reconnaissance, vulnerability scanning, exploitation, credential acquisition, lateral movement, privilege escalation, persistence, data exfiltration, cleanup
- Sub-process nodes: Embed published templates as sub-processes in new templates
- Workflow template market extension: Workflow templates use same market, can contain sub-template references
"""

import asyncio
import json
import logging
import os
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


class NodeType(Enum):
    """Workflow node types."""
    RECONNAISSANCE = "reconnaissance"
    VULNERABILITY_SCANNING = "vulnerability_scanning"
    EXPLOITATION = "exploitation"
    CREDENTIAL_ACQUISITION = "credential_acquisition"
    LATERAL_MOVEMENT = "lateral_movement"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    PERSISTENCE = "persistence"
    DATA_EXFILTRATION = "data_exfiltration"
    CLEANUP = "cleanup"
    SUB_PROCESS = "sub_process"
    CONDITIONAL = "conditional"
    LOOP = "loop"
    PARALLEL_GROUP = "parallel_group"
    CUSTOM = "custom"


class EdgeType(Enum):
    """Workflow edge types."""
    SEQUENTIAL = "sequential"
    CONDITIONAL_TRUE = "conditional_true"
    CONDITIONAL_FALSE = "conditional_false"
    LOOP_BACK = "loop_back"
    PARALLEL = "parallel"


class ConditionOperator(Enum):
    """Condition operators."""
    EQUALS = "equals"
    NOT_EQUALS = "not_equals"
    CONTAINS = "contains"
    GREATER_THAN = "greater_than"
    LESS_THAN = "less_than"
    REGEX_MATCH = "regex_match"


@dataclass
class NodePosition:
    """Node position in canvas.

    Attributes:
        x: X coordinate
        y: Y coordinate
    """
    x: float = 0.0
    y: float = 0.0


@dataclass
class NodeConfig:
    """Node configuration.

    Attributes:
        target: Target for node execution
        timeout: Execution timeout in seconds
        retry_count: Number of retries on failure
        success_condition: Success condition expression
        failure_condition: Failure condition expression
        parameters: Additional parameters
    """
    target: str = ""
    timeout: int = 30
    retry_count: int = 0
    success_condition: str = ""
    failure_condition: str = ""
    parameters: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ConditionRule:
    """Condition rule for branching.

    Attributes:
        rule_id: Unique rule identifier
        field: Field to evaluate
        operator: Comparison operator
        value: Value to compare against
        description: Rule description
    """
    rule_id: str = ""
    field: str = ""
    operator: ConditionOperator = ConditionOperator.EQUALS
    value: str = ""
    description: str = ""


@dataclass
class LoopConfig:
    """Loop configuration.

    Attributes:
        loop_type: Type of loop (fixed, foreach, while, until)
        max_iterations: Maximum iterations (for fixed loops)
        items: Items to iterate over (for foreach loops)
        condition: Loop condition (for while/until loops)
        current_iteration: Current iteration count
    """
    loop_type: str = "fixed"
    max_iterations: int = 1
    items: List[str] = field(default_factory=list)
    condition: str = ""
    current_iteration: int = 0


@dataclass
class WorkflowNode:
    """Workflow node in DAG.

    Attributes:
        node_id: Unique node identifier
        node_type: Type of node
        name: Node display name
        description: Node description
        position: Position in canvas
        config: Node configuration
        condition_rules: List of condition rules
        loop_config: Loop configuration (for loop nodes)
        sub_template_id: Sub-template ID (for sub-process nodes)
        parallel_group_id: Parallel group ID (for parallel nodes)
        input_variables: Input variable names
        output_variables: Output variable names
        created_at: Creation timestamp
    """
    node_id: str = ""
    node_type: NodeType = NodeType.CUSTOM
    name: str = ""
    description: str = ""
    position: NodePosition = field(default_factory=NodePosition)
    config: NodeConfig = field(default_factory=NodeConfig)
    condition_rules: List[ConditionRule] = field(default_factory=list)
    loop_config: Optional[LoopConfig] = None
    sub_template_id: str = ""
    parallel_group_id: str = ""
    input_variables: List[str] = field(default_factory=list)
    output_variables: List[str] = field(default_factory=list)
    created_at: float = 0.0


@dataclass
class WorkflowEdge:
    """Workflow edge connecting nodes.

    Attributes:
        edge_id: Unique edge identifier
        source_node_id: Source node ID
        target_node_id: Target node ID
        edge_type: Type of edge
        condition: Edge condition (for conditional edges)
        label: Edge label for display
    """
    edge_id: str = ""
    source_node_id: str = ""
    target_node_id: str = ""
    edge_type: EdgeType = EdgeType.SEQUENTIAL
    condition: str = ""
    label: str = ""


@dataclass
class ParallelGroup:
    """Parallel execution group.

    Attributes:
        group_id: Unique group identifier
        name: Group name
        node_ids: List of node IDs in group
        max_concurrent: Maximum concurrent executions
        data_sharing: Whether nodes share data
        shared_variables: Variables shared between nodes
    """
    group_id: str = ""
    name: str = ""
    node_ids: List[str] = field(default_factory=list)
    max_concurrent: int = 5
    data_sharing: bool = False
    shared_variables: Dict[str, Any] = field(default_factory=dict)


@dataclass
class WorkflowTemplate:
    """Workflow template containing DAG.

    Attributes:
        workflow_id: Unique workflow identifier
        name: Workflow name
        description: Workflow description
        nodes: List of workflow nodes
        edges: List of workflow edges
        parallel_groups: List of parallel groups
        variables: Workflow variables
        entry_nodes: List of entry node IDs
        exit_nodes: List of exit node IDs
        author: Workflow author
        created_at: Creation timestamp
        updated_at: Last update timestamp
        version: Workflow version
        sub_template_refs: List of referenced sub-template IDs
        is_validated: Whether workflow has been validated
    """
    workflow_id: str = ""
    name: str = ""
    description: str = ""
    nodes: List[WorkflowNode] = field(default_factory=list)
    edges: List[WorkflowEdge] = field(default_factory=list)
    parallel_groups: List[ParallelGroup] = field(default_factory=list)
    variables: Dict[str, str] = field(default_factory=dict)
    entry_nodes: List[str] = field(default_factory=list)
    exit_nodes: List[str] = field(default_factory=list)
    author: str = ""
    created_at: float = 0.0
    updated_at: float = 0.0
    version: str = "1.0.0"
    sub_template_refs: List[str] = field(default_factory=list)
    is_validated: bool = False


class WorkflowEditor:
    """Visual DAG editor for workflow templates.

    Provides drag-and-drop editing, conditional branching, loop logic,
    and sub-process references for building complex attack chain
    workflows.
    """

    def __init__(self, storage_path: str = "") -> None:
        """Initialize workflow editor.

        Args:
            storage_path: Directory path for storage.
        """
        self.storage_path = storage_path
        self._workflows: Dict[str, WorkflowTemplate] = {}
        self._node_library: Dict[str, WorkflowNode] = {}
        self._undo_stack: Dict[str, List[Dict[str, Any]]] = {}
        self._change_history: Dict[str, List[Dict[str, Any]]] = {}

        if storage_path:
            os.makedirs(storage_path, exist_ok=True)
            self._load_data()

        self._initialize_node_library()

    async def create_workflow(
        self,
        name: str,
        description: str,
        author: str = "",
    ) -> WorkflowTemplate:
        """Create new workflow template.

        Args:
            name: Workflow name.
            description: Workflow description.
            author: Workflow author.

        Returns:
            Created WorkflowTemplate.
        """
        workflow_id = f"wf_{int(time.time())}"

        workflow = WorkflowTemplate(
            workflow_id=workflow_id,
            name=name,
            description=description,
            author=author,
            created_at=time.time(),
            updated_at=time.time(),
        )

        self._workflows[workflow_id] = workflow
        self._undo_stack[workflow_id] = []
        self._change_history[workflow_id] = []

        self._save_data()

        return workflow

    async def add_node(
        self,
        workflow_id: str,
        node_type: NodeType,
        name: str,
        position: Optional[NodePosition] = None,
        config: Optional[NodeConfig] = None,
    ) -> Optional[WorkflowNode]:
        """Add node to workflow.

        Args:
            workflow_id: Workflow identifier.
            node_type: Type of node.
            name: Node display name.
            position: Position in canvas.
            config: Node configuration.

        Returns:
            Created WorkflowNode or None.
        """
        workflow = self._workflows.get(workflow_id)
        if not workflow:
            return None

        node_id = f"{workflow_id}_node_{len(workflow.nodes) + 1}"

        node = WorkflowNode(
            node_id=node_id,
            node_type=node_type,
            name=name,
            position=position or NodePosition(),
            config=config or NodeConfig(),
            created_at=time.time(),
        )

        workflow.nodes.append(node)
        workflow.updated_at = time.time()

        if not workflow.entry_nodes:
            workflow.entry_nodes.append(node_id)

        self._record_change(workflow_id, {
            "action": "add_node",
            "node_id": node_id,
            "timestamp": time.time(),
        })

        self._save_data()

        return node

    async def add_edge(
        self,
        workflow_id: str,
        source_node_id: str,
        target_node_id: str,
        edge_type: EdgeType = EdgeType.SEQUENTIAL,
        condition: str = "",
        label: str = "",
    ) -> Optional[WorkflowEdge]:
        """Add edge between nodes.

        Args:
            workflow_id: Workflow identifier.
            source_node_id: Source node ID.
            target_node_id: Target node ID.
            edge_type: Type of edge.
            condition: Edge condition.
            label: Edge label.

        Returns:
            Created WorkflowEdge or None.
        """
        workflow = self._workflows.get(workflow_id)
        if not workflow:
            return None

        if not self._has_node(workflow, source_node_id) or not self._has_node(workflow, target_node_id):
            return None

        if self._would_create_cycle(workflow, source_node_id, target_node_id):
            return None

        edge_id = f"{workflow_id}_edge_{len(workflow.edges) + 1}"

        edge = WorkflowEdge(
            edge_id=edge_id,
            source_node_id=source_node_id,
            target_node_id=target_node_id,
            edge_type=edge_type,
            condition=condition,
            label=label,
        )

        workflow.edges.append(edge)
        workflow.updated_at = time.time()

        self._update_exit_nodes(workflow)

        self._record_change(workflow_id, {
            "action": "add_edge",
            "edge_id": edge_id,
            "timestamp": time.time(),
        })

        self._save_data()

        return edge

    async def add_parallel_group(
        self,
        workflow_id: str,
        name: str,
        node_ids: List[str],
        max_concurrent: int = 5,
        data_sharing: bool = False,
    ) -> Optional[ParallelGroup]:
        """Add parallel execution group.

        Args:
            workflow_id: Workflow identifier.
            name: Group name.
            node_ids: List of node IDs in group.
            max_concurrent: Maximum concurrent executions.
            data_sharing: Whether nodes share data.

        Returns:
            Created ParallelGroup or None.
        """
        workflow = self._workflows.get(workflow_id)
        if not workflow:
            return None

        group_id = f"{workflow_id}_pg_{len(workflow.parallel_groups) + 1}"

        group = ParallelGroup(
            group_id=group_id,
            name=name,
            node_ids=node_ids,
            max_concurrent=max_concurrent,
            data_sharing=data_sharing,
        )

        workflow.parallel_groups.append(group)

        for node_id in node_ids:
            for node in workflow.nodes:
                if node.node_id == node_id:
                    node.parallel_group_id = group_id

        workflow.updated_at = time.time()

        self._save_data()

        return group

    async def add_sub_process(
        self,
        workflow_id: str,
        sub_template_id: str,
        name: str,
        position: Optional[NodePosition] = None,
    ) -> Optional[WorkflowNode]:
        """Add sub-process node referencing published template.

        Args:
            workflow_id: Workflow identifier.
            sub_template_id: Sub-template ID.
            name: Node display name.
            position: Position in canvas.

        Returns:
            Created WorkflowNode or None.
        """
        node = await self.add_node(
            workflow_id,
            NodeType.SUB_PROCESS,
            name,
            position,
        )

        if node:
            node.sub_template_id = sub_template_id

            workflow = self._workflows.get(workflow_id)
            if workflow and sub_template_id not in workflow.sub_template_refs:
                workflow.sub_template_refs.append(sub_template_id)

            self._save_data()

        return node

    async def add_condition_branch(
        self,
        workflow_id: str,
        source_node_id: str,
        true_target_id: str,
        false_target_id: str,
        rules: List[ConditionRule],
    ) -> bool:
        """Add conditional branching.

        Args:
            workflow_id: Workflow identifier.
            source_node_id: Source node ID.
            true_target_id: Target for true condition.
            false_target_id: Target for false condition.
            rules: List of condition rules.

        Returns:
            True if added successfully.
        """
        workflow = self._workflows.get(workflow_id)
        if not workflow:
            return False

        source_node = self._find_node(workflow, source_node_id)
        if not source_node:
            return False

        source_node.condition_rules = rules

        await self.add_edge(
            workflow_id,
            source_node_id,
            true_target_id,
            EdgeType.CONDITIONAL_TRUE,
            "true",
        )

        await self.add_edge(
            workflow_id,
            source_node_id,
            false_target_id,
            EdgeType.CONDITIONAL_FALSE,
            "false",
        )

        return True

    async def add_loop(
        self,
        workflow_id: str,
        loop_type: str,
        max_iterations: int = 1,
        items: Optional[List[str]] = None,
        condition: str = "",
    ) -> Optional[WorkflowNode]:
        """Add loop node.

        Args:
            workflow_id: Workflow identifier.
            loop_type: Type of loop.
            max_iterations: Maximum iterations.
            items: Items to iterate over.
            condition: Loop condition.

        Returns:
            Created WorkflowNode or None.
        """
        node = await self.add_node(
            workflow_id,
            NodeType.LOOP,
            f"Loop ({loop_type})",
        )

        if node:
            node.loop_config = LoopConfig(
                loop_type=loop_type,
                max_iterations=max_iterations,
                items=items or [],
                condition=condition,
            )

            self._save_data()

        return node

    async def remove_node(self, workflow_id: str, node_id: str) -> bool:
        """Remove node from workflow.

        Args:
            workflow_id: Workflow identifier.
            node_id: Node identifier.

        Returns:
            True if removed successfully.
        """
        workflow = self._workflows.get(workflow_id)
        if not workflow:
            return False

        workflow.nodes = [n for n in workflow.nodes if n.node_id != node_id]
        workflow.edges = [
            e for e in workflow.edges
            if e.source_node_id != node_id and e.target_node_id != node_id
        ]

        if node_id in workflow.entry_nodes:
            workflow.entry_nodes.remove(node_id)
        if node_id in workflow.exit_nodes:
            workflow.exit_nodes.remove(node_id)

        workflow.updated_at = time.time()

        self._record_change(workflow_id, {
            "action": "remove_node",
            "node_id": node_id,
            "timestamp": time.time(),
        })

        self._save_data()

        return True

    async def remove_edge(self, workflow_id: str, edge_id: str) -> bool:
        """Remove edge from workflow.

        Args:
            workflow_id: Workflow identifier.
            edge_id: Edge identifier.

        Returns:
            True if removed successfully.
        """
        workflow = self._workflows.get(workflow_id)
        if not workflow:
            return False

        workflow.edges = [e for e in workflow.edges if e.edge_id != edge_id]
        workflow.updated_at = time.time()

        self._record_change(workflow_id, {
            "action": "remove_edge",
            "edge_id": edge_id,
            "timestamp": time.time(),
        })

        self._save_data()

        return True

    async def update_node_config(
        self,
        workflow_id: str,
        node_id: str,
        config: NodeConfig,
    ) -> bool:
        """Update node configuration.

        Args:
            workflow_id: Workflow identifier.
            node_id: Node identifier.
            config: New configuration.

        Returns:
            True if updated successfully.
        """
        workflow = self._workflows.get(workflow_id)
        if not workflow:
            return False

        node = self._find_node(workflow, node_id)
        if not node:
            return False

        node.config = config
        workflow.updated_at = time.time()

        self._record_change(workflow_id, {
            "action": "update_node_config",
            "node_id": node_id,
            "timestamp": time.time(),
        })

        self._save_data()

        return True

    async def move_node(
        self,
        workflow_id: str,
        node_id: str,
        position: NodePosition,
    ) -> bool:
        """Move node position in canvas.

        Args:
            workflow_id: Workflow identifier.
            node_id: Node identifier.
            position: New position.

        Returns:
            True if moved successfully.
        """
        workflow = self._workflows.get(workflow_id)
        if not workflow:
            return False

        node = self._find_node(workflow, node_id)
        if not node:
            return False

        node.position = position
        workflow.updated_at = time.time()

        self._save_data()

        return True

    async def undo(self, workflow_id: str) -> bool:
        """Undo last change.

        Args:
            workflow_id: Workflow identifier.

        Returns:
            True if undone successfully.
        """
        stack = self._undo_stack.get(workflow_id, [])
        if not stack:
            return False

        last_change = stack.pop()
        action = last_change.get("action", "")

        if action == "add_node":
            await self.remove_node(workflow_id, last_change.get("node_id", ""))
        elif action == "add_edge":
            await self.remove_edge(workflow_id, last_change.get("edge_id", ""))

        self._save_data()

        return True

    async def validate_workflow(self, workflow_id: str) -> Tuple[bool, List[str]]:
        """Validate workflow structure.

        Args:
            workflow_id: Workflow identifier.

        Returns:
            Tuple of (is_valid, list of error messages).
        """
        workflow = self._workflows.get(workflow_id)
        if not workflow:
            return False, ["Workflow not found"]

        errors: List[str] = []

        if not workflow.nodes:
            errors.append("Workflow has no nodes")

        if not workflow.entry_nodes:
            errors.append("Workflow has no entry nodes")

        if not workflow.exit_nodes:
            errors.append("Workflow has no exit nodes")

        node_ids = {n.node_id for n in workflow.nodes}

        for edge in workflow.edges:
            if edge.source_node_id not in node_ids:
                errors.append(f"Edge {edge.edge_id} references non-existent source node")
            if edge.target_node_id not in node_ids:
                errors.append(f"Edge {edge.edge_id} references non-existent target node")

        if self._has_cycle(workflow):
            errors.append("Workflow contains cycles (DAG violation)")

        for group in workflow.parallel_groups:
            for node_id in group.node_ids:
                if node_id not in node_ids:
                    errors.append(f"Parallel group {group.group_id} references non-existent node")

        for node in workflow.nodes:
            if node.node_type == NodeType.SUB_PROCESS and not node.sub_template_id:
                errors.append(f"Sub-process node {node.node_id} has no sub-template reference")

        return len(errors) == 0, errors

    async def get_workflow(self, workflow_id: str) -> Optional[WorkflowTemplate]:
        """Get workflow template.

        Args:
            workflow_id: Workflow identifier.

        Returns:
            WorkflowTemplate or None.
        """
        return self._workflows.get(workflow_id)

    async def list_workflows(self, author: str = "") -> List[WorkflowTemplate]:
        """List workflow templates.

        Args:
            author: Filter by author.

        Returns:
            List of WorkflowTemplate objects.
        """
        workflows = list(self._workflows.values())

        if author:
            workflows = [w for w in workflows if w.author == author]

        return workflows

    async def get_node_library(self) -> Dict[str, WorkflowNode]:
        """Get node library.

        Returns:
            Dict of node type to template nodes.
        """
        return self._node_library.copy()

    def _initialize_node_library(self) -> None:
        """Initialize node library with common node types."""
        library_nodes = [
            (NodeType.RECONNAISSANCE, "Reconnaissance", "Information gathering and reconnaissance"),
            (NodeType.VULNERABILITY_SCANNING, "Vulnerability Scan", "Scan for vulnerabilities"),
            (NodeType.EXPLOITATION, "Exploitation", "Exploit identified vulnerabilities"),
            (NodeType.CREDENTIAL_ACQUISITION, "Credential Acquisition", "Extract credentials and secrets"),
            (NodeType.LATERAL_MOVEMENT, "Lateral Movement", "Move laterally through network"),
            (NodeType.PRIVILEGE_ESCALATION, "Privilege Escalation", "Escalate privileges"),
            (NodeType.PERSISTENCE, "Persistence", "Establish persistence"),
            (NodeType.DATA_EXFILTRATION, "Data Exfiltration", "Exfiltrate data"),
            (NodeType.CLEANUP, "Cleanup", "Clean up traces"),
        ]

        for node_type, name, desc in library_nodes:
            node = WorkflowNode(
                node_id=f"lib_{node_type.value}",
                node_type=node_type,
                name=name,
                description=desc,
            )
            self._node_library[node_type.value] = node

    def _has_node(self, workflow: WorkflowTemplate, node_id: str) -> bool:
        """Check if workflow has node.

        Args:
            workflow: Workflow template.
            node_id: Node identifier.

        Returns:
            True if node exists.
        """
        return any(n.node_id == node_id for n in workflow.nodes)

    def _find_node(self, workflow: WorkflowTemplate, node_id: str) -> Optional[WorkflowNode]:
        """Find node in workflow.

        Args:
            workflow: Workflow template.
            node_id: Node identifier.

        Returns:
            WorkflowNode or None.
        """
        for node in workflow.nodes:
            if node.node_id == node_id:
                return node
        return None

    def _would_create_cycle(
        self,
        workflow: WorkflowTemplate,
        source_node_id: str,
        target_node_id: str,
    ) -> bool:
        """Check if adding edge would create cycle.

        Args:
            workflow: Workflow template.
            source_node_id: Source node ID.
            target_node_id: Target node ID.

        Returns:
            True if would create cycle.
        """
        visited: Set[str] = set()
        stack = [target_node_id]

        while stack:
            current = stack.pop()
            if current == source_node_id:
                return True
            if current in visited:
                continue
            visited.add(current)

            for edge in workflow.edges:
                if edge.source_node_id == current:
                    stack.append(edge.target_node_id)

        return False

    def _has_cycle(self, workflow: WorkflowTemplate) -> bool:
        """Check if workflow has cycle.

        Args:
            workflow: Workflow template.

        Returns:
            True if has cycle.
        """
        visited: Set[str] = set()
        rec_stack: Set[str] = set()

        def dfs(node_id: str) -> bool:
            visited.add(node_id)
            rec_stack.add(node_id)

            for edge in workflow.edges:
                if edge.source_node_id == node_id:
                    next_node = edge.target_node_id
                    if next_node not in visited:
                        if dfs(next_node):
                            return True
                    elif next_node in rec_stack:
                        return True

            rec_stack.discard(node_id)
            return False

        for node in workflow.nodes:
            if node.node_id not in visited:
                if dfs(node.node_id):
                    return True

        return False

    def _update_exit_nodes(self, workflow: WorkflowTemplate) -> None:
        """Update exit nodes list.

        Args:
            workflow: Workflow template.
        """
        node_ids = {n.node_id for n in workflow.nodes}
        target_ids = {e.target_node_id for e in workflow.edges}

        workflow.exit_nodes = [nid for nid in node_ids if nid not in target_ids]

    def _record_change(self, workflow_id: str, change: Dict[str, Any]) -> None:
        """Record change for undo.

        Args:
            workflow_id: Workflow identifier.
            change: Change record.
        """
        if workflow_id not in self._undo_stack:
            self._undo_stack[workflow_id] = []

        self._undo_stack[workflow_id].append(change)

        if workflow_id not in self._change_history:
            self._change_history[workflow_id] = []

        self._change_history[workflow_id].append(change)

    def _load_data(self) -> None:
        """Load data from storage."""
        if not self.storage_path:
            return

        try:
            data_file = os.path.join(self.storage_path, "workflow_editor_data.json")
            if os.path.exists(data_file):
                with open(data_file, "r", encoding="utf-8") as f:
                    data = json.load(f)

                    for wf_id, wf_data in data.get("workflows", {}).items():
                        nodes = []
                        for node_data in wf_data.get("nodes", []):
                            pos_data = node_data.get("position", {})
                            config_data = node_data.get("config", {})
                            loop_data = node_data.get("loop_config")

                            loop_config = None
                            if loop_data:
                                loop_config = LoopConfig(
                                    loop_type=loop_data.get("loop_type", "fixed"),
                                    max_iterations=loop_data.get("max_iterations", 1),
                                    items=loop_data.get("items", []),
                                    condition=loop_data.get("condition", ""),
                                    current_iteration=loop_data.get("current_iteration", 0),
                                )

                            node = WorkflowNode(
                                node_id=node_data.get("node_id", ""),
                                node_type=NodeType(node_data.get("node_type", "custom")),
                                name=node_data.get("name", ""),
                                description=node_data.get("description", ""),
                                position=NodePosition(
                                    x=pos_data.get("x", 0.0),
                                    y=pos_data.get("y", 0.0),
                                ),
                                config=NodeConfig(
                                    target=config_data.get("target", ""),
                                    timeout=config_data.get("timeout", 30),
                                    retry_count=config_data.get("retry_count", 0),
                                    success_condition=config_data.get("success_condition", ""),
                                    failure_condition=config_data.get("failure_condition", ""),
                                    parameters=config_data.get("parameters", {}),
                                ),
                                condition_rules=node_data.get("condition_rules", []),
                                loop_config=loop_config,
                                sub_template_id=node_data.get("sub_template_id", ""),
                                parallel_group_id=node_data.get("parallel_group_id", ""),
                                input_variables=node_data.get("input_variables", []),
                                output_variables=node_data.get("output_variables", []),
                                created_at=node_data.get("created_at", 0.0),
                            )
                            nodes.append(node)

                        edges = []
                        for edge_data in wf_data.get("edges", []):
                            edges.append(WorkflowEdge(
                                edge_id=edge_data.get("edge_id", ""),
                                source_node_id=edge_data.get("source_node_id", ""),
                                target_node_id=edge_data.get("target_node_id", ""),
                                edge_type=EdgeType(edge_data.get("edge_type", "sequential")),
                                condition=edge_data.get("condition", ""),
                                label=edge_data.get("label", ""),
                            ))

                        parallel_groups = []
                        for pg_data in wf_data.get("parallel_groups", []):
                            parallel_groups.append(ParallelGroup(
                                group_id=pg_data.get("group_id", ""),
                                name=pg_data.get("name", ""),
                                node_ids=pg_data.get("node_ids", []),
                                max_concurrent=pg_data.get("max_concurrent", 5),
                                data_sharing=pg_data.get("data_sharing", False),
                                shared_variables=pg_data.get("shared_variables", {}),
                            ))

                        workflow = WorkflowTemplate(
                            workflow_id=wf_id,
                            name=wf_data.get("name", ""),
                            description=wf_data.get("description", ""),
                            nodes=nodes,
                            edges=edges,
                            parallel_groups=parallel_groups,
                            variables=wf_data.get("variables", {}),
                            entry_nodes=wf_data.get("entry_nodes", []),
                            exit_nodes=wf_data.get("exit_nodes", []),
                            author=wf_data.get("author", ""),
                            created_at=wf_data.get("created_at", 0.0),
                            updated_at=wf_data.get("updated_at", 0.0),
                            version=wf_data.get("version", "1.0.0"),
                            sub_template_refs=wf_data.get("sub_template_refs", []),
                            is_validated=wf_data.get("is_validated", False),
                        )

                        self._workflows[workflow.workflow_id] = workflow
                        self._undo_stack[workflow.workflow_id] = []
                        self._change_history[workflow.workflow_id] = wf_data.get("change_history", [])

        except Exception as e:
            logger.error(f"Failed to load workflow editor data: {e}")

    def _save_data(self) -> None:
        """Save data to storage."""
        if not self.storage_path:
            return

        try:
            data_file = os.path.join(self.storage_path, "workflow_editor_data.json")

            data = {
                "workflows": {
                    wf_id: {
                        "name": w.name,
                        "description": w.description,
                        "nodes": [
                            {
                                "node_id": n.node_id,
                                "node_type": n.node_type.value,
                                "name": n.name,
                                "description": n.description,
                                "position": {"x": n.position.x, "y": n.position.y},
                                "config": {
                                    "target": n.config.target,
                                    "timeout": n.config.timeout,
                                    "retry_count": n.config.retry_count,
                                    "success_condition": n.config.success_condition,
                                    "failure_condition": n.config.failure_condition,
                                    "parameters": n.config.parameters,
                                },
                                "condition_rules": n.condition_rules,
                                "loop_config": {
                                    "loop_type": n.loop_config.loop_type,
                                    "max_iterations": n.loop_config.max_iterations,
                                    "items": n.loop_config.items,
                                    "condition": n.loop_config.condition,
                                    "current_iteration": n.loop_config.current_iteration,
                                } if n.loop_config else None,
                                "sub_template_id": n.sub_template_id,
                                "parallel_group_id": n.parallel_group_id,
                                "input_variables": n.input_variables,
                                "output_variables": n.output_variables,
                                "created_at": n.created_at,
                            }
                            for n in w.nodes
                        ],
                        "edges": [
                            {
                                "edge_id": e.edge_id,
                                "source_node_id": e.source_node_id,
                                "target_node_id": e.target_node_id,
                                "edge_type": e.edge_type.value,
                                "condition": e.condition,
                                "label": e.label,
                            }
                            for e in w.edges
                        ],
                        "parallel_groups": [
                            {
                                "group_id": g.group_id,
                                "name": g.name,
                                "node_ids": g.node_ids,
                                "max_concurrent": g.max_concurrent,
                                "sharing": g.data_sharing,
                                "shared_variables": g.shared_variables,
                            }
                            for g in w.parallel_groups
                        ],
                        "variables": w.variables,
                        "entry_nodes": w.entry_nodes,
                        "exit_nodes": w.exit_nodes,
                        "author": w.author,
                        "created_at": w.created_at,
                        "updated_at": w.updated_at,
                        "version": w.version,
                        "sub_template_refs": w.sub_template_refs,
                        "is_validated": w.is_validated,
                        "change_history": self._change_history.get(wf_id, []),
                    }
                    for wf_id, w in self._workflows.items()
                },
            }

            with open(data_file, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)

        except Exception as e:
            logger.error(f"Failed to save workflow editor data: {e}")
