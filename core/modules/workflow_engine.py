"""Workflow Engine: Parallel/serial mixed scheduling, inter-node data sharing, conditional routing.

Provides:
- Parallel and serial mixed scheduling: Configure parallel execution groups, nodes within same group execute simultaneously, different groups execute serially
- Inter-node data sharing: Assets discovered by node A automatically passed to nodes B and C
- Conditional routing: if/else/switch logic, determine subsequent execution paths based on predecessor node output
- Loop nodes: Repeat sub-process for each target in asset list
"""

import asyncio
import logging
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Callable, Coroutine, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


class NodeStatus(Enum):
    """Workflow node execution status."""
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"
    TIMEOUT = "timeout"


class WorkflowStatus(Enum):
    """Workflow execution status."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    PAUSED = "paused"
    CANCELLED = "cancelled"


@dataclass
class NodeExecutionResult:
    """Result of node execution.

    Attributes:
        node_id: Node identifier
        status: Execution status
        output: Node output data
        error: Error message if failed
        start_time: Execution start time
        end_time: Execution end time
        duration_ms: Execution duration
    """
    node_id: str = ""
    status: NodeStatus = NodeStatus.PENDING
    output: Dict[str, Any] = field(default_factory=dict)
    error: str = ""
    start_time: float = 0.0
    end_time: float = 0.0
    duration_ms: float = 0.0


@dataclass
class WorkflowExecutionContext:
    """Workflow execution context.

    Attributes:
        execution_id: Unique execution identifier
        workflow_id: Workflow identifier
        status: Execution status
        shared_data: Data shared between nodes
        node_results: Results of executed nodes
        current_node: Currently executing node ID
        start_time: Execution start time
        end_time: Execution end time
        variables: Workflow variables
    """
    execution_id: str = ""
    workflow_id: str = ""
    status: WorkflowStatus = WorkflowStatus.PENDING
    shared_data: Dict[str, Any] = field(default_factory=dict)
    node_results: Dict[str, NodeExecutionResult] = field(default_factory=dict)
    current_node: str = ""
    start_time: float = 0.0
    end_time: float = 0.0
    variables: Dict[str, str] = field(default_factory=dict)


class WorkflowEngine:
    """Workflow execution engine for parallel/serial mixed scheduling.

    Executes workflow templates with support for parallel execution groups,
    inter-node data sharing, conditional routing, and loop nodes.
    """

    def __init__(
        self,
        node_executor: Optional[Callable[[str, Dict[str, Any]], Coroutine[Any, Any, Dict[str, Any]]]] = None,
    ) -> None:
        """Initialize workflow engine.

        Args:
            node_executor: Optional async callback for executing individual nodes.
        """
        self._node_executor = node_executor
        self._execution_contexts: Dict[str, WorkflowExecutionContext] = {}
        self._workflow_cache: Dict[str, Dict[str, Any]] = {}

    async def execute_workflow(
        self,
        workflow_id: str,
        workflow_data: Dict[str, Any],
        variables: Optional[Dict[str, str]] = None,
        progress_callback: Optional[Callable[[str, str, Dict[str, Any]], Coroutine[Any, Any, None]]] = None,
    ) -> WorkflowExecutionContext:
        """Execute workflow template.

        Args:
            workflow_id: Workflow identifier.
            workflow_data: Workflow template data.
            variables: Workflow variables.
            progress_callback: Optional progress callback.

        Returns:
            Workflow execution context.
        """
        execution_id = f"exec_{workflow_id}_{int(time.time())}"

        context = WorkflowExecutionContext(
            execution_id=execution_id,
            workflow_id=workflow_id,
            variables=variables or {},
            start_time=time.time(),
        )

        self._execution_contexts[execution_id] = context
        self._workflow_cache[execution_id] = workflow_data

        context.status = WorkflowStatus.RUNNING

        if progress_callback:
            await progress_callback(execution_id, "started", {})

        try:
            await self._execute_nodes(context, workflow_data, progress_callback)

            context.status = WorkflowStatus.COMPLETED
            context.end_time = time.time()

            if progress_callback:
                await progress_callback(execution_id, "completed", {
                    "duration_ms": (context.end_time - context.start_time) * 1000,
                })

        except Exception as e:
            context.status = WorkflowStatus.FAILED
            context.end_time = time.time()
            logger.error(f"Workflow execution failed: {e}")

            if progress_callback:
                await progress_callback(execution_id, "failed", {"error": str(e)})

        return context

    async def pause_execution(self, execution_id: str) -> bool:
        """Pause workflow execution.

        Args:
            execution_id: Execution identifier.

        Returns:
            True if paused successfully.
        """
        context = self._execution_contexts.get(execution_id)
        if not context:
            return False

        context.status = WorkflowStatus.PAUSED
        return True

    async def resume_execution(self, execution_id: str) -> bool:
        """Resume paused workflow execution.

        Args:
            execution_id: Execution identifier.

        Returns:
            True if resumed successfully.
        """
        context = self._execution_contexts.get(execution_id)
        if not context or context.status != WorkflowStatus.PAUSED:
            return False

        context.status = WorkflowStatus.RUNNING
        return True

    async def cancel_execution(self, execution_id: str) -> bool:
        """Cancel workflow execution.

        Args:
            execution_id: Execution identifier.

        Returns:
            True if cancelled successfully.
        """
        context = self._execution_contexts.get(execution_id)
        if not context:
            return False

        context.status = WorkflowStatus.CANCELLED
        context.end_time = time.time()

        return True

    async def get_execution_context(self, execution_id: str) -> Optional[WorkflowExecutionContext]:
        """Get execution context.

        Args:
            execution_id: Execution identifier.

        Returns:
            WorkflowExecutionContext or None.
        """
        return self._execution_contexts.get(execution_id)

    async def _execute_nodes(
        self,
        context: WorkflowExecutionContext,
        workflow_data: Dict[str, Any],
        progress_callback: Optional[Callable[[str, str, Dict[str, Any]], Coroutine[Any, Any, None]]],
    ) -> None:
        """Execute workflow nodes.

        Args:
            context: Execution context.
            workflow_data: Workflow template data.
            progress_callback: Progress callback.
        """
        nodes = workflow_data.get("nodes", [])
        edges = workflow_data.get("edges", [])
        parallel_groups = workflow_data.get("parallel_groups", [])

        node_map = {n.get("node_id", ""): n for n in nodes}

        entry_nodes = workflow_data.get("entry_nodes", [])
        if not entry_nodes:
            entry_nodes = self._find_entry_nodes(nodes, edges)

        executed: Set[str] = set()
        pending = set(entry_nodes)

        while pending:
            if context.status == WorkflowStatus.PAUSED:
                await asyncio.sleep(1)
                continue

            if context.status == WorkflowStatus.CANCELLED:
                break

            current_batch = self._get_next_executable_nodes(
                pending,
                executed,
                edges,
                node_map,
                parallel_groups,
            )

            if not current_batch:
                break

            parallel_group_map = self._build_parallel_group_map(parallel_groups)

            groups_to_execute = self._group_nodes_by_parallel_group(
                current_batch,
                parallel_group_map,
            )

            for group_nodes in groups_to_execute:
                if len(group_nodes) > 1:
                    await self._execute_parallel(
                        context,
                        group_nodes,
                        node_map,
                        edges,
                        progress_callback,
                    )
                else:
                    node_id = group_nodes[0]
                    result = await self._execute_single_node(
                        context,
                        node_id,
                        node_map,
                        edges,
                        progress_callback,
                    )

                    if result.status == NodeStatus.FAILED:
                        skipped = self._skip_dependent_nodes(node_id, edges, node_map)
                        executed.update(skipped)
                        pending.difference_update(skipped)

                executed.update(group_nodes)
                pending.difference_update(group_nodes)

                new_pending = self._find_next_pending_nodes(
                    executed,
                    edges,
                    node_map,
                )
                pending.update(new_pending)

    async def _execute_parallel(
        self,
        context: WorkflowExecutionContext,
        node_ids: List[str],
        node_map: Dict[str, Dict[str, Any]],
        edges: List[Dict[str, Any]],
        progress_callback: Optional[Callable[[str, str, Dict[str, Any]], Coroutine[Any, Any, None]]],
    ) -> None:
        """Execute nodes in parallel.

        Args:
            context: Execution context.
            node_ids: List of node IDs to execute.
            node_map: Node ID to node data map.
            edges: List of edges.
            progress_callback: Progress callback.
        """
        tasks = []
        for node_id in node_ids:
            task = asyncio.create_task(
                self._execute_single_node(
                    context,
                    node_id,
                    node_map,
                    edges,
                    progress_callback,
                )
            )
            tasks.append(task)

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, Exception):
                logger.error(f"Parallel node execution error: {result}")

    async def _execute_single_node(
        self,
        context: WorkflowExecutionContext,
        node_id: str,
        node_map: Dict[str, Dict[str, Any]],
        edges: List[Dict[str, Any]],
        progress_callback: Optional[Callable[[str, str, Dict[str, Any]], Coroutine[Any, Any, None]]],
    ) -> NodeExecutionResult:
        """Execute single node.

        Args:
            context: Execution context.
            node_id: Node identifier.
            node_map: Node ID to node data map.
            edges: List of edges.
            progress_callback: Progress callback.

        Returns:
            Node execution result.
        """
        node = node_map.get(node_id, {})
        node_type = node.get("node_type", "custom")

        context.current_node = node_id

        result = NodeExecutionResult(
            node_id=node_id,
            status=NodeStatus.RUNNING,
            start_time=time.time(),
        )

        if progress_callback:
            await progress_callback(
                context.execution_id,
                "node_started",
                {"node_id": node_id, "node_type": node_type},
            )

        try:
            if node_type == "loop":
                output = await self._execute_loop_node(context, node, node_map, edges)
            elif node_type == "conditional":
                output = await self._execute_conditional_node(context, node, node_map, edges)
            elif node_type == "sub_process":
                output = await self._execute_sub_process_node(context, node)
            else:
                output = await self._execute_standard_node(context, node)

            result.status = NodeStatus.SUCCESS
            result.output = output
            result.end_time = time.time()
            result.duration_ms = (result.end_time - result.start_time) * 1000

            context.shared_data[node_id] = output

            if progress_callback:
                await progress_callback(
                    context.execution_id,
                    "node_completed",
                    {"node_id": node_id, "output": output},
                )

        except Exception as e:
            result.status = NodeStatus.FAILED
            result.error = str(e)
            result.end_time = time.time()
            result.duration_ms = (result.end_time - result.start_time) * 1000

            logger.error(f"Node {node_id} execution failed: {e}")

            if progress_callback:
                await progress_callback(
                    context.execution_id,
                    "node_failed",
                    {"node_id": node_id, "error": str(e)},
                )

        context.node_results[node_id] = result

        return result

    async def _execute_standard_node(
        self,
        context: WorkflowExecutionContext,
        node: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Execute standard node.

        Args:
            context: Execution context.
            node: Node data.

        Returns:
            Node output.
        """
        config = node.get("config", {})
        target = config.get("target", "")
        timeout = config.get("timeout", 30)
        parameters = config.get("parameters", {})

        if self._node_executor:
            return await asyncio.wait_for(
                self._node_executor(node.get("node_id", ""), {
                    "target": target,
                    "parameters": parameters,
                    "shared_data": context.shared_data,
                    "variables": context.variables,
                }),
                timeout=timeout,
            )

        return {"status": "simulated", "node_id": node.get("node_id", "")}

    async def _execute_loop_node(
        self,
        context: WorkflowExecutionContext,
        node: Dict[str, Any],
        node_map: Dict[str, Dict[str, Any]],
        edges: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Execute loop node.

        Args:
            context: Execution context.
            node: Node data.
            node_map: Node ID to node data map.
            edges: List of edges.

        Returns:
            Loop output.
        """
        loop_config = node.get("loop_config", {})
        loop_type = loop_config.get("loop_type", "fixed")
        max_iterations = loop_config.get("max_iterations", 1)
        items = loop_config.get("items", [])

        results: List[Dict[str, Any]] = []

        if loop_type == "fixed":
            for i in range(max_iterations):
                result = await self._execute_loop_iteration(context, node, i)
                results.append(result)
        elif loop_type == "foreach" and items:
            for item in items:
                result = await self._execute_loop_iteration(context, node, 0, item)
                results.append(result)
        elif loop_type == "while":
            condition = loop_config.get("condition", "")
            iteration = 0
            while self._evaluate_condition(condition, context.shared_data) and iteration < max_iterations:
                result = await self._execute_loop_iteration(context, node, iteration)
                results.append(result)
                iteration += 1

        return {"loop_results": results, "iteration_count": len(results)}

    async def _execute_loop_iteration(
        self,
        context: WorkflowExecutionContext,
        node: Dict[str, Any],
        iteration: int,
        item: str = "",
    ) -> Dict[str, Any]:
        """Execute single loop iteration.

        Args:
            context: Execution context.
            node: Node data.
            iteration: Iteration number.
            item: Current item (for foreach loops).

        Returns:
            Iteration result.
        """
        config = node.get("config", {})
        parameters = config.get("parameters", {})

        if item:
            parameters["current_item"] = item

        parameters["iteration"] = iteration

        if self._node_executor:
            return await self._node_executor(
                node.get("node_id", ""),
                {
                    "target": config.get("target", ""),
                    "parameters": parameters,
                    "shared_data": context.shared_data,
                    "variables": context.variables,
                },
            )

        return {"iteration": iteration, "status": "simulated"}

    async def _execute_conditional_node(
        self,
        context: WorkflowExecutionContext,
        node: Dict[str, Any],
        node_map: Dict[str, Dict[str, Any]],
        edges: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Execute conditional node.

        Args:
            context: Execution context.
            node: Node data.
            node_map: Node ID to node data map.
            edges: List of edges.

        Returns:
            Conditional output.
        """
        condition_rules = node.get("condition_rules", [])

        condition_met = True
        for rule in condition_rules:
            field_name = rule.get("field", "")
            operator = rule.get("operator", "equals")
            value = rule.get("value", "")

            if not self._evaluate_rule(field_name, operator, value, context.shared_data):
                condition_met = False
                break

        return {"condition_met": condition_met, "rules_evaluated": len(condition_rules)}

    async def _execute_sub_process_node(
        self,
        context: WorkflowExecutionContext,
        node: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Execute sub-process node.

        Args:
            context: Execution context.
            node: Node data.

        Returns:
            Sub-process output.
        """
        sub_template_id = node.get("sub_template_id", "")

        if self._node_executor:
            return await self._node_executor(
                node.get("node_id", ""),
                {
                    "sub_template_id": sub_template_id,
                    "shared_data": context.shared_data,
                    "variables": context.variables,
                },
            )

        return {"sub_template_id": sub_template_id, "status": "simulated"}

    def _find_entry_nodes(
        self,
        nodes: List[Dict[str, Any]],
        edges: List[Dict[str, Any]],
    ) -> List[str]:
        """Find entry nodes in workflow.

        Args:
            nodes: List of nodes.
            edges: List of edges.

        Returns:
            List of entry node IDs.
        """
        target_ids = {e.get("target_node_id", "") for e in edges}
        node_ids = {n.get("node_id", "") for n in nodes}

        return [nid for nid in node_ids if nid not in target_ids]

    def _get_next_executable_nodes(
        self,
        pending: Set[str],
        executed: Set[str],
        edges: List[Dict[str, Any]],
        node_map: Dict[str, Dict[str, Any]],
        parallel_groups: List[Dict[str, Any]],
    ) -> List[str]:
        """Get next batch of executable nodes.

        Args:
            pending: Set of pending node IDs.
            executed: Set of executed node IDs.
            edges: List of edges.
            node_map: Node ID to node data map.
            parallel_groups: List of parallel groups.

        Returns:
            List of executable node IDs.
        """
        executable: List[str] = []

        for node_id in pending:
            predecessors = self._get_predecessors(node_id, edges)

            if all(pred in executed for pred in predecessors):
                executable.append(node_id)

        return executable

    def _get_predecessors(
        self,
        node_id: str,
        edges: List[Dict[str, Any]],
    ) -> List[str]:
        """Get predecessor nodes.

        Args:
            node_id: Node identifier.
            edges: List of edges.

        Returns:
            List of predecessor node IDs.
        """
        return [
            e.get("source_node_id", "")
            for e in edges
            if e.get("target_node_id", "") == node_id
        ]

    def _build_parallel_group_map(
        self,
        parallel_groups: List[Dict[str, Any]],
    ) -> Dict[str, List[str]]:
        """Build parallel group map.

        Args:
            parallel_groups: List of parallel groups.

        Returns:
            Dict of group ID to node IDs.
        """
        group_map: Dict[str, List[str]] = {}

        for group in parallel_groups:
            group_map[group.get("group_id", "")] = group.get("node_ids", [])

        return group_map

    def _group_nodes_by_parallel_group(
        self,
        node_ids: List[str],
        parallel_group_map: Dict[str, List[str]],
    ) -> List[List[str]]:
        """Group nodes by parallel group.

        Args:
            node_ids: List of node IDs.
            parallel_group_map: Parallel group map.

        Returns:
            List of node groups.
        """
        grouped: Set[str] = set()
        groups: List[List[str]] = []

        for group_id, group_nodes in parallel_group_map.items():
            matching = [nid for nid in node_ids if nid in group_nodes and nid not in grouped]
            if matching:
                groups.append(matching)
                grouped.update(matching)

        ungrouped = [nid for nid in node_ids if nid not in grouped]
        for nid in ungrouped:
            groups.append([nid])

        return groups

    def _skip_dependent_nodes(
        self,
        failed_node_id: str,
        edges: List[Dict[str, Any]],
        node_map: Dict[str, Dict[str, Any]],
    ) -> Set[str]:
        """Skip nodes dependent on failed node.

        Args:
            failed_node_id: Failed node ID.
            edges: List of edges.
            node_map: Node ID to node data map.

        Returns:
            Set of skipped node IDs.
        """
        skipped: Set[str] = set()
        queue = [failed_node_id]

        while queue:
            current = queue.pop(0)

            for edge in edges:
                if edge.get("source_node_id", "") == current:
                    target = edge.get("target_node_id", "")
                    if target not in skipped:
                        skipped.add(target)
                        queue.append(target)

        return skipped

    def _find_next_pending_nodes(
        self,
        executed: Set[str],
        edges: List[Dict[str, Any]],
        node_map: Dict[str, Dict[str, Any]],
    ) -> Set[str]:
        """Find next pending nodes.

        Args:
            executed: Set of executed node IDs.
            edges: List of edges.
            node_map: Node ID to node data map.

        Returns:
            Set of pending node IDs.
        """
        pending: Set[str] = set()

        for edge in edges:
            source = edge.get("source_node_id", "")
            target = edge.get("target_node_id", "")

            if source in executed and target not in executed:
                predecessors = self._get_predecessors(target, edges)
                if all(pred in executed for pred in predecessors):
                    pending.add(target)

        return pending

    def _evaluate_condition(
        self,
        condition: str,
        shared_data: Dict[str, Any],
    ) -> bool:
        """Evaluate loop condition.

        Args:
            condition: Condition string.
            shared_data: Shared data.

        Returns:
            Condition result.
        """
        if not condition:
            return True

        try:
            return bool(eval(condition, {"shared_data": shared_data}))
        except Exception:
            return False

    def _evaluate_rule(
        self,
        field_name: str,
        operator: str,
        value: str,
        shared_data: Dict[str, Any],
    ) -> bool:
        """Evaluate condition rule.

        Args:
            field_name: Field name.
            operator: Comparison operator.
            value: Value to compare.
            shared_data: Shared data.

        Returns:
            Rule evaluation result.
        """
        field_value = shared_data.get(field_name, "")

        if operator == "equals":
            return str(field_value) == value
        elif operator == "not_equals":
            return str(field_value) != value
        elif operator == "contains":
            return value in str(field_value)
        elif operator == "greater_than":
            try:
                return float(field_value) > float(value)
            except (ValueError, TypeError):
                return False
        elif operator == "less_than":
            try:
                return float(field_value) < float(value)
            except (ValueError, TypeError):
                return False
        elif operator == "regex_match":
            import re
            try:
                return bool(re.match(value, str(field_value)))
            except Exception:
                return False

        return False
