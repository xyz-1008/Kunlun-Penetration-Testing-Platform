"""
Digital Twin Simulation Module - Attack path simulation and Profile pre-evaluation.

This module provides digital twin capabilities for:
    1. Attack path simulation in virtual target environments
    2. Multi-Profile parallel pre-evaluation
    3. Detection probability prediction
    4. Optimal attack path selection

Core capabilities:
    - Network topology modeling
    - Security policy simulation
    - Attack chain pre-execution
    - Profile variant parallel testing
    - Risk and success probability calculation
    - Simulation environment updates

Author: Kunlun Security Lab
License: Internal Use Only
"""

from __future__ import annotations

import asyncio
import copy
import hashlib
import json
import logging
import math
import random
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Coroutine, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


# =============================================================================
# Enums
# =============================================================================

class NodeType(str, Enum):
    """Network node types."""

    WORKSTATION = "workstation"
    SERVER = "server"
    DOMAIN_CONTROLLER = "domain_controller"
    FIREWALL = "firewall"
    IDS = "ids"
    EDR = "edr"
    ROUTER = "router"
    DATABASE = "database"
    WEB_SERVER = "web_server"


class SecurityControl(str, Enum):
    """Security control types."""

    ANTIVIRUS = "antivirus"
    FIREWALL_RULE = "firewall_rule"
    NETWORK_SEGMENTATION = "network_segmentation"
    LOG_MONITORING = "log_monitoring"
    BEHAVIOR_ANALYSIS = "behavior_analysis"
    SANDBOX = "sandbox"
    DLP = "dlp"
    EDR = "edr"


class AttackPhase(str, Enum):
    """Attack chain phases."""

    RECONNAISSANCE = "reconnaissance"
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    LATERAL_MOVEMENT = "lateral_movement"
    COLLECTION = "collection"
    EXFILTRATION = "exfiltration"


class SimulationResult(str, Enum):
    """Simulation outcome."""

    SUCCESS = "success"
    DETECTED = "detected"
    BLOCKED = "blocked"
    PARTIAL = "partial"
    FAILED = "failed"


# =============================================================================
# Data Models
# =============================================================================

@dataclass
class NetworkNode:
    """Network node in digital twin.

    Attributes:
        node_id: Unique node identifier
        node_type: Type of node
        ip_address: IP address
        hostname: Hostname
        os_type: Operating system
        security_controls: Applied security controls
        vulnerabilities: Known vulnerabilities
        is_compromised: Whether node is compromised
    """

    node_id: str = ""
    node_type: NodeType = NodeType.WORKSTATION
    ip_address: str = ""
    hostname: str = ""
    os_type: str = "windows"
    security_controls: List[SecurityControl] = field(default_factory=list)
    vulnerabilities: List[str] = field(default_factory=list)
    is_compromised: bool = False

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "node_id": self.node_id,
            "node_type": self.node_type.value,
            "ip_address": self.ip_address,
            "security_controls": [c.value for c in self.security_controls],
            "is_compromised": self.is_compromised,
        }


@dataclass
class NetworkEdge:
    """Network connection between nodes.

    Attributes:
        source_id: Source node ID
        target_id: Target node ID
        protocol: Connection protocol
        port: Target port
        is_allowed: Whether connection is allowed
        bandwidth: Connection bandwidth
        latency: Connection latency
    """

    source_id: str = ""
    target_id: str = ""
    protocol: str = "tcp"
    port: int = 0
    is_allowed: bool = True
    bandwidth: int = 1000
    latency: float = 1.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "source_id": self.source_id,
            "target_id": self.target_id,
            "protocol": self.protocol,
            "port": self.port,
            "is_allowed": self.is_allowed,
        }


@dataclass
class AttackStep:
    """Single step in attack chain.

    Attributes:
        step_id: Step identifier
        phase: Attack phase
        technique: MITRE ATT&CK technique
        target_node: Target node ID
        success_probability: Base success probability
        detection_probability: Detection probability
        required_access: Required access level
        payload: Attack payload
    """

    step_id: str = ""
    phase: AttackPhase = AttackPhase.RECONNAISSANCE
    technique: str = ""
    target_node: str = ""
    success_probability: float = 0.8
    detection_probability: float = 0.2
    required_access: str = "user"
    payload: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "step_id": self.step_id,
            "phase": self.phase.value,
            "technique": self.technique,
            "target_node": self.target_node,
            "success_probability": self.success_probability,
            "detection_probability": self.detection_probability,
        }


@dataclass
class AttackPath:
    """Complete attack path through network.

    Attributes:
        path_id: Unique path identifier
        steps: Attack steps in sequence
        overall_success: Overall success probability
        overall_detection: Overall detection probability
        estimated_time: Estimated execution time
        risk_score: Overall risk score
        result: Simulation result
    """

    path_id: str = ""
    steps: List[AttackStep] = field(default_factory=list)
    overall_success: float = 0.0
    overall_detection: float = 0.0
    estimated_time: float = 0.0
    risk_score: float = 0.0
    result: SimulationResult = SimulationResult.FAILED

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "path_id": self.path_id,
            "step_count": len(self.steps),
            "overall_success": self.overall_success,
            "overall_detection": self.overall_detection,
            "risk_score": self.risk_score,
            "result": self.result.value,
        }


@dataclass
class ProfileVariant:
    """Profile variant for parallel testing.

    Attributes:
        variant_id: Variant identifier
        profile_config: Profile configuration
        detection_score: Detection score (0-1, lower is better)
        success_score: Success score (0-1)
        stealth_score: Stealth score (0-1)
        simulation_results: Simulation results
    """

    variant_id: str = ""
    profile_config: Dict[str, Any] = field(default_factory=dict)
    detection_score: float = 0.0
    success_score: float = 0.0
    stealth_score: float = 0.0
    simulation_results: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "variant_id": self.variant_id,
            "detection_score": self.detection_score,
            "success_score": self.success_score,
            "stealth_score": self.stealth_score,
        }


@dataclass
class SimulationReport:
    """Simulation execution report.

    Attributes:
        simulation_id: Simulation identifier
        paths_evaluated: Number of paths evaluated
        best_path: Best attack path
        best_profile: Best profile variant
        total_time: Simulation duration
        timestamp: Report timestamp
    """

    simulation_id: str = ""
    paths_evaluated: int = 0
    best_path: Optional[AttackPath] = None
    best_profile: Optional[ProfileVariant] = None
    total_time: float = 0.0
    timestamp: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "simulation_id": self.simulation_id,
            "paths_evaluated": self.paths_evaluated,
            "best_path": self.best_path.to_dict() if self.best_path else None,
            "best_profile": self.best_profile.to_dict() if self.best_profile else None,
            "total_time": self.total_time,
        }


# =============================================================================
# Network Topology Model
# =============================================================================

class NetworkTopologyModel:
    """Models target network topology for simulation.

    Creates a virtual representation of the target network
    including nodes, connections, and security controls.

    Attributes:
        _nodes: Network nodes
        _edges: Network connections
        _security_policies: Security policies
    """

    def __init__(self) -> None:
        """Initialize the NetworkTopologyModel."""
        self._nodes: Dict[str, NetworkNode] = {}
        self._edges: List[NetworkEdge] = []
        self._security_policies: Dict[str, Any] = {}

    def add_node(self, node: NetworkNode) -> None:
        """Add a network node.

        Args:
            node: Node to add.
        """
        self._nodes[node.node_id] = node

    def add_edge(self, edge: NetworkEdge) -> None:
        """Add a network connection.

        Args:
            edge: Edge to add.
        """
        self._edges.append(edge)

    def get_node(self, node_id: str) -> Optional[NetworkNode]:
        """Get a node by ID.

        Args:
            node_id: Node ID.

        Returns:
            NetworkNode, or None.
        """
        return self._nodes.get(node_id)

    def get_neighbors(self, node_id: str) -> List[NetworkNode]:
        """Get neighboring nodes.

        Args:
            node_id: Source node ID.

        Returns:
            List of neighbor nodes.
        """
        neighbors: List[NetworkNode] = []

        for edge in self._edges:
            if edge.source_id == node_id and edge.is_allowed:
                neighbor = self._nodes.get(edge.target_id)
                if neighbor:
                    neighbors.append(neighbor)

        return neighbors

    def get_security_controls(self, node_id: str) -> List[SecurityControl]:
        """Get security controls for a node.

        Args:
            node_id: Node ID.

        Returns:
            List of security controls.
        """
        node = self._nodes.get(node_id)
        if node:
            return node.security_controls
        return []

    def get_node_count(self) -> int:
        """Get total node count.

        Returns:
            Node count.
        """
        return len(self._nodes)

    def get_status(self) -> Dict[str, Any]:
        """Get topology status.

        Returns:
            Dictionary with status summary.
        """
        return {
            "node_count": len(self._nodes),
            "edge_count": len(self._edges),
            "compromised_count": sum(
                (1 for n in self._nodes.values() if n.is_compromised),
            ),
        }


# =============================================================================
# Attack Path Simulator
# =============================================================================

class AttackPathSimulator:
    """Simulates attack paths through network topology.

    Evaluates attack chains against the digital twin to
    predict success and detection probabilities.

    Attributes:
        _topology: Network topology model
        _attack_templates: Attack step templates
    """

    ATTACK_TEMPLATES: Dict[AttackPhase, Dict[str, Any]] = {
        AttackPhase.RECONNAISSANCE: {
            "techniques": ["T1595", "T1592", "T1589"],
            "success_prob": 0.95,
            "detection_prob": 0.05,
            "time_minutes": 30,
        },
        AttackPhase.INITIAL_ACCESS: {
            "techniques": ["T1566.001", "T1190", "T1133"],
            "success_prob": 0.6,
            "detection_prob": 0.3,
            "time_minutes": 60,
        },
        AttackPhase.EXECUTION: {
            "techniques": ["T1059.001", "T1059.003", "T1204"],
            "success_prob": 0.7,
            "detection_prob": 0.4,
            "time_minutes": 15,
        },
        AttackPhase.PERSISTENCE: {
            "techniques": ["T1547", "T1053", "T1136"],
            "success_prob": 0.65,
            "detection_prob": 0.35,
            "time_minutes": 20,
        },
        AttackPhase.PRIVILEGE_ESCALATION: {
            "techniques": ["T1068", "T1078", "T1548"],
            "success_prob": 0.5,
            "detection_prob": 0.45,
            "time_minutes": 45,
        },
        AttackPhase.LATERAL_MOVEMENT: {
            "techniques": ["T1021", "T1570", "T1563"],
            "success_prob": 0.55,
            "detection_prob": 0.4,
            "time_minutes": 30,
        },
        AttackPhase.COLLECTION: {
            "techniques": ["T1005", "T1560", "T1119"],
            "success_prob": 0.8,
            "detection_prob": 0.2,
            "time_minutes": 60,
        },
        AttackPhase.EXFILTRATION: {
            "techniques": ["T1041", "T1048", "T1567"],
            "success_prob": 0.45,
            "detection_prob": 0.5,
            "time_minutes": 45,
        },
    }

    def __init__(self, topology: NetworkTopologyModel) -> None:
        """Initialize the AttackPathSimulator.

        Args:
            topology: Network topology model.
        """
        self._topology = topology
        self._attack_templates = self.ATTACK_TEMPLATES.copy()

    def generate_attack_paths(
        self,
        start_node: str,
        target_node: str,
        max_paths: int = 10,
    ) -> List[AttackPath]:
        """Generate possible attack paths.

        Args:
            start_node: Starting node ID.
            target_node: Target node ID.
            max_paths: Maximum paths to generate.

        Returns:
            List of AttackPath.
        """
        paths: List[AttackPath] = []

        all_paths = self._find_all_paths(start_node, target_node)

        for i, node_sequence in enumerate(all_paths[:max_paths]):
            path = self._create_attack_path(node_sequence, i)
            paths.append(path)

        return paths

    def simulate_path(self, path: AttackPath) -> SimulationResult:
        """Simulate an attack path.

        Args:
            path: Attack path to simulate.

        Returns:
            Simulation result.
        """
        cumulative_success = 1.0
        cumulative_detection = 0.0
        total_time = 0.0

        for step in path.steps:
            node = self._topology.get_node(step.target_node)
            if not node:
                path.result = SimulationResult.FAILED
                return path.result

            step_success = self._calculate_step_success(step, node)
            step_detection = self._calculate_step_detection(step, node)

            cumulative_success *= step_success
            cumulative_detection = 1 - (
                (1 - cumulative_detection) * (1 - step_detection)
            )

            template = self._attack_templates.get(step.phase, {})
            total_time += template.get("time_minutes", 30)

        path.overall_success = cumulative_success
        path.overall_detection = cumulative_detection
        path.estimated_time = total_time

        path.risk_score = self._calculate_risk_score(
            cumulative_success, cumulative_detection,
        )

        if cumulative_detection > 0.7:
            path.result = SimulationResult.DETECTED
        elif cumulative_success < 0.2:
            path.result = SimulationResult.FAILED
        elif cumulative_success > 0.6 and cumulative_detection < 0.3:
            path.result = SimulationResult.SUCCESS
        else:
            path.result = SimulationResult.PARTIAL

        return path.result

    def _find_all_paths(
        self,
        start: str,
        end: str,
        visited: Optional[Set[str]] = None,
    ) -> List[List[str]]:
        """Find all paths between two nodes.

        Args:
            start: Start node.
            end: End node.
            visited: Visited nodes.

        Returns:
            List of node sequences.
        """
        if visited is None:
            visited = set()

        visited.add(start)

        if start == end:
            return [[start]]

        paths: List[List[str]] = []

        for neighbor in self._topology.get_neighbors(start):
            if neighbor.node_id not in visited:
                new_paths = self._find_all_paths(
                    neighbor.node_id, end, visited.copy(),
                )
                for path in new_paths:
                    paths.append([start] + path)

        return paths

    def _create_attack_path(
        self,
        node_sequence: List[str],
        path_index: int,
    ) -> AttackPath:
        """Create an AttackPath from node sequence.

        Args:
            node_sequence: Sequence of nodes.
            path_index: Path index.

        Returns:
            AttackPath.
        """
        steps: List[AttackStep] = []
        phases = list(AttackPhase)

        for i, node_id in enumerate(node_sequence):
            phase = phases[min(i, len(phases) - 1)]
            template = self._attack_templates.get(phase, {})

            techniques = template.get("techniques", [])
            step = AttackStep(
                step_id=f"step_{path_index}_{i}",
                phase=phase,
                technique=random.choice(techniques) if techniques else "",
                target_node=node_id,
                success_probability=template.get("success_prob", 0.5),
                detection_probability=template.get("detection_prob", 0.3),
            )
            steps.append(step)

        return AttackPath(
            path_id=f"path_{path_index}_{hashlib.md5(str(node_sequence).encode()).hexdigest()[:8]}",
            steps=steps,
        )

    def _calculate_step_success(
        self, step: AttackStep, node: NetworkNode,
    ) -> float:
        """Calculate step success probability.

        Args:
            step: Attack step.
            node: Target node.

        Returns:
            Success probability.
        """
        base_prob = step.success_probability

        control_penalty = len(node.security_controls) * 0.1
        vuln_bonus = len(node.vulnerabilities) * 0.05

        return max(0.0, min(1.0, base_prob - control_penalty + vuln_bonus))

    def _calculate_step_detection(
        self, step: AttackStep, node: NetworkNode,
    ) -> float:
        """Calculate step detection probability.

        Args:
            step: Attack step.
            node: Target node.

        Returns:
            Detection probability.
        """
        base_prob = step.detection_probability

        control_bonus = len(node.security_controls) * 0.15

        if SecurityControl.EDR in node.security_controls:
            control_bonus += 0.2
        if SecurityControl.BEHAVIOR_ANALYSIS in node.security_controls:
            control_bonus += 0.15

        return max(0.0, min(1.0, base_prob + control_bonus))

    def _calculate_risk_score(
        self, success: float, detection: float,
    ) -> float:
        """Calculate overall risk score.

        Args:
            success: Success probability.
            detection: Detection probability.

        Returns:
            Risk score (0-1).
        """
        return (success * 0.6) + ((1 - detection) * 0.4)


# =============================================================================
# Profile Pre-Evaluator
# =============================================================================

class ProfilePreEvaluator:
    """Pre-evaluates Profile variants in simulation.

    Tests multiple Profile configurations against the
    digital twin to find optimal settings.

    Attributes:
        _topology: Network topology model
        _simulator: Attack path simulator
        _variants: Profile variants
    """

    def __init__(
        self,
        topology: NetworkTopologyModel,
        simulator: AttackPathSimulator,
    ) -> None:
        """Initialize the ProfilePreEvaluator.

        Args:
            topology: Network topology model.
            simulator: Attack path simulator.
        """
        self._topology = topology
        self._simulator = simulator
        self._variants: List[ProfileVariant] = []

    def add_variant(
        self, variant_id: str, profile_config: Dict[str, Any],
    ) -> None:
        """Add a Profile variant for testing.

        Args:
            variant_id: Variant identifier.
            profile_config: Profile configuration.
        """
        variant = ProfileVariant(
            variant_id=variant_id,
            profile_config=profile_config,
        )
        self._variants.append(variant)

    async def evaluate_all(
        self,
        start_node: str,
        target_node: str,
    ) -> List[ProfileVariant]:
        """Evaluate all Profile variants.

        Args:
            start_node: Starting node.
            target_node: Target node.

        Returns:
            Evaluated variants.
        """
        tasks = []

        for variant in self._variants:
            task = asyncio.create_task(
                self._evaluate_variant(variant, start_node, target_node),
            )
            tasks.append(task)

        await asyncio.gather(*tasks)

        self._variants.sort(
            key=lambda v: v.stealth_score, reverse=True,
        )

        return self._variants

    async def _evaluate_variant(
        self,
        variant: ProfileVariant,
        start_node: str,
        target_node: str,
    ) -> ProfileVariant:
        """Evaluate a single variant.

        Args:
            variant: Variant to evaluate.
            start_node: Starting node.
            target_node: Target node.

        Returns:
            Evaluated variant.
        """
        paths = self._simulator.generate_attack_paths(
            start_node, target_node, max_paths=5,
        )

        results: List[Dict[str, Any]] = []
        total_success = 0.0
        total_detection = 0.0

        for path in paths:
            result = self._simulator.simulate_path(path)
            results.append(path.to_dict())

            total_success += path.overall_success
            total_detection += path.overall_detection

        path_count = len(paths) if paths else 1

        variant.success_score = total_success / path_count
        variant.detection_score = total_detection / path_count
        variant.stealth_score = 1 - variant.detection_score
        variant.simulation_results = results

        return variant

    def get_best_variant(self) -> Optional[ProfileVariant]:
        """Get best performing variant.

        Returns:
            Best ProfileVariant, or None.
        """
        if not self._variants:
            return None

        return max(self._variants, key=lambda v: v.stealth_score)

    def get_status(self) -> Dict[str, Any]:
        """Get evaluator status.

        Returns:
            Dictionary with status summary.
        """
        return {
            "variant_count": len(self._variants),
            "best_variant": (
                self.get_best_variant().variant_id
                if self.get_best_variant() else None
            ),
        }


# =============================================================================
# Digital Twin Simulation Manager
# =============================================================================

class DigitalTwinSimulationManager:
    """Main digital twin simulation coordination engine.

    Integrates network modeling, attack path simulation,
    and Profile pre-evaluation.

    Attributes:
        _topology: Network topology model
        _simulator: Attack path simulator
        _evaluator: Profile pre-evaluator
        _simulation_history: Simulation history
    """

    def __init__(self) -> None:
        """Initialize the DigitalTwinSimulationManager."""
        self._topology = NetworkTopologyModel()
        self._simulator = AttackPathSimulator(self._topology)
        self._evaluator = ProfilePreEvaluator(
            self._topology, self._simulator,
        )
        self._simulation_history: List[SimulationReport] = []

    def build_topology(
        self,
        nodes: List[NetworkNode],
        edges: List[NetworkEdge],
    ) -> None:
        """Build network topology.

        Args:
            nodes: Network nodes.
            edges: Network connections.
        """
        for node in nodes:
            self._topology.add_node(node)

        for edge in edges:
            self._topology.add_edge(edge)

        logger.info(
            f"Topology built: {len(nodes)} nodes, {len(edges)} edges"
        )

    def update_topology(self, changes: Dict[str, Any]) -> None:
        """Update topology with latest intelligence.

        Args:
            changes: Topology changes.
        """
        for node_id, node_data in changes.get("nodes", {}).items():
            node = self._topology.get_node(node_id)
            if node:
                if "security_controls" in node_data:
                    node.security_controls = node_data["security_controls"]
                if "vulnerabilities" in node_data:
                    node.vulnerabilities = node_data["vulnerabilities"]

        logger.info(f"Topology updated with {len(changes)} changes")

    async def run_simulation(
        self,
        start_node: str,
        target_node: str,
        profile_variants: Optional[List[Dict[str, Any]]] = None,
    ) -> SimulationReport:
        """Run full simulation.

        Args:
            start_node: Starting node.
            target_node: Target node.
            profile_variants: Profile variants to test.

        Returns:
            SimulationReport.
        """
        start_time = time.time()

        simulation_id = hashlib.md5(
            f"sim_{time.time()}".encode()
        ).hexdigest()[:12]

        paths = self._simulator.generate_attack_paths(
            start_node, target_node,
        )

        for path in paths:
            self._simulator.simulate_path(path)

        best_path = max(paths, key=lambda p: p.risk_score) if paths else None

        if profile_variants:
            for i, variant_config in enumerate(profile_variants):
                self._evaluator.add_variant(
                    f"variant_{i}", variant_config,
                )

            await self._evaluator.evaluate_all(start_node, target_node)

        best_variant = self._evaluator.get_best_variant()

        elapsed = time.time() - start_time

        report = SimulationReport(
            simulation_id=simulation_id,
            paths_evaluated=len(paths),
            best_path=best_path,
            best_profile=best_variant,
            total_time=elapsed,
            timestamp=time.time(),
        )

        self._simulation_history.append(report)

        logger.info(
            f"Simulation complete: {len(paths)} paths evaluated, "
            f"best risk score: {best_path.risk_score if best_path else 0:.2f}"
        )

        return report

    def get_simulation_history(self) -> List[Dict[str, Any]]:
        """Get simulation history.

        Returns:
            List of simulation reports.
        """
        return [r.to_dict() for r in self._simulation_history]

    def get_status(self) -> Dict[str, Any]:
        """Get simulation manager status.

        Returns:
            Dictionary with status summary.
        """
        return {
            "topology": self._topology.get_status(),
            "evaluator": self._evaluator.get_status(),
            "simulation_count": len(self._simulation_history),
        }


# =============================================================================
# Global Singleton
# =============================================================================

_digital_twin_manager: Optional[DigitalTwinSimulationManager] = None


def get_digital_twin_manager() -> DigitalTwinSimulationManager:
    """Get the global DigitalTwinSimulationManager singleton.

    Returns:
        Singleton DigitalTwinSimulationManager instance.
    """
    global _digital_twin_manager
    if _digital_twin_manager is None:
        _digital_twin_manager = DigitalTwinSimulationManager()
    return _digital_twin_manager


__all__ = [
    "DigitalTwinSimulationManager",
    "NetworkTopologyModel",
    "AttackPathSimulator",
    "ProfilePreEvaluator",
    "NetworkNode",
    "NetworkEdge",
    "AttackStep",
    "AttackPath",
    "ProfileVariant",
    "SimulationReport",
    "NodeType",
    "SecurityControl",
    "AttackPhase",
    "SimulationResult",
    "get_digital_twin_manager",
]
