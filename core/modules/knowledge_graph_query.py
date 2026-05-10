"""Knowledge Graph Query Engine: Graph querying, shortest path calculation, attack path recommendation.

Provides:
- Cypher-style query support and Python chain query API
- Pre-built queries: shortest path to domain controller, assets affected by vulnerability,
  hosts accessible by credential
- Dijkstra/A* shortest path calculation with configurable weights
- Attack surface assessment scoring
- Attack target recommendation engine
"""

import logging
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

import networkx as nx

from .knowledge_graph_builder import KnowledgeGraphBuilder
from .knowledge_graph_model import (
    AttackPath,
    AttackRecommendation,
    AttackSurfaceScore,
    CredentialNode,
    EdgeType,
    GraphEdge,
    GraphNode,
    IPAddressNode,
    NodeType,
    QueryResult,
    SeverityLevel,
    VulnerabilityNode,
)

logger = logging.getLogger(__name__)


class GraphQuery:
    """Fluent query builder for graph queries.

    Provides chainable query API for filtering nodes and edges.
    """

    def __init__(self, builder: KnowledgeGraphBuilder) -> None:
        """Initialize graph query.

        Args:
            builder: Knowledge graph builder instance.
        """
        self._builder = builder
        self._node_filters: List[Callable[[GraphNode], bool]] = []
        self._edge_filters: List[Callable[[GraphEdge], bool]] = []
        self._limit_count: Optional[int] = None

    def node_type(self, node_type: NodeType) -> "GraphQuery":
        """Filter by node type.

        Args:
            node_type: Node type to filter.

        Returns:
            Self for chaining.
        """
        self._node_filters.append(lambda n: n.node_type == node_type)
        return self

    def edge_type(self, edge_type: EdgeType) -> "GraphQuery":
        """Filter by edge type.

        Args:
            edge_type: Edge type to filter.

        Returns:
            Self for chaining.
        """
        self._edge_filters.append(lambda e: e.edge_type == edge_type)
        return self

    def property_equals(self, key: str, value: Any) -> "GraphQuery":
        """Filter by property equality.

        Args:
            key: Property key.
            value: Property value.

        Returns:
            Self for chaining.
        """
        self._node_filters.append(lambda n: n.properties.get(key) == value)
        return self

    def label_contains(self, substring: str) -> "GraphQuery":
        """Filter by label containing substring.

        Args:
            substring: Substring to search for.

        Returns:
            Self for chaining.
        """
        self._node_filters.append(lambda n: substring.lower() in n.label.lower())
        return self

    def limit(self, count: int) -> "GraphQuery":
        """Limit result count.

        Args:
            count: Maximum number of results.

        Returns:
            Self for chaining.
        """
        self._limit_count = count
        return self

    def execute_nodes(self) -> List[GraphNode]:
        """Execute query and return matching nodes.

        Returns:
            List of matching GraphNode objects.
        """
        results = []

        for node in self._builder.get_all_nodes().values():
            if all(f(node) for f in self._node_filters):
                results.append(node)

        if self._limit_count is not None:
            results = results[: self._limit_count]

        return results

    def execute_edges(self) -> List[GraphEdge]:
        """Execute query and return matching edges.

        Returns:
            List of matching GraphEdge objects.
        """
        results = []

        for edge in self._builder.get_all_edges().values():
            if all(f(edge) for f in self._edge_filters):
                results.append(edge)

        if self._limit_count is not None:
            results = results[: self._limit_count]

        return results


class KnowledgeGraphQueryEngine:
    """Query engine for the knowledge graph.

    Provides shortest path calculation, attack surface assessment,
    and attack target recommendation.
    """

    def __init__(self, builder: KnowledgeGraphBuilder) -> None:
        """Initialize query engine.

        Args:
            builder: Knowledge graph builder instance.
        """
        self.builder = builder

    def query(self) -> GraphQuery:
        """Create a new fluent query builder.

        Returns:
            GraphQuery instance for chaining.
        """
        return GraphQuery(self.builder)

    def find_shortest_path(
        self,
        source_node_id: str,
        target_node_id: str,
        algorithm: str = "dijkstra",
        max_paths: int = 3,
    ) -> List[AttackPath]:
        """Find shortest attack path between two nodes.

        Args:
            source_node_id: Source node ID.
            target_node_id: Target node ID.
            algorithm: Algorithm to use (dijkstra/astar).
            max_paths: Maximum number of paths to return.

        Returns:
            List of AttackPath objects.
        """
        graph = self.builder.get_networkx_graph()

        if source_node_id not in graph or target_node_id not in graph:
            return []

        paths: List[AttackPath] = []

        try:
            if algorithm == "dijkstra":
                path_nodes = nx.shortest_path(
                    graph,
                    source=source_node_id,
                    target=target_node_id,
                    weight="weight",
                    method="dijkstra",
                )

                path = self._build_attack_path(path_nodes, 1)
                if path:
                    paths.append(path)

            elif algorithm == "astar":
                path_nodes = nx.astar_path(
                    graph,
                    source=source_node_id,
                    target=target_node_id,
                    weight="weight",
                )

                path = self._build_attack_path(path_nodes, 1)
                if path:
                    paths.append(path)

        except (nx.NetworkXNoPath, nx.NodeNotFound) as e:
            logger.warning(f"No path found: {e}")

        return paths[:max_paths]

    def find_all_paths_to_domain_controller(
        self,
        source_node_id: str,
        max_paths: int = 5,
    ) -> List[AttackPath]:
        """Find all attack paths from source to any domain controller.

        Args:
            source_node_id: Source node ID (typically external IP).
            max_paths: Maximum number of paths to return.

        Returns:
            List of AttackPath objects.
        """
        dc_nodes = self.query().node_type(NodeType.DOMAIN_CONTROLLER).execute_nodes()

        all_paths: List[AttackPath] = []

        for dc_node in dc_nodes:
            paths = self.find_shortest_path(source_node_id, dc_node.node_id)
            all_paths.extend(paths)

        all_paths.sort(key=lambda p: p.total_weight)
        return all_paths[:max_paths]

    def find_assets_affected_by_vulnerability(
        self,
        cve_id: str,
    ) -> List[GraphNode]:
        """Find all assets affected by a specific vulnerability.

        Args:
            cve_id: CVE identifier.

        Returns:
            List of affected asset nodes.
        """
        vuln_id = f"vuln_{cve_id}"
        affected_assets: List[GraphNode] = []

        graph = self.builder.get_networkx_graph()

        if vuln_id not in graph:
            return affected_assets

        for neighbor in graph.neighbors(vuln_id):
            node = self.builder.get_node(neighbor)
            if node:
                affected_assets.append(node)

        return affected_assets

    def find_hosts_accessible_by_credential(
        self,
        cred_id: str,
    ) -> List[GraphNode]:
        """Find all hosts accessible by a specific credential.

        Args:
            cred_id: Credential node ID.

        Returns:
            List of accessible host nodes.
        """
        accessible_hosts: List[GraphNode] = []

        graph = self.builder.get_networkx_graph()

        if cred_id not in graph:
            return accessible_hosts

        for neighbor in graph.neighbors(cred_id):
            edge_data = graph.get_edge_data(cred_id, neighbor)
            if edge_data:
                for edge_key, edge_attrs in edge_data.items():
                    if edge_attrs.get("edge_type") == EdgeType.CREDENTIAL_ASSOCIATION.value:
                        node = self.builder.get_node(neighbor)
                        if node and node.node_type in (
                            NodeType.HOST,
                            NodeType.IP_ADDRESS,
                            NodeType.DOMAIN_CONTROLLER,
                        ):
                            accessible_hosts.append(node)

        return accessible_hosts

    def assess_attack_surface(self) -> AttackSurfaceScore:
        """Assess the overall attack surface from the graph.

        Returns:
            AttackSurfaceScore with detailed metrics.
        """
        score = AttackSurfaceScore()

        all_nodes = self.builder.get_all_nodes()
        all_edges = self.builder.get_all_edges()

        public_ips = [
            n for n in all_nodes.values()
            if isinstance(n, IPAddressNode) and n.is_public
        ]
        score.public_ip_count = len(public_ips)

        open_ports = [
            n for n in all_nodes.values()
            if n.node_type == NodeType.PORT_SERVICE
        ]
        score.open_port_count = len(open_ports)

        high_severity_vulns = [
            n for n in all_nodes.values()
            if isinstance(n, VulnerabilityNode)
            and n.severity in (SeverityLevel.CRITICAL, SeverityLevel.HIGH)
        ]
        score.high_severity_vuln_count = len(high_severity_vulns)

        lateral_edges = [
            e for e in all_edges.values()
            if e.edge_type == EdgeType.LATERAL_MOVEMENT
        ]
        score.reachable_host_count = len(set(
            e.target_id for e in lateral_edges
        ))

        cred_nodes = [
            n for n in all_nodes.values()
            if isinstance(n, CredentialNode)
        ]
        total_hosts = len([
            n for n in all_nodes.values()
            if n.node_type == NodeType.HOST
        ])
        if total_hosts > 0:
            score.credential_coverage = min(1.0, len(cred_nodes) / total_hosts)

        dc_nodes = [
            n for n in all_nodes.values()
            if n.node_type == NodeType.DOMAIN_CONTROLLER
        ]
        if dc_nodes and public_ips:
            paths = self.find_all_paths_to_domain_controller(public_ips[0].node_id)
            score.domain_path_count = len(paths)
            if paths:
                score.shortest_domain_path_length = len(paths[0].nodes)

        score.external_exposure_score = self._calculate_external_score(score)
        score.internal_risk_score = self._calculate_internal_score(score)
        score.domain_risk_score = self._calculate_domain_score(score)
        score.overall_score = self._calculate_overall_score(score)

        return score

    def recommend_next_targets(
        self,
        compromised_node_ids: Optional[List[str]] = None,
        max_recommendations: int = 5,
    ) -> List[AttackRecommendation]:
        """Recommend next attack targets based on current position.

        Args:
            compromised_node_ids: List of currently compromised node IDs.
            max_recommendations: Maximum number of recommendations.

        Returns:
            List of AttackRecommendation objects.
        """
        recommendations: List[AttackRecommendation] = []

        if compromised_node_ids is None:
            compromised_node_ids = []

        all_nodes = self.builder.get_all_nodes()
        graph = self.builder.get_networkx_graph()

        compromised_set = set(compromised_node_ids)

        vuln_nodes = [
            n for n in all_nodes.values()
            if isinstance(n, VulnerabilityNode) and not n.is_exploited
        ]

        for vuln in vuln_nodes:
            for neighbor in graph.neighbors(vuln.node_id):
                if neighbor not in compromised_set:
                    target_node = self.builder.get_node(neighbor)
                    if target_node:
                        recommendations.append(AttackRecommendation(
                            target_node_id=neighbor,
                            target_label=target_node.label,
                            reason=f"Host has unpatched vulnerability: {vuln.vuln_name} ({vuln.cve_id})",
                            success_probability=min(1.0, vuln.cvss_score / 10.0),
                            next_steps=[f"Exploit {vuln.cve_id}", "Establish persistence"],
                        ))

        cred_nodes = [
            n for n in all_nodes.values()
            if isinstance(n, CredentialNode)
        ]

        for cred in cred_nodes:
            accessible = self.find_hosts_accessible_by_credential(cred.node_id)
            for host in accessible:
                if host.node_id not in compromised_set:
                    recommendations.append(AttackRecommendation(
                        target_node_id=host.node_id,
                        target_label=host.label,
                        reason=f"Credential available for {cred.username} on {host.label}",
                        success_probability=0.8,
                        required_credentials=[cred.node_id],
                        next_steps=["Lateral movement", "Privilege escalation"],
                    ))

        recommendations.sort(key=lambda r: r.success_probability, reverse=True)
        return recommendations[:max_recommendations]

    def filter_by_attack_phase(
        self,
        phase: str,
    ) -> Tuple[List[GraphNode], List[GraphEdge]]:
        """Filter graph by attack phase.

        Args:
            phase: Attack phase string.

        Returns:
            Tuple of (nodes, edges) in the specified phase.
        """
        nodes = self.query().property_equals("attack_phase", phase).execute_nodes()

        node_ids = {n.node_id for n in nodes}
        edges = [
            e for e in self.builder.get_all_edges().values()
            if e.source_id in node_ids or e.target_id in node_ids
        ]

        return nodes, edges

    def _build_attack_path(
        self,
        path_nodes: List[str],
        path_index: int,
    ) -> Optional[AttackPath]:
        """Build an AttackPath from a list of node IDs.

        Args:
            path_nodes: List of node IDs in the path.
            path_index: Path index for ID generation.

        Returns:
            AttackPath or None.
        """
        if len(path_nodes) < 2:
            return None

        graph = self.builder.get_networkx_graph()
        total_weight = 0.0
        edge_ids: List[str] = []

        for i in range(len(path_nodes) - 1):
            source = str(path_nodes[i])
            target = str(path_nodes[i + 1])

            edge_data = graph.get_edge_data(source, target)
            if edge_data:
                for edge_key, edge_attrs in edge_data.items():
                    weight = edge_attrs.get("weight", 1.0)
                    total_weight += weight
                    edge_ids.append(str(edge_key))

        labels = []
        for n in path_nodes:
            node = self.builder.get_node(str(n))
            if node:
                labels.append(node.label)
            else:
                labels.append(str(n))

        description = " → ".join(labels)

        risk_score = min(100.0, total_weight * 20)

        return AttackPath(
            path_id=f"path_{path_index}",
            nodes=path_nodes,
            edges=edge_ids,
            total_weight=total_weight,
            description=description,
            risk_score=risk_score,
        )

    def _calculate_external_score(self, score: AttackSurfaceScore) -> float:
        """Calculate external exposure score.

        Args:
            score: Current attack surface score.

        Returns:
            External exposure score (0-100).
        """
        ip_score = min(30, score.public_ip_count * 3)
        port_score = min(30, score.open_port_count * 0.5)
        vuln_score = min(40, score.high_severity_vuln_count * 10)

        return ip_score + port_score + vuln_score

    def _calculate_internal_score(self, score: AttackSurfaceScore) -> float:
        """Calculate internal lateral movement risk score.

        Args:
            score: Current attack surface score.

        Returns:
            Internal risk score (0-100).
        """
        reach_score = min(50, score.reachable_host_count * 2)
        cred_score = min(50, score.credential_coverage * 50)

        return reach_score + cred_score

    def _calculate_domain_score(self, score: AttackSurfaceScore) -> float:
        """Calculate domain compromise risk score.

        Args:
            score: Current attack surface score.

        Returns:
            Domain risk score (0-100).
        """
        if score.domain_path_count == 0:
            return 0.0

        path_score = min(60, score.domain_path_count * 15)

        if score.shortest_domain_path_length > 0:
            length_score = max(0, 40 - (score.shortest_domain_path_length * 5))
        else:
            length_score = 0

        return path_score + length_score

    def _calculate_overall_score(self, score: AttackSurfaceScore) -> float:
        """Calculate overall attack surface score.

        Args:
            score: Current attack surface score.

        Returns:
            Overall score (0-100).
        """
        return (
            score.external_exposure_score * 0.4
            + score.internal_risk_score * 0.35
            + score.domain_risk_score * 0.25
        )
