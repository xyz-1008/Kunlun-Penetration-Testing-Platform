"""Knowledge Graph Integration: Data linkage with asset, vulnerability, C2, domain control, and report modules.

Provides:
- Integration with asset discovery module
- Integration with vulnerability scanning module
- Integration with C2 framework and lateral movement module
- Integration with domain control attack module
- Integration with MITRE ATT&CK mapping module
- Integration with report module
- Event-driven graph updates
"""

import asyncio
import logging
from datetime import datetime
from typing import Any, Callable, Coroutine, Dict, List, Optional, Tuple

from .knowledge_graph_builder import KnowledgeGraphBuilder
from .knowledge_graph_model import (
    AttackPhase,
    AttackTechniqueNode,
    CredentialType,
    EdgeType,
    GraphNode,
    NodeType,
    SeverityLevel,
    UserAccountNode,
)
from .knowledge_graph_query import KnowledgeGraphQueryEngine
from .knowledge_graph_snapshot import KnowledgeGraphSnapshotManager
from .knowledge_graph_visualizer import KnowledgeGraphVisualizer

logger = logging.getLogger(__name__)


class KnowledgeGraphIntegration:
    """Integrates knowledge graph with other platform modules.

    Provides data synchronization, event-driven updates, and
    cross-module query capabilities for the knowledge graph.
    """

    def __init__(
        self,
        builder: Optional[KnowledgeGraphBuilder] = None,
        snapshot_dir: Optional[str] = None,
    ) -> None:
        """Initialize knowledge graph integration.

        Args:
            builder: Knowledge graph builder instance.
            snapshot_dir: Directory for storing snapshots.
        """
        self.builder = builder or KnowledgeGraphBuilder()
        self.query_engine = KnowledgeGraphQueryEngine(self.builder)
        self.visualizer = KnowledgeGraphVisualizer(self.builder)
        self.snapshot_manager = KnowledgeGraphSnapshotManager(snapshot_dir)

        self._event_handlers: Dict[str, List[Callable[[Dict[str, Any]], Coroutine[Any, Any, None]]]] = {}
        self._is_initialized = False

    async def initialize(self) -> None:
        """Initialize the knowledge graph integration.

        Sets up event listeners and loads existing data from modules.
        """
        if self._is_initialized:
            return

        await self._setup_event_listeners()
        self._is_initialized = True

    async def sync_from_asset_module(
        self,
        assets: List[Dict[str, Any]],
    ) -> Tuple[int, int]:
        """Synchronize data from asset discovery module.

        Args:
            assets: List of asset dictionaries from asset discovery.

        Returns:
            Tuple of (nodes_added, edges_added).
        """
        nodes, edges = self.builder.build_from_asset_discovery(assets)

        await self._emit_event("asset_sync", {
            "nodes_added": nodes,
            "edges_added": edges,
            "asset_count": len(assets),
        })

        return nodes, edges

    async def sync_from_vulnerability_module(
        self,
        vulnerabilities: List[Dict[str, Any]],
    ) -> Tuple[int, int]:
        """Synchronize data from vulnerability scanning module.

        Args:
            vulnerabilities: List of vulnerability dictionaries.

        Returns:
            Tuple of (nodes_added, edges_added).
        """
        nodes, edges = self.builder.build_from_vulnerability_scan(vulnerabilities)

        await self._emit_event("vulnerability_sync", {
            "nodes_added": nodes,
            "edges_added": edges,
            "vuln_count": len(vulnerabilities),
        })

        return nodes, edges

    async def sync_from_lateral_movement_module(
        self,
        movements: List[Dict[str, Any]],
    ) -> Tuple[int, int]:
        """Synchronize data from lateral movement module.

        Args:
            movements: List of lateral movement dictionaries.

        Returns:
            Tuple of (nodes_added, edges_added).
        """
        nodes, edges = self.builder.build_from_lateral_movement_logs(movements)

        await self._emit_event("lateral_movement_sync", {
            "nodes_added": nodes,
            "edges_added": edges,
            "movement_count": len(movements),
        })

        return nodes, edges

    async def sync_from_credential_module(
        self,
        credentials: List[Dict[str, Any]],
    ) -> Tuple[int, int]:
        """Synchronize data from credential database.

        Args:
            credentials: List of credential dictionaries.

        Returns:
            Tuple of (nodes_added, edges_added).
        """
        nodes, edges = self.builder.build_from_credentials(credentials)

        await self._emit_event("credential_sync", {
            "nodes_added": nodes,
            "edges_added": edges,
            "cred_count": len(credentials),
        })

        return nodes, edges

    async def sync_from_domain_module(
        self,
        domain_data: List[Dict[str, Any]],
    ) -> Tuple[int, int]:
        """Synchronize data from domain control attack module.

        Args:
            domain_data: List of domain penetration dictionaries.

        Returns:
            Tuple of (nodes_added, edges_added).
        """
        nodes, edges = self.builder.build_from_domain_pentest(domain_data)

        await self._emit_event("domain_sync", {
            "nodes_added": nodes,
            "edges_added": edges,
            "domain_count": len(domain_data),
        })

        return nodes, edges

    async def sync_from_fid_module(
        self,
        clusters: List[Dict[str, Any]],
    ) -> Tuple[int, int]:
        """Synchronize data from FID clustering module.

        Args:
            clusters: List of FID cluster dictionaries.

        Returns:
            Tuple of (nodes_added, edges_added).
        """
        nodes, edges = self.builder.build_from_fid_clustering(clusters)

        await self._emit_event("fid_sync", {
            "nodes_added": nodes,
            "edges_added": edges,
            "cluster_count": len(clusters),
        })

        return nodes, edges

    async def sync_from_attack_technique_module(
        self,
        techniques: List[Dict[str, Any]],
    ) -> Tuple[int, int]:
        """Synchronize data from MITRE ATT&CK mapping module.

        Args:
            techniques: List of attack technique dictionaries.

        Returns:
            Tuple of (nodes_added, edges_added).
        """
        nodes_added = 0
        edges_added = 0

        for tech in techniques:
            attack_id = tech.get("attack_id", "")
            if attack_id:
                node_id = self.builder.add_attack_technique_node(
                    attack_id=attack_id,
                    technique_name=tech.get("technique_name", ""),
                    tactic=tech.get("tactic", ""),
                )
                nodes_added += 1

            event_id = tech.get("event_id", "")
            if event_id and attack_id:
                self.builder.add_attack_technique_mapping_edge(
                    event_id=event_id,
                    technique_id=node_id,
                )
                edges_added += 1

        await self._emit_event("attack_technique_sync", {
            "nodes_added": nodes_added,
            "edges_added": edges_added,
            "technique_count": len(techniques),
        })

        return nodes_added, edges_added

    async def sync_from_user_module(
        self,
        users: List[Dict[str, Any]],
    ) -> Tuple[int, int]:
        """Synchronize data from user/account module.

        Args:
            users: List of user dictionaries.

        Returns:
            Tuple of (nodes_added, edges_added).
        """
        nodes_added = 0

        for user in users:
            username = user.get("username", "")
            if username:
                self.builder.add_user_account_node(
                    username=username,
                    sid=user.get("sid", ""),
                    domain=user.get("domain", ""),
                    groups=user.get("groups", []),
                )
                nodes_added += 1

        await self._emit_event("user_sync", {
            "nodes_added": nodes_added,
            "user_count": len(users),
        })

        return nodes_added, 0

    async def create_snapshot(
        self,
        name: str = "",
        description: str = "",
    ) -> Any:
        """Create a snapshot of the current graph state.

        Args:
            name: Snapshot name.
            description: Snapshot description.

        Returns:
            GraphSnapshot object.
        """
        return self.snapshot_manager.create_snapshot(
            self.builder,
            name=name,
            description=description,
        )

    async def get_force_directed_layout(
        self,
        iterations: int = 50,
    ) -> Dict[str, Any]:
        """Get force-directed graph layout data.

        Args:
            iterations: Number of layout iterations.

        Returns:
            Dictionary with nodes and edges for frontend.
        """
        return self.visualizer.generate_force_directed_layout(iterations)

    async def get_layered_view(self) -> Dict[str, Any]:
        """Get layered view by attack phase.

        Returns:
            Dictionary with layered nodes and edges.
        """
        return self.visualizer.generate_layered_view()

    async def get_timeline_data(self) -> List[Dict[str, Any]]:
        """Get timeline view data.

        Returns:
            List of timeline snapshots.
        """
        return self.visualizer.generate_timeline_data()

    async def get_attack_surface_score(self) -> Dict[str, Any]:
        """Get attack surface assessment score card.

        Returns:
            Dictionary with attack surface scores.
        """
        score = self.query_engine.assess_attack_surface()
        return score.model_dump()

    async def get_attack_recommendations(
        self,
        compromised_nodes: Optional[List[str]] = None,
        max_count: int = 5,
    ) -> List[Dict[str, Any]]:
        """Get attack target recommendations.

        Args:
            compromised_nodes: List of compromised node IDs.
            max_count: Maximum number of recommendations.

        Returns:
            List of recommendation dictionaries.
        """
        recommendations = self.query_engine.recommend_next_targets(
            compromised_nodes,
            max_count,
        )
        return [r.model_dump() for r in recommendations]

    async def find_shortest_path_to_domain(
        self,
        source_node_id: str,
        max_paths: int = 5,
    ) -> List[Dict[str, Any]]:
        """Find shortest attack paths to domain controller.

        Args:
            source_node_id: Source node ID.
            max_paths: Maximum number of paths.

        Returns:
            List of path dictionaries.
        """
        paths = self.query_engine.find_all_paths_to_domain_controller(
            source_node_id,
            max_paths,
        )
        return [p.model_dump() for p in paths]

    async def compare_snapshots(
        self,
        snapshot_a_id: str,
        snapshot_b_id: str,
        format: str = "text",
    ) -> Optional[str]:
        """Compare two snapshots and generate report.

        Args:
            snapshot_a_id: First snapshot ID.
            snapshot_b_id: Second snapshot ID.
            format: Report format.

        Returns:
            Formatted report string or None.
        """
        diff = self.snapshot_manager.compare_snapshots(snapshot_a_id, snapshot_b_id)
        if diff is None:
            return None

        return self.snapshot_manager.generate_diff_report(diff, format)

    async def export_graph(
        self,
        format: str = "json",
        snapshot_id: Optional[str] = None,
    ) -> Optional[str]:
        """Export graph data in various formats.

        Args:
            format: Export format (json/graphml/gexf).
            snapshot_id: Snapshot ID to export (None for current graph).

        Returns:
            Exported data string or None.
        """
        if snapshot_id:
            return self.snapshot_manager.export_snapshot(snapshot_id, format)

        if format == "json":
            data = {
                "nodes": [n.model_dump() for n in self.builder.get_all_nodes().values()],
                "edges": [e.model_dump() for e in self.builder.get_all_edges().values()],
                "metadata": self.builder.get_metadata().model_dump(),
            }
            import json
            return json.dumps(data, indent=2, default=str)

        return None

    async def embed_in_report(
        self,
        report_data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Embed knowledge graph data in a penetration test report.

        Args:
            report_data: Report data dictionary.

        Returns:
            Updated report data with graph information.
        """
        attack_surface = await self.get_attack_surface_score()
        recommendations = await self.get_attack_recommendations()

        report_data["knowledge_graph"] = {
            "metadata": self.builder.get_metadata().model_dump(),
            "attack_surface": attack_surface,
            "recommendations": recommendations,
            "visualization": await self.get_force_directed_layout(),
        }

        return report_data

    def register_event_handler(
        self,
        event_type: str,
        handler: Callable[[Dict[str, Any]], Coroutine[Any, Any, None]],
    ) -> None:
        """Register an event handler for graph events.

        Args:
            event_type: Event type to handle.
            handler: Async event handler function.
        """
        if event_type not in self._event_handlers:
            self._event_handlers[event_type] = []

        self._event_handlers[event_type].append(handler)

    async def _setup_event_listeners(self) -> None:
        """Setup event listeners for automatic graph updates."""
        logger.info("Knowledge graph event listeners initialized")

    async def _emit_event(self, event_type: str, data: Dict[str, Any]) -> None:
        """Emit an event to registered handlers.

        Args:
            event_type: Event type.
            data: Event data.
        """
        handlers = self._event_handlers.get(event_type, [])

        for handler in handlers:
            try:
                await handler(data)
            except Exception as e:
                logger.error(f"Event handler error for {event_type}: {e}")

    def get_graph_statistics(self) -> Dict[str, Any]:
        """Get comprehensive graph statistics.

        Returns:
            Dictionary with graph statistics.
        """
        all_nodes = self.builder.get_all_nodes()
        all_edges = self.builder.get_all_edges()

        node_type_counts: Dict[str, int] = {}
        for node in all_nodes.values():
            node_type_counts[node.node_type.value] = (
                node_type_counts.get(node.node_type.value, 0) + 1
            )

        edge_type_counts: Dict[str, int] = {}
        for edge in all_edges.values():
            edge_type_counts[edge.edge_type.value] = (
                edge_type_counts.get(edge.edge_type.value, 0) + 1
            )

        return {
            "total_nodes": len(all_nodes),
            "total_edges": len(all_edges),
            "node_type_counts": node_type_counts,
            "edge_type_counts": edge_type_counts,
            "metadata": self.builder.get_metadata().model_dump(),
        }

    def clear_graph(self) -> None:
        """Clear the entire graph and reset state."""
        self.builder.clear()
        self._is_initialized = False
