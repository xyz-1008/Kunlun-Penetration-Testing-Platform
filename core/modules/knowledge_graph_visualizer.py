"""Knowledge Graph Visualizer: Force-directed graph, layered view, timeline view data interfaces.

Provides:
- Force-directed graph layout calculation using NetworkX
- Layered view by attack phase
- Timeline view data for historical evolution
- Node styling (colors, sizes, icons by type)
- Edge styling (line types, colors by relationship type)
- Frontend data format conversion for D3.js/vis.js
"""

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple

import networkx as nx

from .knowledge_graph_builder import KnowledgeGraphBuilder
from .knowledge_graph_model import (
    AttackPath,
    EdgeType,
    GraphEdge,
    GraphNode,
    NodeType,
    VulnerabilityNode,
)

logger = logging.getLogger(__name__)


NODE_COLORS = {
    NodeType.IP_ADDRESS: "#3498db",
    NodeType.DOMAIN: "#2ecc71",
    NodeType.PORT_SERVICE: "#9b59b6",
    NodeType.VULNERABILITY: "#e74c3c",
    NodeType.CREDENTIAL: "#f39c12",
    NodeType.HOST: "#1abc9c",
    NodeType.DOMAIN_CONTROLLER: "#c0392b",
    NodeType.ATTACK_TECHNIQUE: "#8e44ad",
    NodeType.USER_ACCOUNT: "#34495e",
}

NODE_ICONS = {
    NodeType.IP_ADDRESS: "globe",
    NodeType.DOMAIN: "link",
    NodeType.PORT_SERVICE: "plug",
    NodeType.VULNERABILITY: "bug",
    NodeType.CREDENTIAL: "key",
    NodeType.HOST: "server",
    NodeType.DOMAIN_CONTROLLER: "shield",
    NodeType.ATTACK_TECHNIQUE: "crosshairs",
    NodeType.USER_ACCOUNT: "user",
}

EDGE_COLORS = {
    EdgeType.DNS_RESOLUTION: "#95a5a6",
    EdgeType.PORT_OPEN: "#3498db",
    EdgeType.VULNERABILITY_AFFECTS: "#e74c3c",
    EdgeType.CREDENTIAL_ASSOCIATION: "#f39c12",
    EdgeType.LATERAL_MOVEMENT: "#e74c3c",
    EdgeType.DOMAIN_TRUST: "#8e44ad",
    EdgeType.CERTIFICATE_SHARING: "#16a085",
    EdgeType.SAME_APP_FAMILY: "#27ae60",
    EdgeType.ATTACK_TECHNIQUE_MAPPING: "#d35400",
}

EDGE_STYLES = {
    EdgeType.DNS_RESOLUTION: "solid",
    EdgeType.PORT_OPEN: "solid",
    EdgeType.VULNERABILITY_AFFECTS: "dashed",
    EdgeType.CREDENTIAL_ASSOCIATION: "dotted",
    EdgeType.LATERAL_MOVEMENT: "dashed",
    EdgeType.DOMAIN_TRUST: "solid",
    EdgeType.CERTIFICATE_SHARING: "solid",
    EdgeType.SAME_APP_FAMILY: "solid",
    EdgeType.ATTACK_TECHNIQUE_MAPPING: "dashed",
}


class VisualNode:
    """Visual representation of a graph node for frontend rendering.

    Attributes:
        id: Node identifier
        label: Display label
        node_type: Node type
        color: Node color
        icon: Node icon
        size: Node size (based on importance)
        x: X coordinate (for layout)
        y: Y coordinate (for layout)
        properties: Node properties for tooltip
        layer: Attack phase layer
    """

    def __init__(
        self,
        id: str,
        label: str,
        node_type: NodeType,
        color: str = "#3498db",
        icon: str = "circle",
        size: float = 20.0,
        x: float = 0.0,
        y: float = 0.0,
        properties: Optional[Dict[str, Any]] = None,
        layer: str = "",
    ) -> None:
        """Initialize visual node.

        Args:
            id: Node identifier.
            label: Display label.
            node_type: Node type.
            color: Node color.
            icon: Node icon.
            size: Node size.
            x: X coordinate.
            y: Y coordinate.
            properties: Node properties.
            layer: Attack phase layer.
        """
        self.id = id
        self.label = label
        self.node_type = node_type
        self.color = color
        self.icon = icon
        self.size = size
        self.x = x
        self.y = y
        self.properties = properties or {}
        self.layer = layer

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for frontend.

        Returns:
            Dictionary representation.
        """
        return {
            "id": self.id,
            "label": self.label,
            "node_type": self.node_type.value,
            "color": self.color,
            "icon": self.icon,
            "size": self.size,
            "x": self.x,
            "y": self.y,
            "properties": self.properties,
            "layer": self.layer,
        }


class VisualEdge:
    """Visual representation of a graph edge for frontend rendering.

    Attributes:
        id: Edge identifier
        source: Source node ID
        target: Target node ID
        edge_type: Edge type
        color: Edge color
        style: Edge style (solid/dashed/dotted)
        width: Edge width
        label: Edge label
    """

    def __init__(
        self,
        id: str,
        source: str,
        target: str,
        edge_type: EdgeType,
        color: str = "#95a5a6",
        style: str = "solid",
        width: float = 1.0,
        label: str = "",
        properties: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Initialize visual edge.

        Args:
            id: Edge identifier.
            source: Source node ID.
            target: Target node ID.
            edge_type: Edge type.
            color: Edge color.
            style: Edge style.
            width: Edge width.
            label: Edge label.
            properties: Edge properties.
        """
        self.id = id
        self.source = source
        self.target = target
        self.edge_type = edge_type
        self.color = color
        self.style = style
        self.width = width
        self.label = label
        self.properties: Dict[str, Any] = properties or {}

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for frontend.

        Returns:
            Dictionary representation.
        """
        return {
            "id": self.id,
            "from": self.source,
            "to": self.target,
            "edge_type": self.edge_type.value,
            "color": self.color,
            "style": self.style,
            "width": self.width,
            "label": self.label,
            "properties": self.properties,
        }


class KnowledgeGraphVisualizer:
    """Generates visualization data for the knowledge graph.

    Provides force-directed layout, layered view, timeline view,
    and attack path highlighting data for frontend rendering.
    """

    def __init__(self, builder: KnowledgeGraphBuilder) -> None:
        """Initialize visualizer.

        Args:
            builder: Knowledge graph builder instance.
        """
        self.builder = builder

    def generate_force_directed_layout(
        self,
        iterations: int = 50,
        scale: float = 1.0,
    ) -> Dict[str, Any]:
        """Generate force-directed graph layout data.

        Args:
            iterations: Number of layout iterations.
            scale: Layout scale factor.

        Returns:
            Dictionary with nodes and edges for D3.js/vis.js.
        """
        graph = self.builder.get_networkx_graph()

        try:
            pos = nx.spring_layout(graph, iterations=iterations, seed=42)
        except Exception as e:
            logger.warning(f"Force-directed layout failed: {e}")
            pos = {node: (0.0, 0.0) for node in graph.nodes()}  # type: ignore[misc]

        visual_nodes = []
        for node_id in graph.nodes():
            coords = pos.get(node_id, (0.0, 0.0))
            x = float(coords[0])
            y = float(coords[1])
            node = self.builder.get_node(node_id)
            if node:
                visual_node = self._create_visual_node(node, x * scale, y * scale)
                visual_nodes.append(visual_node.to_dict())

        visual_edges = []
        for edge_id, edge in self.builder.get_all_edges().items():
            visual_edge = self._create_visual_edge(edge)
            visual_edges.append(visual_edge.to_dict())

        return {
            "nodes": visual_nodes,
            "edges": visual_edges,
            "layout": "force_directed",
        }

    def generate_layered_view(
        self,
        layer_spacing: float = 100.0,
    ) -> Dict[str, Any]:
        """Generate layered view by attack phase.

        Args:
            layer_spacing: Spacing between layers.

        Returns:
            Dictionary with layered nodes and edges.
        """
        layers: Dict[str, Dict[str, Any]] = {
            "external_recon": {"label": "外网暴露层", "nodes": [], "y": 0},
            "initial_access": {"label": "边界突破层", "nodes": [], "y": layer_spacing},
            "establish_foothold": {"label": "内网立足点", "nodes": [], "y": layer_spacing * 2},
            "lateral_movement": {"label": "横向移动层", "nodes": [], "y": layer_spacing * 3},
            "domain_compromise": {"label": "域控层", "nodes": [], "y": layer_spacing * 4},
        }

        all_nodes = self.builder.get_all_nodes()

        for node_id, node in all_nodes.items():
            phase = node.properties.get("attack_phase", "")

            if node.node_type == NodeType.DOMAIN_CONTROLLER:
                phase = "domain_compromise"
            elif node.node_type == NodeType.VULNERABILITY:
                phase = "initial_access"
            elif node.node_type == NodeType.CREDENTIAL:
                phase = "establish_foothold"

            if phase in layers:
                layer_nodes = layers[phase]["nodes"]
                if not isinstance(layer_nodes, list):
                    layer_nodes = []
                    layers[phase]["nodes"] = layer_nodes
                x = float(len(layer_nodes) * 80)
                y = float(layers[phase]["y"])

                visual_node = self._create_visual_node(node, x, y)
                layer_nodes.append(visual_node.to_dict())

        visual_edges = []
        for edge_id, edge in self.builder.get_all_edges().items():
            visual_edge = self._create_visual_edge(edge)
            visual_edges.append(visual_edge.to_dict())

        return {
            "layers": layers,
            "edges": visual_edges,
            "layout": "layered",
        }

    def generate_timeline_data(
        self,
        time_field: str = "created_at",
    ) -> List[Dict[str, Any]]:
        """Generate timeline view data showing graph evolution.

        Args:
            time_field: Field to use for time ordering.

        Returns:
            List of timeline snapshots with nodes and edges.
        """
        all_nodes = self.builder.get_all_nodes()
        all_edges = self.builder.get_all_edges()

        sorted_nodes = sorted(
            all_nodes.values(),
            key=lambda n: getattr(n, time_field, datetime.now()),
        )

        timeline: List[Dict[str, Any]] = []
        cumulative_nodes: Set[str] = set()
        cumulative_edges: Set[str] = set()

        for node in sorted_nodes:
            cumulative_nodes.add(node.node_id)

            snapshot_nodes = []
            for nid in cumulative_nodes:
                n = all_nodes.get(nid)
                if n:
                    visual_node = self._create_visual_node(n, 0, 0)
                    snapshot_nodes.append(visual_node.to_dict())

            snapshot_edges = []
            for eid, edge in all_edges.items():
                if edge.source_id in cumulative_nodes and edge.target_id in cumulative_nodes:
                    cumulative_edges.add(eid)
                    visual_edge = self._create_visual_edge(edge)
                    snapshot_edges.append(visual_edge.to_dict())

            timeline.append({
                "timestamp": getattr(node, time_field, datetime.now()).isoformat(),
                "nodes": snapshot_nodes,
                "edges": snapshot_edges,
                "node_count": len(cumulative_nodes),
                "edge_count": len(cumulative_edges),
            })

        return timeline

    def generate_highlighted_path(
        self,
        attack_path: AttackPath,
        dim_non_path: bool = True,
    ) -> Dict[str, Any]:
        """Generate visualization data with attack path highlighted.

        Args:
            attack_path: Attack path to highlight.
            dim_non_path: Whether to dim non-path nodes.

        Returns:
            Dictionary with highlighted path visualization data.
        """
        path_node_ids = set(attack_path.nodes)
        path_edge_ids = set(attack_path.edges)

        all_nodes = self.builder.get_all_nodes()
        all_edges = self.builder.get_all_edges()

        graph = self.builder.get_networkx_graph()

        try:
            pos = nx.spring_layout(graph, seed=42)
        except Exception:
            pos = {node: (0.0, 0.0) for node in graph.nodes()}  # type: ignore[misc]

        visual_nodes = []
        for node_id, node in all_nodes.items():
            coords = pos.get(node_id, (0.0, 0.0))
            x, y = float(coords[0]), float(coords[1])
            visual_node = self._create_visual_node(node, x, y)

            if node_id in path_node_ids:
                visual_node.size *= 1.5
            elif dim_non_path:
                visual_node.properties["opacity"] = 0.2

            visual_nodes.append(visual_node.to_dict())

        visual_edges = []
        for edge_id, edge in all_edges.items():
            visual_edge = self._create_visual_edge(edge)

            if edge_id in path_edge_ids:
                visual_edge.color = "#ff0000"
                visual_edge.width = 3.0
                visual_edge.style = "solid"
            elif dim_non_path:
                visual_edge.properties = {"opacity": 0.1}

            visual_edges.append(visual_edge.to_dict())

        return {
            "nodes": visual_nodes,
            "edges": visual_edges,
            "path_nodes": list(path_node_ids),
            "path_edges": list(path_edge_ids),
            "path_description": attack_path.description,
            "risk_score": attack_path.risk_score,
        }

    def generate_multiple_paths_view(
        self,
        attack_paths: List[AttackPath],
    ) -> Dict[str, Any]:
        """Generate visualization data with multiple attack paths.

        Args:
            attack_paths: List of attack paths to display.

        Returns:
            Dictionary with multiple paths visualization data.
        """
        path_colors = ["#ff0000", "#00ff00", "#0000ff", "#ff00ff", "#ffff00"]

        all_nodes = self.builder.get_all_nodes()
        all_edges = self.builder.get_all_edges()

        graph = self.builder.get_networkx_graph()

        try:
            pos = nx.spring_layout(graph, seed=42)
        except Exception:
            pos = {node: (0.0, 0.0) for node in graph.nodes()}  # type: ignore[misc]

        visual_nodes = []
        for node_id, node in all_nodes.items():
            coords = pos.get(node_id, (0.0, 0.0))
            x, y = float(coords[0]), float(coords[1])
            visual_node = self._create_visual_node(node, x, y)
            visual_nodes.append(visual_node.to_dict())

        visual_edges = []
        for edge_id, edge in all_edges.items():
            visual_edge = self._create_visual_edge(edge)
            visual_edges.append(visual_edge.to_dict())

        path_data = []
        for i, path in enumerate(attack_paths):
            color = path_colors[i % len(path_colors)]
            path_data.append({
                "path_id": path.path_id,
                "nodes": path.nodes,
                "edges": path.edges,
                "color": color,
                "description": path.description,
                "risk_score": path.risk_score,
            })

        return {
            "nodes": visual_nodes,
            "edges": visual_edges,
            "paths": path_data,
        }

    def _create_visual_node(
        self,
        node: GraphNode,
        x: float = 0.0,
        y: float = 0.0,
    ) -> VisualNode:
        """Create a VisualNode from a GraphNode.

        Args:
            node: GraphNode to convert.
            x: X coordinate.
            y: Y coordinate.

        Returns:
            VisualNode for frontend rendering.
        """
        color = NODE_COLORS.get(node.node_type, "#3498db")
        icon = NODE_ICONS.get(node.node_type, "circle")

        size = 20.0
        if isinstance(node, VulnerabilityNode):
            size = 15.0 + (node.cvss_score * 2)

        layer = node.properties.get("attack_phase", "")

        return VisualNode(
            id=node.node_id,
            label=node.label,
            node_type=node.node_type,
            color=color,
            icon=icon,
            size=size,
            x=x,
            y=y,
            properties=node.properties,
            layer=layer,
        )

    def _create_visual_edge(
        self,
        edge: GraphEdge,
    ) -> VisualEdge:
        """Create a VisualEdge from a GraphEdge.

        Args:
            edge: GraphEdge to convert.

        Returns:
            VisualEdge for frontend rendering.
        """
        color = EDGE_COLORS.get(edge.edge_type, "#95a5a6")
        style = EDGE_STYLES.get(edge.edge_type, "solid")

        width = 1.0
        if edge.edge_type == EdgeType.LATERAL_MOVEMENT:
            width = 2.0
        elif edge.edge_type == EdgeType.CREDENTIAL_ASSOCIATION:
            width = 1.5

        return VisualEdge(
            id=edge.edge_id,
            source=edge.source_id,
            target=edge.target_id,
            edge_type=edge.edge_type,
            color=color,
            style=style,
            width=width,
            label=edge.properties.get("method", ""),
        )
