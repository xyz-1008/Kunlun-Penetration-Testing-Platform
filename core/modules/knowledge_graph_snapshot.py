"""Knowledge Graph Snapshot: Snapshot saving, difference comparison engine.

Provides:
- Automatic snapshot creation after scan tasks
- Manual snapshot creation
- Snapshot storage and retrieval
- Difference comparison between two snapshots
- New/removed/changed nodes and edges detection
- Difference report generation
"""

import json
import logging
import os
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple

from pydantic import BaseModel, Field

from .knowledge_graph_builder import KnowledgeGraphBuilder
from .knowledge_graph_model import EdgeType, GraphEdge, GraphNode, NodeType

logger = logging.getLogger(__name__)


class SnapshotNode(BaseModel):
    """Node data in a snapshot.

    Attributes:
        node_id: Node identifier
        node_type: Node type
        label: Display label
        properties: Node properties
    """
    node_id: str = Field(..., description="Node identifier")
    node_type: str = Field(..., description="Node type")
    label: str = Field(..., description="Display label")
    properties: Dict[str, Any] = Field(default_factory=dict, description="Properties")


class SnapshotEdge(BaseModel):
    """Edge data in a snapshot.

    Attributes:
        edge_id: Edge identifier
        source_id: Source node ID
        target_id: Target node ID
        edge_type: Edge type
        weight: Edge weight
        properties: Edge properties
    """
    edge_id: str = Field(..., description="Edge identifier")
    source_id: str = Field(..., description="Source node ID")
    target_id: str = Field(..., description="Target node ID")
    edge_type: str = Field(..., description="Edge type")
    weight: float = Field(default=1.0, description="Edge weight")
    properties: Dict[str, Any] = Field(default_factory=dict, description="Properties")


class GraphSnapshot(BaseModel):
    """Complete graph snapshot.

    Attributes:
        snapshot_id: Unique snapshot identifier
        name: Snapshot name
        description: Snapshot description
        timestamp: Snapshot creation timestamp
        node_count: Number of nodes
        edge_count: Number of edges
        nodes: List of snapshot nodes
        edges: List of snapshot edges
        metadata: Additional metadata
    """
    snapshot_id: str = Field(..., description="Snapshot identifier")
    name: str = Field(..., description="Snapshot name")
    description: str = Field(default="", description="Description")
    timestamp: str = Field(..., description="Creation timestamp")
    node_count: int = Field(default=0, description="Node count")
    edge_count: int = Field(default=0, description="Edge count")
    nodes: List[SnapshotNode] = Field(default_factory=list, description="Nodes")
    edges: List[SnapshotEdge] = Field(default_factory=list, description="Edges")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Metadata")


class NodeDiff(BaseModel):
    """Difference for a single node.

    Attributes:
        node_id: Node identifier
        diff_type: Type of difference (added/removed/changed)
        old_data: Old node data (for changed/removed)
        new_data: New node data (for added/changed)
        changed_properties: List of changed property keys
    """
    node_id: str = Field(..., description="Node identifier")
    diff_type: str = Field(..., description="Diff type")
    old_data: Optional[SnapshotNode] = Field(default=None, description="Old data")
    new_data: Optional[SnapshotNode] = Field(default=None, description="New data")
    changed_properties: List[str] = Field(default_factory=list, description="Changed properties")


class EdgeDiff(BaseModel):
    """Difference for a single edge.

    Attributes:
        edge_id: Edge identifier
        diff_type: Type of difference (added/removed/changed)
        old_data: Old edge data
        new_data: New edge data
    """
    edge_id: str = Field(..., description="Edge identifier")
    diff_type: str = Field(..., description="Diff type")
    old_data: Optional[SnapshotEdge] = Field(default=None, description="Old data")
    new_data: Optional[SnapshotEdge] = Field(default=None, description="New data")


class SnapshotDiff(BaseModel):
    """Complete difference between two snapshots.

    Attributes:
        snapshot_a_id: First snapshot ID
        snapshot_b_id: Second snapshot ID
        timestamp_a: First snapshot timestamp
        timestamp_b: Second snapshot timestamp
        added_nodes: Nodes added in B
        removed_nodes: Nodes removed in B
        changed_nodes: Nodes with changed properties
        added_edges: Edges added in B
        removed_edges: Edges removed in B
        changed_edges: Edges with changed properties
        summary: Human-readable summary
    """
    snapshot_a_id: str = Field(..., description="First snapshot ID")
    snapshot_b_id: str = Field(..., description="Second snapshot ID")
    timestamp_a: str = Field(..., description="First timestamp")
    timestamp_b: str = Field(..., description="Second timestamp")
    added_nodes: List[NodeDiff] = Field(default_factory=list, description="Added nodes")
    removed_nodes: List[NodeDiff] = Field(default_factory=list, description="Removed nodes")
    changed_nodes: List[NodeDiff] = Field(default_factory=list, description="Changed nodes")
    added_edges: List[EdgeDiff] = Field(default_factory=list, description="Added edges")
    removed_edges: List[EdgeDiff] = Field(default_factory=list, description="Removed edges")
    changed_edges: List[EdgeDiff] = Field(default_factory=list, description="Changed edges")
    summary: str = Field(default="", description="Summary")


class KnowledgeGraphSnapshotManager:
    """Manages graph snapshots and difference comparison.

    Provides snapshot creation, storage, retrieval, and comparison
    functionality for tracking graph evolution over time.
    """

    def __init__(self, snapshot_dir: Optional[str] = None) -> None:
        """Initialize snapshot manager.

        Args:
            snapshot_dir: Directory for storing snapshots.
        """
        self.snapshot_dir = snapshot_dir or "./snapshots"
        os.makedirs(self.snapshot_dir, exist_ok=True)

        self._snapshots: Dict[str, GraphSnapshot] = {}
        self._load_existing_snapshots()

    def create_snapshot(
        self,
        builder: KnowledgeGraphBuilder,
        name: str = "",
        description: str = "",
        auto_save: bool = True,
    ) -> GraphSnapshot:
        """Create a snapshot from the current graph state.

        Args:
            builder: Knowledge graph builder instance.
            name: Snapshot name.
            description: Snapshot description.
            auto_save: Whether to automatically save to disk.

        Returns:
            GraphSnapshot object.
        """
        timestamp = datetime.now().isoformat()
        snapshot_id = f"snapshot_{int(datetime.now().timestamp())}"

        if not name:
            name = f"Snapshot {timestamp[:19]}"

        nodes = []
        for node_id, node in builder.get_all_nodes().items():
            snapshot_node = SnapshotNode(
                node_id=node.node_id,
                node_type=node.node_type.value,
                label=node.label,
                properties=node.properties,
            )
            nodes.append(snapshot_node)

        edges = []
        for edge_id, edge in builder.get_all_edges().items():
            snapshot_edge = SnapshotEdge(
                edge_id=edge.edge_id,
                source_id=edge.source_id,
                target_id=edge.target_id,
                edge_type=edge.edge_type.value,
                weight=edge.weight,
                properties=edge.properties,
            )
            edges.append(snapshot_edge)

        snapshot = GraphSnapshot(
            snapshot_id=snapshot_id,
            name=name,
            description=description,
            timestamp=timestamp,
            node_count=len(nodes),
            edge_count=len(edges),
            nodes=nodes,
            edges=edges,
            metadata=builder.get_metadata().model_dump(),
        )

        self._snapshots[snapshot_id] = snapshot

        if auto_save:
            self._save_snapshot_to_disk(snapshot)

        return snapshot

    def get_snapshot(self, snapshot_id: str) -> Optional[GraphSnapshot]:
        """Get a snapshot by ID.

        Args:
            snapshot_id: Snapshot identifier.

        Returns:
            GraphSnapshot or None.
        """
        return self._snapshots.get(snapshot_id)

    def list_snapshots(self) -> List[GraphSnapshot]:
        """List all available snapshots.

        Returns:
            List of GraphSnapshot objects sorted by timestamp.
        """
        snapshots = list(self._snapshots.values())
        snapshots.sort(key=lambda s: s.timestamp, reverse=True)
        return snapshots

    def delete_snapshot(self, snapshot_id: str) -> bool:
        """Delete a snapshot.

        Args:
            snapshot_id: Snapshot identifier.

        Returns:
            True if snapshot was deleted.
        """
        if snapshot_id in self._snapshots:
            del self._snapshots[snapshot_id]

            file_path = os.path.join(self.snapshot_dir, f"{snapshot_id}.json")
            if os.path.exists(file_path):
                os.remove(file_path)

            return True

        return False

    def compare_snapshots(
        self,
        snapshot_a_id: str,
        snapshot_b_id: str,
    ) -> Optional[SnapshotDiff]:
        """Compare two snapshots and generate difference report.

        Args:
            snapshot_a_id: First snapshot ID.
            snapshot_b_id: Second snapshot ID.

        Returns:
            SnapshotDiff or None.
        """
        snapshot_a = self._snapshots.get(snapshot_a_id)
        snapshot_b = self._snapshots.get(snapshot_b_id)

        if snapshot_a is None or snapshot_b is None:
            return None

        nodes_a = {n.node_id: n for n in snapshot_a.nodes}
        nodes_b = {n.node_id: n for n in snapshot_b.nodes}

        edges_a = {e.edge_id: e for e in snapshot_a.edges}
        edges_b = {e.edge_id: e for e in snapshot_b.edges}

        added_nodes = []
        removed_nodes = []
        changed_nodes = []

        for node_id in set(nodes_b.keys()) - set(nodes_a.keys()):
            added_nodes.append(NodeDiff(
                node_id=node_id,
                diff_type="added",
                new_data=nodes_b[node_id],
            ))

        for node_id in set(nodes_a.keys()) - set(nodes_b.keys()):
            removed_nodes.append(NodeDiff(
                node_id=node_id,
                diff_type="removed",
                old_data=nodes_a[node_id],
            ))

        for node_id in set(nodes_a.keys()) & set(nodes_b.keys()):
            node_a = nodes_a[node_id]
            node_b = nodes_b[node_id]

            changed_props = self._find_changed_properties(node_a, node_b)
            if changed_props:
                changed_nodes.append(NodeDiff(
                    node_id=node_id,
                    diff_type="changed",
                    old_data=node_a,
                    new_data=node_b,
                    changed_properties=changed_props,
                ))

        added_edges = []
        removed_edges = []
        changed_edges = []

        for edge_id in set(edges_b.keys()) - set(edges_a.keys()):
            added_edges.append(EdgeDiff(
                edge_id=edge_id,
                diff_type="added",
                new_data=edges_b[edge_id],
            ))

        for edge_id in set(edges_a.keys()) - set(edges_b.keys()):
            removed_edges.append(EdgeDiff(
                edge_id=edge_id,
                diff_type="removed",
                old_data=edges_a[edge_id],
            ))

        for edge_id in set(edges_a.keys()) & set(edges_b.keys()):
            edge_a = edges_a[edge_id]
            edge_b = edges_b[edge_id]

            if edge_a.weight != edge_b.weight or edge_a.properties != edge_b.properties:
                changed_edges.append(EdgeDiff(
                    edge_id=edge_id,
                    diff_type="changed",
                    old_data=edge_a,
                    new_data=edge_b,
                ))

        summary = self._generate_diff_summary(
            added_nodes, removed_nodes, changed_nodes,
            added_edges, removed_edges, changed_edges,
        )

        return SnapshotDiff(
            snapshot_a_id=snapshot_a_id,
            snapshot_b_id=snapshot_b_id,
            timestamp_a=snapshot_a.timestamp,
            timestamp_b=snapshot_b.timestamp,
            added_nodes=added_nodes,
            removed_nodes=removed_nodes,
            changed_nodes=changed_nodes,
            added_edges=added_edges,
            removed_edges=removed_edges,
            changed_edges=changed_edges,
            summary=summary,
        )

    def generate_diff_report(
        self,
        diff: SnapshotDiff,
        format: str = "text",
    ) -> str:
        """Generate a human-readable difference report.

        Args:
            diff: SnapshotDiff object.
            format: Report format (text/markdown).

        Returns:
            Formatted report string.
        """
        if format == "markdown":
            return self._generate_markdown_report(diff)
        else:
            return self._generate_text_report(diff)

    def export_snapshot(
        self,
        snapshot_id: str,
        format: str = "json",
    ) -> Optional[str]:
        """Export a snapshot in various formats.

        Args:
            snapshot_id: Snapshot identifier.
            format: Export format (json/graphml/gexf).

        Returns:
            Exported data string or None.
        """
        snapshot = self._snapshots.get(snapshot_id)
        if snapshot is None:
            return None

        if format == "json":
            return snapshot.model_dump_json(indent=2)
        elif format == "graphml":
            return self._export_to_graphml(snapshot)
        elif format == "gexf":
            return self._export_to_gexf(snapshot)

        return None

    def _find_changed_properties(
        self,
        node_a: SnapshotNode,
        node_b: SnapshotNode,
    ) -> List[str]:
        """Find properties that changed between two nodes.

        Args:
            node_a: First node.
            node_b: Second node.

        Returns:
            List of changed property keys.
        """
        changed = []

        all_keys = set(node_a.properties.keys()) | set(node_b.properties.keys())

        for key in all_keys:
            if node_a.properties.get(key) != node_b.properties.get(key):
                changed.append(key)

        return changed

    def _generate_diff_summary(
        self,
        added_nodes: List[NodeDiff],
        removed_nodes: List[NodeDiff],
        changed_nodes: List[NodeDiff],
        added_edges: List[EdgeDiff],
        removed_edges: List[EdgeDiff],
        changed_edges: List[EdgeDiff],
    ) -> str:
        """Generate a human-readable difference summary.

        Args:
            added_nodes: Added nodes.
            removed_nodes: Removed nodes.
            changed_nodes: Changed nodes.
            added_edges: Added edges.
            removed_edges: Removed edges.
            changed_edges: Changed edges.

        Returns:
            Summary string.
        """
        parts = []

        if added_nodes:
            parts.append(f"新增节点: {len(added_nodes)}个")

        if removed_nodes:
            parts.append(f"删除节点: {len(removed_nodes)}个")

        if changed_nodes:
            parts.append(f"变更节点: {len(changed_nodes)}个")

        if added_edges:
            parts.append(f"新增关系: {len(added_edges)}个")

        if removed_edges:
            parts.append(f"删除关系: {len(removed_edges)}个")

        if changed_edges:
            parts.append(f"变更关系: {len(changed_edges)}个")

        if not parts:
            return "无变化"

        return "，".join(parts)

    def _generate_text_report(self, diff: SnapshotDiff) -> str:
        """Generate text format difference report.

        Args:
            diff: SnapshotDiff object.

        Returns:
            Text report string.
        """
        lines = [
            f"快照对比报告",
            f"=" * 50,
            f"快照A: {diff.snapshot_a_id} ({diff.timestamp_a})",
            f"快照B: {diff.snapshot_b_id} ({diff.timestamp_b})",
            f"",
            f"摘要: {diff.summary}",
            f"",
        ]

        if diff.added_nodes:
            lines.append("新增节点:")
            for node in diff.added_nodes:
                lines.append(f"  + {node.node_id} ({node.new_data.node_type if node.new_data else 'unknown'})")
            lines.append("")

        if diff.removed_nodes:
            lines.append("删除节点:")
            for node in diff.removed_nodes:
                lines.append(f"  - {node.node_id} ({node.old_data.node_type if node.old_data else 'unknown'})")
            lines.append("")

        if diff.added_edges:
            lines.append("新增关系:")
            for edge in diff.added_edges:
                if edge.new_data:
                    lines.append(f"  + {edge.edge_id}: {edge.new_data.source_id} -> {edge.new_data.target_id}")
            lines.append("")

        if diff.removed_edges:
            lines.append("删除关系:")
            for edge in diff.removed_edges:
                if edge.old_data:
                    lines.append(f"  - {edge.edge_id}: {edge.old_data.source_id} -> {edge.old_data.target_id}")
            lines.append("")

        return "\n".join(lines)

    def _generate_markdown_report(self, diff: SnapshotDiff) -> str:
        """Generate markdown format difference report.

        Args:
            diff: SnapshotDiff object.

        Returns:
            Markdown report string.
        """
        lines = [
            "# 快照对比报告",
            f"",
            f"- **快照A**: {diff.snapshot_a_id} ({diff.timestamp_a})",
            f"- **快照B**: {diff.snapshot_b_id} ({diff.timestamp_b})",
            f"- **摘要**: {diff.summary}",
            f"",
        ]

        if diff.added_nodes:
            lines.append("## 新增节点 (绿色)")
            for node in diff.added_nodes:
                node_type = node.new_data.node_type if node.new_data else "unknown"
                lines.append(f"- 🟢 `{node.node_id}` ({node_type})")
            lines.append("")

        if diff.removed_nodes:
            lines.append("## 删除节点 (红色)")
            for node in diff.removed_nodes:
                node_type = node.old_data.node_type if node.old_data else "unknown"
                lines.append(f"- 🔴 `{node.node_id}` ({node_type})")
            lines.append("")

        if diff.changed_nodes:
            lines.append("## 变更节点 (黄色)")
            for node in diff.changed_nodes:
                lines.append(f"- 🟡 `{node.node_id}`: {', '.join(node.changed_properties)}")
            lines.append("")

        if diff.added_edges:
            lines.append("## 新增关系")
            for edge in diff.added_edges:
                if edge.new_data:
                    lines.append(f"- 🟢 `{edge.new_data.source_id}` → `{edge.new_data.target_id}`")
            lines.append("")

        if diff.removed_edges:
            lines.append("## 删除关系")
            for edge in diff.removed_edges:
                if edge.old_data:
                    lines.append(f"- 🔴 `{edge.old_data.source_id}` → `{edge.old_data.target_id}`")
            lines.append("")

        return "\n".join(lines)

    def _export_to_graphml(self, snapshot: GraphSnapshot) -> str:
        """Export snapshot to GraphML format.

        Args:
            snapshot: GraphSnapshot to export.

        Returns:
            GraphML XML string.
        """
        lines = [
            '<?xml version="1.0" encoding="UTF-8"?>',
            '<graphml xmlns="http://graphml.graphdrawing.org/xmlns">',
            '  <key id="label" for="node" attr.name="label" attr.type="string"/>',
            '  <key id="node_type" for="node" attr.name="node_type" attr.type="string"/>',
            '  <key id="edge_type" for="edge" attr.name="edge_type" attr.type="string"/>',
            '  <graph id="knowledge_graph" edgedefault="directed">',
        ]

        for node in snapshot.nodes:
            lines.append(f'    <node id="{node.node_id}">')
            lines.append(f'      <data key="label">{node.label}</data>')
            lines.append(f'      <data key="node_type">{node.node_type}</data>')
            lines.append(f'    </node>')

        for edge in snapshot.edges:
            lines.append(
                f'    <edge id="{edge.edge_id}" source="{edge.source_id}" target="{edge.target_id}">'
            )
            lines.append(f'      <data key="edge_type">{edge.edge_type}</data>')
            lines.append(f'    </edge>')

        lines.append('  </graph>')
        lines.append('</graphml>')

        return "\n".join(lines)

    def _export_to_gexf(self, snapshot: GraphSnapshot) -> str:
        """Export snapshot to GEXF format.

        Args:
            snapshot: GraphSnapshot to export.

        Returns:
            GEXF XML string.
        """
        lines = [
            '<?xml version="1.0" encoding="UTF-8"?>',
            '<gexf xmlns="http://www.gexf.net/1.3" version="1.3">',
            '  <graph defaultedgetype="directed">',
            '    <nodes>',
        ]

        for node in snapshot.nodes:
            lines.append(f'      <node id="{node.node_id}" label="{node.label}">')
            lines.append(f'        <attvalues>')
            lines.append(f'          <attvalue for="node_type" value="{node.node_type}"/>')
            lines.append(f'        </attvalues>')
            lines.append(f'      </node>')

        lines.append('    </nodes>')
        lines.append('    <edges>')

        for edge in snapshot.edges:
            lines.append(
                f'      <edge id="{edge.edge_id}" source="{edge.source_id}" target="{edge.target_id}">'
            )
            lines.append(f'        <attvalue for="edge_type" value="{edge.edge_type}"/>')
            lines.append(f'      </edge>')

        lines.append('    </edges>')
        lines.append('  </graph>')
        lines.append('</gexf>')

        return "\n".join(lines)

    def _save_snapshot_to_disk(self, snapshot: GraphSnapshot) -> None:
        """Save snapshot to disk as JSON file.

        Args:
            snapshot: GraphSnapshot to save.
        """
        file_path = os.path.join(self.snapshot_dir, f"{snapshot.snapshot_id}.json")

        try:
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(snapshot.model_dump_json(indent=2))

        except Exception as e:
            logger.error(f"Failed to save snapshot: {e}")

    def _load_existing_snapshots(self) -> None:
        """Load existing snapshots from disk."""
        if not os.path.exists(self.snapshot_dir):
            return

        for file_name in os.listdir(self.snapshot_dir):
            if file_name.endswith(".json"):
                file_path = os.path.join(self.snapshot_dir, file_name)

                try:
                    with open(file_path, "r", encoding="utf-8") as f:
                        data = json.load(f)

                    snapshot = GraphSnapshot(**data)
                    self._snapshots[snapshot.snapshot_id] = snapshot

                except Exception as e:
                    logger.warning(f"Failed to load snapshot {file_name}: {e}")
