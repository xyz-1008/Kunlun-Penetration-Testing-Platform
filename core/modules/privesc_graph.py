"""
Windows/Linux提权辅助套件 - 知识图谱双向联动接口
================================================
提权检查结果自动更新到昆仑知识图谱，结合域内信息展示完整攻击链。
支持知识共享与联邦学习。

核心能力:
    1. 提权路径可视化 - 低权限到高权限可攻击路径标记
    2. BloodHound风格域攻击链 - 当前节点到域控完整攻击链
    3. 知识共享与联邦 - 脱敏路径上传/下载社区知识图谱
    4. 双向联动 - 图谱更新决策树，决策结果反馈图谱

Author: 昆仑安全实验室
License: Internal Use Only
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


# =============================================================================
# 枚举与数据模型
# =============================================================================

class GraphNodeType(str, Enum):
    """图谱节点类型"""
    USER = "user"
    GROUP = "group"
    COMPUTER = "computer"
    DOMAIN = "domain"
    SERVICE = "service"
    PRIVILEGE = "privilege"
    VULNERABILITY = "vulnerability"
    EXPLOIT_VECTOR = "exploit_vector"


class GraphEdgeType(str, Enum):
    """图谱边类型"""
    MEMBER_OF = "member_of"
    CAN_PRIVESC = "can_privesc"
    HAS_PRIVILEGE = "has_privilege"
    CAN_EXPLOIT = "can_exploit"
    LEADS_TO = "leads_to"
    TRUSTS = "trusts"
    CONTROLS = "controls"
    ADMIN_TO = "admin_to"


class GraphSyncStatus(str, Enum):
    """图谱同步状态"""
    PENDING = "pending"
    SYNCING = "syncing"
    SYNCED = "synced"
    FAILED = "failed"


@dataclass
class GraphNode:
    """图谱节点

    Attributes:
        node_id: 节点唯一ID
        node_type: 节点类型
        name: 节点名称
        properties: 节点属性
        risk_score: 风险评分
        created_at: 创建时间
    """
    node_id: str = ""
    node_type: GraphNodeType = GraphNodeType.USER
    name: str = ""
    properties: Dict[str, Any] = field(default_factory=dict)
    risk_score: float = 0.0
    created_at: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典

        Returns:
            节点字典
        """
        return {
            "node_id": self.node_id,
            "node_type": self.node_type.value,
            "name": self.name,
            "properties": self.properties,
            "risk_score": round(self.risk_score, 2),
            "created_at": self.created_at,
        }


@dataclass
class GraphEdge:
    """图谱边

    Attributes:
        edge_id: 边唯一ID
        source_id: 源节点ID
        target_id: 目标节点ID
        edge_type: 边类型
        properties: 边属性
        weight: 权重
    """
    edge_id: str = ""
    source_id: str = ""
    target_id: str = ""
    edge_type: GraphEdgeType = GraphEdgeType.CAN_PRIVESC
    properties: Dict[str, Any] = field(default_factory=dict)
    weight: float = 1.0

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典

        Returns:
            边字典
        """
        return {
            "edge_id": self.edge_id,
            "source_id": self.source_id,
            "target_id": self.target_id,
            "edge_type": self.edge_type.value,
            "properties": self.properties,
            "weight": round(self.weight, 2),
        }


@dataclass
class AttackPath:
    """攻击路径

    Attributes:
        path_id: 路径唯一ID
        source_node: 起始节点
        target_node: 目标节点
        nodes: 路径节点列表
        edges: 路径边列表
        total_risk: 总风险
        success_probability: 成功概率
        description: 路径描述
    """
    path_id: str = ""
    source_node: str = ""
    target_node: str = ""
    nodes: List[str] = field(default_factory=list)
    edges: List[str] = field(default_factory=list)
    total_risk: float = 0.0
    success_probability: float = 0.0
    description: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典

        Returns:
            路径字典
        """
        return {
            "path_id": self.path_id,
            "source_node": self.source_node,
            "target_node": self.target_node,
            "nodes": self.nodes,
            "edges": self.edges,
            "total_risk": round(self.total_risk, 2),
            "success_probability": round(self.success_probability, 4),
            "description": self.description,
        }


@dataclass
class KnowledgeEntry:
    """知识条目

    Attributes:
        entry_id: 条目唯一ID
        source_session: 来源会话
        target_os: 目标操作系统
        exploit_vector: 利用向量
        success: 是否成功
        risk_level: 风险等级
        edr_detected: 是否检测到EDR
        timestamp: 时间戳
        anonymized: 是否已脱敏
    """
    entry_id: str = ""
    source_session: str = ""
    target_os: str = ""
    exploit_vector: str = ""
    success: bool = False
    risk_level: str = "medium"
    edr_detected: bool = False
    timestamp: str = ""
    anonymized: bool = True

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典

        Returns:
            条目字典
        """
        return {
            "entry_id": self.entry_id,
            "source_session": self.source_session,
            "target_os": self.target_os,
            "exploit_vector": self.exploit_vector,
            "success": self.success,
            "risk_level": self.risk_level,
            "edr_detected": self.edr_detected,
            "timestamp": self.timestamp,
            "anonymized": self.anonymized,
        }


# =============================================================================
# 本地知识图谱存储
# =============================================================================

class LocalGraphStore:
    """本地知识图谱存储

    使用内存+JSON持久化存储知识图谱。

    Attributes:
        _nodes: 节点字典 {node_id: GraphNode}
        _edges: 边字典 {edge_id: GraphEdge}
        _adjacency: 邻接表 {node_id: [neighbor_ids]}
        _storage_path: 存储路径
    """

    def __init__(self, storage_path: Optional[str] = None) -> None:
        """初始化本地图谱存储

        Args:
            storage_path: 存储路径
        """
        self._nodes: Dict[str, GraphNode] = {}
        self._edges: Dict[str, GraphEdge] = {}
        self._adjacency: Dict[str, List[str]] = {}
        self._storage_path = storage_path or os.path.join(
            os.path.expanduser("~"), ".kunlun", "privesc_graph.json",
        )
        self._load()

    def add_node(self, node: GraphNode) -> None:
        """添加节点

        Args:
            node: 图谱节点
        """
        self._nodes[node.node_id] = node
        if node.node_id not in self._adjacency:
            self._adjacency[node.node_id] = []

    def add_edge(self, edge: GraphEdge) -> None:
        """添加边

        Args:
            edge: 图谱边
        """
        self._edges[edge.edge_id] = edge

        if edge.source_id not in self._adjacency:
            self._adjacency[edge.source_id] = []
        self._adjacency[edge.source_id].append(edge.target_id)

    def get_node(self, node_id: str) -> Optional[GraphNode]:
        """获取节点

        Args:
            node_id: 节点ID

        Returns:
            节点或None
        """
        return self._nodes.get(node_id)

    def get_neighbors(self, node_id: str) -> List[str]:
        """获取邻居节点

        Args:
            node_id: 节点ID

        Returns:
            邻居节点ID列表
        """
        return self._adjacency.get(node_id, [])

    def find_path(
        self,
        source_id: str,
        target_id: str,
        max_depth: int = 10,
    ) -> Optional[List[str]]:
        """查找两个节点之间的路径（BFS）

        Args:
            source_id: 起始节点ID
            target_id: 目标节点ID
            max_depth: 最大深度

        Returns:
            路径节点ID列表或None
        """
        if source_id == target_id:
            return [source_id]

        visited: Set[str] = {source_id}
        queue: List[Tuple[str, List[str]]] = [(source_id, [source_id])]

        while queue:
            current, path = queue.pop(0)

            if len(path) > max_depth:
                continue

            for neighbor in self._adjacency.get(current, []):
                if neighbor == target_id:
                    return path + [neighbor]

                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append((neighbor, path + [neighbor]))

        return None

    def find_all_paths(
        self,
        source_id: str,
        target_id: str,
        max_depth: int = 10,
    ) -> List[List[str]]:
        """查找所有路径（DFS）

        Args:
            source_id: 起始节点ID
            target_id: 目标节点ID
            max_depth: 最大深度

        Returns:
            所有路径列表
        """
        paths: List[List[str]] = []
        self._dfs_paths(source_id, target_id, [source_id], set(), paths, max_depth)
        return paths

    def _dfs_paths(
        self,
        current: str,
        target: str,
        path: List[str],
        visited: Set[str],
        paths: List[List[str]],
        max_depth: int,
    ) -> None:
        """DFS查找所有路径

        Args:
            current: 当前节点
            target: 目标节点
            path: 当前路径
            visited: 已访问节点
            paths: 路径结果列表
            max_depth: 最大深度
        """
        if current == target:
            paths.append(list(path))
            return

        if len(path) >= max_depth:
            return

        visited.add(current)

        for neighbor in self._adjacency.get(current, []):
            if neighbor not in visited:
                path.append(neighbor)
                self._dfs_paths(neighbor, target, path, visited, paths, max_depth)
                path.pop()

        visited.discard(current)

    def get_all_nodes(self) -> List[GraphNode]:
        """获取所有节点

        Returns:
            节点列表
        """
        return list(self._nodes.values())

    def get_all_edges(self) -> List[GraphEdge]:
        """获取所有边

        Returns:
            边列表
        """
        return list(self._edges.values())

    def save(self) -> bool:
        """保存图谱到本地

        Returns:
            是否成功
        """
        try:
            data = {
                "nodes": {nid: n.to_dict() for nid, n in self._nodes.items()},
                "edges": {eid: e.to_dict() for eid, e in self._edges.items()},
                "adjacency": self._adjacency,
                "saved_at": datetime.now().isoformat(),
            }

            os.makedirs(os.path.dirname(self._storage_path) or ".", exist_ok=True)

            with open(self._storage_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)

            return True

        except Exception as e:
            logger.error(f"图谱保存失败: {e}")
            return False

    def _load(self) -> None:
        """从本地加载图谱"""
        try:
            if not os.path.exists(self._storage_path):
                return

            with open(self._storage_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            for nid, node_data in data.get("nodes", {}).items():
                node = GraphNode(
                    node_id=node_data["node_id"],
                    node_type=GraphNodeType(node_data["node_type"]),
                    name=node_data["name"],
                    properties=node_data.get("properties", {}),
                    risk_score=node_data.get("risk_score", 0.0),
                    created_at=node_data.get("created_at", ""),
                )
                self._nodes[nid] = node

            for eid, edge_data in data.get("edges", {}).items():
                edge = GraphEdge(
                    edge_id=edge_data["edge_id"],
                    source_id=edge_data["source_id"],
                    target_id=edge_data["target_id"],
                    edge_type=GraphEdgeType(edge_data["edge_type"]),
                    properties=edge_data.get("properties", {}),
                    weight=edge_data.get("weight", 1.0),
                )
                self._edges[eid] = edge

            self._adjacency = data.get("adjacency", {})

        except Exception as e:
            logger.error(f"图谱加载失败: {e}")


# =============================================================================
# 提权路径分析器
# =============================================================================

class PrivescPathAnalyzer:
    """提权路径分析器

    分析从当前权限到目标权限的完整攻击链。

    Attributes:
        _graph: 图谱存储
    """

    def __init__(self, graph: LocalGraphStore) -> None:
        """初始化提权路径分析器

        Args:
            graph: 图谱存储
        """
        self._graph = graph

    def analyze_privesc_paths(
        self,
        current_user: str,
        target_privilege: str = "SYSTEM",
    ) -> List[AttackPath]:
        """分析提权路径

        Args:
            current_user: 当前用户
            target_privilege: 目标权限

        Returns:
            攻击路径列表
        """
        source_node = self._find_user_node(current_user)
        target_node = self._find_privilege_node(target_privilege)

        if not source_node or not target_node:
            return []

        paths = self._graph.find_all_paths(
            source_node.node_id,
            target_node.node_id,
        )

        attack_paths = []
        for i, path in enumerate(paths):
            attack_path = self._build_attack_path(path, i)
            attack_paths.append(attack_path)

        attack_paths.sort(key=lambda p: p.success_probability, reverse=True)
        return attack_paths

    def build_domain_attack_chain(
        self,
        current_computer: str,
        domain_controller: str,
    ) -> Optional[AttackPath]:
        """构建域攻击链（BloodHound风格）

        Args:
            current_computer: 当前计算机
            domain_controller: 域控制器

        Returns:
            攻击路径或None
        """
        source = self._find_computer_node(current_computer)
        target = self._find_computer_node(domain_controller)

        if not source or not target:
            return None

        path = self._graph.find_path(source.node_id, target.node_id)

        if not path:
            return None

        return self._build_attack_path(path, 0, is_domain_chain=True)

    def update_graph_with_findings(
        self,
        findings: List[Dict[str, Any]],
        session_id: str,
    ) -> int:
        """用风险发现更新图谱

        Args:
            findings: 风险发现列表
            session_id: 会话ID

        Returns:
            更新的节点数
        """
        updated = 0

        for finding in findings:
            vector_type = finding.get("category", "")
            risk_score = finding.get("risk_score", 0)

            if risk_score < 30:
                continue

            vector_node = self._create_exploit_vector_node(
                vector_type, finding, session_id,
            )
            self._graph.add_node(vector_node)

            user_node = self._find_user_node(
                finding.get("user", "unknown"),
            )
            if user_node:
                edge = GraphEdge(
                    edge_id=f"edge_{user_node.node_id}_{vector_node.node_id}",
                    source_id=user_node.node_id,
                    target_id=vector_node.node_id,
                    edge_type=GraphEdgeType.CAN_EXPLOIT,
                    properties={
                        "finding_id": finding.get("finding_id", ""),
                        "risk_score": risk_score,
                    },
                    weight=risk_score / 100.0,
                )
                self._graph.add_edge(edge)

                priv_node = self._find_privilege_node(
                    finding.get("target_privilege", "SYSTEM"),
                )
                if priv_node:
                    priv_edge = GraphEdge(
                        edge_id=f"edge_{vector_node.node_id}_{priv_node.node_id}",
                        source_id=vector_node.node_id,
                        target_id=priv_node.node_id,
                        edge_type=GraphEdgeType.LEADS_TO,
                        properties={
                            "exploit_method": finding.get("exploit_method", ""),
                        },
                        weight=risk_score / 100.0,
                    )
                    self._graph.add_edge(priv_edge)

            updated += 1

        self._graph.save()
        return updated

    def _find_user_node(self, username: str) -> Optional[GraphNode]:
        """查找用户节点

        Args:
            username: 用户名

        Returns:
            用户节点或None
        """
        for node in self._graph.get_all_nodes():
            if node.node_type == GraphNodeType.USER and node.name == username:
                return node
        return None

    def _find_privilege_node(self, privilege: str) -> Optional[GraphNode]:
        """查找权限节点

        Args:
            privilege: 权限名

        Returns:
            权限节点或None
        """
        for node in self._graph.get_all_nodes():
            if node.node_type == GraphNodeType.PRIVILEGE and node.name == privilege:
                return node
        return None

    def _find_computer_node(self, computer: str) -> Optional[GraphNode]:
        """查找计算机节点

        Args:
            computer: 计算机名

        Returns:
            计算机节点或None
        """
        for node in self._graph.get_all_nodes():
            if node.node_type == GraphNodeType.COMPUTER and node.name == computer:
                return node
        return None

    def _create_exploit_vector_node(
        self,
        vector_type: str,
        finding: Dict[str, Any],
        session_id: str,
    ) -> GraphNode:
        """创建利用向量节点

        Args:
            vector_type: 向量类型
            finding: 风险发现
            session_id: 会话ID

        Returns:
            利用向量节点
        """
        hash_input = f"{vector_type}_{session_id}".encode()
        node_id = f"vector_{hashlib.md5(hash_input).hexdigest()[:8]}"

        return GraphNode(
            node_id=node_id,
            node_type=GraphNodeType.EXPLOIT_VECTOR,
            name=vector_type,
            properties={
                "finding_id": finding.get("finding_id", ""),
                "risk_score": finding.get("risk_score", 0),
                "session_id": session_id,
            },
            risk_score=finding.get("risk_score", 0),
            created_at=datetime.now().isoformat(),
        )

    def _build_attack_path(
        self,
        path: List[str],
        index: int,
        is_domain_chain: bool = False,
    ) -> AttackPath:
        """构建攻击路径对象

        Args:
            path: 路径节点ID列表
            index: 路径索引
            is_domain_chain: 是否为域攻击链

        Returns:
            攻击路径
        """
        nodes = []
        edges = []
        total_risk = 0.0

        for node_id in path:
            node = self._graph.get_node(node_id)
            if node:
                nodes.append(node.name)
                total_risk += node.risk_score

        path_id = f"path_{index}_{int(time.time())}"

        return AttackPath(
            path_id=path_id,
            source_node=path[0] if path else "",
            target_node=path[-1] if path else "",
            nodes=nodes,
            edges=edges,
            total_risk=total_risk,
            success_probability=1.0 / (1.0 + total_risk / 100),
            description=(
                f"域攻击链: {' -> '.join(nodes)}"
                if is_domain_chain
                else f"提权路径: {' -> '.join(nodes)}"
            ),
        )


# =============================================================================
# 知识联邦同步器
# =============================================================================

class KnowledgeFederator:
    """知识联邦同步器

    支持脱敏知识上传/下载社区知识图谱。

    Attributes:
        _local_store: 本地图谱存储
        _community_url: 社区知识图谱URL
        _sync_status: 同步状态
        _sync_callbacks: 同步回调列表
    """

    def __init__(
        self,
        local_store: LocalGraphStore,
        community_url: str = "https://community.kunlun.internal/api/v1/knowledge",
    ) -> None:
        """初始化知识联邦同步器

        Args:
            local_store: 本地图谱存储
            community_url: 社区知识图谱URL
        """
        self._local_store = local_store
        self._community_url = community_url
        self._sync_status = GraphSyncStatus.PENDING
        self._sync_callbacks: List[Callable[[GraphSyncStatus, str], None]] = []

    def on_sync(self, callback: Callable[[GraphSyncStatus, str], None]) -> None:
        """注册同步回调

        Args:
            callback: 回调函数
        """
        self._sync_callbacks.append(callback)

    def _notify_sync(self, status: GraphSyncStatus, message: str) -> None:
        """通知同步状态

        Args:
            status: 同步状态
            message: 状态描述
        """
        self._sync_status = status
        for cb in self._sync_callbacks:
            try:
                cb(status, message)
            except Exception:
                pass

    async def upload_knowledge(
        self,
        entries: List[KnowledgeEntry],
    ) -> Dict[str, Any]:
        """上传脱敏知识到社区

        Args:
            entries: 知识条目列表

        Returns:
            上传结果
        """
        self._notify_sync(GraphSyncStatus.SYNCING, "开始上传知识...")

        try:
            anonymized_entries = [
                self._anonymize_entry(e) for e in entries
            ]

            payload = {
                "entries": [e.to_dict() for e in anonymized_entries],
                "timestamp": datetime.now().isoformat(),
                "source": "kunlun_privesc_suite",
            }

            upload_success = await self._send_to_community(payload)

            if upload_success:
                self._notify_sync(GraphSyncStatus.SYNCED, "知识上传成功")
                return {"success": True, "uploaded": len(entries)}
            else:
                self._notify_sync(GraphSyncStatus.FAILED, "知识上传失败")
                return {"success": False, "error": "上传失败"}

        except Exception as e:
            self._notify_sync(GraphSyncStatus.FAILED, f"上传异常: {e}")
            return {"success": False, "error": str(e)}

    async def download_knowledge(self) -> Dict[str, Any]:
        """从社区下载知识

        Returns:
            下载结果
        """
        self._notify_sync(GraphSyncStatus.SYNCING, "开始下载知识...")

        try:
            community_data = await self._fetch_from_community()

            if not community_data:
                self._notify_sync(GraphSyncStatus.FAILED, "无可用知识")
                return {"success": False, "error": "无可用知识"}

            entries = community_data.get("entries", [])
            self._merge_community_knowledge(entries)

            self._notify_sync(
                GraphSyncStatus.SYNCED,
                f"已下载并合并 {len(entries)} 条知识",
            )

            return {"success": True, "downloaded": len(entries)}

        except Exception as e:
            self._notify_sync(GraphSyncStatus.FAILED, f"下载异常: {e}")
            return {"success": False, "error": str(e)}

    def _anonymize_entry(self, entry: KnowledgeEntry) -> KnowledgeEntry:
        """脱敏知识条目

        Args:
            entry: 原始条目

        Returns:
            脱敏后的条目
        """
        anonymized = KnowledgeEntry(
            entry_id=hashlib.md5(
                f"{entry.exploit_vector}_{entry.target_os}".encode()
            ).hexdigest()[:12],
            source_session="anonymous",
            target_os=entry.target_os,
            exploit_vector=entry.exploit_vector,
            success=entry.success,
            risk_level=entry.risk_level,
            edr_detected=entry.edr_detected,
            timestamp=entry.timestamp,
            anonymized=True,
        )
        return anonymized

    async def _send_to_community(self, payload: Dict[str, Any]) -> bool:
        """发送到社区

        Args:
            payload: 数据负载

        Returns:
            是否成功
        """
        try:
            import urllib.request

            data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(
                self._community_url,
                data=data,
                headers={"Content-Type": "application/json"},
                method="POST",
            )

            with urllib.request.urlopen(req, timeout=30) as response:
                return response.status == 200

        except Exception as e:
            logger.error(f"社区上传失败: {e}")
            return False

    async def _fetch_from_community(self) -> Optional[Dict[str, Any]]:
        """从社区获取数据

        Returns:
            社区数据或None
        """
        try:
            import urllib.request

            req = urllib.request.Request(self._community_url)

            with urllib.request.urlopen(req, timeout=30) as response:
                return json.loads(response.read().decode("utf-8"))

        except Exception as e:
            logger.error(f"社区下载失败: {e}")
            return None

    def _merge_community_knowledge(self, entries: List[Dict[str, Any]]) -> None:
        """合并社区知识

        Args:
            entries: 社区知识条目
        """
        for entry_data in entries:
            exploit_vector = entry_data.get("exploit_vector", "")
            success = entry_data.get("success", False)

            if not exploit_vector:
                continue

            community_hash = hashlib.md5(exploit_vector.encode()).hexdigest()[:8]
            vector_node = GraphNode(
                node_id=f"community_{community_hash}",
                node_type=GraphNodeType.EXPLOIT_VECTOR,
                name=exploit_vector,
                properties={
                    "source": "community",
                    "success_rate": 1.0 if success else 0.0,
                    "community_validated": True,
                },
                risk_score=70.0 if success else 30.0,
                created_at=datetime.now().isoformat(),
            )
            self._local_store.add_node(vector_node)

        self._local_store.save()


# =============================================================================
# 主知识图谱联动接口
# =============================================================================

class PrivescGraphInterface:
    """提权知识图谱联动接口

    整合图谱存储、路径分析、知识联邦。

    Attributes:
        _graph: 本地图谱存储
        _analyzer: 提权路径分析器
        _federator: 知识联邦同步器
    """

    def __init__(
        self,
        storage_path: Optional[str] = None,
        community_url: str = "",
    ) -> None:
        """初始化知识图谱联动接口

        Args:
            storage_path: 图谱存储路径
            community_url: 社区知识图谱URL
        """
        self._graph = LocalGraphStore(storage_path)
        self._analyzer = PrivescPathAnalyzer(self._graph)
        self._federator = KnowledgeFederator(
            self._graph, community_url,
        )

    @property
    def graph(self) -> LocalGraphStore:
        """获取图谱存储

        Returns:
            本地图谱存储
        """
        return self._graph

    @property
    def analyzer(self) -> PrivescPathAnalyzer:
        """获取路径分析器

        Returns:
            提权路径分析器
        """
        return self._analyzer

    @property
    def federator(self) -> KnowledgeFederator:
        """获取联邦同步器

        Returns:
            知识联邦同步器
        """
        return self._federator

    async def analyze_and_update(
        self,
        findings: List[Dict[str, Any]],
        session_id: str,
        current_user: str,
        target_privilege: str = "SYSTEM",
    ) -> Dict[str, Any]:
        """分析并更新图谱

        Args:
            findings: 风险发现列表
            session_id: 会话ID
            current_user: 当前用户
            target_privilege: 目标权限

        Returns:
            分析结果
        """
        updated_nodes = self._analyzer.update_graph_with_findings(
            findings, session_id,
        )

        attack_paths = self._analyzer.analyze_privesc_paths(
            current_user, target_privilege,
        )

        self._graph.save()

        return {
            "updated_nodes": updated_nodes,
            "attack_paths": [p.to_dict() for p in attack_paths],
            "total_nodes": len(self._graph.get_all_nodes()),
            "total_edges": len(self._graph.get_all_edges()),
        }

    async def upload_to_community(
        self,
        entries: List[KnowledgeEntry],
    ) -> Dict[str, Any]:
        """上传知识到社区

        Args:
            entries: 知识条目列表

        Returns:
            上传结果
        """
        return await self._federator.upload_knowledge(entries)

    async def download_from_community(self) -> Dict[str, Any]:
        """从社区下载知识

        Returns:
            下载结果
        """
        return await self._federator.download_knowledge()

    def get_graph_statistics(self) -> Dict[str, Any]:
        """获取图谱统计

        Returns:
            统计信息
        """
        nodes = self._graph.get_all_nodes()
        edges = self._graph.get_all_edges()

        node_types: Dict[str, int] = {}
        for node in nodes:
            node_types[node.node_type.value] = (
                node_types.get(node.node_type.value, 0) + 1
            )

        return {
            "total_nodes": len(nodes),
            "total_edges": len(edges),
            "node_types": node_types,
            "storage_path": self._graph._storage_path,
        }


# =============================================================================
# 全局单例
# =============================================================================

_graph_interface: Optional[PrivescGraphInterface] = None


def get_graph_interface(
    storage_path: Optional[str] = None,
    community_url: str = "",
) -> PrivescGraphInterface:
    """获取知识图谱联动接口全局单例

    Args:
        storage_path: 图谱存储路径
        community_url: 社区知识图谱URL

    Returns:
        PrivescGraphInterface 实例
    """
    global _graph_interface
    if _graph_interface is None:
        _graph_interface = PrivescGraphInterface(storage_path, community_url)
    return _graph_interface


__all__ = [
    "PrivescGraphInterface",
    "LocalGraphStore",
    "PrivescPathAnalyzer",
    "KnowledgeFederator",
    "GraphNode",
    "GraphEdge",
    "AttackPath",
    "KnowledgeEntry",
    "GraphNodeType",
    "GraphEdgeType",
    "GraphSyncStatus",
    "get_graph_interface",
]
