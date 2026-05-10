"""
Windows提权辅助套件 - 决策树构建与优先级排序
=============================================
根据系统信息自动生成可视化利用决策树（Mermaid格式），构建优先级矩阵，
支持多策略排序（fast/stealth/stable）。

核心能力:
    1. 决策树构建 - Mermaid格式可视化，节点为检查项，边为利用依赖关系
    2. 优先级矩阵 - 成功率/隐蔽性/对系统影响三维度排序
    3. 策略切换 - fast/stealth/stable 三种推荐策略
    4. 路径分析 - 根节点为当前权限，叶节点为SYSTEM/管理员

Author: 昆仑安全实验室
License: Internal Use Only
"""

from __future__ import annotations

import json
import logging
import os
import platform
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


# =============================================================================
# 枚举与数据模型
# =============================================================================

class DecisionStrategy(str, Enum):
    """决策策略"""
    FAST = "fast"
    STEALTH = "stealth"
    STABLE = "stable"
    BALANCED = "balanced"


class NodeRole(str, Enum):
    """决策树节点角色"""
    ROOT = "root"
    INTERMEDIATE = "intermediate"
    LEAF = "leaf"
    CONDITION = "condition"


class EdgeType(str, Enum):
    """决策树边类型"""
    EXPLOIT = "exploit"
    CONDITION = "condition"
    FALLBACK = "fallback"
    PERSISTENCE = "persistence"


@dataclass
class DecisionNode:
    """决策树节点

    Attributes:
        node_id: 节点唯一ID
        label: 节点显示标签
        role: 节点角色
        privilege_level: 权限级别描述
        description: 详细描述
        category: 关联检查类别
        risk_score: 风险评分 0-100
        edr_risk: EDR风险等级
        estimated_time: 预估耗时（秒）
        success_probability: 成功概率 0-1
        prerequisites: 前置条件列表
        is_exploitable: 是否可利用
    """
    node_id: str = ""
    label: str = ""
    role: NodeRole = NodeRole.INTERMEDIATE
    privilege_level: str = ""
    description: str = ""
    category: str = ""
    risk_score: int = 0
    edr_risk: str = "medium"
    estimated_time: int = 30
    success_probability: float = 0.0
    prerequisites: List[str] = field(default_factory=list)
    is_exploitable: bool = False

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "node_id": self.node_id,
            "label": self.label,
            "role": self.role.value,
            "privilege_level": self.privilege_level,
            "description": self.description,
            "category": self.category,
            "risk_score": self.risk_score,
            "edr_risk": self.edr_risk,
            "estimated_time": self.estimated_time,
            "success_probability": self.success_probability,
            "prerequisites": self.prerequisites,
            "is_exploitable": self.is_exploitable,
        }


@dataclass
class DecisionEdge:
    """决策树边

    Attributes:
        edge_id: 边唯一ID
        source_id: 源节点ID
        target_id: 目标节点ID
        edge_type: 边类型
        label: 边显示标签
        exploit_method: 利用方法描述
        exploit_command: 利用命令
        success_probability: 成功概率 0-1
        edr_risk: EDR风险等级
        estimated_time: 预估耗时（秒）
        system_impact: 系统影响评分 0-100
        stealth_score: 隐蔽性评分 0-100
    """
    edge_id: str = ""
    source_id: str = ""
    target_id: str = ""
    edge_type: EdgeType = EdgeType.EXPLOIT
    label: str = ""
    exploit_method: str = ""
    exploit_command: str = ""
    success_probability: float = 0.0
    edr_risk: str = "medium"
    estimated_time: int = 30
    system_impact: int = 50
    stealth_score: int = 50

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "edge_id": self.edge_id,
            "source_id": self.source_id,
            "target_id": self.target_id,
            "edge_type": self.edge_type.value,
            "label": self.label,
            "exploit_method": self.exploit_method,
            "exploit_command": self.exploit_command,
            "success_probability": self.success_probability,
            "edr_risk": self.edr_risk,
            "estimated_time": self.estimated_time,
            "system_impact": self.system_impact,
            "stealth_score": self.stealth_score,
        }


@dataclass
class ExploitPath:
    """利用路径

    Attributes:
        path_id: 路径唯一ID
        nodes: 节点ID序列
        edges: 边ID序列
        total_success_probability: 总成功概率
        total_estimated_time: 总预估耗时
        max_edr_risk: 最大EDR风险
        avg_stealth_score: 平均隐蔽性评分
        avg_system_impact: 平均系统影响
        description: 路径描述
        is_recommended: 是否推荐
    """
    path_id: str = ""
    nodes: List[str] = field(default_factory=list)
    edges: List[str] = field(default_factory=list)
    total_success_probability: float = 0.0
    total_estimated_time: int = 0
    max_edr_risk: str = "medium"
    avg_stealth_score: float = 0.0
    avg_system_impact: float = 0.0
    description: str = ""
    is_recommended: bool = False

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "path_id": self.path_id,
            "nodes": self.nodes,
            "edges": self.edges,
            "total_success_probability": round(self.total_success_probability, 2),
            "total_estimated_time": self.total_estimated_time,
            "max_edr_risk": self.max_edr_risk,
            "avg_stealth_score": round(self.avg_stealth_score, 1),
            "avg_system_impact": round(self.avg_system_impact, 1),
            "description": self.description,
            "is_recommended": self.is_recommended,
        }


@dataclass
class PriorityMatrix:
    """优先级矩阵

    Attributes:
        vectors: 可利用向量列表
        sorted_by_success: 按成功率排序
        sorted_by_stealth: 按隐蔽性排序
        sorted_by_stability: 按稳定性排序
        recommended: 推荐向量
        strategy: 当前策略
    """
    vectors: List[Dict[str, Any]] = field(default_factory=list)
    sorted_by_success: List[str] = field(default_factory=list)
    sorted_by_stealth: List[str] = field(default_factory=list)
    sorted_by_stability: List[str] = field(default_factory=list)
    recommended: Optional[Dict[str, Any]] = None
    strategy: DecisionStrategy = DecisionStrategy.BALANCED

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "vectors": self.vectors,
            "sorted_by_success": self.sorted_by_success,
            "sorted_by_stealth": self.sorted_by_stealth,
            "sorted_by_stability": self.sorted_by_stability,
            "recommended": self.recommended,
            "strategy": self.strategy.value,
        }


@dataclass
class DecisionTree:
    """决策树

    Attributes:
        tree_id: 树唯一ID
        session_id: Beacon会话ID
        hostname: 主机名
        root_node: 根节点
        nodes: 节点字典
        edges: 边列表
        paths: 利用路径列表
        priority_matrix: 优先级矩阵
        generated_at: 生成时间
    """
    tree_id: str = ""
    session_id: str = ""
    hostname: str = ""
    root_node: Optional[DecisionNode] = None
    nodes: Dict[str, DecisionNode] = field(default_factory=dict)
    edges: List[DecisionEdge] = field(default_factory=list)
    paths: List[ExploitPath] = field(default_factory=list)
    priority_matrix: Optional[PriorityMatrix] = None
    generated_at: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "tree_id": self.tree_id,
            "session_id": self.session_id,
            "hostname": self.hostname,
            "root_node": self.root_node.to_dict() if self.root_node else None,
            "nodes": {nid: n.to_dict() for nid, n in self.nodes.items()},
            "edges": [e.to_dict() for e in self.edges],
            "paths": [p.to_dict() for p in self.paths],
            "priority_matrix": self.priority_matrix.to_dict() if self.priority_matrix else None,
            "generated_at": self.generated_at,
        }


# =============================================================================
# 决策树构建器
# =============================================================================

class PrivescDecisionTreeBuilder:
    """提权决策树构建器

    根据收集的系统信息和分析结果，自动生成利用决策树。

    Attributes:
        _tree: 当前决策树
        _node_counter: 节点计数器
    """

    def __init__(self) -> None:
        """初始化决策树构建器"""
        self._tree: Optional[DecisionTree] = None
        self._node_counter: int = 0

    def _next_node_id(self) -> str:
        """生成下一个节点ID

        Returns:
            节点ID
        """
        self._node_counter += 1
        return f"node_{self._node_counter:03d}"

    def _next_edge_id(self) -> str:
        """生成下一个边ID

        Returns:
            边ID
        """
        return f"edge_{self._node_counter:03d}"

    def build(
        self,
        session_id: str,
        hostname: str,
        current_privilege: str,
        findings: List[Dict[str, Any]],
    ) -> DecisionTree:
        """构建决策树

        Args:
            session_id: Beacon会话ID
            hostname: 主机名
            current_privilege: 当前权限级别
            findings: 风险发现列表

        Returns:
            决策树
        """
        import uuid

        self._tree = DecisionTree(
            tree_id=str(uuid.uuid4())[:12],
            session_id=session_id,
            hostname=hostname,
            generated_at=datetime.now().isoformat(),
        )
        self._node_counter = 0

        exploitable = [f for f in findings if f.get("risk_score", 0) >= 30]

        self._build_root_node(current_privilege)
        self._build_intermediate_nodes(exploitable)
        self._build_leaf_nodes()
        self._build_edges(exploitable)
        self._find_all_paths()
        self._build_priority_matrix(exploitable)

        return self._tree

    def _build_root_node(self, current_privilege: str) -> None:
        """构建根节点

        Args:
            current_privilege: 当前权限级别
        """
        assert self._tree is not None

        root = DecisionNode(
            node_id=self._next_node_id(),
            label=current_privilege,
            role=NodeRole.ROOT,
            privilege_level=current_privilege,
            description=f"当前用户权限: {current_privilege}",
            is_exploitable=False,
        )
        self._tree.root_node = root
        self._tree.nodes[root.node_id] = root

    def _build_intermediate_nodes(self, findings: List[Dict[str, Any]]) -> None:
        """构建中间节点（可利用向量）

        Args:
            findings: 风险发现列表
        """
        assert self._tree is not None

        for f in findings:
            category = f.get("category", "")
            risk_score = f.get("risk_score", 0)

            node = DecisionNode(
                node_id=self._next_node_id(),
                label=f.get("title", category),
                role=NodeRole.INTERMEDIATE,
                privilege_level=self._estimate_privilege(category),
                description=f.get("description", ""),
                category=category,
                risk_score=risk_score,
                edr_risk=self._estimate_edr_risk(category),
                estimated_time=self._estimate_time(category),
                success_probability=min(risk_score / 100.0, 0.95),
                prerequisites=self._get_prerequisites(category),
                is_exploitable=True,
            )
            self._tree.nodes[node.node_id] = node

    def _build_leaf_nodes(self) -> None:
        """构建叶节点（目标权限）"""
        assert self._tree is not None

        leaf_nodes = [
            DecisionNode(
                node_id=self._next_node_id(),
                label="Administrator",
                role=NodeRole.LEAF,
                privilege_level="Administrator",
                description="本地管理员权限",
                is_exploitable=False,
            ),
            DecisionNode(
                node_id=self._next_node_id(),
                label="SYSTEM",
                role=NodeRole.LEAF,
                privilege_level="NT AUTHORITY\\SYSTEM",
                description="系统最高权限",
                is_exploitable=False,
            ),
        ]

        for node in leaf_nodes:
            self._tree.nodes[node.node_id] = node

    def _build_edges(self, findings: List[Dict[str, Any]]) -> None:
        """构建边（利用路径）

        Args:
            findings: 风险发现列表
        """
        assert self._tree is not None
        assert self._tree.root_node is not None

        root_id = self._tree.root_node.node_id

        intermediate_nodes = [
            n for n in self._tree.nodes.values()
            if n.role == NodeRole.INTERMEDIATE and n.is_exploitable
        ]
        leaf_nodes = [
            n for n in self._tree.nodes.values()
            if n.role == NodeRole.LEAF
        ]

        for node in intermediate_nodes:
            edge = DecisionEdge(
                edge_id=self._next_edge_id(),
                source_id=root_id,
                target_id=node.node_id,
                edge_type=EdgeType.EXPLOIT,
                label=node.label,
                exploit_method=self._get_exploit_method(node.category),
                exploit_command=self._get_exploit_command(node.category),
                success_probability=node.success_probability,
                edr_risk=node.edr_risk,
                estimated_time=node.estimated_time,
                system_impact=self._estimate_system_impact(node.category),
                stealth_score=self._estimate_stealth(node.category),
            )
            self._tree.edges.append(edge)

            for leaf in leaf_nodes:
                if self._can_reach(node.category, leaf.privilege_level):
                    leaf_edge = DecisionEdge(
                        edge_id=self._next_edge_id(),
                        source_id=node.node_id,
                        target_id=leaf.node_id,
                        edge_type=EdgeType.EXPLOIT,
                        label="→ " + leaf.label,
                        exploit_method="利用成功，权限提升",
                        success_probability=node.success_probability * 0.9,
                        edr_risk=node.edr_risk,
                        estimated_time=10,
                        system_impact=0,
                        stealth_score=node.stealth_score,
                    )
                    self._tree.edges.append(leaf_edge)

        for i, n1 in enumerate(intermediate_nodes):
            for n2 in intermediate_nodes[i + 1:]:
                if self._can_chain(n1.category, n2.category):
                    chain_edge = DecisionEdge(
                        edge_id=self._next_edge_id(),
                        source_id=n1.node_id,
                        target_id=n2.node_id,
                        edge_type=EdgeType.PERSISTENCE,
                        label=f"组合: {n1.label} + {n2.label}",
                        exploit_method="组合利用链",
                        success_probability=n1.success_probability * n2.success_probability,
                        edr_risk=self._max_edr(n1.edr_risk, n2.edr_risk),
                        estimated_time=n1.estimated_time + n2.estimated_time,
                        system_impact=max(
                            self._estimate_system_impact(n1.category),
                            self._estimate_system_impact(n2.category),
                        ),
                        stealth_score=min(
                            self._estimate_stealth(n1.category),
                            self._estimate_stealth(n2.category),
                        ),
                    )
                    self._tree.edges.append(chain_edge)

    def _find_all_paths(self) -> None:
        """查找所有从根到叶的路径"""
        assert self._tree is not None
        assert self._tree.root_node is not None

        paths: List[ExploitPath] = []
        path_counter = 0

        leaf_nodes = [
            n for n in self._tree.nodes.values()
            if n.role == NodeRole.LEAF
        ]

        for leaf in leaf_nodes:
            dfs_paths = self._dfs_paths(
                self._tree.root_node.node_id,
                leaf.node_id,
            )
            for node_seq in dfs_paths:
                path_counter += 1
                path_edges = []
                total_prob = 1.0
                total_time = 0
                max_edr = "none"
                total_stealth = 0
                total_impact = 0
                edge_count = 0

                for i in range(len(node_seq) - 1):
                    edge = self._find_edge(node_seq[i], node_seq[i + 1])
                    if edge:
                        path_edges.append(edge.edge_id)
                        total_prob *= edge.success_probability
                        total_time += edge.estimated_time
                        max_edr = self._max_edr(max_edr, edge.edr_risk)
                        total_stealth += edge.stealth_score
                        total_impact += edge.system_impact
                        edge_count += 1

                avg_stealth = total_stealth / max(edge_count, 1)
                avg_impact = total_impact / max(edge_count, 1)

                path_labels = [
                    self._tree.nodes[nid].label
                    for nid in node_seq
                    if nid in self._tree.nodes
                ]

                path = ExploitPath(
                    path_id=f"path_{path_counter:03d}",
                    nodes=node_seq,
                    edges=path_edges,
                    total_success_probability=total_prob,
                    total_estimated_time=total_time,
                    max_edr_risk=max_edr,
                    avg_stealth_score=avg_stealth,
                    avg_system_impact=avg_impact,
                    description=" → ".join(path_labels),
                )
                paths.append(path)

        paths.sort(key=lambda p: -p.total_success_probability)

        if paths:
            paths[0].is_recommended = True

        self._tree.paths = paths

    def _dfs_paths(self, start: str, end: str) -> List[List[str]]:
        """深度优先搜索所有路径

        Args:
            start: 起始节点ID
            end: 目标节点ID

        Returns:
            所有路径列表
        """
        assert self._tree is not None

        all_paths: List[List[str]] = []
        stack: List[Tuple[str, List[str]]] = [(start, [start])]
        visited_global: Set[str] = set()

        while stack:
            current, path = stack.pop()

            if current == end:
                all_paths.append(path)
                continue

            neighbors = self._get_neighbors(current)
            for neighbor in neighbors:
                if neighbor not in path:
                    stack.append((neighbor, path + [neighbor]))

        return all_paths

    def _get_neighbors(self, node_id: str) -> List[str]:
        """获取节点的邻居

        Args:
            node_id: 节点ID

        Returns:
            邻居节点ID列表
        """
        assert self._tree is not None

        neighbors = []
        for edge in self._tree.edges:
            if edge.source_id == node_id:
                neighbors.append(edge.target_id)
        return neighbors

    def _find_edge(self, source_id: str, target_id: str) -> Optional[DecisionEdge]:
        """查找边

        Args:
            source_id: 源节点ID
            target_id: 目标节点ID

        Returns:
            边或None
        """
        assert self._tree is not None

        for edge in self._tree.edges:
            if edge.source_id == source_id and edge.target_id == target_id:
                return edge
        return None

    def _build_priority_matrix(self, findings: List[Dict[str, Any]]) -> None:
        """构建优先级矩阵

        Args:
            findings: 风险发现列表
        """
        assert self._tree is not None

        exploitable = [f for f in findings if f.get("risk_score", 0) >= 30]

        vectors = []
        for f in exploitable:
            category = f.get("category", "")
            risk_score = f.get("risk_score", 0)

            success_prob = min(risk_score / 100.0, 0.95)
            stealth = self._estimate_stealth(category)
            stability = self._estimate_stability(category)
            impact = self._estimate_system_impact(category)

            vectors.append({
                "category": category,
                "title": f.get("title", ""),
                "risk_score": risk_score,
                "success_probability": round(success_prob, 2),
                "stealth_score": stealth,
                "stability_score": stability,
                "system_impact": impact,
                "edr_risk": self._estimate_edr_risk(category),
                "estimated_time": self._estimate_time(category),
            })

        by_success = sorted(vectors, key=lambda v: -v["success_probability"])
        by_stealth = sorted(vectors, key=lambda v: -v["stealth_score"])
        by_stability = sorted(vectors, key=lambda v: -v["stability_score"])

        recommended = None
        if vectors:
            best = max(
                vectors,
                key=lambda v: v["success_probability"] * 0.5
                + (v["stealth_score"] / 100.0) * 0.3
                + (v["stability_score"] / 100.0) * 0.2,
            )
            recommended = best

        self._tree.priority_matrix = PriorityMatrix(
            vectors=vectors,
            sorted_by_success=[v["category"] for v in by_success],
            sorted_by_stealth=[v["category"] for v in by_stealth],
            sorted_by_stability=[v["category"] for v in by_stability],
            recommended=recommended,
            strategy=DecisionStrategy.BALANCED,
        )

    # =========================================================================
    # 辅助方法
    # =========================================================================

    def _estimate_privilege(self, category: str) -> str:
        """估计利用后权限级别

        Args:
            category: 检查类别

        Returns:
            权限级别描述
        """
        system_categories = {
            "always_install_elevated",
            "cve_patch_missing",
            "vulnerable_driver",
            "token_privilege",
        }
        admin_categories = {
            "unquoted_service_path",
            "writable_service",
            "scheduled_task",
            "uac_config",
        }

        if category in system_categories:
            return "NT AUTHORITY\\SYSTEM"
        if category in admin_categories:
            return "Administrator"
        return "Unknown"

    def _estimate_edr_risk(self, category: str) -> str:
        """估计EDR风险

        Args:
            category: 检查类别

        Returns:
            EDR风险等级
        """
        edr_map = {
            "always_install_elevated": "medium",
            "unquoted_service_path": "low",
            "writable_service": "medium",
            "cve_patch_missing": "medium",
            "vulnerable_driver": "critical",
            "token_privilege": "high",
            "uac_config": "low",
            "scheduled_task": "low",
            "credential_file": "low",
            "dll_hijack": "low",
            "outdated_software": "medium",
            "vm_escape": "critical",
        }
        return edr_map.get(category, "medium")

    def _estimate_time(self, category: str) -> int:
        """估计利用耗时

        Args:
            category: 检查类别

        Returns:
            预估耗时（秒）
        """
        time_map = {
            "always_install_elevated": 60,
            "unquoted_service_path": 30,
            "writable_service": 30,
            "cve_patch_missing": 120,
            "vulnerable_driver": 180,
            "token_privilege": 90,
            "uac_config": 15,
            "scheduled_task": 30,
            "credential_file": 10,
            "dll_hijack": 60,
            "outdated_software": 120,
            "vm_escape": 300,
        }
        return time_map.get(category, 60)

    def _estimate_stealth(self, category: str) -> int:
        """估计隐蔽性评分

        Args:
            category: 检查类别

        Returns:
            隐蔽性评分 0-100
        """
        stealth_map = {
            "always_install_elevated": 40,
            "unquoted_service_path": 60,
            "writable_service": 45,
            "cve_patch_missing": 50,
            "vulnerable_driver": 15,
            "token_privilege": 30,
            "uac_config": 55,
            "scheduled_task": 65,
            "credential_file": 80,
            "dll_hijack": 70,
            "outdated_software": 50,
            "vm_escape": 20,
        }
        return stealth_map.get(category, 50)

    def _estimate_stability(self, category: str) -> int:
        """估计稳定性评分

        Args:
            category: 检查类别

        Returns:
            稳定性评分 0-100
        """
        stability_map = {
            "always_install_elevated": 80,
            "unquoted_service_path": 65,
            "writable_service": 60,
            "cve_patch_missing": 55,
            "vulnerable_driver": 20,
            "token_privilege": 70,
            "uac_config": 75,
            "scheduled_task": 70,
            "credential_file": 95,
            "dll_hijack": 60,
            "outdated_software": 50,
            "vm_escape": 30,
        }
        return stability_map.get(category, 60)

    def _estimate_system_impact(self, category: str) -> int:
        """估计系统影响评分

        Args:
            category: 检查类别

        Returns:
            系统影响评分 0-100
        """
        impact_map = {
            "always_install_elevated": 30,
            "unquoted_service_path": 25,
            "writable_service": 40,
            "cve_patch_missing": 35,
            "vulnerable_driver": 90,
            "token_privilege": 20,
            "uac_config": 15,
            "scheduled_task": 30,
            "credential_file": 5,
            "dll_hijack": 20,
            "outdated_software": 25,
            "vm_escape": 95,
        }
        return impact_map.get(category, 30)

    def _get_prerequisites(self, category: str) -> List[str]:
        """获取前置条件

        Args:
            category: 检查类别

        Returns:
            前置条件列表
        """
        prereq_map = {
            "always_install_elevated": ["AlwaysInstallElevated=1"],
            "unquoted_service_path": ["未引号服务路径", "可写目录"],
            "writable_service": ["服务修改权限"],
            "cve_patch_missing": ["缺失补丁"],
            "vulnerable_driver": ["漏洞驱动已加载"],
            "token_privilege": ["SeImpersonatePrivilege"],
            "uac_config": ["UAC未启用最高级别"],
            "scheduled_task": ["计划任务可写"],
            "credential_file": ["敏感文件存在"],
            "dll_hijack": ["DLL搜索路径可写"],
            "outdated_software": ["过时软件已安装"],
            "vm_escape": ["虚拟机环境"],
        }
        return prereq_map.get(category, [])

    def _get_exploit_method(self, category: str) -> str:
        """获取利用方法描述

        Args:
            category: 检查类别

        Returns:
            利用方法描述
        """
        method_map = {
            "always_install_elevated": "利用AlwaysInstallElevated以SYSTEM权限安装MSI包",
            "unquoted_service_path": "在未引号服务路径的父目录放置恶意exe",
            "writable_service": "修改可写服务的binPath指向恶意exe",
            "cve_patch_missing": "利用缺失补丁的已知CVE漏洞",
            "vulnerable_driver": "利用漏洞驱动加载未签名内核模块",
            "token_privilege": "利用SeImpersonatePrivilege进行令牌窃取",
            "uac_config": "利用UAC配置弱点绕过用户账户控制",
            "scheduled_task": "劫持以SYSTEM权限运行的计划任务",
            "credential_file": "从自动安装文件中提取明文凭据",
            "dll_hijack": "在DLL搜索路径中放置恶意DLL",
            "outdated_software": "利用过时软件的已知漏洞",
            "vm_escape": "尝试从虚拟机逃逸到宿主机",
        }
        return method_map.get(category, "")

    def _get_exploit_command(self, category: str) -> str:
        """获取利用命令

        Args:
            category: 检查类别

        Returns:
            利用命令
        """
        command_map = {
            "always_install_elevated": "msiexec /quiet /qn /i payload.msi",
            "unquoted_service_path": 'copy payload.exe "C:\\Program Files\\Vuln\\Program.exe"',
            "writable_service": 'sc config <service> binPath= "C:\\path\\to\\payload.exe"',
            "cve_patch_missing": "<cve_exploit_command>",
            "vulnerable_driver": "kdmapper.exe <driver.sys>",
            "token_privilege": "GodPotato.exe -cmd <command>",
            "uac_config": "bypass_uac_script.ps1",
            "scheduled_task": 'copy payload.exe "C:\\path\\to\\task\\executable.exe"',
            "credential_file": 'type C:\\Windows\\Panther\\Unattend.xml',
            "dll_hijack": 'copy payload.dll "C:\\path\\to\\hijackable\\target.dll"',
            "outdated_software": "<software_exploit_command>",
            "vm_escape": "<vm_escape_exploit>",
        }
        return command_map.get(category, "")

    def _can_reach(self, category: str, target_privilege: str) -> bool:
        """判断是否能达到目标权限

        Args:
            category: 检查类别
            target_privilege: 目标权限

        Returns:
            是否能达到
        """
        system_categories = {
            "always_install_elevated",
            "cve_patch_missing",
            "vulnerable_driver",
            "token_privilege",
        }

        if target_privilege == "NT AUTHORITY\\SYSTEM":
            return category in system_categories
        if target_privilege == "Administrator":
            return True
        return False

    def _can_chain(self, cat1: str, cat2: str) -> bool:
        """判断两个类别是否可以组合利用

        Args:
            cat1: 第一个类别
            cat2: 第二个类别

        Returns:
            是否可以组合
        """
        chain_pairs = [
            ("token_privilege", "writable_service"),
            ("token_privilege", "unquoted_service_path"),
            ("always_install_elevated", "credential_file"),
            ("unquoted_service_path", "dll_hijack"),
            ("cve_patch_missing", "credential_file"),
        ]
        return (cat1, cat2) in chain_pairs or (cat2, cat1) in chain_pairs

    def _max_edr(self, edr1: str, edr2: str) -> str:
        """取两个EDR风险中的较大值

        Args:
            edr1: 第一个EDR风险
            edr2: 第二个EDR风险

        Returns:
            较大的EDR风险
        """
        risk_order = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        return edr1 if risk_order.get(edr1, 0) >= risk_order.get(edr2, 0) else edr2


# =============================================================================
# Mermaid格式生成器
# =============================================================================

class MermaidDecisionTreeRenderer:
    """Mermaid格式决策树渲染器

    将决策树转换为Mermaid流程图语法。
    """

    @staticmethod
    def render(tree: DecisionTree) -> str:
        """渲染Mermaid格式决策树

        Args:
            tree: 决策树

        Returns:
            Mermaid格式字符串
        """
        lines = ["graph TD"]

        if tree.root_node:
            root = tree.root_node
            lines.append(
                f'    {root.node_id}["{root.label}"]:::rootStyle'
            )

        for node in tree.nodes.values():
            if node.role == NodeRole.ROOT:
                continue

            style_class = "leafStyle" if node.role == NodeRole.LEAF else "nodeStyle"
            if node.is_exploitable:
                risk_color = MermaidDecisionTreeRenderer._risk_color(node.risk_score)
                lines.append(
                    f'    {node.node_id}["{node.label}\\n风险:{node.risk_score}"]:::{style_class}'
                )
            else:
                lines.append(
                    f'    {node.node_id}["{node.label}"]:::{style_class}'
                )

        for edge in tree.edges:
            source_label = ""
            if edge.exploit_method:
                source_label = f"|{edge.exploit_method[:30]}|"

            if edge.edge_type == EdgeType.PERSISTENCE:
                lines.append(
                    f"    {edge.source_id} -.-> {source_label} {edge.target_id}"
                )
            else:
                lines.append(
                    f"    {edge.source_id} --> {source_label} {edge.target_id}"
                )

        lines.append("")
        lines.append("    classDef rootStyle fill:#2d2d2d,stroke:#ff6b6b,stroke-width:3px,color:#fff")
        lines.append("    classDef nodeStyle fill:#1a1a2e,stroke:#4ecdc4,stroke-width:2px,color:#fff")
        lines.append("    classDef leafStyle fill:#1a1a2e,stroke:#ffd93d,stroke-width:3px,color:#fff")

        return "\n".join(lines)

    @staticmethod
    def _risk_color(score: int) -> str:
        """根据风险评分返回颜色

        Args:
            score: 风险评分

        Returns:
            颜色代码
        """
        if score >= 80:
            return "#ff4757"
        if score >= 60:
            return "#ffa502"
        if score >= 40:
            return "#ffdd59"
        return "#2ed573"


# =============================================================================
# 策略切换器
# =============================================================================

class PrivescStrategyManager:
    """提权策略管理器

    管理利用策略切换，支持fast/stealth/stable/balanced四种策略。
    """

    STRATEGY_DESCRIPTIONS = {
        DecisionStrategy.FAST: "优先成功率，快速提权",
        DecisionStrategy.STEALTH: "优先隐蔽性，降低检测风险",
        DecisionStrategy.STABLE: "优先稳定性，降低系统影响",
        DecisionStrategy.BALANCED: "平衡成功率/隐蔽性/稳定性",
    }

    def __init__(self) -> None:
        """初始化策略管理器"""
        self._current_strategy: DecisionStrategy = DecisionStrategy.BALANCED

    @property
    def current_strategy(self) -> DecisionStrategy:
        """获取当前策略"""
        return self._current_strategy

    def set_strategy(self, strategy: DecisionStrategy) -> Dict[str, Any]:
        """切换策略

        Args:
            strategy: 新策略

        Returns:
            策略切换结果
        """
        self._current_strategy = strategy
        return {
            "strategy": strategy.value,
            "description": self.STRATEGY_DESCRIPTIONS.get(strategy, ""),
            "sort_key": self._get_sort_key(strategy),
        }

    def _get_sort_key(self, strategy: DecisionStrategy):
        """获取排序键

        Args:
            strategy: 策略

        Returns:
            排序键函数
        """
        sort_keys = {
            DecisionStrategy.FAST: lambda v: -v["success_probability"],
            DecisionStrategy.STEALTH: lambda v: -v["stealth_score"],
            DecisionStrategy.STABLE: lambda v: -v["stability_score"],
            DecisionStrategy.BALANCED: lambda v: -(
                v["success_probability"] * 0.5
                + (v["stealth_score"] / 100.0) * 0.3
                + (v["stability_score"] / 100.0) * 0.2
            ),
        }
        return sort_keys.get(strategy, sort_keys[DecisionStrategy.BALANCED])

    def sort_vectors(
        self, vectors: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """按当前策略排序向量

        Args:
            vectors: 可利用向量列表

        Returns:
            排序后的向量列表
        """
        sort_key = self._get_sort_key(self._current_strategy)
        return sorted(vectors, key=sort_key)

    def get_recommendation(
        self, vectors: List[Dict[str, Any]],
    ) -> Optional[Dict[str, Any]]:
        """获取推荐向量

        Args:
            vectors: 可利用向量列表

        Returns:
            推荐的向量或None
        """
        if not vectors:
            return None

        sorted_vectors = self.sort_vectors(vectors)
        return sorted_vectors[0]


# =============================================================================
# 全局单例
# =============================================================================

_decision_tree_builder: Optional[PrivescDecisionTreeBuilder] = None
_strategy_manager: Optional[PrivescStrategyManager] = None


def get_decision_tree_builder() -> PrivescDecisionTreeBuilder:
    """获取决策树构建器全局单例

    Returns:
        PrivescDecisionTreeBuilder 实例
    """
    global _decision_tree_builder
    if _decision_tree_builder is None:
        _decision_tree_builder = PrivescDecisionTreeBuilder()
    return _decision_tree_builder


def get_strategy_manager() -> PrivescStrategyManager:
    """获取策略管理器全局单例

    Returns:
        PrivescStrategyManager 实例
    """
    global _strategy_manager
    if _strategy_manager is None:
        _strategy_manager = PrivescStrategyManager()
    return _strategy_manager


__all__ = [
    "PrivescDecisionTreeBuilder",
    "MermaidDecisionTreeRenderer",
    "PrivescStrategyManager",
    "DecisionStrategy",
    "NodeRole",
    "EdgeType",
    "DecisionNode",
    "DecisionEdge",
    "ExploitPath",
    "PriorityMatrix",
    "DecisionTree",
    "get_decision_tree_builder",
    "get_strategy_manager",
]
