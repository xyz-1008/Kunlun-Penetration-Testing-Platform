"""
Windows/Linux提权辅助套件 - 配置管理与分发模块
===================================================
统一配置管理、热更新分发、规则与知识库管理。

核心能力:
    1. 提权策略配置 - 全局默认策略、按Beacon分组策略
    2. 规则与知识库分发 - C2统一管理、自动拉取
    3. 策略热更新 - 自动推送、增量更新

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
from typing import Any, Callable, Coroutine, Dict, List, Optional, Set

logger = logging.getLogger(__name__)


# =============================================================================
# 枚举与数据模型
# =============================================================================

class ConfigScope(str, Enum):
    """配置范围"""
    GLOBAL = "global"
    GROUP = "group"
    BEACON = "beacon"


class ConfigKey(str, Enum):
    """配置键"""
    MAX_CONCURRENT = "max_concurrent"
    EXPLOIT_TIMEOUT = "exploit_timeout"
    ALLOW_KERNEL_EXPLOIT = "allow_kernel_exploit"
    AUTO_PERSIST = "auto_persist"
    SCHEDULED_CHECK_INTERVAL = "scheduled_check_interval"
    ENABLE_STEALTH_MODE = "enable_stealth_mode"
    MAX_PAYLOAD_SIZE = "max_payload_size"
    CLEANUP_AFTER_EXPLOIT = "cleanup_after_exploit"
    REPORT_TO_C2 = "report_to_c2"
    RULE_VERSION = "rule_version"
    KNOWLEDGE_BASE_VERSION = "knowledge_base_version"


@dataclass
class PolicyConfig:
    """策略配置

    Attributes:
        max_concurrent: 最大并发利用数
        exploit_timeout: 默认利用超时（秒）
        allow_kernel_exploit: 是否允许内核利用
        auto_persist: 是否自动持久化
        scheduled_check_interval: 定时检查间隔（小时）
        enable_stealth_mode: 是否启用隐身模式
        max_payload_size: 最大载荷大小（KB）
        cleanup_after_exploit: 利用后是否清理
        report_to_c2: 是否上报C2
    """
    max_concurrent: int = 5
    exploit_timeout: int = 300
    allow_kernel_exploit: bool = False
    auto_persist: bool = False
    scheduled_check_interval: int = 24
    enable_stealth_mode: bool = True
    max_payload_size: int = 1024
    cleanup_after_exploit: bool = True
    report_to_c2: bool = True

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "max_concurrent": self.max_concurrent,
            "exploit_timeout": self.exploit_timeout,
            "allow_kernel_exploit": self.allow_kernel_exploit,
            "auto_persist": self.auto_persist,
            "scheduled_check_interval": self.scheduled_check_interval,
            "enable_stealth_mode": self.enable_stealth_mode,
            "max_payload_size": self.max_payload_size,
            "cleanup_after_exploit": self.cleanup_after_exploit,
            "report_to_c2": self.report_to_c2,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PolicyConfig":
        """从字典创建

        Args:
            data: 配置字典

        Returns:
            PolicyConfig实例
        """
        return cls(
            max_concurrent=data.get("max_concurrent", 5),
            exploit_timeout=data.get("exploit_timeout", 300),
            allow_kernel_exploit=data.get("allow_kernel_exploit", False),
            auto_persist=data.get("auto_persist", False),
            scheduled_check_interval=data.get("scheduled_check_interval", 24),
            enable_stealth_mode=data.get("enable_stealth_mode", True),
            max_payload_size=data.get("max_payload_size", 1024),
            cleanup_after_exploit=data.get("cleanup_after_exploit", True),
            report_to_c2=data.get("report_to_c2", True),
        )


@dataclass
class BeaconGroup:
    """Beacon分组

    Attributes:
        group_id: 分组ID
        name: 分组名
        description: 描述
        beacon_ids: Beacon ID列表
        policy: 策略配置
        tags: 标签
    """
    group_id: str = ""
    name: str = ""
    description: str = ""
    beacon_ids: List[str] = field(default_factory=list)
    policy: PolicyConfig = field(default_factory=PolicyConfig)
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "group_id": self.group_id,
            "name": self.name,
            "description": self.description,
            "beacon_ids": self.beacon_ids,
            "policy": self.policy.to_dict(),
            "tags": self.tags,
        }


@dataclass
class RuleEntry:
    """规则条目

    Attributes:
        rule_id: 规则ID
        name: 规则名
        description: 描述
        category: 分类
        severity: 严重程度
        check_command: 检查命令
        exploit_command: 利用命令
        platforms: 支持平台
        cve_ids: CVE ID列表
        enabled: 是否启用
        version: 版本
        checksum: 校验和
        created_at: 创建时间
        updated_at: 更新时间
    """
    rule_id: str = ""
    name: str = ""
    description: str = ""
    category: str = ""
    severity: str = "medium"
    check_command: str = ""
    exploit_command: str = ""
    platforms: List[str] = field(default_factory=list)
    cve_ids: List[str] = field(default_factory=list)
    enabled: bool = True
    version: str = "1.0.0"
    checksum: str = ""
    created_at: str = ""
    updated_at: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "description": self.description,
            "category": self.category,
            "severity": self.severity,
            "check_command": self.check_command,
            "exploit_command": self.exploit_command,
            "platforms": self.platforms,
            "cve_ids": self.cve_ids,
            "enabled": self.enabled,
            "version": self.version,
            "checksum": self.checksum,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    def compute_checksum(self) -> str:
        """计算校验和

        Returns:
            校验和
        """
        content = json.dumps(self.to_dict(), sort_keys=True)
        return hashlib.sha256(content.encode()).hexdigest()[:16]


@dataclass
class KnowledgeEntry:
    """知识条目

    Attributes:
        entry_id: 条目ID
        title: 标题
        content: 内容
        category: 分类
        tags: 标签
        references: 参考链接
        version: 版本
        checksum: 校验和
    """
    entry_id: str = ""
    title: str = ""
    content: str = ""
    category: str = ""
    tags: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    version: str = "1.0.0"
    checksum: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "entry_id": self.entry_id,
            "title": self.title,
            "content": self.content,
            "category": self.category,
            "tags": self.tags,
            "references": self.references,
            "version": self.version,
            "checksum": self.checksum,
        }

    def compute_checksum(self) -> str:
        """计算校验和

        Returns:
            校验和
        """
        content = json.dumps(self.to_dict(), sort_keys=True)
        return hashlib.sha256(content.encode()).hexdigest()[:16]


@dataclass
class UpdateManifest:
    """更新清单

    Attributes:
        version: 版本
        timestamp: 时间戳
        rules_added: 新增规则
        rules_updated: 更新规则
        rules_removed: 移除规则
        knowledge_updated: 知识更新
        config_changes: 配置变更
    """
    version: str = ""
    timestamp: str = ""
    rules_added: List[str] = field(default_factory=list)
    rules_updated: List[str] = field(default_factory=list)
    rules_removed: List[str] = field(default_factory=list)
    knowledge_updated: List[str] = field(default_factory=list)
    config_changes: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "version": self.version,
            "timestamp": self.timestamp,
            "rules_added": self.rules_added,
            "rules_updated": self.rules_updated,
            "rules_removed": self.rules_removed,
            "knowledge_updated": self.knowledge_updated,
            "config_changes": self.config_changes,
        }


@dataclass
class ConfigSnapshot:
    """配置快照

    Attributes:
        snapshot_id: 快照ID
        timestamp: 时间戳
        global_policy: 全局策略
        groups: 分组配置
        rules: 规则
        knowledge: 知识
        version: 版本
    """
    snapshot_id: str = ""
    timestamp: str = ""
    global_policy: PolicyConfig = field(default_factory=PolicyConfig)
    groups: List[BeaconGroup] = field(default_factory=list)
    rules: List[RuleEntry] = field(default_factory=list)
    knowledge: List[KnowledgeEntry] = field(default_factory=list)
    version: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "snapshot_id": self.snapshot_id,
            "timestamp": self.timestamp,
            "global_policy": self.global_policy.to_dict(),
            "groups": [g.to_dict() for g in self.groups],
            "rules": [r.to_dict() for r in self.rules],
            "knowledge": [k.to_dict() for k in self.knowledge],
            "version": self.version,
        }


# =============================================================================
# 配置存储
# =============================================================================

class ConfigStorage:
    """配置存储

    管理配置的持久化。

    Attributes:
        _storage_path: 存储路径
    """

    def __init__(self, storage_path: str = "") -> None:
        """初始化配置存储

        Args:
            storage_path: 存储路径
        """
        self._storage_path = storage_path or os.path.join(
            os.path.expanduser("~"), ".privesc_config"
        )
        os.makedirs(self._storage_path, exist_ok=True)

    async def save_policy(self, policy: PolicyConfig, scope: ConfigScope, scope_id: str = "") -> bool:
        """保存策略

        Args:
            policy: 策略配置
            scope: 配置范围
            scope_id: 范围ID

        Returns:
            是否成功
        """
        try:
            filename = f"policy_{scope.value}_{scope_id or 'default'}.json"
            filepath = os.path.join(self._storage_path, filename)

            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(policy.to_dict(), f, indent=2, ensure_ascii=False)

            return True
        except Exception as e:
            logger.error(f"保存策略失败: {e}")
            return False

    async def load_policy(self, scope: ConfigScope, scope_id: str = "") -> Optional[PolicyConfig]:
        """加载策略

        Args:
            scope: 配置范围
            scope_id: 范围ID

        Returns:
            策略配置
        """
        try:
            filename = f"policy_{scope.value}_{scope_id or 'default'}.json"
            filepath = os.path.join(self._storage_path, filename)

            if not os.path.exists(filepath):
                return None

            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)

            return PolicyConfig.from_dict(data)
        except Exception as e:
            logger.error(f"加载策略失败: {e}")
            return None

    async def save_rules(self, rules: List[RuleEntry]) -> bool:
        """保存规则

        Args:
            rules: 规则列表

        Returns:
            是否成功
        """
        try:
            filepath = os.path.join(self._storage_path, "rules.json")

            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(
                    [r.to_dict() for r in rules],
                    f,
                    indent=2,
                    ensure_ascii=False,
                )

            return True
        except Exception as e:
            logger.error(f"保存规则失败: {e}")
            return False

    async def load_rules(self) -> List[RuleEntry]:
        """加载规则

        Returns:
            规则列表
        """
        try:
            filepath = os.path.join(self._storage_path, "rules.json")

            if not os.path.exists(filepath):
                return []

            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)

            return [
                RuleEntry(
                    rule_id=r.get("rule_id", ""),
                    name=r.get("name", ""),
                    description=r.get("description", ""),
                    category=r.get("category", ""),
                    severity=r.get("severity", "medium"),
                    check_command=r.get("check_command", ""),
                    exploit_command=r.get("exploit_command", ""),
                    platforms=r.get("platforms", []),
                    cve_ids=r.get("cve_ids", []),
                    enabled=r.get("enabled", True),
                    version=r.get("version", "1.0.0"),
                    checksum=r.get("checksum", ""),
                    created_at=r.get("created_at", ""),
                    updated_at=r.get("updated_at", ""),
                )
                for r in data
            ]
        except Exception as e:
            logger.error(f"加载规则失败: {e}")
            return []

    async def save_knowledge(self, knowledge: List[KnowledgeEntry]) -> bool:
        """保存知识

        Args:
            knowledge: 知识列表

        Returns:
            是否成功
        """
        try:
            filepath = os.path.join(self._storage_path, "knowledge.json")

            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(
                    [k.to_dict() for k in knowledge],
                    f,
                    indent=2,
                    ensure_ascii=False,
                )

            return True
        except Exception as e:
            logger.error(f"保存知识失败: {e}")
            return False

    async def load_knowledge(self) -> List[KnowledgeEntry]:
        """加载知识

        Returns:
            知识列表
        """
        try:
            filepath = os.path.join(self._storage_path, "knowledge.json")

            if not os.path.exists(filepath):
                return []

            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)

            return [
                KnowledgeEntry(
                    entry_id=k.get("entry_id", ""),
                    title=k.get("title", ""),
                    content=k.get("content", ""),
                    category=k.get("category", ""),
                    tags=k.get("tags", []),
                    references=k.get("references", []),
                    version=k.get("version", "1.0.0"),
                    checksum=k.get("checksum", ""),
                )
                for k in data
            ]
        except Exception as e:
            logger.error(f"加载知识失败: {e}")
            return []


# =============================================================================
# 配置管理器
# =============================================================================

class PrivescConfigManager:
    """提权配置管理器

    管理全局策略、分组策略、规则和知识库。

    Attributes:
        _global_policy: 全局策略
        _groups: 分组配置
        _rules: 规则
        _knowledge: 知识
        _storage: 配置存储
        _beacon_policies: Beacon策略
        _update_callbacks: 更新回调
    """

    def __init__(self, storage_path: str = "") -> None:
        """初始化配置管理器

        Args:
            storage_path: 存储路径
        """
        self._global_policy = PolicyConfig()
        self._groups: Dict[str, BeaconGroup] = {}
        self._rules: Dict[str, RuleEntry] = {}
        self._knowledge: Dict[str, KnowledgeEntry] = {}
        self._storage = ConfigStorage(storage_path)
        self._beacon_policies: Dict[str, PolicyConfig] = {}
        self._update_callbacks: List[Callable[..., Coroutine]] = []

    async def initialize(self) -> None:
        """初始化配置"""
        await self._load_all()

    async def _load_all(self) -> None:
        """加载所有配置"""
        global_policy = await self._storage.load_policy(ConfigScope.GLOBAL)
        if global_policy:
            self._global_policy = global_policy

        rules = await self._storage.load_rules()
        for rule in rules:
            self._rules[rule.rule_id] = rule

        knowledge = await self._storage.load_knowledge()
        for entry in knowledge:
            self._knowledge[entry.entry_id] = entry

    async def save_all(self) -> None:
        """保存所有配置"""
        await self._storage.save_policy(self._global_policy, ConfigScope.GLOBAL)
        await self._storage.save_rules(list(self._rules.values()))
        await self._storage.save_knowledge(list(self._knowledge.values()))

    def get_global_policy(self) -> PolicyConfig:
        """获取全局策略

        Returns:
            全局策略
        """
        return self._global_policy

    async def update_global_policy(self, **kwargs: Any) -> None:
        """更新全局策略

        Args:
            **kwargs: 策略参数
        """
        for key, value in kwargs.items():
            if hasattr(self._global_policy, key):
                setattr(self._global_policy, key, value)

        await self._storage.save_policy(self._global_policy, ConfigScope.GLOBAL)
        await self._notify_update("global_policy", kwargs)

    def get_beacon_policy(self, beacon_id: str) -> PolicyConfig:
        """获取Beacon策略

        Args:
            beacon_id: Beacon ID

        Returns:
            策略配置
        """
        if beacon_id in self._beacon_policies:
            return self._beacon_policies[beacon_id]

        group = self._get_beacon_group(beacon_id)
        if group:
            return group.policy

        return self._global_policy

    async def set_beacon_policy(
        self, beacon_id: str, policy: PolicyConfig,
    ) -> None:
        """设置Beacon策略

        Args:
            beacon_id: Beacon ID
            policy: 策略配置
        """
        self._beacon_policies[beacon_id] = policy
        await self._storage.save_policy(
            policy, ConfigScope.BEACON, beacon_id,
        )
        await self._notify_update("beacon_policy", {"beacon_id": beacon_id})

    def _get_beacon_group(self, beacon_id: str) -> Optional[BeaconGroup]:
        """获取Beacon所在分组

        Args:
            beacon_id: Beacon ID

        Returns:
            分组
        """
        for group in self._groups.values():
            if beacon_id in group.beacon_ids:
                return group
        return None

    def create_group(self, group: BeaconGroup) -> str:
        """创建分组

        Args:
            group: 分组配置

        Returns:
            分组ID
        """
        if not group.group_id:
            group.group_id = f"group_{int(time.time())}"

        self._groups[group.group_id] = group
        return group.group_id

    def get_group(self, group_id: str) -> Optional[BeaconGroup]:
        """获取分组

        Args:
            group_id: 分组ID

        Returns:
            分组配置
        """
        return self._groups.get(group_id)

    def get_all_groups(self) -> List[BeaconGroup]:
        """获取所有分组

        Returns:
            分组列表
        """
        return list(self._groups.values())

    def add_rule(self, rule: RuleEntry) -> str:
        """添加规则

        Args:
            rule: 规则条目

        Returns:
            规则ID
        """
        if not rule.rule_id:
            rule.rule_id = f"rule_{int(time.time())}"

        rule.checksum = rule.compute_checksum()
        rule.updated_at = datetime.now().isoformat()

        self._rules[rule.rule_id] = rule
        return rule.rule_id

    def get_rule(self, rule_id: str) -> Optional[RuleEntry]:
        """获取规则

        Args:
            rule_id: 规则ID

        Returns:
            规则条目
        """
        return self._rules.get(rule_id)

    def get_all_rules(self) -> List[RuleEntry]:
        """获取所有规则

        Returns:
            规则列表
        """
        return list(self._rules.values())

    def get_enabled_rules(self) -> List[RuleEntry]:
        """获取启用的规则

        Returns:
            规则列表
        """
        return [r for r in self._rules.values() if r.enabled]

    def remove_rule(self, rule_id: str) -> bool:
        """移除规则

        Args:
            rule_id: 规则ID

        Returns:
            是否成功
        """
        if rule_id in self._rules:
            del self._rules[rule_id]
            return True
        return False

    def add_knowledge(self, entry: KnowledgeEntry) -> str:
        """添加知识

        Args:
            entry: 知识条目

        Returns:
            条目ID
        """
        if not entry.entry_id:
            entry.entry_id = f"kb_{int(time.time())}"

        entry.checksum = entry.compute_checksum()
        self._knowledge[entry.entry_id] = entry
        return entry.entry_id

    def get_knowledge(self, entry_id: str) -> Optional[KnowledgeEntry]:
        """获取知识

        Args:
            entry_id: 条目ID

        Returns:
            知识条目
        """
        return self._knowledge.get(entry_id)

    def get_all_knowledge(self) -> List[KnowledgeEntry]:
        """获取所有知识

        Returns:
            知识列表
        """
        return list(self._knowledge.values())

    def register_update_callback(self, callback: Callable[..., Coroutine]) -> None:
        """注册更新回调

        Args:
            callback: 回调函数
        """
        self._update_callbacks.append(callback)

    async def _notify_update(self, update_type: str, details: Dict[str, Any]) -> None:
        """通知更新

        Args:
            update_type: 更新类型
            details: 详细信息
        """
        for callback in self._update_callbacks:
            try:
                await callback(update_type, details)
            except Exception as e:
                logger.error(f"更新回调失败: {e}")

    def export_config(self) -> str:
        """导出配置

        Returns:
            JSON字符串
        """
        snapshot = ConfigSnapshot(
            snapshot_id=f"snapshot_{int(time.time())}",
            timestamp=datetime.now().isoformat(),
            global_policy=self._global_policy,
            groups=list(self._groups.values()),
            rules=list(self._rules.values()),
            knowledge=list(self._knowledge.values()),
            version="1.0.0",
        )
        return json.dumps(snapshot.to_dict(), indent=2, ensure_ascii=False)

    def import_config(self, json_str: str) -> bool:
        """导入配置

        Args:
            json_str: JSON字符串

        Returns:
            是否成功
        """
        try:
            data = json.loads(json_str)

            if "global_policy" in data:
                self._global_policy = PolicyConfig.from_dict(data["global_policy"])

            if "groups" in data:
                for g_data in data["groups"]:
                    group = BeaconGroup(
                        group_id=g_data.get("group_id", ""),
                        name=g_data.get("name", ""),
                        description=g_data.get("description", ""),
                        beacon_ids=g_data.get("beacon_ids", []),
                        policy=PolicyConfig.from_dict(g_data.get("policy", {})),
                        tags=g_data.get("tags", []),
                    )
                    self._groups[group.group_id] = group

            if "rules" in data:
                for r_data in data["rules"]:
                    rule = RuleEntry(
                        rule_id=r_data.get("rule_id", ""),
                        name=r_data.get("name", ""),
                        description=r_data.get("description", ""),
                        category=r_data.get("category", ""),
                        severity=r_data.get("severity", "medium"),
                        check_command=r_data.get("check_command", ""),
                        exploit_command=r_data.get("exploit_command", ""),
                        platforms=r_data.get("platforms", []),
                        cve_ids=r_data.get("cve_ids", []),
                        enabled=r_data.get("enabled", True),
                        version=r_data.get("version", "1.0.0"),
                        checksum=r_data.get("checksum", ""),
                        created_at=r_data.get("created_at", ""),
                        updated_at=r_data.get("updated_at", ""),
                    )
                    self._rules[rule.rule_id] = rule

            if "knowledge" in data:
                for k_data in data["knowledge"]:
                    entry = KnowledgeEntry(
                        entry_id=k_data.get("entry_id", ""),
                        title=k_data.get("title", ""),
                        content=k_data.get("content", ""),
                        category=k_data.get("category", ""),
                        tags=k_data.get("tags", []),
                        references=k_data.get("references", []),
                        version=k_data.get("version", "1.0.0"),
                        checksum=k_data.get("checksum", ""),
                    )
                    self._knowledge[entry.entry_id] = entry

            return True
        except Exception as e:
            logger.error(f"导入配置失败: {e}")
            return False


# =============================================================================
# 热更新分发器
# =============================================================================

class HotUpdateDistributor:
    """热更新分发器

    管理配置的热更新和增量分发。

    Attributes:
        _config_manager: 配置管理器
        _manifests: 更新清单
        _beacon_versions: Beacon版本
    """

    def __init__(self, config_manager: PrivescConfigManager) -> None:
        """初始化热更新分发器

        Args:
            config_manager: 配置管理器
        """
        self._config_manager = config_manager
        self._manifests: List[UpdateManifest] = []
        self._beacon_versions: Dict[str, str] = {}

    def create_update_manifest(
        self,
        version: str,
        rules_added: Optional[List[str]] = None,
        rules_updated: Optional[List[str]] = None,
        rules_removed: Optional[List[str]] = None,
        knowledge_updated: Optional[List[str]] = None,
        config_changes: Optional[Dict[str, Any]] = None,
    ) -> UpdateManifest:
        """创建更新清单

        Args:
            version: 版本
            rules_added: 新增规则
            rules_updated: 更新规则
            rules_removed: 移除规则
            knowledge_updated: 知识更新
            config_changes: 配置变更

        Returns:
            更新清单
        """
        manifest = UpdateManifest(
            version=version,
            timestamp=datetime.now().isoformat(),
            rules_added=rules_added or [],
            rules_updated=rules_updated or [],
            rules_removed=rules_removed or [],
            knowledge_updated=knowledge_updated or [],
            config_changes=config_changes or {},
        )

        self._manifests.append(manifest)
        return manifest

    def get_incremental_update(
        self, beacon_id: str, current_version: str,
    ) -> Dict[str, Any]:
        """获取增量更新

        Args:
            beacon_id: Beacon ID
            current_version: 当前版本

        Returns:
            增量更新数据
        """
        update_data: Dict[str, Any] = {
            "beacon_id": beacon_id,
            "current_version": current_version,
            "updates": [],
        }

        for manifest in self._manifests:
            if manifest.version > current_version:
                update_data["updates"].append(manifest.to_dict())

        self._beacon_versions[beacon_id] = (
            self._manifests[-1].version if self._manifests else current_version
        )

        return update_data

    def get_full_config(self, beacon_id: str) -> Dict[str, Any]:
        """获取完整配置

        Args:
            beacon_id: Beacon ID

        Returns:
            完整配置
        """
        policy = self._config_manager.get_beacon_policy(beacon_id)

        return {
            "beacon_id": beacon_id,
            "policy": policy.to_dict(),
            "rules": [
                r.to_dict()
                for r in self._config_manager.get_enabled_rules()
            ],
            "knowledge": [
                k.to_dict()
                for k in self._config_manager.get_all_knowledge()
            ],
            "version": (
                self._manifests[-1].version if self._manifests else "1.0.0"
            ),
            "timestamp": datetime.now().isoformat(),
        }

    def get_latest_version(self) -> str:
        """获取最新版本

        Returns:
            版本号
        """
        return self._manifests[-1].version if self._manifests else "1.0.0"

    def get_beacon_version(self, beacon_id: str) -> str:
        """获取Beacon版本

        Args:
            beacon_id: Beacon ID

        Returns:
            版本号
        """
        return self._beacon_versions.get(beacon_id, "1.0.0")


# =============================================================================
# 主配置模块
# =============================================================================

class PrivescConfigModule:
    """配置管理与分发模块

    整合配置管理、热更新分发。

    Attributes:
        _config_manager: 配置管理器
        _update_distributor: 热更新分发器
    """

    def __init__(self, storage_path: str = "") -> None:
        """初始化配置模块

        Args:
            storage_path: 存储路径
        """
        self._config_manager = PrivescConfigManager(storage_path)
        self._update_distributor = HotUpdateDistributor(self._config_manager)

    async def initialize(self) -> None:
        """初始化配置"""
        await self._config_manager.initialize()

    async def save_all(self) -> None:
        """保存所有配置"""
        await self._config_manager.save_all()

    def get_global_policy(self) -> PolicyConfig:
        """获取全局策略

        Returns:
            全局策略
        """
        return self._config_manager.get_global_policy()

    async def update_global_policy(self, **kwargs: Any) -> None:
        """更新全局策略

        Args:
            **kwargs: 策略参数
        """
        await self._config_manager.update_global_policy(**kwargs)

    def get_beacon_policy(self, beacon_id: str) -> PolicyConfig:
        """获取Beacon策略

        Args:
            beacon_id: Beacon ID

        Returns:
            策略配置
        """
        return self._config_manager.get_beacon_policy(beacon_id)

    async def set_beacon_policy(
        self, beacon_id: str, policy: PolicyConfig,
    ) -> None:
        """设置Beacon策略

        Args:
            beacon_id: Beacon ID
            policy: 策略配置
        """
        await self._config_manager.set_beacon_policy(beacon_id, policy)

    def create_group(self, group: BeaconGroup) -> str:
        """创建分组

        Args:
            group: 分组配置

        Returns:
            分组ID
        """
        return self._config_manager.create_group(group)

    def get_group(self, group_id: str) -> Optional[BeaconGroup]:
        """获取分组

        Args:
            group_id: 分组ID

        Returns:
            分组配置
        """
        return self._config_manager.get_group(group_id)

    def get_all_groups(self) -> List[BeaconGroup]:
        """获取所有分组

        Returns:
            分组列表
        """
        return self._config_manager.get_all_groups()

    def add_rule(self, rule: RuleEntry) -> str:
        """添加规则

        Args:
            rule: 规则条目

        Returns:
            规则ID
        """
        return self._config_manager.add_rule(rule)

    def get_rule(self, rule_id: str) -> Optional[RuleEntry]:
        """获取规则

        Args:
            rule_id: 规则ID

        Returns:
            规则条目
        """
        return self._config_manager.get_rule(rule_id)

    def get_all_rules(self) -> List[RuleEntry]:
        """获取所有规则

        Returns:
            规则列表
        """
        return self._config_manager.get_all_rules()

    def get_enabled_rules(self) -> List[RuleEntry]:
        """获取启用的规则

        Returns:
            规则列表
        """
        return self._config_manager.get_enabled_rules()

    def remove_rule(self, rule_id: str) -> bool:
        """移除规则

        Args:
            rule_id: 规则ID

        Returns:
            是否成功
        """
        return self._config_manager.remove_rule(rule_id)

    def add_knowledge(self, entry: KnowledgeEntry) -> str:
        """添加知识

        Args:
            entry: 知识条目

        Returns:
            条目ID
        """
        return self._config_manager.add_knowledge(entry)

    def get_knowledge(self, entry_id: str) -> Optional[KnowledgeEntry]:
        """获取知识

        Args:
            entry_id: 条目ID

        Returns:
            知识条目
        """
        return self._config_manager.get_knowledge(entry_id)

    def get_all_knowledge(self) -> List[KnowledgeEntry]:
        """获取所有知识

        Returns:
            知识列表
        """
        return self._config_manager.get_all_knowledge()

    def create_update_manifest(
        self,
        version: str,
        rules_added: Optional[List[str]] = None,
        rules_updated: Optional[List[str]] = None,
        rules_removed: Optional[List[str]] = None,
        knowledge_updated: Optional[List[str]] = None,
        config_changes: Optional[Dict[str, Any]] = None,
    ) -> UpdateManifest:
        """创建更新清单

        Args:
            version: 版本
            rules_added: 新增规则
            rules_updated: 更新规则
            rules_removed: 移除规则
            knowledge_updated: 知识更新
            config_changes: 配置变更

        Returns:
            更新清单
        """
        return self._update_distributor.create_update_manifest(
            version,
            rules_added,
            rules_updated,
            rules_removed,
            knowledge_updated,
            config_changes,
        )

    def get_incremental_update(
        self, beacon_id: str, current_version: str,
    ) -> Dict[str, Any]:
        """获取增量更新

        Args:
            beacon_id: Beacon ID
            current_version: 当前版本

        Returns:
            增量更新数据
        """
        return self._update_distributor.get_incremental_update(
            beacon_id, current_version,
        )

    def get_full_config(self, beacon_id: str) -> Dict[str, Any]:
        """获取完整配置

        Args:
            beacon_id: Beacon ID

        Returns:
            完整配置
        """
        return self._update_distributor.get_full_config(beacon_id)

    def export_config(self) -> str:
        """导出配置

        Returns:
            JSON字符串
        """
        return self._config_manager.export_config()

    def import_config(self, json_str: str) -> bool:
        """导入配置

        Args:
            json_str: JSON字符串

        Returns:
            是否成功
        """
        return self._config_manager.import_config(json_str)

    def register_update_callback(self, callback: Callable[..., Coroutine]) -> None:
        """注册更新回调

        Args:
            callback: 回调函数
        """
        self._config_manager.register_update_callback(callback)


# =============================================================================
# 全局单例
# =============================================================================

_config_module: Optional[PrivescConfigModule] = None


def get_config_module() -> PrivescConfigModule:
    """获取配置模块全局单例

    Returns:
        PrivescConfigModule 实例
    """
    global _config_module
    if _config_module is None:
        _config_module = PrivescConfigModule()
    return _config_module


__all__ = [
    "PrivescConfigModule",
    "PrivescConfigManager",
    "HotUpdateDistributor",
    "ConfigStorage",
    "PolicyConfig",
    "BeaconGroup",
    "RuleEntry",
    "KnowledgeEntry",
    "UpdateManifest",
    "ConfigSnapshot",
    "ConfigScope",
    "ConfigKey",
    "get_config_module",
]
