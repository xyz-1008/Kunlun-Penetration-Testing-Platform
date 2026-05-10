"""Gadget chain manager for Java deserialization exploitation.

Provides:
- Load and manage 30+ built-in gadget chain configurations
- Automatic chain discovery and matching
- Chain editor for custom chain creation
- Plugin market integration for community chains
"""

import asyncio
import logging
import os
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Coroutine, Dict, List, Optional, Tuple

import yaml  # type: ignore[import-untyped]

logger = logging.getLogger(__name__)


class PayloadType(Enum):
    """Payload execution types."""
    COMMAND_EXECUTION = "command_execution"
    JNDI_INJECTION = "jndi_injection"
    FILE_WRITE = "file_write"
    MEMORY_SHELL = "memory_shell"
    DNS_OOB = "dns_oob"


class GadgetCategory(Enum):
    """Gadget chain categories."""
    COMMONS_COLLECTIONS = "commons_collections"
    COMMONS_BEANUTILS = "commons_beanutils"
    JDK = "jdk"
    SPRING = "spring"
    HIBERNATE = "hibernate"
    ROME = "rome"
    C3P0 = "c3p0"
    ASPECTJ = "aspectj"
    FASTJSON = "fastjson"
    JACKSON = "jackson"


class JdkVersion(Enum):
    """JDK version ranges."""
    JDK7 = "jdk7"
    JDK8 = "jdk8"
    JDK8U20 = "jdk8u20"
    JDK8U71 = "jdk8u71"
    JDK8U102 = "jdk8u102"
    JDK8U242 = "jdk8u242"
    JDK11 = "jdk11"
    JDK17 = "jdk17"
    ALL = "all"


@dataclass
class GadgetStep:
    """Single step in a gadget chain.

    Attributes:
        step_name: Step identifier
        class_name: Java class name
        method_name: Method to invoke
        parameters: Method parameters
        description: Step description
    """
    step_name: str = ""
    class_name: str = ""
    method_name: str = ""
    parameters: List[str] = field(default_factory=list)
    description: str = ""


@dataclass
class GadgetChain:
    """Gadget chain configuration.

    Attributes:
        chain_id: Unique chain identifier
        name: Chain display name
        category: Gadget category
        payload_type: Payload execution type
        jdk_versions: Compatible JDK versions
        dependencies: Required library dependencies
        exploit_method: How the chain is exploited
        steps: Chain execution steps
        description: Chain description
        risk_level: Risk level (1-5)
        success_rate: Historical success rate
        mitre_technique: MITRE ATT&CK technique ID
        author: Chain author
        created_at: Creation timestamp
        updated_at: Last update timestamp
        is_builtin: Whether chain is built-in
        is_custom: Whether chain is user custom
    """
    chain_id: str = ""
    name: str = ""
    category: GadgetCategory = GadgetCategory.COMMONS_COLLECTIONS
    payload_type: PayloadType = PayloadType.COMMAND_EXECUTION
    jdk_versions: List[JdkVersion] = field(default_factory=list)
    dependencies: List[Dict[str, str]] = field(default_factory=list)
    exploit_method: str = ""
    steps: List[GadgetStep] = field(default_factory=list)
    description: str = ""
    risk_level: int = 3
    success_rate: float = 0.0
    mitre_technique: str = "T1566.001"
    author: str = ""
    created_at: float = 0.0
    updated_at: float = 0.0
    is_builtin: bool = True
    is_custom: bool = False

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "chain_id": self.chain_id,
            "name": self.name,
            "category": self.category.value,
            "payload_type": self.payload_type.value,
            "jdk_versions": [v.value for v in self.jdk_versions],
            "dependencies": self.dependencies,
            "exploit_method": self.exploit_method,
            "steps": [
                {
                    "step_name": s.step_name,
                    "class_name": s.class_name,
                    "method_name": s.method_name,
                    "parameters": s.parameters,
                    "description": s.description,
                }
                for s in self.steps
            ],
            "description": self.description,
            "risk_level": self.risk_level,
            "success_rate": self.success_rate,
            "mitre_technique": self.mitre_technique,
            "author": self.author,
            "is_builtin": self.is_builtin,
            "is_custom": self.is_custom,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "GadgetChain":
        """Create GadgetChain from dictionary.

        Args:
            data: Dictionary with chain configuration.

        Returns:
            GadgetChain instance.
        """
        jdk_versions = []
        for v in data.get("jdk_versions", []):
            try:
                jdk_versions.append(JdkVersion(v))
            except ValueError:
                pass

        steps = []
        for s in data.get("steps", []):
            steps.append(
                GadgetStep(
                    step_name=s.get("step_name", ""),
                    class_name=s.get("class_name", ""),
                    method_name=s.get("method_name", ""),
                    parameters=s.get("parameters", []),
                    description=s.get("description", ""),
                )
            )

        try:
            category = GadgetCategory(data.get("category", "commons_collections"))
        except ValueError:
            category = GadgetCategory.COMMONS_COLLECTIONS

        try:
            payload_type = PayloadType(data.get("payload_type", "command_execution"))
        except ValueError:
            payload_type = PayloadType.COMMAND_EXECUTION

        return cls(
            chain_id=data.get("chain_id", ""),
            name=data.get("name", ""),
            category=category,
            payload_type=payload_type,
            jdk_versions=jdk_versions,
            dependencies=data.get("dependencies", []),
            exploit_method=data.get("exploit_method", ""),
            steps=steps,
            description=data.get("description", ""),
            risk_level=data.get("risk_level", 3),
            success_rate=data.get("success_rate", 0.0),
            mitre_technique=data.get("mitre_technique", "T1566.001"),
            author=data.get("author", ""),
            created_at=data.get("created_at", 0.0),
            updated_at=data.get("updated_at", 0.0),
            is_builtin=data.get("is_builtin", True),
            is_custom=data.get("is_custom", False),
        )


@dataclass
class ChainMatchResult:
    """Result of chain matching.

    Attributes:
        chain: Matched gadget chain
        match_score: Match confidence score (0-100)
        match_reasons: Reasons for match
        recommended: Whether chain is recommended
    """
    chain: GadgetChain
    match_score: float = 0.0
    match_reasons: List[str] = field(default_factory=list)
    recommended: bool = False


class GadgetChainManager:
    """Gadget chain manager for Java deserialization.

    Provides chain loading, matching, recommendation, and editing
    capabilities for Java deserialization exploitation.
    """

    BUILTIN_CHAINS_DIR = "gadget_chains"

    def __init__(
        self,
        chains_dir: Optional[str] = None,
        plugin_market: Optional[Any] = None,
        event_bus: Optional[Any] = None,
    ) -> None:
        """Initialize gadget chain manager.

        Args:
            chains_dir: Directory containing chain YAML configs.
            plugin_market: Plugin market for downloading chains.
            event_bus: Event bus for broadcasting events.
        """
        self.chains_dir = chains_dir or os.path.join(
            os.path.dirname(__file__), self.BUILTIN_CHAINS_DIR
        )
        self.plugin_market = plugin_market
        self.event_bus = event_bus
        self._chains: Dict[str, GadgetChain] = {}
        self._custom_chains: Dict[str, GadgetChain] = {}
        self._progress_callback: Optional[Callable[[str, float], Coroutine[Any, Any, None]]] = None
        self._log_callback: Optional[Callable[[str], Coroutine[Any, Any, None]]] = None

    def set_callbacks(
        self,
        progress_cb: Optional[Callable[[str, float], Coroutine[Any, Any, None]]] = None,
        log_cb: Optional[Callable[[str], Coroutine[Any, Any, None]]] = None,
    ) -> None:
        """Set progress and log callbacks.

        Args:
            progress_cb: Callback for progress updates (message, percentage).
            log_cb: Callback for log messages.
        """
        self._progress_callback = progress_cb
        self._log_callback = log_cb

    async def _report_progress(self, message: str, percentage: float) -> None:
        """Report progress via callback.

        Args:
            message: Progress message.
            percentage: Progress percentage (0-100).
        """
        if self._progress_callback:
            await self._progress_callback(message, percentage)
        logger.info("GadgetChain Progress: %.1f%% - %s", percentage, message)

    async def _report_log(self, message: str) -> None:
        """Report log via callback.

        Args:
            message: Log message.
        """
        if self._log_callback:
            await self._log_callback(message)
        logger.info("GadgetChain: %s", message)

    async def load_builtin_chains(self) -> int:
        """Load built-in gadget chains from YAML configs.

        Returns:
            Number of chains loaded.
        """
        count = 0

        try:
            await self._report_progress("加载内置Gadget链", 10)
            await self._report_log("开始加载内置Gadget链配置...")

            chains_path = Path(self.chains_dir)
            if not chains_path.exists():
                chains_path.mkdir(parents=True, exist_ok=True)
                await self._report_log("创建Gadget链配置目录")
                return 0

            yaml_files = list(chains_path.glob("*.yaml")) + list(chains_path.glob("*.yml"))

            for yaml_file in yaml_files:
                try:
                    chain = await self._load_chain_from_yaml(yaml_file)
                    if chain:
                        self._chains[chain.chain_id] = chain
                        count += 1
                except Exception as e:
                    logger.error("Failed to load chain %s: %s", yaml_file, e)

            await self._report_progress("完成", 100)
            await self._report_log(f"内置Gadget链加载完成: {count} 条")

        except Exception as e:
            await self._report_log(f"内置Gadget链加载失败: {e}")
            logger.error("Builtin chains loading failed: %s", e)

        return count

    async def _load_chain_from_yaml(self, yaml_path: Path) -> Optional[GadgetChain]:
        """Load a single chain from YAML file.

        Args:
            yaml_path: Path to YAML file.

        Returns:
            GadgetChain instance or None.
        """
        try:
            with open(yaml_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)

            if not data:
                return None

            chain = GadgetChain.from_dict(data)
            chain.is_builtin = True
            chain.created_at = chain.created_at or time.time()
            chain.updated_at = chain.updated_at or time.time()

            return chain

        except Exception as e:
            logger.error("YAML chain loading failed %s: %s", yaml_path, e)
            return None

    async def load_custom_chains(self) -> int:
        """Load custom chains from user directory.

        Returns:
            Number of custom chains loaded.
        """
        count = 0

        try:
            custom_dir = Path(self.chains_dir) / "custom"
            if not custom_dir.exists():
                return 0

            yaml_files = list(custom_dir.glob("*.yaml")) + list(custom_dir.glob("*.yml"))

            for yaml_file in yaml_files:
                try:
                    chain = await self._load_chain_from_yaml(yaml_file)
                    if chain:
                        chain.is_custom = True
                        self._custom_chains[chain.chain_id] = chain
                        count += 1
                except Exception as e:
                    logger.error("Failed to load custom chain %s: %s", yaml_file, e)

            await self._report_log(f"自定义Gadget链加载完成: {count} 条")

        except Exception as e:
            await self._report_log(f"自定义Gadget链加载失败: {e}")
            logger.error("Custom chains loading failed: %s", e)

        return count

    def get_chain(self, chain_id: str) -> Optional[GadgetChain]:
        """Get chain by ID.

        Args:
            chain_id: Chain identifier.

        Returns:
            GadgetChain or None.
        """
        return self._chains.get(chain_id) or self._custom_chains.get(chain_id)

    def get_all_chains(self) -> List[GadgetChain]:
        """Get all loaded chains.

        Returns:
            List of all GadgetChain instances.
        """
        return list(self._chains.values()) + list(self._custom_chains.values())

    def get_chains_by_category(self, category: GadgetCategory) -> List[GadgetChain]:
        """Get chains by category.

        Args:
            category: Gadget category.

        Returns:
            List of matching chains.
        """
        return [
            c for c in self.get_all_chains() if c.category == category
        ]

    def get_chains_by_payload_type(self, payload_type: PayloadType) -> List[GadgetChain]:
        """Get chains by payload type.

        Args:
            payload_type: Payload type.

        Returns:
            List of matching chains.
        """
        return [
            c for c in self.get_all_chains() if c.payload_type == payload_type
        ]

    def search_chains(self, query: str) -> List[GadgetChain]:
        """Search chains by name or description.

        Args:
            query: Search query string.

        Returns:
            List of matching chains.
        """
        query_lower = query.lower()
        results: List[GadgetChain] = []

        for chain in self.get_all_chains():
            if (
                query_lower in chain.name.lower()
                or query_lower in chain.description.lower()
                or query_lower in chain.category.value.lower()
            ):
                results.append(chain)

        return results

    async def match_chains(
        self,
        target_info: Optional[Dict[str, Any]] = None,
        detected_deps: Optional[List[Dict[str, str]]] = None,
        jdk_version: Optional[str] = None,
    ) -> List[ChainMatchResult]:
        """Match and recommend chains for target.

        Args:
            target_info: Target information dictionary.
            detected_deps: Detected dependencies.
            jdk_version: Target JDK version.

        Returns:
            List of ChainMatchResult sorted by score.
        """
        results: List[ChainMatchResult] = []

        try:
            await self._report_progress("匹配Gadget链", 10)
            await self._report_log("开始匹配推荐Gadget链...")

            all_chains = self.get_all_chains()

            for chain in all_chains:
                score = 0.0
                reasons: List[str] = []

                if detected_deps:
                    for dep in detected_deps:
                        for chain_dep in chain.dependencies:
                            if (
                                dep.get("name", "").lower()
                                == chain_dep.get("name", "").lower()
                            ):
                                score += 30.0
                                reasons.append(
                                    f"依赖匹配: {dep.get('name')}"
                                )

                if jdk_version:
                    target_jdk = self._parse_jdk_version(jdk_version)
                    if target_jdk in chain.jdk_versions:
                        score += 25.0
                        reasons.append(f"JDK版本匹配: {jdk_version}")
                    elif JdkVersion.ALL in chain.jdk_versions:
                        score += 15.0
                        reasons.append("JDK版本兼容(ALL)")

                if chain.success_rate > 0:
                    score += chain.success_rate * 20.0

                if score > 0:
                    result = ChainMatchResult(
                        chain=chain,
                        match_score=min(score, 100.0),
                        match_reasons=reasons,
                        recommended=score >= 50.0,
                    )
                    results.append(result)

            results.sort(key=lambda r: r.match_score, reverse=True)

            await self._report_log(f"匹配完成: 推荐 {len([r for r in results if r.recommended])} 条链")

        except Exception as e:
            await self._report_log(f"链匹配失败: {e}")
            logger.error("Chain matching failed: %s", e)

        return results

    def _parse_jdk_version(self, version_str: str) -> Optional[JdkVersion]:
        """Parse JDK version string to enum.

        Args:
            version_str: JDK version string.

        Returns:
            JdkVersion enum or None.
        """
        version_lower = version_str.lower()

        if "1.7" in version_lower or "jdk7" in version_lower:
            return JdkVersion.JDK7
        if "1.8" in version_lower or "jdk8" in version_lower:
            if "u20" in version_lower:
                return JdkVersion.JDK8U20
            if "u71" in version_lower:
                return JdkVersion.JDK8U71
            if "u102" in version_lower:
                return JdkVersion.JDK8U102
            if "u242" in version_lower:
                return JdkVersion.JDK8U242
            return JdkVersion.JDK8
        if "11" in version_lower:
            return JdkVersion.JDK11
        if "17" in version_lower:
            return JdkVersion.JDK17

        return None

    async def create_custom_chain(self, chain_data: Dict[str, Any]) -> Optional[GadgetChain]:
        """Create a custom gadget chain.

        Args:
            chain_data: Chain configuration data.

        Returns:
            Created GadgetChain or None.
        """
        try:
            chain = GadgetChain.from_dict(chain_data)
            chain.chain_id = chain.chain_id or f"custom_{int(time.time())}"
            chain.is_custom = True
            chain.is_builtin = False
            chain.created_at = time.time()
            chain.updated_at = time.time()

            self._custom_chains[chain.chain_id] = chain

            await self._save_custom_chain(chain)
            await self._report_log(f"自定义链创建成功: {chain.name}")

            return chain

        except Exception as e:
            await self._report_log(f"自定义链创建失败: {e}")
            logger.error("Custom chain creation failed: %s", e)
            return None

    async def update_chain(self, chain_id: str, updates: Dict[str, Any]) -> bool:
        """Update an existing chain.

        Args:
            chain_id: Chain identifier.
            updates: Fields to update.

        Returns:
            True if update successful.
        """
        try:
            chain = self.get_chain(chain_id)
            if not chain:
                return False

            for key, value in updates.items():
                if hasattr(chain, key):
                    setattr(chain, key, value)

            chain.updated_at = time.time()

            if chain.is_custom:
                await self._save_custom_chain(chain)

            await self._report_log(f"链更新成功: {chain.name}")
            return True

        except Exception as e:
            await self._report_log(f"链更新失败: {e}")
            logger.error("Chain update failed: %s", e)
            return False

    async def delete_chain(self, chain_id: str) -> bool:
        """Delete a custom chain.

        Args:
            chain_id: Chain identifier.

        Returns:
            True if deletion successful.
        """
        try:
            if chain_id in self._custom_chains:
                del self._custom_chains[chain_id]

                custom_dir = Path(self.chains_dir) / "custom"
                yaml_path = custom_dir / f"{chain_id}.yaml"
                if yaml_path.exists():
                    yaml_path.unlink()

                await self._report_log(f"自定义链删除成功: {chain_id}")
                return True

            return False

        except Exception as e:
            await self._report_log(f"链删除失败: {e}")
            logger.error("Chain deletion failed: %s", e)
            return False

    async def _save_custom_chain(self, chain: GadgetChain) -> bool:
        """Save custom chain to YAML file.

        Args:
            chain: GadgetChain to save.

        Returns:
            True if save successful.
        """
        try:
            custom_dir = Path(self.chains_dir) / "custom"
            custom_dir.mkdir(parents=True, exist_ok=True)

            yaml_path = custom_dir / f"{chain.chain_id}.yaml"

            with open(yaml_path, "w", encoding="utf-8") as f:
                yaml.dump(chain.to_dict(), f, default_flow_style=False, allow_unicode=True)

            return True

        except Exception as e:
            logger.error("Custom chain save failed: %s", e)
            return False

    async def download_chain_from_market(self, chain_id: str) -> bool:
        """Download chain from plugin market.

        Args:
            chain_id: Chain identifier.

        Returns:
            True if download successful.
        """
        try:
            if not self.plugin_market:
                await self._report_log("插件市场未配置")
                return False

            chain_data = await self.plugin_market.download_gadget_chain(chain_id)
            if chain_data:
                chain = await self.create_custom_chain(chain_data)
                return chain is not None

            return False

        except Exception as e:
            await self._report_log(f"链下载失败: {e}")
            logger.error("Chain download failed: %s", e)
            return False

    async def upload_chain_to_market(self, chain_id: str) -> bool:
        """Upload custom chain to plugin market.

        Args:
            chain_id: Chain identifier.

        Returns:
            True if upload successful.
        """
        try:
            chain = self.get_chain(chain_id)
            if not chain or not chain.is_custom:
                return False

            if not self.plugin_market:
                return False

            result = await self.plugin_market.upload_gadget_chain(chain.to_dict())
            return bool(result)

        except Exception as e:
            logger.error("Chain upload failed: %s", e)
            return False

    def get_chain_statistics(self) -> Dict[str, Any]:
        """Get chain loading statistics.

        Returns:
            Dictionary with statistics.
        """
        all_chains = self.get_all_chains()
        categories: Dict[str, int] = {}

        for chain in all_chains:
            cat = chain.category.value
            categories[cat] = categories.get(cat, 0) + 1

        return {
            "total_chains": len(all_chains),
            "builtin_chains": len(self._chains),
            "custom_chains": len(self._custom_chains),
            "categories": categories,
        }
