"""Federation Registry: Market source management, trust levels, enable/disable.

Provides:
- Market source model with trust levels (official/community/personal)
- Add/remove/enable/disable market sources
- Built-in official market source (immutable)
- Source discovery directory
- Source metadata and sync strategy configuration
"""

import logging
import os
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class TrustLevel(str, Enum):
    """Trust level for market sources.

    Attributes:
        OFFICIAL: Fully trusted, resources reviewed by official team
        COMMUNITY: Medium trust, community reviewed, user discretion advised
        PERSONAL: Low trust, for personal or small team sharing only
    """
    OFFICIAL = "official"
    COMMUNITY = "community"
    PERSONAL = "personal"


class SyncDirection(str, Enum):
    """Synchronization direction for market sources.

    Attributes:
        PULL_ONLY: One-way pull from source market
        BIDIRECTIONAL: Two-way sync (requires mutual agreement)
    """
    PULL_ONLY = "pull_only"
    BIDIRECTIONAL = "bidirectional"


class SyncStrategy(str, Enum):
    """Synchronization strategy for market sources.

    Attributes:
        SCHEDULED: Automatic sync at regular intervals
        MANUAL: Only sync when manually triggered
        EVENT_DRIVEN: Sync on local resource changes
    """
    SCHEDULED = "scheduled"
    MANUAL = "manual"
    EVENT_DRIVEN = "event_driven"


class MarketSource(BaseModel):
    """Market source configuration.

    Attributes:
        source_id: Unique source identifier
        name: Source display name
        description: Source description
        url: Source base URL
        maintainer: Maintainer name or organization
        trust_level: Trust level of this source
        sync_direction: Synchronization direction
        sync_strategy: Synchronization strategy
        sync_interval_hours: Hours between scheduled syncs
        enabled: Whether this source is enabled
        is_builtin: Whether this is a built-in source (cannot be deleted)
        last_sync_time: Last successful sync timestamp
        resource_count: Number of resources available from this source
        metadata: Additional metadata
    """
    source_id: str = Field(..., description="Unique source identifier")
    name: str = Field(..., description="Source display name")
    description: str = Field(default="", description="Source description")
    url: str = Field(..., description="Source base URL")
    maintainer: str = Field(default="", description="Maintainer name")
    trust_level: TrustLevel = Field(default=TrustLevel.COMMUNITY, description="Trust level")
    sync_direction: SyncDirection = Field(default=SyncDirection.PULL_ONLY, description="Sync direction")
    sync_strategy: SyncStrategy = Field(default=SyncStrategy.SCHEDULED, description="Sync strategy")
    sync_interval_hours: float = Field(default=24.0, description="Sync interval in hours")
    enabled: bool = Field(default=True, description="Whether source is enabled")
    is_builtin: bool = Field(default=False, description="Whether source is built-in")
    last_sync_time: Optional[str] = Field(default=None, description="Last sync timestamp")
    resource_count: int = Field(default=0, description="Resource count")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata")


class SourceDiscoveryEntry(BaseModel):
    """Entry in the source discovery directory.

    Attributes:
        name: Source name
        url: Source URL
        description: Source description
        trust_level: Recommended trust level
        category: Source category (e.g., plugins, poc, templates)
        recommended: Whether this source is recommended by official
    """
    name: str = Field(..., description="Source name")
    url: str = Field(..., description="Source URL")
    description: str = Field(default="", description="Description")
    trust_level: TrustLevel = Field(default=TrustLevel.COMMUNITY, description="Trust level")
    category: str = Field(default="general", description="Source category")
    recommended: bool = Field(default=False, description="Whether recommended")


class FederationRegistry:
    """Manages market sources for the federation protocol.

    Provides source registration, discovery, trust management,
    and configuration persistence.
    """

    def __init__(self, data_dir: Optional[str] = None) -> None:
        """Initialize federation registry.

        Args:
            data_dir: Directory for storing source configurations.
        """
        self.data_dir = data_dir or "./federation_data"
        os.makedirs(self.data_dir, exist_ok=True)

        self._sources: Dict[str, MarketSource] = {}
        self._discovery_entries: List[SourceDiscoveryEntry] = []
        self._trust_policies: Dict[TrustLevel, Dict[str, Any]] = {}

        self._initialize_builtin_sources()
        self._initialize_trust_policies()
        self._load_sources_from_disk()

    def add_source(
        self,
        name: str,
        url: str,
        description: str = "",
        maintainer: str = "",
        trust_level: TrustLevel = TrustLevel.COMMUNITY,
        sync_direction: SyncDirection = SyncDirection.PULL_ONLY,
        sync_strategy: SyncStrategy = SyncStrategy.SCHEDULED,
        sync_interval_hours: float = 24.0,
    ) -> Optional[MarketSource]:
        """Add a new market source.

        Args:
            name: Source display name.
            url: Source base URL.
            description: Source description.
            maintainer: Maintainer name.
            trust_level: Trust level for this source.
            sync_direction: Synchronization direction.
            sync_strategy: Synchronization strategy.
            sync_interval_hours: Hours between scheduled syncs.

        Returns:
            MarketSource if added successfully, None if URL already exists.
        """
        for source in self._sources.values():
            if source.url == url:
                logger.warning(f"Source with URL {url} already exists")
                return None

        source_id = f"source_{name.lower().replace(' ', '_')}_{int(datetime.now().timestamp())}"

        source = MarketSource(
            source_id=source_id,
            name=name,
            description=description,
            url=url,
            maintainer=maintainer,
            trust_level=trust_level,
            sync_direction=sync_direction,
            sync_strategy=sync_strategy,
            sync_interval_hours=sync_interval_hours,
        )

        self._sources[source_id] = source
        self._save_sources_to_disk()

        return source

    def remove_source(self, source_id: str) -> bool:
        """Remove a market source.

        Args:
            source_id: Source identifier.

        Returns:
            True if removed, False if not found or built-in.
        """
        source = self._sources.get(source_id)
        if source is None:
            return False

        if source.is_builtin:
            logger.warning(f"Cannot remove built-in source: {source.name}")
            return False

        del self._sources[source_id]
        self._save_sources_to_disk()

        return True

    def enable_source(self, source_id: str) -> bool:
        """Enable a market source.

        Args:
            source_id: Source identifier.

        Returns:
            True if enabled, False if not found.
        """
        source = self._sources.get(source_id)
        if source is None:
            return False

        source.enabled = True
        self._save_sources_to_disk()

        return True

    def disable_source(self, source_id: str) -> bool:
        """Disable a market source.

        Args:
            source_id: Source identifier.

        Returns:
            True if disabled, False if not found.
        """
        source = self._sources.get(source_id)
        if source is None:
            return False

        source.enabled = False
        self._save_sources_to_disk()

        return True

    def get_source(self, source_id: str) -> Optional[MarketSource]:
        """Get a market source by ID.

        Args:
            source_id: Source identifier.

        Returns:
            MarketSource or None.
        """
        return self._sources.get(source_id)

    def get_source_by_url(self, url: str) -> Optional[MarketSource]:
        """Get a market source by URL.

        Args:
            url: Source URL.

        Returns:
            MarketSource or None.
        """
        for source in self._sources.values():
            if source.url == url:
                return source
        return None

    def list_sources(
        self,
        enabled_only: bool = False,
        trust_level: Optional[TrustLevel] = None,
    ) -> List[MarketSource]:
        """List all market sources with optional filters.

        Args:
            enabled_only: If True, only return enabled sources.
            trust_level: If specified, only return sources with this trust level.

        Returns:
            List of MarketSource objects.
        """
        sources = list(self._sources.values())

        if enabled_only:
            sources = [s for s in sources if s.enabled]

        if trust_level is not None:
            sources = [s for s in sources if s.trust_level == trust_level]

        return sources

    def update_sync_strategy(
        self,
        source_id: str,
        strategy: SyncStrategy,
        interval_hours: Optional[float] = None,
    ) -> bool:
        """Update sync strategy for a market source.

        Args:
            source_id: Source identifier.
            strategy: New sync strategy.
            interval_hours: New sync interval (for scheduled strategy).

        Returns:
            True if updated, False if not found.
        """
        source = self._sources.get(source_id)
        if source is None:
            return False

        source.sync_strategy = strategy

        if interval_hours is not None:
            source.sync_interval_hours = interval_hours

        self._save_sources_to_disk()

        return True

    def update_trust_level(
        self,
        source_id: str,
        trust_level: TrustLevel,
    ) -> bool:
        """Update trust level for a market source.

        Args:
            source_id: Source identifier.
            trust_level: New trust level.

        Returns:
            True if updated, False if not found or built-in.
        """
        source = self._sources.get(source_id)
        if source is None:
            return False

        if source.is_builtin:
            logger.warning(f"Cannot change trust level for built-in source: {source.name}")
            return False

        source.trust_level = trust_level
        self._save_sources_to_disk()

        return True

    def record_sync(self, source_id: str, resource_count: int = 0) -> None:
        """Record a successful sync for a market source.

        Args:
            source_id: Source identifier.
            resource_count: Number of resources synced.
        """
        source = self._sources.get(source_id)
        if source:
            source.last_sync_time = datetime.now().isoformat()
            source.resource_count = resource_count
            self._save_sources_to_disk()

    def get_discovery_entries(
        self,
        category: Optional[str] = None,
        recommended_only: bool = False,
    ) -> List[SourceDiscoveryEntry]:
        """Get source discovery directory entries.

        Args:
            category: Filter by category.
            recommended_only: If True, only return recommended entries.

        Returns:
            List of discovery entries.
        """
        entries = self._discovery_entries

        if category:
            entries = [e for e in entries if e.category == category]

        if recommended_only:
            entries = [e for e in entries if e.recommended]

        return entries

    def add_discovery_entry(self, entry: SourceDiscoveryEntry) -> None:
        """Add a discovery directory entry.

        Args:
            entry: Discovery entry to add.
        """
        self._discovery_entries.append(entry)

    def get_trust_policy(self, trust_level: TrustLevel) -> Dict[str, Any]:
        """Get trust policy for a trust level.

        Args:
            trust_level: Trust level.

        Returns:
            Policy dictionary with allowed operations.
        """
        return self._trust_policies.get(trust_level, {})

    def set_trust_policy(
        self,
        trust_level: TrustLevel,
        policy: Dict[str, Any],
    ) -> None:
        """Set trust policy for a trust level.

        Args:
            trust_level: Trust level.
            policy: Policy dictionary.
        """
        self._trust_policies[trust_level] = policy

    def _initialize_builtin_sources(self) -> None:
        """Initialize built-in official market source."""
        official_source = MarketSource(
            source_id="official_kunlun_market",
            name="昆仑官方市场",
            description="Kunlun official marketplace with verified resources",
            url="https://market.kunlun-pentest.com/api/v1",
            maintainer="Kunlun Team",
            trust_level=TrustLevel.OFFICIAL,
            sync_direction=SyncDirection.PULL_ONLY,
            sync_strategy=SyncStrategy.SCHEDULED,
            sync_interval_hours=12.0,
            enabled=True,
            is_builtin=True,
        )

        self._sources[official_source.source_id] = official_source

    def _initialize_trust_policies(self) -> None:
        """Initialize default trust policies."""
        self._trust_policies[TrustLevel.OFFICIAL] = {
            "auto_install": True,
            "sandbox_required": False,
            "signature_verify": True,
            "max_risk_score": 100,
        }

        self._trust_policies[TrustLevel.COMMUNITY] = {
            "auto_install": False,
            "sandbox_required": True,
            "signature_verify": True,
            "max_risk_score": 50,
        }

        self._trust_policies[TrustLevel.PERSONAL] = {
            "auto_install": False,
            "sandbox_required": True,
            "signature_verify": True,
            "max_risk_score": 20,
        }

    def _save_sources_to_disk(self) -> None:
        """Save sources configuration to disk."""
        import json

        file_path = os.path.join(self.data_dir, "sources.json")

        try:
            data = {
                "sources": {
                    sid: s.model_dump() for sid, s in self._sources.items()
                },
                "discovery_entries": [e.model_dump() for e in self._discovery_entries],
                "trust_policies": {
                    k.value: v for k, v in self._trust_policies.items()
                },
            }

            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)

        except Exception as e:
            logger.error(f"Failed to save sources: {e}")

    def _load_sources_from_disk(self) -> None:
        """Load sources configuration from disk."""
        import json

        file_path = os.path.join(self.data_dir, "sources.json")

        if not os.path.exists(file_path):
            return

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            for sid, s_data in data.get("sources", {}).items():
                if s_data.get("is_builtin"):
                    continue

                source = MarketSource(**s_data)
                self._sources[sid] = source

            for e_data in data.get("discovery_entries", []):
                entry = SourceDiscoveryEntry(**e_data)
                self._discovery_entries.append(entry)

            for k, v in data.get("trust_policies", {}).items():
                try:
                    trust_level = TrustLevel(k)
                    self._trust_policies[trust_level] = v
                except ValueError:
                    pass

        except Exception as e:
            logger.error(f"Failed to load sources: {e}")
