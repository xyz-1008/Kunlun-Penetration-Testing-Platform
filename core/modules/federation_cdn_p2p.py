"""Federation CDN & P2P: CDN acceleration selection, P2P network management, mirror source config.

Provides:
- CDN node selection based on latency measurement
- Custom CDN source configuration
- P2P network management for resource sharing (optional)
- Mirror source configuration and upstream sync
- Download acceleration with fallback mechanisms
"""

import asyncio
import logging
import os
import time
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Set

import aiohttp
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class CDNNodeType(str, Enum):
    """Types of CDN nodes.

    Attributes:
        OFFICIAL: Official CDN node
        CUSTOM: User-configured custom CDN node
        MIRROR: Mirror source acting as CDN
    """
    OFFICIAL = "official"
    CUSTOM = "custom"
    MIRROR = "mirror"


class CDNNode(BaseModel):
    """CDN node configuration and status.

    Attributes:
        node_id: Unique node identifier
        name: Node display name
        url: Node base URL
        node_type: Type of CDN node
        enabled: Whether this node is enabled
        latency_ms: Last measured latency in milliseconds
        last_check: Last health check timestamp
        is_healthy: Whether the node is currently healthy
        priority: Node priority (lower = higher priority)
    """
    node_id: str = Field(..., description="Node identifier")
    name: str = Field(..., description="Display name")
    url: str = Field(..., description="Node URL")
    node_type: CDNNodeType = Field(default=CDNNodeType.OFFICIAL, description="Node type")
    enabled: bool = Field(default=True, description="Whether enabled")
    latency_ms: float = Field(default=9999.0, description="Latency in ms")
    last_check: Optional[str] = Field(default=None, description="Last check time")
    is_healthy: bool = Field(default=False, description="Health status")
    priority: int = Field(default=0, description="Priority")


class P2PStatus(str, Enum):
    """P2P network status.

    Attributes:
        DISABLED: P2P is disabled
        CONNECTING: Connecting to P2P network
        CONNECTED: Connected to P2P network
        SEEDING: Actively seeding resources
        DOWNLOADING: Downloading resources via P2P
    """
    DISABLED = "disabled"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    SEEDING = "seeding"
    DOWNLOADING = "downloading"


class P2PConfig(BaseModel):
    """P2P network configuration.

    Attributes:
        enabled: Whether P2P is enabled
        max_upload_bandwidth: Maximum upload bandwidth in KB/s
        max_download_bandwidth: Maximum download bandwidth in KB/s
        max_connections: Maximum number of P2P connections
        shared_resources: Set of resource IDs being shared
        status: Current P2P status
        peer_count: Number of connected peers
        uploaded_bytes: Total bytes uploaded
        downloaded_bytes: Total bytes downloaded
    """
    enabled: bool = Field(default=False, description="Whether P2P is enabled")
    max_upload_bandwidth: int = Field(default=1024, description="Max upload KB/s")
    max_download_bandwidth: int = Field(default=4096, description="Max download KB/s")
    max_connections: int = Field(default=50, description="Max connections")
    shared_resources: Set[str] = Field(default_factory=set, description="Shared resources")
    status: P2PStatus = Field(default=P2PStatus.DISABLED, description="P2P status")
    peer_count: int = Field(default=0, description="Peer count")
    uploaded_bytes: int = Field(default=0, description="Uploaded bytes")
    downloaded_bytes: int = Field(default=0, description="Downloaded bytes")


class MirrorSource(BaseModel):
    """Mirror source configuration.

    Attributes:
        mirror_id: Unique mirror identifier
        name: Mirror display name
        url: Mirror base URL
        upstream_url: Upstream source URL to sync from
        sync_interval_hours: Hours between upstream syncs
        last_sync: Last successful sync timestamp
        enabled: Whether this mirror is enabled
        is_internal: Whether this is an internal enterprise mirror
    """
    mirror_id: str = Field(..., description="Mirror identifier")
    name: str = Field(..., description="Display name")
    url: str = Field(..., description="Mirror URL")
    upstream_url: str = Field(..., description="Upstream URL")
    sync_interval_hours: float = Field(default=6.0, description="Sync interval")
    last_sync: Optional[str] = Field(default=None, description="Last sync time")
    enabled: bool = Field(default=True, description="Whether enabled")
    is_internal: bool = Field(default=False, description="Internal mirror")


class CDNManager:
    """Manages CDN nodes and download acceleration.

    Provides node health checking, latency measurement,
    and automatic selection of the fastest node.
    """

    def __init__(self) -> None:
        """Initialize CDN manager."""
        self._nodes: Dict[str, CDNNode] = {}
        self._session: Optional[aiohttp.ClientSession] = None
        self._initialize_default_nodes()

    def add_node(
        self,
        name: str,
        url: str,
        node_type: CDNNodeType = CDNNodeType.CUSTOM,
        priority: int = 10,
    ) -> CDNNode:
        """Add a CDN node.

        Args:
            name: Node display name.
            url: Node base URL.
            node_type: Type of CDN node.
            priority: Node priority.

        Returns:
            CDNNode object.
        """
        node_id = f"cdn_{name.lower().replace(' ', '_')}_{int(time.time())}"

        node = CDNNode(
            node_id=node_id,
            name=name,
            url=url,
            node_type=node_type,
            priority=priority,
        )

        self._nodes[node_id] = node

        return node

    def remove_node(self, node_id: str) -> bool:
        """Remove a CDN node.

        Args:
            node_id: Node identifier.

        Returns:
            True if removed, False if not found.
        """
        if node_id in self._nodes:
            del self._nodes[node_id]
            return True
        return False

    def enable_node(self, node_id: str) -> bool:
        """Enable a CDN node.

        Args:
            node_id: Node identifier.

        Returns:
            True if enabled, False if not found.
        """
        node = self._nodes.get(node_id)
        if node:
            node.enabled = True
            return True
        return False

    def disable_node(self, node_id: str) -> bool:
        """Disable a CDN node.

        Args:
            node_id: Node identifier.

        Returns:
            True if disabled, False if not found.
        """
        node = self._nodes.get(node_id)
        if node:
            node.enabled = True
            return True
        return False

    def get_best_node(self) -> Optional[CDNNode]:
        """Get the best CDN node based on latency and priority.

        Returns:
            Best CDNNode or None.
        """
        enabled_nodes = [n for n in self._nodes.values() if n.enabled and n.is_healthy]

        if not enabled_nodes:
            return None

        enabled_nodes.sort(key=lambda n: (n.latency_ms, n.priority))

        return enabled_nodes[0]

    def list_nodes(
        self,
        node_type: Optional[CDNNodeType] = None,
        enabled_only: bool = False,
    ) -> List[CDNNode]:
        """List CDN nodes with optional filters.

        Args:
            node_type: Filter by node type.
            enabled_only: Only return enabled nodes.

        Returns:
            List of CDNNode objects.
        """
        nodes = list(self._nodes.values())

        if node_type is not None:
            nodes = [n for n in nodes if n.node_type == node_type]

        if enabled_only:
            nodes = [n for n in nodes if n.enabled]

        return nodes

    async def check_all_nodes(self) -> Dict[str, bool]:
        """Check health and latency of all CDN nodes.

        Returns:
            Dictionary mapping node IDs to health status.
        """
        results: Dict[str, bool] = {}

        tasks = []
        for node in self._nodes.values():
            if node.enabled:
                tasks.append(self._check_node(node))

        if tasks:
            node_results = await asyncio.gather(*tasks, return_exceptions=True)
            for node, result in zip(
                [n for n in self._nodes.values() if n.enabled],
                node_results,
            ):
                if isinstance(result, bool):
                    results[node.node_id] = result
                else:
                    results[node.node_id] = False

        return results

    async def get_download_url(self, resource_path: str) -> str:
        """Get the optimal download URL for a resource.

        Args:
            resource_path: Resource path relative to CDN root.

        Returns:
            Full download URL.
        """
        best_node = self.get_best_node()

        if best_node:
            base_url = best_node.url.rstrip("/")
            return f"{base_url}/{resource_path.lstrip('/')}"

        return resource_path

    async def _check_node(self, node: CDNNode) -> bool:
        """Check health and measure latency of a CDN node.

        Args:
            node: CDN node to check.

        Returns:
            True if node is healthy.
        """
        url = f"{node.url}/health"

        try:
            if self._session is None:
                self._session = aiohttp.ClientSession(
                    timeout=aiohttp.ClientTimeout(total=5)
                )

            start_time = time.time()

            async with self._session.get(url) as response:
                elapsed = (time.time() - start_time) * 1000

                node.latency_ms = elapsed
                node.is_healthy = response.status == 200
                node.last_check = datetime.now().isoformat()

                return node.is_healthy

        except Exception as e:
            logger.warning(f"CDN node {node.name} check failed: {e}")
            node.is_healthy = False
            node.last_check = datetime.now().isoformat()
            return False

    def _initialize_default_nodes(self) -> None:
        """Initialize default official CDN nodes."""
        default_nodes = [
            CDNNode(
                node_id="cdn_official_cn_east",
                name="官方CDN-华东",
                url="https://cdn-east.kunlun-pentest.com",
                node_type=CDNNodeType.OFFICIAL,
                priority=1,
            ),
            CDNNode(
                node_id="cdn_official_cn_north",
                name="官方CDN-华北",
                url="https://cdn-north.kunlun-pentest.com",
                node_type=CDNNodeType.OFFICIAL,
                priority=2,
            ),
            CDNNode(
                node_id="cdn_official_cn_south",
                name="官方CDN-华南",
                url="https://cdn-south.kunlun-pentest.com",
                node_type=CDNNodeType.OFFICIAL,
                priority=3,
            ),
        ]

        for node in default_nodes:
            self._nodes[node.node_id] = node


class P2PManager:
    """Manages P2P network for resource sharing.

    Provides P2P enable/disable, resource seeding,
    and peer connection management.
    """

    def __init__(self, resource_dir: Optional[str] = None) -> None:
        """Initialize P2P manager.

        Args:
            resource_dir: Directory containing shared resources.
        """
        self.resource_dir = resource_dir or "./federation_downloads"
        self.config = P2PConfig()
        self._peers: Dict[str, Dict[str, Any]] = {}

    def enable_p2p(self) -> None:
        """Enable P2P network participation."""
        self.config.enabled = True
        self.config.status = P2PStatus.CONNECTING

    def disable_p2p(self) -> None:
        """Disable P2P network participation."""
        self.config.enabled = False
        self.config.status = P2PStatus.DISABLED
        self._peers.clear()

    def share_resource(self, resource_id: str) -> None:
        """Add a resource to the P2P shared pool.

        Args:
            resource_id: Resource identifier to share.
        """
        if self.config.enabled:
            self.config.shared_resources.add(resource_id)
            self.config.status = P2PStatus.SEEDING

    def unshare_resource(self, resource_id: str) -> None:
        """Remove a resource from the P2P shared pool.

        Args:
            resource_id: Resource identifier to unshare.
        """
        self.config.shared_resources.discard(resource_id)

        if not self.config.shared_resources:
            self.config.status = P2PStatus.CONNECTED

    def get_shared_resources(self) -> Set[str]:
        """Get the set of shared resource IDs.

        Returns:
            Set of resource IDs.
        """
        return self.config.shared_resources.copy()

    def get_stats(self) -> Dict[str, Any]:
        """Get P2P network statistics.

        Returns:
            Statistics dictionary.
        """
        return {
            "enabled": self.config.enabled,
            "status": self.config.status.value,
            "peer_count": self.config.peer_count,
            "shared_count": len(self.config.shared_resources),
            "uploaded_bytes": self.config.uploaded_bytes,
            "downloaded_bytes": self.config.downloaded_bytes,
            "max_upload_bandwidth": self.config.max_upload_bandwidth,
            "max_download_bandwidth": self.config.max_download_bandwidth,
        }


class MirrorManager:
    """Manages mirror sources for enterprise internal deployment.

    Provides mirror configuration, upstream sync scheduling,
    and mirror health monitoring.
    """

    def __init__(self) -> None:
        """Initialize mirror manager."""
        self._mirrors: Dict[str, MirrorSource] = {}

    def add_mirror(
        self,
        name: str,
        url: str,
        upstream_url: str,
        is_internal: bool = False,
        sync_interval_hours: float = 6.0,
    ) -> MirrorSource:
        """Add a mirror source.

        Args:
            name: Mirror display name.
            url: Mirror base URL.
            upstream_url: Upstream source URL.
            is_internal: Whether this is an internal mirror.
            sync_interval_hours: Hours between upstream syncs.

        Returns:
            MirrorSource object.
        """
        mirror_id = f"mirror_{name.lower().replace(' ', '_')}_{int(time.time())}"

        mirror = MirrorSource(
            mirror_id=mirror_id,
            name=name,
            url=url,
            upstream_url=upstream_url,
            sync_interval_hours=sync_interval_hours,
            is_internal=is_internal,
        )

        self._mirrors[mirror_id] = mirror

        return mirror

    def remove_mirror(self, mirror_id: str) -> bool:
        """Remove a mirror source.

        Args:
            mirror_id: Mirror identifier.

        Returns:
            True if removed, False if not found.
        """
        if mirror_id in self._mirrors:
            del self._mirrors[mirror_id]
            return True
        return False

    def enable_mirror(self, mirror_id: str) -> bool:
        """Enable a mirror source.

        Args:
            mirror_id: Mirror identifier.

        Returns:
            True if enabled, False if not found.
        """
        mirror = self._mirrors.get(mirror_id)
        if mirror:
            mirror.enabled = True
            return True
        return False

    def disable_mirror(self, mirror_id: str) -> bool:
        """Disable a mirror source.

        Args:
            mirror_id: Mirror identifier.

        Returns:
            True if disabled, False if not found.
        """
        mirror = self._mirrors.get(mirror_id)
        if mirror:
            mirror.enabled = False
            return True
        return False

    def list_mirrors(
        self,
        enabled_only: bool = False,
        internal_only: bool = False,
    ) -> List[MirrorSource]:
        """List mirror sources with optional filters.

        Args:
            enabled_only: Only return enabled mirrors.
            internal_only: Only return internal mirrors.

        Returns:
            List of MirrorSource objects.
        """
        mirrors = list(self._mirrors.values())

        if enabled_only:
            mirrors = [m for m in mirrors if m.enabled]

        if internal_only:
            mirrors = [m for m in mirrors if m.is_internal]

        return mirrors

    def get_mirror(self, mirror_id: str) -> Optional[MirrorSource]:
        """Get a mirror source by ID.

        Args:
            mirror_id: Mirror identifier.

        Returns:
            MirrorSource or None.
        """
        return self._mirrors.get(mirror_id)

    def record_sync(self, mirror_id: str) -> None:
        """Record a successful sync for a mirror.

        Args:
            mirror_id: Mirror identifier.
        """
        mirror = self._mirrors.get(mirror_id)
        if mirror:
            mirror.last_sync = datetime.now().isoformat()
