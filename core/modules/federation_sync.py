"""Federation Sync: Scheduled/manual sync engine, conflict resolution, on-demand download.

Provides:
- Scheduled synchronization engine with configurable intervals
- Manual sync trigger for specific sources
- Conflict resolution based on trust level and version
- On-demand resource package download
- Sync progress tracking and reporting
"""

import asyncio
import logging
import os
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Coroutine, Dict, List, Optional, Set, Tuple

from pydantic import BaseModel, Field

from .federation_protocol import (
    FederationProtocol,
    ResourceEntity,
    ResourceMetadata,
    ResourceType,
    SyncResponse,
)
from .federation_registry import (
    FederationRegistry,
    MarketSource,
    SyncStrategy,
    TrustLevel,
)

logger = logging.getLogger(__name__)


class SyncStatus(str, Enum):
    """Status of a synchronization operation.

    Attributes:
        IDLE: No sync in progress
        RUNNING: Sync currently running
        COMPLETED: Last sync completed successfully
        FAILED: Last sync failed
        CONFLICT: Sync completed with conflicts
    """
    IDLE = "idle"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CONFLICT = "conflict"


class SyncProgress(BaseModel):
    """Progress information for a sync operation.

    Attributes:
        source_id: Source being synced
        status: Current sync status
        total_resources: Total resources to sync
        synced_resources: Number of resources synced
        current_resource: Currently syncing resource ID
        error_message: Error message if failed
        started_at: Sync start timestamp
        completed_at: Sync completion timestamp
    """
    source_id: str = Field(..., description="Source ID")
    status: SyncStatus = Field(default=SyncStatus.IDLE, description="Status")
    total_resources: int = Field(default=0, description="Total resources")
    synced_resources: int = Field(default=0, description="Synced count")
    current_resource: str = Field(default="", description="Current resource")
    error_message: str = Field(default="", description="Error message")
    started_at: Optional[str] = Field(default=None, description="Start time")
    completed_at: Optional[str] = Field(default=None, description="Completion time")


class ConflictInfo(BaseModel):
    """Information about a resource conflict.

    Attributes:
        resource_id: Conflicting resource ID
        local_version: Local resource version
        remote_version: Remote resource version
        local_source_id: Local resource source ID
        remote_source_id: Remote resource source ID
        resolution: How the conflict was resolved
    """
    resource_id: str = Field(..., description="Resource ID")
    local_version: str = Field(..., description="Local version")
    remote_version: str = Field(..., description="Remote version")
    local_source_id: str = Field(default="", description="Local source")
    remote_source_id: str = Field(default="", description="Remote source")
    resolution: str = Field(default="", description="Resolution")


class FederationSyncEngine:
    """Manages synchronization between local resources and market sources.

    Provides scheduled sync, manual sync, conflict resolution,
    and on-demand resource downloading.
    """

    def __init__(
        self,
        registry: FederationRegistry,
        protocol: Optional[FederationProtocol] = None,
        download_dir: Optional[str] = None,
    ) -> None:
        """Initialize sync engine.

        Args:
            registry: Federation registry with source configurations.
            protocol: Federation protocol client.
            download_dir: Directory for downloaded resource packages.
        """
        self.registry = registry
        self.protocol = protocol or FederationProtocol()
        self.download_dir = download_dir or "./federation_downloads"
        os.makedirs(self.download_dir, exist_ok=True)

        self._local_resources: Dict[str, ResourceMetadata] = {}
        self._sync_progress: Dict[str, SyncProgress] = {}
        self._conflicts: List[ConflictInfo] = []
        self._blacklisted_ids: Set[str] = set()
        self._running = False
        self._sync_tasks: Dict[str, asyncio.Task[None]] = {}
        self._progress_callbacks: List[Callable[[SyncProgress], Coroutine[Any, Any, None]]] = []

    async def start_scheduled_sync(self) -> None:
        """Start scheduled synchronization for all enabled sources."""
        if self._running:
            return

        self._running = True

        while self._running:
            sources = self.registry.list_sources(enabled_only=True)

            for source in sources:
                if source.sync_strategy == SyncStrategy.SCHEDULED:
                    await self._check_and_sync_source(source)

            await asyncio.sleep(60)

    async def stop_scheduled_sync(self) -> None:
        """Stop scheduled synchronization."""
        self._running = False

        for task in self._sync_tasks.values():
            task.cancel()

        self._sync_tasks.clear()

    async def sync_source(
        self,
        source_id: str,
        resource_types: Optional[List[ResourceType]] = None,
    ) -> SyncProgress:
        """Manually sync a specific market source.

        Args:
            source_id: Source identifier to sync.
            resource_types: Types of resources to sync.

        Returns:
            SyncProgress with sync results.
        """
        source = self.registry.get_source(source_id)
        if source is None:
            return SyncProgress(
                source_id=source_id,
                status=SyncStatus.FAILED,
                error_message="Source not found",
            )

        if not source.enabled:
            return SyncProgress(
                source_id=source_id,
                status=SyncStatus.FAILED,
                error_message="Source is disabled",
            )

        progress = SyncProgress(
            source_id=source_id,
            status=SyncStatus.RUNNING,
            started_at=datetime.now().isoformat(),
        )

        self._sync_progress[source_id] = progress
        await self._notify_progress(progress)

        try:
            last_sync = source.last_sync_time
            is_incremental = last_sync is not None

            if is_incremental:
                response = await self.protocol.incremental_sync(
                    source, last_sync, resource_types
                )
            else:
                response = await self.protocol.full_sync(source, resource_types)

            progress.total_resources = response.total_count
            await self._notify_progress(progress)

            await self._process_sync_response(source, response, progress)

            progress.status = SyncStatus.COMPLETED
            progress.completed_at = datetime.now().isoformat()

            self.registry.record_sync(source_id, progress.synced_resources)

        except Exception as e:
            progress.status = SyncStatus.FAILED
            progress.error_message = str(e)
            progress.completed_at = datetime.now().isoformat()
            logger.error(f"Sync failed for {source.name}: {e}")

        await self._notify_progress(progress)

        return progress

    async def download_resource(
        self,
        source: MarketSource,
        resource_id: str,
        version: str,
        output_path: Optional[str] = None,
    ) -> Optional[str]:
        """Download a resource package on demand.

        Args:
            source: Market source to download from.
            resource_id: Resource identifier.
            version: Resource version.
            output_path: Custom output path (None for default).

        Returns:
            Local file path if download succeeded, None otherwise.
        """
        if resource_id in self._blacklisted_ids:
            logger.warning(f"Resource {resource_id} is blacklisted, skipping download")
            return None

        entity = await self.protocol.fetch_resource_entity(source, resource_id, version)
        if entity is None:
            return None

        if output_path is None:
            output_path = os.path.join(
                self.download_dir,
                f"{resource_id}_{version}.zip",
            )

        success = await self.protocol.download_resource_package(entity, output_path)

        if success:
            return output_path
        else:
            return None

    def get_sync_progress(self, source_id: str) -> Optional[SyncProgress]:
        """Get sync progress for a source.

        Args:
            source_id: Source identifier.

        Returns:
            SyncProgress or None.
        """
        return self._sync_progress.get(source_id)

    def get_conflicts(self) -> List[ConflictInfo]:
        """Get list of unresolved conflicts.

        Returns:
            List of ConflictInfo objects.
        """
        return self._conflicts

    def resolve_conflict(
        self,
        resource_id: str,
        use_version: str,
        use_source_id: str,
    ) -> bool:
        """Manually resolve a conflict by selecting which version to use.

        Args:
            resource_id: Resource identifier.
            use_version: Version to keep.
            use_source_id: Source ID to keep.

        Returns:
            True if conflict was resolved.
        """
        for i, conflict in enumerate(self._conflicts):
            if conflict.resource_id == resource_id:
                conflict.resolution = f"Selected version {use_version} from {use_source_id}"
                self._conflicts.pop(i)
                return True

        return False

    def register_progress_callback(
        self,
        callback: Callable[[SyncProgress], Coroutine[Any, Any, None]],
    ) -> None:
        """Register a callback for sync progress updates.

        Args:
            callback: Async callback function.
        """
        self._progress_callbacks.append(callback)

    def add_local_resource(self, resource: ResourceMetadata) -> None:
        """Add a resource to the local resource index.

        Args:
            resource: Resource metadata.
        """
        self._local_resources[resource.resource_id] = resource

    def remove_local_resource(self, resource_id: str) -> None:
        """Remove a resource from the local resource index.

        Args:
            resource_id: Resource identifier.
        """
        self._local_resources.pop(resource_id, None)

    def get_local_resource(self, resource_id: str) -> Optional[ResourceMetadata]:
        """Get a local resource by ID.

        Args:
            resource_id: Resource identifier.

        Returns:
            ResourceMetadata or None.
        """
        return self._local_resources.get(resource_id)

    def list_local_resources(
        self,
        resource_type: Optional[ResourceType] = None,
    ) -> List[ResourceMetadata]:
        """List local resources with optional type filter.

        Args:
            resource_type: Filter by resource type.

        Returns:
            List of ResourceMetadata objects.
        """
        resources = list(self._local_resources.values())

        if resource_type is not None:
            resources = [r for r in resources if r.resource_type == resource_type]

        return resources

    async def _check_and_sync_source(self, source: MarketSource) -> None:
        """Check if a source needs sync and perform it if needed.

        Args:
            source: Market source to check.
        """
        if source.last_sync_time is None:
            await self.sync_source(source.source_id)
            return

        try:
            last_sync = datetime.fromisoformat(source.last_sync_time)
            elapsed = (datetime.now() - last_sync).total_seconds()
            interval = source.sync_interval_hours * 3600

            if elapsed >= interval:
                await self.sync_source(source.source_id)

        except Exception as e:
            logger.error(f"Sync check error for {source.name}: {e}")

    async def _process_sync_response(
        self,
        source: MarketSource,
        response: SyncResponse,
        progress: SyncProgress,
    ) -> None:
        """Process sync response and update local resources.

        Args:
            source: Market source.
            response: Sync response data.
            progress: Current sync progress.
        """
        for resource in response.resources:
            resource.source_id = source.source_id
            progress.current_resource = resource.resource_id
            progress.synced_resources += 1

            await self._notify_progress(progress)

            if resource.is_deleted:
                self.remove_local_resource(resource.resource_id)
                continue

            if resource.resource_id in self._blacklisted_ids:
                continue

            if resource.resource_id in self._local_resources:
                await self._handle_conflict(source, resource)
            else:
                self._local_resources[resource.resource_id] = resource

    async def _handle_conflict(
        self,
        source: MarketSource,
        remote_resource: ResourceMetadata,
    ) -> None:
        """Handle a resource conflict between local and remote versions.

        Args:
            source: Market source of the remote resource.
            remote_resource: Remote resource metadata.
        """
        local_resource = self._local_resources.get(remote_resource.resource_id)
        if local_resource is None:
            return

        local_source = self.registry.get_source(local_resource.source_id)
        local_trust = local_source.trust_level if local_source else TrustLevel.PERSONAL
        remote_trust = source.trust_level

        if remote_trust.value > local_trust.value:
            self._local_resources[remote_resource.resource_id] = remote_resource
        elif remote_trust.value == local_trust.value:
            if self._compare_versions(remote_resource.version, local_resource.version) > 0:
                self._local_resources[remote_resource.resource_id] = remote_resource
            else:
                conflict = ConflictInfo(
                    resource_id=remote_resource.resource_id,
                    local_version=local_resource.version,
                    remote_version=remote_resource.version,
                    local_source_id=local_resource.source_id,
                    remote_source_id=source.source_id,
                    resolution="Kept local version (same trust, older version)",
                )
                self._conflicts.append(conflict)
        else:
            conflict = ConflictInfo(
                resource_id=remote_resource.resource_id,
                local_version=local_resource.version,
                remote_version=remote_resource.version,
                local_source_id=local_resource.source_id,
                remote_source_id=source.source_id,
                resolution="Kept local version (higher trust)",
            )
            self._conflicts.append(conflict)

    def _compare_versions(self, version_a: str, version_b: str) -> int:
        """Compare two semantic versions.

        Args:
            version_a: First version.
            version_b: Second version.

        Returns:
            -1 if a < b, 0 if a == b, 1 if a > b.
        """
        try:
            parts_a = [int(x) for x in version_a.split(".")]
            parts_b = [int(x) for x in version_b.split(".")]

            for a, b in zip(parts_a, parts_b):
                if a < b:
                    return -1
                elif a > b:
                    return 1

            if len(parts_a) < len(parts_b):
                return -1
            elif len(parts_a) > len(parts_b):
                return 1

            return 0

        except (ValueError, AttributeError):
            if version_a > version_b:
                return 1
            elif version_a < version_b:
                return -1
            return 0

    async def _notify_progress(self, progress: SyncProgress) -> None:
        """Notify registered callbacks of progress updates.

        Args:
            progress: Current sync progress.
        """
        for callback in self._progress_callbacks:
            try:
                await callback(progress)
            except Exception as e:
                logger.error(f"Progress callback error: {e}")

    async def update_blacklist(self) -> None:
        """Update the local blacklist from all enabled sources."""
        sources = self.registry.list_sources(enabled_only=True)

        for source in sources:
            try:
                blacklisted = await self.protocol.fetch_blacklist(source)
                self._blacklisted_ids.update(blacklisted)
            except Exception as e:
                logger.error(f"Failed to fetch blacklist from {source.name}: {e}")
