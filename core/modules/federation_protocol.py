"""Federation Protocol: Sync protocol definition, RESTful API specs, incremental sync logic.

Provides:
- Standard federation protocol for market resource synchronization
- RESTful API interface specifications
- Incremental sync based on timestamps and version comparison
- Resource metadata and entity package fetching
- Protocol version negotiation
"""

import asyncio
import logging
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

import aiohttp
from pydantic import BaseModel, Field

from .federation_registry import MarketSource, SyncDirection, TrustLevel

logger = logging.getLogger(__name__)

PROTOCOL_VERSION = "1.0.0"


class ResourceType(str, Enum):
    """Types of resources that can be federated.

    Attributes:
        PLUGIN: Plugin package
        POC_TEMPLATE: Proof of concept template
        FINGERPRINT_RULE: Service fingerprint rule
        ATTACK_CHAIN_TEMPLATE: Attack chain template
        C2_PROFILE: Malleable C2 profile
        NUCLEI_TEMPLATE: Nuclei template package
    """
    PLUGIN = "plugin"
    POC_TEMPLATE = "poc_template"
    FINGERPRINT_RULE = "fingerprint_rule"
    ATTACK_CHAIN_TEMPLATE = "attack_chain_template"
    C2_PROFILE = "c2_profile"
    NUCLEI_TEMPLATE = "nuclei_template"


class ResourceMetadata(BaseModel):
    """Metadata for a federated resource.

    Attributes:
        resource_id: Unique resource identifier
        resource_type: Type of resource
        name: Resource display name
        version: Semantic version string
        description: Resource description
        author: Resource author
        source_id: Originating market source ID
        created_at: Creation timestamp
        updated_at: Last update timestamp
        tags: Resource tags
        download_url: URL to download the resource package
        package_hash: SHA256 hash of the resource package
        signature: Digital signature of the package
        download_count: Number of downloads
        rating: Average rating (0-5)
        is_deleted: Whether this resource has been deleted
    """
    resource_id: str = Field(..., description="Unique resource identifier")
    resource_type: ResourceType = Field(..., description="Resource type")
    name: str = Field(..., description="Display name")
    version: str = Field(..., description="Semantic version")
    description: str = Field(default="", description="Description")
    author: str = Field(default="", description="Author")
    source_id: str = Field(default="", description="Origin source ID")
    created_at: str = Field(default="", description="Creation timestamp")
    updated_at: str = Field(default="", description="Last update timestamp")
    tags: List[str] = Field(default_factory=list, description="Tags")
    download_url: str = Field(default="", description="Download URL")
    package_hash: str = Field(default="", description="SHA256 hash")
    signature: str = Field(default="", description="Digital signature")
    download_count: int = Field(default=0, description="Download count")
    rating: float = Field(default=0.0, description="Average rating")
    is_deleted: bool = Field(default=False, description="Whether deleted")


class ResourceEntity(BaseModel):
    """Resource entity package information.

    Attributes:
        resource_id: Resource identifier
        version: Resource version
        package_url: URL to download the package
        package_size: Package size in bytes
        package_hash: SHA256 hash
        content_type: MIME type of the package
        dependencies: List of dependency resource IDs
    """
    resource_id: str = Field(..., description="Resource identifier")
    version: str = Field(..., description="Resource version")
    package_url: str = Field(..., description="Package download URL")
    package_size: int = Field(default=0, description="Package size in bytes")
    package_hash: str = Field(default="", description="SHA256 hash")
    content_type: str = Field(default="application/zip", description="MIME type")
    dependencies: List[str] = Field(default_factory=list, description="Dependencies")


class SyncRequest(BaseModel):
    """Synchronization request parameters.

    Attributes:
        source_id: Market source ID to sync from
        resource_types: Types of resources to sync (empty = all)
        since_timestamp: Only fetch resources updated after this time
        include_deleted: Whether to include deleted resources
        include_ratings: Whether to include rating data
    """
    source_id: str = Field(..., description="Source ID to sync from")
    resource_types: List[ResourceType] = Field(default_factory=list, description="Resource types")
    since_timestamp: Optional[str] = Field(default=None, description="Fetch after this time")
    include_deleted: bool = Field(default=False, description="Include deleted")
    include_ratings: bool = Field(default=False, description="Include ratings")


class SyncResponse(BaseModel):
    """Synchronization response data.

    Attributes:
        resources: List of resource metadata
        total_count: Total number of resources
        has_more: Whether there are more resources to fetch
        next_cursor: Cursor for pagination
        sync_timestamp: Server sync timestamp
    """
    resources: List[ResourceMetadata] = Field(default_factory=list, description="Resources")
    total_count: int = Field(default=0, description="Total count")
    has_more: bool = Field(default=False, description="Has more")
    next_cursor: Optional[str] = Field(default=None, description="Next cursor")
    sync_timestamp: str = Field(default="", description="Sync timestamp")


class FederationProtocol:
    """Implements the federation sync protocol for market sources.

    Provides RESTful API communication, incremental sync logic,
    and resource metadata/entity fetching.
    """

    def __init__(
        self,
        timeout: int = 30,
        max_retries: int = 3,
        token: Optional[str] = None,
    ) -> None:
        """Initialize federation protocol client.

        Args:
            timeout: HTTP request timeout in seconds.
            max_retries: Maximum retry attempts for failed requests.
            token: Authentication token for API access.
        """
        self.timeout = timeout
        self.max_retries = max_retries
        self.token = token
        self._session: Optional[aiohttp.ClientSession] = None

    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create HTTP session.

        Returns:
            aiohttp ClientSession.
        """
        if self._session is None or self._session.closed:
            headers: Dict[str, str] = {
                "X-Federation-Protocol-Version": PROTOCOL_VERSION,
                "Accept": "application/json",
            }

            if self.token:
                headers["Authorization"] = f"Bearer {self.token}"

            self._session = aiohttp.ClientSession(
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=self.timeout),
            )

        return self._session

    async def close(self) -> None:
        """Close the HTTP session."""
        if self._session and not self._session.closed:
            await self._session.close()

    async def health_check(self, source: MarketSource) -> bool:
        """Check if a market source is reachable and healthy.

        Args:
            source: Market source to check.

        Returns:
            True if source is healthy.
        """
        url = f"{source.url}/health"

        try:
            session = await self._get_session()
            async with session.get(url) as response:
                return response.status == 200
        except Exception as e:
            logger.warning(f"Health check failed for {source.name}: {e}")
            return False

    async def fetch_resource_list(
        self,
        source: MarketSource,
        request: SyncRequest,
    ) -> SyncResponse:
        """Fetch resource metadata list from a market source.

        Args:
            source: Market source to fetch from.
            request: Sync request parameters.

        Returns:
            SyncResponse with resource metadata.
        """
        url = f"{source.url}/api/v1/resources"
        params: Dict[str, Any] = {}

        if request.resource_types:
            params["types"] = ",".join(rt.value for rt in request.resource_types)

        if request.since_timestamp:
            params["since"] = request.since_timestamp

        if request.include_deleted:
            params["include_deleted"] = "true"

        if request.include_ratings:
            params["include_ratings"] = "true"

        try:
            session = await self._get_session()
            async with session.get(url, params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    return SyncResponse(**data)
                else:
                    logger.error(f"Fetch failed: {response.status}")
                    return SyncResponse()

        except Exception as e:
            logger.error(f"Fetch error: {e}")
            return SyncResponse()

    async def fetch_resource_entity(
        self,
        source: MarketSource,
        resource_id: str,
        version: str,
    ) -> Optional[ResourceEntity]:
        """Fetch resource entity package info from a market source.

        Args:
            source: Market source to fetch from.
            resource_id: Resource identifier.
            version: Resource version.

        Returns:
            ResourceEntity or None.
        """
        url = f"{source.url}/api/v1/resources/{resource_id}/entities/{version}"

        try:
            session = await self._get_session()
            async with session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    return ResourceEntity(**data)
                else:
                    logger.error(f"Entity fetch failed: {response.status}")
                    return None

        except Exception as e:
            logger.error(f"Entity fetch error: {e}")
            return None

    async def download_resource_package(
        self,
        entity: ResourceEntity,
        output_path: str,
        resume: bool = True,
    ) -> bool:
        """Download a resource package with resume support.

        Args:
            entity: Resource entity with download URL.
            output_path: Local path to save the package.
            resume: Whether to resume interrupted downloads.

        Returns:
            True if download succeeded.
        """
        import os

        headers: Dict[str, str] = {}

        if resume and os.path.exists(output_path):
            existing_size = os.path.getsize(output_path)
            headers["Range"] = f"bytes={existing_size}-"

        try:
            session = await self._get_session()
            async with session.get(entity.package_url, headers=headers) as response:
                if response.status in (200, 206):
                    mode = "ab" if response.status == 206 else "wb"

                    with open(output_path, mode) as f:
                        async for chunk in response.content.iter_chunked(8192):
                            f.write(chunk)

                    return True
                else:
                    logger.error(f"Download failed: {response.status}")
                    return False

        except Exception as e:
            logger.error(f"Download error: {e}")
            return False

    async def push_resource_update(
        self,
        source: MarketSource,
        resource: ResourceMetadata,
    ) -> bool:
        """Push a resource update to a market source (bidirectional sync).

        Args:
            source: Market source to push to.
            resource: Resource metadata to push.

        Returns:
            True if push succeeded.
        """
        if source.sync_direction != SyncDirection.BIDIRECTIONAL:
            logger.warning(f"Source {source.name} does not support bidirectional sync")
            return False

        url = f"{source.url}/api/v1/resources/push"

        try:
            session = await self._get_session()
            async with session.post(url, json=resource.model_dump()) as response:
                return response.status == 200

        except Exception as e:
            logger.error(f"Push error: {e}")
            return False

    async def fetch_blacklist(
        self,
        source: MarketSource,
    ) -> List[str]:
        """Fetch the malicious resource blacklist from a market source.

        Args:
            source: Market source to fetch from.

        Returns:
            List of blacklisted resource IDs.
        """
        url = f"{source.url}/api/v1/blacklist"

        try:
            session = await self._get_session()
            async with session.get(url) as response:
                if response.status == 200:
                    data: Dict[str, Any] = await response.json()
                    result: List[str] = data.get("blacklisted_ids", [])
                    return result
                else:
                    return []

        except Exception as e:
            logger.error(f"Blacklist fetch error: {e}")
            return []

    async def report_malicious_resource(
        self,
        source: MarketSource,
        resource_id: str,
        reason: str = "",
    ) -> bool:
        """Report a malicious resource to a market source.

        Args:
            source: Market source to report to.
            resource_id: Resource identifier to report.
            reason: Reason for the report.

        Returns:
            True if report succeeded.
        """
        url = f"{source.url}/api/v1/resources/{resource_id}/report"

        try:
            session = await self._get_session()
            async with session.post(url, json={"reason": reason}) as response:
                return response.status == 200

        except Exception as e:
            logger.error(f"Report error: {e}")
            return False

    async def get_source_info(
        self,
        source: MarketSource,
    ) -> Optional[Dict[str, Any]]:
        """Get information about a market source.

        Args:
            source: Market source to query.

        Returns:
            Source information dictionary or None.
        """
        url = f"{source.url}/api/v1/info"

        try:
            session = await self._get_session()
            async with session.get(url) as response:
                if response.status == 200:
                    result: Dict[str, Any] = await response.json()
                    return result
                else:
                    return None

        except Exception as e:
            logger.error(f"Source info error: {e}")
            return None

    async def incremental_sync(
        self,
        source: MarketSource,
        last_sync_timestamp: Optional[str],
        resource_types: Optional[List[ResourceType]] = None,
    ) -> SyncResponse:
        """Perform incremental sync with a market source.

        Fetches only resources that have changed since the last sync.

        Args:
            source: Market source to sync with.
            last_sync_timestamp: Timestamp of last successful sync.
            resource_types: Types of resources to sync.

        Returns:
            SyncResponse with changed resources.
        """
        request = SyncRequest(
            source_id=source.source_id,
            resource_types=resource_types or [],
            since_timestamp=last_sync_timestamp,
            include_deleted=True,
        )

        return await self.fetch_resource_list(source, request)

    async def full_sync(
        self,
        source: MarketSource,
        resource_types: Optional[List[ResourceType]] = None,
    ) -> SyncResponse:
        """Perform full sync with a market source.

        Fetches all resources regardless of last sync time.

        Args:
            source: Market source to sync with.
            resource_types: Types of resources to sync.

        Returns:
            SyncResponse with all resources.
        """
        request = SyncRequest(
            source_id=source.source_id,
            resource_types=resource_types or [],
            since_timestamp=None,
            include_deleted=False,
        )

        return await self.fetch_resource_list(source, request)
