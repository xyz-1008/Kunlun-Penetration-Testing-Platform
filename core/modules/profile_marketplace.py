"""
Profile Marketplace Module - Community marketplace integration interface.

This module provides:
    1. Profile upload and download from community marketplace
    2. Filtering by industry, environment, protocol
    3. Rating, review, and download tracking
    4. Hot profile recommendations
    5. Built-in library updates

Core capabilities:
    - Profile catalog browsing
    - Industry/environment/protocol filtering
    - Rating and review system
    - Download statistics
    - Profile version management
    - Community knowledge sharing

Author: Kunlun Security Lab
License: Internal Use Only
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Coroutine, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


# =============================================================================
# Enums
# =============================================================================

class Industry(str, Enum):
    """Target industry categories."""

    FINANCE = "finance"
    GOVERNMENT = "government"
    EDUCATION = "education"
    HEALTHCARE = "healthcare"
    TECHNOLOGY = "technology"
    MANUFACTURING = "manufacturing"
    RETAIL = "retail"
    ENERGY = "energy"
    TELECOM = "telecom"
    GENERAL = "general"


class Environment(str, Enum):
    """Deployment environment."""

    CLOUD = "cloud"
    ON_PREMISE = "on_premise"
    HYBRID = "hybrid"
    CONTAINERIZED = "containerized"
    IOT = "iot"


class Protocol(str, Enum):
    """Communication protocol."""

    HTTP = "http"
    HTTPS = "https"
    DNS = "dns"
    ICMP = "icmp"
    SMTP = "smtp"
    WEBSOCKET = "websocket"
    HTTP2 = "http2"
    HTTP3 = "http3"


class ProfileStatus(str, Enum):
    """Profile publication status."""

    DRAFT = "draft"
    PUBLISHED = "published"
    DEPRECATED = "deprecated"
    ARCHIVED = "archived"


# =============================================================================
# Data Models
# =============================================================================

@dataclass
class ProfileMetadata:
    """Profile marketplace metadata.

    Attributes:
        profile_id: Unique profile identifier
        name: Profile name
        description: Profile description
        author: Profile author
        version: Profile version
        industry: Target industry
        environment: Deployment environment
        protocols: Supported protocols
        status: Publication status
        created_at: Creation timestamp
        updated_at: Last update timestamp
        tags: Search tags
    """

    profile_id: str = ""
    name: str = ""
    description: str = ""
    author: str = ""
    version: str = "1.0.0"
    industry: Industry = Industry.GENERAL
    environment: Environment = Environment.ON_PREMISE
    protocols: List[Protocol] = field(default_factory=lambda: [Protocol.HTTPS])
    status: ProfileStatus = ProfileStatus.DRAFT
    created_at: float = 0.0
    updated_at: float = 0.0
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "profile_id": self.profile_id,
            "name": self.name,
            "description": self.description,
            "author": self.author,
            "version": self.version,
            "industry": self.industry.value,
            "environment": self.environment.value,
            "protocols": [p.value for p in self.protocols],
            "status": self.status.value,
            "tags": self.tags,
        }


@dataclass
class ProfileStats:
    """Profile usage statistics.

    Attributes:
        profile_id: Profile identifier
        download_count: Total downloads
        rating: Average rating (1-5)
        rating_count: Number of ratings
        review_count: Number of reviews
        success_rate: Operational success rate
        avg_lifetime_hours: Average beacon lifetime
        detection_count: Total detections
    """

    profile_id: str = ""
    download_count: int = 0
    rating: float = 0.0
    rating_count: int = 0
    review_count: int = 0
    success_rate: float = 0.0
    avg_lifetime_hours: float = 0.0
    detection_count: int = 0

    @property
    def popularity_score(self) -> float:
        """Calculate popularity score."""
        download_weight = min(self.download_count / 100, 1.0)
        rating_weight = self.rating / 5.0
        rating_confidence = min(self.rating_count / 10, 1.0)

        return (
            download_weight * 0.4
            + rating_weight * rating_confidence * 0.4
            + rating_confidence * 0.2
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "profile_id": self.profile_id,
            "download_count": self.download_count,
            "rating": round(self.rating, 2),
            "rating_count": self.rating_count,
            "popularity_score": round(self.popularity_score, 3),
        }


@dataclass
class Review:
    """Profile review.

    Attributes:
        review_id: Review identifier
        profile_id: Profile identifier
        author: Review author
        rating: Rating (1-5)
        comment: Review comment
        timestamp: Review timestamp
        helpful_count: Helpful votes
    """

    review_id: str = ""
    profile_id: str = ""
    author: str = ""
    rating: int = 5
    comment: str = ""
    timestamp: float = 0.0
    helpful_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "review_id": self.review_id,
            "profile_id": self.profile_id,
            "author": self.author,
            "rating": self.rating,
            "comment": self.comment,
            "helpful_count": self.helpful_count,
        }


@dataclass
class MarketplaceListing:
    """Complete marketplace listing.

    Attributes:
        metadata: Profile metadata
        stats: Usage statistics
        reviews: User reviews
        yaml_content: Profile YAML content
    """

    metadata: ProfileMetadata = field(default_factory=ProfileMetadata)
    stats: ProfileStats = field(default_factory=ProfileStats)
    reviews: List[Review] = field(default_factory=list)
    yaml_content: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "metadata": self.metadata.to_dict(),
            "stats": self.stats.to_dict(),
            "review_count": len(self.reviews),
            "top_reviews": [r.to_dict() for r in self.reviews[:3]],
        }


# =============================================================================
# Profile Registry
# =============================================================================

class ProfileRegistry:
    """Local profile registry and cache.

    Manages downloaded profiles, tracks versions,
    and provides offline access.

    Attributes:
        _profiles: Local profile storage
        _download_history: Download history
    """

    def __init__(self, storage_path: str = "") -> None:
        """Initialize the ProfileRegistry.

        Args:
            storage_path: Local storage path.
        """
        self._profiles: Dict[str, MarketplaceListing] = {}
        self._download_history: List[Dict[str, Any]] = []
        self._storage_path = storage_path

    def add_profile(self, listing: MarketplaceListing) -> None:
        """Add a profile to registry.

        Args:
            listing: Marketplace listing.
        """
        self._profiles[listing.metadata.profile_id] = listing

    def get_profile(self, profile_id: str) -> Optional[MarketplaceListing]:
        """Get a profile from registry.

        Args:
            profile_id: Profile identifier.

        Returns:
            MarketplaceListing, or None.
        """
        return self._profiles.get(profile_id)

    def list_profiles(
        self,
        industry: Optional[Industry] = None,
        environment: Optional[Environment] = None,
        protocol: Optional[Protocol] = None,
        status: Optional[ProfileStatus] = None,
    ) -> List[MarketplaceListing]:
        """List profiles with filters.

        Args:
            industry: Filter by industry.
            environment: Filter by environment.
            protocol: Filter by protocol.
            status: Filter by status.

        Returns:
            List of matching MarketplaceListing.
        """
        results = list(self._profiles.values())

        if industry:
            results = [
                p for p in results
                if p.metadata.industry == industry
            ]

        if environment:
            results = [
                p for p in results
                if p.metadata.environment == environment
            ]

        if protocol:
            results = [
                p for p in results
                if protocol in p.metadata.protocols
            ]

        if status:
            results = [
                p for p in results
                if p.metadata.status == status
            ]

        return results

    def record_download(self, profile_id: str) -> None:
        """Record a profile download.

        Args:
            profile_id: Profile identifier.
        """
        self._download_history.append({
            "profile_id": profile_id,
            "timestamp": time.time(),
        })

        listing = self._profiles.get(profile_id)
        if listing:
            listing.stats.download_count += 1

    def get_status(self) -> Dict[str, Any]:
        """Get registry status.

        Returns:
            Dictionary with status summary.
        """
        return {
            "total_profiles": len(self._profiles),
            "total_downloads": len(self._download_history),
            "industries": list(set(
                p.metadata.industry.value
                for p in self._profiles.values()
            )),
        }


# =============================================================================
# Marketplace Client
# =============================================================================

class MarketplaceClient:
    """Client for community marketplace API.

    Handles profile upload, download, rating,
    and search operations.

    Attributes:
        _api_url: Marketplace API URL
        _api_key: API authentication key
        _registry: Local profile registry
    """

    DEFAULT_API_URL = "https://marketplace.kunlun.internal/api/v1"

    def __init__(
        self,
        api_url: str = "",
        api_key: str = "",
        registry: Optional[ProfileRegistry] = None,
    ) -> None:
        """Initialize the MarketplaceClient.

        Args:
            api_url: Marketplace API URL.
            api_key: API authentication key.
            registry: Local profile registry.
        """
        self._api_url = api_url or self.DEFAULT_API_URL
        self._api_key = api_key
        self._registry = registry or ProfileRegistry()

    async def search_profiles(
        self,
        query: str = "",
        industry: Optional[Industry] = None,
        environment: Optional[Environment] = None,
        protocol: Optional[Protocol] = None,
        min_rating: float = 0.0,
        limit: int = 20,
    ) -> List[MarketplaceListing]:
        """Search marketplace profiles.

        Args:
            query: Search query string.
            industry: Filter by industry.
            environment: Filter by environment.
            protocol: Filter by protocol.
            min_rating: Minimum rating filter.
            limit: Maximum results.

        Returns:
            List of matching MarketplaceListing.
        """
        results = self._registry.list_profiles(
            industry=industry,
            environment=environment,
            protocol=protocol,
        )

        if query:
            query_lower = query.lower()
            results = [
                p for p in results
                if query_lower in p.metadata.name.lower()
                or query_lower in p.metadata.description.lower()
                or any(query_lower in t.lower() for t in p.metadata.tags)
            ]

        results = [
            p for p in results
            if p.stats.rating >= min_rating
        ]

        results.sort(
            key=lambda p: p.stats.popularity_score,
            reverse=True,
        )

        return results[:limit]

    async def get_profile_detail(
        self, profile_id: str,
    ) -> Optional[MarketplaceListing]:
        """Get detailed profile information.

        Args:
            profile_id: Profile identifier.

        Returns:
            MarketplaceListing, or None.
        """
        return self._registry.get_profile(profile_id)

    async def download_profile(
        self, profile_id: str,
    ) -> Optional[MarketplaceListing]:
        """Download a profile from marketplace.

        Args:
            profile_id: Profile identifier.

        Returns:
            Downloaded MarketplaceListing, or None.
        """
        listing = self._registry.get_profile(profile_id)

        if listing:
            self._registry.record_download(profile_id)
            logger.info(f"Profile downloaded: {profile_id}")
            return listing

        return None

    async def upload_profile(
        self,
        yaml_content: str,
        metadata: ProfileMetadata,
    ) -> Optional[str]:
        """Upload a profile to marketplace.

        Args:
            yaml_content: Profile YAML content.
            metadata: Profile metadata.

        Returns:
            Profile ID, or None.
        """
        if not metadata.profile_id:
            metadata.profile_id = hashlib.md5(
                f"profile_{time.time()}_{metadata.name}".encode()
            ).hexdigest()[:12]

        now = time.time()
        metadata.created_at = now
        metadata.updated_at = now
        metadata.status = ProfileStatus.PUBLISHED

        listing = MarketplaceListing(
            metadata=metadata,
            stats=ProfileStats(profile_id=metadata.profile_id),
            yaml_content=yaml_content,
        )

        self._registry.add_profile(listing)

        logger.info(f"Profile uploaded: {metadata.profile_id}")
        return metadata.profile_id

    async def rate_profile(
        self,
        profile_id: str,
        rating: int,
        comment: str = "",
        author: str = "",
    ) -> bool:
        """Rate a profile.

        Args:
            profile_id: Profile identifier.
            rating: Rating (1-5).
            comment: Review comment.
            author: Review author.

        Returns:
            True if rating submitted successfully.
        """
        if not 1 <= rating <= 5:
            return False

        listing = self._registry.get_profile(profile_id)
        if not listing:
            return False

        review = Review(
            review_id=hashlib.md5(
                f"review_{time.time()}".encode()
            ).hexdigest()[:12],
            profile_id=profile_id,
            author=author,
            rating=rating,
            comment=comment,
            timestamp=time.time(),
        )

        listing.reviews.append(review)

        total_rating = listing.stats.rating * listing.stats.rating_count + rating
        listing.stats.rating_count += 1
        listing.stats.rating = total_rating / listing.stats.rating_count
        listing.stats.review_count = len(listing.reviews)

        logger.info(
            f"Profile rated: {profile_id} -> {rating}/5"
        )

        return True

    async def get_hot_profiles(self, limit: int = 10) -> List[MarketplaceListing]:
        """Get hot/trending profiles.

        Args:
            limit: Maximum results.

        Returns:
            List of hot MarketplaceListing.
        """
        all_profiles = self._registry.list_profiles(
            status=ProfileStatus.PUBLISHED,
        )

        all_profiles.sort(
            key=lambda p: p.stats.popularity_score,
            reverse=True,
        )

        return all_profiles[:limit]

    def get_status(self) -> Dict[str, Any]:
        """Get marketplace client status.

        Returns:
            Dictionary with status summary.
        """
        return {
            "api_url": self._api_url,
            "registry": self._registry.get_status(),
        }


# =============================================================================
# Profile Marketplace Manager
# =============================================================================

class ProfileMarketplaceManager:
    """Main marketplace coordination engine.

    Integrates marketplace client, registry,
    and recommendation system.

    Attributes:
        _client: Marketplace API client
        _registry: Local profile registry
    """

    def __init__(
        self,
        api_url: str = "",
        api_key: str = "",
    ) -> None:
        """Initialize the ProfileMarketplaceManager.

        Args:
            api_url: Marketplace API URL.
            api_key: API authentication key.
        """
        self._registry = ProfileRegistry()
        self._client = MarketplaceClient(
            api_url=api_url,
            api_key=api_key,
            registry=self._registry,
        )

    async def search(
        self,
        query: str = "",
        industry: Optional[Industry] = None,
        environment: Optional[Environment] = None,
        protocol: Optional[Protocol] = None,
        min_rating: float = 0.0,
        limit: int = 20,
    ) -> List[MarketplaceListing]:
        """Search marketplace profiles.

        Args:
            query: Search query.
            industry: Filter by industry.
            environment: Filter by environment.
            protocol: Filter by protocol.
            min_rating: Minimum rating.
            limit: Maximum results.

        Returns:
            List of matching MarketplaceListing.
        """
        return await self._client.search_profiles(
            query=query,
            industry=industry,
            environment=environment,
            protocol=protocol,
            min_rating=min_rating,
            limit=limit,
        )

    async def download(self, profile_id: str) -> Optional[MarketplaceListing]:
        """Download a profile.

        Args:
            profile_id: Profile identifier.

        Returns:
            Downloaded MarketplaceListing, or None.
        """
        return await self._client.download_profile(profile_id)

    async def upload(
        self,
        yaml_content: str,
        metadata: ProfileMetadata,
    ) -> Optional[str]:
        """Upload a profile.

        Args:
            yaml_content: Profile YAML content.
            metadata: Profile metadata.

        Returns:
            Profile ID, or None.
        """
        return await self._client.upload_profile(yaml_content, metadata)

    async def rate(
        self,
        profile_id: str,
        rating: int,
        comment: str = "",
        author: str = "",
    ) -> bool:
        """Rate a profile.

        Args:
            profile_id: Profile identifier.
            rating: Rating (1-5).
            comment: Review comment.
            author: Review author.

        Returns:
            True if rating submitted.
        """
        return await self._client.rate_profile(
            profile_id, rating, comment, author,
        )

    async def get_hot_profiles(
        self, limit: int = 10,
    ) -> List[MarketplaceListing]:
        """Get hot profiles.

        Args:
            limit: Maximum results.

        Returns:
            List of hot MarketplaceListing.
        """
        return await self._client.get_hot_profiles(limit)

    def get_recommendations(
        self,
        preferred_industry: Optional[Industry] = None,
        preferred_environment: Optional[Environment] = None,
    ) -> List[MarketplaceListing]:
        """Get personalized profile recommendations.

        Args:
            preferred_industry: Preferred industry.
            preferred_environment: Preferred environment.

        Returns:
            List of recommended MarketplaceListing.
        """
        candidates = self._registry.list_profiles(
            industry=preferred_industry,
            environment=preferred_environment,
            status=ProfileStatus.PUBLISHED,
        )

        candidates.sort(
            key=lambda p: p.stats.popularity_score,
            reverse=True,
        )

        return candidates[:10]

    def get_status(self) -> Dict[str, Any]:
        """Get marketplace manager status.

        Returns:
            Dictionary with status summary.
        """
        return {
            "client": self._client.get_status(),
        }


# =============================================================================
# Global Singleton
# =============================================================================

_marketplace_manager: Optional[ProfileMarketplaceManager] = None


def get_marketplace_manager() -> ProfileMarketplaceManager:
    """Get the global ProfileMarketplaceManager singleton.

    Returns:
        Singleton ProfileMarketplaceManager instance.
    """
    global _marketplace_manager
    if _marketplace_manager is None:
        _marketplace_manager = ProfileMarketplaceManager()
    return _marketplace_manager


__all__ = [
    "ProfileMarketplaceManager",
    "MarketplaceClient",
    "ProfileRegistry",
    "ProfileMetadata",
    "ProfileStats",
    "Review",
    "MarketplaceListing",
    "Industry",
    "Environment",
    "Protocol",
    "ProfileStatus",
    "get_marketplace_manager",
]
