"""Template Marketplace: Market browsing, search, installation, rating, and reviews.

Provides:
- Category browsing: by vulnerability type, target platform (Windows/Linux/Web/Cloud), difficulty, popularity
- Search and filtering: keyword search, tag filtering, rating sorting, download count sorting
- Template detail page: full step preview, usage statistics, user reviews, version history
- One-click installation to local template library
- Template update notifications: notify users when followed templates have new versions
"""

import asyncio
import json
import logging
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum, auto
from typing import Any, Callable, Coroutine, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


class TemplateCategory(Enum):
    """Template categories."""
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    CSRF = "csrf"
    RCE = "rce"
    AUTH_BYPASS = "auth_bypass"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    LATERAL_MOVEMENT = "lateral_movement"
    PERSISTENCE = "persistence"
    RECONNAISSANCE = "reconnaissance"
    POST_EXPLOITATION = "post_exploitation"
    WEB = "web"
    NETWORK = "network"
    CLOUD = "cloud"
    ACTIVE_DIRECTORY = "active_directory"
    CUSTOM = "custom"


class TargetPlatform(Enum):
    """Target platform types."""
    WINDOWS = "windows"
    LINUX = "linux"
    WEB = "web"
    CLOUD = "cloud"
    MOBILE = "mobile"
    IOT = "iot"
    NETWORK_DEVICE = "network_device"
    DATABASE = "database"


class DifficultyLevel(Enum):
    """Template difficulty levels."""
    BEGINNER = "beginner"
    INTERMEDIATE = "intermediate"
    ADVANCED = "advanced"
    EXPERT = "expert"


class TemplateStatus(Enum):
    """Template publication status."""
    DRAFT = "draft"
    PUBLISHED = "published"
    UNDER_REVIEW = "under_review"
    REJECTED = "rejected"
    ARCHIVED = "archived"


class SortOption(Enum):
    """Template sorting options."""
    NEWEST = "newest"
    OLDEST = "oldest"
    RATING = "rating"
    DOWNLOADS = "downloads"
    NAME = "name"
    DIFFICULTY = "difficulty"


@dataclass
class TemplateReview:
    """User review for a template.

    Attributes:
        review_id: Unique review identifier
        template_id: Template identifier
        user_id: User identifier
        username: User display name
        rating: Rating (1-5 stars)
        comment: Review comment
        created_at: Review creation timestamp
        is_verified_purchase: Whether user downloaded template
        helpful_count: Number of users who found review helpful
    """
    review_id: str = ""
    template_id: str = ""
    user_id: str = ""
    username: str = ""
    rating: int = 5
    comment: str = ""
    created_at: float = 0.0
    is_verified_purchase: bool = False
    helpful_count: int = 0


@dataclass
class TemplateVersion:
    """Template version information.

    Attributes:
        version: Version string
        release_date: Release timestamp
        changelog: Version changelog
        is_current: Whether this is the current version
        download_count: Number of downloads for this version
    """
    version: str = "1.0.0"
    release_date: float = 0.0
    changelog: str = ""
    is_current: bool = False
    download_count: int = 0


@dataclass
class MarketplaceTemplate:
    """Template available in marketplace.

    Attributes:
        template_id: Unique template identifier
        name: Template name
        description: Template description
        author: Template author
        author_id: Author user ID
        category: Template category
        platforms: Target platforms
        difficulty: Difficulty level
        tags: Template tags
        version: Current version
        versions: Version history
        price: Price (0 for free)
        is_verified: Whether template is verified
        rating: Average rating (0-5)
        review_count: Number of reviews
        download_count: Total downloads
        view_count: Total views
        created_at: Creation timestamp
        updated_at: Last update timestamp
        status: Publication status
        preview_steps: Preview of first 3 steps
        required_modules: Required Kunlun modules
        estimated_time_minutes: Estimated completion time
        is_featured: Whether template is featured
        report_count: Number of reports
    """
    template_id: str = ""
    name: str = ""
    description: str = ""
    author: str = ""
    author_id: str = ""
    category: TemplateCategory = TemplateCategory.CUSTOM
    platforms: List[TargetPlatform] = field(default_factory=list)
    difficulty: DifficultyLevel = DifficultyLevel.BEGINNER
    tags: List[str] = field(default_factory=list)
    version: str = "1.0.0"
    versions: List[TemplateVersion] = field(default_factory=list)
    price: float = 0.0
    is_verified: bool = False
    rating: float = 0.0
    review_count: int = 0
    download_count: int = 0
    view_count: int = 0
    created_at: float = 0.0
    updated_at: float = 0.0
    status: TemplateStatus = TemplateStatus.DRAFT
    preview_steps: List[Dict[str, Any]] = field(default_factory=list)
    required_modules: List[str] = field(default_factory=list)
    estimated_time_minutes: int = 0
    is_featured: bool = False
    report_count: int = 0


@dataclass
class MarketplaceFilters:
    """Filters for marketplace browsing.

    Attributes:
        category: Filter by category
        platforms: Filter by platforms
        difficulty: Filter by difficulty
        min_rating: Minimum rating filter
        is_verified: Verified only filter
        is_free: Free only filter
        tags: Filter by tags
        author: Filter by author
        keyword: Search keyword
        sort: Sort option
        page: Page number
        page_size: Items per page
    """
    category: Optional[TemplateCategory] = None
    platforms: Optional[List[TargetPlatform]] = None
    difficulty: Optional[DifficultyLevel] = None
    min_rating: float = 0.0
    is_verified: bool = False
    is_free: bool = False
    tags: Optional[List[str]] = None
    author: str = ""
    keyword: str = ""
    sort: SortOption = SortOption.NEWEST
    page: int = 1
    page_size: int = 20


@dataclass
class MarketplaceResult:
    """Marketplace search results.

    Attributes:
        templates: List of matching templates
        total_count: Total number of matching templates
        page: Current page
        page_size: Items per page
        total_pages: Total number of pages
    """
    templates: List[MarketplaceTemplate] = field(default_factory=list)
    total_count: int = 0
    page: int = 1
    page_size: int = 20
    total_pages: int = 0


class TemplateMarketplace:
    """Marketplace for browsing, searching, and installing attack chain templates.

    Provides category browsing, search and filtering, template details,
    reviews, ratings, and one-click installation.
    """

    def __init__(self, storage_path: str = "") -> None:
        """Initialize template marketplace.

        Args:
            storage_path: Directory path for marketplace storage.
        """
        self.storage_path = storage_path
        self._templates: Dict[str, MarketplaceTemplate] = {}
        self._reviews: Dict[str, List[TemplateReview]] = {}
        self._user_ratings: Dict[str, Dict[str, int]] = {}
        self._user_downloads: Dict[str, List[str]] = {}
        self._user_follows: Dict[str, List[str]] = {}
        self._installed_templates: Dict[str, Dict[str, Any]] = {}

        if storage_path:
            os.makedirs(storage_path, exist_ok=True)
            self._load_data()

    async def publish_template(
        self,
        template_id: str,
        name: str,
        description: str,
        author: str,
        author_id: str,
        category: TemplateCategory,
        platforms: Optional[List[TargetPlatform]] = None,
        difficulty: DifficultyLevel = DifficultyLevel.BEGINNER,
        tags: Optional[List[str]] = None,
        price: float = 0.0,
        preview_steps: Optional[List[Dict[str, Any]]] = None,
        required_modules: Optional[List[str]] = None,
        estimated_time_minutes: int = 0,
    ) -> Optional[MarketplaceTemplate]:
        """Publish template to marketplace.

        Args:
            template_id: Template identifier.
            name: Template name.
            description: Template description.
            author: Template author.
            author_id: Author user ID.
            category: Template category.
            platforms: Target platforms.
            difficulty: Difficulty level.
            tags: Template tags.
            price: Template price.
            preview_steps: Preview steps.
            required_modules: Required modules.
            estimated_time_minutes: Estimated completion time.

        Returns:
            Published MarketplaceTemplate or None.
        """
        now = time.time()

        version = TemplateVersion(
            version="1.0.0",
            release_date=now,
            changelog="Initial release",
            is_current=True,
        )

        template = MarketplaceTemplate(
            template_id=template_id,
            name=name,
            description=description,
            author=author,
            author_id=author_id,
            category=category,
            platforms=platforms or [],
            difficulty=difficulty,
            tags=tags or [],
            version="1.0.0",
            versions=[version],
            price=price,
            created_at=now,
            updated_at=now,
            status=TemplateStatus.PUBLISHED,
            preview_steps=preview_steps or [],
            required_modules=required_modules or [],
            estimated_time_minutes=estimated_time_minutes,
        )

        self._templates[template_id] = template
        self._reviews[template_id] = []

        self._save_data()

        return template

    async def update_template_version(
        self,
        template_id: str,
        new_version: str,
        changelog: str,
        preview_steps: Optional[List[Dict[str, Any]]] = None,
    ) -> bool:
        """Update template version.

        Args:
            template_id: Template identifier.
            new_version: New version string.
            changelog: Version changelog.
            preview_steps: Updated preview steps.

        Returns:
            True if updated successfully.
        """
        template = self._templates.get(template_id)
        if not template:
            return False

        for v in template.versions:
            v.is_current = False

        version = TemplateVersion(
            version=new_version,
            release_date=time.time(),
            changelog=changelog,
            is_current=True,
        )

        template.versions.append(version)
        template.version = new_version
        template.updated_at = time.time()

        if preview_steps:
            template.preview_steps = preview_steps

        self._save_data()

        return True

    async def browse_templates(
        self,
        filters: Optional[MarketplaceFilters] = None,
    ) -> MarketplaceResult:
        """Browse templates with filters.

        Args:
            filters: Optional marketplace filters.

        Returns:
            MarketplaceResult with matching templates.
        """
        if not filters:
            filters = MarketplaceFilters()

        templates = list(self._templates.values())

        if filters.category:
            templates = [t for t in templates if t.category == filters.category]

        if filters.platforms:
            templates = [
                t for t in templates
                if any(p in t.platforms for p in filters.platforms)
            ]

        if filters.difficulty:
            templates = [t for t in templates if t.difficulty == filters.difficulty]

        if filters.min_rating > 0:
            templates = [t for t in templates if t.rating >= filters.min_rating]

        if filters.is_verified:
            templates = [t for t in templates if t.is_verified]

        if filters.is_free:
            templates = [t for t in templates if t.price == 0]

        if filters.tags:
            templates = [
                t for t in templates
                if any(tag in t.tags for tag in filters.tags)
            ]

        if filters.author:
            templates = [t for t in templates if filters.author.lower() in t.author.lower()]

        if filters.keyword:
            keyword = filters.keyword.lower()
            templates = [
                t for t in templates
                if keyword in t.name.lower()
                or keyword in t.description.lower()
                or any(keyword in tag.lower() for tag in t.tags)
            ]

        templates = self._sort_templates(templates, filters.sort)

        total_count = len(templates)
        total_pages = max(1, (total_count + filters.page_size - 1) // filters.page_size)

        start_idx = (filters.page - 1) * filters.page_size
        end_idx = start_idx + filters.page_size
        page_templates = templates[start_idx:end_idx]

        return MarketplaceResult(
            templates=page_templates,
            total_count=total_count,
            page=filters.page,
            page_size=filters.page_size,
            total_pages=total_pages,
        )

    async def get_template_details(self, template_id: str) -> Optional[MarketplaceTemplate]:
        """Get template details.

        Args:
            template_id: Template identifier.

        Returns:
            MarketplaceTemplate or None.
        """
        template = self._templates.get(template_id)
        if template:
            template.view_count += 1
            self._save_data()
        return template

    async def install_template(
        self,
        template_id: str,
        user_id: str,
    ) -> bool:
        """Install template to local library.

        Args:
            template_id: Template identifier.
            user_id: User identifier.

        Returns:
            True if installed successfully.
        """
        template = self._templates.get(template_id)
        if not template:
            return False

        template.download_count += 1

        if user_id not in self._user_downloads:
            self._user_downloads[user_id] = []

        if template_id not in self._user_downloads[user_id]:
            self._user_downloads[user_id].append(template_id)

        self._installed_templates[template_id] = {
            "user_id": user_id,
            "installed_at": time.time(),
            "version": template.version,
        }

        self._save_data()

        return True

    async def add_review(
        self,
        template_id: str,
        user_id: str,
        username: str,
        rating: int,
        comment: str = "",
    ) -> Optional[TemplateReview]:
        """Add review for template.

        Args:
            template_id: Template identifier.
            user_id: User identifier.
            username: User display name.
            rating: Rating (1-5).
            comment: Review comment.

        Returns:
            Created TemplateReview or None.
        """
        if not (1 <= rating <= 5):
            return None

        template = self._templates.get(template_id)
        if not template:
            return None

        review_id = f"review_{template_id}_{user_id}_{int(time.time())}"

        is_verified = template_id in self._user_downloads.get(user_id, [])

        review = TemplateReview(
            review_id=review_id,
            template_id=template_id,
            user_id=user_id,
            username=username,
            rating=rating,
            comment=comment,
            created_at=time.time(),
            is_verified_purchase=is_verified,
        )

        if template_id not in self._reviews:
            self._reviews[template_id] = []

        existing = next((r for r in self._reviews[template_id] if r.user_id == user_id), None)
        if existing:
            existing.rating = rating
            existing.comment = comment
            existing.created_at = time.time()
        else:
            self._reviews[template_id].append(review)

        self._update_template_rating(template_id)

        if user_id not in self._user_ratings:
            self._user_ratings[user_id] = {}
        self._user_ratings[user_id][template_id] = rating

        self._save_data()

        return review

    async def get_reviews(
        self,
        template_id: str,
        page: int = 1,
        page_size: int = 10,
    ) -> Tuple[List[TemplateReview], int]:
        """Get reviews for template.

        Args:
            template_id: Template identifier.
            page: Page number.
            page_size: Items per page.

        Returns:
            Tuple of (reviews, total_count).
        """
        reviews = self._reviews.get(template_id, [])
        total_count = len(reviews)

        start_idx = (page - 1) * page_size
        end_idx = start_idx + page_size
        page_reviews = reviews[start_idx:end_idx]

        return page_reviews, total_count

    async def follow_template(self, template_id: str, user_id: str) -> bool:
        """Follow template for update notifications.

        Args:
            template_id: Template identifier.
            user_id: User identifier.

        Returns:
            True if followed successfully.
        """
        if user_id not in self._user_follows:
            self._user_follows[user_id] = []

        if template_id not in self._user_follows[user_id]:
            self._user_follows[user_id].append(template_id)
            self._save_data()
            return True

        return False

    async def unfollow_template(self, template_id: str, user_id: str) -> bool:
        """Unfollow template.

        Args:
            template_id: Template identifier.
            user_id: User identifier.

        Returns:
            True if unfollowed successfully.
        """
        if user_id in self._user_follows:
            if template_id in self._user_follows[user_id]:
                self._user_follows[user_id].remove(template_id)
                self._save_data()
                return True

        return False

    async def get_followed_templates(self, user_id: str) -> List[MarketplaceTemplate]:
        """Get templates followed by user.

        Args:
            user_id: User identifier.

        Returns:
            List of followed MarketplaceTemplate objects.
        """
        followed_ids = self._user_follows.get(user_id, [])
        return [
            self._templates[tid]
            for tid in followed_ids
            if tid in self._templates
        ]

    async def report_template(
        self,
        template_id: str,
        user_id: str,
        reason: str,
    ) -> bool:
        """Report template for review.

        Args:
            template_id: Template identifier.
            user_id: User identifier.
            reason: Report reason.

        Returns:
            True if reported successfully.
        """
        template = self._templates.get(template_id)
        if not template:
            return False

        template.report_count += 1

        if template.report_count >= 5:
            template.status = TemplateStatus.UNDER_REVIEW

        self._save_data()

        return True

    async def verify_template(self, template_id: str) -> bool:
        """Mark template as verified.

        Args:
            template_id: Template identifier.

        Returns:
            True if verified successfully.
        """
        template = self._templates.get(template_id)
        if not template:
            return False

        template.is_verified = True
        self._save_data()

        return True

    async def feature_template(self, template_id: str) -> bool:
        """Mark template as featured.

        Args:
            template_id: Template identifier.

        Returns:
            True if featured successfully.
        """
        template = self._templates.get(template_id)
        if not template:
            return False

        template.is_featured = True
        self._save_data()

        return True

    async def get_categories(self) -> List[Dict[str, Any]]:
        """Get template categories with counts.

        Returns:
            List of category info dicts.
        """
        category_counts: Dict[str, int] = {}

        for template in self._templates.values():
            cat = template.category.value
            category_counts[cat] = category_counts.get(cat, 0) + 1

        return [
            {"category": cat, "count": count}
            for cat, count in category_counts.items()
        ]

    async def get_popular_tags(self, limit: int = 20) -> List[Dict[str, Any]]:
        """Get popular tags.

        Args:
            limit: Maximum number of tags.

        Returns:
            List of tag count dicts.
        """
        tag_counts: Dict[str, int] = {}

        for template in self._templates.values():
            for tag in template.tags:
                tag_counts[tag] = tag_counts.get(tag, 0) + 1

        sorted_tags = sorted(tag_counts.items(), key=lambda x: x[1], reverse=True)

        return [{"tag": tag, "count": count} for tag, count in sorted_tags[:limit]]

    def _sort_templates(
        self,
        templates: List[MarketplaceTemplate],
        sort: SortOption,
    ) -> List[MarketplaceTemplate]:
        """Sort templates by option.

        Args:
            templates: Templates to sort.
            sort: Sort option.

        Returns:
            Sorted list of templates.
        """
        if sort == SortOption.NEWEST:
            return sorted(templates, key=lambda t: t.created_at, reverse=True)
        elif sort == SortOption.OLDEST:
            return sorted(templates, key=lambda t: t.created_at)
        elif sort == SortOption.RATING:
            return sorted(templates, key=lambda t: t.rating, reverse=True)
        elif sort == SortOption.DOWNLOADS:
            return sorted(templates, key=lambda t: t.download_count, reverse=True)
        elif sort == SortOption.NAME:
            return sorted(templates, key=lambda t: t.name.lower())
        elif sort == SortOption.DIFFICULTY:
            difficulty_order = {
                DifficultyLevel.BEGINNER: 0,
                DifficultyLevel.INTERMEDIATE: 1,
                DifficultyLevel.ADVANCED: 2,
                DifficultyLevel.EXPERT: 3,
            }
            return sorted(templates, key=lambda t: difficulty_order.get(t.difficulty, 0))

        return templates

    def _update_template_rating(self, template_id: str) -> None:
        """Update template average rating.

        Args:
            template_id: Template identifier.
        """
        reviews = self._reviews.get(template_id, [])
        if reviews:
            avg_rating = sum(r.rating for r in reviews) / len(reviews)
            template = self._templates.get(template_id)
            if template:
                template.rating = round(avg_rating, 1)
                template.review_count = len(reviews)

    def _load_data(self) -> None:
        """Load marketplace data from storage."""
        if not self.storage_path:
            return

        try:
            data_file = os.path.join(self.storage_path, "marketplace_data.json")
            if os.path.exists(data_file):
                with open(data_file, "r", encoding="utf-8") as f:
                    data = json.load(f)

                    for tpl_data in data.get("templates", []):
                        versions = []
                        for v_data in tpl_data.get("versions", []):
                            versions.append(TemplateVersion(
                                version=v_data.get("version", "1.0.0"),
                                release_date=v_data.get("release_date", 0.0),
                                changelog=v_data.get("changelog", ""),
                                is_current=v_data.get("is_current", False),
                                download_count=v_data.get("download_count", 0),
                            ))

                        template = MarketplaceTemplate(
                            template_id=tpl_data.get("template_id", ""),
                            name=tpl_data.get("name", ""),
                            description=tpl_data.get("description", ""),
                            author=tpl_data.get("author", ""),
                            author_id=tpl_data.get("author_id", ""),
                            category=TemplateCategory(tpl_data.get("category", "custom")),
                            platforms=[TargetPlatform(p) for p in tpl_data.get("platforms", [])],
                            difficulty=DifficultyLevel(tpl_data.get("difficulty", "beginner")),
                            tags=tpl_data.get("tags", []),
                            version=tpl_data.get("version", "1.0.0"),
                            versions=versions,
                            price=tpl_data.get("price", 0.0),
                            is_verified=tpl_data.get("is_verified", False),
                            rating=tpl_data.get("rating", 0.0),
                            review_count=tpl_data.get("review_count", 0),
                            download_count=tpl_data.get("download_count", 0),
                            view_count=tpl_data.get("view_count", 0),
                            created_at=tpl_data.get("created_at", 0.0),
                            updated_at=tpl_data.get("updated_at", 0.0),
                            status=TemplateStatus(tpl_data.get("status", "draft")),
                            preview_steps=tpl_data.get("preview_steps", []),
                            required_modules=tpl_data.get("required_modules", []),
                            estimated_time_minutes=tpl_data.get("estimated_time_minutes", 0),
                            is_featured=tpl_data.get("is_featured", False),
                            report_count=tpl_data.get("report_count", 0),
                        )

                        self._templates[template.template_id] = template

                    for template_id, reviews_data in data.get("reviews", {}).items():
                        reviews = []
                        for r_data in reviews_data:
                            reviews.append(TemplateReview(
                                review_id=r_data.get("review_id", ""),
                                template_id=r_data.get("template_id", ""),
                                user_id=r_data.get("user_id", ""),
                                username=r_data.get("username", ""),
                                rating=r_data.get("rating", 5),
                                comment=r_data.get("comment", ""),
                                created_at=r_data.get("created_at", 0.0),
                                is_verified_purchase=r_data.get("is_verified_purchase", False),
                                helpful_count=r_data.get("helpful_count", 0),
                            ))
                        self._reviews[template_id] = reviews

                    self._user_downloads = data.get("user_downloads", {})
                    self._user_follows = data.get("user_follows", {})
                    self._user_ratings = data.get("user_ratings", {})
                    self._installed_templates = data.get("installed_templates", {})

        except Exception as e:
            logger.error(f"Failed to load marketplace data: {e}")

    def _save_data(self) -> None:
        """Save marketplace data to storage."""
        if not self.storage_path:
            return

        try:
            data_file = os.path.join(self.storage_path, "marketplace_data.json")

            data = {
                "templates": [
                    {
                        "template_id": t.template_id,
                        "name": t.name,
                        "description": t.description,
                        "author": t.author,
                        "author_id": t.author_id,
                        "category": t.category.value,
                        "platforms": [p.value for p in t.platforms],
                        "difficulty": t.difficulty.value,
                        "tags": t.tags,
                        "version": t.version,
                        "versions": [
                            {
                                "version": v.version,
                                "release_date": v.release_date,
                                "changelog": v.changelog,
                                "is_current": v.is_current,
                                "download_count": v.download_count,
                            }
                            for v in t.versions
                        ],
                        "price": t.price,
                        "is_verified": t.is_verified,
                        "rating": t.rating,
                        "review_count": t.review_count,
                        "download_count": t.download_count,
                        "view_count": t.view_count,
                        "created_at": t.created_at,
                        "updated_at": t.updated_at,
                        "status": t.status.value,
                        "preview_steps": t.preview_steps,
                        "required_modules": t.required_modules,
                        "estimated_time_minutes": t.estimated_time_minutes,
                        "is_featured": t.is_featured,
                        "report_count": t.report_count,
                    }
                    for t in self._templates.values()
                ],
                "reviews": {
                    tid: [
                        {
                            "review_id": r.review_id,
                            "template_id": r.template_id,
                            "user_id": r.user_id,
                            "username": r.username,
                            "rating": r.rating,
                            "comment": r.comment,
                            "created_at": r.created_at,
                            "is_verified_purchase": r.is_verified_purchase,
                            "helpful_count": r.helpful_count,
                        }
                        for r in reviews
                    ]
                    for tid, reviews in self._reviews.items()
                },
                "user_downloads": self._user_downloads,
                "user_follows": self._user_follows,
                "user_ratings": self._user_ratings,
                "installed_templates": self._installed_templates,
            }

            with open(data_file, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)

        except Exception as e:
            logger.error(f"Failed to save marketplace data: {e}")
