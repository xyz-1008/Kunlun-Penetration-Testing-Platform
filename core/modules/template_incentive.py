"""Template Incentive: Points system, level hierarchy, and monetization mechanism.

Provides:
- Points earning: publishing templates, template likes, template downloads, submitting vulnerability reports, helping other users
- Level system: Bronze → Silver → Gold → Platinum → Diamond → King
- High-level user privileges: priority review, official certification label, more exposure recommendations
- Monetization: paid templates (30% platform commission), free trial (first 3 steps), tipping, enterprise bounties
- Contributor growth: new author → certified author → official partner → core contributor
"""

import asyncio
import json
import logging
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum, auto
from typing import Any, Callable, Coroutine, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class UserLevel(Enum):
    """User level hierarchy."""
    BRONZE = "bronze"
    SILVER = "silver"
    GOLD = "gold"
    PLATINUM = "platinum"
    DIAMOND = "diamond"
    KING = "king"


class ContributorTier(Enum):
    """Contributor growth tiers."""
    NEW_AUTHOR = "new_author"
    CERTIFIED_AUTHOR = "certified_author"
    OFFICIAL_PARTNER = "official_partner"
    CORE_CONTRIBUTOR = "core_contributor"


class PointsSource(Enum):
    """Points earning sources."""
    PUBLISH_TEMPLATE = "publish_template"
    TEMPLATE_LIKED = "template_liked"
    TEMPLATE_DOWNLOADED = "template_downloaded"
    SUBMIT_REPORT = "submit_report"
    HELP_USER = "help_user"
    RECEIVE_TIP = "receive_tip"
    VALIDATE_TEMPLATE = "validate_template"
    REVIEW_TEMPLATE = "review_template"
    DAILY_LOGIN = "daily_login"
    ACHIEVEMENT = "achievement"


@dataclass
class PointsTransaction:
    """Single points transaction.

    Attributes:
        transaction_id: Unique transaction identifier
        user_id: User identifier
        source: Points source
        amount: Points amount (positive for earn, negative for spend)
        description: Transaction description
        related_id: Related entity ID (template, report, etc.)
        timestamp: Transaction timestamp
        balance_after: User balance after transaction
    """
    transaction_id: str = ""
    user_id: str = ""
    source: PointsSource = PointsSource.DAILY_LOGIN
    amount: int = 0
    description: str = ""
    related_id: str = ""
    timestamp: float = 0.0
    balance_after: int = 0


@dataclass
class UserPoints:
    """User points information.

    Attributes:
        user_id: User identifier
        username: User display name
        total_points: Total accumulated points
        current_balance: Current spendable balance
        level: User level
        contributor_tier: Contributor tier
        templates_published: Number of templates published
        templates_downloaded: Total downloads of user's templates
        templates_verified: Number of verified templates
        total_reviews: Number of reviews written
        total_tips_received: Total tips received
        join_date: User join timestamp
        last_login: Last login timestamp
        is_certified: Whether user has official certification
        is_core_contributor: Whether user is core contributor
    """
    user_id: str = ""
    username: str = ""
    total_points: int = 0
    current_balance: int = 0
    level: UserLevel = UserLevel.BRONZE
    contributor_tier: ContributorTier = ContributorTier.NEW_AUTHOR
    templates_published: int = 0
    templates_downloaded: int = 0
    templates_verified: int = 0
    total_reviews: int = 0
    total_tips_received: int = 0
    join_date: float = 0.0
    last_login: float = 0.0
    is_certified: bool = False
    is_core_contributor: bool = False


@dataclass
class TemplatePricing:
    """Template pricing information.

    Attributes:
        template_id: Template identifier
        author_id: Author user ID
        price: Template price in points
        is_paid: Whether template is paid
        platform_commission_rate: Platform commission rate (default 30%)
        author_earnings: Total author earnings from this template
        total_sales: Total number of sales
        free_trial_steps: Number of free trial steps
        is_on_sale: Whether template is on sale
        sale_price: Sale price (if on sale)
    """
    template_id: str = ""
    author_id: str = ""
    price: int = 0
    is_paid: bool = False
    platform_commission_rate: float = 0.3
    author_earnings: int = 0
    total_sales: int = 0
    free_trial_steps: int = 3
    is_on_sale: bool = False
    sale_price: int = 0


Tip = Dict[str, Any]


@dataclass
class BountyTask:
    """Enterprise bounty task.

    Attributes:
        task_id: Unique task identifier
        title: Task title
        description: Task description
        enterprise_id: Enterprise user ID
        reward_points: Reward points
        deadline: Task deadline
        status: Task status
        assigned_to: Assigned user ID
        submitted_solution: Submitted solution
        is_completed: Whether task is completed
        created_at: Creation timestamp
        completed_at: Completion timestamp
    """
    task_id: str = ""
    title: str = ""
    description: str = ""
    enterprise_id: str = ""
    reward_points: int = 0
    deadline: float = 0.0
    status: str = "open"
    assigned_to: str = ""
    submitted_solution: str = ""
    is_completed: bool = False
    created_at: float = 0.0
    completed_at: float = 0.0


class TemplateIncentive:
    """Incentive system for template marketplace contributors.

    Manages points, levels, monetization, and contributor growth
    to encourage community participation and quality content.
    """

    LEVEL_THRESHOLDS = {
        UserLevel.BRONZE: 0,
        UserLevel.SILVER: 1000,
        UserLevel.GOLD: 5000,
        UserLevel.PLATINUM: 15000,
        UserLevel.DIAMOND: 50000,
        UserLevel.KING: 100000,
    }

    CONTRIBUTOR_TIER_REQUIREMENTS = {
        ContributorTier.NEW_AUTHOR: {"templates": 0, "points": 0},
        ContributorTier.CERTIFIED_AUTHOR: {"templates": 5, "points": 2000},
        ContributorTier.OFFICIAL_PARTNER: {"templates": 15, "points": 10000, "verified": 3},
        ContributorTier.CORE_CONTRIBUTOR: {"templates": 30, "points": 30000, "verified": 10},
    }

    POINTS_REWARDS = {
        PointsSource.PUBLISH_TEMPLATE: 100,
        PointsSource.TEMPLATE_LIKED: 10,
        PointsSource.TEMPLATE_DOWNLOADED: 20,
        PointsSource.SUBMIT_REPORT: 50,
        PointsSource.HELP_USER: 30,
        PointsSource.RECEIVE_TIP: 1,
        PointsSource.VALIDATE_TEMPLATE: 75,
        PointsSource.REVIEW_TEMPLATE: 15,
        PointsSource.DAILY_LOGIN: 5,
        PointsSource.ACHIEVEMENT: 200,
    }

    def __init__(self, storage_path: str = "") -> None:
        """Initialize template incentive system.

        Args:
            storage_path: Directory path for incentive storage.
        """
        self.storage_path = storage_path
        self._user_points: Dict[str, UserPoints] = {}
        self._transactions: Dict[str, List[PointsTransaction]] = {}
        self._template_pricing: Dict[str, TemplatePricing] = {}
        self._tips: Dict[str, List[Dict[str, Any]]] = {}
        self._bounty_tasks: Dict[str, BountyTask] = {}

        if storage_path:
            os.makedirs(storage_path, exist_ok=True)
            self._load_data()

    async def register_user(
        self,
        user_id: str,
        username: str,
    ) -> UserPoints:
        """Register new user in incentive system.

        Args:
            user_id: User identifier.
            username: User display name.

        Returns:
            Created UserPoints.
        """
        now = time.time()

        user_points = UserPoints(
            user_id=user_id,
            username=username,
            join_date=now,
            last_login=now,
        )

        self._user_points[user_id] = user_points
        self._transactions[user_id] = []

        self._save_data()

        return user_points

    async def get_user_points(self, user_id: str) -> Optional[UserPoints]:
        """Get user points information.

        Args:
            user_id: User identifier.

        Returns:
            UserPoints or None.
        """
        return self._user_points.get(user_id)

    async def award_points(
        self,
        user_id: str,
        source: PointsSource,
        amount: int = 0,
        description: str = "",
        related_id: str = "",
    ) -> Optional[PointsTransaction]:
        """Award points to user.

        Args:
            user_id: User identifier.
            source: Points source.
            amount: Points amount (0 for default).
            description: Transaction description.
            related_id: Related entity ID.

        Returns:
            Created PointsTransaction or None.
        """
        user = self._user_points.get(user_id)
        if not user:
            return None

        points = amount if amount > 0 else self.POINTS_REWARDS.get(source, 0)

        user.total_points += points
        user.current_balance += points

        transaction_id = f"txn_{user_id}_{int(time.time())}"

        transaction = PointsTransaction(
            transaction_id=transaction_id,
            user_id=user_id,
            source=source,
            amount=points,
            description=description or source.value,
            related_id=related_id,
            timestamp=time.time(),
            balance_after=user.current_balance,
        )

        if user_id not in self._transactions:
            self._transactions[user_id] = []

        self._transactions[user_id].append(transaction)

        self._update_user_level(user)
        self._update_contributor_tier(user)

        self._save_data()

        return transaction

    async def spend_points(
        self,
        user_id: str,
        amount: int,
        description: str = "",
        related_id: str = "",
    ) -> bool:
        """Spend user points.

        Args:
            user_id: User identifier.
            amount: Points to spend.
            description: Transaction description.
            related_id: Related entity ID.

        Returns:
            True if spent successfully.
        """
        user = self._user_points.get(user_id)
        if not user or user.current_balance < amount:
            return False

        user.current_balance -= amount

        transaction_id = f"txn_{user_id}_{int(time.time())}"

        transaction = PointsTransaction(
            transaction_id=transaction_id,
            user_id=user_id,
            source=PointsSource.TEMPLATE_DOWNLOADED,
            amount=-amount,
            description=description,
            related_id=related_id,
            timestamp=time.time(),
            balance_after=user.current_balance,
        )

        if user_id not in self._transactions:
            self._transactions[user_id] = []

        self._transactions[user_id].append(transaction)

        self._save_data()

        return True

    async def set_template_price(
        self,
        template_id: str,
        author_id: str,
        price: int,
        free_trial_steps: int = 3,
    ) -> Optional[TemplatePricing]:
        """Set template price.

        Args:
            template_id: Template identifier.
            author_id: Author user ID.
            price: Template price in points.
            free_trial_steps: Number of free trial steps.

        Returns:
            Created TemplatePricing or None.
        """
        if price < 0:
            return None

        pricing = TemplatePricing(
            template_id=template_id,
            author_id=author_id,
            price=price,
            is_paid=price > 0,
            free_trial_steps=free_trial_steps,
        )

        self._template_pricing[template_id] = pricing
        self._save_data()

        return pricing

    async def purchase_template(
        self,
        template_id: str,
        buyer_id: str,
    ) -> bool:
        """Purchase template with points.

        Args:
            template_id: Template identifier.
            buyer_id: Buyer user ID.

        Returns:
            True if purchased successfully.
        """
        pricing = self._template_pricing.get(template_id)
        if not pricing or not pricing.is_paid:
            return False

        price = pricing.sale_price if pricing.is_on_sale else pricing.price

        if not await self.spend_points(buyer_id, price, f"Purchase template {template_id}", template_id):
            return False

        author_earnings = int(price * (1 - pricing.platform_commission_rate))

        await self.award_points(
            pricing.author_id,
            PointsSource.TEMPLATE_DOWNLOADED,
            author_earnings,
            f"Template sale: {template_id}",
            template_id,
        )

        pricing.total_sales += 1
        pricing.author_earnings += author_earnings

        self._save_data()

        return True

    async def send_tip(
        self,
        template_id: str,
        from_user_id: str,
        to_user_id: str,
        amount: int,
    ) -> bool:
        """Send tip to template author.

        Args:
            template_id: Template identifier.
            from_user_id: Tip sender user ID.
            to_user_id: Tip receiver user ID.
            amount: Tip amount in points.

        Returns:
            True if tipped successfully.
        """
        if not await self.spend_points(from_user_id, amount, f"Tip for template {template_id}", template_id):
            return False

        await self.award_points(
            to_user_id,
            PointsSource.RECEIVE_TIP,
            amount,
            f"Received tip for template {template_id}",
            template_id,
        )

        to_user = self._user_points.get(to_user_id)
        if to_user:
            to_user.total_tips_received += 1

        tip_id = f"tip_{template_id}_{from_user_id}_{int(time.time())}"

        if template_id not in self._tips:
            self._tips[template_id] = []

        self._tips[template_id].append({
            "tip_id": tip_id,
            "from_user_id": from_user_id,
            "to_user_id": to_user_id,
            "amount": amount,
            "timestamp": time.time(),
        })

        self._save_data()

        return True

    async def create_bounty_task(
        self,
        title: str,
        description: str,
        enterprise_id: str,
        reward_points: int,
        deadline_days: int = 30,
    ) -> Optional[BountyTask]:
        """Create enterprise bounty task.

        Args:
            title: Task title.
            description: Task description.
            enterprise_id: Enterprise user ID.
            reward_points: Reward points.
            deadline_days: Task deadline in days.

        Returns:
            Created BountyTask or None.
        """
        task_id = f"bounty_{int(time.time())}"

        task = BountyTask(
            task_id=task_id,
            title=title,
            description=description,
            enterprise_id=enterprise_id,
            reward_points=reward_points,
            deadline=time.time() + (deadline_days * 86400),
            created_at=time.time(),
        )

        self._bounty_tasks[task_id] = task
        self._save_data()

        return task

    async def assign_bounty_task(
        self,
        task_id: str,
        user_id: str,
    ) -> bool:
        """Assign bounty task to user.

        Args:
            task_id: Task identifier.
            user_id: User identifier.

        Returns:
            True if assigned successfully.
        """
        task = self._bounty_tasks.get(task_id)
        if not task or task.status != "open":
            return False

        task.assigned_to = user_id
        task.status = "in_progress"
        self._save_data()

        return True

    async def complete_bounty_task(
        self,
        task_id: str,
        solution: str,
    ) -> bool:
        """Complete bounty task.

        Args:
            task_id: Task identifier.
            solution: Submitted solution.

        Returns:
            True if completed successfully.
        """
        task = self._bounty_tasks.get(task_id)
        if not task or task.status != "in_progress":
            return False

        task.submitted_solution = solution
        task.is_completed = True
        task.status = "completed"
        task.completed_at = time.time()

        if task.assigned_to:
            await self.award_points(
                task.assigned_to,
                PointsSource.SUBMIT_REPORT,
                task.reward_points,
                f"Bounty task completed: {task.title}",
                task_id,
            )

        self._save_data()

        return True

    async def get_leaderboard(
        self,
        limit: int = 20,
    ) -> List[Dict[str, Any]]:
        """Get points leaderboard.

        Args:
            limit: Maximum number of users.

        Returns:
            List of user ranking dicts.
        """
        sorted_users = sorted(
            self._user_points.values(),
            key=lambda u: u.total_points,
            reverse=True,
        )

        return [
            {
                "rank": i + 1,
                "user_id": u.user_id,
                "username": u.username,
                "total_points": u.total_points,
                "level": u.level.value,
                "contributor_tier": u.contributor_tier.value,
                "templates_published": u.templates_published,
                "templates_downloaded": u.templates_downloaded,
            }
            for i, u in enumerate(sorted_users[:limit])
        ]

    async def get_user_transactions(
        self,
        user_id: str,
        page: int = 1,
        page_size: int = 20,
    ) -> Tuple[List[PointsTransaction], int]:
        """Get user transaction history.

        Args:
            user_id: User identifier.
            page: Page number.
            page_size: Items per page.

        Returns:
            Tuple of (transactions, total_count).
        """
        transactions = self._transactions.get(user_id, [])
        total_count = len(transactions)

        start_idx = (page - 1) * page_size
        end_idx = start_idx + page_size
        page_transactions = transactions[start_idx:end_idx]

        return page_transactions, total_count

    async def certify_user(self, user_id: str) -> bool:
        """Certify user with official label.

        Args:
            user_id: User identifier.

        Returns:
            True if certified successfully.
        """
        user = self._user_points.get(user_id)
        if not user:
            return False

        user.is_certified = True
        self._save_data()

        return True

    async def promote_to_core_contributor(self, user_id: str) -> bool:
        """Promote user to core contributor.

        Args:
            user_id: User identifier.

        Returns:
            True if promoted successfully.
        """
        user = self._user_points.get(user_id)
        if not user:
            return False

        user.is_core_contributor = True
        user.contributor_tier = ContributorTier.CORE_CONTRIBUTOR
        self._save_data()

        return True

    def _update_user_level(self, user: UserPoints) -> None:
        """Update user level based on total points.

        Args:
            user: User points to update.
        """
        for level in reversed(list(UserLevel)):
            threshold = self.LEVEL_THRESHOLDS.get(level, 0)
            if user.total_points >= threshold:
                user.level = level
                break

    def _update_contributor_tier(self, user: UserPoints) -> None:
        """Update contributor tier based on achievements.

        Args:
            user: User points to update.
        """
        for tier in reversed(list(ContributorTier)):
            requirements = self.CONTRIBUTOR_TIER_REQUIREMENTS.get(tier, {})

            if user.templates_published >= requirements.get("templates", 0):
                if user.total_points >= requirements.get("points", 0):
                    if user.templates_verified >= requirements.get("verified", 0):
                        user.contributor_tier = tier
                        break

    def _load_data(self) -> None:
        """Load incentive data from storage."""
        if not self.storage_path:
            return

        try:
            data_file = os.path.join(self.storage_path, "incentive_data.json")
            if os.path.exists(data_file):
                with open(data_file, "r", encoding="utf-8") as f:
                    data = json.load(f)

                    for user_data in data.get("user_points", []):
                        user = UserPoints(
                            user_id=user_data.get("user_id", ""),
                            username=user_data.get("username", ""),
                            total_points=user_data.get("total_points", 0),
                            current_balance=user_data.get("current_balance", 0),
                            level=UserLevel(user_data.get("level", "bronze")),
                            contributor_tier=ContributorTier(user_data.get("contributor_tier", "new_author")),
                            templates_published=user_data.get("templates_published", 0),
                            templates_downloaded=user_data.get("templates_downloaded", 0),
                            templates_verified=user_data.get("templates_verified", 0),
                            total_reviews=user_data.get("total_reviews", 0),
                            total_tips_received=user_data.get("total_tips_received", 0),
                            join_date=user_data.get("join_date", 0.0),
                            last_login=user_data.get("last_login", 0.0),
                            is_certified=user_data.get("is_certified", False),
                            is_core_contributor=user_data.get("is_core_contributor", False),
                        )

                        self._user_points[user.user_id] = user

                    for user_id, txns in data.get("transactions", {}).items():
                        transactions = []
                        for txn_data in txns:
                            transactions.append(PointsTransaction(
                                transaction_id=txn_data.get("transaction_id", ""),
                                user_id=txn_data.get("user_id", ""),
                                source=PointsSource(txn_data.get("source", "daily_login")),
                                amount=txn_data.get("amount", 0),
                                description=txn_data.get("description", ""),
                                related_id=txn_data.get("related_id", ""),
                                timestamp=txn_data.get("timestamp", 0.0),
                                balance_after=txn_data.get("balance_after", 0),
                            ))
                        self._transactions[user_id] = transactions

                    for pricing_data in data.get("template_pricing", []):
                        pricing = TemplatePricing(
                            template_id=pricing_data.get("template_id", ""),
                            author_id=pricing_data.get("author_id", ""),
                            price=pricing_data.get("price", 0),
                            is_paid=pricing_data.get("is_paid", False),
                            platform_commission_rate=pricing_data.get("platform_commission_rate", 0.3),
                            author_earnings=pricing_data.get("author_earnings", 0),
                            total_sales=pricing_data.get("total_sales", 0),
                            free_trial_steps=pricing_data.get("free_trial_steps", 3),
                            is_on_sale=pricing_data.get("is_on_sale", False),
                            sale_price=pricing_data.get("sale_price", 0),
                        )

                        self._template_pricing[pricing.template_id] = pricing

                    self._tips = data.get("tips", {})

                    for task_data in data.get("bounty_tasks", []):
                        task = BountyTask(
                            task_id=task_data.get("task_id", ""),
                            title=task_data.get("title", ""),
                            description=task_data.get("description", ""),
                            enterprise_id=task_data.get("enterprise_id", ""),
                            reward_points=task_data.get("reward_points", 0),
                            deadline=task_data.get("deadline", 0.0),
                            status=task_data.get("status", "open"),
                            assigned_to=task_data.get("assigned_to", ""),
                            submitted_solution=task_data.get("submitted_solution", ""),
                            is_completed=task_data.get("is_completed", False),
                            created_at=task_data.get("created_at", 0.0),
                            completed_at=task_data.get("completed_at", 0.0),
                        )

                        self._bounty_tasks[task.task_id] = task

        except Exception as e:
            logger.error(f"Failed to load incentive data: {e}")

    def _save_data(self) -> None:
        """Save incentive data to storage."""
        if not self.storage_path:
            return

        try:
            data_file = os.path.join(self.storage_path, "incentive_data.json")

            data = {
                "user_points": [
                    {
                        "user_id": u.user_id,
                        "username": u.username,
                        "total_points": u.total_points,
                        "current_balance": u.current_balance,
                        "level": u.level.value,
                        "contributor_tier": u.contributor_tier.value,
                        "templates_published": u.templates_published,
                        "templates_downloaded": u.templates_downloaded,
                        "templates_verified": u.templates_verified,
                        "total_reviews": u.total_reviews,
                        "total_tips_received": u.total_tips_received,
                        "join_date": u.join_date,
                        "last_login": u.last_login,
                        "is_certified": u.is_certified,
                        "is_core_contributor": u.is_core_contributor,
                    }
                    for u in self._user_points.values()
                ],
                "transactions": {
                    uid: [
                        {
                            "transaction_id": t.transaction_id,
                            "user_id": t.user_id,
                            "source": t.source.value,
                            "amount": t.amount,
                            "description": t.description,
                            "related_id": t.related_id,
                            "timestamp": t.timestamp,
                            "balance_after": t.balance_after,
                        }
                        for t in txns
                    ]
                    for uid, txns in self._transactions.items()
                },
                "template_pricing": [
                    {
                        "template_id": p.template_id,
                        "author_id": p.author_id,
                        "price": p.price,
                        "is_paid": p.is_paid,
                        "platform_commission_rate": p.platform_commission_rate,
                        "author_earnings": p.author_earnings,
                        "total_sales": p.total_sales,
                        "free_trial_steps": p.free_trial_steps,
                        "is_on_sale": p.is_on_sale,
                        "sale_price": p.sale_price,
                    }
                    for p in self._template_pricing.values()
                ],
                "tips": self._tips,
                "bounty_tasks": [
                    {
                        "task_id": t.task_id,
                        "title": t.title,
                        "description": t.description,
                        "enterprise_id": t.enterprise_id,
                        "reward_points": t.reward_points,
                        "deadline": t.deadline,
                        "status": t.status,
                        "assigned_to": t.assigned_to,
                        "submitted_solution": t.submitted_solution,
                        "is_completed": t.is_completed,
                        "created_at": t.created_at,
                        "completed_at": t.completed_at,
                    }
                    for t in self._bounty_tasks.values()
                ],
            }

            with open(data_file, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)

        except Exception as e:
            logger.error(f"Failed to save incentive data: {e}")
