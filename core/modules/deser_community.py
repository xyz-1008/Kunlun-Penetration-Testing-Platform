"""Community collaboration and sharing for Java deserialization exploitation.

Provides:
- Gadget chain sharing with voting mechanism
- Exploit script sharing with parameterization
- Vulnerability intelligence subscription
"""

import asyncio
import base64
import json
import logging
import secrets
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Coroutine, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


class ShareStatus(Enum):
    """Share status types."""
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    ARCHIVED = "archived"


class ContentType(Enum):
    """Content type for sharing."""
    GADGET_CHAIN = "gadget_chain"
    EXPLOIT_SCRIPT = "exploit_script"
    PAYLOAD_TEMPLATE = "payload_template"
    CASE_STUDY = "case_study"
    BYPASS_TECHNIQUE = "bypass_technique"


class SubscriptionType(Enum):
    """Subscription type for intelligence."""
    CVE_ALERTS = "cve_alerts"
    GADGET_UPDATES = "gadget_updates"
    SECURITY_ADVISORIES = "security_advisories"
    COMMUNITY_DIGEST = "community_digest"


@dataclass
class SharedGadgetChain:
    """Shared gadget chain data.

    Attributes:
        chain_id: Unique chain identifier
        name: Chain name
        description: Chain description
        author: Chain author
        dependencies: Required dependencies
        compatible_jdks: Compatible JDK versions
        payload_template: Payload template
        success_rate: Reported success rate
        vote_count: Vote count
        upvotes: Upvote count
        downvotes: Downvote count
        status: Share status
        created_date: Creation date
        tags: Tags for categorization
    """
    chain_id: str = ""
    name: str = ""
    description: str = ""
    author: str = ""
    dependencies: List[str] = field(default_factory=list)
    compatible_jdks: List[str] = field(default_factory=list)
    payload_template: bytes = b""
    success_rate: float = 0.0
    vote_count: int = 0
    upvotes: int = 0
    downvotes: int = 0
    status: ShareStatus = ShareStatus.PENDING
    created_date: str = ""
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "chain_id": self.chain_id,
            "name": self.name,
            "description": self.description,
            "author": self.author,
            "dependencies": self.dependencies,
            "compatible_jdks": self.compatible_jdks,
            "success_rate": self.success_rate,
            "vote_count": self.vote_count,
            "upvotes": self.upvotes,
            "downvotes": self.downvotes,
            "status": self.status.value,
            "tags": self.tags,
        }


@dataclass
class SharedExploitScript:
    """Shared exploit script data.

    Attributes:
        script_id: Unique script identifier
        title: Script title
        description: Script description
        author: Script author
        target_product: Target product
        target_version: Target version range
        parameters: Script parameters
        script_content: Script content
        language: Script language
        success_rate: Reported success rate
        vote_count: Vote count
        upvotes: Upvote count
        downvotes: Downvote count
        status: Share status
        created_date: Creation date
        tags: Tags for categorization
    """
    script_id: str = ""
    title: str = ""
    description: str = ""
    author: str = ""
    target_product: str = ""
    target_version: str = ""
    parameters: Dict[str, str] = field(default_factory=dict)
    script_content: str = ""
    language: str = "python"
    success_rate: float = 0.0
    vote_count: int = 0
    upvotes: int = 0
    downvotes: int = 0
    status: ShareStatus = ShareStatus.PENDING
    created_date: str = ""
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "script_id": self.script_id,
            "title": self.title,
            "description": self.description,
            "author": self.author,
            "target_product": self.target_product,
            "target_version": self.target_version,
            "parameters": self.parameters,
            "language": self.language,
            "success_rate": self.success_rate,
            "vote_count": self.vote_count,
            "upvotes": self.upvotes,
            "downvotes": self.downvotes,
            "status": self.status.value,
            "tags": self.tags,
        }


@dataclass
class CveIntelligence:
    """CVE intelligence data.

    Attributes:
        cve_id: CVE identifier
        title: Intelligence title
        severity: Severity level
        description: Intelligence description
        affected_products: Affected products
        exploit_available: Whether exploit available
        exploit_in_wild: Whether exploited in wild
        related_gadget_chains: Related gadget chains
        remediation: Remediation suggestions
        references: Reference URLs
        published_date: Publication date
        last_updated: Last update date
    """
    cve_id: str = ""
    title: str = ""
    severity: str = ""
    description: str = ""
    affected_products: List[str] = field(default_factory=list)
    exploit_available: bool = False
    exploit_in_wild: bool = False
    related_gadget_chains: List[str] = field(default_factory=list)
    remediation: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    published_date: str = ""
    last_updated: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "cve_id": self.cve_id,
            "title": self.title,
            "severity": self.severity,
            "description": self.description,
            "affected_products": self.affected_products,
            "exploit_available": self.exploit_available,
            "exploit_in_wild": self.exploit_in_wild,
            "related_gadget_chains": self.related_gadget_chains,
            "remediation": self.remediation,
            "published_date": self.published_date,
        }


@dataclass
class UserSubscription:
    """User subscription data.

    Attributes:
        user_id: User identifier
        subscription_types: Subscribed types
        notification_enabled: Whether notifications enabled
        email_notifications: Whether email notifications enabled
        last_notification_date: Last notification date
    """
    user_id: str = ""
    subscription_types: List[SubscriptionType] = field(default_factory=list)
    notification_enabled: bool = True
    email_notifications: bool = False
    last_notification_date: str = ""


@dataclass
class CommunityStats:
    """Community statistics.

    Attributes:
        total_chains: Total shared chains
        total_scripts: Total shared scripts
        total_users: Total community users
        total_votes: Total votes cast
        active_contributors: Active contributor count
        approved_content: Approved content count
        pending_content: Pending content count
    """
    total_chains: int = 0
    total_scripts: int = 0
    total_users: int = 0
    total_votes: int = 0
    active_contributors: int = 0
    approved_content: int = 0
    pending_content: int = 0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "total_chains": self.total_chains,
            "total_scripts": self.total_scripts,
            "total_users": self.total_users,
            "total_votes": self.total_votes,
            "active_contributors": self.active_contributors,
            "approved_content": self.approved_content,
            "pending_content": self.pending_content,
        }


class DeserCommunity:
    """Community collaboration and sharing platform.

    Provides gadget chain sharing, exploit script sharing,
    and vulnerability intelligence subscription.
    """

    def __init__(
        self,
        event_bus: Optional[Any] = None,
    ) -> None:
        """Initialize community platform.

        Args:
            event_bus: Event bus for broadcasting events.
        """
        self.event_bus = event_bus
        self._progress_callback: Optional[Callable[[str, float], Coroutine[Any, Any, None]]] = None
        self._log_callback: Optional[Callable[[str], Coroutine[Any, Any, None]]] = None
        self._shared_chains: Dict[str, SharedGadgetChain] = {}
        self._shared_scripts: Dict[str, SharedExploitScript] = {}
        self._cve_intelligence: Dict[str, CveIntelligence] = {}
        self._user_subscriptions: Dict[str, UserSubscription] = {}
        self._user_votes: Dict[str, Set[str]] = {}
        self._community_stats: CommunityStats = CommunityStats()

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
        logger.info("Community Progress: %.1f%% - %s", percentage, message)

    async def _report_log(self, message: str) -> None:
        """Report log via callback.

        Args:
            message: Log message.
        """
        if self._log_callback:
            await self._log_callback(message)
        logger.info("Community: %s", message)

    async def share_gadget_chain(
        self,
        chain: SharedGadgetChain,
    ) -> Optional[str]:
        """Share a gadget chain to community.

        Args:
            chain: Gadget chain to share.

        Returns:
            Chain ID or None if failed.
        """
        try:
            await self._report_progress("分享Gadget链", 10)

            if not chain.chain_id:
                chain.chain_id = f"chain_{int(time.time())}_{secrets.token_hex(4)}"

            if not chain.created_date:
                chain.created_date = time.strftime("%Y-%m-%d")

            chain.status = ShareStatus.PENDING
            self._shared_chains[chain.chain_id] = chain

            self._community_stats.total_chains += 1
            self._community_stats.pending_content += 1

            await self._report_log(f"Gadget链已分享: {chain.name}")
            await self._report_progress("完成", 100)

            if self.event_bus:
                await self.event_bus.broadcast("chain_shared", {
                    "chain_id": chain.chain_id,
                    "name": chain.name,
                    "author": chain.author,
                })

            return chain.chain_id

        except Exception as e:
            await self._report_log(f"Gadget链分享失败: {e}")
            logger.error("Gadget chain sharing failed: %s", e)
            return None

    async def share_exploit_script(
        self,
        script: SharedExploitScript,
    ) -> Optional[str]:
        """Share an exploit script to community.

        Args:
            script: Exploit script to share.

        Returns:
            Script ID or None if failed.
        """
        try:
            await self._report_progress("分享利用脚本", 10)

            if not script.script_id:
                script.script_id = f"script_{int(time.time())}_{secrets.token_hex(4)}"

            if not script.created_date:
                script.created_date = time.strftime("%Y-%m-%d")

            script.status = ShareStatus.PENDING
            self._shared_scripts[script.script_id] = script

            self._community_stats.total_scripts += 1
            self._community_stats.pending_content += 1

            await self._report_log(f"利用脚本已分享: {script.title}")
            await self._report_progress("完成", 100)

            if self.event_bus:
                await self.event_bus.broadcast("script_shared", {
                    "script_id": script.script_id,
                    "title": script.title,
                    "author": script.author,
                })

            return script.script_id

        except Exception as e:
            await self._report_log(f"利用脚本分享失败: {e}")
            logger.error("Exploit script sharing failed: %s", e)
            return None

    async def vote_content(
        self,
        user_id: str,
        content_type: ContentType,
        content_id: str,
        vote_up: bool = True,
    ) -> bool:
        """Vote on shared content.

        Args:
            user_id: User identifier.
            content_type: Content type.
            content_id: Content identifier.
            vote_up: True for upvote, False for downvote.

        Returns:
            True if vote succeeded.
        """
        try:
            if user_id not in self._user_votes:
                self._user_votes[user_id] = set()

            vote_key = f"{content_type.value}:{content_id}"
            if vote_key in self._user_votes[user_id]:
                return False

            if content_type == ContentType.GADGET_CHAIN:
                chain = self._shared_chains.get(content_id)
                if not chain:
                    return False

                if vote_up:
                    chain.upvotes += 1
                else:
                    chain.downvotes += 1
                chain.vote_count = chain.upvotes + chain.downvotes

            elif content_type == ContentType.EXPLOIT_SCRIPT:
                script = self._shared_scripts.get(content_id)
                if not script:
                    return False

                if vote_up:
                    script.upvotes += 1
                else:
                    script.downvotes += 1
                script.vote_count = script.upvotes + script.downvotes

            self._user_votes[user_id].add(vote_key)
            self._community_stats.total_votes += 1

            return True

        except Exception as e:
            logger.error("Voting failed: %s", e)
            return False

    async def get_top_chains(
        self,
        limit: int = 10,
        status_filter: Optional[ShareStatus] = None,
    ) -> List[SharedGadgetChain]:
        """Get top voted gadget chains.

        Args:
            limit: Maximum number of chains to return.
            status_filter: Filter by share status.

        Returns:
            List of top SharedGadgetChain.
        """
        chains = list(self._shared_chains.values())

        if status_filter:
            chains = [c for c in chains if c.status == status_filter]

        chains.sort(key=lambda c: c.upvotes - c.downvotes, reverse=True)

        return chains[:limit]

    async def get_top_scripts(
        self,
        limit: int = 10,
        status_filter: Optional[ShareStatus] = None,
    ) -> List[SharedExploitScript]:
        """Get top voted exploit scripts.

        Args:
            limit: Maximum number of scripts to return.
            status_filter: Filter by share status.

        Returns:
            List of top SharedExploitScript.
        """
        scripts = list(self._shared_scripts.values())

        if status_filter:
            scripts = [s for s in scripts if s.status == status_filter]

        scripts.sort(key=lambda s: s.upvotes - s.downvotes, reverse=True)

        return scripts[:limit]

    async def subscribe_to_intelligence(
        self,
        user_id: str,
        subscription_types: Optional[List[SubscriptionType]] = None,
        email_notifications: bool = False,
    ) -> bool:
        """Subscribe user to vulnerability intelligence.

        Args:
            user_id: User identifier.
            subscription_types: Types to subscribe to.
            email_notifications: Whether to enable email notifications.

        Returns:
            True if subscription succeeded.
        """
        try:
            await self._report_progress("订阅漏洞情报", 10)

            subscription = UserSubscription(
                user_id=user_id,
                subscription_types=subscription_types or [SubscriptionType.CVE_ALERTS],
                notification_enabled=True,
                email_notifications=email_notifications,
            )

            self._user_subscriptions[user_id] = subscription

            await self._report_log(f"用户 {user_id} 已订阅漏洞情报")
            await self._report_progress("完成", 100)

            return True

        except Exception as e:
            await self._report_log(f"订阅失败: {e}")
            logger.error("Intelligence subscription failed: %s", e)
            return False

    async def get_cve_intelligence(
        self,
        cve_id: str,
    ) -> Optional[CveIntelligence]:
        """Get CVE intelligence data.

        Args:
            cve_id: CVE identifier.

        Returns:
            CveIntelligence or None.
        """
        return self._cve_intelligence.get(cve_id)

    async def add_cve_intelligence(
        self,
        intelligence: CveIntelligence,
    ) -> bool:
        """Add CVE intelligence data.

        Args:
            intelligence: CVE intelligence data.

        Returns:
            True if added successfully.
        """
        try:
            if not intelligence.cve_id:
                return False

            if not intelligence.last_updated:
                intelligence.last_updated = time.strftime("%Y-%m-%d")

            self._cve_intelligence[intelligence.cve_id] = intelligence

            await self._notify_subscribers(
                SubscriptionType.CVE_ALERTS,
                {
                    "cve_id": intelligence.cve_id,
                    "title": intelligence.title,
                    "severity": intelligence.severity,
                },
            )

            return True

        except Exception as e:
            logger.error("Failed to add CVE intelligence: %s", e)
            return False

    async def get_user_subscriptions(
        self,
        user_id: str,
    ) -> Optional[UserSubscription]:
        """Get user subscription data.

        Args:
            user_id: User identifier.

        Returns:
            UserSubscription or None.
        """
        return self._user_subscriptions.get(user_id)

    async def get_community_stats(self) -> CommunityStats:
        """Get community statistics.

        Returns:
            CommunityStats.
        """
        self._community_stats.approved_content = sum(
            1 for c in self._shared_chains.values()
            if c.status == ShareStatus.APPROVED
        ) + sum(
            1 for s in self._shared_scripts.values()
            if s.status == ShareStatus.APPROVED
        )

        return self._community_stats

    async def search_shared_content(
        self,
        keyword: str,
        content_type: Optional[ContentType] = None,
    ) -> Dict[str, List[Any]]:
        """Search shared content by keyword.

        Args:
            keyword: Search keyword.
            content_type: Filter by content type.

        Returns:
            Dictionary of search results by type.
        """
        results: Dict[str, List[Any]] = {
            "chains": [],
            "scripts": [],
        }

        keyword_lower = keyword.lower()

        if content_type in (None, ContentType.GADGET_CHAIN):
            for chain in self._shared_chains.values():
                if (
                    keyword_lower in chain.name.lower()
                    or keyword_lower in chain.description.lower()
                    or any(keyword_lower in tag.lower() for tag in chain.tags)
                ):
                    results["chains"].append(chain.to_dict())

        if content_type in (None, ContentType.EXPLOIT_SCRIPT):
            for script in self._shared_scripts.values():
                if (
                    keyword_lower in script.title.lower()
                    or keyword_lower in script.description.lower()
                    or any(keyword_lower in tag.lower() for tag in script.tags)
                ):
                    results["scripts"].append(script.to_dict())

        return results

    async def _notify_subscribers(
        self,
        subscription_type: SubscriptionType,
        data: Dict[str, Any],
    ) -> None:
        """Notify subscribers of new intelligence.

        Args:
            subscription_type: Subscription type.
            data: Notification data.
        """
        try:
            for user_id, subscription in self._user_subscriptions.items():
                if (
                    subscription.notification_enabled
                    and subscription_type in subscription.subscription_types
                ):
                    if self.event_bus:
                        await self.event_bus.broadcast("intelligence_notification", {
                            "user_id": user_id,
                            "type": subscription_type.value,
                            "data": data,
                        })
        except Exception as e:
            logger.error("Subscriber notification failed: %s", e)

    async def export_community_data(self) -> Dict[str, Any]:
        """Export community data.

        Returns:
            Community data dictionary.
        """
        return {
            "chains": {k: v.to_dict() for k, v in self._shared_chains.items()},
            "scripts": {k: v.to_dict() for k, v in self._shared_scripts.items()},
            "cve_intelligence": {k: v.to_dict() for k, v in self._cve_intelligence.items()},
            "stats": self._community_stats.to_dict(),
        }
