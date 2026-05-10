"""Update Checker: Update checking, multi-source priority, notification alerts.

Provides:
- Automatic update checking on startup (configurable)
- Periodic checking every N hours
- Manual checking via settings panel
- Multi-source priority with automatic failover
- Notification alerts for important updates
- Release channel filtering (Stable/Beta/Dev)
"""

import asyncio
import json
import logging
import os
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Callable, Coroutine, Dict, List, Optional, Tuple

from .updater_version import (
    CompatibilityResult,
    CompatibilityStatus,
    ReleaseChannel,
    SemVer,
    UpdateSource,
    UpdateType,
    VersionManager,
    VersionMetadata,
)

logger = logging.getLogger(__name__)


class CheckStatus(Enum):
    """Status of update check operation."""
    SUCCESS = "success"
    NO_UPDATE = "no_update"
    NETWORK_ERROR = "network_error"
    SOURCE_ERROR = "source_error"
    PARSE_ERROR = "parse_error"


@dataclass
class CheckResult:
    """Result of an update check operation.

    Attributes:
        status: Check status
        current_version: Current version
        latest_version: Latest available version
        latest_metadata: Latest version metadata
        is_update_available: Whether update is available
        is_force_update: Whether update is mandatory
        check_time: Check timestamp
        error_message: Error message if check failed
    """
    status: CheckStatus = CheckStatus.SUCCESS
    current_version: Optional[SemVer] = None
    latest_version: Optional[SemVer] = None
    latest_metadata: Optional[VersionMetadata] = None
    is_update_available: bool = False
    is_force_update: bool = False
    check_time: float = 0.0
    error_message: str = ""


@dataclass
class UpdateNotification:
    """Update notification information.

    Attributes:
        notification_id: Unique notification identifier
        version: Available version
        title: Notification title
        message: Notification message
        is_important: Whether notification is important
        actions: Available user actions
        created_time: Notification creation timestamp
    """
    notification_id: str = ""
    version: Optional[SemVer] = None
    title: str = ""
    message: str = ""
    is_important: bool = False
    actions: List[str] = field(default_factory=list)
    created_time: float = 0.0


class UpdateChecker:
    """Checks for available updates from configured sources.

    Provides automatic and manual update checking with multi-source
    priority, release channel filtering, and notification generation.
    """

    def __init__(
        self,
        version_manager: VersionManager,
        current_version: Optional[SemVer] = None,
        release_channel: ReleaseChannel = ReleaseChannel.STABLE,
        auto_check: bool = True,
        check_interval: float = 86400.0,
    ) -> None:
        """Initialize update checker.

        Args:
            version_manager: Version manager instance.
            current_version: Current application version.
            release_channel: Release channel to check.
            auto_check: Whether to check automatically.
            check_interval: Interval between automatic checks in seconds.
        """
        self.version_manager = version_manager
        self.current_version = current_version or VersionManager.CURRENT_VERSION
        self.release_channel = release_channel
        self.auto_check = auto_check
        self.check_interval = check_interval

        self._last_check_time: float = 0.0
        self._check_task: Optional[asyncio.Task[None]] = None
        self._notification_callbacks: List[Callable[[UpdateNotification], Coroutine[Any, Any, None]]] = []
        self._skipped_versions: List[SemVer] = []

    def register_notification_callback(
        self,
        callback: Callable[[UpdateNotification], Coroutine[Any, Any, None]],
    ) -> None:
        """Register callback for update notifications.

        Args:
            callback: Async callback for notifications.
        """
        self._notification_callbacks.append(callback)

    def skip_version(self, version: SemVer) -> None:
        """Mark a version to be skipped in notifications.

        Args:
            version: Version to skip.
        """
        if version not in self._skipped_versions:
            self._skipped_versions.append(version)

    async def check_for_updates(self) -> CheckResult:
        """Check for available updates from all configured sources.

        Returns:
            CheckResult with update information.
        """
        result = CheckResult(
            current_version=self.current_version,
            check_time=time.time(),
        )

        sources = self.version_manager.get_enabled_sources()

        if not sources:
            result.status = CheckStatus.SOURCE_ERROR
            result.error_message = "No update sources configured"
            return result

        for source in sources:
            try:
                metadata = await self._fetch_version_metadata(source)

                if metadata is None:
                    continue

                if metadata.release_channel.value > self.release_channel.value:
                    continue

                if metadata.version <= self.current_version:
                    continue

                if metadata.version in self._skipped_versions:
                    continue

                result.latest_version = metadata.version
                result.latest_metadata = metadata
                result.is_update_available = True
                result.is_force_update = metadata.is_force_update
                result.status = CheckStatus.SUCCESS

                self.version_manager.cache_version_metadata(
                    metadata.version, metadata
                )

                if result.is_update_available:
                    await self._send_notification(result)

                source.last_check_time = time.time()
                self._last_check_time = time.time()

                return result

            except Exception as e:
                logger.warning(f"Failed to check source {source.name}: {e}")
                continue

        result.status = CheckStatus.NO_UPDATE
        self._last_check_time = time.time()

        return result

    async def check_for_updates_manual(self) -> CheckResult:
        """Perform a manual update check.

        Returns:
            CheckResult with update information.
        """
        return await self.check_for_updates()

    async def start_auto_check(self) -> None:
        """Start automatic update checking."""
        if self._check_task is not None:
            return

        if not self.auto_check:
            return

        self._check_task = asyncio.create_task(self._auto_check_loop())

    async def stop_auto_check(self) -> None:
        """Stop automatic update checking."""
        if self._check_task is not None:
            self._check_task.cancel()
            try:
                await self._check_task
            except asyncio.CancelledError:
                pass
            self._check_task = None

    async def _auto_check_loop(self) -> None:
        """Run automatic update checking loop."""
        while True:
            try:
                await asyncio.sleep(self.check_interval)
                await self.check_for_updates()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Auto check error: {e}")
                await asyncio.sleep(60)

    async def _fetch_version_metadata(
        self,
        source: UpdateSource,
    ) -> Optional[VersionMetadata]:
        """Fetch version metadata from an update source.

        Args:
            source: Update source to fetch from.

        Returns:
            VersionMetadata or None.
        """
        if source.url.startswith("http://") or source.url.startswith("https://"):
            return await self._fetch_from_http(source)
        elif source.url.startswith("file://") or os.path.isabs(source.url):
            return await self._fetch_from_file(source)

        return None

    async def _fetch_from_http(
        self,
        source: UpdateSource,
    ) -> Optional[VersionMetadata]:
        """Fetch metadata from HTTP source.

        Args:
            source: Update source.

        Returns:
            VersionMetadata or None.
        """
        try:
            import aiohttp

            url = f"{source.url}/version.json"

            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as response:
                    if response.status != 200:
                        return None

                    data = await response.text()
                    return self.version_manager.deserialize_metadata(data)

        except ImportError:
            logger.warning("aiohttp not available for HTTP update checking")
            return None
        except Exception as e:
            logger.warning(f"HTTP fetch failed: {e}")
            return None

    async def _fetch_from_file(
        self,
        source: UpdateSource,
    ) -> Optional[VersionMetadata]:
        """Fetch metadata from local file source.

        Args:
            source: Update source.

        Returns:
            VersionMetadata or None.
        """
        try:
            file_path = source.url.replace("file://", "")

            if not os.path.exists(file_path):
                return None

            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()

            return self.version_manager.deserialize_metadata(content)

        except Exception as e:
            logger.warning(f"File fetch failed: {e}")
            return None

    async def _send_notification(self, result: CheckResult) -> None:
        """Send update notification to registered callbacks.

        Args:
            result: Check result with update information.
        """
        if result.latest_metadata is None:
            return

        notification = UpdateNotification(
            notification_id=f"notif_{int(time.time())}",
            version=result.latest_version,
            title=f"New version available: {result.latest_version}",
            message=result.latest_metadata.description[:200],
            is_important=result.is_force_update,
            actions=["Update Now", "Remind Later", "Skip This Version"],
            created_time=time.time(),
        )

        for callback in self._notification_callbacks:
            try:
                await callback(notification)
            except Exception as e:
                logger.error(f"Notification callback error: {e}")

    def get_last_check_time(self) -> float:
        """Get timestamp of last update check.

        Returns:
            Last check timestamp.
        """
        return self._last_check_time

    def should_check_now(self) -> bool:
        """Check if it's time for an automatic update check.

        Returns:
            True if check should be performed.
        """
        if not self.auto_check:
            return False

        time_since_last = time.time() - self._last_check_time
        return time_since_last >= self.check_interval
