"""Update UI: Update log display, settings panel, notification popups.

Provides:
- Update details panel with version info and Markdown changelog
- Settings panel for update configuration
- Notification popup for important updates
- History version changelog viewer
- Plugin update management UI
- Progress display for downloads and installations
"""

import asyncio
import logging
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Callable, Coroutine, Dict, List, Optional, Tuple

from .updater_checker import CheckResult, CheckStatus, UpdateChecker, UpdateNotification
from .updater_downloader import DownloadProgress, DownloadStatus, UpdateDownloader
from .updater_installer import BackupInfo, InstallProgress, InstallStatus, UpdateInstaller
from .updater_plugin import PluginInfo, PluginUpdateInfo, PluginUpdater, PluginUpdateProgress, PluginUpdateStatus
from .updater_version import ReleaseChannel, SemVer, UpdateSource, VersionManager, VersionMetadata

logger = logging.getLogger(__name__)


class UIPanel(Enum):
    """UI panel types."""
    SETTINGS = "settings"
    UPDATE_DETAILS = "update_details"
    NOTIFICATION = "notification"
    HISTORY = "history"
    PLUGIN_UPDATES = "plugin_updates"


@dataclass
class UpdateLogEntry:
    """Update log entry for display.

    Attributes:
        timestamp: Log timestamp
        action: Action performed (check/download/install/rollback)
        version: Version involved
        result: Result of action
        details: Additional details
    """
    timestamp: float = 0.0
    action: str = ""
    version: Optional[SemVer] = None
    result: str = ""
    details: str = ""


@dataclass
class NotificationAction:
    """Notification action button.

    Attributes:
        label: Button label
        action_id: Action identifier
        is_primary: Whether this is the primary action
    """
    label: str = ""
    action_id: str = ""
    is_primary: bool = False


class UpdateUIManager:
    """Manages update-related UI components.

    Provides update log display, settings panel, notification popups,
    and progress tracking for the update process.
    """

    def __init__(
        self,
        version_manager: VersionManager,
        update_checker: UpdateChecker,
        downloader: UpdateDownloader,
        installer: UpdateInstaller,
        plugin_updater: Optional[PluginUpdater] = None,
    ) -> None:
        """Initialize update UI manager.

        Args:
            version_manager: Version manager instance.
            update_checker: Update checker instance.
            downloader: Update downloader instance.
            installer: Update installer instance.
            plugin_updater: Optional plugin updater instance.
        """
        self.version_manager = version_manager
        self.update_checker = update_checker
        self.downloader = downloader
        self.installer = installer
        self.plugin_updater = plugin_updater

        self._log_entries: List[UpdateLogEntry] = []
        self._notification_callbacks: List[Callable[[str, Dict[str, Any]], Coroutine[Any, Any, None]]] = []
        self._current_panel: Optional[UIPanel] = None

    def register_notification_callback(
        self,
        callback: Callable[[str, Dict[str, Any]], Coroutine[Any, Any, None]],
    ) -> None:
        """Register callback for UI notifications.

        Args:
            callback: Async callback for UI notifications.
        """
        self._notification_callbacks.append(callback)

    async def show_update_notification(self, notification: UpdateNotification) -> None:
        """Display update notification popup.

        Args:
            notification: Update notification to display.
        """
        self._add_log_entry(
            action="notification",
            version=notification.version,
            result="shown",
            details=notification.title,
        )

        data = {
            "notification_id": notification.notification_id,
            "version": str(notification.version) if notification.version else "",
            "title": notification.title,
            "message": notification.message,
            "is_important": notification.is_important,
            "actions": [
                NotificationAction(label=action, action_id=action.lower().replace(" ", "_"))
                for action in notification.actions
            ],
        }

        await self._notify_ui("update_notification", data)

    async def show_settings_panel(self) -> Dict[str, Any]:
        """Generate settings panel data.

        Returns:
            Dictionary with settings panel data.
        """
        sources = self.version_manager.get_enabled_sources()

        return {
            "panel": UIPanel.SETTINGS.value,
            "current_version": str(self.version_manager.CURRENT_VERSION),
            "release_channel": self.update_checker.release_channel.value,
            "auto_check": self.update_checker.auto_check,
            "check_interval_hours": self.update_checker.check_interval / 3600,
            "update_sources": [
                {
                    "name": source.name,
                    "url": source.url,
                    "priority": source.priority,
                    "is_enabled": source.is_enabled,
                }
                for source in sources
            ],
            "last_check_time": self.update_checker.get_last_check_time(),
            "skipped_versions": [str(v) for v in self.update_checker._skipped_versions],
        }

    async def show_update_details(self, metadata: VersionMetadata) -> Dict[str, Any]:
        """Generate update details panel data.

        Args:
            metadata: Version metadata to display.

        Returns:
            Dictionary with update details data.
        """
        return {
            "panel": UIPanel.UPDATE_DETAILS.value,
            "version": str(metadata.version),
            "release_date": metadata.release_date,
            "release_channel": metadata.release_channel.value,
            "update_type": metadata.update_type.value,
            "is_force_update": metadata.is_force_update,
            "description": metadata.description,
            "file_size": self._format_file_size(metadata.file_size),
            "file_hash": metadata.file_hash[:16] + "..." if metadata.file_hash else "",
            "breaking_changes": metadata.breaking_changes,
        }

    async def show_history_panel(self) -> Dict[str, Any]:
        """Generate history panel data with update logs.

        Returns:
            Dictionary with history panel data.
        """
        return {
            "panel": UIPanel.HISTORY.value,
            "log_entries": [
                {
                    "timestamp": entry.timestamp,
                    "action": entry.action,
                    "version": str(entry.version) if entry.version else "",
                    "result": entry.result,
                    "details": entry.details,
                }
                for entry in self._log_entries
            ],
        }

    async def show_plugin_updates_panel(self) -> Dict[str, Any]:
        """Generate plugin updates panel data.

        Returns:
            Dictionary with plugin updates panel data.
        """
        if self.plugin_updater is None:
            return {"panel": UIPanel.PLUGIN_UPDATES.value, "plugins": [], "updates": {}}

        plugins = await self.plugin_updater.scan_installed_plugins()
        updates = await self.plugin_updater.check_plugin_updates()

        return {
            "panel": UIPanel.PLUGIN_UPDATES.value,
            "plugins": [
                {
                    "plugin_id": plugin.plugin_id,
                    "name": plugin.name,
                    "version": str(plugin.version) if plugin.version else "",
                    "is_enabled": plugin.is_enabled,
                }
                for plugin in plugins
            ],
            "updates": {
                plugin_id: {
                    "current_version": str(update.current_version) if update.current_version else "",
                    "latest_version": str(update.latest_version) if update.latest_version else "",
                    "release_notes": update.release_notes,
                    "is_compatible": update.is_compatible,
                }
                for plugin_id, update in updates.items()
            },
        }

    async def show_download_progress(self, progress: DownloadProgress) -> Dict[str, Any]:
        """Generate download progress display data.

        Args:
            progress: Current download progress.

        Returns:
            Dictionary with progress display data.
        """
        return {
            "type": "download_progress",
            "status": progress.status.value,
            "percentage": progress.percentage,
            "downloaded": self._format_file_size(progress.downloaded_bytes),
            "total": self._format_file_size(progress.total_bytes),
            "speed": f"{self._format_file_size(int(progress.speed_bytes_per_sec))}/s",
            "eta": self._format_eta(progress.eta_seconds),
        }

    async def show_install_progress(self, progress: InstallProgress) -> Dict[str, Any]:
        """Generate installation progress display data.

        Args:
            progress: Current installation progress.

        Returns:
            Dictionary with progress display data.
        """
        return {
            "type": "install_progress",
            "status": progress.status.value,
            "percentage": progress.percentage,
            "current_file": progress.current_file,
            "processed_files": progress.processed_files,
            "total_files": progress.total_files,
            "error_message": progress.error_message,
        }

    async def show_plugin_update_progress(self, progress: PluginUpdateProgress) -> Dict[str, Any]:
        """Generate plugin update progress display data.

        Args:
            progress: Current plugin update progress.

        Returns:
            Dictionary with progress display data.
        """
        return {
            "type": "plugin_update_progress",
            "plugin_id": progress.plugin_id,
            "status": progress.status.value,
            "percentage": progress.percentage,
            "error_message": progress.error_message,
        }

    async def show_rollback_panel(self, backups: List[BackupInfo]) -> Dict[str, Any]:
        """Generate rollback panel data with available backups.

        Args:
            backups: List of available backups.

        Returns:
            Dictionary with rollback panel data.
        """
        return {
            "panel": "rollback",
            "backups": [
                {
                    "backup_id": backup.backup_id,
                    "version": str(backup.version) if backup.version else "",
                    "backup_time": backup.backup_time,
                    "backup_size": self._format_file_size(backup.backup_size),
                    "file_count": backup.file_count,
                }
                for backup in backups
            ],
        }

    def _add_log_entry(
        self,
        action: str,
        version: Optional[SemVer] = None,
        result: str = "",
        details: str = "",
    ) -> None:
        """Add an entry to the update log.

        Args:
            action: Action performed.
            version: Version involved.
            result: Result of action.
            details: Additional details.
        """
        entry = UpdateLogEntry(
            timestamp=time.time(),
            action=action,
            version=version,
            result=result,
            details=details,
        )
        self._log_entries.append(entry)

    def _format_file_size(self, size_bytes: int) -> str:
        """Format file size for display.

        Args:
            size_bytes: Size in bytes.

        Returns:
            Formatted size string.
        """
        if size_bytes < 1024:
            return f"{size_bytes} B"
        elif size_bytes < 1024 * 1024:
            return f"{size_bytes / 1024:.1f} KB"
        elif size_bytes < 1024 * 1024 * 1024:
            return f"{size_bytes / (1024 * 1024):.1f} MB"
        else:
            return f"{size_bytes / (1024 * 1024 * 1024):.1f} GB"

    def _format_eta(self, seconds: float) -> str:
        """Format ETA for display.

        Args:
            seconds: Seconds remaining.

        Returns:
            Formatted ETA string.
        """
        if seconds < 60:
            return f"{int(seconds)}s"
        elif seconds < 3600:
            return f"{int(seconds / 60)}m {int(seconds % 60)}s"
        else:
            return f"{int(seconds / 3600)}h {int((seconds % 3600) / 60)}m"

    async def _notify_ui(self, event_type: str, data: Dict[str, Any]) -> None:
        """Send notification to UI.

        Args:
            event_type: Event type identifier.
            data: Event data.
        """
        for callback in self._notification_callbacks:
            try:
                await callback(event_type, data)
            except Exception as e:
                logger.error(f"UI notification callback error: {e}")
