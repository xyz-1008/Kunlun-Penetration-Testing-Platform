"""Plugin Updater: Independent plugin update management.

Provides:
- Independent version management for each plugin (SemVer)
- Plugin compatibility declaration with main program version range
- Plugin update without affecting main program or other plugins
- Batch update for all plugins
- Plugin rollback on failure or compatibility issues
- Plugin marketplace integration for version checking
"""

import asyncio
import json
import logging
import os
import shutil
import time
import zipfile
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Callable, Coroutine, Dict, List, Optional, Tuple

from .updater_version import SemVer, VersionManager

logger = logging.getLogger(__name__)


class PluginUpdateStatus(Enum):
    """Status of plugin update operation."""
    PENDING = "pending"
    CHECKING = "checking"
    DOWNLOADING = "downloading"
    INSTALLING = "installing"
    COMPLETED = "completed"
    FAILED = "failed"
    ROLLING_BACK = "rolling_back"


@dataclass
class PluginInfo:
    """Plugin information.

    Attributes:
        plugin_id: Unique plugin identifier
        name: Plugin name
        version: Current version
        description: Plugin description
        author: Plugin author
        install_path: Installation directory path
        is_enabled: Whether plugin is enabled
        compatible_main_versions: Compatible main program version range
        last_update_time: Last update timestamp
    """
    plugin_id: str = ""
    name: str = ""
    version: Optional[SemVer] = None
    description: str = ""
    author: str = ""
    install_path: str = ""
    is_enabled: bool = True
    compatible_main_versions: str = ""
    last_update_time: float = 0.0


@dataclass
class PluginUpdateInfo:
    """Plugin update information.

    Attributes:
        plugin_id: Plugin identifier
        current_version: Current version
        latest_version: Latest available version
        download_url: Download URL
        file_size: Package size in bytes
        file_hash: SHA256 hash
        release_notes: Release notes
        is_compatible: Whether update is compatible
        requires_restart: Whether restart is required
    """
    plugin_id: str = ""
    current_version: Optional[SemVer] = None
    latest_version: Optional[SemVer] = None
    download_url: str = ""
    file_size: int = 0
    file_hash: str = ""
    release_notes: str = ""
    is_compatible: bool = True
    requires_restart: bool = False


@dataclass
class PluginUpdateProgress:
    """Plugin update progress information.

    Attributes:
        plugin_id: Plugin being updated
        status: Current update status
        percentage: Update percentage (0-100)
        error_message: Error message if failed
    """
    plugin_id: str = ""
    status: PluginUpdateStatus = PluginUpdateStatus.PENDING
    percentage: float = 0.0
    error_message: str = ""


class PluginUpdater:
    """Manages independent plugin updates.

    Provides version checking, downloading, installation, and rollback
    for individual plugins without affecting the main program.
    """

    PLUGIN_MANIFEST = "plugin.json"
    BACKUP_SUFFIX = "_backup"

    def __init__(
        self,
        version_manager: VersionManager,
        plugins_dir: str,
        main_version: Optional[SemVer] = None,
    ) -> None:
        """Initialize plugin updater.

        Args:
            version_manager: Version manager instance.
            plugins_dir: Directory containing installed plugins.
            main_version: Current main program version.
        """
        self.version_manager = version_manager
        self.plugins_dir = plugins_dir
        self.main_version = main_version or VersionManager.CURRENT_VERSION

        self._progress_callbacks: List[Callable[[PluginUpdateProgress], Coroutine[Any, Any, None]]] = []
        self._plugin_cache: Dict[str, PluginInfo] = {}

    def register_progress_callback(
        self,
        callback: Callable[[PluginUpdateProgress], Coroutine[Any, Any, None]],
    ) -> None:
        """Register callback for update progress.

        Args:
            callback: Async callback for progress updates.
        """
        self._progress_callbacks.append(callback)

    async def scan_installed_plugins(self) -> List[PluginInfo]:
        """Scan for installed plugins and read their manifests.

        Returns:
            List of installed PluginInfo objects.
        """
        plugins: List[PluginInfo] = []

        if not os.path.exists(self.plugins_dir):
            return plugins

        for entry in os.listdir(self.plugins_dir):
            plugin_path = os.path.join(self.plugins_dir, entry)

            if not os.path.isdir(plugin_path):
                continue

            manifest_path = os.path.join(plugin_path, self.PLUGIN_MANIFEST)
            if not os.path.exists(manifest_path):
                continue

            try:
                plugin_info = await self._load_plugin_manifest(plugin_path)
                if plugin_info:
                    plugins.append(plugin_info)
                    self._plugin_cache[plugin_info.plugin_id] = plugin_info

            except Exception as e:
                logger.warning(f"Failed to load plugin manifest for {entry}: {e}")

        return plugins

    async def check_plugin_updates(self) -> Dict[str, PluginUpdateInfo]:
        """Check for updates for all installed plugins.

        Returns:
            Dictionary mapping plugin IDs to update information.
        """
        updates = {}

        plugins = await self.scan_installed_plugins()

        for plugin in plugins:
            update_info = await self._check_single_plugin_update(plugin)

            if update_info and update_info.latest_version:
                if update_info.latest_version > (plugin.version or SemVer()):
                    updates[plugin.plugin_id] = update_info

        return updates

    async def update_plugin(
        self,
        plugin_id: str,
        update_info: PluginUpdateInfo,
        auto_rollback: bool = True,
    ) -> bool:
        """Update a single plugin.

        Args:
            plugin_id: Plugin identifier.
            update_info: Update information.
            auto_rollback: Whether to automatically rollback on failure.

        Returns:
            True if update succeeded.
        """
        progress = PluginUpdateProgress(
            plugin_id=plugin_id,
            status=PluginUpdateStatus.PENDING,
        )
        await self._notify_progress(progress)

        try:
            plugin_info = self._plugin_cache.get(plugin_id)
            if plugin_info is None:
                progress.error_message = "Plugin not found"
                progress.status = PluginUpdateStatus.FAILED
                await self._notify_progress(progress)
                return False

            if not update_info.is_compatible:
                progress.error_message = "Update is not compatible with current main program version"
                progress.status = PluginUpdateStatus.FAILED
                await self._notify_progress(progress)
                return False

            progress.status = PluginUpdateStatus.DOWNLOADING
            progress.percentage = 10.0
            await self._notify_progress(progress)

            package_path = await self._download_plugin_update(update_info)
            if package_path is None:
                progress.error_message = "Failed to download update"
                progress.status = PluginUpdateStatus.FAILED
                await self._notify_progress(progress)
                return False

            progress.status = PluginUpdateStatus.INSTALLING
            progress.percentage = 50.0
            await self._notify_progress(progress)

            backup_path = await self._backup_plugin(plugin_info)

            success = await self._install_plugin_update(plugin_info, package_path)

            if success:
                progress.status = PluginUpdateStatus.COMPLETED
                progress.percentage = 100.0
                await self._notify_progress(progress)

                plugin_info.version = update_info.latest_version
                plugin_info.last_update_time = time.time()
                self._plugin_cache[plugin_id] = plugin_info

                return True
            else:
                if auto_rollback and backup_path:
                    progress.status = PluginUpdateStatus.ROLLING_BACK
                    await self._notify_progress(progress)

                    await self._restore_plugin_backup(plugin_info, backup_path)

                progress.status = PluginUpdateStatus.FAILED
                progress.error_message = "Update installation failed"
                await self._notify_progress(progress)

                return False

        except Exception as e:
            logger.error(f"Plugin update failed: {e}")
            progress.status = PluginUpdateStatus.FAILED
            progress.error_message = str(e)
            await self._notify_progress(progress)
            return False

    async def update_all_plugins(self) -> Dict[str, bool]:
        """Update all plugins with available updates.

        Returns:
            Dictionary mapping plugin IDs to success status.
        """
        results = {}

        updates = await self.check_plugin_updates()

        for plugin_id, update_info in updates.items():
            success = await self.update_plugin(plugin_id, update_info)
            results[plugin_id] = success

        return results

    async def rollback_plugin(self, plugin_id: str) -> bool:
        """Rollback a plugin to its previous version.

        Args:
            plugin_id: Plugin identifier.

        Returns:
            True if rollback succeeded.
        """
        plugin_info = self._plugin_cache.get(plugin_id)
        if plugin_info is None:
            return False

        backup_path = plugin_info.install_path + self.BACKUP_SUFFIX

        if not os.path.exists(backup_path):
            return False

        try:
            await self._restore_plugin_backup(plugin_info, backup_path)
            return True

        except Exception as e:
            logger.error(f"Plugin rollback failed: {e}")
            return False

    async def _check_single_plugin_update(
        self,
        plugin: PluginInfo,
    ) -> Optional[PluginUpdateInfo]:
        """Check for update for a single plugin.

        Args:
            plugin: Plugin information.

        Returns:
            PluginUpdateInfo or None.
        """
        try:
            marketplace_url = f"https://marketplace.kunlun.com/api/plugins/{plugin.plugin_id}/latest"

            import aiohttp

            async with aiohttp.ClientSession() as session:
                async with session.get(marketplace_url, timeout=aiohttp.ClientTimeout(total=10)) as response:
                    if response.status != 200:
                        return None

                    data = await response.json()

                    latest_version = SemVer.parse(data["version"])

                    is_compatible = self._check_plugin_compatibility(
                        plugin.compatible_main_versions,
                        self.main_version,
                    )

                    return PluginUpdateInfo(
                        plugin_id=plugin.plugin_id,
                        current_version=plugin.version,
                        latest_version=latest_version,
                        download_url=data.get("download_url", ""),
                        file_size=data.get("file_size", 0),
                        file_hash=data.get("file_hash", ""),
                        release_notes=data.get("release_notes", ""),
                        is_compatible=is_compatible,
                        requires_restart=data.get("requires_restart", False),
                    )

        except ImportError:
            logger.warning("aiohttp not available for plugin update checking")
            return None
        except Exception as e:
            logger.warning(f"Failed to check plugin update for {plugin.plugin_id}: {e}")
            return None

    async def _download_plugin_update(
        self,
        update_info: PluginUpdateInfo,
    ) -> Optional[str]:
        """Download plugin update package.

        Args:
            update_info: Update information.

        Returns:
            Path to downloaded package or None.
        """
        try:
            import aiohttp

            package_path = os.path.join(
                self.plugins_dir,
                f"{update_info.plugin_id}_update.zip",
            )

            async with aiohttp.ClientSession() as session:
                async with session.get(
                    update_info.download_url,
                    timeout=aiohttp.ClientTimeout(total=300),
                ) as response:
                    if response.status != 200:
                        return None

                    with open(package_path, "wb") as f:
                        async for chunk in response.content.iter_chunked(8192):
                            f.write(chunk)

            return package_path

        except ImportError:
            return None
        except Exception as e:
            logger.error(f"Failed to download plugin update: {e}")
            return None

    async def _install_plugin_update(
        self,
        plugin_info: PluginInfo,
        package_path: str,
    ) -> bool:
        """Install a plugin update package.

        Args:
            plugin_info: Plugin information.
            package_path: Path to update package.

        Returns:
            True if installation succeeded.
        """
        try:
            with zipfile.ZipFile(package_path, "r") as zf:
                zf.extractall(plugin_info.install_path)

            if os.path.exists(package_path):
                os.remove(package_path)

            return True

        except Exception as e:
            logger.error(f"Failed to install plugin update: {e}")
            return False

    async def _backup_plugin(self, plugin_info: PluginInfo) -> Optional[str]:
        """Create backup of current plugin version.

        Args:
            plugin_info: Plugin information.

        Returns:
            Backup path or None.
        """
        try:
            backup_path = plugin_info.install_path + self.BACKUP_SUFFIX

            if os.path.exists(backup_path):
                shutil.rmtree(backup_path)

            shutil.copytree(plugin_info.install_path, backup_path)

            return backup_path

        except Exception as e:
            logger.error(f"Failed to backup plugin: {e}")
            return None

    async def _restore_plugin_backup(
        self,
        plugin_info: PluginInfo,
        backup_path: str,
    ) -> bool:
        """Restore plugin from backup.

        Args:
            plugin_info: Plugin information.
            backup_path: Path to backup directory.

        Returns:
            True if restore succeeded.
        """
        try:
            if os.path.exists(plugin_info.install_path):
                shutil.rmtree(plugin_info.install_path)

            shutil.copytree(backup_path, plugin_info.install_path)

            return True

        except Exception as e:
            logger.error(f"Failed to restore plugin backup: {e}")
            return False

    async def _load_plugin_manifest(self, plugin_path: str) -> Optional[PluginInfo]:
        """Load plugin manifest file.

        Args:
            plugin_path: Path to plugin directory.

        Returns:
            PluginInfo or None.
        """
        manifest_path = os.path.join(plugin_path, self.PLUGIN_MANIFEST)

        if not os.path.exists(manifest_path):
            return None

        try:
            with open(manifest_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            version = None
            if data.get("version"):
                version = SemVer.parse(data["version"])

            return PluginInfo(
                plugin_id=data.get("id", os.path.basename(plugin_path)),
                name=data.get("name", ""),
                version=version,
                description=data.get("description", ""),
                author=data.get("author", ""),
                install_path=plugin_path,
                is_enabled=data.get("enabled", True),
                compatible_main_versions=data.get("compatible_main_versions", ""),
                last_update_time=data.get("last_update_time", 0.0),
            )

        except Exception as e:
            logger.warning(f"Failed to parse plugin manifest: {e}")
            return None

    def _check_plugin_compatibility(
        self,
        compatible_versions: str,
        main_version: SemVer,
    ) -> bool:
        """Check if plugin is compatible with main program version.

        Args:
            compatible_versions: Version range string (e.g., ">=1.0.0,<2.0.0").
            main_version: Main program version.

        Returns:
            True if compatible.
        """
        if not compatible_versions:
            return True

        try:
            constraints = [c.strip() for c in compatible_versions.split(",")]

            for constraint in constraints:
                if constraint.startswith(">="):
                    min_version = SemVer.parse(constraint[2:])
                    if main_version < min_version:
                        return False
                elif constraint.startswith("<"):
                    max_version = SemVer.parse(constraint[1:])
                    if main_version >= max_version:
                        return False
                elif constraint.startswith(">"):
                    min_version = SemVer.parse(constraint[1:])
                    if main_version <= min_version:
                        return False
                elif constraint.startswith("<="):
                    max_version = SemVer.parse(constraint[2:])
                    if main_version > max_version:
                        return False

            return True

        except Exception:
            return True

    async def _notify_progress(self, progress: PluginUpdateProgress) -> None:
        """Notify progress callbacks.

        Args:
            progress: Current update progress.
        """
        for callback in self._progress_callbacks:
            try:
                await callback(progress)
            except Exception as e:
                logger.error(f"Plugin progress callback error: {e}")
