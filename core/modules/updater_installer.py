"""Update Installer: Update package application, backup and rollback, gray release management.

Provides:
- Update package extraction and application
- Automatic backup before update
- One-click rollback to previous versions
- Gray release management (Stable/Beta/Dev channels)
- Update state persistence for recovery
- Disk space checking and warnings
"""

import asyncio
import json
import logging
import os
import shutil
import subprocess
import sys
import tempfile
import time
import zipfile
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Dict, List, Optional, Tuple

from .updater_version import ReleaseChannel, SemVer, VersionManager, VersionMetadata

logger = logging.getLogger(__name__)


class InstallStatus(Enum):
    """Status of update installation."""
    PENDING = "pending"
    BACKING_UP = "backing_up"
    EXTRACTING = "extracting"
    APPLYING = "applying"
    COMPLETED = "completed"
    FAILED = "failed"
    ROLLING_BACK = "rolling_back"


@dataclass
class BackupInfo:
    """Backup version information.

    Attributes:
        backup_id: Unique backup identifier
        version: Backed up version
        backup_path: Path to backup directory
        backup_time: Backup timestamp
        backup_size: Backup size in bytes
        file_count: Number of files in backup
    """
    backup_id: str = ""
    version: Optional[SemVer] = None
    backup_path: str = ""
    backup_time: float = 0.0
    backup_size: int = 0
    file_count: int = 0


@dataclass
class InstallProgress:
    """Installation progress information.

    Attributes:
        status: Current installation status
        percentage: Installation percentage (0-100)
        current_file: Currently processing file
        total_files: Total files to process
        processed_files: Files processed so far
        error_message: Error message if failed
    """
    status: InstallStatus = InstallStatus.PENDING
    percentage: float = 0.0
    current_file: str = ""
    total_files: int = 0
    processed_files: int = 0
    error_message: str = ""


@dataclass
class UpdateState:
    """Persistent update state for recovery.

    Attributes:
        version: Target version
        stage: Current update stage
        backup_id: Backup identifier
        download_path: Path to downloaded update package
        is_resumable: Whether update can be resumed
        last_update_time: Last state update timestamp
    """
    version: Optional[SemVer] = None
    stage: str = ""
    backup_id: str = ""
    download_path: str = ""
    is_resumable: bool = False
    last_update_time: float = 0.0


class UpdateInstaller:
    """Installs updates and manages backups/rollbacks.

    Provides update package application, automatic backup creation,
    one-click rollback, and gray release channel management.
    """

    STATE_FILE = "update_state.json"
    BACKUP_DIR_NAME = "backups"
    MAX_BACKUPS = 3
    PROTECTED_DIRS = {"config", "plugins", "data", "logs"}

    def __init__(
        self,
        version_manager: VersionManager,
        app_dir: str,
        backup_dir: Optional[str] = None,
    ) -> None:
        """Initialize update installer.

        Args:
            version_manager: Version manager instance.
            app_dir: Application installation directory.
            backup_dir: Directory for version backups.
        """
        self.version_manager = version_manager
        self.app_dir = app_dir
        self.backup_dir = backup_dir or os.path.join(app_dir, self.BACKUP_DIR_NAME)
        os.makedirs(self.backup_dir, exist_ok=True)

        self._state_file = os.path.join(app_dir, self.STATE_FILE)
        self._progress_callbacks: List[Any] = []
        self._current_state: Optional[UpdateState] = None

    def register_progress_callback(self, callback: Any) -> None:
        """Register callback for installation progress.

        Args:
            callback: Callback function for progress updates.
        """
        self._progress_callbacks.append(callback)

    async def install_update(
        self,
        package_path: str,
        metadata: VersionMetadata,
        require_restart: bool = True,
    ) -> bool:
        """Install an update package.

        Args:
            package_path: Path to update package.
            metadata: Version metadata.
            require_restart: Whether restart is required.

        Returns:
            True if installation succeeded.
        """
        progress = InstallProgress(status=InstallStatus.PENDING)
        await self._notify_progress(progress)

        try:
            if not os.path.exists(package_path):
                progress.error_message = "Update package not found"
                progress.status = InstallStatus.FAILED
                await self._notify_progress(progress)
                return False

            if not self._check_disk_space(package_path):
                progress.error_message = "Insufficient disk space"
                progress.status = InstallStatus.FAILED
                await self._notify_progress(progress)
                return False

            progress.status = InstallStatus.BACKING_UP
            await self._notify_progress(progress)

            backup_info = await self._create_backup(metadata.version)
            if backup_info is None:
                logger.warning("Backup creation failed, continuing anyway")

            state = UpdateState(
                version=metadata.version,
                stage="backing_up",
                backup_id=backup_info.backup_id if backup_info else "",
                download_path=package_path,
                is_resumable=True,
                last_update_time=time.time(),
            )
            await self._save_state(state)

            progress.status = InstallStatus.EXTRACTING
            progress.percentage = 20.0
            await self._notify_progress(progress)

            extract_dir = os.path.join(tempfile.gettempdir(), f"kunlun_update_{int(time.time())}")
            os.makedirs(extract_dir, exist_ok=True)

            with zipfile.ZipFile(package_path, "r") as zf:
                file_list = [f for f in zf.namelist() if not f.endswith("/")]
                progress.total_files = len(file_list)

                for i, file_name in enumerate(file_list):
                    if self._is_protected_file(file_name):
                        continue

                    progress.current_file = file_name
                    progress.processed_files = i + 1
                    progress.percentage = 20 + (i / len(file_list)) * 50
                    await self._notify_progress(progress)

                    zf.extract(file_name, extract_dir)

            state.stage = "extracting"
            state.last_update_time = time.time()
            await self._save_state(state)

            progress.status = InstallStatus.APPLYING
            progress.percentage = 70.0
            await self._notify_progress(progress)

            await self._apply_update(extract_dir, metadata.version)

            state.stage = "applying"
            state.last_update_time = time.time()
            await self._save_state(state)

            progress.percentage = 90.0
            await self._notify_progress(progress)

            shutil.rmtree(extract_dir, ignore_errors=True)

            if require_restart:
                await self._schedule_restart(metadata.version)

            progress.status = InstallStatus.COMPLETED
            progress.percentage = 100.0
            await self._notify_progress(progress)

            await self._clear_state()

            self._cleanup_old_backups()

            return True

        except Exception as e:
            logger.error(f"Update installation failed: {e}")
            progress.status = InstallStatus.FAILED
            progress.error_message = str(e)
            await self._notify_progress(progress)

            await self._clear_state()
            return False

    async def rollback_to_version(self, version: SemVer) -> bool:
        """Rollback to a previous version.

        Args:
            version: Version to rollback to.

        Returns:
            True if rollback succeeded.
        """
        progress = InstallProgress(status=InstallStatus.ROLLING_BACK)
        await self._notify_progress(progress)

        try:
            backup_info = await self._find_backup(version)
            if backup_info is None:
                progress.error_message = f"No backup found for version {version}"
                progress.status = InstallStatus.FAILED
                await self._notify_progress(progress)
                return False

            progress.status = InstallStatus.EXTRACTING
            progress.percentage = 20.0
            await self._notify_progress(progress)

            await self._restore_backup(backup_info)

            progress.status = InstallStatus.APPLYING
            progress.percentage = 70.0
            await self._notify_progress(progress)

            await self._schedule_restart(version)

            progress.status = InstallStatus.COMPLETED
            progress.percentage = 100.0
            await self._notify_progress(progress)

            return True

        except Exception as e:
            logger.error(f"Rollback failed: {e}")
            progress.status = InstallStatus.FAILED
            progress.error_message = str(e)
            await self._notify_progress(progress)
            return False

    async def get_available_backups(self) -> List[BackupInfo]:
        """Get list of available version backups.

        Returns:
            List of BackupInfo objects.
        """
        backups: List[BackupInfo] = []

        if not os.path.exists(self.backup_dir):
            return backups

        for entry in os.listdir(self.backup_dir):
            backup_path = os.path.join(self.backup_dir, entry)

            if not os.path.isdir(backup_path):
                continue

            info_file = os.path.join(backup_path, "backup_info.json")
            if not os.path.exists(info_file):
                continue

            try:
                with open(info_file, "r", encoding="utf-8") as f:
                    data = json.load(f)

                version = SemVer.parse(data["version"])
                backup = BackupInfo(
                    backup_id=data["backup_id"],
                    version=version,
                    backup_path=backup_path,
                    backup_time=float(data.get("backup_time", 0)),
                    backup_size=data.get("backup_size", 0),
                    file_count=data.get("file_count", 0),
                )
                backups.append(backup)

            except Exception as e:
                logger.warning(f"Failed to read backup info for {entry}: {e}")

        backups.sort(key=lambda b: b.backup_time, reverse=True)
        return backups

    async def recover_from_failure(self) -> bool:
        """Recover from a failed update.

        Returns:
            True if recovery succeeded.
        """
        state = await self._load_state()
        if state is None:
            return False

        logger.info(f"Recovering from failed update at stage: {state.stage}")

        if state.backup_id:
            backup_info = await self._find_backup_by_id(state.backup_id)
            if backup_info:
                return await self.rollback_to_version(backup_info.version or SemVer())

        return False

    async def _create_backup(self, target_version: SemVer) -> Optional[BackupInfo]:
        """Create backup of current version.

        Args:
            target_version: Target version being installed.

        Returns:
            BackupInfo or None.
        """
        try:
            backup_id = f"backup_{int(time.time())}"
            backup_path = os.path.join(self.backup_dir, backup_id)
            os.makedirs(backup_path, exist_ok=True)

            file_count = 0
            total_size = 0

            for root, dirs, files in os.walk(self.app_dir):
                rel_root = os.path.relpath(root, self.app_dir)

                if any(rel_root.startswith(d) for d in self.PROTECTED_DIRS):
                    continue

                for file_name in files:
                    src_file = os.path.join(root, file_name)
                    rel_path = os.path.relpath(src_file, self.app_dir)

                    if self._is_protected_file(rel_path):
                        continue

                    dest_file = os.path.join(backup_path, rel_path)
                    os.makedirs(os.path.dirname(dest_file), exist_ok=True)

                    shutil.copy2(src_file, dest_file)
                    file_count += 1
                    total_size += os.path.getsize(src_file)

            info = {
                "backup_id": backup_id,
                "version": str(target_version),
                "backup_time": time.time(),
                "backup_size": total_size,
                "file_count": file_count,
            }

            with open(os.path.join(backup_path, "backup_info.json"), "w", encoding="utf-8") as f:
                json.dump(info, f, indent=2)

            backup_time_val = info.get("backup_time", 0.0)
            if isinstance(backup_time_val, (int, float)):
                backup_time_float = float(backup_time_val)
            else:
                backup_time_float = 0.0

            return BackupInfo(
                backup_id=backup_id,
                version=target_version,
                backup_path=backup_path,
                backup_time=backup_time_float,
                backup_size=total_size,
                file_count=file_count,
            )

        except Exception as e:
            logger.error(f"Backup creation failed: {e}")
            return None

    async def _restore_backup(self, backup_info: BackupInfo) -> None:
        """Restore from a backup.

        Args:
            backup_info: Backup information.
        """
        for root, dirs, files in os.walk(backup_info.backup_path):
            for file_name in files:
                src_file = os.path.join(root, file_name)
                rel_path = os.path.relpath(src_file, backup_info.backup_path)

                if self._is_protected_file(rel_path):
                    continue

                dest_file = os.path.join(self.app_dir, rel_path)
                os.makedirs(os.path.dirname(dest_file), exist_ok=True)

                shutil.copy2(src_file, dest_file)

    async def _apply_update(self, extract_dir: str, version: SemVer) -> None:
        """Apply extracted update files.

        Args:
            extract_dir: Directory with extracted update files.
            version: Target version.
        """
        for root, dirs, files in os.walk(extract_dir):
            for file_name in files:
                src_file = os.path.join(root, file_name)
                rel_path = os.path.relpath(src_file, extract_dir)

                if self._is_protected_file(rel_path):
                    continue

                dest_file = os.path.join(self.app_dir, rel_path)
                os.makedirs(os.path.dirname(dest_file), exist_ok=True)

                shutil.copy2(src_file, dest_file)

    async def _schedule_restart(self, version: SemVer) -> None:
        """Schedule application restart after update.

        Args:
            version: New version number.
        """
        if sys.platform == "win32":
            exe_path = sys.executable
            script_path = sys.argv[0]

            subprocess.Popen(
                [exe_path, script_path, "--updated"],
                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
            )

    def _check_disk_space(self, package_path: str) -> bool:
        """Check if there's enough disk space for update.

        Args:
            package_path: Path to update package.

        Returns:
            True if enough space is available.
        """
        try:
            package_size = os.path.getsize(package_path)
            required_space = package_size * 3

            stat = shutil.disk_usage(self.app_dir)
            return stat.free > required_space

        except Exception:
            return True

    def _is_protected_file(self, file_path: str) -> bool:
        """Check if a file is protected from update.

        Args:
            file_path: Relative file path.

        Returns:
            True if file is protected.
        """
        for protected in self.PROTECTED_DIRS:
            if file_path.startswith(protected + os.sep) or file_path.startswith(protected + "/"):
                return True

        return False

    async def _save_state(self, state: UpdateState) -> None:
        """Save update state for recovery.

        Args:
            state: Update state to save.
        """
        self._current_state = state

        data = {
            "version": str(state.version) if state.version else "",
            "stage": state.stage,
            "backup_id": state.backup_id,
            "download_path": state.download_path,
            "is_resumable": state.is_resumable,
            "last_update_time": state.last_update_time,
        }

        with open(self._state_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    async def _load_state(self) -> Optional[UpdateState]:
        """Load update state from file.

        Returns:
            UpdateState or None.
        """
        if not os.path.exists(self._state_file):
            return None

        try:
            with open(self._state_file, "r", encoding="utf-8") as f:
                data = json.load(f)

            version = None
            if data.get("version"):
                version = SemVer.parse(data["version"])

            return UpdateState(
                version=version,
                stage=data.get("stage", ""),
                backup_id=data.get("backup_id", ""),
                download_path=data.get("download_path", ""),
                is_resumable=data.get("is_resumable", False),
                last_update_time=data.get("last_update_time", 0.0),
            )

        except Exception as e:
            logger.warning(f"Failed to load state: {e}")
            return None

    async def _clear_state(self) -> None:
        """Clear update state file."""
        self._current_state = None

        if os.path.exists(self._state_file):
            try:
                os.remove(self._state_file)
            except Exception:
                pass

    async def _find_backup(self, version: SemVer) -> Optional[BackupInfo]:
        """Find backup for a specific version.

        Args:
            version: Version to find.

        Returns:
            BackupInfo or None.
        """
        backups = await self.get_available_backups()

        for backup in backups:
            if backup.version == version:
                return backup

        return None

    async def _find_backup_by_id(self, backup_id: str) -> Optional[BackupInfo]:
        """Find backup by ID.

        Args:
            backup_id: Backup identifier.

        Returns:
            BackupInfo or None.
        """
        backups = await self.get_available_backups()

        for backup in backups:
            if backup.backup_id == backup_id:
                return backup

        return None

    def _cleanup_old_backups(self) -> None:
        """Clean up old backups, keeping only MAX_BACKUPS most recent."""
        backups = []

        if not os.path.exists(self.backup_dir):
            return

        for entry in os.listdir(self.backup_dir):
            backup_path = os.path.join(self.backup_dir, entry)

            if os.path.isdir(backup_path):
                info_file = os.path.join(backup_path, "backup_info.json")
                if os.path.exists(info_file):
                    try:
                        with open(info_file, "r", encoding="utf-8") as f:
                            data = json.load(f)
                        backups.append((data.get("backup_time", 0), backup_path))
                    except Exception:
                        pass

        backups.sort(key=lambda x: x[0], reverse=True)

        for _, backup_path in backups[self.MAX_BACKUPS:]:
            try:
                shutil.rmtree(backup_path)
            except Exception as e:
                logger.warning(f"Failed to remove old backup: {e}")

    async def _notify_progress(self, progress: InstallProgress) -> None:
        """Notify progress callbacks.

        Args:
            progress: Current installation progress.
        """
        for callback in self._progress_callbacks:
            try:
                if asyncio.iscoroutinefunction(callback):
                    await callback(progress)
                else:
                    callback(progress)
            except Exception as e:
                logger.error(f"Progress callback error: {e}")
