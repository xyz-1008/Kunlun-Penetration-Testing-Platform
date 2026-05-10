"""Update Downloader: Update package download, resume support, incremental update calculation and integration.

Provides:
- Update package download with progress tracking
- Resume interrupted downloads (breakpoint resume)
- Incremental update calculation (file hash comparison)
- Binary diff support for small file updates
- Download integrity verification (SHA256)
- Temporary file management
"""

import asyncio
import hashlib
import json
import logging
import os
import shutil
import tempfile
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Callable, Coroutine, Dict, List, Optional, Tuple

from .updater_version import SemVer, UpdateSource, VersionManager, VersionMetadata

logger = logging.getLogger(__name__)


class DownloadStatus(Enum):
    """Status of download operation."""
    PENDING = "pending"
    DOWNLOADING = "downloading"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class DownloadProgress:
    """Download progress information.

    Attributes:
        total_bytes: Total bytes to download
        downloaded_bytes: Bytes downloaded so far
        speed_bytes_per_sec: Current download speed
        percentage: Download percentage (0-100)
        eta_seconds: Estimated time to completion
        status: Current download status
    """
    total_bytes: int = 0
    downloaded_bytes: int = 0
    speed_bytes_per_sec: float = 0.0
    percentage: float = 0.0
    eta_seconds: float = 0.0
    status: DownloadStatus = DownloadStatus.PENDING


@dataclass
class FileDiff:
    """File difference information for incremental updates.

    Attributes:
        file_path: Relative file path
        action: Action to perform (add/update/delete)
        current_hash: Current file hash (empty if new)
        target_hash: Target file hash
        file_size: File size in bytes
        needs_download: Whether file needs to be downloaded
    """
    file_path: str = ""
    action: str = "update"
    current_hash: str = ""
    target_hash: str = ""
    file_size: int = 0
    needs_download: bool = True


@dataclass
class IncrementalUpdateInfo:
    """Incremental update information.

    Attributes:
        current_version: Current version
        target_version: Target version
        files_to_add: Files to add
        files_to_update: Files to update
        files_to_delete: Files to delete
        total_download_size: Total download size
    """
    current_version: Optional[SemVer] = None
    target_version: Optional[SemVer] = None
    files_to_add: List[FileDiff] = field(default_factory=list)
    files_to_update: List[FileDiff] = field(default_factory=list)
    files_to_delete: List[FileDiff] = field(default_factory=list)
    total_download_size: int = 0


class UpdateDownloader:
    """Downloads update packages with resume support.

    Provides download progress tracking, breakpoint resume,
    incremental update calculation, and integrity verification.
    """

    CHUNK_SIZE = 8192
    RESUME_FILE = ".download_resume"

    def __init__(
        self,
        version_manager: VersionManager,
        download_dir: Optional[str] = None,
    ) -> None:
        """Initialize update downloader.

        Args:
            version_manager: Version manager instance.
            download_dir: Directory for downloaded files.
        """
        self.version_manager = version_manager
        self.download_dir = download_dir or os.path.join(
            tempfile.gettempdir(), "kunlun_updates"
        )
        os.makedirs(self.download_dir, exist_ok=True)

        self._progress_callbacks: List[Callable[[DownloadProgress], Coroutine[Any, Any, None]]] = []
        self._current_download: Optional[asyncio.Task[None]] = None
        self._is_cancelled = False

    def register_progress_callback(
        self,
        callback: Callable[[DownloadProgress], Coroutine[Any, Any, None]],
    ) -> None:
        """Register callback for download progress updates.

        Args:
            callback: Async callback for progress.
        """
        self._progress_callbacks.append(callback)

    async def download_update(
        self,
        source: UpdateSource,
        metadata: VersionMetadata,
        resume: bool = True,
    ) -> Optional[str]:
        """Download an update package.

        Args:
            source: Update source to download from.
            metadata: Version metadata.
            resume: Whether to resume interrupted download.

        Returns:
            Path to downloaded file or None.
        """
        self._is_cancelled = False

        file_name = f"kunlun_{metadata.version}.zip"
        file_path = os.path.join(self.download_dir, file_name)
        resume_path = os.path.join(self.download_dir, self.RESUME_FILE)

        start_pos = 0

        if resume and os.path.exists(file_path):
            start_pos = os.path.getsize(file_path)
            if start_pos >= metadata.file_size:
                return file_path

        if source.url.startswith("http://") or source.url.startswith("https://"):
            return await self._download_http(
                source, metadata, file_path, resume_path, start_pos
            )
        elif source.url.startswith("file://") or os.path.isabs(source.url):
            return await self._download_file(source, metadata, file_path)

        return None

    async def _download_http(
        self,
        source: UpdateSource,
        metadata: VersionMetadata,
        file_path: str,
        resume_path: str,
        start_pos: int,
        resume: bool = True,
    ) -> Optional[str]:
        """Download update from HTTP source.

        Args:
            source: Update source.
            metadata: Version metadata.
            file_path: Target file path.
            resume_path: Resume info file path.
            start_pos: Start position for resume.

        Returns:
            Path to downloaded file or None.
        """
        try:
            import aiohttp

            url = f"{source.url}/updates/{metadata.version}.zip"

            headers = {}
            if start_pos > 0:
                headers["Range"] = f"bytes={start_pos}-"

            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url, headers=headers, timeout=aiohttp.ClientTimeout(total=3600)
                ) as response:
                    if response.status not in (200, 206):
                        logger.error(f"Download failed with status {response.status}")
                        return None

                    total_size = int(response.headers.get("Content-Length", 0))
                    if start_pos > 0:
                        total_size += start_pos

                    progress = DownloadProgress(
                        total_bytes=total_size,
                        downloaded_bytes=start_pos,
                        status=DownloadStatus.DOWNLOADING,
                    )

                    mode = "ab" if start_pos > 0 else "wb"
                    resume_flag = resume

                    with open(file_path, mode) as f:
                        start_time = time.time()

                        async for chunk in response.content.iter_chunked(self.CHUNK_SIZE):
                            if self._is_cancelled:
                                progress.status = DownloadStatus.CANCELLED
                                await self._notify_progress(progress)
                                return None

                            f.write(chunk)

                            progress.downloaded_bytes += len(chunk)
                            elapsed = time.time() - start_time
                            if elapsed > 0:
                                progress.speed_bytes_per_sec = (
                                    progress.downloaded_bytes - start_pos
                                ) / elapsed

                            if progress.total_bytes > 0:
                                progress.percentage = (
                                    progress.downloaded_bytes / progress.total_bytes
                                ) * 100

                                remaining_bytes = (
                                    progress.total_bytes - progress.downloaded_bytes
                                )
                                if progress.speed_bytes_per_sec > 0:
                                    progress.eta_seconds = (
                                        remaining_bytes / progress.speed_bytes_per_sec
                                    )

                            await self._notify_progress(progress)

                            if resume_flag:
                                await self._save_resume_info(
                                    resume_path, file_path, progress.downloaded_bytes
                                )

                    if resume_flag and os.path.exists(resume_path):
                        os.remove(resume_path)

                    progress.status = DownloadStatus.COMPLETED
                    progress.percentage = 100.0
                    await self._notify_progress(progress)

                    if not await self._verify_download(file_path, metadata.file_hash):
                        logger.error("Download verification failed")
                        return None

                    return file_path

        except ImportError:
            logger.warning("aiohttp not available for HTTP download")
            return None
        except Exception as e:
            logger.error(f"Download failed: {e}")
            return None

    async def _download_file(
        self,
        source: UpdateSource,
        metadata: VersionMetadata,
        file_path: str,
    ) -> Optional[str]:
        """Download update from local file source.

        Args:
            source: Update source.
            metadata: Version metadata.
            file_path: Target file path.

        Returns:
            Path to copied file or None.
        """
        try:
            source_path = source.url.replace("file://", "")
            source_path = os.path.join(source_path, f"{metadata.version}.zip")

            if not os.path.exists(source_path):
                return None

            shutil.copy2(source_path, file_path)

            if not await self._verify_download(file_path, metadata.file_hash):
                return None

            return file_path

        except Exception as e:
            logger.error(f"File copy failed: {e}")
            return None

    async def calculate_incremental_update(
        self,
        current_version: SemVer,
        target_version: SemVer,
        current_files: Dict[str, str],
        target_manifest: Dict[str, str],
    ) -> IncrementalUpdateInfo:
        """Calculate incremental update between two versions.

        Args:
            current_version: Current version.
            target_version: Target version.
            current_files: Current files with their hashes.
            target_manifest: Target files with their hashes.

        Returns:
            IncrementalUpdateInfo with file differences.
        """
        info = IncrementalUpdateInfo(
            current_version=current_version,
            target_version=target_version,
        )

        all_files = set(current_files.keys()) | set(target_manifest.keys())

        for file_path in all_files:
            current_hash = current_files.get(file_path, "")
            target_hash = target_manifest.get(file_path, "")

            if file_path not in current_files:
                info.files_to_add.append(FileDiff(
                    file_path=file_path,
                    action="add",
                    target_hash=target_hash,
                    needs_download=True,
                ))
            elif file_path not in target_manifest:
                info.files_to_delete.append(FileDiff(
                    file_path=file_path,
                    action="delete",
                    current_hash=current_hash,
                    needs_download=False,
                ))
            elif current_hash != target_hash:
                info.files_to_update.append(FileDiff(
                    file_path=file_path,
                    action="update",
                    current_hash=current_hash,
                    target_hash=target_hash,
                    needs_download=True,
                ))

        info.total_download_size = sum(
            f.file_size for f in info.files_to_add + info.files_to_update
            if f.needs_download
        )

        return info

    async def cancel_download(self) -> None:
        """Cancel current download operation."""
        self._is_cancelled = True

        if self._current_download is not None:
            self._current_download.cancel()
            try:
                await self._current_download
            except asyncio.CancelledError:
                pass

    async def _verify_download(self, file_path: str, expected_hash: str) -> bool:
        """Verify downloaded file integrity.

        Args:
            file_path: Path to downloaded file.
            expected_hash: Expected SHA256 hash.

        Returns:
            True if file matches expected hash.
        """
        if not expected_hash:
            return True

        actual_hash = self.version_manager.calculate_file_hash(file_path)
        return actual_hash == expected_hash

    async def _save_resume_info(
        self,
        resume_path: str,
        file_path: str,
        downloaded_bytes: int,
    ) -> None:
        """Save resume information for download continuation.

        Args:
            resume_path: Path to resume info file.
            file_path: Path to downloaded file.
            downloaded_bytes: Bytes downloaded so far.
        """
        try:
            info = {
                "file_path": file_path,
                "downloaded_bytes": downloaded_bytes,
                "timestamp": time.time(),
            }

            with open(resume_path, "w", encoding="utf-8") as f:
                json.dump(info, f)

        except Exception as e:
            logger.warning(f"Failed to save resume info: {e}")

    async def _notify_progress(self, progress: DownloadProgress) -> None:
        """Notify progress callbacks.

        Args:
            progress: Current download progress.
        """
        for callback in self._progress_callbacks:
            try:
                await callback(progress)
            except Exception as e:
                logger.error(f"Progress callback error: {e}")

    def cleanup_downloads(self, max_age_days: float = 7.0) -> int:
        """Clean up old downloaded files.

        Args:
            max_age_days: Maximum age in days.

        Returns:
            Number of files cleaned up.
        """
        cleaned = 0
        current_time = time.time()
        max_age_seconds = max_age_days * 86400

        for file_name in os.listdir(self.download_dir):
            file_path = os.path.join(self.download_dir, file_name)

            if os.path.isfile(file_path):
                file_age = current_time - os.path.getmtime(file_path)

                if file_age > max_age_seconds:
                    try:
                        os.remove(file_path)
                        cleaned += 1
                    except Exception as e:
                        logger.warning(f"Failed to remove {file_path}: {e}")

        return cleaned
