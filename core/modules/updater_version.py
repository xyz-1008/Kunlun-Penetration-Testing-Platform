"""Version Management: Version definition, compatibility validation, update source management.

Provides:
- SemVer version parsing and comparison
- Compatibility validation between versions
- Update source configuration and priority management
- Release channel management (Stable/Beta/Dev)
- Version metadata handling
"""

import hashlib
import json
import logging
import os
import re
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class ReleaseChannel(Enum):
    """Release channels for update distribution."""
    STABLE = "stable"
    BETA = "beta"
    DEV = "dev"


class UpdateType(Enum):
    """Types of version updates."""
    MAJOR = "major"
    MINOR = "minor"
    PATCH = "patch"


class CompatibilityStatus(Enum):
    """Compatibility status between versions."""
    COMPATIBLE = "compatible"
    INCOMPATIBLE = "incompatible"
    UNKNOWN = "unknown"


@dataclass
class SemVer:
    """Semantic version representation.

    Attributes:
        major: Major version number
        minor: Minor version number
        patch: Patch version number
        pre_release: Pre-release identifier (e.g., "beta.1")
        build_metadata: Build metadata
    """
    major: int = 0
    minor: int = 0
    patch: int = 0
    pre_release: str = ""
    build_metadata: str = ""

    def __str__(self) -> str:
        """Return string representation of version.

        Returns:
            Version string in SemVer format.
        """
        version = f"{self.major}.{self.minor}.{self.patch}"
        if self.pre_release:
            version += f"-{self.pre_release}"
        if self.build_metadata:
            version += f"+{self.build_metadata}"
        return version

    def __eq__(self, other: object) -> bool:
        """Check version equality.

        Args:
            other: Other version to compare.

        Returns:
            True if versions are equal.
        """
        if not isinstance(other, SemVer):
            return False
        return (
            self.major == other.major
            and self.minor == other.minor
            and self.patch == other.patch
            and self.pre_release == other.pre_release
        )

    def __lt__(self, other: "SemVer") -> bool:
        """Compare versions (less than).

        Args:
            other: Other version to compare.

        Returns:
            True if this version is less than other.
        """
        if self.major != other.major:
            return self.major < other.major
        if self.minor != other.minor:
            return self.minor < other.minor
        if self.patch != other.patch:
            return self.patch < other.patch

        if self.pre_release and not other.pre_release:
            return True
        if not self.pre_release and other.pre_release:
            return False
        if self.pre_release and other.pre_release:
            return self.pre_release < other.pre_release

        return False

    def __le__(self, other: "SemVer") -> bool:
        """Compare versions (less than or equal).

        Args:
            other: Other version to compare.

        Returns:
            True if this version is less than or equal to other.
        """
        return self == other or self < other

    def __gt__(self, other: "SemVer") -> bool:
        """Compare versions (greater than).

        Args:
            other: Other version to compare.

        Returns:
            True if this version is greater than other.
        """
        return not self <= other

    def __ge__(self, other: "SemVer") -> bool:
        """Compare versions (greater than or equal).

        Args:
            other: Other version to compare.

        Returns:
            True if this version is greater than or equal to other.
        """
        return not self < other

    def get_update_type(self, other: "SemVer") -> UpdateType:
        """Determine update type between this version and another.

        Args:
            other: Target version.

        Returns:
            UpdateType (major/minor/patch).
        """
        if other.major != self.major:
            return UpdateType.MAJOR
        if other.minor != self.minor:
            return UpdateType.MINOR
        return UpdateType.PATCH

    @classmethod
    def parse(cls, version_str: str) -> "SemVer":
        """Parse a version string into SemVer object.

        Args:
            version_str: Version string (e.g., "1.2.3-beta.1+build.123").

        Returns:
            Parsed SemVer object.

        Raises:
            ValueError: If version string is invalid.
        """
        pattern = r"^(\d+)\.(\d+)\.(\d+)(?:-([a-zA-Z0-9.]+))?(?:\+([a-zA-Z0-9.]+))?$"
        match = re.match(pattern, version_str.strip())

        if not match:
            raise ValueError(f"Invalid version string: {version_str}")

        return cls(
            major=int(match.group(1)),
            minor=int(match.group(2)),
            patch=int(match.group(3)),
            pre_release=match.group(4) or "",
            build_metadata=match.group(5) or "",
        )


@dataclass
class VersionMetadata:
    """Metadata for a version release.

    Attributes:
        version: Version number
        release_date: Release date (ISO format)
        release_channel: Release channel
        update_type: Type of update
        is_force_update: Whether update is mandatory
        description: Update description (Markdown)
        file_size: Update package size in bytes
        file_hash: SHA256 hash of update package
        min_os_version: Minimum OS version required
        max_os_version: Maximum OS version supported
        compatible_plugin_versions: Compatible plugin version ranges
        breaking_changes: List of breaking changes
    """
    version: SemVer = field(default_factory=SemVer)
    release_date: str = ""
    release_channel: ReleaseChannel = ReleaseChannel.STABLE
    update_type: UpdateType = UpdateType.PATCH
    is_force_update: bool = False
    description: str = ""
    file_size: int = 0
    file_hash: str = ""
    min_os_version: str = ""
    max_os_version: str = ""
    compatible_plugin_versions: Dict[str, str] = field(default_factory=dict)
    breaking_changes: List[str] = field(default_factory=list)


@dataclass
class UpdateSource:
    """Update source configuration.

    Attributes:
        name: Source name
        url: Source URL (HTTPS or local file path)
        priority: Source priority (lower is higher priority)
        is_enabled: Whether source is enabled
        last_check_time: Last check timestamp
        check_interval: Check interval in seconds
    """
    name: str = ""
    url: str = ""
    priority: int = 0
    is_enabled: bool = True
    last_check_time: float = 0.0
    check_interval: float = 86400.0


@dataclass
class CompatibilityResult:
    """Version compatibility check result.

    Attributes:
        status: Compatibility status
        current_version: Current version
        target_version: Target version
        is_compatible: Whether versions are compatible
        issues: List of compatibility issues
        recommendations: List of recommendations
    """
    status: CompatibilityStatus = CompatibilityStatus.UNKNOWN
    current_version: Optional[SemVer] = None
    target_version: Optional[SemVer] = None
    is_compatible: bool = False
    issues: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)


class VersionManager:
    """Manages version information and compatibility validation.

    Provides SemVer parsing, version comparison, compatibility checking,
    and update source management.
    """

    CURRENT_VERSION = SemVer(1, 0, 0)

    def __init__(self) -> None:
        """Initialize version manager."""
        self._update_sources: List[UpdateSource] = []
        self._version_cache: Dict[str, VersionMetadata] = {}

    def parse_version(self, version_str: str) -> SemVer:
        """Parse a version string.

        Args:
            version_str: Version string to parse.

        Returns:
            Parsed SemVer object.
        """
        return SemVer.parse(version_str)

    def compare_versions(self, v1: SemVer, v2: SemVer) -> int:
        """Compare two versions.

        Args:
            v1: First version.
            v2: Second version.

        Returns:
            -1 if v1 < v2, 0 if equal, 1 if v1 > v2.
        """
        if v1 < v2:
            return -1
        if v1 > v2:
            return 1
        return 0

    def check_compatibility(
        self,
        current_version: SemVer,
        target_version: SemVer,
        target_metadata: Optional[VersionMetadata] = None,
    ) -> CompatibilityResult:
        """Check compatibility between current and target versions.

        Args:
            current_version: Current version.
            target_version: Target version.
            target_metadata: Target version metadata.

        Returns:
            CompatibilityResult with compatibility information.
        """
        result = CompatibilityResult(
            current_version=current_version,
            target_version=target_version,
        )

        update_type = current_version.get_update_type(target_version)

        if update_type == UpdateType.MAJOR:
            result.issues.append(
                "Major version update may contain breaking changes"
            )
            result.recommendations.append(
                "Backup your data before upgrading"
            )

        if target_metadata:
            if target_metadata.breaking_changes:
                result.issues.extend(target_metadata.breaking_changes)

            if target_metadata.is_force_update:
                result.recommendations.append(
                    "This is a mandatory security update"
                )

        if not result.issues:
            result.status = CompatibilityStatus.COMPATIBLE
            result.is_compatible = True
        else:
            result.status = CompatibilityStatus.INCOMPATIBLE
            result.is_compatible = not target_metadata or not target_metadata.is_force_update

        return result

    def add_update_source(self, source: UpdateSource) -> None:
        """Add an update source.

        Args:
            source: Update source to add.
        """
        self._update_sources.append(source)
        self._update_sources.sort(key=lambda s: s.priority)

    def remove_update_source(self, source_name: str) -> bool:
        """Remove an update source by name.

        Args:
            source_name: Name of source to remove.

        Returns:
            True if source was removed.
        """
        for i, source in enumerate(self._update_sources):
            if source.name == source_name:
                self._update_sources.pop(i)
                return True
        return False

    def get_enabled_sources(self) -> List[UpdateSource]:
        """Get list of enabled update sources sorted by priority.

        Returns:
            List of enabled UpdateSource objects.
        """
        return [s for s in self._update_sources if s.is_enabled]

    def get_primary_source(self) -> Optional[UpdateSource]:
        """Get the primary (highest priority) update source.

        Returns:
            Primary UpdateSource or None.
        """
        enabled = self.get_enabled_sources()
        return enabled[0] if enabled else None

    def cache_version_metadata(
        self,
        version: SemVer,
        metadata: VersionMetadata,
    ) -> None:
        """Cache version metadata.

        Args:
            version: Version number.
            metadata: Version metadata.
        """
        self._version_cache[str(version)] = metadata

    def get_cached_metadata(self, version: SemVer) -> Optional[VersionMetadata]:
        """Get cached version metadata.

        Args:
            version: Version number.

        Returns:
            Cached VersionMetadata or None.
        """
        return self._version_cache.get(str(version))

    def calculate_file_hash(self, file_path: str) -> str:
        """Calculate SHA256 hash of a file.

        Args:
            file_path: Path to file.

        Returns:
            SHA256 hash string.
        """
        sha256 = hashlib.sha256()

        with open(file_path, "rb") as f:
            while True:
                chunk = f.read(8192)
                if not chunk:
                    break
                sha256.update(chunk)

        return sha256.hexdigest()

    def serialize_metadata(self, metadata: VersionMetadata) -> str:
        """Serialize version metadata to JSON string.

        Args:
            metadata: VersionMetadata to serialize.

        Returns:
            JSON string.
        """
        data = {
            "version": str(metadata.version),
            "release_date": metadata.release_date,
            "release_channel": metadata.release_channel.value,
            "update_type": metadata.update_type.value,
            "is_force_update": metadata.is_force_update,
            "description": metadata.description,
            "file_size": metadata.file_size,
            "file_hash": metadata.file_hash,
            "min_os_version": metadata.min_os_version,
            "max_os_version": metadata.max_os_version,
            "compatible_plugin_versions": metadata.compatible_plugin_versions,
            "breaking_changes": metadata.breaking_changes,
        }

        return json.dumps(data, indent=2)

    def deserialize_metadata(self, json_str: str) -> VersionMetadata:
        """Deserialize version metadata from JSON string.

        Args:
            json_str: JSON string.

        Returns:
            Deserialized VersionMetadata object.
        """
        data = json.loads(json_str)

        return VersionMetadata(
            version=SemVer.parse(data["version"]),
            release_date=data.get("release_date", ""),
            release_channel=ReleaseChannel(data.get("release_channel", "stable")),
            update_type=UpdateType(data.get("update_type", "patch")),
            is_force_update=data.get("is_force_update", False),
            description=data.get("description", ""),
            file_size=data.get("file_size", 0),
            file_hash=data.get("file_hash", ""),
            min_os_version=data.get("min_os_version", ""),
            max_os_version=data.get("max_os_version", ""),
            compatible_plugin_versions=data.get("compatible_plugin_versions", {}),
            breaking_changes=data.get("breaking_changes", []),
        )
