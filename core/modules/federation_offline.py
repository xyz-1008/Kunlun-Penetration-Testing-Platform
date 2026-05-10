"""Federation Offline: Offline package export/import, air-gapped environment support.

Provides:
- Export selected resources to offline market packages (tar.gz)
- Import offline market packages with integrity verification
- Incremental export (only changed resources since last export)
- Air-gapped environment support with dependency bundling
- Package validation and resource manifest generation
"""

import hashlib
import json
import logging
import os
import tarfile
import tempfile
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple

from pydantic import BaseModel, Field

from .federation_protocol import ResourceMetadata, ResourceType
from .federation_sync import FederationSyncEngine

logger = logging.getLogger(__name__)


class OfflinePackageManifest(BaseModel):
    """Manifest for an offline market package.

    Attributes:
        package_id: Unique package identifier
        version: Package format version
        created_at: Package creation timestamp
        resource_count: Number of resources in package
        total_size_bytes: Total package size in bytes
        resources: List of resource metadata included
        includes_dependencies: Whether dependencies are bundled
        includes_ratings: Whether rating data is included
        checksum: SHA256 checksum of the package content
    """
    package_id: str = Field(..., description="Package identifier")
    version: str = Field(default="1.0.0", description="Format version")
    created_at: str = Field(..., description="Creation timestamp")
    resource_count: int = Field(default=0, description="Resource count")
    total_size_bytes: int = Field(default=0, description="Total size")
    resources: List[ResourceMetadata] = Field(default_factory=list, description="Resources")
    includes_dependencies: bool = Field(default=False, description="Has dependencies")
    includes_ratings: bool = Field(default=False, description="Has ratings")
    checksum: str = Field(default="", description="SHA256 checksum")


class ExportFilter(BaseModel):
    """Filter criteria for offline package export.

    Attributes:
        resource_types: Types of resources to include
        tags: Tags to filter by (empty = all)
        since_timestamp: Only include resources updated after this time
        max_resources: Maximum number of resources to export
        include_dependencies: Whether to include dependencies
        include_ratings: Whether to include rating data
    """
    resource_types: List[ResourceType] = Field(default_factory=list, description="Resource types")
    tags: List[str] = Field(default_factory=list, description="Tags")
    since_timestamp: Optional[str] = Field(default=None, description="Include after this time")
    max_resources: int = Field(default=0, description="Max resources (0 = unlimited)")
    include_dependencies: bool = Field(default=False, description="Include dependencies")
    include_ratings: bool = Field(default=False, description="Include ratings")


class ImportResult(BaseModel):
    """Result of an offline package import operation.

    Attributes:
        success: Whether import succeeded
        imported_count: Number of resources imported
        skipped_count: Number of resources skipped
        conflict_count: Number of conflicts detected
        error_count: Number of errors encountered
        errors: List of error messages
        manifest: Package manifest that was imported
    """
    success: bool = Field(default=False, description="Whether succeeded")
    imported_count: int = Field(default=0, description="Imported count")
    skipped_count: int = Field(default=0, description="Skipped count")
    conflict_count: int = Field(default=0, description="Conflict count")
    error_count: int = Field(default=0, description="Error count")
    errors: List[str] = Field(default_factory=list, description="Error messages")
    manifest: Optional[OfflinePackageManifest] = Field(default=None, description="Manifest")


class FederationOfflinePackage:
    """Manages offline market package export and import.

    Provides package creation, validation, import with conflict
    resolution, and air-gapped environment support.
    """

    def __init__(
        self,
        sync_engine: Optional[FederationSyncEngine] = None,
        temp_dir: Optional[str] = None,
    ) -> None:
        """Initialize offline package manager.

        Args:
            sync_engine: Federation sync engine for resource access.
            temp_dir: Temporary directory for package operations.
        """
        self.sync_engine = sync_engine
        self.temp_dir = temp_dir or tempfile.gettempdir()

    def export_package(
        self,
        output_path: str,
        resources: List[ResourceMetadata],
        filter_config: Optional[ExportFilter] = None,
        include_packages: bool = False,
    ) -> Optional[OfflinePackageManifest]:
        """Export resources to an offline market package.

        Args:
            output_path: Path to save the package file.
            resources: List of resources to export.
            filter_config: Export filter configuration.
            include_packages: Whether to bundle Python dependencies.

        Returns:
            OfflinePackageManifest if export succeeded, None otherwise.
        """
        filter_config = filter_config or ExportFilter()

        filtered_resources = self._apply_export_filter(resources, filter_config)

        if not filtered_resources:
            logger.warning("No resources match export filter")
            return None

        package_id = f"offline_pkg_{int(datetime.now().timestamp())}"

        manifest = OfflinePackageManifest(
            package_id=package_id,
            created_at=datetime.now().isoformat(),
            resource_count=len(filtered_resources),
            resources=filtered_resources,
            includes_dependencies=include_packages,
            includes_ratings=filter_config.include_ratings,
        )

        try:
            with tarfile.open(output_path, "w:gz") as tar:
                manifest_json = manifest.model_dump_json(indent=2)
                manifest_bytes = manifest_json.encode("utf-8")
                manifest_info = tarfile.TarInfo(name="manifest.json")
                manifest_info.size = len(manifest_bytes)
                tar.addfile(manifest_info, fileobj=__import__("io").BytesIO(manifest_bytes))

                for resource in filtered_resources:
                    resource_path = f"resources/{resource.resource_id}.json"
                    resource_json = resource.model_dump_json(indent=2)
                    resource_bytes = resource_json.encode("utf-8")
                    resource_info = tarfile.TarInfo(name=resource_path)
                    resource_info.size = len(resource_bytes)
                    tar.addfile(resource_info, fileobj=__import__("io").BytesIO(resource_bytes))

                if include_packages:
                    self._add_dependencies_to_package(tar, filtered_resources)

            manifest.total_size_bytes = os.path.getsize(output_path)
            manifest.checksum = self._calculate_file_checksum(output_path)

            return manifest

        except Exception as e:
            logger.error(f"Export failed: {e}")
            return None

    def export_incremental_package(
        self,
        output_path: str,
        resources: List[ResourceMetadata],
        last_export_timestamp: str,
        filter_config: Optional[ExportFilter] = None,
    ) -> Optional[OfflinePackageManifest]:
        """Export only resources changed since last export.

        Args:
            output_path: Path to save the package file.
            resources: List of all resources.
            last_export_timestamp: Timestamp of last export.
            filter_config: Export filter configuration.

        Returns:
            OfflinePackageManifest if export succeeded, None otherwise.
        """
        changed_resources = [
            r for r in resources
            if r.updated_at > last_export_timestamp
        ]

        if not changed_resources:
            logger.info("No resources changed since last export")
            return None

        return self.export_package(output_path, changed_resources, filter_config)

    def import_package(
        self,
        package_path: str,
        merge_conflicts: str = "skip",
    ) -> ImportResult:
        """Import an offline market package.

        Args:
            package_path: Path to the package file.
            merge_conflicts: How to handle conflicts (skip/overwrite/keep_both).

        Returns:
            ImportResult with import statistics.
        """
        result = ImportResult()

        if not os.path.exists(package_path):
            result.errors.append(f"Package file not found: {package_path}")
            return result

        try:
            with tarfile.open(package_path, "r:gz") as tar:
                manifest_member = tar.getmember("manifest.json")
                manifest_file = tar.extractfile(manifest_member)

                if manifest_file is None:
                    result.errors.append("Failed to extract manifest")
                    return result

                manifest_data = json.loads(manifest_file.read().decode("utf-8"))
                manifest = OfflinePackageManifest(**manifest_data)
                result.manifest = manifest

                checksum = self._calculate_file_checksum(package_path)
                if checksum != manifest.checksum:
                    result.errors.append("Package checksum mismatch, file may be corrupted")
                    return result

                for resource in manifest.resources:
                    try:
                        resource_member = tar.getmember(f"resources/{resource.resource_id}.json")
                        resource_file = tar.extractfile(resource_member)

                        if resource_file is None:
                            result.skipped_count += 1
                            continue

                        import_resource = ResourceMetadata(
                            **json.loads(resource_file.read().decode("utf-8"))
                        )

                        if self.sync_engine:
                            existing = self.sync_engine.get_local_resource(
                                import_resource.resource_id
                            )

                            if existing:
                                if merge_conflicts == "skip":
                                    result.skipped_count += 1
                                    continue
                                elif merge_conflicts == "overwrite":
                                    self.sync_engine.add_local_resource(import_resource)
                                    result.imported_count += 1
                                else:
                                    result.conflict_count += 1
                                    result.skipped_count += 1
                            else:
                                self.sync_engine.add_local_resource(import_resource)
                                result.imported_count += 1
                        else:
                            result.imported_count += 1

                    except Exception as e:
                        result.error_count += 1
                        result.errors.append(f"Failed to import {resource.resource_id}: {e}")

                result.success = result.error_count == 0

        except Exception as e:
            result.errors.append(f"Failed to open package: {e}")

        return result

    def validate_package(
        self,
        package_path: str,
    ) -> Tuple[bool, List[str]]:
        """Validate an offline market package.

        Args:
            package_path: Path to the package file.

        Returns:
            Tuple of (is_valid, list of validation errors).
        """
        errors: List[str] = []

        if not os.path.exists(package_path):
            return False, ["Package file not found"]

        try:
            with tarfile.open(package_path, "r:gz") as tar:
                if "manifest.json" not in tar.getnames():
                    errors.append("Missing manifest.json")
                    return False, errors

                manifest_member = tar.getmember("manifest.json")
                manifest_file = tar.extractfile(manifest_member)

                if manifest_file is None:
                    errors.append("Failed to read manifest")
                    return False, errors

                manifest_data = json.loads(manifest_file.read().decode("utf-8"))
                manifest = OfflinePackageManifest(**manifest_data)

                checksum = self._calculate_file_checksum(package_path)
                if checksum != manifest.checksum:
                    errors.append("Checksum mismatch")

                for resource in manifest.resources:
                    resource_path = f"resources/{resource.resource_id}.json"
                    if resource_path not in tar.getnames():
                        errors.append(f"Missing resource file: {resource_path}")

        except Exception as e:
            errors.append(f"Validation error: {e}")

        return len(errors) == 0, errors

    def generate_resource_manifest(
        self,
        package_path: str,
    ) -> Optional[str]:
        """Generate a human-readable resource manifest for a package.

        Args:
            package_path: Path to the package file.

        Returns:
            Formatted manifest string or None.
        """
        try:
            with tarfile.open(package_path, "r:gz") as tar:
                manifest_member = tar.getmember("manifest.json")
                manifest_file = tar.extractfile(manifest_member)

                if manifest_file is None:
                    return None

                manifest_data = json.loads(manifest_file.read().decode("utf-8"))
                manifest = OfflinePackageManifest(**manifest_data)

                lines = [
                    f"离线市场包清单",
                    f"=" * 50,
                    f"包ID: {manifest.package_id}",
                    f"创建时间: {manifest.created_at}",
                    f"资源数量: {manifest.resource_count}",
                    f"包大小: {manifest.total_size_bytes} bytes",
                    f"包含依赖: {'是' if manifest.includes_dependencies else '否'}",
                    f"",
                    f"资源列表:",
                    f"-" * 30,
                ]

                for resource in manifest.resources:
                    lines.append(
                        f"  - {resource.name} (v{resource.version}) "
                        f"[{resource.resource_type.value}]"
                    )

                return "\n".join(lines)

        except Exception as e:
            logger.error(f"Failed to generate manifest: {e}")
            return None

    def _apply_export_filter(
        self,
        resources: List[ResourceMetadata],
        filter_config: ExportFilter,
    ) -> List[ResourceMetadata]:
        """Apply export filter to resources.

        Args:
            resources: List of resources to filter.
            filter_config: Export filter configuration.

        Returns:
            Filtered list of resources.
        """
        filtered = resources

        if filter_config.resource_types:
            filtered = [
                r for r in filtered
                if r.resource_type in filter_config.resource_types
            ]

        if filter_config.tags:
            filtered = [
                r for r in filtered
                if any(tag in r.tags for tag in filter_config.tags)
            ]

        if filter_config.since_timestamp:
            filtered = [
                r for r in filtered
                if r.updated_at > filter_config.since_timestamp
            ]

        if filter_config.max_resources > 0:
            filtered = filtered[: filter_config.max_resources]

        return filtered

    def _add_dependencies_to_package(
        self,
        tar: tarfile.TarFile,
        resources: List[ResourceMetadata],
    ) -> None:
        """Add Python dependencies to the package.

        Args:
            tar: TarFile to add dependencies to.
            resources: List of resources with dependencies.
        """
        dependencies: Set[str] = set()

        for resource in resources:
            for tag in resource.tags:
                if tag.startswith("dep:"):
                    dependencies.add(tag[4:])

        if dependencies:
            requirements = "\n".join(sorted(dependencies))
            requirements_bytes = requirements.encode("utf-8")
            requirements_info = tarfile.TarInfo(name="requirements.txt")
            requirements_info.size = len(requirements_bytes)
            tar.addfile(requirements_info, fileobj=__import__("io").BytesIO(requirements_bytes))

    def _calculate_file_checksum(self, file_path: str) -> str:
        """Calculate SHA256 checksum of a file.

        Args:
            file_path: Path to the file.

        Returns:
            SHA256 hex digest string.
        """
        sha256 = hashlib.sha256()

        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)

        return sha256.hexdigest()
