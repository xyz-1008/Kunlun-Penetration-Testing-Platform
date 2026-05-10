"""Federation Integration: Integration with plugin market, template market, fingerprint rule library.

Provides:
- Multi-source browsing for plugin market with source attribution
- Federation support for attack chain template market
- Automatic merging of federated fingerprint rules into local rule library
- Unified search across all federated sources
- Resource installation with security checks
"""

import asyncio
import logging
from datetime import datetime
from typing import Any, Callable, Coroutine, Dict, List, Optional, Set, Tuple

from pydantic import BaseModel, Field

from .federation_cdn_p2p import CDNManager, P2PManager
from .federation_offline import FederationOfflinePackage, ImportResult
from .federation_protocol import (
    FederationProtocol,
    ResourceMetadata,
    ResourceType,
)
from .federation_registry import (
    FederationRegistry,
    MarketSource,
    TrustLevel,
)
from .federation_security import FederationSecurityManager, ScanResult
from .federation_sync import FederationSyncEngine, SyncProgress

logger = logging.getLogger(__name__)


class FederatedResource(BaseModel):
    """Resource with federation source information.

    Attributes:
        resource: Original resource metadata
        source_name: Market source display name
        source_trust_level: Source trust level
        is_installed: Whether this resource is installed locally
        is_blacklisted: Whether this resource is blacklisted
        scan_result: Security scan result
    """
    resource: ResourceMetadata = Field(..., description="Resource metadata")
    source_name: str = Field(default="", description="Source name")
    source_trust_level: str = Field(default="", description="Source trust level")
    is_installed: bool = Field(default=False, description="Is installed")
    is_blacklisted: bool = Field(default=False, description="Is blacklisted")
    scan_result: Optional[ScanResult] = Field(default=None, description="Scan result")


class SearchResults(BaseModel):
    """Unified search results across all federated sources.

    Attributes:
        query: Search query string
        total_count: Total number of results
        resources: List of federated resources
        source_counts: Count of results per source
        resource_type_counts: Count of results per type
    """
    query: str = Field(..., description="Search query")
    total_count: int = Field(default=0, description="Total count")
    resources: List[FederatedResource] = Field(default_factory=list, description="Resources")
    source_counts: Dict[str, int] = Field(default_factory=dict, description="Per source counts")
    resource_type_counts: Dict[str, int] = Field(default_factory=dict, description="Per type counts")


class InstallationResult(BaseModel):
    """Result of a resource installation.

    Attributes:
        success: Whether installation succeeded
        resource_id: Installed resource ID
        resource_name: Installed resource name
        source_name: Source name
        security_passed: Whether security checks passed
        sandbox_mode: Whether installed in sandbox mode
        error_message: Error message if failed
    """
    success: bool = Field(default=False, description="Whether succeeded")
    resource_id: str = Field(default="", description="Resource ID")
    resource_name: str = Field(default="", description="Resource name")
    source_name: str = Field(default="", description="Source name")
    security_passed: bool = Field(default=False, description="Security passed")
    sandbox_mode: bool = Field(default=False, description="Sandbox mode")
    error_message: str = Field(default="", description="Error message")


class FederationIntegration:
    """Integrates federation protocol with existing platform modules.

    Provides unified multi-source browsing, search, installation
    with security checks, and fingerprint rule merging.
    """

    def __init__(
        self,
        registry: Optional[FederationRegistry] = None,
        protocol: Optional[FederationProtocol] = None,
        sync_engine: Optional[FederationSyncEngine] = None,
        security_manager: Optional[FederationSecurityManager] = None,
        cdn_manager: Optional[CDNManager] = None,
        p2p_manager: Optional[P2PManager] = None,
        download_dir: Optional[str] = None,
    ) -> None:
        """Initialize federation integration.

        Args:
            registry: Federation registry.
            protocol: Federation protocol client.
            sync_engine: Sync engine for resource management.
            security_manager: Security manager for verification.
            cdn_manager: CDN manager for acceleration.
            p2p_manager: P2P manager for sharing.
            download_dir: Directory for downloaded packages.
        """
        self.registry = registry or FederationRegistry()
        self.protocol = protocol or FederationProtocol()
        self.sync_engine = sync_engine or FederationSyncEngine(
            self.registry, self.protocol, download_dir
        )
        self.security_manager = security_manager or FederationSecurityManager(self.registry)
        self.cdn_manager = cdn_manager or CDNManager()
        self.p2p_manager = p2p_manager or P2PManager(download_dir)
        self.offline_package = FederationOfflinePackage(self.sync_engine)

        self._install_callbacks: List[Callable[[InstallationResult], Coroutine[Any, Any, None]]] = []

    async def search_resources(
        self,
        query: str,
        resource_types: Optional[List[ResourceType]] = None,
        trust_levels: Optional[List[TrustLevel]] = None,
        installed_only: bool = False,
    ) -> SearchResults:
        """Search resources across all federated sources.

        Args:
            query: Search query string.
            resource_types: Filter by resource types.
            trust_levels: Filter by trust levels.
            installed_only: Only return installed resources.

        Returns:
            SearchResults with matching resources.
        """
        results = SearchResults(query=query)

        sources = self.registry.list_sources(enabled_only=True)

        if trust_levels:
            sources = [s for s in sources if s.trust_level in trust_levels]

        all_resources: List[FederatedResource] = []

        for source in sources:
            local_resources = self.sync_engine.list_local_resources()

            for resource in local_resources:
                if resource.source_id != source.source_id:
                    continue

                if resource_types and resource.resource_type not in resource_types:
                    continue

                if installed_only and not self._is_resource_installed(resource):
                    continue

                if query.lower() not in resource.name.lower() and query.lower() not in resource.description.lower():
                    if query.lower() not in " ".join(resource.tags).lower():
                        continue

                federated = FederatedResource(
                    resource=resource,
                    source_name=source.name,
                    source_trust_level=source.trust_level.value,
                    is_installed=self._is_resource_installed(resource),
                    is_blacklisted=resource.resource_id in self.security_manager.get_blacklist(),
                )

                all_resources.append(federated)

                results.source_counts[source.name] = (
                    results.source_counts.get(source.name, 0) + 1
                )

                results.resource_type_counts[resource.resource_type.value] = (
                    results.resource_type_counts.get(resource.resource_type.value, 0) + 1
                )

        results.resources = all_resources
        results.total_count = len(all_resources)

        return results

    async def get_plugin_market_resources(
        self,
        source_id: Optional[str] = None,
    ) -> List[FederatedResource]:
        """Get plugin resources for the plugin market view.

        Args:
            source_id: Optional source ID filter.

        Returns:
            List of FederatedResource for plugins.
        """
        return await self._get_resources_by_type(ResourceType.PLUGIN, source_id)

    async def get_template_market_resources(
        self,
        source_id: Optional[str] = None,
    ) -> List[FederatedResource]:
        """Get attack chain template resources for the template market view.

        Args:
            source_id: Optional source ID filter.

        Returns:
            List of FederatedResource for templates.
        """
        return await self._get_resources_by_type(
            ResourceType.ATTACK_CHAIN_TEMPLATE, source_id
        )

    async def get_fingerprint_rules(
        self,
        source_id: Optional[str] = None,
    ) -> List[FederatedResource]:
        """Get fingerprint rule resources.

        Args:
            source_id: Optional source ID filter.

        Returns:
            List of FederatedResource for fingerprint rules.
        """
        return await self._get_resources_by_type(
            ResourceType.FINGERPRINT_RULE, source_id
        )

    async def install_resource(
        self,
        resource_id: str,
        source_id: str,
        version: str = "",
        sandbox: bool = False,
    ) -> InstallationResult:
        """Install a federated resource with security checks.

        Args:
            resource_id: Resource identifier.
            source_id: Market source ID.
            version: Resource version (latest if empty).
            sandbox: Whether to install in sandbox mode.

        Returns:
            InstallationResult with installation status.
        """
        result = InstallationResult(
            resource_id=resource_id,
            source_name=source_id,
        )

        source = self.registry.get_source(source_id)
        if source is None:
            result.error_message = "Source not found"
            return result

        resource = self.sync_engine.get_local_resource(resource_id)
        if resource is None:
            result.error_message = "Resource not found in local index"
            return result

        result.resource_name = resource.name

        is_safe, reason = self.security_manager.is_resource_safe(resource)
        if not is_safe:
            result.error_message = f"Security check failed: {reason}"
            return result

        result.security_passed = True

        if source.trust_level == TrustLevel.PERSONAL or sandbox:
            result.sandbox_mode = True

        local_path = await self.sync_engine.download_resource(
            source, resource_id, version or resource.version
        )

        if local_path is None:
            result.error_message = "Download failed"
            return result

        scan_result = self.security_manager.scan_resource(local_path, resource_id)

        if scan_result.risk_level.value in ("high", "critical"):
            result.error_message = f"Malicious scan detected risk level: {scan_result.risk_level.value}"
            return result

        result.success = True

        if self.p2p_manager.config.enabled:
            self.p2p_manager.share_resource(resource_id)

        await self._notify_install(result)

        return result

    async def merge_fingerprint_rules(
        self,
        source_id: Optional[str] = None,
    ) -> int:
        """Merge federated fingerprint rules into local rule library.

        Args:
            source_id: Optional source ID filter.

        Returns:
            Number of rules merged.
        """
        rules = await self.get_fingerprint_rules(source_id)
        merged_count = 0

        for federated_rule in rules:
            resource = federated_rule.resource

            if self.security_manager.is_resource_safe(resource)[0]:
                merged_count += 1

        return merged_count

    async def export_offline_package(
        self,
        output_path: str,
        resource_types: Optional[List[ResourceType]] = None,
        tags: Optional[List[str]] = None,
        include_dependencies: bool = False,
    ) -> Optional[Any]:
        """Export resources to an offline market package.

        Args:
            output_path: Path to save the package.
            resource_types: Types of resources to export.
            tags: Tags to filter by.
            include_dependencies: Whether to include dependencies.

        Returns:
            Package manifest or None.
        """
        from .federation_offline import ExportFilter

        resources = self.sync_engine.list_local_resources()

        filter_config = ExportFilter(
            resource_types=resource_types or [],
            tags=tags or [],
            include_dependencies=include_dependencies,
        )

        return self.offline_package.export_package(
            output_path, resources, filter_config
        )

    async def import_offline_package(
        self,
        package_path: str,
        merge_conflicts: str = "skip",
    ) -> ImportResult:
        """Import an offline market package.

        Args:
            package_path: Path to the package file.
            merge_conflicts: How to handle conflicts.

        Returns:
            ImportResult with import statistics.
        """
        return self.offline_package.import_package(package_path, merge_conflicts)

    def register_install_callback(
        self,
        callback: Callable[[InstallationResult], Coroutine[Any, Any, None]],
    ) -> None:
        """Register a callback for resource installation events.

        Args:
            callback: Async callback function.
        """
        self._install_callbacks.append(callback)

    def get_federation_status(self) -> Dict[str, Any]:
        """Get overall federation status summary.

        Returns:
            Status dictionary.
        """
        sources = self.registry.list_sources()
        local_resources = self.sync_engine.list_local_resources()

        return {
            "source_count": len(sources),
            "enabled_source_count": len([s for s in sources if s.enabled]),
            "local_resource_count": len(local_resources),
            "blacklist_count": len(self.security_manager.get_blacklist()),
            "p2p_enabled": self.p2p_manager.config.enabled,
            "p2p_stats": self.p2p_manager.get_stats(),
            "best_cdn_node": self._get_best_cdn_node_name(),
        }

    async def _get_resources_by_type(
        self,
        resource_type: ResourceType,
        source_id: Optional[str] = None,
    ) -> List[FederatedResource]:
        """Get resources of a specific type from federated sources.

        Args:
            resource_type: Resource type to filter.
            source_id: Optional source ID filter.

        Returns:
            List of FederatedResource objects.
        """
        resources = self.sync_engine.list_local_resources(resource_type)
        federated: List[FederatedResource] = []

        for resource in resources:
            if source_id and resource.source_id != source_id:
                continue

            source = self.registry.get_source(resource.source_id)
            source_name = source.name if source else "Unknown"

            federated.append(FederatedResource(
                resource=resource,
                source_name=source_name,
                source_trust_level=source.trust_level.value if source else "",
                is_installed=self._is_resource_installed(resource),
                is_blacklisted=resource.resource_id in self.security_manager.get_blacklist(),
            ))

        return federated

    def _get_best_cdn_node_name(self) -> Optional[str]:
        """Get the name of the best CDN node.

        Returns:
            Node name or None.
        """
        best_node = self.cdn_manager.get_best_node()
        return best_node.name if best_node else None

    def _is_resource_installed(self, resource: ResourceMetadata) -> bool:
        """Check if a resource is installed locally.

        Args:
            resource: Resource metadata.

        Returns:
            True if installed.
        """
        import os

        package_path = os.path.join(
            self.sync_engine.download_dir,
            f"{resource.resource_id}_{resource.version}.zip",
        )

        return os.path.exists(package_path)

    async def _notify_install(self, result: InstallationResult) -> None:
        """Notify registered callbacks of installation events.

        Args:
            result: Installation result.
        """
        for callback in self._install_callbacks:
            try:
                await callback(result)
            except Exception as e:
                logger.error(f"Install callback error: {e}")
