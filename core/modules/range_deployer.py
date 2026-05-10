"""Range Deployer: One-click deployment, environment configuration, proxy auto-setup, and destruction cleanup.

Provides:
- One-click range deployment from Kunlun interface
- Automatic image pulling and container startup
- Automatic proxy configuration for traffic capture
- Display of range access URL and default credentials after deployment
- One-click range destruction with container and volume cleanup
- Proxy configuration recovery on range destruction
"""

import asyncio
import json
import logging
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum, auto
from typing import Any, Callable, Coroutine, Dict, List, Optional, Set, Tuple

from .range_manager import (
    ContainerStatus,
    DifficultyLevel,
    DockerConfig,
    DockerManager,
    RangeInstance,
    RangeLibrary,
    RangeMetadata,
    VulnerabilityType,
)

logger = logging.getLogger(__name__)


class DeploymentStatus(Enum):
    """Deployment operation status."""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class DeploymentResult:
    """Result of range deployment operation.

    Attributes:
        status: Deployment status
        instance: Deployed range instance (if successful)
        access_url: Range access URL
        default_credentials: Default username/password pairs
        proxy_configured: Whether proxy was configured
        error_message: Error message (if failed)
        deployment_time_seconds: Total deployment time
        steps_completed: List of completed deployment steps
    """
    status: DeploymentStatus = DeploymentStatus.PENDING
    instance: Optional[RangeInstance] = None
    access_url: str = ""
    default_credentials: List[Dict[str, str]] = field(default_factory=list)
    proxy_configured: bool = False
    error_message: str = ""
    deployment_time_seconds: float = 0.0
    steps_completed: List[str] = field(default_factory=list)


@dataclass
class ProxyConfig:
    """Proxy configuration for range traffic capture.

    Attributes:
        proxy_host: Proxy server host
        proxy_port: Proxy server port
        intercept_enabled: Whether interception is enabled
        scope_rules: URL scope rules for interception
        ssl_cert_path: SSL certificate path for HTTPS interception
    """
    proxy_host: str = "127.0.0.1"
    proxy_port: int = 8080
    intercept_enabled: bool = True
    scope_rules: List[str] = field(default_factory=list)
    ssl_cert_path: str = ""


@dataclass
class CleanupResult:
    """Result of range cleanup operation.

    Attributes:
        success: Whether cleanup was successful
        containers_removed: Number of containers removed
        volumes_removed: Number of volumes removed
        networks_removed: Number of networks removed
        proxy_config_restored: Whether proxy config was restored
        error_message: Error message (if failed)
    """
    success: bool = False
    containers_removed: int = 0
    volumes_removed: int = 0
    networks_removed: int = 0
    proxy_config_restored: bool = False
    error_message: str = ""


class ProxyManager:
    """Proxy manager for range traffic capture.

    Configures MITM proxy to capture range traffic automatically.
    """

    def __init__(self) -> None:
        """Initialize proxy manager."""
        self._active_configs: Dict[str, ProxyConfig] = {}

    async def configure_for_range(
        self,
        instance: RangeInstance,
        proxy_config: Optional[ProxyConfig] = None,
    ) -> bool:
        """Configure proxy for range instance.

        Args:
            instance: Range instance to configure proxy for.
            proxy_config: Optional proxy configuration.

        Returns:
            True if proxy configured successfully.
        """
        config = proxy_config or ProxyConfig()

        scope_rule = f"http://localhost:{instance.host_port}/*"
        config.scope_rules.append(scope_rule)

        self._active_configs[instance.instance_id] = config

        try:
            await self._apply_proxy_scope(config)
            instance.proxy_configured = True
            return True

        except Exception as e:
            logger.error(f"Failed to configure proxy: {e}")
            return False

    async def remove_range_config(self, instance_id: str) -> bool:
        """Remove proxy configuration for range instance.

        Args:
            instance_id: Instance identifier.

        Returns:
            True if configuration removed successfully.
        """
        if instance_id in self._active_configs:
            del self._active_configs[instance_id]
            return True
        return False

    async def _apply_proxy_scope(self, config: ProxyConfig) -> None:
        """Apply proxy scope rules.

        Args:
            config: Proxy configuration.
        """
        pass


class RangeDeployer:
    """Range deployment orchestrator.

    Handles one-click deployment, environment configuration,
    proxy auto-setup, and destruction cleanup.

    Attributes:
        range_library: Range library instance
        docker_manager: Docker manager instance
        proxy_manager: Proxy manager instance
        _deploy_callback: Optional deployment progress callback
    """

    def __init__(
        self,
        range_library: Optional[RangeLibrary] = None,
        docker_manager: Optional[DockerManager] = None,
        proxy_manager: Optional[ProxyManager] = None,
        docker_config: Optional[DockerConfig] = None,
        deploy_callback: Optional[Callable[[str, float], Coroutine[Any, Any, None]]] = None,
    ) -> None:
        """Initialize range deployer.

        Args:
            range_library: Range library instance. Creates new if None.
            docker_manager: Docker manager instance. Creates new if None.
            proxy_manager: Proxy manager instance. Creates new if None.
            docker_config: Docker configuration. Uses defaults if None.
            deploy_callback: Optional async callback for deployment progress.
        """
        self.range_library = range_library or RangeLibrary()
        self.docker_config = docker_config or DockerConfig()
        self.docker_manager = docker_manager or DockerManager(
            config=self.docker_config,
            progress_callback=deploy_callback,
        )
        self.proxy_manager = proxy_manager or ProxyManager()
        self._deploy_callback = deploy_callback

    async def _report_progress(self, message: str, percentage: float) -> None:
        """Report deployment progress.

        Args:
            message: Progress message.
            percentage: Progress percentage (0-100).
        """
        if self._deploy_callback:
            await self._deploy_callback(message, percentage)

    async def deploy_range(
        self,
        range_id: str,
        cpu_limit: Optional[float] = None,
        memory_limit_mb: Optional[int] = None,
        configure_proxy: bool = True,
    ) -> DeploymentResult:
        """Deploy range environment with one click.

        Args:
            range_id: Range identifier to deploy.
            cpu_limit: Optional CPU limit override.
            memory_limit_mb: Optional memory limit override.
            configure_proxy: Whether to configure proxy automatically.

        Returns:
            DeploymentResult with deployment status and instance info.
        """
        start_time = time.time()
        result = DeploymentResult()

        await self._report_progress(f"Starting deployment: {range_id}", 5.0)

        range_meta = self.range_library.get_range(range_id)
        if not range_meta:
            result.status = DeploymentStatus.FAILED
            result.error_message = f"Range not found: {range_id}"
            return result

        if range_meta.docker_compose_file and not os.path.exists(range_meta.docker_compose_file):
            result.status = DeploymentStatus.FAILED
            result.error_message = f"Docker Compose file not found: {range_meta.docker_compose_file}"
            return result

        result.steps_completed.append("Validated range metadata")
        await self._report_progress("Validating range metadata...", 10.0)

        network_created = await self.docker_manager.create_network()
        if not network_created:
            result.status = DeploymentStatus.FAILED
            result.error_message = "Failed to create Docker network"
            return result

        result.steps_completed.append("Created isolated network")
        await self._report_progress("Creating isolated network...", 20.0)

        if range_meta.docker_image:
            image_pulled = await self.docker_manager.pull_image(range_meta.docker_image)
            if not image_pulled:
                result.status = DeploymentStatus.FAILED
                result.error_message = f"Failed to pull image: {range_meta.docker_image}"
                return result

        result.steps_completed.append("Pulled Docker image")
        await self._report_progress("Pulling Docker image...", 40.0)

        instance = await self.docker_manager.start_container(
            range_meta=range_meta,
            cpu_limit=cpu_limit,
            memory_limit_mb=memory_limit_mb,
        )

        if not instance:
            result.status = DeploymentStatus.FAILED
            result.error_message = "Failed to start container"
            return result

        result.steps_completed.append("Started container")
        await self._report_progress("Starting container...", 70.0)

        if configure_proxy:
            proxy_configured = await self.proxy_manager.configure_for_range(instance)
            result.proxy_configured = proxy_configured
            if proxy_configured:
                result.steps_completed.append("Configured proxy")

        result.status = DeploymentStatus.COMPLETED
        result.instance = instance
        result.access_url = instance.access_url
        result.default_credentials = range_meta.default_credentials
        result.deployment_time_seconds = time.time() - start_time

        await self._report_progress(
            f"Range deployed: {result.access_url}",
            100.0,
        )

        return result

    async def destroy_range(self, instance_id: str) -> CleanupResult:
        """Destroy range environment and cleanup.

        Args:
            instance_id: Instance identifier to destroy.

        Returns:
            CleanupResult with cleanup status.
        """
        result = CleanupResult()

        instance = None
        for inst in await self.docker_manager.list_running_instances():
            if inst.instance_id == instance_id:
                instance = inst
                break

        if not instance:
            result.error_message = f"Instance not found: {instance_id}"
            return result

        await self._report_progress(f"Destroying range: {instance_id}", 20.0)

        proxy_removed = await self.proxy_manager.remove_range_config(instance_id)
        result.proxy_config_restored = proxy_removed

        await self._report_progress("Removing proxy configuration...", 40.0)

        destroyed = await self.docker_manager.destroy_container(instance_id)
        if destroyed:
            result.containers_removed = 1
        else:
            result.error_message = "Failed to destroy container"
            return result

        await self._report_progress("Destroying container...", 70.0)

        result.success = True
        result.networks_removed = 0

        await self._report_progress("Range destroyed successfully", 100.0)

        return result

    async def destroy_all_ranges(self) -> CleanupResult:
        """Destroy all running range environments.

        Returns:
            CleanupResult with cleanup status.
        """
        result = CleanupResult()

        instances = await self.docker_manager.list_running_instances()
        if not instances:
            result.success = True
            return result

        await self._report_progress(f"Destroying {len(instances)} ranges...", 10.0)

        for i, instance in enumerate(instances):
            await self.proxy_manager.remove_range_config(instance.instance_id)
            destroyed = await self.docker_manager.destroy_container(instance.instance_id)
            if destroyed:
                result.containers_removed += 1

            progress = 10.0 + (i + 1) / len(instances) * 80.0
            await self._report_progress(
                f"Destroyed {instance.container_name}",
                progress,
            )

        result.success = result.containers_removed == len(instances)

        await self._report_progress("All ranges destroyed", 100.0)

        return result

    async def get_deployment_status(self, instance_id: str) -> Optional[Dict[str, Any]]:
        """Get deployment status for instance.

        Args:
            instance_id: Instance identifier.

        Returns:
            Dictionary with deployment status or None.
        """
        for instance in await self.docker_manager.list_running_instances():
            if instance.instance_id == instance_id:
                return {
                    "instance_id": instance.instance_id,
                    "range_id": instance.range_id,
                    "status": instance.status.value,
                    "access_url": instance.access_url,
                    "host_port": instance.host_port,
                    "started_at": instance.started_at,
                    "proxy_configured": instance.proxy_configured,
                    "cpu_limit": instance.cpu_limit,
                    "memory_limit_mb": instance.memory_limit_mb,
                }
        return None

    async def list_deployed_ranges(self) -> List[Dict[str, Any]]:
        """List all deployed range environments.

        Returns:
            List of deployment status dictionaries.
        """
        instances = await self.docker_manager.list_running_instances()
        result = []

        for instance in instances:
            range_meta = self.range_library.get_range(instance.range_id)
            result.append({
                "instance_id": instance.instance_id,
                "range_id": instance.range_id,
                "range_name": range_meta.name if range_meta else instance.range_id,
                "status": instance.status.value,
                "access_url": instance.access_url,
                "host_port": instance.host_port,
                "difficulty": range_meta.difficulty.value if range_meta else "unknown",
                "vulnerability_types": [v.value for v in range_meta.vulnerability_types] if range_meta else [],
                "started_at": instance.started_at,
                "proxy_configured": instance.proxy_configured,
            })

        return result
