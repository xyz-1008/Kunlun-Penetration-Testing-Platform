"""Wireless BLE Scanner: BLE device discovery, service enumeration.

Provides:
- BLE device discovery based on Bleak library
- Service and characteristic enumeration
- Unencrypted or weakly encrypted characteristic detection
- Bluetooth device information extraction
- Security vulnerability detection for BLE devices
"""

import asyncio
import logging
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


class BLESecurityLevel(Enum):
    """BLE security levels."""
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass
class BLECharacteristic:
    """BLE characteristic information.

    Attributes:
        uuid: Characteristic UUID
        name: Characteristic name
        properties: List of properties (read/write/notify)
        security_level: Required security level
        is_encrypted: Whether communication is encrypted
        value: Current characteristic value
    """
    uuid: str = ""
    name: str = ""
    properties: List[str] = field(default_factory=list)
    security_level: BLESecurityLevel = BLESecurityLevel.NONE
    is_encrypted: bool = False
    value: bytes = b""


@dataclass
class BLEService:
    """BLE service information.

    Attributes:
        uuid: Service UUID
        name: Service name
        characteristics: List of characteristics
        is_primary: Whether service is primary
    """
    uuid: str = ""
    name: str = ""
    characteristics: List[BLECharacteristic] = field(default_factory=list)
    is_primary: bool = True


@dataclass
class BLEDeviceInfo:
    """BLE device information.

    Attributes:
        address: Device MAC address
        name: Device name
        rssi: Received signal strength indicator
        manufacturer_data: Manufacturer specific data
        services: List of discovered services
        security_findings: List of security findings
    """
    address: str = ""
    name: str = ""
    rssi: int = 0
    manufacturer_data: Dict[str, bytes] = field(default_factory=dict)
    services: List[BLEService] = field(default_factory=list)
    security_findings: List[str] = field(default_factory=list)


@dataclass
class BLEScanResult:
    """Complete BLE scan result.

    Attributes:
        discovered_devices: List of discovered devices
        total_devices: Total number of devices discovered
        scan_duration: Scan duration in seconds
        scan_timestamp: Scan timestamp
    """
    discovered_devices: List[BLEDeviceInfo] = field(default_factory=list)
    total_devices: int = 0
    scan_duration: float = 0.0
    scan_timestamp: float = 0.0


class BLEScanner:
    """Scans BLE devices for security vulnerabilities.

    Provides device discovery, service enumeration, and
    security assessment for Bluetooth Low Energy devices.
    """

    KNOWN_SERVICES = {
        "00001800-0000-1000-8000-00805f9b34fb": "Generic Access",
        "00001801-0000-1000-8000-00805f9b34fb": "Generic Attribute",
        "0000180a-0000-1000-8000-00805f9b34fb": "Device Information",
        "0000180f-0000-1000-8000-00805f9b34fb": "Battery Service",
        "0000181a-0000-1000-8000-00805f9b34fb": "Environmental Sensing",
        "0000181b-0000-1000-8000-00805f9b34fb": "Body Composition",
        "0000181d-0000-1000-8000-00805f9b34fb": "User Data",
        "0000181e-0000-1000-8000-00805f9b34fb": "Weight Scale",
        "00001530-1212-efde-1523-785feabcd123": "Nordic UART",
        "6e400001-b5a3-f393-e0a9-e50e24dcca9e": "Nordic UART Service",
    }

    KNOWN_CHARACTERISTICS = {
        "00002a00-0000-1000-8000-00805f9b34fb": "Device Name",
        "00002a01-0000-1000-8000-00805f9b34fb": "Appearance",
        "00002a04-0000-1000-8000-00805f9b34fb": "Peripheral Preferred Connection Parameters",
        "00002a05-0000-1000-8000-00805f9b34fb": "Service Changed",
        "00002a19-0000-1000-8000-00805f9b34fb": "Battery Level",
        "00002a24-0000-1000-8000-00805f9b34fb": "Model Number String",
        "00002a25-0000-1000-8000-00805f9b34fb": "Serial Number String",
        "00002a26-0000-1000-8000-00805f9b34fb": "Firmware Revision String",
        "00002a27-0000-1000-8000-00805f9b34fb": "Hardware Revision String",
        "00002a28-0000-1000-8000-00805f9b34fb": "Software Revision String",
        "00002a29-0000-1000-8000-00805f9b34fb": "Manufacturer Name String",
        "6e400002-b5a3-f393-e0a9-e50e24dcca9e": "Nordic UART TX",
        "6e400003-b5a3-f393-e0a9-e50e24dcca9e": "Nordic UART RX",
    }

    SENSITIVE_SERVICES = {
        "00001800-0000-1000-8000-00805f9b34fb",
        "0000180a-0000-1000-8000-00805f9b34fb",
        "00001530-1212-efde-1523-785feabcd123",
    }

    def __init__(self, timeout: float = 5.0) -> None:
        """Initialize BLE scanner.

        Args:
            timeout: Scan timeout in seconds.
        """
        self.timeout = timeout
        self._bleak_available = self._check_bleak_availability()

    def _check_bleak_availability(self) -> bool:
        """Check if Bleak library is available.

        Returns:
            True if Bleak is installed.
        """
        try:
            import bleak  # type: ignore
            return True
        except ImportError:
            return False

    async def scan_devices(self, duration: float = 10.0) -> BLEScanResult:
        """Scan for nearby BLE devices.

        Args:
            duration: Scan duration in seconds.

        Returns:
            BLEScanResult with discovered devices.
        """
        result = BLEScanResult(
            scan_timestamp=time.time(),
        )

        if not self._bleak_available:
            logger.warning("Bleak library not available - BLE scanning disabled")
            return result

        try:
            from bleak import BleakScanner

            start_time = time.time()
            devices = await BleakScanner.discover(timeout=duration)
            result.scan_duration = time.time() - start_time

            for device in devices:
                device_info = BLEDeviceInfo(
                    address=device.address,
                    name=device.name or "Unknown",
                    rssi=device.rssi or 0,
                )

                if device.metadata:
                    device_info.manufacturer_data = device.metadata.get("manufacturer_data", {})

                result.discovered_devices.append(device_info)

            result.total_devices = len(result.discovered_devices)

        except Exception as e:
            logger.error(f"BLE scan failed: {e}")

        return result

    async def enumerate_services(self, device_address: str) -> Optional[BLEDeviceInfo]:
        """Enumerate services and characteristics of a BLE device.

        Args:
            device_address: Device MAC address.

        Returns:
            BLEDeviceInfo with services and characteristics.
        """
        if not self._bleak_available:
            return None

        try:
            from bleak import BleakClient

            device_info = BLEDeviceInfo(address=device_address)

            async with BleakClient(device_address) as client:
                if not client.is_connected:
                    return None

                device_info.name = (
                    await client.read_gatt_char("00002a00-0000-1000-8000-00805f9b34fb")
                ).decode("utf-8", errors="ignore")

                services = await client.get_services()

                for service in services:
                    ble_service = BLEService(
                        uuid=str(service.uuid),
                        name=self.KNOWN_SERVICES.get(str(service.uuid), "Unknown Service"),
                        is_primary=True,
                    )

                    for char in service.characteristics:
                        characteristic = BLECharacteristic(
                            uuid=str(char.uuid),
                            name=self.KNOWN_CHARACTERISTICS.get(str(char.uuid), "Unknown Characteristic"),
                            properties=char.properties or [],
                            security_level=BLESecurityLevel.NONE,
                            is_encrypted=False,
                        )

                        if "read" in characteristic.properties:
                            try:
                                value = await client.read_gatt_char(char.uuid)
                                characteristic.value = value
                            except Exception:
                                pass

                        ble_service.characteristics.append(characteristic)

                    device_info.services.append(ble_service)

                self._analyze_security(device_info)

            return device_info

        except Exception as e:
            logger.error(f"Service enumeration failed: {e}")
            return None

    async def test_characteristic_access(
        self,
        device_address: str,
        characteristic_uuid: str,
    ) -> Optional[BLECharacteristic]:
        """Test access to a specific characteristic.

        Args:
            device_address: Device MAC address.
            characteristic_uuid: Characteristic UUID.

        Returns:
            BLECharacteristic with access information.
        """
        if not self._bleak_available:
            return None

        try:
            from bleak import BleakClient

            characteristic = BLECharacteristic(uuid=characteristic_uuid)

            async with BleakClient(device_address) as client:
                if not client.is_connected:
                    return None

                if "read" in characteristic.properties:
                    try:
                        value = await client.read_gatt_char(characteristic_uuid)
                        characteristic.value = value
                    except Exception:
                        pass

                if "write" in characteristic.properties:
                    try:
                        await client.write_gatt_char(characteristic_uuid, b"\x00")
                        characteristic.security_level = BLESecurityLevel.NONE
                    except Exception:
                        characteristic.security_level = BLESecurityLevel.HIGH

            return characteristic

        except Exception as e:
            logger.error(f"Characteristic access test failed: {e}")
            return None

    def _analyze_security(self, device_info: BLEDeviceInfo) -> None:
        """Analyze security of BLE device.

        Args:
            device_info: Device information to analyze.
        """
        for service in device_info.services:
            if service.uuid in self.SENSITIVE_SERVICES:
                for char in service.characteristics:
                    if not char.is_encrypted and "write" in char.properties:
                        device_info.security_findings.append(
                            f"Unencrypted writable characteristic: {char.uuid}"
                        )

                    if char.security_level == BLESecurityLevel.NONE:
                        device_info.security_findings.append(
                            f"No security on characteristic: {char.uuid}"
                        )

        if not device_info.security_findings:
            device_info.security_findings.append("No obvious security issues detected")

    async def get_device_info(self, device_address: str) -> Optional[Dict[str, Any]]:
        """Get basic device information.

        Args:
            device_address: Device MAC address.

        Returns:
            Dictionary with device information.
        """
        if not self._bleak_available:
            return None

        try:
            from bleak import BleakClient

            info: Dict[str, Any] = {}

            async with BleakClient(device_address) as client:
                if not client.is_connected:
                    return None

                info["address"] = device_address
                info["name"] = client.address
                info["mtu_size"] = client.mtu_size

            return info

        except Exception as e:
            logger.error(f"Failed to get device info: {e}")
            return None
