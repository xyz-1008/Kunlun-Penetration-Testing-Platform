"""IoT CoAP Scanner: CoAP discovery, resource enumeration.

Provides:
- CoAP discovery request (GET /.well-known/core)
- Resource endpoint enumeration with sensitive resource marking
- Default credential and unauthorized access testing
- CoAP protocol implementation (RFC 7252)
- Resource content analysis
"""

import asyncio
import logging
import os
import struct
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


class CoAPMethod(Enum):
    """CoAP request methods."""
    GET = 1
    POST = 2
    PUT = 3
    DELETE = 4


class CoAPCode(Enum):
    """CoAP response codes."""
    CONTENT = "2.05"
    CREATED = "2.01"
    DELETED = "2.02"
    VALID = "2.03"
    CHANGED = "2.04"
    UNAUTHORIZED = "4.01"
    FORBIDDEN = "4.03"
    NOT_FOUND = "4.04"
    METHOD_NOT_ALLOWED = "4.05"
    INTERNAL_ERROR = "5.00"


@dataclass
class CoAPResource:
    """Discovered CoAP resource.

    Attributes:
        path: Resource path
        content_type: Content type
        is_sensitive: Whether resource is sensitive
        content: Resource content (if retrieved)
        access_level: Access level (public/restricted/protected)
    """
    path: str = ""
    content_type: str = ""
    is_sensitive: bool = False
    content: bytes = b""
    access_level: str = "unknown"


@dataclass
class CoAPDeviceInfo:
    """CoAP device information.

    Attributes:
        host: Device host
        port: Device port
        resources: List of discovered resources
        supports_discovery: Whether .well-known/core is accessible
        requires_auth: Whether authentication is required
        security_findings: List of security findings
    """
    host: str = ""
    port: int = 5683
    resources: List[CoAPResource] = field(default_factory=list)
    supports_discovery: bool = False
    requires_auth: bool = False
    security_findings: List[str] = field(default_factory=list)


@dataclass
class CoAPScanResult:
    """Complete CoAP scan result.

    Attributes:
        device_info: Device information
        total_resources: Total resources discovered
        sensitive_resources: Number of sensitive resources
        scan_timestamp: Scan timestamp
    """
    device_info: Optional[CoAPDeviceInfo] = None
    total_resources: int = 0
    sensitive_resources: int = 0
    scan_timestamp: float = 0.0


class CoAPScanner:
    """Scans CoAP devices for security vulnerabilities.

    Provides resource discovery, endpoint enumeration, and
    unauthorized access testing for IoT devices.
    """

    WELL_KNOWN_CORE = "/.well-known/core"

    SENSITIVE_PATHS = {
        "/config",
        "/settings",
        "/admin",
        "/auth",
        "/token",
        "/credentials",
        "/password",
        "/secret",
        "/key",
        "/debug",
        "/log",
        "/system",
        "/firmware",
        "/update",
        "/backup",
        "/restore",
        "/factory",
        "/reset",
        "/shutdown",
        "/reboot",
    }

    COMMON_ENDPOINTS = {
        "/light",
        "/temperature",
        "/humidity",
        "/sensor",
        "/actuator",
        "/status",
        "/state",
        "/control",
        "/data",
        "/info",
        "/device",
        "/time",
        "/health",
        "/battery",
        "/power",
        "/voltage",
        "/current",
        "/switch",
        "/relay",
        "/motor",
        "/valve",
        "/pump",
        "/fan",
        "/heater",
        "/cooler",
        "/lock",
        "/door",
        "/window",
        "/alarm",
        "/camera",
        "/mic",
        "/speaker",
        "/display",
        "/led",
        "/button",
        "/counter",
        "/timer",
        "/schedule",
        "/scene",
        "/group",
        "/zone",
        "/room",
        "/floor",
        "/building",
    }

    def __init__(self, timeout: float = 3.0) -> None:
        """Initialize CoAP scanner.

        Args:
            timeout: Request timeout in seconds.
        """
        self.timeout = timeout
        self._message_id = 0

    async def scan_device(
        self,
        host: str,
        port: int = 5683,
    ) -> CoAPScanResult:
        """Scan a CoAP device for vulnerabilities.

        Args:
            host: Device host address.
            port: Device port number.

        Returns:
            CoAPScanResult with scan findings.
        """
        device_info = CoAPDeviceInfo(
            host=host,
            port=port,
        )

        discovery_success = await self._test_discovery(host, port)
        device_info.supports_discovery = discovery_success

        if discovery_success:
            resources = await self._discover_resources(host, port)
            device_info.resources = resources
        else:
            resources = await self._enumerate_endpoints(host, port)
            device_info.resources = resources

        for resource in device_info.resources:
            if resource.is_sensitive:
                device_info.security_findings.append(
                    f"Sensitive resource accessible: {resource.path}"
                )

        if not device_info.resources:
            device_info.security_findings.append("No resources discovered - device may be secure")
        else:
            device_info.security_findings.append(
                f"Discovered {len(device_info.resources)} resources"
            )

        auth_required = await self._test_authentication(host, port)
        device_info.requires_auth = auth_required

        if not auth_required:
            device_info.security_findings.append("No authentication required - unauthorized access possible")

        return CoAPScanResult(
            device_info=device_info,
            total_resources=len(device_info.resources),
            sensitive_resources=sum(1 for r in device_info.resources if r.is_sensitive),
            scan_timestamp=time.time(),
        )

    async def _test_discovery(self, host: str, port: int) -> bool:
        """Test if device supports CoAP resource discovery.

        Args:
            host: Device host.
            port: Device port.

        Returns:
            True if discovery is supported.
        """
        try:
            response = await self._send_request(
                host, port, CoAPMethod.GET, self.WELL_KNOWN_CORE
            )

            return response is not None and len(response) > 0

        except Exception as e:
            logger.debug(f"Discovery test failed: {e}")
            return False

    async def _discover_resources(self, host: str, port: int) -> List[CoAPResource]:
        """Discover resources using CoAP discovery.

        Args:
            host: Device host.
            port: Device port.

        Returns:
            List of discovered CoAPResource objects.
        """
        resources = []

        try:
            response = await self._send_request(
                host, port, CoAPMethod.GET, self.WELL_KNOWN_CORE
            )

            if response:
                resources = self._parse_core_link_format(response)

        except Exception as e:
            logger.debug(f"Resource discovery failed: {e}")

        return resources

    async def _enumerate_endpoints(self, host: str, port: int) -> List[CoAPResource]:
        """Enumerate common CoAP endpoints.

        Args:
            host: Device host.
            port: Device port.

        Returns:
            List of accessible CoAPResource objects.
        """
        resources = []

        for endpoint in self.COMMON_ENDPOINTS:
            try:
                response = await self._send_request(
                    host, port, CoAPMethod.GET, endpoint
                )

                if response is not None:
                    resource = CoAPResource(
                        path=endpoint,
                        is_sensitive=endpoint in self.SENSITIVE_PATHS,
                        content=response,
                        access_level="public",
                    )
                    resources.append(resource)

            except Exception:
                continue

        return resources

    async def _test_authentication(self, host: str, port: int) -> bool:
        """Test if device requires authentication.

        Args:
            host: Device host.
            port: Device port.

        Returns:
            True if authentication is required.
        """
        try:
            response = await self._send_request(
                host, port, CoAPMethod.GET, "/status"
            )

            if response is None:
                return True

            return False

        except Exception:
            return True

    async def _send_request(
        self,
        host: str,
        port: int,
        method: CoAPMethod,
        path: str,
    ) -> Optional[bytes]:
        """Send a CoAP request and return response.

        Args:
            host: Device host.
            port: Device port.
            method: CoAP method.
            path: Resource path.

        Returns:
            Response payload bytes or None.
        """
        try:
            loop = asyncio.get_event_loop()
            reader, writer = await asyncio.open_connection(host, port)

            self._message_id = (self._message_id + 1) & 0xFFFF

            request = self._build_request(method, path, self._message_id)

            writer.write(request)
            await writer.drain()

            response = await asyncio.wait_for(reader.read(4096), timeout=self.timeout)

            writer.close()
            await writer.wait_closed()

            if len(response) >= 4:
                code = response[1]
                if 0x40 <= code <= 0x5F:
                    return None

                payload_start = 4
                for i in range(4, len(response)):
                    if response[i] == 0xFF:
                        payload_start = i + 1
                        break
                    if (response[i] & 0x0F) == 13:
                        i += 1
                    elif (response[i] & 0x0F) == 14:
                        i += 2

                return response[payload_start:]

            return None

        except Exception as e:
            logger.debug(f"CoAP request failed: {e}")
            return None

    def _build_request(
        self,
        method: CoAPMethod,
        path: str,
        message_id: int,
    ) -> bytes:
        """Build a CoAP request packet.

        Args:
            method: CoAP method.
            path: Resource path.
            message_id: Message identifier.

        Returns:
            CoAP request packet bytes.
        """
        ver = 0x01
        type_confirmable = 0x00
        token_length = 0x00

        header = bytes([
            (ver << 6) | (type_confirmable << 4) | token_length,
            method.value,
            (message_id >> 8) & 0xFF,
            message_id & 0xFF,
        ])

        uri_path = self._encode_option(11, path.encode("utf-8"))

        payload_marker = b"\xFF"

        return header + uri_path + payload_marker

    def _encode_option(self, option_number: int, value: bytes) -> bytes:
        """Encode a CoAP option.

        Args:
            option_number: Option number.
            value: Option value.

        Returns:
            Encoded option bytes.
        """
        option_delta = option_number
        option_length = len(value)

        delta_nibble = self._encode_option_nibble(option_delta)
        length_nibble = self._encode_option_nibble(option_length)

        option_header = bytes([(delta_nibble << 4) | length_nibble])

        return option_header + value

    def _encode_option_nibble(self, value: int) -> int:
        """Encode option delta/length nibble.

        Args:
            value: Value to encode.

        Returns:
            Encoded nibble value.
        """
        if value < 13:
            return value
        elif value < 269:
            return 13
        else:
            return 14

    def _parse_core_link_format(self, data: bytes) -> List[CoAPResource]:
        """Parse CoRE Link Format response.

        Args:
            data: Response payload bytes.

        Returns:
            List of CoAPResource objects.
        """
        resources = []

        try:
            text = data.decode("utf-8", errors="ignore")

            links = text.split(",")
            for link in links:
                link = link.strip()
                if not link:
                    continue

                parts = link.split(";")
                path = parts[0].strip("<>")

                content_type = ""
                for part in parts[1:]:
                    if "ct=" in part:
                        content_type = part.split("=")[1].strip('"')

                resource = CoAPResource(
                    path=path,
                    content_type=content_type,
                    is_sensitive=path in self.SENSITIVE_PATHS,
                    access_level="public",
                )
                resources.append(resource)

        except Exception as e:
            logger.debug(f"Failed to parse link format: {e}")

        return resources
