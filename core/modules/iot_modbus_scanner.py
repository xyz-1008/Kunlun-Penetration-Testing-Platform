"""IoT Modbus Scanner: Modbus function code probing, register read/write testing.

Provides:
- Modbus TCP function code probing (read coils, read holding registers, etc.)
- Device ID and register value enumeration
- Write permission testing
- Modbus protocol implementation (RFC 7252)
- Security vulnerability detection
"""

import asyncio
import logging
import struct
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


class ModbusFunctionCode(Enum):
    """Modbus function codes."""
    READ_COILS = 0x01
    READ_DISCRETE_INPUTS = 0x02
    READ_HOLDING_REGISTERS = 0x03
    READ_INPUT_REGISTERS = 0x04
    WRITE_SINGLE_COIL = 0x05
    WRITE_SINGLE_REGISTER = 0x06
    WRITE_MULTIPLE_COILS = 0x0F
    WRITE_MULTIPLE_REGISTERS = 0x10
    READ_DEVICE_IDENTIFICATION = 0x2B


class ModbusExceptionCode(Enum):
    """Modbus exception codes."""
    ILLEGAL_FUNCTION = 0x01
    ILLEGAL_DATA_ADDRESS = 0x02
    ILLEGAL_DATA_VALUE = 0x03
    SLAVE_DEVICE_FAILURE = 0x04
    ACKNOWLEDGE = 0x05
    SLAVE_DEVICE_BUSY = 0x06
    NEGATIVE_ACKNOWLEDGE = 0x07
    MEMORY_PARITY_ERROR = 0x08
    GATEWAY_PATH_UNAVAILABLE = 0x0A
    GATEWAY_TARGET_FAILED = 0x0B


@dataclass
class ModbusRegister:
    """Modbus register information.

    Attributes:
        address: Register address
        value: Register value
        register_type: Type of register
        is_writable: Whether register is writable
        description: Register description
    """
    address: int = 0
    value: int = 0
    register_type: str = ""
    is_writable: bool = False
    description: str = ""


@dataclass
class ModbusDeviceInfo:
    """Modbus device information.

    Attributes:
        host: Device host
        port: Device port
        unit_id: Unit identifier
        vendor_name: Vendor name
        product_code: Product code
        revision: Firmware revision
        device_id: Device identifier
        security_findings: List of security findings
    """
    host: str = ""
    port: int = 502
    unit_id: int = 1
    vendor_name: str = ""
    product_code: str = ""
    revision: str = ""
    device_id: str = ""
    security_findings: List[str] = field(default_factory=list)


@dataclass
class ModbusScanResult:
    """Complete Modbus scan result.

    Attributes:
        device_info: Device information
        coils: List of coil registers
        discrete_inputs: List of discrete input registers
        holding_registers: List of holding registers
        input_registers: List of input registers
        writable_registers: List of writable registers
        scan_timestamp: Scan timestamp
    """
    device_info: Optional[ModbusDeviceInfo] = None
    coils: List[ModbusRegister] = field(default_factory=list)
    discrete_inputs: List[ModbusRegister] = field(default_factory=list)
    holding_registers: List[ModbusRegister] = field(default_factory=list)
    input_registers: List[ModbusRegister] = field(default_factory=list)
    writable_registers: List[ModbusRegister] = field(default_factory=list)
    scan_timestamp: float = 0.0


class ModbusScanner:
    """Scans Modbus TCP devices for security vulnerabilities.

    Provides function code probing, register enumeration, and
    write permission testing for industrial control systems.
    """

    DEFAULT_UNIT_ID = 1
    MAX_REGISTER_ADDRESS = 65535
    DEFAULT_READ_COUNT = 10

    def __init__(self, timeout: float = 3.0) -> None:
        """Initialize Modbus scanner.

        Args:
            timeout: Request timeout in seconds.
        """
        self.timeout = timeout
        self._transaction_id = 0

    async def scan_device(
        self,
        host: str,
        port: int = 502,
        unit_id: int = DEFAULT_UNIT_ID,
    ) -> ModbusScanResult:
        """Scan a Modbus device for vulnerabilities.

        Args:
            host: Device host address.
            port: Device port number.
            unit_id: Unit identifier.

        Returns:
            ModbusScanResult with scan findings.
        """
        device_info = ModbusDeviceInfo(
            host=host,
            port=port,
            unit_id=unit_id,
        )

        device_info.vendor_name, device_info.product_code, device_info.revision = (
            await self._read_device_identification(host, port, unit_id)
        )

        if device_info.vendor_name:
            device_info.security_findings.append(
                f"Device identified: {device_info.vendor_name} {device_info.product_code}"
            )

        coils = await self._read_coils(host, port, unit_id, 0, self.DEFAULT_READ_COUNT)
        discrete_inputs = await self._read_discrete_inputs(
            host, port, unit_id, 0, self.DEFAULT_READ_COUNT
        )
        holding_registers = await self._read_holding_registers(
            host, port, unit_id, 0, self.DEFAULT_READ_COUNT
        )
        input_registers = await self._read_input_registers(
            host, port, unit_id, 0, self.DEFAULT_READ_COUNT
        )

        writable = []
        for reg in holding_registers:
            write_success = await self._test_write_register(
                host, port, unit_id, reg.address, reg.value
            )
            if write_success:
                reg.is_writable = True
                writable.append(reg)
                device_info.security_findings.append(
                    f"Writable register found at address {reg.address}"
                )

        for coil in coils:
            write_success = await self._test_write_coil(
                host, port, unit_id, coil.address, False
            )
            if write_success:
                coil.is_writable = True
                writable.append(coil)
                device_info.security_findings.append(
                    f"Writable coil found at address {coil.address}"
                )

        if not device_info.security_findings:
            device_info.security_findings.append("No obvious vulnerabilities detected")

        return ModbusScanResult(
            device_info=device_info,
            coils=coils,
            discrete_inputs=discrete_inputs,
            holding_registers=holding_registers,
            input_registers=input_registers,
            writable_registers=writable,
            scan_timestamp=time.time(),
        )

    async def _read_coils(
        self,
        host: str,
        port: int,
        unit_id: int,
        start_address: int,
        quantity: int,
    ) -> List[ModbusRegister]:
        """Read coil registers from device.

        Args:
            host: Device host.
            port: Device port.
            unit_id: Unit identifier.
            start_address: Start address.
            quantity: Number of registers to read.

        Returns:
            List of ModbusRegister objects.
        """
        return await self._read_registers(
            host, port, unit_id, ModbusFunctionCode.READ_COILS,
            start_address, quantity, "coil"
        )

    async def _read_discrete_inputs(
        self,
        host: str,
        port: int,
        unit_id: int,
        start_address: int,
        quantity: int,
    ) -> List[ModbusRegister]:
        """Read discrete input registers from device.

        Args:
            host: Device host.
            port: Device port.
            unit_id: Unit identifier.
            start_address: Start address.
            quantity: Number of registers to read.

        Returns:
            List of ModbusRegister objects.
        """
        return await self._read_registers(
            host, port, unit_id, ModbusFunctionCode.READ_DISCRETE_INPUTS,
            start_address, quantity, "discrete_input"
        )

    async def _read_holding_registers(
        self,
        host: str,
        port: int,
        unit_id: int,
        start_address: int,
        quantity: int,
    ) -> List[ModbusRegister]:
        """Read holding registers from device.

        Args:
            host: Device host.
            port: Device port.
            unit_id: Unit identifier.
            start_address: Start address.
            quantity: Number of registers to read.

        Returns:
            List of ModbusRegister objects.
        """
        return await self._read_registers(
            host, port, unit_id, ModbusFunctionCode.READ_HOLDING_REGISTERS,
            start_address, quantity, "holding"
        )

    async def _read_input_registers(
        self,
        host: str,
        port: int,
        unit_id: int,
        start_address: int,
        quantity: int,
    ) -> List[ModbusRegister]:
        """Read input registers from device.

        Args:
            host: Device host.
            port: Device port.
            unit_id: Unit identifier.
            start_address: Start address.
            quantity: Number of registers to read.

        Returns:
            List of ModbusRegister objects.
        """
        return await self._read_registers(
            host, port, unit_id, ModbusFunctionCode.READ_INPUT_REGISTERS,
            start_address, quantity, "input"
        )

    async def _read_registers(
        self,
        host: str,
        port: int,
        unit_id: int,
        function_code: ModbusFunctionCode,
        start_address: int,
        quantity: int,
        register_type: str,
    ) -> List[ModbusRegister]:
        """Read registers from device.

        Args:
            host: Device host.
            port: Device port.
            unit_id: Unit identifier.
            function_code: Modbus function code.
            start_address: Start address.
            quantity: Number of registers to read.
            register_type: Type of register.

        Returns:
            List of ModbusRegister objects.
        """
        registers = []

        try:
            request = self._build_read_request(
                function_code, start_address, quantity, unit_id
            )

            response = await self._send_request(host, port, request)

            if response and len(response) > 5:
                byte_count = response[5]
                data = response[6:6+byte_count]

                for i in range(quantity):
                    if function_code in (
                        ModbusFunctionCode.READ_COILS,
                        ModbusFunctionCode.READ_DISCRETE_INPUTS,
                    ):
                        byte_index = i // 8
                        bit_index = i % 8
                        if byte_index < len(data):
                            value = (data[byte_index] >> bit_index) & 0x01
                        else:
                            value = 0
                    else:
                        value_index = i * 2
                        if value_index + 1 < len(data):
                            value = struct.unpack(">H", data[value_index:value_index+2])[0]
                        else:
                            value = 0

                    registers.append(ModbusRegister(
                        address=start_address + i,
                        value=value,
                        register_type=register_type,
                    ))

        except Exception as e:
            logger.debug(f"Failed to read {register_type} registers: {e}")

        return registers

    async def _read_device_identification(
        self,
        host: str,
        port: int,
        unit_id: int,
    ) -> Tuple[str, str, str]:
        """Read device identification information.

        Args:
            host: Device host.
            port: Device port.
            unit_id: Unit identifier.

        Returns:
            Tuple of (vendor_name, product_code, revision).
        """
        vendor_name = ""
        product_code = ""
        revision = ""

        try:
            request = self._build_device_identification_request(unit_id)
            response = await self._send_request(host, port, request)

            if response and len(response) > 10:
                num_objects = response[8]
                offset = 9

                for _ in range(num_objects):
                    if offset + 2 > len(response):
                        break

                    object_id = response[offset]
                    object_length = response[offset + 1]
                    offset += 2

                    if offset + object_length > len(response):
                        break

                    object_value = response[offset:offset+object_length].decode(
                        "ascii", errors="ignore"
                    )
                    offset += object_length

                    if object_id == 0x00:
                        vendor_name = object_value
                    elif object_id == 0x01:
                        product_code = object_value
                    elif object_id == 0x02:
                        revision = object_value

        except Exception as e:
            logger.debug(f"Failed to read device identification: {e}")

        return vendor_name, product_code, revision

    async def _test_write_register(
        self,
        host: str,
        port: int,
        unit_id: int,
        address: int,
        value: int,
    ) -> bool:
        """Test if a register is writable.

        Args:
            host: Device host.
            port: Device port.
            unit_id: Unit identifier.
            address: Register address.
            value: Value to write.

        Returns:
            True if write was successful.
        """
        try:
            request = self._build_write_register_request(
                address, value, unit_id
            )

            response = await self._send_request(host, port, request)

            if response and len(response) > 5:
                function_code = response[1]
                return function_code == ModbusFunctionCode.WRITE_SINGLE_REGISTER.value

        except Exception:
            pass

        return False

    async def _test_write_coil(
        self,
        host: str,
        port: int,
        unit_id: int,
        address: int,
        value: bool,
    ) -> bool:
        """Test if a coil is writable.

        Args:
            host: Device host.
            port: Device port.
            unit_id: Unit identifier.
            address: Coil address.
            value: Value to write.

        Returns:
            True if write was successful.
        """
        try:
            request = self._build_write_coil_request(
                address, value, unit_id
            )

            response = await self._send_request(host, port, request)

            if response and len(response) > 5:
                function_code = response[1]
                return function_code == ModbusFunctionCode.WRITE_SINGLE_COIL.value

        except Exception:
            pass

        return False

    async def _send_request(
        self,
        host: str,
        port: int,
        request: bytes,
    ) -> Optional[bytes]:
        """Send a Modbus request and return response.

        Args:
            host: Device host.
            port: Device port.
            request: Request bytes.

        Returns:
            Response bytes or None.
        """
        try:
            reader, writer = await asyncio.open_connection(host, port)

            writer.write(request)
            await writer.drain()

            response = await asyncio.wait_for(reader.read(256), timeout=self.timeout)

            writer.close()
            await writer.wait_closed()

            return response

        except Exception as e:
            logger.debug(f"Modbus request failed: {e}")
            return None

    def _build_read_request(
        self,
        function_code: ModbusFunctionCode,
        start_address: int,
        quantity: int,
        unit_id: int,
    ) -> bytes:
        """Build a Modbus read request.

        Args:
            function_code: Modbus function code.
            start_address: Start address.
            quantity: Number of registers.
            unit_id: Unit identifier.

        Returns:
            Modbus request bytes.
        """
        self._transaction_id = (self._transaction_id + 1) & 0xFFFF

        header = struct.pack(
            ">HHHBB",
            self._transaction_id,
            0x0000,
            0x0006,
            unit_id,
            function_code.value,
        )

        payload = struct.pack(">HH", start_address, quantity)

        return header + payload

    def _build_write_register_request(
        self,
        address: int,
        value: int,
        unit_id: int,
    ) -> bytes:
        """Build a Modbus write register request.

        Args:
            address: Register address.
            value: Value to write.
            unit_id: Unit identifier.

        Returns:
            Modbus request bytes.
        """
        self._transaction_id = (self._transaction_id + 1) & 0xFFFF

        header = struct.pack(
            ">HHHBB",
            self._transaction_id,
            0x0000,
            0x0006,
            unit_id,
            ModbusFunctionCode.WRITE_SINGLE_REGISTER.value,
        )

        payload = struct.pack(">HH", address, value)

        return header + payload

    def _build_write_coil_request(
        self,
        address: int,
        value: bool,
        unit_id: int,
    ) -> bytes:
        """Build a Modbus write coil request.

        Args:
            address: Coil address.
            value: Value to write.
            unit_id: Unit identifier.

        Returns:
            Modbus request bytes.
        """
        self._transaction_id = (self._transaction_id + 1) & 0xFFFF

        header = struct.pack(
            ">HHHBB",
            self._transaction_id,
            0x0000,
            0x0006,
            unit_id,
            ModbusFunctionCode.WRITE_SINGLE_COIL.value,
        )

        value_bytes = b"\xFF\x00" if value else b"\x00\x00"
        payload = struct.pack(">H", address) + value_bytes

        return header + payload

    def _build_device_identification_request(
        self,
        unit_id: int,
    ) -> bytes:
        """Build a Modbus device identification request.

        Args:
            unit_id: Unit identifier.

        Returns:
            Modbus request bytes.
        """
        self._transaction_id = (self._transaction_id + 1) & 0xFFFF

        header = struct.pack(
            ">HHHBB",
            self._transaction_id,
            0x0000,
            0x0007,
            unit_id,
            ModbusFunctionCode.READ_DEVICE_IDENTIFICATION.value,
        )

        payload = struct.pack(">BBB", 0x0E, 0x01, 0x00)

        return header + payload
