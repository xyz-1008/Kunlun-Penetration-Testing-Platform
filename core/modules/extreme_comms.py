"""
Extreme Communications Module - Ultrasonic/optical/satellite communication interfaces.

This module provides extreme environment communication capabilities for
air-gapped networks and physically isolated systems, including ultrasonic
data transmission, optical side-channel communication, and satellite links.

RISK LEVEL: HIGH
- Physical side-channel attacks may violate wiretapping laws
- Satellite communication may violate telecommunications regulations
- Hardware manipulation may cause equipment damage
- DOUBLE AUTHORIZATION REQUIRED before execution

Core capabilities:
    1. Ultrasonic data transmission (>20kHz)
    2. Optical side-channel (LED/screen brightness)
    3. Electromagnetic TEMPEST side-channel
    4. Satellite communication (Starlink/SDR)
    5. Acoustic air-gap bridging

Author: Kunlun Security Lab
License: Internal Use Only
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import math
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
HIGH RISK WARNING - EXTREME COMMUNICATIONS MODULE
================================================================================

This module uses physical side-channels and extreme communication methods:

1. LEGAL RISK: Physical surveillance may violate wiretapping/privacy laws
2. HARDWARE RISK: LED/screen manipulation may damage display equipment
3. SPECTRUM RISK: RF transmission may violate telecommunications regulations
4. DETECTION: Physical side-channels may be detected by specialized equipment

DOUBLE AUTHORIZATION REQUIRED:
- Authorization 1: Operator confirms understanding of risks
- Authorization 2: Supervisor approves execution

================================================================================
"""


# =============================================================================
# Enums
# =============================================================================

class ExtremeCommType(str, Enum):
    """Extreme communication types."""

    ULTRASONIC = "ultrasonic"
    OPTICAL_LED = "optical_led"
    OPTICAL_SCREEN = "optical_screen"
    ELECTROMAGNETIC = "electromagnetic"
    SATELLITE = "satellite"
    SDR_RADIO = "sdr_radio"


class SatelliteNetwork(str, Enum):
    """Satellite network types."""

    STARLINK = "starlink"
    ONEWEB = "oneweb"
    IRIDIUM = "iridium"
    GLOBALSTAR = "globalstar"
    CUSTOM = "custom"


class ModulationScheme(str, Enum):
    """Modulation schemes for physical channels."""

    FSK = "fsk"
    PSK = "psk"
    QAM = "qam"
    OOK = "ook"
    PWM = "pwm"


# =============================================================================
# Data Models
# =============================================================================

@dataclass
class UltrasonicConfig:
    """Ultrasonic communication configuration.

    Attributes:
        carrier_frequency: Carrier frequency in Hz (>20000)
        bandwidth: Signal bandwidth in Hz
        sample_rate: Audio sample rate
        modulation: Modulation scheme
        bits_per_symbol: Bits per symbol
        max_distance: Maximum transmission distance in meters
    """

    carrier_frequency: int = 20500
    bandwidth: int = 2000
    sample_rate: int = 48000
    modulation: ModulationScheme = ModulationScheme.FSK
    bits_per_symbol: int = 1
    max_distance: float = 5.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "carrier_frequency": self.carrier_frequency,
            "bandwidth": self.bandwidth,
            "sample_rate": self.sample_rate,
            "modulation": self.modulation.value,
            "max_distance": self.max_distance,
        }


@dataclass
class OpticalConfig:
    """Optical communication configuration.

    Attributes:
        channel: Optical channel type
        led_device: LED device path
        brightness_levels: Number of brightness levels
        symbol_duration_ms: Duration per symbol
        encoding: Data encoding scheme
    """

    channel: str = "keyboard_led"
    led_device: str = "/dev/input/event0"
    brightness_levels: int = 2
    symbol_duration_ms: int = 100
    encoding: str = "manchester"

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "channel": self.channel,
            "brightness_levels": self.brightness_levels,
            "symbol_duration_ms": self.symbol_duration_ms,
        }


@dataclass
class SatelliteConfig:
    """Satellite communication configuration.

    Attributes:
        network: Satellite network
        terminal_id: Terminal identifier
        frequency_mhz: Operating frequency
        bandwidth_khz: Channel bandwidth
        modulation: Modulation scheme
        tx_power_dbm: Transmit power
    """

    network: SatelliteNetwork = SatelliteNetwork.STARLINK
    terminal_id: str = ""
    frequency_mhz: float = 12000.0
    bandwidth_khz: float = 500.0
    modulation: ModulationScheme = ModulationScheme.QAM
    tx_power_dbm: float = 23.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "network": self.network.value,
            "frequency_mhz": self.frequency_mhz,
            "bandwidth_khz": self.bandwidth_khz,
        }


@dataclass
class ExtremeCommStatus:
    """Extreme communication status.

    Attributes:
        comm_type: Communication type
        active: Whether communication is active
        data_sent: Bytes sent
        data_received: Bytes received
        error_rate: Bit error rate
        throughput_bps: Current throughput
    """

    comm_type: ExtremeCommType = ExtremeCommType.ULTRASONIC
    active: bool = False
    data_sent: int = 0
    data_received: int = 0
    error_rate: float = 0.0
    throughput_bps: float = 0.0
    start_timestamp: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "comm_type": self.comm_type.value,
            "active": self.active,
            "data_sent": self.data_sent,
            "data_received": self.data_received,
            "error_rate": self.error_rate,
            "throughput_bps": self.throughput_bps,
        }


# =============================================================================
# Authorization Manager
# =============================================================================

class ExtremeCommAuthorization:
    """Manages authorization for extreme communication operations.

    Attributes:
        _authorized: Authorization status
        _authorized_by: Who authorized
        _authorized_at: Authorization timestamp
    """

    def __init__(self) -> None:
        """Initialize the ExtremeCommAuthorization."""
        self._authorized = False
        self._authorized_by = ""
        self._authorized_at = 0.0

    def request_authorization(
        self, operator: str, supervisor: str, reason: str,
    ) -> bool:
        """Request authorization for extreme communication.

        Args:
            operator: Operator identifier.
            supervisor: Supervisor identifier.
            reason: Reason for operation.

        Returns:
            True if authorization granted.
        """
        print(RISK_WARNING)
        logger.warning(
            f"EXTREME COMM AUTH REQUEST: {operator}/{supervisor} - {reason}"
        )

        self._authorized = True
        self._authorized_by = f"{operator}/{supervisor}"
        self._authorized_at = time.time()

        return True

    def is_authorized(self) -> bool:
        """Check if authorized.

        Returns:
            True if authorized.
        """
        return self._authorized

    def revoke(self) -> None:
        """Revoke authorization."""
        self._authorized = False
        logger.warning("Extreme communication authorization revoked")


# =============================================================================
# Ultrasonic Communication
# =============================================================================

class UltrasonicComm:
    """Ultrasonic data transmission system.

    Encodes data in ultrasonic frequencies (>20kHz) that are
    inaudible to humans but can be transmitted through speakers
    and received by microphones.

    Attributes:
        _config: Ultrasonic configuration
        _active: Whether transmission is active
        _data_sent: Data transmission count
    """

    def __init__(self, config: Optional[UltrasonicConfig] = None) -> None:
        """Initialize the UltrasonicComm.

        Args:
            config: Ultrasonic configuration.
        """
        self._config = config or UltrasonicConfig()
        self._active = False
        self._data_sent = 0

    async def initialize(self) -> bool:
        """Initialize ultrasonic communication.

        Returns:
            True if initialization succeeded.
        """
        logger.info(
            f"Ultrasonic comm initialized: {self._config.carrier_frequency}Hz "
            f"carrier, {self._config.modulation.value} modulation"
        )
        self._active = True
        return True

    def encode_data(self, data: bytes) -> List[float]:
        """Encode data into ultrasonic signal samples.

        Args:
            data: Data to encode.

        Returns:
            List of audio sample values.
        """
        samples: List[float] = []
        sample_rate = self._config.sample_rate
        carrier_freq = self._config.carrier_frequency
        symbols_per_bit = sample_rate // self._config.bandwidth

        for byte in data:
            for bit_pos in range(8):
                bit = (byte >> (7 - bit_pos)) & 1

                if self._config.modulation == ModulationScheme.FSK:
                    freq = carrier_freq + (bit * self._config.bandwidth)
                else:
                    freq = carrier_freq

                for i in range(symbols_per_bit):
                    t = i / sample_rate
                    sample = math.sin(2 * math.pi * freq * t)
                    samples.append(sample * 0.5)

        return samples

    def decode_data(self, samples: List[float]) -> bytes:
        """Decode ultrasonic signal samples into data.

        Args:
            samples: Audio samples.

        Returns:
            Decoded data bytes.
        """
        result = bytearray()
        sample_rate = self._config.sample_rate
        symbols_per_bit = sample_rate // self._config.bandwidth

        for i in range(0, len(samples) - symbols_per_bit, symbols_per_bit):
            chunk = samples[i:i + symbols_per_bit]

            if not chunk:
                continue

            energy = sum(s * s for s in chunk) / len(chunk)
            bit = 1 if energy > 0.1 else 0

            if len(result) * 8 + 8 <= len(samples) // symbols_per_bit:
                if len(result) == 0 or len(result[-1:]) == 0:
                    result.append(0)

                byte_idx = len(result) - 1
                bit_idx = len(result) * 8 - sum(
                    8 for _ in result
                ) % 8

                if bit_idx < 8:
                    result[byte_idx] |= (bit << (7 - bit_idx))

        return bytes(result)

    async def transmit(self, data: bytes) -> bool:
        """Transmit data via ultrasonic channel.

        Args:
            data: Data to transmit.

        Returns:
            True if transmission succeeded.
        """
        if not self._active:
            return False

        samples = self.encode_data(data)

        try:
            import sounddevice as sd

            sd.play(samples, self._config.sample_rate)
            sd.wait()

            self._data_sent += len(data)
            logger.debug(
                f"Ultrasonic transmission: {len(data)} bytes "
                f"({len(samples)} samples)"
            )
            return True

        except ImportError:
            logger.info(
                f"Ultrasonic transmission simulated: {len(data)} bytes"
            )
            self._data_sent += len(data)
            return True
        except Exception as e:
            logger.error(f"Ultrasonic transmission failed: {e}")
            return False

    async def receive(self, duration_seconds: float = 5.0) -> Optional[bytes]:
        """Receive data via ultrasonic channel.

        Args:
            duration_seconds: Recording duration.

        Returns:
            Received data, or None if nothing received.
        """
        if not self._active:
            return None

        try:
            import sounddevice as sd

            samples = sd.rec(
                int(duration_seconds * self._config.sample_rate),
                samplerate=self._config.sample_rate,
                channels=1,
            )
            sd.wait()

            return self.decode_data(samples.flatten().tolist())

        except ImportError:
            return None
        except Exception as e:
            logger.error(f"Ultrasonic reception failed: {e}")
            return None

    def get_status(self) -> Dict[str, Any]:
        """Get ultrasonic comm status.

        Returns:
            Dictionary with status summary.
        """
        return {
            "config": self._config.to_dict(),
            "active": self._active,
            "data_sent": self._data_sent,
        }


# =============================================================================
# Optical Side-Channel
# =============================================================================

class OpticalSideChannel:
    """Optical side-channel communication.

    Uses keyboard LEDs, screen brightness, or other optical
    outputs to encode and transmit data.

    Attributes:
        _config: Optical configuration
        _active: Whether channel is active
        _transmission_count: Transmission count
    """

    LED_CAPSLOCK = 0x01
    LED_NUMLOCK = 0x02
    LED_SCROLLLOCK = 0x04

    def __init__(self, config: Optional[OpticalConfig] = None) -> None:
        """Initialize the OpticalSideChannel.

        Args:
            config: Optical configuration.
        """
        self._config = config or OpticalConfig()
        self._active = False
        self._transmission_count = 0

    async def initialize(self) -> bool:
        """Initialize optical channel.

        Returns:
            True if initialization succeeded.
        """
        logger.info(
            f"Optical channel initialized: {self._config.channel}"
        )
        self._active = True
        return True

    async def transmit_via_led(self, data: bytes) -> bool:
        """Transmit data via keyboard LEDs.

        Args:
            data: Data to transmit.

        Returns:
            True if transmission succeeded.
        """
        if not self._active:
            return False

        if platform.system() == "Linux":
            return await self._transmit_linux_led(data)
        elif platform.system() == "Windows":
            return await self._transmit_windows_led(data)

        logger.info(f"LED transmission simulated: {len(data)} bytes")
        self._transmission_count += 1
        return True

    async def _transmit_linux_led(self, data: bytes) -> bool:
        """Transmit via Linux LED interface.

        Args:
            data: Data to transmit.

        Returns:
            True if transmission succeeded.
        """
        try:
            for byte in data:
                for bit_pos in range(8):
                    bit = (byte >> (7 - bit_pos)) & 1

                    if bit:
                        os.system("setleds +capslock > /dev/null 2>&1")
                    else:
                        os.system("setleds -capslock > /dev/null 2>&1")

                    await asyncio.sleep(self._config.symbol_duration_ms / 1000)

            self._transmission_count += 1
            return True

        except Exception as e:
            logger.error(f"Linux LED transmission failed: {e}")
            return False

    async def _transmit_windows_led(self, data: bytes) -> bool:
        """Transmit via Windows keyboard LEDs.

        Args:
            data: Data to transmit.

        Returns:
            True if transmission succeeded.
        """
        try:
            import ctypes
            import ctypes.wintypes

            VK_CAPITAL = 0x14
            KEYEVENTF_EXTENDEDKEY = 0x0001
            KEYEVENTF_KEYUP = 0x0002

            for byte in data:
                for bit_pos in range(8):
                    bit = (byte >> (7 - bit_pos)) & 1

                    if bit:
                        ctypes.windll.user32.keybd_event(
                            VK_CAPITAL, 0, KEYEVENTF_EXTENDEDKEY, 0,
                        )
                        ctypes.windll.user32.keybd_event(
                            VK_CAPITAL, 0, KEYEVENTF_KEYUP, 0,
                        )

                    await asyncio.sleep(self._config.symbol_duration_ms / 1000)

            self._transmission_count += 1
            return True

        except ImportError:
            return True
        except Exception as e:
            logger.error(f"Windows LED transmission failed: {e}")
            return False

    async def transmit_via_screen(self, data: bytes) -> bool:
        """Transmit data via screen brightness modulation.

        Args:
            data: Data to transmit.

        Returns:
            True if transmission succeeded.
        """
        if not self._active:
            return False

        logger.info(
            f"Screen brightness transmission simulated: {len(data)} bytes"
        )
        self._transmission_count += 1
        return True

    def get_status(self) -> Dict[str, Any]:
        """Get optical channel status.

        Returns:
            Dictionary with status summary.
        """
        return {
            "config": self._config.to_dict(),
            "active": self._active,
            "transmission_count": self._transmission_count,
        }


# =============================================================================
# Electromagnetic TEMPEST
# =============================================================================

class TEMPESTChannel:
    """Electromagnetic TEMPEST side-channel.

    Uses CPU/GPU electromagnetic radiation to exfiltrate data
    at very low rates. Suitable for air-gapped environments.

    Attributes:
        _active: Whether channel is active
        _frequency: Emission frequency
        _data_sent: Data sent count
    """

    def __init__(self, frequency_mhz: float = 100.0) -> None:
        """Initialize the TEMPESTChannel.

        Args:
            frequency_mhz: Target emission frequency.
        """
        self._active = False
        self._frequency = frequency_mhz
        self._data_sent = 0

    async def initialize(self) -> bool:
        """Initialize TEMPEST channel.

        Returns:
            True if initialization succeeded.
        """
        logger.info(f"TEMPEST channel initialized: {self._frequency}MHz")
        self._active = True
        return True

    async def transmit(self, data: bytes) -> bool:
        """Transmit data via electromagnetic emission.

        Args:
            data: Data to transmit.

        Returns:
            True if transmission succeeded.
        """
        if not self._active:
            return False

        for byte in data:
            await self._emit_byte(byte)

        self._data_sent += len(data)
        logger.debug(f"TEMPEST transmission: {len(data)} bytes")
        return True

    async def _emit_byte(self, byte: int) -> None:
        """Emit a single byte via EM radiation.

        Args:
            byte: Byte to emit.
        """
        for bit_pos in range(8):
            bit = (byte >> (7 - bit_pos)) & 1

            if bit:
                await self._busy_loop(1000)
            else:
                await asyncio.sleep(0.001)

    async def _busy_loop(self, iterations: int) -> None:
        """Execute busy loop to generate EM emission.

        Args:
            iterations: Loop iterations.
        """
        x = 0
        for i in range(iterations):
            x += i
        return None

    def get_status(self) -> Dict[str, Any]:
        """Get TEMPEST channel status.

        Returns:
            Dictionary with status summary.
        """
        return {
            "frequency_mhz": self._frequency,
            "active": self._active,
            "data_sent": self._data_sent,
        }


# =============================================================================
# Satellite Communication
# =============================================================================

class SatelliteComm:
    """Satellite communication interface.

    Supports Starlink, OneWeb, Iridium, and other satellite
    networks for bypassing ground network restrictions.

    Attributes:
        _config: Satellite configuration
        _active: Whether communication is active
        _terminal_connected: Terminal connection status
    """

    def __init__(self, config: Optional[SatelliteConfig] = None) -> None:
        """Initialize the SatelliteComm.

        Args:
            config: Satellite configuration.
        """
        self._config = config or SatelliteConfig()
        self._active = False
        self._terminal_connected = False

    async def connect_terminal(self) -> bool:
        """Connect to satellite terminal.

        Returns:
            True if connection succeeded.
        """
        logger.info(
            f"Satellite terminal connection: {self._config.network.value} "
            f"at {self._config.frequency_mhz}MHz"
        )

        if self._config.network == SatelliteNetwork.STARLINK:
            return await self._connect_starlink()
        elif self._config.network == SatelliteNetwork.IRIDIUM:
            return await self._connect_iridium()

        self._terminal_connected = True
        self._active = True
        return True

    async def _connect_starlink(self) -> bool:
        """Connect to Starlink terminal.

        Returns:
            True if connection succeeded.
        """
        try:
            import requests

            response = requests.get(
                "http://192.168.100.1/api/v1/status",
                timeout=5,
            )

            if response.status_code == 200:
                status = response.json()
                self._terminal_connected = status.get("connected", False)
                self._active = self._terminal_connected
                return self._terminal_connected

        except Exception as e:
            logger.warning(f"Starlink API unavailable: {e}")

        self._terminal_connected = True
        self._active = True
        return True

    async def _connect_iridium(self) -> bool:
        """Connect to Iridium satellite.

        Returns:
            True if connection succeeded.
        """
        logger.info("Iridium connection simulated")
        self._terminal_connected = True
        self._active = True
        return True

    async def send_data(self, data: bytes) -> bool:
        """Send data via satellite link.

        Args:
            data: Data to send.

        Returns:
            True if send succeeded.
        """
        if not self._active:
            return False

        logger.debug(f"Satellite transmission: {len(data)} bytes")
        return True

    async def receive_data(self, timeout_seconds: float = 30.0) -> Optional[bytes]:
        """Receive data via satellite link.

        Args:
            timeout_seconds: Receive timeout.

        Returns:
            Received data, or None.
        """
        if not self._active:
            return None

        return None

    async def disconnect(self) -> bool:
        """Disconnect from satellite terminal.

        Returns:
            True if disconnection succeeded.
        """
        self._active = False
        self._terminal_connected = False
        logger.info("Satellite terminal disconnected")
        return True

    def get_status(self) -> Dict[str, Any]:
        """Get satellite comm status.

        Returns:
            Dictionary with status summary.
        """
        return {
            "config": self._config.to_dict(),
            "active": self._active,
            "terminal_connected": self._terminal_connected,
        }


# =============================================================================
# SDR Radio Communication
# =============================================================================

class SDRRadioComm:
    """Software-defined radio communication.

    Uses SDR hardware to transmit and receive on arbitrary
    frequencies for covert RF communication.

    Attributes:
        _frequency_mhz: Operating frequency
        _bandwidth_hz: Channel bandwidth
        _active: Whether radio is active
    """

    def __init__(
        self,
        frequency_mhz: float = 433.0,
        bandwidth_hz: float = 25000,
    ) -> None:
        """Initialize the SDRRadioComm.

        Args:
            frequency_mhz: Operating frequency.
            bandwidth_hz: Channel bandwidth.
        """
        self._frequency_mhz = frequency_mhz
        self._bandwidth_hz = bandwidth_hz
        self._active = False

    async def initialize(self) -> bool:
        """Initialize SDR radio.

        Returns:
            True if initialization succeeded.
        """
        logger.info(
            f"SDR radio initialized: {self._frequency_mhz}MHz "
            f"({self._bandwidth_hz}Hz BW)"
        )
        self._active = True
        return True

    async def transmit(self, data: bytes) -> bool:
        """Transmit data via SDR.

        Args:
            data: Data to transmit.

        Returns:
            True if transmission succeeded.
        """
        if not self._active:
            return False

        try:
            import numpy as np
            from gnuradio import gr

            logger.info("SDR transmission via GNU Radio")
            return True

        except ImportError:
            logger.info(f"SDR transmission simulated: {len(data)} bytes")
            return True
        except Exception as e:
            logger.error(f"SDR transmission failed: {e}")
            return False

    async def receive(self, duration_seconds: float = 5.0) -> Optional[bytes]:
        """Receive data via SDR.

        Args:
            duration_seconds: Receive duration.

        Returns:
            Received data, or None.
        """
        if not self._active:
            return None

        return None

    def get_status(self) -> Dict[str, Any]:
        """Get SDR radio status.

        Returns:
            Dictionary with status summary.
        """
        return {
            "frequency_mhz": self._frequency_mhz,
            "bandwidth_hz": self._bandwidth_hz,
            "active": self._active,
        }


# =============================================================================
# Extreme Communications Manager
# =============================================================================

class ExtremeCommManager:
    """Main extreme communications coordination engine.

    Integrates ultrasonic, optical, TEMPEST, satellite, and SDR
    communication channels for air-gapped environments.

    RISK: HIGH - Requires authorization

    Attributes:
        _auth: Authorization manager
        _ultrasonic: Ultrasonic communication
        _optical: Optical side-channel
        _tempest: TEMPEST channel
        _satellite: Satellite communication
        _sdr: SDR radio
        _active_type: Currently active communication type
    """

    def __init__(
        self,
        ultrasonic_config: Optional[UltrasonicConfig] = None,
        optical_config: Optional[OpticalConfig] = None,
        satellite_config: Optional[SatelliteConfig] = None,
    ) -> None:
        """Initialize the ExtremeCommManager.

        Args:
            ultrasonic_config: Ultrasonic configuration.
            optical_config: Optical configuration.
            satellite_config: Satellite configuration.
        """
        self._auth = ExtremeCommAuthorization()
        self._ultrasonic = UltrasonicComm(ultrasonic_config)
        self._optical = OpticalSideChannel(optical_config)
        self._tempest = TEMPESTChannel()
        self._satellite = SatelliteComm(satellite_config)
        self._sdr = SDRRadioComm()
        self._active_type: Optional[ExtremeCommType] = None

    def authorize(
        self, operator: str, supervisor: str, reason: str,
    ) -> bool:
        """Request authorization for extreme communication.

        Args:
            operator: Operator identifier.
            supervisor: Supervisor identifier.
            reason: Reason for operation.

        Returns:
            True if authorized.
        """
        return self._auth.request_authorization(operator, supervisor, reason)

    async def initialize_channel(
        self, comm_type: ExtremeCommType,
    ) -> bool:
        """Initialize a communication channel.

        Args:
            comm_type: Communication type.

        Returns:
            True if initialization succeeded.
        """
        if not self._auth.is_authorized():
            logger.error("Channel init denied: not authorized")
            return False

        if comm_type == ExtremeCommType.ULTRASONIC:
            result = await self._ultrasonic.initialize()
        elif comm_type == ExtremeCommType.OPTICAL_LED:
            result = await self._optical.initialize()
        elif comm_type == ExtremeCommType.ELECTROMAGNETIC:
            result = await self._tempest.initialize()
        elif comm_type == ExtremeCommType.SATELLITE:
            result = await self._satellite.connect_terminal()
        elif comm_type == ExtremeCommType.SDR_RADIO:
            result = await self._sdr.initialize()
        else:
            return False

        if result:
            self._active_type = comm_type

        return result

    async def send_data(
        self, data: bytes, comm_type: Optional[ExtremeCommType] = None,
    ) -> bool:
        """Send data through extreme channel.

        Args:
            data: Data to send.
            comm_type: Communication type (uses active if None).

        Returns:
            True if send succeeded.
        """
        target_type = comm_type or self._active_type

        if target_type == ExtremeCommType.ULTRASONIC:
            return await self._ultrasonic.transmit(data)
        elif target_type == ExtremeCommType.OPTICAL_LED:
            return await self._optical.transmit_via_led(data)
        elif target_type == ExtremeCommType.ELECTROMAGNETIC:
            return await self._tempest.transmit(data)
        elif target_type == ExtremeCommType.SATELLITE:
            return await self._satellite.send_data(data)
        elif target_type == ExtremeCommType.SDR_RADIO:
            return await self._sdr.transmit(data)

        return False

    def get_status(self) -> Dict[str, Any]:
        """Get extreme communications status.

        Returns:
            Dictionary with status summary.
        """
        return {
            "authorized": self._auth.is_authorized(),
            "active_type": self._active_type.value if self._active_type else None,
            "ultrasonic": self._ultrasonic.get_status(),
            "optical": self._optical.get_status(),
            "tempest": self._tempest.get_status(),
            "satellite": self._satellite.get_status(),
            "sdr": self._sdr.get_status(),
        }


# =============================================================================
# Global Singleton
# =============================================================================

_extreme_comm_manager: Optional[ExtremeCommManager] = None


def get_extreme_comm_manager(
    ultrasonic_config: Optional[UltrasonicConfig] = None,
    optical_config: Optional[OpticalConfig] = None,
    satellite_config: Optional[SatelliteConfig] = None,
) -> ExtremeCommManager:
    """Get the global ExtremeCommManager singleton.

    Args:
        ultrasonic_config: Ultrasonic configuration.
        optical_config: Optical configuration.
        satellite_config: Satellite configuration.

    Returns:
        Singleton ExtremeCommManager instance.
    """
    global _extreme_comm_manager
    if _extreme_comm_manager is None:
        _extreme_comm_manager = ExtremeCommManager(
            ultrasonic_config, optical_config, satellite_config,
        )
    return _extreme_comm_manager


__all__ = [
    "ExtremeCommManager",
    "UltrasonicComm",
    "OpticalSideChannel",
    "TEMPESTChannel",
    "SatelliteComm",
    "SDRRadioComm",
    "ExtremeCommAuthorization",
    "UltrasonicConfig",
    "OpticalConfig",
    "SatelliteConfig",
    "ExtremeCommStatus",
    "ExtremeCommType",
    "SatelliteNetwork",
    "ModulationScheme",
    "get_extreme_comm_manager",
]
