"""
Windows/Linux提权辅助套件 - 提权失败自愈与降级策略模块
===================================================
失败自动回滚、降级策略链、自愈恢复逻辑。

核心能力:
    1. 失败自动回滚 - 注册表/服务/权限恢复、临时对象清理
    2. 降级策略链 - 内核漏洞 → 服务滥用 → Potato → UAC绕过 → DLL劫持 → 凭据窃取
    3. 自愈恢复 - 服务重启、BSOD风险预警、系统稳定性恢复

Author: 昆仑安全实验室
License: Internal Use Only
"""

from __future__ import annotations

import asyncio
import logging
import os
import platform
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# =============================================================================
# 枚举与数据模型
# =============================================================================

class RollbackStatus(str, Enum):
    """回滚状态"""
    PENDING = "pending"
    SUCCESS = "success"
    FAILED = "failed"
    PARTIAL = "partial"


class ExploitTier(str, Enum):
    """利用层级"""
    KERNEL_EXPLOIT = "kernel_exploit"
    SERVICE_ABUSE = "service_abuse"
    POTATO_FAMILY = "potato_family"
    UAC_BYPASS = "uac_bypass"
    DLL_HIJACK = "dll_hijack"
    CREDENTIAL_THEFT = "credential_theft"


class HealStatus(str, Enum):
    """自愈状态"""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    CRITICAL = "critical"
    BSOD_RISK = "bsod_risk"


@dataclass
class SystemStateSnapshot:
    """系统状态快照

    Attributes:
        snapshot_id: 快照ID
        timestamp: 时间戳
        registry_keys: 注册表键值
        services: 服务状态
        file_permissions: 文件权限
        processes: 进程列表
        temp_objects: 临时对象
    """
    snapshot_id: str = ""
    timestamp: str = ""
    registry_keys: Dict[str, str] = field(default_factory=dict)
    services: Dict[str, str] = field(default_factory=dict)
    file_permissions: Dict[str, str] = field(default_factory=dict)
    processes: List[str] = field(default_factory=list)
    temp_objects: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "snapshot_id": self.snapshot_id,
            "timestamp": self.timestamp,
            "registry_keys": self.registry_keys,
            "services": self.services,
            "file_permissions": self.file_permissions,
            "processes": self.processes,
            "temp_objects": self.temp_objects,
        }


@dataclass
class RollbackResult:
    """回滚结果

    Attributes:
        operation: 操作名
        status: 回滚状态
        details: 详细信息
        error: 错误信息
    """
    operation: str = ""
    status: RollbackStatus = RollbackStatus.PENDING
    details: str = ""
    error: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "operation": self.operation,
            "status": self.status.value,
            "details": self.details,
            "error": self.error,
        }


@dataclass
class FallbackStrategy:
    """降级策略

    Attributes:
        tier: 利用层级
        name: 策略名
        description: 描述
        success_rate: 成功率
        risk_level: 风险等级
        requirements: 前置条件
        command: 执行命令
    """
    tier: ExploitTier = ExploitTier.KERNEL_EXPLOIT
    name: str = ""
    description: str = ""
    success_rate: float = 0.0
    risk_level: str = "high"
    requirements: List[str] = field(default_factory=list)
    command: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "tier": self.tier.value,
            "name": self.name,
            "description": self.description,
            "success_rate": self.success_rate,
            "risk_level": self.risk_level,
            "requirements": self.requirements,
            "command": self.command,
        }


@dataclass
class HealResult:
    """自愈结果

    Attributes:
        status: 自愈状态
        recovered_services: 恢复的服务
        warnings: 警告信息
        bsod_risk: BSOD风险
        recommendations: 建议
    """
    status: HealStatus = HealStatus.HEALTHY
    recovered_services: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    bsod_risk: bool = False
    recommendations: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "status": self.status.value,
            "recovered_services": self.recovered_services,
            "warnings": self.warnings,
            "bsod_risk": self.bsod_risk,
            "recommendations": self.recommendations,
        }


@dataclass
class SelfHealingReport:
    """自愈报告

    Attributes:
        report_id: 报告ID
        timestamp: 时间戳
        rollback_results: 回滚结果
        fallback_chain: 降级链
        heal_result: 自愈结果
        final_status: 最终状态
    """
    report_id: str = ""
    timestamp: str = ""
    rollback_results: List[RollbackResult] = field(default_factory=list)
    fallback_chain: List[FallbackStrategy] = field(default_factory=list)
    heal_result: HealResult = field(default_factory=HealResult)
    final_status: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "report_id": self.report_id,
            "timestamp": self.timestamp,
            "rollback_results": [r.to_dict() for r in self.rollback_results],
            "fallback_chain": [f.to_dict() for f in self.fallback_chain],
            "heal_result": self.heal_result.to_dict(),
            "final_status": self.final_status,
        }


# =============================================================================
# 系统状态快照
# =============================================================================

class SystemStateCapturer:
    """系统状态捕获器

    捕获利用前的系统状态，用于回滚。

    Attributes:
        _is_windows: 是否为Windows系统
    """

    def __init__(self) -> None:
        """初始化系统状态捕获器"""
        self._is_windows = platform.system().lower() == "windows"

    async def capture(self) -> SystemStateSnapshot:
        """捕获系统状态

        Returns:
            系统状态快照
        """
        snapshot = SystemStateSnapshot(
            snapshot_id=f"snapshot_{int(time.time())}",
            timestamp=datetime.now().isoformat(),
        )

        snapshot.registry_keys = await self._capture_registry()
        snapshot.services = await self._capture_services()
        snapshot.file_permissions = await self._capture_file_permissions()
        snapshot.processes = await self._capture_processes()

        return snapshot

    async def _capture_registry(self) -> Dict[str, str]:
        """捕获注册表

        Returns:
            注册表键值
        """
        if not self._is_windows:
            return {}

        keys = [
            "HKLM\\SYSTEM\\CurrentControlSet\\Services",
            "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
            "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager",
        ]

        registry = {}
        for key in keys:
            try:
                proc = await asyncio.create_subprocess_shell(
                    f'reg query "{key}" /v "" 2>nul',
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await proc.communicate(timeout=5)
                output = stdout.decode("utf-8", errors="replace").strip()
                registry[key] = output
            except Exception:
                registry[key] = ""

        return registry

    async def _capture_services(self) -> Dict[str, str]:
        """捕获服务状态

        Returns:
            服务状态
        """
        if self._is_windows:
            return await self._capture_windows_services()
        else:
            return await self._capture_linux_services()

    async def _capture_windows_services(self) -> Dict[str, str]:
        """捕获Windows服务

        Returns:
            服务状态
        """
        services = {}
        try:
            proc = await asyncio.create_subprocess_shell(
                'powershell -Command "'
                "Get-Service | "
                "Select-Object Name, Status | "
                'ConvertTo-Json"',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate(timeout=10)
            output = stdout.decode("utf-8", errors="replace")

            import json
            data = json.loads(output)
            if isinstance(data, dict):
                data = [data]

            for svc in data:
                services[svc.get("Name", "")] = svc.get("Status", "")

        except Exception:
            pass

        return services

    async def _capture_linux_services(self) -> Dict[str, str]:
        """捕获Linux服务

        Returns:
            服务状态
        """
        services = {}
        try:
            proc = await asyncio.create_subprocess_shell(
                "systemctl list-units --type=service --no-pager",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate(timeout=10)
            output = stdout.decode("utf-8", errors="replace")

            for line in output.split("\n"):
                if ".service" in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        services[parts[0]] = parts[1]

        except Exception:
            pass

        return services

    async def _capture_file_permissions(self) -> Dict[str, str]:
        """捕获文件权限

        Returns:
            文件权限
        """
        permissions = {}
        paths = [
            "/etc/passwd",
            "/etc/shadow",
            "/etc/sudoers",
            "/tmp",
        ] if not self._is_windows else [
            "C:\\Windows\\System32\\cmd.exe",
            "C:\\Windows\\Temp",
        ]

        for path in paths:
            try:
                if self._is_windows:
                    cmd = f'icacls "{path}" 2>nul'
                else:
                    cmd = f"ls -la {path} 2>/dev/null"

                proc = await asyncio.create_subprocess_shell(
                    cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await proc.communicate(timeout=5)
                permissions[path] = stdout.decode("utf-8", errors="replace").strip()

            except Exception:
                permissions[path] = ""

        return permissions

    async def _capture_processes(self) -> List[str]:
        """捕获进程列表

        Returns:
            进程列表
        """
        processes = []
        try:
            if self._is_windows:
                cmd = (
                    'powershell -Command "'
                    "Get-Process | "
                    "Select-Object -ExpandProperty Name"
                    '"'
                )
            else:
                cmd = "ps aux | awk '{print $11}'"

            proc = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate(timeout=10)
            processes = stdout.decode("utf-8", errors="replace").strip().split("\n")

        except Exception:
            pass

        return processes


# =============================================================================
# 自动回滚
# =============================================================================

class AutoRollback:
    """自动回滚

    利用失败后自动恢复系统状态。

    Attributes:
        _snapshot: 系统状态快照
        _is_windows: 是否为Windows系统
    """

    def __init__(self) -> None:
        """初始化自动回滚"""
        self._snapshot: Optional[SystemStateSnapshot] = None
        self._is_windows = platform.system().lower() == "windows"

    def set_snapshot(self, snapshot: SystemStateSnapshot) -> None:
        """设置快照

        Args:
            snapshot: 系统状态快照
        """
        self._snapshot = snapshot

    async def rollback_all(self) -> List[RollbackResult]:
        """回滚所有

        Returns:
            回滚结果
        """
        if not self._snapshot:
            return [RollbackResult(
                operation="rollback_all",
                status=RollbackStatus.FAILED,
                error="无可用快照",
            )]

        results = []

        results.append(await self._rollback_registry())
        results.append(await self._rollback_services())
        results.append(await self._rollback_file_permissions())
        results.append(await self._cleanup_temp_objects())

        return results

    async def _rollback_registry(self) -> RollbackResult:
        """回滚注册表

        Returns:
            回滚结果
        """
        if not self._is_windows or not self._snapshot:
            return RollbackResult(
                operation="rollback_registry",
                status=RollbackStatus.FAILED,
                error="不支持或无快照",
            )

        try:
            for key, value in self._snapshot.registry_keys.items():
                if value:
                    proc = await asyncio.create_subprocess_shell(
                        f'reg add "{key}" /ve /d "{value}" /f',
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )
                    _, _ = await proc.communicate(timeout=10)

            return RollbackResult(
                operation="rollback_registry",
                status=RollbackStatus.SUCCESS,
                details=f"回滚 {len(self._snapshot.registry_keys)} 个注册表键",
            )

        except Exception as e:
            return RollbackResult(
                operation="rollback_registry",
                status=RollbackStatus.FAILED,
                error=str(e),
            )

    async def _rollback_services(self) -> RollbackResult:
        """回滚服务

        Returns:
            回滚结果
        """
        if not self._snapshot:
            return RollbackResult(
                operation="rollback_services",
                status=RollbackStatus.FAILED,
                error="无快照",
            )

        try:
            for svc_name, status in self._snapshot.services.items():
                if self._is_windows:
                    cmd = f"sc {svc_name} {status.lower()}"
                else:
                    action = "start" if status == "running" else "stop"
                    cmd = f"systemctl {action} {svc_name}"

                proc = await asyncio.create_subprocess_shell(
                    cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                _, _ = await proc.communicate(timeout=10)

            return RollbackResult(
                operation="rollback_services",
                status=RollbackStatus.SUCCESS,
                details=f"回滚 {len(self._snapshot.services)} 个服务",
            )

        except Exception as e:
            return RollbackResult(
                operation="rollback_services",
                status=RollbackStatus.FAILED,
                error=str(e),
            )

    async def _rollback_file_permissions(self) -> RollbackResult:
        """回滚文件权限

        Returns:
            回滚结果
        """
        if not self._snapshot:
            return RollbackResult(
                operation="rollback_file_permissions",
                status=RollbackStatus.FAILED,
                error="无快照",
            )

        try:
            for path, perms in self._snapshot.file_permissions.items():
                if perms and os.path.exists(path):
                    if self._is_windows:
                        cmd = f'icacls "{path}" /reset'
                    else:
                        cmd = f"chmod {perms.split()[0]} {path}"

                    proc = await asyncio.create_subprocess_shell(
                        cmd,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )
                    _, _ = await proc.communicate(timeout=10)

            return RollbackResult(
                operation="rollback_file_permissions",
                status=RollbackStatus.SUCCESS,
                details=f"回滚 {len(self._snapshot.file_permissions)} 个文件权限",
            )

        except Exception as e:
            return RollbackResult(
                operation="rollback_file_permissions",
                status=RollbackStatus.FAILED,
                error=str(e),
            )

    async def _cleanup_temp_objects(self) -> RollbackResult:
        """清理临时对象

        Returns:
            回滚结果
        """
        if not self._snapshot:
            return RollbackResult(
                operation="cleanup_temp_objects",
                status=RollbackStatus.FAILED,
                error="无快照",
            )

        cleaned = 0
        try:
            for obj in self._snapshot.temp_objects:
                if os.path.exists(obj):
                    if os.path.isfile(obj):
                        os.remove(obj)
                    elif os.path.isdir(obj):
                        import shutil
                        shutil.rmtree(obj, ignore_errors=True)
                    cleaned += 1

            return RollbackResult(
                operation="cleanup_temp_objects",
                status=RollbackStatus.SUCCESS,
                details=f"清理 {cleaned} 个临时对象",
            )

        except Exception as e:
            return RollbackResult(
                operation="cleanup_temp_objects",
                status=RollbackStatus.PARTIAL,
                details=f"清理 {cleaned} 个，失败: {e}",
            )


# =============================================================================
# 降级策略链
# =============================================================================

FALLBACK_CHAIN_WINDOWS = [
    FallbackStrategy(
        tier=ExploitTier.KERNEL_EXPLOIT,
        name="内核漏洞利用",
        description="利用内核漏洞获取SYSTEM权限",
        success_rate=0.3,
        risk_level="critical",
        requirements=["内核版本匹配", "未安装补丁"],
        command="exploit_kernel",
    ),
    FallbackStrategy(
        tier=ExploitTier.SERVICE_ABUSE,
        name="服务权限滥用",
        description="利用可写服务配置提权",
        success_rate=0.6,
        risk_level="high",
        requirements=["SERVICE_CHANGE_CONFIG权限"],
        command="sc config <service> binPath= <payload>",
    ),
    FallbackStrategy(
        tier=ExploitTier.POTATO_FAMILY,
        name="Potato系列",
        description="JuicyPotato/RoguePotato/SweetPotato",
        success_rate=0.5,
        risk_level="high",
        requirements=["SeImpersonatePrivilege"],
        command="JuicyPotato.exe -p <payload>",
    ),
    FallbackStrategy(
        tier=ExploitTier.UAC_BYPASS,
        name="UAC绕过",
        description="绕过UAC获取管理员权限",
        success_rate=0.7,
        risk_level="medium",
        requirements=["当前用户为管理员组成员"],
        command="fodhelper.exe /c <payload>",
    ),
    FallbackStrategy(
        tier=ExploitTier.DLL_HIJACK,
        name="DLL劫持",
        description="劫持高权限进程的DLL加载",
        success_rate=0.4,
        risk_level="medium",
        requirements=["可写DLL路径"],
        command="copy payload.dll <target_path>",
    ),
    FallbackStrategy(
        tier=ExploitTier.CREDENTIAL_THEFT,
        name="凭据窃取",
        description="从缓存中提取高权限Token",
        success_rate=0.3,
        risk_level="low",
        requirements=["Debug权限"],
        command="mimikatz token::elevate",
    ),
]

FALLBACK_CHAIN_LINUX = [
    FallbackStrategy(
        tier=ExploitTier.KERNEL_EXPLOIT,
        name="内核漏洞利用",
        description="利用内核漏洞获取root权限",
        success_rate=0.3,
        risk_level="critical",
        requirements=["内核版本匹配"],
        command="exploit_kernel",
    ),
    FallbackStrategy(
        tier=ExploitTier.SERVICE_ABUSE,
        name="服务权限滥用",
        description="利用sudo配置不当提权",
        success_rate=0.6,
        risk_level="high",
        requirements=["sudo权限"],
        command="sudo -l",
    ),
    FallbackStrategy(
        tier=ExploitTier.POTATO_FAMILY,
        name="SUID提权",
        description="利用SUID位配置不当提权",
        success_rate=0.5,
        risk_level="high",
        requirements=["SUID二进制文件"],
        command="find / -perm -4000 2>/dev/null",
    ),
    FallbackStrategy(
        tier=ExploitTier.UAC_BYPASS,
        name="Capabilities提权",
        description="利用Linux capabilities提权",
        success_rate=0.4,
        risk_level="medium",
        requirements=["特殊capabilities"],
        command="getcap -r / 2>/dev/null",
    ),
    FallbackStrategy(
        tier=ExploitTier.DLL_HIJACK,
        name="共享库劫持",
        description="劫持LD_PRELOAD或共享库",
        success_rate=0.3,
        risk_level="medium",
        requirements=["可写库路径"],
        command="export LD_PRELOAD=<payload.so>",
    ),
    FallbackStrategy(
        tier=ExploitTier.CREDENTIAL_THEFT,
        name="凭据窃取",
        description="从缓存中提取密码/密钥",
        success_rate=0.4,
        risk_level="low",
        requirements=["读取权限"],
        command="cat /etc/shadow",
    ),
]


class FallbackChainManager:
    """降级策略链管理器

    当首选利用失败时，自动降级尝试次级方案。

    Attributes:
        _chain: 降级链
        _current_tier: 当前层级
        _is_windows: 是否为Windows系统
    """

    def __init__(self) -> None:
        """初始化降级策略链管理器"""
        self._is_windows = platform.system().lower() == "windows"
        self._chain = FALLBACK_CHAIN_WINDOWS if self._is_windows else FALLBACK_CHAIN_LINUX
        self._current_tier: int = 0

    def get_chain(self) -> List[FallbackStrategy]:
        """获取降级链

        Returns:
            降级链
        """
        return self._chain

    def get_next_strategy(self) -> Optional[FallbackStrategy]:
        """获取下一个策略

        Returns:
            降级策略
        """
        if self._current_tier >= len(self._chain):
            return None

        strategy = self._chain[self._current_tier]
        self._current_tier += 1

        return strategy

    def reset(self) -> None:
        """重置降级链"""
        self._current_tier = 0

    async def evaluate_environment(self, strategy: FallbackStrategy) -> bool:
        """评估环境是否适合该策略

        Args:
            strategy: 降级策略

        Returns:
            是否适合
        """
        if strategy.tier == ExploitTier.KERNEL_EXPLOIT:
            return await self._check_kernel_exploit_possible()
        elif strategy.tier == ExploitTier.SERVICE_ABUSE:
            return await self._check_service_abuse_possible()
        elif strategy.tier == ExploitTier.POTATO_FAMILY:
            return await self._check_potato_possible()
        elif strategy.tier == ExploitTier.UAC_BYPASS:
            return await self._check_uac_bypass_possible()
        elif strategy.tier == ExploitTier.DLL_HIJACK:
            return await self._check_dll_hijack_possible()
        elif strategy.tier == ExploitTier.CREDENTIAL_THEFT:
            return await self._check_credential_theft_possible()

        return False

    async def _check_kernel_exploit_possible(self) -> bool:
        """检查内核漏洞利用可能性

        Returns:
            是否可能
        """
        try:
            if self._is_windows:
                proc = await asyncio.create_subprocess_shell(
                    'powershell -Command "'
                    "Get-CimInstance Win32_OperatingSystem | "
                    "Select-Object -ExpandProperty Version"
                    '"',
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
            else:
                proc = await asyncio.create_subprocess_shell(
                    "uname -r",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )

            stdout, _ = await proc.communicate()
            return len(stdout.decode("utf-8", errors="replace").strip()) > 0

        except Exception:
            return False

    async def _check_service_abuse_possible(self) -> bool:
        """检查服务滥用可能性

        Returns:
            是否可能
        """
        try:
            if self._is_windows:
                proc = await asyncio.create_subprocess_shell(
                    'powershell -Command "'
                    "Get-Service | Where-Object {$_.StartType -eq 'Auto'} | "
                    "Select-Object -First 1 -ExpandProperty Name"
                    '"',
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
            else:
                proc = await asyncio.create_subprocess_shell(
                    "sudo -l 2>/dev/null | grep -c '(ALL)'",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )

            stdout, _ = await proc.communicate()
            return len(stdout.decode("utf-8", errors="replace").strip()) > 0

        except Exception:
            return False

    async def _check_potato_possible(self) -> bool:
        """检查Potato可能性

        Returns:
            是否可能
        """
        try:
            if self._is_windows:
                proc = await asyncio.create_subprocess_shell(
                    'powershell -Command "'
                    "whoami /priv | "
                    'Select-String SeImpersonatePrivilege"',
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
            else:
                proc = await asyncio.create_subprocess_shell(
                    "find / -perm -4000 2>/dev/null | head -1",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )

            stdout, _ = await proc.communicate()
            return len(stdout.decode("utf-8", errors="replace").strip()) > 0

        except Exception:
            return False

    async def _check_uac_bypass_possible(self) -> bool:
        """检查UAC绕过可能性

        Returns:
            是否可能
        """
        if not self._is_windows:
            return False

        try:
            proc = await asyncio.create_subprocess_shell(
                'powershell -Command "'
                "Get-LocalGroupMember -Name Administrators | "
                'Select-Object -ExpandProperty Name"',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            output = stdout.decode("utf-8", errors="replace")

            return len(output.strip()) > 0

        except Exception:
            return False

    async def _check_dll_hijack_possible(self) -> bool:
        """检查DLL劫持可能性

        Returns:
            是否可能
        """
        try:
            if self._is_windows:
                proc = await asyncio.create_subprocess_shell(
                    'powershell -Command "'
                    "Get-ChildItem C:\\Windows\\Temp -ErrorAction SilentlyContinue | "
                    'Select-Object -First 1"',
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
            else:
                proc = await asyncio.create_subprocess_shell(
                    "ls -la /tmp 2>/dev/null | head -1",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )

            stdout, _ = await proc.communicate()
            return len(stdout.decode("utf-8", errors="replace").strip()) > 0

        except Exception:
            return False

    async def _check_credential_theft_possible(self) -> bool:
        """检查凭据窃取可能性

        Returns:
            是否可能
        """
        try:
            if self._is_windows:
                proc = await asyncio.create_subprocess_shell(
                    'powershell -Command "'
                    "Get-Process -Name lsass -ErrorAction SilentlyContinue | "
                    'Select-Object -First 1"',
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
            else:
                proc = await asyncio.create_subprocess_shell(
                    "test -r /etc/shadow && echo yes",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )

            stdout, _ = await proc.communicate()
            return len(stdout.decode("utf-8", errors="replace").strip()) > 0

        except Exception:
            return False


# =============================================================================
# 自愈恢复
# =============================================================================

class SelfHealingManager:
    """自愈恢复管理器

    恢复系统稳定性，处理服务崩溃和BSOD风险。

    Attributes:
        _is_windows: 是否为Windows系统
    """

    def __init__(self) -> None:
        """初始化自愈恢复管理器"""
        self._is_windows = platform.system().lower() == "windows"

    async def assess_health(self) -> HealResult:
        """评估系统健康

        Returns:
            自愈结果
        """
        result = HealResult()

        result.bsod_risk = await self._check_bsod_risk()
        if result.bsod_risk:
            result.status = HealStatus.BSOD_RISK
            result.warnings.append("检测到BSOD风险，建议放弃该利用向量")
            return result

        crashed_services = await self._check_crashed_services()
        if crashed_services:
            result.status = HealStatus.DEGRADED
            result.recovered_services = await self._restart_services(crashed_services)
            result.warnings.append(f"已重启 {len(crashed_services)} 个崩溃的服务")

        if result.status == HealStatus.HEALTHY:
            result.recommendations.append("系统状态健康，可继续执行")

        return result

    async def _check_bsod_risk(self) -> bool:
        """检查BSOD风险

        Returns:
            是否有风险
        """
        if not self._is_windows:
            return False

        try:
            proc = await asyncio.create_subprocess_shell(
                'powershell -Command "'
                "Get-EventLog -LogName System -EntryType Error -Newest 10 | "
                'Where-Object {$_.Source -eq \'BugCheck\'} | '
                'Measure-Object | '
                'Select-Object -ExpandProperty Count"',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate(timeout=10)
            output = stdout.decode("utf-8", errors="replace").strip()

            return int(output) > 0 if output.isdigit() else False

        except Exception:
            return False

    async def _check_crashed_services(self) -> List[str]:
        """检查崩溃的服务

        Returns:
            崩溃的服务列表
        """
        crashed = []

        try:
            if self._is_windows:
                proc = await asyncio.create_subprocess_shell(
                    'powershell -Command "'
                    "Get-Service | Where-Object {$_.Status -eq 'Stopped'} | "
                    "Select-Object -ExpandProperty Name"
                    '"',
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
            else:
                proc = await asyncio.create_subprocess_shell(
                    "systemctl --failed --no-pager | grep failed | awk '{print $2}'",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )

            stdout, _ = await proc.communicate(timeout=10)
            output = stdout.decode("utf-8", errors="replace").strip()

            if output:
                crashed = output.split("\n")

        except Exception:
            pass

        return crashed

    async def _restart_services(self, services: List[str]) -> List[str]:
        """重启服务

        Args:
            services: 服务列表

        Returns:
            成功重启的服务列表
        """
        restarted = []

        for svc in services:
            try:
                if self._is_windows:
                    cmd = f"sc start {svc}"
                else:
                    cmd = f"systemctl restart {svc}"

                proc = await asyncio.create_subprocess_shell(
                    cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                _, _ = await proc.communicate(timeout=30)

                if proc.returncode == 0:
                    restarted.append(svc)

            except Exception:
                pass

        return restarted


# =============================================================================
# 主自愈模块
# =============================================================================

class PrivescSelfHealingModule:
    """提权失败自愈与降级策略模块

    整合自动回滚、降级策略链、自愈恢复。

    Attributes:
        _capturer: 系统状态捕获器
        _rollback: 自动回滚
        _fallback: 降级策略链管理器
        _healing: 自愈恢复管理器
    """

    def __init__(self) -> None:
        """初始化自愈模块"""
        self._capturer = SystemStateCapturer()
        self._rollback = AutoRollback()
        self._fallback = FallbackChainManager()
        self._healing = SelfHealingManager()

    async def capture_pre_exploit_state(self) -> SystemStateSnapshot:
        """捕获利用前状态

        Returns:
            系统状态快照
        """
        snapshot = await self._capturer.capture()
        self._rollback.set_snapshot(snapshot)
        return snapshot

    async def execute_rollback(self) -> List[RollbackResult]:
        """执行回滚

        Returns:
            回滚结果
        """
        return await self._rollback.rollback_all()

    async def get_next_fallback_strategy(self) -> Optional[FallbackStrategy]:
        """获取下一个降级策略

        Returns:
            降级策略
        """
        strategy = self._fallback.get_next_strategy()

        if strategy:
            is_suitable = await self._fallback.evaluate_environment(strategy)
            if not is_suitable:
                return await self.get_next_fallback_strategy()

        return strategy

    async def reset_fallback_chain(self) -> None:
        """重置降级链"""
        self._fallback.reset()

    async def assess_system_health(self) -> HealResult:
        """评估系统健康

        Returns:
            自愈结果
        """
        return await self._healing.assess_health()

    async def full_recovery(self) -> SelfHealingReport:
        """完整恢复流程

        Returns:
            自愈报告
        """
        report = SelfHealingReport(
            report_id=f"recovery_{int(time.time())}",
            timestamp=datetime.now().isoformat(),
        )

        report.rollback_results = await self.execute_rollback()

        self._fallback.reset()
        while True:
            strategy = await self.get_next_fallback_strategy()
            if not strategy:
                break
            report.fallback_chain.append(strategy)

        report.heal_result = await self.assess_system_health()

        if report.heal_result.bsod_risk:
            report.final_status = "critical_bsod_risk"
        elif report.heal_result.status == HealStatus.DEGRADED:
            report.final_status = "degraded_recovered"
        else:
            report.final_status = "healthy"

        return report


# =============================================================================
# 全局单例
# =============================================================================

_self_healing_module: Optional[PrivescSelfHealingModule] = None


def get_self_healing_module() -> PrivescSelfHealingModule:
    """获取自愈模块全局单例

    Returns:
        PrivescSelfHealingModule 实例
    """
    global _self_healing_module
    if _self_healing_module is None:
        _self_healing_module = PrivescSelfHealingModule()
    return _self_healing_module


__all__ = [
    "PrivescSelfHealingModule",
    "SystemStateCapturer",
    "AutoRollback",
    "FallbackChainManager",
    "SelfHealingManager",
    "SystemStateSnapshot",
    "RollbackResult",
    "FallbackStrategy",
    "HealResult",
    "SelfHealingReport",
    "RollbackStatus",
    "ExploitTier",
    "HealStatus",
    "FALLBACK_CHAIN_WINDOWS",
    "FALLBACK_CHAIN_LINUX",
    "get_self_healing_module",
]
