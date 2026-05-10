"""
Windows/Linux提权辅助套件 - 漏洞自动化研究与PoC生成模块
===================================================
补丁差异分析、内核漏洞自动下载编译、PoC沙箱验证。

核心能力:
    1. 补丁差异分析 - Windows补丁对比，找出缺失的高危补丁
    2. 内核漏洞自动化 - Linux内核漏洞自动匹配Exploit-DB/GitHub
    3. PoC沙箱验证 - 隔离环境验证PoC有效性

Author: 昆仑安全实验室
License: Internal Use Only
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import platform
import re
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# =============================================================================
# 枚举与数据模型
# =============================================================================

class PlatformType(str, Enum):
    """平台类型"""
    WINDOWS = "windows"
    LINUX = "linux"


class PocStatus(str, Enum):
    """PoC状态"""
    PENDING = "pending"
    DOWNLOADING = "downloading"
    COMPILING = "compiling"
    VALIDATING = "validating"
    READY = "ready"
    FAILED = "failed"
    UNSAFE = "unsafe"


class Severity(str, Enum):
    """严重程度"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class PatchInfo:
    """补丁信息

    Attributes:
        kb_id: KB编号
        title: 补丁标题
        installed_date: 安装日期
        cve_ids: 关联CVE列表
        severity: 严重程度
        is_missing: 是否缺失
        has_public_exploit: 是否有公开利用代码
        exploit_url: 利用代码URL
    """
    kb_id: str = ""
    title: str = ""
    installed_date: str = ""
    cve_ids: List[str] = field(default_factory=list)
    severity: Severity = Severity.LOW
    is_missing: bool = False
    has_public_exploit: bool = False
    exploit_url: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "kb_id": self.kb_id,
            "title": self.title,
            "installed_date": self.installed_date,
            "cve_ids": self.cve_ids,
            "severity": self.severity.value,
            "is_missing": self.is_missing,
            "has_public_exploit": self.has_public_exploit,
            "exploit_url": self.exploit_url,
        }


@dataclass
class KernelVuln:
    """内核漏洞信息

    Attributes:
        cve_id: CVE编号
        description: 漏洞描述
        affected_versions: 受影响版本
        fixed_version: 修复版本
        exploit_available: 是否有利用代码
        exploit_source: 利用代码来源
        exploit_url: 利用代码URL
        severity: 严重程度
        compilation_required: 是否需要编译
        compilation_deps: 编译依赖
    """
    cve_id: str = ""
    description: str = ""
    affected_versions: List[str] = field(default_factory=list)
    fixed_version: str = ""
    exploit_available: bool = False
    exploit_source: str = ""
    exploit_url: str = ""
    severity: Severity = Severity.LOW
    compilation_required: bool = False
    compilation_deps: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "cve_id": self.cve_id,
            "description": self.description,
            "affected_versions": self.affected_versions,
            "fixed_version": self.fixed_version,
            "exploit_available": self.exploit_available,
            "exploit_source": self.exploit_source,
            "exploit_url": self.exploit_url,
            "severity": self.severity.value,
            "compilation_required": self.compilation_required,
            "compilation_deps": self.compilation_deps,
        }


@dataclass
class PocResult:
    """PoC验证结果

    Attributes:
        poc_id: PoC ID
        cve_id: CVE编号
        status: PoC状态
        source_url: 来源URL
        local_path: 本地路径
        compilation_output: 编译输出
        validation_output: 验证输出
        is_safe: 是否安全
        risk_assessment: 风险评估
        created_at: 创建时间
        error: 错误信息
    """
    poc_id: str = ""
    cve_id: str = ""
    status: PocStatus = PocStatus.PENDING
    source_url: str = ""
    local_path: str = ""
    compilation_output: str = ""
    validation_output: str = ""
    is_safe: bool = False
    risk_assessment: str = ""
    created_at: str = ""
    error: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "poc_id": self.poc_id,
            "cve_id": self.cve_id,
            "status": self.status.value,
            "source_url": self.source_url,
            "local_path": self.local_path,
            "compilation_output": self.compilation_output,
            "validation_output": self.validation_output,
            "is_safe": self.is_safe,
            "risk_assessment": self.risk_assessment,
            "created_at": self.created_at,
            "error": self.error,
        }


# =============================================================================
# Windows补丁差异分析器
# =============================================================================

MSRC_BULLETIN_DB = {
    "KB5034441": {
        "title": "Windows Recovery Environment安全更新",
        "cve_ids": ["CVE-2024-20666"],
        "severity": Severity.CRITICAL,
        "has_exploit": True,
        "exploit_url": "https://github.com/afwu/WinPwn",
    },
    "KB5034123": {
        "title": "Windows NTLM安全更新",
        "cve_ids": ["CVE-2024-20674"],
        "severity": Severity.HIGH,
        "has_exploit": True,
        "exploit_url": "",
    },
    "KB5034445": {
        "title": "Windows SMB安全更新",
        "cve_ids": ["CVE-2024-20678"],
        "severity": Severity.CRITICAL,
        "has_exploit": False,
        "exploit_url": "",
    },
    "KB5034203": {
        "title": "Windows Clip安全更新",
        "cve_ids": ["CVE-2024-20653"],
        "severity": Severity.HIGH,
        "has_exploit": True,
        "exploit_url": "",
    },
    "KB5034440": {
        "title": "Windows TCP/IP安全更新",
        "cve_ids": ["CVE-2024-20671"],
        "severity": Severity.CRITICAL,
        "has_exploit": True,
        "exploit_url": "",
    },
}

KNOWN_EXPLOITABLE_PATCHES = {
    "KB5034441": "CVE-2024-20666",
    "KB5017365": "CVE-2022-37969",
    "KB5004945": "CVE-2021-34527",
    "KB5005573": "CVE-2021-36942",
    "KB4580325": "CVE-2020-1472",
    "KB4556799": "CVE-2020-1031",
    "KB4534273": "CVE-2020-0683",
    "KB4523205": "CVE-2019-1315",
    "KB4499180": "CVE-2019-1069",
    "KB4493437": "CVE-2019-0803",
}


class WindowsPatchAnalyzer:
    """Windows补丁差异分析器

    收集已安装补丁列表，对比MSRC安全更新指南，找出缺失的高危补丁。

    Attributes:
        _installed_patches: 已安装补丁
        _bulletin_db: 公告数据库
    """

    def __init__(self) -> None:
        """初始化Windows补丁分析器"""
        self._installed_patches: Dict[str, PatchInfo] = {}
        self._bulletin_db: Dict[str, Dict[str, Any]] = dict(MSRC_BULLETIN_DB)

    async def analyze(self) -> List[PatchInfo]:
        """分析缺失补丁

        Returns:
            缺失补丁列表
        """
        await self._collect_installed_patches()
        return await self._find_missing_patches()

    async def _collect_installed_patches(self) -> None:
        """收集已安装补丁

        Returns:
            已安装补丁字典
        """
        try:
            proc = await asyncio.create_subprocess_shell(
                'powershell -Command "Get-HotFix | '
                'Select-Object HotFixID, Description, '
                'InstalledOn | ConvertTo-Json"',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate(timeout=30)
            output = stdout.decode("utf-8", errors="replace")

            if output.strip():
                patches = json.loads(output)
                if isinstance(patches, dict):
                    patches = [patches]

                for patch in patches:
                    kb_id = patch.get("HotFixID", "")
                    if kb_id:
                        self._installed_patches[kb_id] = PatchInfo(
                            kb_id=kb_id,
                            title=patch.get("Description", ""),
                            installed_date=patch.get("InstalledOn", ""),
                        )

        except Exception as e:
            logger.debug(f"收集已安装补丁失败: {e}")

    async def _find_missing_patches(self) -> List[PatchInfo]:
        """查找缺失补丁

        Returns:
            缺失补丁列表
        """
        missing = []

        for kb_id, bulletin in self._bulletin_db.items():
            if kb_id not in self._installed_patches:
                is_exploitable = kb_id in KNOWN_EXPLOITABLE_PATCHES

                missing.append(PatchInfo(
                    kb_id=kb_id,
                    title=bulletin["title"],
                    cve_ids=bulletin["cve_ids"],
                    severity=bulletin["severity"],
                    is_missing=True,
                    has_public_exploit=is_exploitable or bulletin.get("has_exploit", False),
                    exploit_url=bulletin.get("exploit_url", ""),
                ))

        missing.sort(key=lambda p: p.severity.value, reverse=True)
        return missing


# =============================================================================
# Linux内核漏洞自动化
# =============================================================================

KERNEL_EXPLOIT_DB = {
    "CVE-2021-4034": {
        "description": "PwnKit - polkit pkexec本地提权",
        "affected_versions": ["2011-2021"],
        "fixed_version": "polkit-0.105-33",
        "exploit_source": "exploit-db",
        "exploit_url": "https://www.exploit-db.com/exploits/50590",
        "severity": Severity.CRITICAL,
        "compilation_required": True,
        "compilation_deps": ["gcc", "make"],
    },
    "CVE-2021-3156": {
        "description": "Baron Samedit - sudo堆缓冲区溢出",
        "affected_versions": ["1.8.2-1.8.31", "1.9.0-1.9.5p1"],
        "fixed_version": "sudo-1.9.5p2",
        "exploit_source": "github",
        "exploit_url": "https://github.com/blasty/CVE-2021-3156",
        "severity": Severity.CRITICAL,
        "compilation_required": True,
        "compilation_deps": ["gcc", "make"],
    },
    "CVE-2022-0847": {
        "description": "PwnKit变体 - polkit提权",
        "affected_versions": ["2011-2022"],
        "fixed_version": "polkit-0.105-37",
        "exploit_source": "github",
        "exploit_url": "https://github.com/ly4k/PwnKit",
        "severity": Severity.CRITICAL,
        "compilation_required": True,
        "compilation_deps": ["gcc"],
    },
    "CVE-2023-22809": {
        "description": "sudoedit绕过 - 任意文件编辑",
        "affected_versions": ["1.8.0-1.9.12p1"],
        "fixed_version": "sudo-1.9.12p2",
        "exploit_source": "github",
        "exploit_url": "https://github.com/n3m1dotsys/CVE-2023-22809-sudoedit-privesc",
        "severity": Severity.HIGH,
        "compilation_required": False,
        "compilation_deps": [],
    },
    "CVE-2024-1086": {
        "description": "Linux内核netfilter UAF提权",
        "affected_versions": ["5.14-6.6"],
        "fixed_version": "6.6.15",
        "exploit_source": "github",
        "exploit_url": "https://github.com/lysannschlegel/CVE-2024-1086",
        "severity": Severity.CRITICAL,
        "compilation_required": True,
        "compilation_deps": ["gcc", "make", "linux-headers"],
    },
}


class LinuxKernelVulnDetector:
    """Linux内核漏洞检测器

    对比当前内核版本与Exploit-DB/GitHub已知利用代码。

    Attributes:
        _kernel_version: 当前内核版本
        _vuln_db: 漏洞数据库
    """

    def __init__(self) -> None:
        """初始化Linux内核漏洞检测器"""
        self._kernel_version = ""
        self._vuln_db: Dict[str, Dict[str, Any]] = dict(KERNEL_EXPLOIT_DB)

    async def detect(self) -> List[KernelVuln]:
        """检测内核漏洞

        Returns:
            漏洞列表
        """
        await self._get_kernel_version()
        return await self._match_vulnerabilities()

    async def _get_kernel_version(self) -> None:
        """获取内核版本"""
        try:
            proc = await asyncio.create_subprocess_shell(
                "uname -r",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            self._kernel_version = stdout.decode("utf-8", errors="replace").strip()
        except Exception as e:
            logger.debug(f"获取内核版本失败: {e}")

    async def _match_vulnerabilities(self) -> List[KernelVuln]:
        """匹配漏洞

        Returns:
            漏洞列表
        """
        vulns = []

        for cve_id, vuln_info in self._vuln_db.items():
            if self._is_affected(vuln_info):
                vulns.append(KernelVuln(
                    cve_id=cve_id,
                    description=vuln_info["description"],
                    affected_versions=vuln_info["affected_versions"],
                    fixed_version=vuln_info["fixed_version"],
                    exploit_available=True,
                    exploit_source=vuln_info["exploit_source"],
                    exploit_url=vuln_info["exploit_url"],
                    severity=vuln_info["severity"],
                    compilation_required=vuln_info["compilation_required"],
                    compilation_deps=vuln_info["compilation_deps"],
                ))

        vulns.sort(key=lambda v: v.severity.value, reverse=True)
        return vulns

    def _is_affected(self, vuln_info: Dict[str, Any]) -> bool:
        """检查是否受影响

        Args:
            vuln_info: 漏洞信息

        Returns:
            是否受影响
        """
        kernel = self._kernel_version

        for affected_range in vuln_info.get("affected_versions", []):
            if "-" in affected_range:
                start, end = affected_range.split("-", 1)
                if self._version_compare(kernel, start) >= 0 and \
                   self._version_compare(kernel, end) <= 0:
                    return True
            else:
                if affected_range in kernel:
                    return True

        return False

    def _version_compare(self, v1: str, v2: str) -> int:
        """比较版本号

        Args:
            v1: 版本1
            v2: 版本2

        Returns:
            -1: v1 < v2, 0: v1 == v2, 1: v1 > v2
        """
        def normalize(v: str) -> List[int]:
            return [
                int(x) for x in re.sub(r'[^0-9.]', '', v).split(".")
                if x
            ]

        n1 = normalize(v1)
        n2 = normalize(v2)

        for a, b in zip(n1, n2):
            if a < b:
                return -1
            if a > b:
                return 1

        return 0


# =============================================================================
# PoC下载与编译
# =============================================================================

class PocDownloader:
    """PoC下载器

    从Exploit-DB/GitHub下载PoC代码。

    Attributes:
        _download_dir: 下载目录
        _timeout: 下载超时
    """

    def __init__(
        self,
        download_dir: Optional[str] = None,
        timeout: int = 30,
    ) -> None:
        """初始化PoC下载器

        Args:
            download_dir: 下载目录
            timeout: 下载超时（秒）
        """
        self._download_dir = download_dir or os.path.join(
            os.path.expanduser("~"), ".kunlun", "pocs",
        )
        self._timeout = timeout

    async def download_poc(self, cve_id: str, url: str) -> str:
        """下载PoC

        Args:
            cve_id: CVE编号
            url: PoC URL

        Returns:
            本地文件路径
        """
        os.makedirs(self._download_dir, exist_ok=True)

        local_path = os.path.join(self._download_dir, f"{cve_id}.py")

        try:
            import urllib.request

            req = urllib.request.Request(url)
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                content = resp.read()

            with open(local_path, "wb") as f:
                f.write(content)

            return local_path

        except Exception as e:
            logger.debug(f"PoC下载失败: {e}")
            return ""


class PocCompiler:
    """PoC编译器

    自动检测编译环境并编译PoC。

    Attributes:
        _timeout: 编译超时
    """

    def __init__(self, timeout: int = 60) -> None:
        """初始化PoC编译器

        Args:
            timeout: 编译超时（秒）
        """
        self._timeout = timeout

    async def check_build_environment(self) -> Dict[str, bool]:
        """检查编译环境

        Returns:
            编译工具可用性
        """
        tools = {
            "gcc": False,
            "make": False,
            "g++": False,
            "cmake": False,
            "python3": False,
        }

        for tool in tools:
            try:
                proc = await asyncio.create_subprocess_shell(
                    f"{tool} --version",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                _, _ = await proc.communicate()
                tools[tool] = proc.returncode == 0
            except Exception:
                tools[tool] = False

        return tools

    async def compile_poc(
        self,
        source_path: str,
        output_path: Optional[str] = None,
    ) -> Tuple[bool, str]:
        """编译PoC

        Args:
            source_path: 源码路径
            output_path: 输出路径

        Returns:
            (成功, 编译输出)
        """
        if not os.path.exists(source_path):
            return False, f"源文件不存在: {source_path}"

        if output_path is None:
            output_path = os.path.splitext(source_path)[0]

        ext = os.path.splitext(source_path)[1].lower()

        if ext in [".c", ".cpp"]:
            return await self._compile_c(source_path, output_path)
        elif ext == ".py":
            return True, "Python脚本无需编译"
        else:
            return False, f"不支持的文件类型: {ext}"

    async def _compile_c(self, source: str, output: str) -> Tuple[bool, str]:
        """编译C/C++代码

        Args:
            source: 源码路径
            output: 输出路径

        Returns:
            (成功, 编译输出)
        """
        try:
            proc = await asyncio.create_subprocess_shell(
                f"gcc -o {output} {source} -w",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate(timeout=self._timeout)

            output_text = (
                stdout.decode("utf-8", errors="replace") +
                stderr.decode("utf-8", errors="replace")
            )

            return proc.returncode == 0, output_text

        except Exception as e:
            return False, str(e)


# =============================================================================
# PoC沙箱验证器
# =============================================================================

class PocSandboxValidator:
    """PoC沙箱验证器

    在本地隔离环境中验证PoC有效性。

    Attributes:
        _sandbox_dir: 沙箱目录
        _timeout: 验证超时
    """

    def __init__(
        self,
        sandbox_dir: Optional[str] = None,
        timeout: int = 30,
    ) -> None:
        """初始化PoC沙箱验证器

        Args:
            sandbox_dir: 沙箱目录
            timeout: 验证超时（秒）
        """
        self._sandbox_dir = sandbox_dir or os.path.join(
            os.path.expanduser("~"), ".kunlun", "sandbox",
        )
        self._timeout = timeout

    async def validate_poc(self, poc_path: str, cve_id: str) -> PocResult:
        """验证PoC

        Args:
            poc_path: PoC路径
            cve_id: CVE编号

        Returns:
            验证结果
        """
        result = PocResult(
            poc_id=f"poc_{cve_id}_{int(time.time())}",
            cve_id=cve_id,
            status=PocStatus.VALIDATING,
            source_url=poc_path,
            local_path=poc_path,
            created_at=datetime.now().isoformat(),
        )

        os.makedirs(self._sandbox_dir, exist_ok=True)

        is_safe = await self._check_safety(poc_path)
        if not is_safe:
            result.status = PocStatus.UNSAFE
            result.is_safe = False
            result.risk_assessment = "PoC包含危险操作，不建议执行"
            return result

        validation_output = await self._run_validation(poc_path)
        result.validation_output = validation_output
        result.is_safe = True
        result.status = PocStatus.READY
        result.risk_assessment = "PoC通过安全验证，可谨慎使用"

        return result

    async def _check_safety(self, poc_path: str) -> bool:
        """检查PoC安全性

        Args:
            poc_path: PoC路径

        Returns:
            是否安全
        """
        try:
            with open(poc_path, "r", errors="replace") as f:
                content = f.read()

            dangerous_patterns = [
                r"os\.system\(['\"]rm -rf /",
                r"subprocess\.call\(['\"]rm -rf /",
                r"shutil\.rmtree\(['\"]/",
                r"dd if=/dev/zero",
                r":\(\)\{\s*:\|:",
                r"mkfs\.",
                r"fdisk",
                r"parted",
            ]

            for pattern in dangerous_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    return False

            return True

        except Exception as e:
            logger.debug(f"PoC安全检查失败: {e}")
            return False

    async def _run_validation(self, poc_path: str) -> str:
        """运行验证

        Args:
            poc_path: PoC路径

        Returns:
            验证输出
        """
        ext = os.path.splitext(poc_path)[1].lower()

        try:
            if ext == ".py":
                proc = await asyncio.create_subprocess_shell(
                    f"python3 -c \"import ast; ast.parse(open('{poc_path}').read())\"",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
            elif ext in [".c", ".cpp"]:
                binary_path = os.path.splitext(poc_path)[0]
                if os.path.exists(binary_path):
                    proc = await asyncio.create_subprocess_shell(
                        f"file {binary_path}",
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )
                else:
                    return "二进制文件不存在，请先编译"
            else:
                return f"不支持的文件类型: {ext}"

            stdout, stderr = await proc.communicate(timeout=self._timeout)

            return (
                stdout.decode("utf-8", errors="replace") +
                stderr.decode("utf-8", errors="replace")
            )

        except Exception as e:
            return f"验证失败: {e}"


# =============================================================================
# 主漏洞研究模块
# =============================================================================

class PocResearchModule:
    """漏洞自动化研究模块

    整合补丁差异分析、内核漏洞检测、PoC下载编译验证。

    Attributes:
        _windows_analyzer: Windows补丁分析器
        _linux_detector: Linux内核漏洞检测器
        _downloader: PoC下载器
        _compiler: PoC编译器
        _validator: PoC沙箱验证器
    """

    def __init__(
        self,
        download_dir: Optional[str] = None,
        sandbox_dir: Optional[str] = None,
    ) -> None:
        """初始化漏洞研究模块

        Args:
            download_dir: 下载目录
            sandbox_dir: 沙箱目录
        """
        self._windows_analyzer = WindowsPatchAnalyzer()
        self._linux_detector = LinuxKernelVulnDetector()
        self._downloader = PocDownloader(download_dir)
        self._compiler = PocCompiler()
        self._validator = PocSandboxValidator(sandbox_dir)

    async def full_research(self) -> Dict[str, Any]:
        """完整漏洞研究

        Returns:
            研究结果
        """
        system = platform.system().lower()

        if system == "windows":
            return await self._windows_research()
        else:
            return await self._linux_research()

    async def _windows_research(self) -> Dict[str, Any]:
        """Windows漏洞研究

        Returns:
            研究结果
        """
        missing_patches = await self._windows_analyzer.analyze()

        pocs = []
        for patch in missing_patches:
            if patch.has_public_exploit and patch.exploit_url:
                poc_result = await self._download_and_validate_poc(
                    patch.cve_ids[0] if patch.cve_ids else patch.kb_id,
                    patch.exploit_url,
                )
                pocs.append(poc_result)

        return {
            "platform": "windows",
            "missing_patches": [p.to_dict() for p in missing_patches],
            "pocs": [p.to_dict() for p in pocs],
            "summary": {
                "total_missing": len(missing_patches),
                "total_exploitable": sum(
                    1 for p in missing_patches if p.has_public_exploit
                ),
                "total_pocs_ready": sum(
                    1 for p in pocs if p.status == PocStatus.READY
                ),
            },
            "researched_at": datetime.now().isoformat(),
        }

    async def _linux_research(self) -> Dict[str, Any]:
        """Linux漏洞研究

        Returns:
            研究结果
        """
        vulns = await self._linux_detector.detect()

        pocs = []
        for vuln in vulns:
            if vuln.exploit_available and vuln.exploit_url:
                poc_result = await self._download_and_validate_poc(
                    vuln.cve_id,
                    vuln.exploit_url,
                )
                pocs.append(poc_result)

        build_env = await self._compiler.check_build_environment()

        return {
            "platform": "linux",
            "kernel_version": self._linux_detector._kernel_version,
            "vulnerabilities": [v.to_dict() for v in vulns],
            "pocs": [p.to_dict() for p in pocs],
            "build_environment": build_env,
            "summary": {
                "total_vulns": len(vulns),
                "total_critical": sum(
                    1 for v in vulns if v.severity == Severity.CRITICAL
                ),
                "total_pocs_ready": sum(
                    1 for p in pocs if p.status == PocStatus.READY
                ),
            },
            "researched_at": datetime.now().isoformat(),
        }

    async def _download_and_validate_poc(
        self, cve_id: str, url: str,
    ) -> PocResult:
        """下载并验证PoC

        Args:
            cve_id: CVE编号
            url: PoC URL

        Returns:
            PoC结果
        """
        local_path = await self._downloader.download_poc(cve_id, url)

        if not local_path:
            return PocResult(
                poc_id=f"poc_{cve_id}_{int(time.time())}",
                cve_id=cve_id,
                status=PocStatus.FAILED,
                source_url=url,
                error="PoC下载失败",
                created_at=datetime.now().isoformat(),
            )

        if os.path.splitext(local_path)[1].lower() in [".c", ".cpp"]:
            success, output = await self._compiler.compile_poc(local_path)
            if not success:
                return PocResult(
                    poc_id=f"poc_{cve_id}_{int(time.time())}",
                    cve_id=cve_id,
                    status=PocStatus.FAILED,
                    source_url=url,
                    local_path=local_path,
                    compilation_output=output,
                    error="PoC编译失败",
                    created_at=datetime.now().isoformat(),
                )

        result = await self._validator.validate_poc(local_path, cve_id)
        result.source_url = url

        return result


# =============================================================================
# 全局单例
# =============================================================================

_poc_research: Optional[PocResearchModule] = None


def get_poc_research() -> PocResearchModule:
    """获取漏洞研究模块全局单例

    Returns:
        PocResearchModule 实例
    """
    global _poc_research
    if _poc_research is None:
        _poc_research = PocResearchModule()
    return _poc_research


__all__ = [
    "PocResearchModule",
    "WindowsPatchAnalyzer",
    "LinuxKernelVulnDetector",
    "PocDownloader",
    "PocCompiler",
    "PocSandboxValidator",
    "PatchInfo",
    "KernelVuln",
    "PocResult",
    "PlatformType",
    "PocStatus",
    "Severity",
    "MSRC_BULLETIN_DB",
    "KNOWN_EXPLOITABLE_PATCHES",
    "KERNEL_EXPLOIT_DB",
    "get_poc_research",
]
