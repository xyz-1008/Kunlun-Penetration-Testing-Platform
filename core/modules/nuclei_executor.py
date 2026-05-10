"""
Nuclei模板适配引擎 - 核心执行器
让昆仑直接加载并执行社区标准的Nuclei YAML模板

架构设计:
    NucleiExecutor (主控)
    ├── NucleiTemplateLoader (模板加载)
    │   ├── 本地目录扫描
    │   ├── ZIP压缩包加载
    │   └── 远程Git仓库拉取
    ├── NucleiHTTPExecutor (HTTP DSL执行器)
    │   ├── 变量解析与替换
    │   ├── Raw/Unsafe/Pipeline/Race模式
    │   ├── Attack类型执行 (batteringram/pitchfork/clusterbomb)
    │   ├── Cookie复用与会话管理
    │   └── 内存超限自动终止
    ├── NucleiMatcherEngine (匹配器引擎)
    │   ├── Word/Regex/Status/Size/DSL匹配
    │   └── AND/OR条件组合
    └── NucleiExtractorEngine (提取器引擎)
        ├── Regex/JSON/XPath/Kval提取
        └── 动态变量存储
"""

import asyncio
import hashlib
import json
import logging
import os
import random
import re
import socket
import sys
import tarfile
import time
import zipfile
import tempfile
import shutil
import itertools
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple, Set, Callable
from datetime import datetime
from urllib.parse import urlparse, urljoin

import aiohttp
import yaml

from .nuclei_models import (
    NucleiTemplate, NucleiVerifyResult, NucleiTemplateStats,
    NucleiSeverity, HTTPRequest, Matcher, Extractor,
    MatcherType, MatcherPart, MatcherCondition,
    ExtractorType, HTTPMethod, AttackType, SizeOperator,
    FingerprintRule,
)
from .nuclei_helpers import (
    NucleiVariableContext, NucleiHelpers, evaluate_dsl_expression,
)
from .result_models import PoCVerificationResult, ConfidenceLevel, SeverityLevel, PoCStatus

logger = logging.getLogger(__name__)

DANGEROUS_PATTERNS = [
    re.compile(r'\beval\s*\('),
    re.compile(r'\bexec\s*\('),
    re.compile(r'__import__\s*\('),
    re.compile(r'\bos\.system\b'),
    re.compile(r'\bsubprocess\b'),
    re.compile(r'\bopen\s*\('),
    re.compile(r'__builtins__'),
    re.compile(r'__subclasses__'),
]

DEFAULT_MAX_RESPONSE_SIZE = 4 * 1024 * 1024
DEFAULT_RACE_COUNT = 5
DEFAULT_RACE_DELAY = 0.0


class MemoryGuard:
    """内存守卫 - 监控响应体大小，超限自动终止"""

    def __init__(self, max_size: int = DEFAULT_MAX_RESPONSE_SIZE):
        self._max_size = max_size
        self._current_size = 0
        self._truncated = False

    @property
    def max_size(self) -> int:
        return self._max_size

    @property
    def current_size(self) -> int:
        return self._current_size

    @property
    def truncated(self) -> bool:
        return self._truncated

    def reset(self):
        self._current_size = 0
        self._truncated = False

    def check_and_accumulate(self, chunk: bytes) -> bytes:
        """检查并累积数据块，超限则截断"""
        self._current_size += len(chunk)
        if self._current_size > self._max_size:
            if not self._truncated:
                self._truncated = True
                logger.warning(f"响应体超过限制 {self._max_size} 字节，已截断")
            allowed = self._max_size - (self._current_size - len(chunk))
            if allowed <= 0:
                return b""
            return chunk[:allowed]
        return chunk

    def check_size(self, size: int) -> bool:
        """检查大小是否超限"""
        return size <= self._max_size


class TemplateCache:
    """模板缓存管理器

    提供模板索引缓存、文件变更检测、热更新和版本管理:
    - MD5哈希校验避免重复解析
    - 文件修改时间+哈希双重变更检测
    - 自动增量重载变更文件
    - 模板版本追踪（加载时间/来源/MD5/回滚）

    Attributes:
        _cache_dir: 缓存目录路径
        _index: 模板索引 {template_id: cache_entry}
        _file_hashes: 文件哈希映射 {file_path: md5_hash}
        _file_mtimes: 文件修改时间映射 {file_path: mtime}
        _version_history: 版本历史 {template_id: [version_entries]}
    """

    def __init__(self, cache_dir: Optional[str] = None):
        self._cache_dir = Path(cache_dir) if cache_dir else Path(tempfile.gettempdir()) / "kunlun_nuclei_cache"
        self._cache_dir.mkdir(parents=True, exist_ok=True)
        self._index: Dict[str, Dict[str, Any]] = {}
        self._file_hashes: Dict[str, str] = {}
        self._file_mtimes: Dict[str, float] = {}
        self._version_history: Dict[str, List[Dict[str, Any]]] = {}
        self._index_file = self._cache_dir / "template_index.json"
        self._load_index()

    @property
    def cache_dir(self) -> Path:
        return self._cache_dir

    @property
    def index(self) -> Dict[str, Dict[str, Any]]:
        return dict(self._index)

    def compute_file_hash(self, file_path: str) -> str:
        """计算文件MD5哈希

        Args:
            file_path: 文件路径

        Returns:
            MD5十六进制字符串
        """
        hasher = hashlib.md5()
        try:
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    hasher.update(chunk)
        except (IOError, OSError):
            return ""
        return hasher.hexdigest()

    def compute_content_hash(self, content: str) -> str:
        """计算内容MD5哈希

        Args:
            content: 文本内容

        Returns:
            MD5十六进制字符串
        """
        return hashlib.md5(content.encode("utf-8")).hexdigest()

    def has_changed(self, file_path: str) -> bool:
        """检测文件是否变更

        通过MD5哈希检测文件内容变更。
        如果文件是首次追踪，记录状态并返回False。

        Args:
            file_path: 文件路径

        Returns:
            是否已变更
        """
        try:
            current_mtime = os.path.getmtime(file_path)
        except OSError:
            return True

        current_hash = self.compute_file_hash(file_path)
        if not current_hash:
            return True

        if file_path not in self._file_hashes:
            self._file_hashes[file_path] = current_hash
            self._file_mtimes[file_path] = current_mtime
            return False

        changed = current_hash != self._file_hashes[file_path]
        if changed:
            self._file_hashes[file_path] = current_hash
            self._file_mtimes[file_path] = current_mtime

        return changed

    def register(self, template_id: str, file_path: str, source_type: str,
                 content_hash: str = ""):
        """注册模板到缓存索引

        Args:
            template_id: 模板ID
            file_path: 文件路径
            source_type: 来源类型
            content_hash: 内容哈希
        """
        entry = {
            "template_id": template_id,
            "file_path": file_path,
            "source_type": source_type,
            "content_hash": content_hash or self.compute_file_hash(file_path),
            "loaded_at": datetime.now().isoformat(),
            "file_mtime": os.path.getmtime(file_path) if os.path.exists(file_path) else 0,
        }

        if template_id in self._index:
            if template_id not in self._version_history:
                self._version_history[template_id] = []
            self._version_history[template_id].append(dict(self._index[template_id]))

        self._index[template_id] = entry
        if file_path:
            self._file_hashes[file_path] = entry["content_hash"]
            self._file_mtimes[file_path] = entry["file_mtime"]

    def unregister(self, template_id: str):
        """从缓存索引移除模板

        Args:
            template_id: 模板ID
        """
        if template_id in self._index:
            entry = self._index.pop(template_id)
            file_path = entry.get("file_path", "")
            self._file_hashes.pop(file_path, None)
            self._file_mtimes.pop(file_path, None)

    def get_entry(self, template_id: str) -> Optional[Dict[str, Any]]:
        """获取缓存条目

        Args:
            template_id: 模板ID

        Returns:
            缓存条目或None
        """
        return self._index.get(template_id)

    def get_version_history(self, template_id: str) -> List[Dict[str, Any]]:
        """获取模板版本历史

        Args:
            template_id: 模板ID

        Returns:
            版本历史列表
        """
        return self._version_history.get(template_id, [])

    def add_version(self, template_id: str, version: str,
                    source: str, source_type: str):
        """添加模板版本记录

        Args:
            template_id: 模板ID
            version: 版本号
            source: 来源路径
            source_type: 来源类型 (local/remote/archive)
        """
        if template_id not in self._version_history:
            self._version_history[template_id] = []

        entry = {
            "version": version,
            "source": source,
            "source_type": source_type,
            "loaded_at": datetime.now().isoformat(),
            "md5": self._file_hashes.get(source, ""),
        }
        self._version_history[template_id].append(entry)

    def get_changed_files(self, directory: str) -> List[str]:
        """扫描目录获取变更文件列表

        Args:
            directory: 模板目录

        Returns:
            变更文件路径列表
        """
        changed: List[str] = []
        dir_path = Path(directory)
        if not dir_path.exists():
            return changed

        for yaml_file in dir_path.rglob("*.yaml"):
            if self.has_changed(str(yaml_file)):
                changed.append(str(yaml_file))
        for yml_file in dir_path.rglob("*.yml"):
            if self.has_changed(str(yml_file)):
                changed.append(str(yml_file))

        return changed

    def get_stale_entries(self) -> List[str]:
        """获取文件已不存在的过期缓存条目

        Returns:
            过期模板ID列表
        """
        stale: List[str] = []
        for template_id, entry in self._index.items():
            file_path = entry.get("file_path", "")
            if file_path and not os.path.exists(file_path):
                stale.append(template_id)
        return stale

    def clear(self):
        """清空所有缓存"""
        self._index.clear()
        self._file_hashes.clear()
        self._file_mtimes.clear()
        self._version_history.clear()

    def save_index(self):
        """持久化缓存索引到磁盘"""
        import json
        try:
            index_data = {
                "index": self._index,
                "version_history": self._version_history,
                "updated_at": datetime.now().isoformat(),
            }
            with open(self._index_file, "w", encoding="utf-8") as f:
                json.dump(index_data, f, indent=2, ensure_ascii=False)
        except (IOError, OSError) as e:
            logger.debug(f"缓存索引保存失败: {e}")

    def _load_index(self):
        """从磁盘加载缓存索引"""
        import json
        if not self._index_file.exists():
            return
        try:
            with open(self._index_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            self._index = data.get("index", {})
            self._version_history = data.get("version_history", {})
            for entry in self._index.values():
                fp = entry.get("file_path", "")
                if fp:
                    self._file_hashes[fp] = entry.get("content_hash", "")
                    self._file_mtimes[fp] = entry.get("file_mtime", 0)
        except (json.JSONDecodeError, IOError) as e:
            logger.debug(f"缓存索引加载失败: {e}")


class NucleiTemplateLoader:
    """Nuclei YAML模板加载器

    支持从本地目录、ZIP/tar.gz压缩包、远程Git仓库加载模板。
    解析时进行语法校验，错误模板自动跳过并记录日志。
    集成缓存系统，支持增量更新和热重载。
    """

    def __init__(self, templates_dir: Optional[str] = None,
                 cache: Optional[TemplateCache] = None,
                 access_token: str = ""):
        self._templates_dir = Path(templates_dir) if templates_dir else None
        self._templates: Dict[str, NucleiTemplate] = {}
        self._failed_templates: List[Tuple[str, str]] = []
        self._stats = NucleiTemplateStats()
        self._cache = cache or TemplateCache()
        self._access_token = access_token
        self._duplicate_warnings: List[str] = []
        self._lock = asyncio.Lock()

    @property
    def templates(self) -> Dict[str, NucleiTemplate]:
        return self._templates

    @property
    def stats(self) -> NucleiTemplateStats:
        return self._stats

    @property
    def failed_templates(self) -> List[Tuple[str, str]]:
        return self._failed_templates

    @property
    def cache(self) -> TemplateCache:
        return self._cache

    @property
    def duplicate_warnings(self) -> List[str]:
        return list(self._duplicate_warnings)

    @property
    def access_token(self) -> str:
        return self._access_token

    @access_token.setter
    def access_token(self, value: str):
        self._access_token = value

    def load_from_directory(self, directory: str, recursive: bool = True) -> int:
        """从本地目录递归加载模板

        Args:
            directory: 模板目录路径
            recursive: 是否递归扫描子目录

        Returns:
            成功加载的模板数量
        """
        start_time = time.time()
        dir_path = Path(directory)
        if not dir_path.exists():
            logger.warning(f"模板目录不存在: {directory}")
            return 0

        pattern = "**/*.yaml" if recursive else "*.yaml"
        yaml_files = list(dir_path.glob(pattern)) + list(
            dir_path.glob("**/*.yml" if recursive else "*.yml")
        )

        loaded = 0
        for file_path in yaml_files:
            if self._load_single_template(file_path, "local"):
                loaded += 1

        self._stats.load_time = time.time() - start_time
        self._stats.loaded_templates = loaded
        self._stats.total_templates = len(self._templates)
        self._compute_stats()
        logger.info(f"从目录加载了 {loaded} 个模板, 失败 {len(self._failed_templates)} 个")
        return loaded

    def load_from_zip(self, zip_path: str) -> int:
        """从ZIP压缩包加载模板

        Args:
            zip_path: ZIP文件路径

        Returns:
            成功加载的模板数量
        """
        start_time = time.time()
        if not os.path.exists(zip_path):
            logger.error(f"ZIP文件不存在: {zip_path}")
            return 0

        loaded = 0
        with tempfile.TemporaryDirectory() as tmpdir:
            try:
                with zipfile.ZipFile(zip_path, 'r') as zf:
                    zf.extractall(tmpdir)
                loaded = self.load_from_directory(tmpdir, recursive=True)
            except zipfile.BadZipFile as e:
                logger.error(f"无效的ZIP文件: {e}")
            except Exception as e:
                logger.error(f"ZIP加载失败: {e}")

        self._stats.load_time = time.time() - start_time
        return loaded

    def load_from_targz(self, targz_path: str) -> int:
        """从tar.gz压缩包加载模板

        Args:
            targz_path: tar.gz文件路径

        Returns:
            成功加载的模板数量
        """
        start_time = time.time()
        if not os.path.exists(targz_path):
            logger.error(f"tar.gz文件不存在: {targz_path}")
            return 0

        loaded = 0
        with tempfile.TemporaryDirectory() as tmpdir:
            try:
                with tarfile.open(targz_path, "r:gz") as tf:
                    tf.extractall(tmpdir)
                loaded = self.load_from_directory(tmpdir, recursive=True)
            except tarfile.TarError as e:
                logger.error(f"无效的tar.gz文件: {e}")
            except Exception as e:
                logger.error(f"tar.gz加载失败: {e}")

        self._stats.load_time = time.time() - start_time
        return loaded

    def load_from_archive(self, archive_path: str) -> int:
        """从压缩包加载模板（自动识别ZIP/tar.gz格式）

        Args:
            archive_path: 压缩包文件路径

        Returns:
            成功加载的模板数量
        """
        if archive_path.endswith(".tar.gz") or archive_path.endswith(".tgz"):
            return self.load_from_targz(archive_path)
        elif archive_path.endswith(".zip"):
            return self.load_from_zip(archive_path)
        else:
            logger.error(f"不支持的压缩格式: {archive_path}")
            return 0

    async def load_from_remote(self, repo_url: str, branch: str = "main",
                                incremental: bool = False) -> int:
        """从远程Git仓库拉取模板

        支持:
        - 公开仓库直接克隆
        - 私人仓库通过Access Token认证
        - 增量拉取 (git pull 而非 git clone)

        Args:
            repo_url: Git仓库URL
            branch: 分支名
            incremental: 是否增量拉取

        Returns:
            成功加载的模板数量
        """
        start_time = time.time()
        loaded = 0

        if self._access_token:
            if repo_url.startswith("https://"):
                repo_url = repo_url.replace(
                    "https://",
                    f"https://oauth2:{self._access_token}@"
                )

        with tempfile.TemporaryDirectory() as tmpdir:
            try:
                repo_dir = os.path.join(tmpdir, "templates")

                if incremental and os.path.exists(repo_dir):
                    process = await asyncio.create_subprocess_exec(
                        "git", "-C", repo_dir, "pull", "origin", branch,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )
                else:
                    process = await asyncio.create_subprocess_exec(
                        "git", "clone", "--depth", "1", "--branch", branch,
                        repo_url, repo_dir,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )
                await process.wait()

                if process.returncode == 0:
                    loaded = self.load_from_directory(repo_dir, recursive=True)
                else:
                    stderr = await process.stderr.read() if process.stderr else b""
                    logger.error(f"Git操作失败: {repo_url} - {stderr.decode(errors='ignore')}")
            except FileNotFoundError:
                logger.error("Git未安装，无法从远程仓库加载模板")
            except Exception as e:
                logger.error(f"远程加载失败: {e}")

        self._stats.load_time = time.time() - start_time
        return loaded

    def _load_single_template(self, file_path: Path, source_type: str) -> bool:
        """加载单个模板文件

        Args:
            file_path: 模板文件路径
            source_type: 来源类型 (local/zip/targz/remote)

        Returns:
            是否加载成功
        """
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()

            if self._contains_dangerous_code(content):
                self._failed_templates.append((str(file_path), "包含危险代码"))
                logger.warning(f"模板包含危险代码，已跳过: {file_path}")
                return False

            content_hash = self._cache.compute_content_hash(content)

            if not self._cache.has_changed(str(file_path)):
                cached_entry = self._cache.get_entry(
                    self._extract_template_id_from_content(content)
                )
                if cached_entry:
                    logger.debug(f"模板未变更，跳过: {file_path}")
                    return False

            yaml_data = yaml.safe_load(content)

            if not yaml_data or not isinstance(yaml_data, dict):
                self._failed_templates.append((str(file_path), "无效的YAML格式"))
                return False

            if "id" not in yaml_data:
                self._failed_templates.append((str(file_path), "缺少id字段"))
                return False

            template_id = yaml_data["id"]

            if template_id in self._templates:
                existing = self._templates[template_id]
                warning = (
                    f"模板ID重复: [{template_id}] "
                    f"旧={existing.source_path}, 新={file_path}, "
                    f"已按最新版本覆盖"
                )
                self._duplicate_warnings.append(warning)
                logger.warning(warning)

            template = NucleiTemplate(**yaml_data)
            template.source_path = str(file_path)
            template.source_type = source_type

            self._templates[template.id] = template
            self._cache.register(template.id, str(file_path), source_type, content_hash)
            logger.debug(f"加载模板: {template.id} - {template.info.name}")
            return True

        except yaml.YAMLError as e:
            self._failed_templates.append((str(file_path), f"YAML解析错误: {e}"))
            logger.warning(f"YAML解析失败 {file_path}: {e}")
        except Exception as e:
            self._failed_templates.append((str(file_path), str(e)))
            logger.warning(f"模板加载失败 {file_path}: {e}")

        return False

    @staticmethod
    def _extract_template_id_from_content(content: str) -> str:
        """从YAML内容中快速提取模板ID（不完整解析）

        Args:
            content: YAML内容

        Returns:
            模板ID或空字符串
        """
        for line in content.split("\n"):
            line = line.strip()
            if line.startswith("id:") or line.startswith("id :"):
                return line.split(":", 1)[1].strip().strip('"').strip("'")
        return ""

    def _contains_dangerous_code(self, content: str) -> bool:
        """检测模板中是否包含危险代码"""
        for pattern in DANGEROUS_PATTERNS:
            if pattern.search(content):
                return True
        return False

    def _compute_stats(self):
        """计算统计信息"""
        severity_count: Dict[str, int] = {}
        tag_count: Dict[str, int] = {}
        protocol_count: Dict[str, int] = {"http": 0}

        for template in self._templates.values():
            sev = template.info.severity.value
            severity_count[sev] = severity_count.get(sev, 0) + 1

            if template.requests:
                protocol_count["http"] = protocol_count.get("http", 0) + 1
            if template.dns:
                protocol_count["dns"] = protocol_count.get("dns", 0) + 1
            if template.tcp:
                protocol_count["tcp"] = protocol_count.get("tcp", 0) + 1

            if template.info.tags:
                for tag in template.info.tags.split(","):
                    tag = tag.strip()
                    if tag:
                        tag_count[tag] = tag_count.get(tag, 0) + 1

        self._stats.by_severity = severity_count
        self._stats.by_tags = tag_count
        self._stats.by_protocol = protocol_count
        self._stats.failed_templates = len(self._failed_templates)

    def search(self, keyword: str) -> List[NucleiTemplate]:
        """按关键词搜索模板

        Args:
            keyword: 搜索关键词

        Returns:
            匹配的模板列表
        """
        results = []
        kw_lower = keyword.lower()
        for template in self._templates.values():
            if (kw_lower in template.id.lower() or
                kw_lower in template.info.name.lower() or
                kw_lower in template.info.tags.lower() or
                any(kw_lower in author.lower() for author in template.info.author)):
                results.append(template)
        return results

    def get_by_severity(self, severity: NucleiSeverity) -> List[NucleiTemplate]:
        """按严重级别筛选"""
        return [t for t in self._templates.values() if t.info.severity == severity]

    def get_by_tag(self, tag: str) -> List[NucleiTemplate]:
        """按标签筛选"""
        return [t for t in self._templates.values() if tag in t.info.tags]

    def get_template(self, template_id: str) -> Optional[NucleiTemplate]:
        """获取指定模板"""
        return self._templates.get(template_id)

    def get_templates_by_group(self, group_key: str = "tags") -> Dict[str, List[NucleiTemplate]]:
        """按分组键获取模板分组

        Args:
            group_key: 分组键 (tags/author/severity/directory)

        Returns:
            分组后的模板字典
        """
        groups: Dict[str, List[NucleiTemplate]] = {}
        for template in self._templates.values():
            if group_key == "tags":
                keys = [t.strip() for t in template.info.tags.split(",") if t.strip()]
            elif group_key == "author":
                keys = template.info.author if template.info.author else ["unknown"]
            elif group_key == "severity":
                keys = [template.info.severity.value]
            elif group_key == "directory":
                keys = [str(Path(template.source_path).parent.name) if template.source_path else "root"]
            else:
                keys = ["all"]

            for key in keys:
                if key not in groups:
                    groups[key] = []
                groups[key].append(template)

        return groups

    async def hot_reload(self, directory: Optional[str] = None) -> int:
        """热更新：检测文件变更并增量重载

        扫描模板目录，仅重新加载已变更的文件。
        同时清理文件已删除的过期模板。

        Args:
            directory: 模板目录（默认使用初始化时的目录）

        Returns:
            重载的模板数量
        """
        async with self._lock:
            target_dir = directory or (str(self._templates_dir) if self._templates_dir else "")
            if not target_dir:
                logger.warning("未指定模板目录，无法热更新")
                return 0

            changed_files = self._cache.get_changed_files(target_dir)
            stale_ids = self._cache.get_stale_entries()

            for stale_id in stale_ids:
                if stale_id in self._templates:
                    del self._templates[stale_id]
                    self._cache.unregister(stale_id)
                    logger.debug(f"清理过期模板: {stale_id}")

            reloaded = 0
            for file_path in changed_files:
                if self._load_single_template(Path(file_path), "local"):
                    reloaded += 1

            if reloaded > 0 or stale_ids:
                self._compute_stats()
                self._cache.save_index()
                logger.info(
                    f"热更新完成: 重载 {reloaded} 个模板, "
                    f"清理 {len(stale_ids)} 个过期模板"
                )

            return reloaded

    async def start_hot_reload_watcher(self, directory: Optional[str] = None,
                                        interval: int = 30):
        """启动热更新监视器（后台任务）

        Args:
            directory: 监视目录
            interval: 检查间隔秒数
        """
        target_dir = directory or (str(self._templates_dir) if self._templates_dir else "")
        if not target_dir:
            logger.warning("未指定模板目录，无法启动热更新监视器")
            return

        async def _watch_loop():
            while True:
                try:
                    await asyncio.sleep(interval)
                    await self.hot_reload(target_dir)
                except asyncio.CancelledError:
                    break
                except Exception as e:
                    logger.error(f"热更新监视异常: {e}")

        asyncio.create_task(_watch_loop())
        logger.info(f"热更新监视器已启动: {target_dir} (间隔 {interval}s)")


class NucleiMatcherEngine:
    """Nuclei匹配器引擎

    支持 AND/OR 逻辑组合，word/regex/status/size/dsl/binary 六种匹配类型，
    可指定匹配位置 (header/body/firstline/all)，支持 negative 反向匹配。
    支持多层嵌套 matchers（递归AND/OR组合）。
    """

    def match(self, matchers: List[Matcher], condition: MatcherCondition,
              response_body: str, response_headers: Dict[str, str],
              status_code: int, content_length: int) -> Tuple[bool, str, str]:
        """执行匹配

        Args:
            matchers: 匹配器列表
            condition: 全局匹配条件 (AND/OR)
            response_body: 响应体
            response_headers: 响应头
            status_code: HTTP状态码
            content_length: 响应体大小

        Returns:
            (是否匹配, 证据字符串, 匹配器名称)
        """
        if not matchers:
            return False, "", ""

        results: List[Tuple[bool, str]] = []
        for matcher in matchers:
            matched, evidence = self._match_single(
                matcher, response_body, response_headers, status_code, content_length
            )
            if matcher.negative:
                matched = not matched
            results.append((matched, evidence))

        if condition == MatcherCondition.AND:
            overall = all(r[0] for r in results)
        else:
            overall = any(r[0] for r in results)

        evidence = "; ".join(r[1] for r in results if r[1])
        matcher_name = matchers[0].name or "" if matchers else ""

        return overall, evidence, matcher_name

    def _match_single(self, matcher: Matcher, body: str, headers: Dict[str, str],
                      status_code: int, content_length: int) -> Tuple[bool, str]:
        """执行单个匹配器，支持嵌套matchers

        如果matcher包含嵌套matchers列表，则递归执行嵌套匹配。
        否则按matcher.type执行对应类型的匹配。
        """
        if matcher.matchers:
            return self._match_nested(matcher, body, headers, status_code, content_length)

        target_text = self._get_target_text(matcher.part, body, headers)

        if matcher.type == MatcherType.WORD:
            return self._match_word(matcher, target_text)
        elif matcher.type == MatcherType.REGEX:
            return self._match_regex(matcher, target_text)
        elif matcher.type == MatcherType.STATUS:
            return self._match_status(matcher, status_code)
        elif matcher.type == MatcherType.SIZE:
            return self._match_size(matcher, content_length)
        elif matcher.type == MatcherType.DSL:
            return self._match_dsl(matcher, body, headers, status_code, content_length)
        elif matcher.type == MatcherType.BINARY:
            return self._match_binary(matcher, body)

        return False, ""

    def _match_nested(self, matcher: Matcher, body: str, headers: Dict[str, str],
                      status_code: int, content_length: int) -> Tuple[bool, str]:
        """递归执行嵌套匹配器

        支持多层嵌套的AND/OR组合:
        - 每个嵌套matcher可以有自己的matchers-condition
        - 递归深度无限制（实际受Python递归栈限制）

        Args:
            matcher: 包含嵌套matchers的匹配器
            body: 响应体
            headers: 响应头
            status_code: 状态码
            content_length: 响应体大小

        Returns:
            (是否匹配, 证据)
        """
        nested_results: List[Tuple[bool, str]] = []
        for nested in matcher.matchers:
            nested_matched, nested_evidence = self._match_single(
                nested, body, headers, status_code, content_length
            )
            if nested.negative:
                nested_matched = not nested_matched
            nested_results.append((nested_matched, nested_evidence))

        condition = matcher.matchers_condition
        if condition == MatcherCondition.AND:
            overall = all(r[0] for r in nested_results)
        else:
            overall = any(r[0] for r in nested_results)

        evidence = "; ".join(r[1] for r in nested_results if r[1])
        return overall, evidence

    def _get_target_text(self, part: MatcherPart, body: str, headers: Dict[str, str]) -> str:
        """获取匹配目标文本"""
        if part == MatcherPart.BODY:
            return body
        elif part == MatcherPart.HEADER:
            return "\n".join(f"{k}: {v}" for k, v in headers.items())
        elif part == MatcherPart.FIRSTLINE:
            return body.split("\n")[0] if body else ""
        elif part == MatcherPart.ALL:
            header_text = "\n".join(f"{k}: {v}" for k, v in headers.items())
            return f"{header_text}\n\n{body}"
        return body

    def _match_word(self, matcher: Matcher, text: str) -> Tuple[bool, str]:
        """关键词匹配"""
        search_text = text.lower() if matcher.case_insensitive else text

        matched_words = []
        for word in matcher.words:
            search_word = word.lower() if matcher.case_insensitive else word
            if matcher.encoding == "hex":
                try:
                    search_word = bytes.fromhex(word).decode("utf-8", errors="ignore")
                except ValueError:
                    continue

            if search_word in search_text:
                matched_words.append(word)

        if matcher.match_all:
            matched = len(matched_words) == len(matcher.words)
        else:
            matched = len(matched_words) > 0

        evidence = ", ".join(matched_words) if matched_words else ""
        return matched, evidence

    def _match_regex(self, matcher: Matcher, text: str) -> Tuple[bool, str]:
        """正则匹配"""
        flags = re.IGNORECASE if matcher.case_insensitive else 0
        matched_patterns = []
        for pattern in matcher.regex:
            try:
                if re.search(pattern, text, flags):
                    matched_patterns.append(pattern)
            except re.error:
                continue

        if matcher.match_all:
            matched = len(matched_patterns) == len(matcher.regex)
        else:
            matched = len(matched_patterns) > 0

        evidence = ", ".join(matched_patterns) if matched_patterns else ""
        return matched, evidence

    def _match_status(self, matcher: Matcher, status_code: int) -> Tuple[bool, str]:
        """状态码匹配"""
        if status_code in matcher.status:
            return True, str(status_code)
        return False, ""

    def _match_size(self, matcher: Matcher, content_length: int) -> Tuple[bool, str]:
        """响应大小匹配 - 支持 >, <, ==, >=, <= 运算符"""
        if matcher.size is None:
            return False, ""
        op = matcher.size_operator
        size = matcher.size
        if op == SizeOperator.GT and content_length > size:
            return True, f"size>{size}"
        elif op == SizeOperator.LT and content_length < size:
            return True, f"size<{size}"
        elif op == SizeOperator.EQ and content_length == size:
            return True, f"size=={size}"
        elif op == SizeOperator.GTE and content_length >= size:
            return True, f"size>={size}"
        elif op == SizeOperator.LTE and content_length <= size:
            return True, f"size<={size}"
        return False, ""

    def _match_dsl(self, matcher: Matcher, body: str, headers: Dict[str, str],
                   status_code: int, content_length: int) -> Tuple[bool, str]:
        """DSL表达式匹配"""
        for expr in matcher.dsl:
            if evaluate_dsl_expression(expr, body, headers, status_code, content_length):
                return True, expr
        return False, ""

    def _match_binary(self, matcher: Matcher, body: str) -> Tuple[bool, str]:
        """二进制匹配"""
        for hex_pattern in matcher.binary:
            try:
                binary_pattern = bytes.fromhex(hex_pattern)
                if binary_pattern in body.encode("utf-8", errors="ignore"):
                    return True, hex_pattern
            except ValueError:
                continue
        return False, ""


class NucleiExtractorEngine:
    """Nuclei提取器引擎

    支持 regex/json/xpath/kval/dsl 五种提取类型，
    提取结果存储为内部变量供后续请求引用。
    """

    def extract(self, extractors: List[Extractor], response_body: str,
                response_headers: Dict[str, str]) -> Dict[str, Any]:
        """执行提取

        Args:
            extractors: 提取器列表
            response_body: 响应体
            response_headers: 响应头

        Returns:
            提取结果字典 {name: value}
        """
        extracted: Dict[str, Any] = {}
        for extractor in extractors:
            values = self._extract_single(extractor, response_body, response_headers)
            if values:
                name = extractor.name or f"extracted_{len(extracted)}"
                if isinstance(values, list) and len(values) == 1:
                    extracted[name] = values[0]
                else:
                    extracted[name] = values
        return extracted

    def _extract_single(self, extractor: Extractor, body: str,
                        headers: Dict[str, str]) -> Any:
        """执行单个提取器"""
        target_text = self._get_target_text(extractor.part, body, headers)

        if extractor.type == ExtractorType.REGEX:
            return self._extract_regex(extractor, target_text)
        elif extractor.type == ExtractorType.JSON:
            return self._extract_json(extractor, target_text)
        elif extractor.type == ExtractorType.XPATH:
            return self._extract_xpath(extractor, target_text)
        elif extractor.type == ExtractorType.KVAL:
            return self._extract_kval(extractor, headers)
        elif extractor.type == ExtractorType.DSL:
            return self._extract_dsl(extractor, body, headers)

        return None

    def _get_target_text(self, part: MatcherPart, body: str, headers: Dict[str, str]) -> str:
        if part == MatcherPart.BODY:
            return body
        elif part == MatcherPart.HEADER:
            return "\n".join(f"{k}: {v}" for k, v in headers.items())
        elif part == MatcherPart.ALL:
            return "\n".join(f"{k}: {v}" for k, v in headers.items()) + "\n\n" + body
        return body

    def _extract_regex(self, extractor: Extractor, text: str) -> List[str]:
        """正则提取"""
        flags = re.IGNORECASE if extractor.case_insensitive else 0
        results = []
        for pattern in extractor.regex:
            try:
                matches = re.findall(pattern, text, flags)
                for m in matches:
                    if isinstance(m, tuple) and len(m) > extractor.group - 1:
                        results.append(m[extractor.group - 1])
                    elif isinstance(m, str):
                        results.append(m)
            except re.error:
                continue
        return results

    def _extract_json(self, extractor: Extractor, text: str) -> List[Any]:
        """JSON提取 - 使用简易JSONPath"""
        import json
        results = []
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return results

        for path in extractor.json_path:
            value = self._jsonpath_get(data, path)
            if value is not None:
                results.append(value)
        return results

    def _jsonpath_get(self, data: Any, path: str) -> Any:
        """简易JSONPath实现"""
        parts = path.strip("$.").split(".")
        current = data
        for part in parts:
            if isinstance(current, dict):
                current = current.get(part)
            elif isinstance(current, list):
                try:
                    idx = int(part)
                    current = current[idx] if 0 <= idx < len(current) else None
                except ValueError:
                    results = []
                    for item in current:
                        if isinstance(item, dict):
                            v = item.get(part)
                            if v is not None:
                                results.append(v)
                    current = results if results else None
            else:
                return None
            if current is None:
                return None
        return current

    def _extract_xpath(self, extractor: Extractor, text: str) -> List[str]:
        """XPath提取"""
        try:
            from lxml import etree
        except ImportError:
            logger.debug("lxml未安装，XPath提取不可用")
            return []

        results = []
        try:
            tree = etree.HTML(text)
            for path in extractor.xpath:
                nodes = tree.xpath(path)
                for node in nodes:
                    if extractor.attribute:
                        val = node.get(extractor.attribute)
                        if val:
                            results.append(val)
                    else:
                        text_content = node.text or ""
                        results.append(text_content.strip())
        except Exception as e:
            logger.debug(f"XPath提取失败: {e}")

        return results

    def _extract_kval(self, extractor: Extractor, headers: Dict[str, str]) -> List[str]:
        """Key-Value提取"""
        results = []
        for key in extractor.kval:
            for header_name, header_value in headers.items():
                if header_name.lower() == key.lower():
                    results.append(header_value)
        return results

    def _extract_dsl(self, extractor: Extractor, body: str, headers: Dict[str, str]) -> List[str]:
        """DSL提取"""
        results = []
        for expr in extractor.dsl:
            try:
                safe_locals = {"body": body, "len": len}
                for k, v in headers.items():
                    safe_locals[f"header_{k.replace('-', '_').lower()}"] = v
                result = eval(expr, {"__builtins__": {}}, safe_locals)
                results.append(str(result))
            except Exception:
                continue
        return results


class NucleiHTTPExecutor:
    """Nuclei HTTP协议执行器

    纯Python实现，支持标准/Raw/Unsafe/Pipeline/Race五种模式，
    以及 batteringram/pitchfork/clusterbomb 三种Attack类型。
    内置内存守卫，响应体超限自动截断。
    """

    def __init__(self, timeout: float = 10.0, max_redirects: int = 3,
                 max_response_size: int = DEFAULT_MAX_RESPONSE_SIZE,
                 enable_http2: bool = False):
        self._timeout = timeout
        self._max_redirects = max_redirects
        self._session: Optional[aiohttp.ClientSession] = None
        self._cookie_jar: Dict[str, str] = {}
        self._pipeline_connections: Dict[str, aiohttp.ClientSession] = {}
        self._memory_guard = MemoryGuard(max_response_size)
        self._session_lock = asyncio.Lock()
        self._enable_http2 = enable_http2
        self._h2_sessions: Dict[str, Any] = {}
        self._h2_lock = asyncio.Lock()

    @property
    def memory_guard(self) -> MemoryGuard:
        return self._memory_guard

    async def _get_session(self) -> aiohttp.ClientSession:
        async with self._session_lock:
            if self._session is None or self._session.closed:
                connector = aiohttp.TCPConnector(
                    limit=100,
                    limit_per_host=30,
                    ttl_dns_cache=300,
                    ssl=False,
                )
                timeout = aiohttp.ClientTimeout(total=self._timeout)
                self._session = aiohttp.ClientSession(
                    connector=connector,
                    timeout=timeout,
                    cookie_jar=aiohttp.CookieJar(unsafe=True),
                )
            return self._session

    async def _get_h2_session(self, host: str, port: int) -> Any:
        """获取或创建HTTP/2会话

        使用aiohttp的HTTP/2支持进行h2协商和多路复用流管理。

        Args:
            host: 目标主机
            port: 目标端口

        Returns:
            HTTP/2客户端会话
        """
        async with self._h2_lock:
            conn_key = f"{host}:{port}"
            if conn_key in self._h2_sessions:
                session = self._h2_sessions[conn_key]
                if not session.closed:
                    return session

            connector = aiohttp.TCPConnector(
                limit=10,
                limit_per_host=10,
                ttl_dns_cache=300,
                ssl=False,
                force_close=False,
                enable_cleanup_closed=True,
            )
            timeout = aiohttp.ClientTimeout(total=self._timeout)
            session = aiohttp.ClientSession(
                connector=connector,
                timeout=timeout,
            )
            self._h2_sessions[conn_key] = session
            return session

    async def _execute_http2(self, request: HTTPRequest, base_url: str,
                              var_ctx: NucleiVariableContext) -> Tuple[int, str, Dict[str, str], str, str]:
        """HTTP/2请求执行

        利用HTTP/2多路复用特性，在同一连接上并发发送多个请求。

        Args:
            request: HTTP请求定义
            base_url: 基础URL
            var_ctx: 变量上下文

        Returns:
            (状态码, 响应体, 响应头, 请求Hex, 响应Hex)
        """
        method = request.method.value
        path = request.path[0] if request.path else "/"
        path = var_ctx.resolve(path)
        full_url = self._build_url(base_url, path)

        headers = {}
        for k, v in request.headers.items():
            headers[var_ctx.resolve(k)] = var_ctx.resolve(v)

        if request.cookie_reuse and var_ctx.get_cookies():
            cookie_str = "; ".join(f"{k}={v}" for k, v in var_ctx.get_cookies().items())
            headers["Cookie"] = cookie_str

        body = var_ctx.resolve(request.body) if request.body else None

        parsed = urlparse(full_url)
        host = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "https" else 80)

        session = await self._get_h2_session(host, port)

        try:
            async with session.request(
                method=method,
                url=full_url,
                headers=headers,
                data=body,
                allow_redirects=request.redirects,
                max_redirects=request.max_redirects,
                ssl=False,
            ) as response:
                response_body = await response.text()
                response_headers = dict(response.headers)

                if request.cookie_reuse:
                    for cookie_name, cookie in response.cookies.items():
                        var_ctx.set_cookie(cookie_name, cookie.value)

                request_hex = self._build_request_hex(method, full_url, headers, body)
                response_hex = self._build_response_hex(response.status, response_headers, response_body)

                return response.status, response_body, response_headers, request_hex, response_hex

        except asyncio.TimeoutError:
            logger.debug(f"HTTP/2请求超时: {full_url}")
            return 0, "", {}, "", ""
        except aiohttp.ClientError as e:
            logger.debug(f"HTTP/2请求失败 {full_url}: {e}")
            return 0, "", {}, "", ""
        except Exception as e:
            logger.debug(f"HTTP/2请求异常 {full_url}: {e}")
            return 0, "", {}, "", ""

    async def execute_request(self, request: HTTPRequest, target_url: str,
                              var_ctx: NucleiVariableContext,
                              extracted_values: Dict[str, Any] = None) -> Tuple[int, str, Dict[str, str], str, str]:
        """执行单个HTTP请求

        根据请求配置自动选择执行模式：Race > Attack > Raw > Unsafe > Pipeline > Standard

        Args:
            request: HTTP请求定义
            target_url: 目标URL
            var_ctx: 变量上下文
            extracted_values: 之前提取的值

        Returns:
            (状态码, 响应体, 响应头, 请求Hex, 响应Hex)
        """
        if extracted_values:
            for k, v in extracted_values.items():
                var_ctx.set_extracted(k, v)

        self._memory_guard.reset()

        if request.race_count > 1:
            return await self._execute_race(request, target_url, var_ctx)

        if request.attack is not None and request.payloads:
            return await self._execute_attack(request, target_url, var_ctx)

        if request.raw:
            return await self._execute_raw(request, target_url, var_ctx)
        if request.unsafe:
            return await self._execute_unsafe(request, target_url, var_ctx)
        if request.pipeline:
            return await self._execute_pipeline(request, target_url, var_ctx)

        return await self._execute_standard(request, target_url, var_ctx)

    async def _execute_standard(self, request: HTTPRequest, base_url: str,
                                 var_ctx: NucleiVariableContext) -> Tuple[int, str, Dict[str, str], str, str]:
        """标准HTTP请求执行"""
        method = request.method.value
        path = request.path[0] if request.path else "/"
        path = var_ctx.resolve(path)
        full_url = self._build_url(base_url, path)

        headers = {}
        for k, v in request.headers.items():
            headers[var_ctx.resolve(k)] = var_ctx.resolve(v)

        if request.cookie_reuse and var_ctx.get_cookies():
            cookie_str = "; ".join(f"{k}={v}" for k, v in var_ctx.get_cookies().items())
            headers["Cookie"] = cookie_str

        body = var_ctx.resolve(request.body) if request.body else None

        session = await self._get_session()

        try:
            async with session.request(
                method=method,
                url=full_url,
                headers=headers,
                data=body,
                allow_redirects=request.redirects,
                max_redirects=request.max_redirects,
                ssl=False,
            ) as response:
                response_body = await response.text()
                response_headers = dict(response.headers)

                if request.cookie_reuse:
                    for cookie_name, cookie in response.cookies.items():
                        var_ctx.set_cookie(cookie_name, cookie.value)

                request_hex = self._build_request_hex(method, full_url, headers, body)
                response_hex = self._build_response_hex(response.status, response_headers, response_body)

                return response.status, response_body, response_headers, request_hex, response_hex

        except asyncio.TimeoutError:
            logger.debug(f"请求超时: {full_url}")
            return 0, "", {}, "", ""
        except aiohttp.ClientError as e:
            logger.debug(f"请求失败 {full_url}: {e}")
            return 0, "", {}, "", ""
        except Exception as e:
            logger.debug(f"请求异常 {full_url}: {e}")
            return 0, "", {}, "", ""

    async def _execute_raw(self, request: HTTPRequest, base_url: str,
                            var_ctx: NucleiVariableContext) -> Tuple[int, str, Dict[str, str], str, str]:
        """Raw模式 - 直接传入完整HTTP请求报文（兼容Burp/Yakit格式）"""
        session = await self._get_session()

        for raw_block in request.raw:
            raw_block = var_ctx.resolve(raw_block)
            lines = raw_block.strip().split("\n")
            if not lines:
                continue

            request_line = lines[0].strip()
            parts = request_line.split(" ")
            if len(parts) < 2:
                continue

            method = parts[0]
            path = parts[1]
            full_url = self._build_url(base_url, path)

            headers = {}
            body_start = 0
            for i, line in enumerate(lines[1:], 1):
                line = line.strip()
                if not line:
                    body_start = i + 1
                    break
                if ":" in line:
                    key, value = line.split(":", 1)
                    headers[key.strip()] = value.strip()

            body = "\n".join(lines[body_start:]) if body_start < len(lines) else ""

            try:
                async with session.request(
                    method=method,
                    url=full_url,
                    headers=headers,
                    data=body or None,
                    allow_redirects=request.redirects,
                    max_redirects=request.max_redirects,
                    ssl=False,
                ) as response:
                    response_body = await response.text()
                    response_headers = dict(response.headers)
                    request_hex = self._build_request_hex(method, full_url, headers, body)
                    response_hex = self._build_response_hex(response.status, response_headers, response_body)
                    return response.status, response_body, response_headers, request_hex, response_hex
            except Exception as e:
                logger.debug(f"Raw请求失败: {e}")
                continue

        return 0, "", {}, "", ""

    async def _execute_unsafe(self, request: HTTPRequest, base_url: str,
                               var_ctx: NucleiVariableContext) -> Tuple[int, str, Dict[str, str], str, str]:
        """Unsafe模式 - 不转义特殊字符，直接发送原始字节"""
        import socket
        import ssl as ssl_module

        parsed = urlparse(base_url)
        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "https" else 80)

        path = request.path[0] if request.path else "/"
        path = var_ctx.resolve(path)

        raw_request = f"{request.method.value} {path} HTTP/1.1\r\n"
        raw_request += f"Host: {host}\r\n"
        for k, v in request.headers.items():
            raw_request += f"{var_ctx.resolve(k)}: {var_ctx.resolve(v)}\r\n"
        if request.body:
            raw_body = var_ctx.resolve(request.body)
            raw_request += f"Content-Length: {len(raw_body.encode())}\r\n"
            raw_request += "\r\n"
            raw_request += raw_body
        else:
            raw_request += "\r\n"

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self._timeout)

            if parsed.scheme == "https":
                ctx = ssl_module.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl_module.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=host)

            sock.connect((host, port))
            sock.sendall(raw_request.encode("utf-8", errors="ignore"))

            response_data = b""
            while True:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    chunk = self._memory_guard.check_and_accumulate(chunk)
                    response_data += chunk
                    if b"\r\n\r\n" in response_data:
                        header_end = response_data.index(b"\r\n\r\n")
                        headers_text = response_data[:header_end].decode("utf-8", errors="ignore")
                        content_length = 0
                        for line in headers_text.split("\r\n"):
                            if line.lower().startswith("content-length:"):
                                try:
                                    content_length = int(line.split(":")[1].strip())
                                except ValueError:
                                    pass
                                break
                        body_received = len(response_data) - header_end - 4
                        if content_length > 0 and body_received >= content_length:
                            break
                except socket.timeout:
                    break

            sock.close()

            response_text = response_data.decode("utf-8", errors="ignore")
            parts = response_text.split("\r\n\r\n", 1)
            header_text = parts[0] if parts else ""
            body = parts[1] if len(parts) > 1 else ""

            header_lines = header_text.split("\r\n")
            status_line = header_lines[0] if header_lines else "HTTP/1.1 0"
            status_parts = status_line.split(" ")
            status_code = int(status_parts[1]) if len(status_parts) > 1 else 0

            response_headers = {}
            for line in header_lines[1:]:
                if ":" in line:
                    k, v = line.split(":", 1)
                    response_headers[k.strip()] = v.strip()

            return status_code, body, response_headers, raw_request, response_text

        except Exception as e:
            logger.debug(f"Unsafe请求失败: {e}")
            return 0, "", {}, "", ""

    async def _execute_pipeline(self, request: HTTPRequest, base_url: str,
                                 var_ctx: NucleiVariableContext) -> Tuple[int, str, Dict[str, str], str, str]:
        """Pipeline模式 - 同一连接复用发送多个请求，减少TLS握手开销"""
        method = request.method.value
        path = request.path[0] if request.path else "/"
        path = var_ctx.resolve(path)
        full_url = self._build_url(base_url, path)

        headers = {}
        for k, v in request.headers.items():
            headers[var_ctx.resolve(k)] = var_ctx.resolve(v)

        body = var_ctx.resolve(request.body) if request.body else None

        parsed = urlparse(full_url)
        conn_key = f"{parsed.scheme}://{parsed.netloc}"

        if conn_key not in self._pipeline_connections:
            connector = aiohttp.TCPConnector(
                limit=request.pipeline_concurrent_connections,
                limit_per_host=request.pipeline_concurrent_connections,
                force_close=False,
                enable_cleanup_closed=True,
                ssl=False,
            )
            timeout = aiohttp.ClientTimeout(total=self._timeout)
            self._pipeline_connections[conn_key] = aiohttp.ClientSession(
                connector=connector,
                timeout=timeout,
            )

        session = self._pipeline_connections[conn_key]

        try:
            async with session.request(
                method=method,
                url=full_url,
                headers=headers,
                data=body,
                allow_redirects=request.redirects,
                max_redirects=request.max_redirects,
                ssl=False,
            ) as response:
                response_body = await response.text()
                response_headers = dict(response.headers)
                request_hex = self._build_request_hex(method, full_url, headers, body)
                response_hex = self._build_response_hex(response.status, response_headers, response_body)
                return response.status, response_body, response_headers, request_hex, response_hex
        except Exception as e:
            logger.debug(f"Pipeline请求失败: {e}")
            return 0, "", {}, "", ""

    async def _execute_race(self, request: HTTPRequest, base_url: str,
                             var_ctx: NucleiVariableContext) -> Tuple[int, str, Dict[str, str], str, str]:
        """竞态模式 - 同时发送多个并发请求，用于竞态条件漏洞检测

        所有请求同时发出（asyncio.gather），利用HTTP/1.1 Pipelining
        或HTTP/2多路复用的特性制造竞态窗口。
        """
        race_count = max(request.race_count, 2)
        logger.debug(f"竞态模式: {race_count} 个并发请求 -> {base_url}")

        async def _single_race() -> Tuple[int, str, Dict[str, str], str, str]:
            return await self._execute_standard(request, base_url, var_ctx)

        tasks = [_single_race() for _ in range(race_count)]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        valid_results = []
        for r in results:
            if isinstance(r, Exception):
                logger.debug(f"竞态请求异常: {r}")
            elif isinstance(r, tuple) and r[0] > 0:
                valid_results.append(r)

        if valid_results:
            status_codes = set(r[0] for r in valid_results)
            if len(status_codes) > 1:
                logger.info(f"竞态检测: 收到不同状态码 {status_codes}")

            return valid_results[0]

        return 0, "", {}, "", ""

    async def _execute_attack(self, request: HTTPRequest, base_url: str,
                               var_ctx: NucleiVariableContext) -> Tuple[int, str, Dict[str, str], str, str]:
        """Attack模式 - 集群炸弹类型参数爆破

        支持三种攻击类型:
        - batteringram: 所有Payload位置使用同一个Payload值
        - pitchfork: 每个Payload位置使用各自Payload列表的对应位置值
        - clusterbomb: 所有Payload位置进行笛卡尔积组合
        """
        attack_type = request.attack
        payloads = request.payloads

        if not payloads:
            return await self._execute_standard(request, base_url, var_ctx)

        payload_names = list(payloads.keys())
        payload_values = {
            name: (p.get("values", []) if isinstance(p, dict) else p)
            for name, p in payloads.items()
        }

        for name in payload_names:
            if isinstance(payload_values[name], dict):
                payload_values[name] = payload_values[name].get("values", [])
            if not isinstance(payload_values[name], list):
                payload_values[name] = [str(payload_values[name])]

        combinations: List[Dict[str, str]] = []

        if attack_type == AttackType.BATTERINGRAM:
            all_values = []
            for vals in payload_values.values():
                all_values.extend(vals)
            for val in all_values:
                combo = {name: val for name in payload_names}
                combinations.append(combo)

        elif attack_type == AttackType.PITCHFORK:
            max_len = max(len(v) for v in payload_values.values())
            for i in range(max_len):
                combo = {}
                for name in payload_names:
                    vals = payload_values[name]
                    combo[name] = vals[i] if i < len(vals) else vals[-1] if vals else ""
                combinations.append(combo)

        elif attack_type == AttackType.CLUSTERBOMB:
            names_ordered = payload_names
            values_ordered = [payload_values[n] for n in names_ordered]
            for combo_vals in itertools.product(*values_ordered):
                combo = dict(zip(names_ordered, combo_vals))
                combinations.append(combo)

        if not combinations:
            return await self._execute_standard(request, base_url, var_ctx)

        logger.debug(f"Attack模式 [{attack_type.value}]: {len(combinations)} 个组合")

        last_result = (0, "", {}, "", "")
        for combo in combinations:
            for name, value in combo.items():
                var_ctx.set_variable(name, value)

            result = await self._execute_standard(request, base_url, var_ctx)
            if result[0] > 0:
                last_result = result

        return last_result

    def _build_url(self, base_url: str, path: str) -> str:
        """构建完整URL"""
        if path.startswith("http://") or path.startswith("https://"):
            return path
        if path.startswith("{{BaseURL}}"):
            path = path.replace("{{BaseURL}}", base_url.rstrip("/"))
        if not path.startswith("/"):
            path = "/" + path
        return base_url.rstrip("/") + path

    def _build_request_hex(self, method: str, url: str, headers: Dict[str, str], body: Optional[str]) -> str:
        """构建请求十六进制"""
        raw = f"{method} {url} HTTP/1.1\r\n"
        for k, v in headers.items():
            raw += f"{k}: {v}\r\n"
        raw += "\r\n"
        if body:
            raw += body
        return raw.encode("utf-8", errors="ignore").hex()

    def _build_response_hex(self, status: int, headers: Dict[str, str], body: str) -> str:
        """构建响应十六进制"""
        raw = f"HTTP/1.1 {status}\r\n"
        for k, v in headers.items():
            raw += f"{k}: {v}\r\n"
        raw += "\r\n"
        raw += body
        return raw.encode("utf-8", errors="ignore").hex()

    async def close(self):
        """关闭所有连接"""
        async with self._session_lock:
            if self._session and not self._session.closed:
                await self._session.close()
                self._session = None
        for conn in self._pipeline_connections.values():
            if not conn.closed:
                await conn.close()
        self._pipeline_connections.clear()
        async with self._h2_lock:
            for conn in self._h2_sessions.values():
                if not conn.closed:
                    await conn.close()
            self._h2_sessions.clear()


class NucleiDNSExecutor:
    """Nuclei DNS协议执行器

    支持DNS查询类型:
    - A/AAAA: IPv4/IPv6地址解析
    - CNAME: 别名记录
    - MX: 邮件交换记录
    - TXT: 文本记录
    - NS: 域名服务器记录
    - SOA: 授权起始记录
    - PTR: 反向解析
    - ANY: 所有记录

    支持自定义DNS服务器和DNS over HTTPS备用。
    """

    RECORD_TYPES = ["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA", "PTR", "ANY"]

    def __init__(self, timeout: float = 10.0, nameservers: Optional[List[str]] = None):
        self._timeout = timeout
        self._nameservers = nameservers or []
        self._doh_endpoints = [
            "https://dns.google/resolve",
            "https://cloudflare-dns.com/dns-query",
        ]

    async def execute_query(self, dns_request: Dict[str, Any], target_host: str,
                            var_ctx: 'NucleiVariableContext') -> Tuple[bool, str, Dict[str, Any]]:
        """执行DNS查询

        Args:
            dns_request: DNS请求定义 (name, type, class等)
            target_host: 目标主机名
            var_ctx: 变量上下文

        Returns:
            (是否匹配, 证据, 响应数据)
        """
        query_name = dns_request.get("name", target_host)
        query_name = var_ctx.resolve(query_name)

        query_type = dns_request.get("type", "A").upper()
        if query_type not in self.RECORD_TYPES:
            query_type = "A"

        query_class = dns_request.get("class", "INET")

        results = await self._resolve(query_name, query_type)

        if not results:
            return False, "", {"query": query_name, "type": query_type, "records": []}

        evidence = f"DNS {query_type} {query_name}: {', '.join(results[:5])}"
        response_data = {
            "query": query_name,
            "type": query_type,
            "class": query_class,
            "records": results,
            "count": len(results),
        }

        return True, evidence, response_data

    async def _resolve(self, hostname: str, record_type: str) -> List[str]:
        """DNS解析

        优先使用系统DNS，失败时回退到DoH。

        Args:
            hostname: 主机名
            record_type: 记录类型

        Returns:
            解析结果列表
        """
        results: List[str] = []

        try:
            if record_type == "A":
                results = await self._resolve_a(hostname)
            elif record_type == "AAAA":
                results = await self._resolve_aaaa(hostname)
            elif record_type == "CNAME":
                results = await self._resolve_cname(hostname)
            elif record_type == "MX":
                results = await self._resolve_mx(hostname)
            elif record_type == "TXT":
                results = await self._resolve_txt(hostname)
            elif record_type == "NS":
                results = await self._resolve_ns(hostname)
            elif record_type == "SOA":
                results = await self._resolve_soa(hostname)
            elif record_type == "PTR":
                results = await self._resolve_ptr(hostname)
            elif record_type == "ANY":
                results = await self._resolve_any(hostname)
        except Exception as e:
            logger.debug(f"DNS解析失败 ({record_type} {hostname}): {e}")

        if not results:
            results = await self._resolve_via_doh(hostname, record_type)

        return results

    async def _resolve_a(self, hostname: str) -> List[str]:
        """A记录解析"""
        loop = asyncio.get_event_loop()
        try:
            addrs = await asyncio.wait_for(
                loop.getaddrinfo(hostname, None, family=socket.AF_INET),
                timeout=self._timeout,
            )
            return list(set(addr[4][0] for addr in addrs))
        except (asyncio.TimeoutError, socket.gaierror):
            return []

    async def _resolve_aaaa(self, hostname: str) -> List[str]:
        """AAAA记录解析"""
        loop = asyncio.get_event_loop()
        try:
            addrs = await asyncio.wait_for(
                loop.getaddrinfo(hostname, None, family=socket.AF_INET6),
                timeout=self._timeout,
            )
            return list(set(addr[4][0] for addr in addrs))
        except (asyncio.TimeoutError, socket.gaierror):
            return []

    async def _resolve_cname(self, hostname: str) -> List[str]:
        """CNAME记录解析 - 通过DoH"""
        return await self._resolve_via_doh(hostname, "CNAME")

    async def _resolve_mx(self, hostname: str) -> List[str]:
        """MX记录解析 - 通过DoH"""
        return await self._resolve_via_doh(hostname, "MX")

    async def _resolve_txt(self, hostname: str) -> List[str]:
        """TXT记录解析 - 通过DoH"""
        return await self._resolve_via_doh(hostname, "TXT")

    async def _resolve_ns(self, hostname: str) -> List[str]:
        """NS记录解析 - 通过DoH"""
        return await self._resolve_via_doh(hostname, "NS")

    async def _resolve_soa(self, hostname: str) -> List[str]:
        """SOA记录解析 - 通过DoH"""
        return await self._resolve_via_doh(hostname, "SOA")

    async def _resolve_ptr(self, hostname: str) -> List[str]:
        """PTR记录解析"""
        loop = asyncio.get_event_loop()
        try:
            result = await asyncio.wait_for(
                loop.getnameinfo((hostname, 0), 0),
                timeout=self._timeout,
            )
            return [result[0]] if result[0] else []
        except (asyncio.TimeoutError, socket.gaierror):
            return []

    async def _resolve_any(self, hostname: str) -> List[str]:
        """ANY记录解析 - 通过DoH"""
        return await self._resolve_via_doh(hostname, "ANY")

    async def _resolve_via_doh(self, hostname: str, record_type: str) -> List[str]:
        """通过DNS over HTTPS解析

        Args:
            hostname: 主机名
            record_type: 记录类型

        Returns:
            解析结果列表
        """
        import json
        results: List[str] = []

        for endpoint in self._doh_endpoints:
            try:
                params = {"name": hostname, "type": record_type}
                timeout = aiohttp.ClientTimeout(total=self._timeout)
                async with aiohttp.ClientSession(timeout=timeout) as session:
                    async with session.get(
                        endpoint,
                        params=params,
                        headers={"Accept": "application/dns-json"},
                    ) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            answers = data.get("Answer", [])
                            for answer in answers:
                                data_value = answer.get("data", "")
                                if data_value:
                                    results.append(data_value.strip('"'))
                            if results:
                                break
            except Exception as e:
                logger.debug(f"DoH查询失败 ({endpoint}): {e}")
                continue

        return results


class NucleiTCPExecutor:
    """Nuclei TCP协议执行器

    支持:
    - 自定义十六进制数据发送
    - TLS升级探测
    - Banner读取与匹配
    - 多行输入数据
    - 正则匹配响应
    """

    def __init__(self, timeout: float = 10.0):
        self._timeout = timeout

    async def execute_connection(self, tcp_request: Dict[str, Any], target_host: str,
                                  target_port: int,
                                  var_ctx: 'NucleiVariableContext') -> Tuple[bool, str, str, str]:
        """执行TCP连接和数据交互

        Args:
            tcp_request: TCP请求定义 (inputs, host, port, tls等)
            target_host: 目标主机
            target_port: 目标端口
            var_ctx: 变量上下文

        Returns:
            (是否匹配, 证据, 请求Hex, 响应Hex)
        """
        host = tcp_request.get("host", target_host)
        host = var_ctx.resolve(host)

        port_str = tcp_request.get("port", str(target_port))
        port_str = var_ctx.resolve(port_str)
        try:
            port = int(port_str)
        except ValueError:
            port = target_port

        inputs = tcp_request.get("inputs", [])
        use_tls = tcp_request.get("tls", False)
        read_size = tcp_request.get("read-size", 4096)
        read_all = tcp_request.get("read-all", False)

        request_hex_parts: List[str] = []
        response_data = b""

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self._timeout)

            if use_tls:
                import ssl as ssl_module
                ctx = ssl_module.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl_module.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=host)

            await asyncio.get_event_loop().run_in_executor(
                None, sock.connect, (host, port)
            )

            for input_item in inputs:
                data = input_item.get("data", "")
                data_type = input_item.get("type", "hex")

                if data_type == "hex":
                    try:
                        raw_data = bytes.fromhex(data.replace(" ", ""))
                    except ValueError:
                        raw_data = data.encode("utf-8", errors="ignore")
                else:
                    raw_data = var_ctx.resolve(data).encode("utf-8", errors="ignore")

                request_hex_parts.append(raw_data.hex())

                await asyncio.get_event_loop().run_in_executor(
                    None, sock.sendall, raw_data
                )

                await asyncio.sleep(0.1)

            if read_all:
                while True:
                    try:
                        chunk = await asyncio.get_event_loop().run_in_executor(
                            None, sock.recv, read_size
                        )
                        if not chunk:
                            break
                        response_data += chunk
                    except socket.timeout:
                        break
            else:
                try:
                    response_data = await asyncio.get_event_loop().run_in_executor(
                        None, sock.recv, read_size
                    )
                except socket.timeout:
                    pass

            sock.close()

        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            logger.debug(f"TCP连接失败 {host}:{port}: {e}")
            return False, "", "", ""
        except Exception as e:
            logger.debug(f"TCP执行异常 {host}:{port}: {e}")
            return False, "", "", ""

        request_hex = "|".join(request_hex_parts)
        response_hex = response_data.hex()
        response_text = response_data.decode("utf-8", errors="ignore")

        evidence = f"TCP {host}:{port} - {len(response_data)} bytes received"
        return True, evidence, request_hex, response_hex

    async def read_banner(self, host: str, port: int, use_tls: bool = False) -> str:
        """读取TCP Banner

        Args:
            host: 目标主机
            port: 目标端口
            use_tls: 是否使用TLS

        Returns:
            Banner字符串
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self._timeout)

            if use_tls:
                import ssl as ssl_module
                ctx = ssl_module.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl_module.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=host)

            await asyncio.get_event_loop().run_in_executor(
                None, sock.connect, (host, port)
            )

            await asyncio.sleep(0.5)

            banner = await asyncio.get_event_loop().run_in_executor(
                None, sock.recv, 4096
            )
            sock.close()
            return banner.decode("utf-8", errors="ignore").strip()
        except Exception as e:
            logger.debug(f"Banner读取失败 {host}:{port}: {e}")
            return ""


class RequestDelayConfig:
    """请求延迟配置

    支持固定延迟和随机范围延迟:
    - fixed: 固定延迟秒数
    - min/max: 随机延迟范围 [min, max]

    Examples:
        >>> cfg = RequestDelayConfig(fixed=0.5)
        >>> cfg.get_delay()  # 0.5

        >>> cfg = RequestDelayConfig(min_delay=0.1, max_delay=2.0)
        >>> delay = cfg.get_delay()  # 0.1 ~ 2.0 之间的随机值
    """

    def __init__(self, fixed: float = 0.0, min_delay: float = 0.0, max_delay: float = 0.0):
        self._fixed = fixed
        self._min = min_delay
        self._max = max_delay

    @property
    def is_random(self) -> bool:
        return self._min > 0 or self._max > 0

    def get_delay(self) -> float:
        """获取延迟秒数"""
        if self._fixed > 0:
            return self._fixed
        if self._min > 0 or self._max > 0:
            return random.uniform(self._min, self._max)
        return 0.0


class NucleiExecutor:
    """Nuclei模板执行引擎主控

    统一调度模板加载、HTTP执行、匹配器、提取器，
    通过事件总线发布结果，与反连平台、插件市场联动。
    """

    def __init__(self, templates_dir: Optional[str] = None,
                 timeout: float = 10.0, request_delay: float = 0.0,
                 max_concurrency: int = 10,
                 max_response_size: int = DEFAULT_MAX_RESPONSE_SIZE,
                 max_requests: int = 100,
                 delay_config: Optional[RequestDelayConfig] = None):
        self._loader = NucleiTemplateLoader(templates_dir)
        self._http_executor = NucleiHTTPExecutor(
            timeout=timeout,
            max_response_size=max_response_size,
        )
        self._dns_executor = NucleiDNSExecutor(timeout=timeout)
        self._tcp_executor = NucleiTCPExecutor(timeout=timeout)
        self._matcher_engine = NucleiMatcherEngine()
        self._extractor_engine = NucleiExtractorEngine()
        self._timeout = timeout
        self._request_delay = request_delay
        self._max_concurrency = max_concurrency
        self._max_response_size = max_response_size
        self._max_requests = max_requests
        self._delay_config = delay_config or RequestDelayConfig(fixed=request_delay)
        self._semaphore = asyncio.Semaphore(max_concurrency)
        self._event_bus = None
        self._oob_address = ""
        self._execution_stats: Dict[str, Any] = {
            "total_executed": 0,
            "vulnerabilities_found": 0,
            "errors": 0,
        }
        self._fingerprint_generator = NucleiFingerprintGenerator(self._loader)
        self._update_scheduler = NucleiUpdateScheduler(self)
        self._cli_handler = NucleiCLIHandler(self)
        self._system_integration = NucleiSystemIntegration(self)

    @property
    def loader(self) -> NucleiTemplateLoader:
        return self._loader

    @property
    def stats(self) -> NucleiTemplateStats:
        return self._loader.stats

    @property
    def execution_stats(self) -> Dict[str, Any]:
        return dict(self._execution_stats)

    @property
    def memory_guard(self) -> MemoryGuard:
        return self._http_executor.memory_guard

    @property
    def fingerprint_generator(self) -> 'NucleiFingerprintGenerator':
        return self._fingerprint_generator

    @property
    def update_scheduler(self) -> 'NucleiUpdateScheduler':
        return self._update_scheduler

    @property
    def cli_handler(self) -> 'NucleiCLIHandler':
        return self._cli_handler

    @property
    def system_integration(self) -> 'NucleiSystemIntegration':
        return self._system_integration

    @property
    def max_requests(self) -> int:
        return self._max_requests

    @max_requests.setter
    def max_requests(self, value: int):
        self._max_requests = value

    @property
    def delay_config(self) -> RequestDelayConfig:
        return self._delay_config

    @delay_config.setter
    def delay_config(self, value: RequestDelayConfig):
        self._delay_config = value

    def set_event_bus(self, event_bus):
        """设置事件总线，用于发布漏洞发现事件"""
        self._event_bus = event_bus

    @property
    def event_bus(self):
        """获取事件总线"""
        return self._event_bus

    def set_oob_address(self, address: str):
        """设置反连平台地址，自动替换 {{Collaborator}} 变量"""
        self._oob_address = address

    @property
    def oob_address(self) -> str:
        """获取反连平台地址"""
        return self._oob_address

    def load_templates(self, directory: str) -> int:
        """从本地目录加载模板"""
        return self._loader.load_from_directory(directory)

    def load_templates_from_zip(self, zip_path: str) -> int:
        """从ZIP压缩包加载模板"""
        return self._loader.load_from_zip(zip_path)

    async def load_templates_from_remote(self, repo_url: str) -> int:
        """从远程Git仓库加载模板"""
        return await self._loader.load_from_remote(repo_url)

    async def execute(self, template: NucleiTemplate, target_url: str,
                      options: Optional[Dict[str, Any]] = None) -> NucleiVerifyResult:
        """执行单个模板验证

        根据模板类型自动选择执行器:
        - HTTP请求 -> NucleiHTTPExecutor
        - DNS请求 -> NucleiDNSExecutor
        - TCP请求 -> NucleiTCPExecutor

        完整执行流程:
        1. 创建变量上下文，注入反连地址和模板变量
        2. 遍历模板中的每个请求
        3. 执行请求 → 提取器提取 → 匹配器匹配
        4. 构建统一的 NucleiVerifyResult

        Args:
            template: Nuclei模板对象
            target_url: 目标URL
            options: 执行选项 (timeout_override, skip_match等)

        Returns:
            NucleiVerifyResult 验证结果
        """
        options = options or {}
        start_time = time.time()
        self._execution_stats["total_executed"] += 1

        parsed = urlparse(target_url)
        host = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "https" else 80)

        var_ctx = NucleiVariableContext(
            base_url=target_url,
            target_host=host,
            target_port=port,
        )

        if self._oob_address:
            var_ctx.set_variable("Collaborator", self._oob_address)
            var_ctx.set_variable("interactsh-url", self._oob_address)

        for var_name, var_value in template.variables.items():
            var_ctx.set_variable(var_name, var_value)

        if template.requests:
            return await self._execute_http(template, target_url, var_ctx, start_time, options)
        elif template.dns:
            return await self._execute_dns(template, target_url, var_ctx, start_time, options)
        elif template.tcp:
            return await self._execute_tcp(template, target_url, var_ctx, start_time, options)
        else:
            return NucleiVerifyResult(
                template_id=template.id,
                template_name=template.info.name,
                target=target_url,
                vulnerable=False,
                matched=False,
                error="模板未定义任何请求",
                severity=template.info.severity.value,
                response_time=time.time() - start_time,
                timestamp=datetime.now().isoformat(),
            )

    async def _execute_http(self, template: NucleiTemplate, target_url: str,
                            var_ctx: NucleiVariableContext, start_time: float,
                            options: Dict[str, Any]) -> NucleiVerifyResult:
        """执行HTTP模板"""
        all_extracted: Dict[str, Any] = {}
        overall_vulnerable = False
        all_evidence: List[str] = []
        last_request_hex = ""
        last_response_hex = ""
        last_status_code = 0
        truncated = False

        for req_idx, request in enumerate(template.requests):
            if req_idx >= self._max_requests:
                logger.warning(
                    f"模板 [{template.id}] 达到最大请求数限制 {self._max_requests}，"
                    f"已跳过剩余 {len(template.requests) - req_idx} 个请求"
                )
                break

            delay = self._delay_config.get_delay()
            if delay > 0 and req_idx > 0:
                await asyncio.sleep(delay)

            try:
                timeout_override = options.get("timeout_override")
                if timeout_override:
                    self._http_executor._timeout = timeout_override

                status_code, body, headers, req_hex, resp_hex = (
                    await self._http_executor.execute_request(
                        request, target_url, var_ctx, all_extracted
                    )
                )

                last_request_hex = req_hex
                last_response_hex = resp_hex
                last_status_code = status_code

                if self._http_executor.memory_guard.truncated:
                    truncated = True

                if status_code == 0:
                    continue

                if request.extractors:
                    extracted = self._extractor_engine.extract(
                        request.extractors, body, headers
                    )
                    all_extracted.update(extracted)

                if request.matchers:
                    matched, evidence, matcher_name = self._matcher_engine.match(
                        request.matchers,
                        request.matchers_condition,
                        body, headers, status_code, len(body)
                    )

                    if matched:
                        overall_vulnerable = True
                        if evidence:
                            all_evidence.append(f"[{matcher_name}] {evidence}")

                if request.stop_at_first_match and overall_vulnerable:
                    break

            except asyncio.TimeoutError:
                logger.warning(f"模板执行超时 [{template.id}] 请求 #{req_idx}")
                self._execution_stats["errors"] += 1
                break
            except Exception as e:
                logger.debug(f"请求执行异常 [{template.id}] 请求 #{req_idx}: {e}")
                self._execution_stats["errors"] += 1
                continue

        response_time = time.time() - start_time

        if overall_vulnerable:
            self._execution_stats["vulnerabilities_found"] += 1

        result = NucleiVerifyResult(
            template_id=template.id,
            template_name=template.info.name,
            target=target_url,
            vulnerable=overall_vulnerable,
            matched=overall_vulnerable,
            extracted=bool(all_extracted),
            evidence=" | ".join(all_evidence) if all_evidence else "",
            request_hex=last_request_hex,
            response_hex=last_response_hex,
            extracted_values=all_extracted,
            severity=template.info.severity.value,
            author=", ".join(template.info.author) if template.info.author else "",
            description=template.info.description,
            tags=[t.strip() for t in template.info.tags.split(",") if t.strip()],
            cve=template.info.classification.cve_id if template.info.classification else [],
            response_time=response_time,
            timestamp=datetime.now().isoformat(),
        )

        if truncated:
            result.evidence += " [响应体已截断]"

        self._publish_result(result, template, target_url, overall_vulnerable, response_time)
        return result

    async def _execute_dns(self, template: NucleiTemplate, target_url: str,
                           var_ctx: NucleiVariableContext, start_time: float,
                           options: Dict[str, Any]) -> NucleiVerifyResult:
        """执行DNS模板

        遍历模板中的DNS请求，执行DNS查询并匹配结果。

        Args:
            template: Nuclei模板
            target_url: 目标URL
            var_ctx: 变量上下文
            start_time: 开始时间
            options: 执行选项

        Returns:
            验证结果
        """
        all_extracted: Dict[str, Any] = {}
        overall_vulnerable = False
        all_evidence: List[str] = []
        last_request_hex = ""
        last_response_hex = ""

        parsed = urlparse(target_url)
        host = parsed.hostname or target_url

        for req_idx, dns_request in enumerate(template.dns):
            if req_idx >= self._max_requests:
                logger.warning(f"DNS模板 [{template.id}] 达到最大请求数限制")
                break

            delay = self._delay_config.get_delay()
            if delay > 0 and req_idx > 0:
                await asyncio.sleep(delay)

            try:
                matched, evidence, response_data = await self._dns_executor.execute_query(
                    dns_request, host, var_ctx
                )

                last_request_hex = f"DNS:{dns_request.get('type','A')}:{dns_request.get('name',host)}"
                last_response_hex = json.dumps(response_data, ensure_ascii=False)

                if matched:
                    overall_vulnerable = True
                    if evidence:
                        all_evidence.append(evidence)

                matchers = dns_request.get("matchers", [])
                if matchers:
                    matcher_objects = [Matcher(**m) if isinstance(m, dict) else m for m in matchers]
                    matchers_condition = dns_request.get("matchers-condition", "or")
                    condition = MatcherCondition(matchers_condition) if isinstance(matchers_condition, str) else matchers_condition

                    body_for_match = json.dumps(response_data)
                    matched, evidence, matcher_name = self._matcher_engine.match(
                        matcher_objects, condition,
                        body_for_match, {}, 200, len(body_for_match)
                    )
                    if matched:
                        overall_vulnerable = True
                        if evidence:
                            all_evidence.append(f"[DNS/{matcher_name}] {evidence}")

                extractors = dns_request.get("extractors", [])
                if extractors:
                    extractor_objects = [Extractor(**e) if isinstance(e, dict) else e for e in extractors]
                    body_for_extract = json.dumps(response_data)
                    extracted = self._extractor_engine.extract(
                        extractor_objects, body_for_extract, {}
                    )
                    all_extracted.update(extracted)

            except asyncio.TimeoutError:
                logger.warning(f"DNS模板执行超时 [{template.id}] 请求 #{req_idx}")
                self._execution_stats["errors"] += 1
                break
            except Exception as e:
                logger.debug(f"DNS请求执行异常 [{template.id}] 请求 #{req_idx}: {e}")
                self._execution_stats["errors"] += 1
                continue

        response_time = time.time() - start_time

        if overall_vulnerable:
            self._execution_stats["vulnerabilities_found"] += 1

        result = NucleiVerifyResult(
            template_id=template.id,
            template_name=template.info.name,
            target=target_url,
            vulnerable=overall_vulnerable,
            matched=overall_vulnerable,
            extracted=bool(all_extracted),
            evidence=" | ".join(all_evidence) if all_evidence else "",
            request_hex=last_request_hex,
            response_hex=last_response_hex,
            extracted_values=all_extracted,
            severity=template.info.severity.value,
            author=", ".join(template.info.author) if template.info.author else "",
            description=template.info.description,
            tags=[t.strip() for t in template.info.tags.split(",") if t.strip()],
            cve=template.info.classification.cve_id if template.info.classification else [],
            response_time=response_time,
            timestamp=datetime.now().isoformat(),
        )

        self._publish_result(result, template, target_url, overall_vulnerable, response_time)
        return result

    async def _execute_tcp(self, template: NucleiTemplate, target_url: str,
                           var_ctx: NucleiVariableContext, start_time: float,
                           options: Dict[str, Any]) -> NucleiVerifyResult:
        """执行TCP模板

        遍历模板中的TCP请求，建立TCP连接并匹配Banner/响应。

        Args:
            template: Nuclei模板
            target_url: 目标URL
            var_ctx: 变量上下文
            start_time: 开始时间
            options: 执行选项

        Returns:
            验证结果
        """
        all_extracted: Dict[str, Any] = {}
        overall_vulnerable = False
        all_evidence: List[str] = []
        last_request_hex = ""
        last_response_hex = ""

        parsed = urlparse(target_url)
        host = parsed.hostname or target_url
        port = parsed.port or 80

        for req_idx, tcp_request in enumerate(template.tcp):
            if req_idx >= self._max_requests:
                logger.warning(f"TCP模板 [{template.id}] 达到最大请求数限制")
                break

            delay = self._delay_config.get_delay()
            if delay > 0 and req_idx > 0:
                await asyncio.sleep(delay)

            try:
                matched, evidence, req_hex, resp_hex = await self._tcp_executor.execute_connection(
                    tcp_request, host, port, var_ctx
                )

                last_request_hex = req_hex
                last_response_hex = resp_hex

                if matched:
                    overall_vulnerable = True
                    if evidence:
                        all_evidence.append(evidence)

                matchers = tcp_request.get("matchers", [])
                if matchers:
                    matcher_objects = [Matcher(**m) if isinstance(m, dict) else m for m in matchers]
                    matchers_condition = tcp_request.get("matchers-condition", "or")
                    condition = MatcherCondition(matchers_condition) if isinstance(matchers_condition, str) else matchers_condition

                    resp_text = resp_hex
                    try:
                        resp_text = bytes.fromhex(resp_hex).decode("utf-8", errors="replace")
                    except (ValueError, UnicodeDecodeError):
                        pass

                    matched, evidence, matcher_name = self._matcher_engine.match(
                        matcher_objects, condition,
                        resp_text, {}, 200, len(resp_text)
                    )
                    if matched:
                        overall_vulnerable = True
                        if evidence:
                            all_evidence.append(f"[TCP/{matcher_name}] {evidence}")

                extractors = tcp_request.get("extractors", [])
                if extractors:
                    extractor_objects = [Extractor(**e) if isinstance(e, dict) else e for e in extractors]
                    resp_text = resp_hex
                    try:
                        resp_text = bytes.fromhex(resp_hex).decode("utf-8", errors="replace")
                    except (ValueError, UnicodeDecodeError):
                        pass
                    extracted = self._extractor_engine.extract(
                        extractor_objects, resp_text, {}
                    )
                    all_extracted.update(extracted)

            except asyncio.TimeoutError:
                logger.warning(f"TCP模板执行超时 [{template.id}] 请求 #{req_idx}")
                self._execution_stats["errors"] += 1
                break
            except Exception as e:
                logger.debug(f"TCP请求执行异常 [{template.id}] 请求 #{req_idx}: {e}")
                self._execution_stats["errors"] += 1
                continue

        response_time = time.time() - start_time

        if overall_vulnerable:
            self._execution_stats["vulnerabilities_found"] += 1

        result = NucleiVerifyResult(
            template_id=template.id,
            template_name=template.info.name,
            target=target_url,
            vulnerable=overall_vulnerable,
            matched=overall_vulnerable,
            extracted=bool(all_extracted),
            evidence=" | ".join(all_evidence) if all_evidence else "",
            request_hex=last_request_hex,
            response_hex=last_response_hex,
            extracted_values=all_extracted,
            severity=template.info.severity.value,
            author=", ".join(template.info.author) if template.info.author else "",
            description=template.info.description,
            tags=[t.strip() for t in template.info.tags.split(",") if t.strip()],
            cve=template.info.classification.cve_id if template.info.classification else [],
            response_time=response_time,
            timestamp=datetime.now().isoformat(),
        )

        self._publish_result(result, template, target_url, overall_vulnerable, response_time)
        return result

    def _publish_result(self, result: NucleiVerifyResult, template: NucleiTemplate,
                        target_url: str, vulnerable: bool, response_time: float):
        """发布执行结果到事件总线

        Args:
            result: 验证结果
            template: 模板对象
            target_url: 目标URL
            vulnerable: 是否存在漏洞
            response_time: 响应时间
        """
        if self._event_bus and vulnerable:
            self._event_bus.publish(
                event_type="nuclei_vuln_found",
                source="NucleiExecutor",
                data={
                    "result": result.model_dump(),
                    "template_id": template.id,
                    "severity": template.info.severity.value,
                    "target": target_url,
                },
            )

        if self._event_bus:
            self._event_bus.publish(
                event_type="nuclei_execution_complete",
                source="NucleiExecutor",
                data={
                    "template_id": template.id,
                    "target": target_url,
                    "vulnerable": vulnerable,
                    "response_time": response_time,
                },
            )

    async def execute_batch(self, templates: List[NucleiTemplate], target_url: str,
                            options: Optional[Dict[str, Any]] = None) -> List[NucleiVerifyResult]:
        """批量执行模板（并发控制）

        Args:
            templates: 模板列表
            target_url: 目标URL
            options: 执行选项

        Returns:
            验证结果列表
        """
        async def _execute_with_semaphore(template: NucleiTemplate) -> NucleiVerifyResult:
            async with self._semaphore:
                return await self.execute(template, target_url, options)

        tasks = [_execute_with_semaphore(t) for t in templates]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        valid_results: List[NucleiVerifyResult] = []
        for r in results:
            if isinstance(r, Exception):
                logger.error(f"批量执行异常: {r}")
            elif isinstance(r, NucleiVerifyResult):
                valid_results.append(r)

        return valid_results

    async def execute_by_fingerprint(self, target_url: str, fingerprint: Dict[str, Any],
                                     options: Optional[Dict[str, Any]] = None) -> List[NucleiVerifyResult]:
        """根据资产指纹匹配并执行模板

        Args:
            target_url: 目标URL
            fingerprint: 资产指纹信息 (product, tags, cpe等)
            options: 执行选项

        Returns:
            验证结果列表
        """
        matched_templates = self._match_by_fingerprint(fingerprint)
        if not matched_templates:
            logger.debug(f"无匹配模板: {fingerprint.get('product', 'unknown')}")
            return []

        return await self.execute_batch(matched_templates, target_url, options)

    def _match_by_fingerprint(self, fingerprint: Dict[str, Any]) -> List[NucleiTemplate]:
        """根据指纹匹配模板"""
        matched: List[NucleiTemplate] = []
        product = fingerprint.get("product", "").lower()
        tags = fingerprint.get("tags", [])
        cpe = fingerprint.get("cpe", "").lower()

        for template in self._loader.templates.values():
            template_tags = [t.strip() for t in template.info.tags.split(",") if t.strip()]
            template_name_lower = template.info.name.lower()

            if product and product in template_name_lower:
                matched.append(template)
            elif cpe and template.info.classification and template.info.classification.cpe:
                if cpe in (template.info.classification.cpe or "").lower():
                    matched.append(template)
            elif any(tag in template_tags for tag in tags):
                matched.append(template)

        return matched

    def to_poc_result(self, nuclei_result: NucleiVerifyResult) -> PoCVerificationResult:
        """转换为昆仑PoC验证结果

        Args:
            nuclei_result: Nuclei验证结果

        Returns:
            昆仑标准的PoC验证结果
        """
        severity_map = {
            "critical": SeverityLevel.CRITICAL,
            "high": SeverityLevel.HIGH,
            "medium": SeverityLevel.MEDIUM,
            "low": SeverityLevel.LOW,
            "info": SeverityLevel.INFO,
        }

        confidence = ConfidenceLevel.CONFIRMED if nuclei_result.vulnerable else ConfidenceLevel.UNCONFIRMED

        return PoCVerificationResult(
            poc_id=nuclei_result.template_id,
            poc_name=nuclei_result.template_name,
            target=nuclei_result.target,
            status=PoCStatus.SUCCESS if nuclei_result.vulnerable else PoCStatus.FAILED,
            vulnerable=nuclei_result.vulnerable,
            confidence=confidence,
            severity=severity_map.get(nuclei_result.severity, SeverityLevel.INFO),
            cve=", ".join(nuclei_result.cve) if nuclei_result.cve else "",
            evidence=nuclei_result.evidence,
            execution_time=nuclei_result.response_time,
            metadata={
                "template_id": nuclei_result.template_id,
                "author": nuclei_result.author,
                "tags": nuclei_result.tags,
                "extracted": nuclei_result.extracted_values,
                "engine": "nuclei",
            },
        )

    async def close(self):
        """关闭执行器，释放所有资源"""
        await self._update_scheduler.stop()
        await self._system_integration.close()
        await self._http_executor.close()

    async def update_templates(self, repo_url: str = "https://github.com/projectdiscovery/nuclei-templates.git") -> int:
        """从官方仓库更新模板

        Args:
            repo_url: Nuclei模板仓库URL

        Returns:
            加载的模板数量
        """
        logger.info(f"正在从 {repo_url} 更新模板...")
        count = await self._loader.load_from_remote(repo_url)
        logger.info(f"模板更新完成，共加载 {count} 个模板")
        return count

    def search_templates(self, keyword: str) -> List[NucleiTemplate]:
        """搜索模板

        Args:
            keyword: 搜索关键词

        Returns:
            匹配的模板列表
        """
        return self._loader.search(keyword)

    def get_template_groups(self) -> Dict[str, List[NucleiTemplate]]:
        """获取按标签分组的模板"""
        return self._loader.get_templates_by_group("tags")

    def generate_fingerprints(self) -> List[FingerprintRule]:
        """从已加载模板自动生成指纹规则

        遍历所有模板的matchers，提取word/regex匹配条件，
        生成指纹规则补充到资产识别规则库。

        Returns:
            生成的指纹规则列表
        """
        return self._fingerprint_generator.generate_all()

    async def handle_cli(self, args: List[str]) -> str:
        """处理CLI命令

        Args:
            args: 命令参数列表 (如 ["search", "apache"])

        Returns:
            命令输出字符串
        """
        return await self._cli_handler.handle(args)

    async def start_auto_update(self, interval: int = 86400, immediate: bool = True):
        """启动模板自动更新

        Args:
            interval: 更新间隔秒数 (默认24小时)
            immediate: 是否立即执行首次更新
        """
        self._update_scheduler._update_interval = interval
        await self._update_scheduler.start(immediate=immediate)

    async def stop_auto_update(self):
        """停止模板自动更新"""
        await self._update_scheduler.stop()

    def enable_system_integration(self):
        """启用系统集成 (反连/代理/指纹联动)"""
        self._system_integration.enable()

    def disable_system_integration(self):
        """禁用系统集成"""
        self._system_integration.disable()


class NucleiFingerprintGenerator:
    """Nuclei指纹自动生成器

    从已加载的Nuclei模板中自动提取指纹规则:
    - word匹配器 → 产品关键词指纹
    - regex匹配器 → 版本正则指纹
    - 分类信息 → CPE/CVE指纹

    生成的指纹规则可直接补充到资产识别规则库。
    """

    def __init__(self, loader: NucleiTemplateLoader):
        self._loader = loader
        self._fingerprints: Dict[str, FingerprintRule] = {}

    @property
    def fingerprints(self) -> Dict[str, FingerprintRule]:
        return self._fingerprints

    def generate_all(self) -> List[FingerprintRule]:
        """从所有模板生成指纹规则

        Returns:
            生成的指纹规则列表
        """
        rules: List[FingerprintRule] = []
        for template in self._loader.templates.values():
            rule = self._generate_from_template(template)
            if rule:
                rules.append(rule)
                self._fingerprints[rule.rule_id] = rule
        logger.info(f"从 {len(self._loader.templates)} 个模板生成了 {len(rules)} 条指纹规则")
        return rules

    def _generate_from_template(self, template: NucleiTemplate) -> Optional[FingerprintRule]:
        """从单个模板生成指纹规则"""
        words: List[str] = []
        regex_patterns: List[str] = []
        product = ""
        cpe = ""

        if template.info.classification:
            if template.info.classification.cpe:
                cpe = template.info.classification.cpe
            if template.info.classification.cve_id:
                pass

        for matcher in template.get_all_matchers():
            if matcher.type == MatcherType.WORD and matcher.words:
                words.extend(matcher.words)
            if matcher.type == MatcherType.REGEX and matcher.regex:
                regex_patterns.extend(matcher.regex)

        if not words and not regex_patterns:
            return None

        if words:
            product = words[0]

        rule_id = f"fp_{template.id}"
        return FingerprintRule(
            rule_id=rule_id,
            template_id=template.id,
            protocol="http",
            product=product,
            words=list(set(words)),
            regex_patterns=list(set(regex_patterns)),
            cpe=cpe,
            severity=template.info.severity.value,
            confidence=0.7 if (words and regex_patterns) else 0.5,
        )

    def match(self, response_body: str, response_headers: str = "") -> List[FingerprintRule]:
        """根据响应内容匹配指纹规则

        Args:
            response_body: 响应体
            response_headers: 响应头

        Returns:
            匹配的指纹规则列表
        """
        matched: List[FingerprintRule] = []
        search_text = f"{response_headers}\n{response_body}".lower()

        for rule in self._fingerprints.values():
            score = 0
            total = len(rule.words) + len(rule.regex_patterns)
            if total == 0:
                continue

            for word in rule.words:
                if word.lower() in search_text:
                    score += 1

            for pattern in rule.regex_patterns:
                try:
                    if re.search(pattern, search_text, re.IGNORECASE):
                        score += 1
                except re.error:
                    continue

            if score > 0 and score / total >= rule.confidence:
                matched.append(rule)

        return matched


class NucleiUpdateScheduler:
    """Nuclei模板定期更新调度器

    支持从远程Git仓库定期拉取最新模板:
    - 启动时立即更新
    - 按配置的间隔时间定期更新
    - 支持多个仓库源
    """

    def __init__(self, executor: 'NucleiExecutor', update_interval: int = 86400):
        self._executor = executor
        self._update_interval = update_interval
        self._repos: List[str] = [
            "https://github.com/projectdiscovery/nuclei-templates.git",
        ]
        self._task: Optional[asyncio.Task] = None
        self._running = False
        self._last_update: float = 0.0
        self._update_count: int = 0

    @property
    def last_update(self) -> float:
        return self._last_update

    @property
    def update_count(self) -> int:
        return self._update_count

    def add_repo(self, repo_url: str):
        """添加模板仓库源"""
        if repo_url not in self._repos:
            self._repos.append(repo_url)

    async def start(self, immediate: bool = True):
        """启动定期更新

        Args:
            immediate: 是否立即执行首次更新
        """
        if self._running:
            return
        self._running = True

        if immediate:
            await self._do_update()

        self._task = asyncio.create_task(self._update_loop())

    async def stop(self):
        """停止定期更新"""
        self._running = False
        if self._task and not self._task.done():
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

    async def _update_loop(self):
        """更新循环"""
        while self._running:
            try:
                await asyncio.sleep(self._update_interval)
                if self._running:
                    await self._do_update()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"定期更新异常: {e}")

    async def _do_update(self):
        """执行更新"""
        total_loaded = 0
        for repo_url in self._repos:
            try:
                count = await self._executor.update_templates(repo_url)
                total_loaded += count
            except Exception as e:
                logger.error(f"更新仓库失败 {repo_url}: {e}")

        self._last_update = time.time()
        self._update_count += 1
        logger.info(f"定期更新 #{self._update_count} 完成，共加载 {total_loaded} 个模板")


class NucleiCLIHandler:
    """Nuclei CLI命令处理器

    支持以下命令:
    - nuclei update: 从官方仓库拉取最新模板
    - nuclei search <keyword>: 按名称/标签/作者/CVE搜索
    - nuclei stats: 统计模板数量/分类/最近更新
    - nuclei list: 列出所有模板
    - nuclei info <id>: 查看模板详情
    """

    def __init__(self, executor: 'NucleiExecutor'):
        self._executor = executor

    async def handle(self, args: List[str]) -> str:
        """处理CLI命令

        Args:
            args: 命令参数列表

        Returns:
            命令输出字符串
        """
        if not args:
            return self._help()

        command = args[0].lower()

        if command == "update":
            return await self._cmd_update(args[1:])
        elif command == "search":
            return self._cmd_search(args[1:])
        elif command == "stats":
            return self._cmd_stats()
        elif command == "list":
            return self._cmd_list(args[1:])
        elif command == "info":
            return self._cmd_info(args[1:])
        elif command == "validate":
            return self._cmd_validate(args[1:])
        elif command == "test":
            return await self._cmd_test(args[1:])
        elif command == "help":
            return self._help()
        else:
            return f"未知命令: {command}\n{self._help()}"

    async def _cmd_update(self, args: List[str]) -> str:
        """nuclei update - 更新模板"""
        repo_url = args[0] if args else "https://github.com/projectdiscovery/nuclei-templates.git"
        count = await self._executor.update_templates(repo_url)
        return f"模板更新完成，共加载 {count} 个模板"

    def _cmd_search(self, args: List[str]) -> str:
        """nuclei search <keyword> - 搜索模板"""
        if not args:
            return "用法: nuclei search <keyword>"
        keyword = " ".join(args)
        results = self._executor.search_templates(keyword)
        if not results:
            return f"未找到匹配 '{keyword}' 的模板"

        lines = [f"搜索 '{keyword}' 找到 {len(results)} 个模板:"]
        for t in results[:50]:
            lines.append(f"  [{t.info.severity.value.upper()}] {t.id} - {t.info.name}")
        if len(results) > 50:
            lines.append(f"  ... 还有 {len(results) - 50} 个结果")
        return "\n".join(lines)

    def _cmd_stats(self) -> str:
        """nuclei stats - 统计信息"""
        stats = self._executor.stats
        exec_stats = self._executor.execution_stats

        lines = [
            "=== Nuclei 模板统计 ===",
            f"模板总数: {stats.total_templates}",
            f"加载成功: {stats.loaded_templates}",
            f"加载失败: {stats.failed_templates}",
            f"加载耗时: {stats.load_time:.2f}s",
            "",
            "按严重级别:",
        ]
        for sev, count in sorted(stats.by_severity.items()):
            lines.append(f"  {sev}: {count}")

        lines.append("")
        lines.append("按协议:")
        for proto, count in sorted(stats.by_protocol.items()):
            lines.append(f"  {proto}: {count}")

        lines.append("")
        lines.append("热门标签 (Top 10):")
        sorted_tags = sorted(stats.by_tags.items(), key=lambda x: x[1], reverse=True)[:10]
        for tag, count in sorted_tags:
            lines.append(f"  {tag}: {count}")

        lines.append("")
        lines.append("=== 执行统计 ===")
        lines.append(f"已执行: {exec_stats.get('total_executed', 0)}")
        lines.append(f"发现漏洞: {exec_stats.get('vulnerabilities_found', 0)}")
        lines.append(f"错误: {exec_stats.get('errors', 0)}")

        return "\n".join(lines)

    def _cmd_list(self, args: List[str]) -> str:
        """nuclei list [filter] - 列出模板"""
        filter_key = args[0] if args else ""
        templates = list(self._executor.loader.templates.values())

        if filter_key:
            filter_lower = filter_key.lower()
            templates = [
                t for t in templates
                if (filter_lower in t.info.severity.value or
                    filter_lower in t.info.tags.lower() or
                    filter_lower in t.id.lower())
            ]

        lines = [f"共 {len(templates)} 个模板:"]
        for t in templates[:100]:
            lines.append(f"  [{t.info.severity.value.upper()}] {t.id} - {t.info.name}")
        if len(templates) > 100:
            lines.append(f"  ... 还有 {len(templates) - 100} 个")
        return "\n".join(lines)

    def _cmd_info(self, args: List[str]) -> str:
        """nuclei info <id> - 查看模板详情"""
        if not args:
            return "用法: nuclei info <template_id>"
        template_id = args[0]
        template = self._executor.loader.get_template(template_id)
        if not template:
            return f"模板不存在: {template_id}"

        lines = [
            f"ID: {template.id}",
            f"名称: {template.info.name}",
            f"作者: {', '.join(template.info.author)}",
            f"严重级别: {template.info.severity.value}",
            f"描述: {template.info.description}",
            f"标签: {template.info.tags}",
            f"来源: {template.source_path}",
            f"请求数: {len(template.requests)}",
        ]

        if template.info.classification:
            cls_info = template.info.classification
            if cls_info.cve_id:
                lines.append(f"CVE: {', '.join(cls_info.cve_id)}")
            if cls_info.cwe_id:
                lines.append(f"CWE: {', '.join(cls_info.cwe_id)}")
            if cls_info.cpe:
                lines.append(f"CPE: {cls_info.cpe}")

        for i, req in enumerate(template.requests):
            lines.append(f"")
            lines.append(f"--- 请求 #{i + 1} ---")
            lines.append(f"  方法: {req.method.value}")
            lines.append(f"  路径: {req.path}")
            lines.append(f"  匹配器: {len(req.matchers)} 个")
            lines.append(f"  提取器: {len(req.extractors)} 个")
            if req.attack:
                lines.append(f"  攻击类型: {req.attack.value}")

        return "\n".join(lines)

    def _cmd_validate(self, args: List[str]) -> str:
        """nuclei validate <path> - 校验模板语法

        校验指定模板文件的YAML语法和必填字段，
        不执行实际请求。

        Args:
            args: [文件路径]

        Returns:
            校验结果
        """
        if not args:
            return "用法: nuclei validate <template_path>"

        file_path = args[0]
        if not os.path.exists(file_path):
            return f"文件不存在: {file_path}"

        errors: List[str] = []
        warnings: List[str] = []

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()

            yaml_data = yaml.safe_load(content)

            if not yaml_data or not isinstance(yaml_data, dict):
                errors.append("无效的YAML格式或空文件")
            else:
                if "id" not in yaml_data:
                    errors.append("缺少必填字段: id")
                else:
                    template_id = yaml_data["id"]
                    if not isinstance(template_id, str) or not template_id.strip():
                        errors.append("id字段不能为空")

                if "info" not in yaml_data:
                    errors.append("缺少必填字段: info")
                else:
                    info = yaml_data["info"]
                    if not isinstance(info, dict):
                        errors.append("info字段必须是字典")
                    else:
                        if "name" not in info:
                            errors.append("info中缺少必填字段: name")
                        if "severity" not in info:
                            warnings.append("info中建议填写: severity")

                has_requests = bool(yaml_data.get("requests") or yaml_data.get("http"))
                has_dns = bool(yaml_data.get("dns"))
                has_tcp = bool(yaml_data.get("tcp"))

                if not (has_requests or has_dns or has_tcp):
                    warnings.append("模板未定义任何请求 (requests/dns/tcp)")

                if has_requests:
                    requests = yaml_data.get("requests") or yaml_data.get("http", [])
                    if isinstance(requests, list):
                        for i, req in enumerate(requests):
                            if isinstance(req, dict):
                                if "matchers" in req:
                                    matchers = req["matchers"]
                                    if isinstance(matchers, list):
                                        for j, m in enumerate(matchers):
                                            if isinstance(m, dict) and "type" not in m:
                                                errors.append(
                                                    f"请求#{i+1} 匹配器#{j+1} 缺少type字段"
                                                )

        except yaml.YAMLError as e:
            errors.append(f"YAML解析错误: {e}")
        except Exception as e:
            errors.append(f"读取失败: {e}")

        lines = [f"校验文件: {file_path}"]
        if errors:
            lines.append(f"\n错误 ({len(errors)}):")
            for err in errors:
                lines.append(f"  ✗ {err}")
        else:
            lines.append("\n✓ 语法校验通过")

        if warnings:
            lines.append(f"\n警告 ({len(warnings)}):")
            for warn in warnings:
                lines.append(f"  ⚠ {warn}")

        if not errors:
            lines.append("\n状态: 有效 ✓")

        return "\n".join(lines)

    async def _cmd_test(self, args: List[str]) -> str:
        """nuclei test <template-id> --url <target> - 单模板调试模式

        对指定目标执行单个模板，输出详细执行过程。

        Args:
            args: [template_id, --url, target_url]

        Returns:
            执行结果
        """
        if len(args) < 3 or args[1] != "--url":
            return "用法: nuclei test <template_id> --url <target_url>"

        template_id = args[0]
        target_url = args[2]

        template = self._executor.loader.get_template(template_id)
        if not template:
            return f"模板不存在: {template_id}"

        lines = [
            f"调试模式: {template.id}",
            f"目标: {target_url}",
            f"名称: {template.info.name}",
            f"严重级别: {template.info.severity.value}",
            f"请求数: {len(template.requests)}",
            "-" * 50,
        ]

        try:
            result = await self._executor.execute(template, target_url)

            lines.append(f"执行时间: {result.response_time:.3f}s")
            lines.append(f"漏洞状态: {'发现漏洞 ✓' if result.vulnerable else '未发现 ✗'}")
            lines.append(f"匹配状态: {'匹配 ✓' if result.matched else '未匹配 ✗'}")
            lines.append(f"提取状态: {'已提取 ✓' if result.extracted else '未提取 ✗'}")

            if result.evidence:
                lines.append(f"\n证据:")
                lines.append(f"  {result.evidence}")

            if result.extracted_values:
                lines.append(f"\n提取数据:")
                for k, v in result.extracted_values.items():
                    v_str = str(v)
                    if len(v_str) > 200:
                        v_str = v_str[:200] + "..."
                    lines.append(f"  {k}: {v_str}")

            if result.request_hex:
                lines.append(f"\n请求Hex长度: {len(result.request_hex)} 字符")
            if result.response_hex:
                lines.append(f"响应Hex长度: {len(result.response_hex)} 字符")

            if result.error:
                lines.append(f"\n错误: {result.error}")

        except Exception as e:
            lines.append(f"执行异常: {e}")

        return "\n".join(lines)

    def _help(self) -> str:
        """帮助信息"""
        return """Nuclei 模板管理命令:

  nuclei update [repo_url]    - 从远程仓库更新模板
  nuclei search <keyword>    - 按关键词搜索模板
  nuclei stats               - 显示模板和执行统计
  nuclei list [filter]       - 列出模板 (可按severity/tag过滤)
  nuclei info <id>           - 查看模板详情
  nuclei validate <path>     - 校验模板文件语法
  nuclei test <id> --url <u> - 单模板调试模式
  nuclei help                - 显示此帮助"""


class NucleiSystemIntegration:
    """Nuclei引擎与昆仑系统深度集成

    负责:
    - 与反连平台联动: {{Collaborator}} 自动替换
    - 与代理模块联动: 代理流量提取URL/Cookie作为模板输入
    - 与资产指纹联动: 指纹匹配后自动选择模板
    - 与报告模块联动: 结果自动纳入报告
    - 与插件市场联动: 模板作为插件的一种形式，支持下载/上传模板包
    """

    def __init__(self, executor: 'NucleiExecutor'):
        self._executor = executor
        self._proxy_traffic_queue: asyncio.Queue = asyncio.Queue(maxsize=1000)
        self._fingerprint_cache: Dict[str, List[str]] = {}
        self._integration_enabled = False
        self._report_results: List[NucleiVerifyResult] = []
        self._report_lock = asyncio.Lock()
        self._plugin_market_url = ""
        self._installed_packages: Dict[str, Dict[str, Any]] = {}

    @property
    def integration_enabled(self) -> bool:
        return self._integration_enabled

    def enable(self):
        """启用系统集成"""
        self._integration_enabled = True
        logger.info("Nuclei系统集成已启用")

    def disable(self):
        """禁用系统集成"""
        self._integration_enabled = False
        logger.info("Nuclei系统集成已禁用")

    def set_oob_address(self, address: str):
        """设置反连平台地址

        自动替换模板中的 {{Collaborator}} 和 {{interactsh-url}} 变量。
        """
        self._executor.set_oob_address(address)
        logger.info(f"反连地址已设置: {address}")

    async def feed_proxy_traffic(self, url: str, cookies: Dict[str, str] = None,
                                  headers: Dict[str, str] = None):
        """从代理模块喂入流量数据

        代理拦截的HTTP流量自动提取URL和Cookie，
        作为Nuclei模板的目标输入。

        Args:
            url: 拦截到的URL
            cookies: 提取的Cookie
            headers: 提取的请求头
        """
        if not self._integration_enabled:
            return

        try:
            self._proxy_traffic_queue.put_nowait({
                "url": url,
                "cookies": cookies or {},
                "headers": headers or {},
                "timestamp": time.time(),
            })
        except asyncio.QueueFull:
            pass

    async def on_fingerprint_matched(self, fingerprint: Dict[str, Any], target_url: str):
        """资产指纹匹配后的回调

        当资产识别模块匹配到指纹后，自动选择对应的Nuclei模板执行。

        Args:
            fingerprint: 匹配到的资产指纹
            target_url: 目标URL
        """
        if not self._integration_enabled:
            return

        cache_key = f"{target_url}:{fingerprint.get('product', '')}"
        if cache_key in self._fingerprint_cache:
            return

        try:
            results = await self._executor.execute_by_fingerprint(target_url, fingerprint)
            self._fingerprint_cache[cache_key] = [r.template_id for r in results if r.vulnerable]

            if results:
                vuln_count = sum(1 for r in results if r.vulnerable)
                logger.info(
                    f"指纹联动: {fingerprint.get('product', 'unknown')} -> "
                    f"执行 {len(results)} 个模板, 发现 {vuln_count} 个漏洞"
                )
        except Exception as e:
            logger.error(f"指纹联动执行失败: {e}")

    async def on_oob_callback(self, callback_data: Dict[str, Any]):
        """反连平台回调处理

        当反连平台收到回连时，自动关联对应的Nuclei模板。

        Args:
            callback_data: 回连数据 (protocol, address, raw_data等)
        """
        if not self._integration_enabled:
            return

        protocol = callback_data.get("protocol", "")
        raw_data = callback_data.get("raw_data", "")

        logger.info(f"反连回调: protocol={protocol}, data_len={len(raw_data)}")

        if self._executor.event_bus:
            self._executor.event_bus.publish(
                event_type="nuclei_oob_callback",
                source="NucleiSystemIntegration",
                data={
                    "protocol": protocol,
                    "raw_data": raw_data,
                    "oob_address": self._executor.oob_address,
                },
            )

    def get_integration_status(self) -> Dict[str, Any]:
        """获取集成状态"""
        return {
            "enabled": self._integration_enabled,
            "oob_address": self._executor.oob_address,
            "proxy_queue_size": self._proxy_traffic_queue.qsize(),
            "fingerprint_cache_size": len(self._fingerprint_cache),
            "templates_loaded": self._executor.stats.total_templates,
            "executions": self._executor.execution_stats,
            "report_queue_size": len(self._report_results),
            "installed_packages": len(self._installed_packages),
        }

    async def add_to_report(self, result: NucleiVerifyResult):
        """将执行结果添加到报告队列

        执行结果自动汇入报告生成流程，支持批量导出。

        Args:
            result: Nuclei验证结果
        """
        async with self._report_lock:
            self._report_results.append(result)

    async def get_report_results(self, clear: bool = False) -> List[NucleiVerifyResult]:
        """获取报告结果列表

        Args:
            clear: 是否清空已获取的结果

        Returns:
            验证结果列表
        """
        async with self._report_lock:
            results = list(self._report_results)
            if clear:
                self._report_results.clear()
            return results

    async def export_report_data(self) -> Dict[str, Any]:
        """导出报告数据

        将累积的执行结果转换为报告模块可用的格式。

        Returns:
            报告数据字典
        """
        results = await self.get_report_results()
        vuln_count = sum(1 for r in results if r.vulnerable)

        return {
            "engine": "nuclei",
            "total_executed": len(results),
            "vulnerabilities_found": vuln_count,
            "by_severity": self._group_by_severity(results),
            "results": [r.model_dump() for r in results],
            "generated_at": datetime.now().isoformat(),
        }

    @staticmethod
    def _group_by_severity(results: List[NucleiVerifyResult]) -> Dict[str, int]:
        """按严重级别分组统计"""
        groups: Dict[str, int] = {}
        for r in results:
            if r.vulnerable:
                sev = r.severity or "info"
                groups[sev] = groups.get(sev, 0) + 1
        return groups

    def set_plugin_market_url(self, url: str):
        """设置插件市场URL

        Args:
            url: 插件市场API地址
        """
        self._plugin_market_url = url

    async def install_from_market(self, package_name: str) -> bool:
        """从插件市场安装模板包

        下载模板包并自动加载到模板引擎。

        Args:
            package_name: 模板包名称

        Returns:
            是否安装成功
        """
        if not self._plugin_market_url:
            logger.warning("未配置插件市场URL")
            return False

        try:
            download_url = f"{self._plugin_market_url.rstrip('/')}/packages/{package_name}/download"
            timeout = aiohttp.ClientTimeout(total=60)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(download_url) as resp:
                    if resp.status != 200:
                        logger.error(f"下载模板包失败: HTTP {resp.status}")
                        return False

                    content = await resp.read()

            with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
                tmp.write(content)
                tmp_path = tmp.name

            try:
                count = self._executor.loader.load_from_archive(tmp_path)
                if count > 0:
                    self._installed_packages[package_name] = {
                        "name": package_name,
                        "installed_at": datetime.now().isoformat(),
                        "template_count": count,
                    }
                    logger.info(f"从插件市场安装 {package_name}: {count} 个模板")
                    return True
            finally:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass

        except Exception as e:
            logger.error(f"插件市场安装失败: {e}")

        return False

    async def upload_to_market(self, template_path: str, package_name: str,
                                description: str = "") -> bool:
        """上传模板包到插件市场

        Args:
            template_path: 模板文件或目录路径
            package_name: 包名称
            description: 包描述

        Returns:
            是否上传成功
        """
        if not self._plugin_market_url:
            logger.warning("未配置插件市场URL")
            return False

        try:
            with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
                with zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED) as zf:
                    src_path = Path(template_path)
                    if src_path.is_file():
                        zf.write(src_path, src_path.name)
                    elif src_path.is_dir():
                        for f in src_path.rglob("*"):
                            if f.is_file():
                                zf.write(f, f.relative_to(src_path))
                tmp_path = tmp.name

            try:
                upload_url = f"{self._plugin_market_url.rstrip('/')}/packages/upload"
                data = aiohttp.FormData()
                data.add_field("name", package_name)
                data.add_field("description", description)
                data.add_field("file", open(tmp_path, "rb"), filename=f"{package_name}.zip")

                timeout = aiohttp.ClientTimeout(total=120)
                async with aiohttp.ClientSession(timeout=timeout) as session:
                    async with session.post(upload_url, data=data) as resp:
                        if resp.status in (200, 201):
                            logger.info(f"上传模板包成功: {package_name}")
                            return True
                        else:
                            logger.error(f"上传失败: HTTP {resp.status}")
            finally:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass

        except Exception as e:
            logger.error(f"插件市场上传失败: {e}")

        return False

    def get_installed_packages(self) -> Dict[str, Dict[str, Any]]:
        """获取已安装的模板包列表

        Returns:
            已安装包字典
        """
        return dict(self._installed_packages)

    async def close(self):
        """关闭集成，清理资源"""
        self._integration_enabled = False
        while not self._proxy_traffic_queue.empty():
            try:
                self._proxy_traffic_queue.get_nowait()
            except asyncio.QueueEmpty:
                break
        self._fingerprint_cache.clear()
