"""
被动扫描引擎 - 后台自动分析代理流量，实时发现Web漏洞和信息泄露

架构设计:
    PassiveScanner (主控)
    ├── PassiveRuleLoader (规则加载器)
    │   ├── YAML规则解析
    │   ├── Python自定义规则 (BasePassiveRule)
    │   ├── 规则热加载 (文件监控)
    │   └── 插件市场规则包安装
    ├── PassiveScanWorker (扫描Worker池)
    │   ├── asyncio有界任务队列
    │   ├── 协程池并发消费
    │   ├── 域名黑白名单过滤
    │   └── 静态资源黑名单跳过
    ├── PassiveRuleEngine (规则执行引擎)
    │   ├── 信息泄露检测 (IP/邮箱/密钥/JWT/注释/版本/DB串/Git)
    │   ├── 安全配置缺陷检测 (XFO/HSTS/CSP/XCTO/Cookie/CORS/TLS)
    │   └── 漏洞模式检测 (反射参数/SQL错误/堆栈/路径/备份/目录列表/调试接口/PHP探针)
    ├── PassiveDedupManager (智能去重管理器)
    │   ├── 内存LRU缓存
    │   ├── SQLite持久化
    │   └── 手动清除支持
    ├── PassiveResultExporter (结果导出器)
    │   ├── JSON导出
    │   └── HTML报告导出
    ├── PassiveNotificationManager (通知管理器)
    │   ├── 桌面通知 (高危发现)
    │   └── Webhook推送
    └── PassiveScannerIntegration (代理集成桥接)
        ├── 事件总线订阅
        ├── 请求/响应关联
        └── 界面联动接口
"""

import asyncio
import logging
import re
import os
import sys
import time
import json
import hashlib
import sqlite3
import threading
import itertools
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple, Set, Callable, Union, Type
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from collections import defaultdict, OrderedDict
from urllib.parse import urlparse, parse_qs

import yaml

from .result_models import PoCVerificationResult, ConfidenceLevel, SeverityLevel, PoCStatus

logger = logging.getLogger(__name__)

DEFAULT_MAX_QUEUE_SIZE = 5000
DEFAULT_MAX_WORKERS = 5
DEFAULT_MAX_BODY_SIZE = 512 * 1024
DEFAULT_DEDUP_DB_PATH = "data/passive_dedup.db"
DEFAULT_RULES_DIR = "data/rules/passive"


class PassiveSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class PassiveRuleCategory(str, Enum):
    INFO_LEAK = "信息泄露"
    SECURITY_CONFIG = "安全配置缺陷"
    VULN_PATTERN = "漏洞模式"
    CUSTOM = "自定义"


class FindingStatus(str, Enum):
    NEW = "new"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    IGNORED = "ignored"


@dataclass
class PassiveScanFinding:
    rule_id: str
    rule_name: str
    category: PassiveRuleCategory
    severity: PassiveSeverity
    url: str
    method: str
    evidence: str
    evidence_location: str
    request_headers: Dict[str, str] = field(default_factory=dict)
    response_headers: Dict[str, str] = field(default_factory=dict)
    request_body: str = ""
    response_body_snippet: str = ""
    status_code: int = 0
    timestamp: datetime = field(default_factory=datetime.now)
    host: str = ""
    path: str = ""
    matched_pattern: str = ""
    description: str = ""
    remediation: str = ""
    status: FindingStatus = FindingStatus.NEW
    finding_id: str = ""

    def __post_init__(self):
        if not self.finding_id:
            raw = f"{self.rule_id}:{self.url}:{self.evidence[:50]}:{self.timestamp.isoformat()}"
            self.finding_id = hashlib.md5(raw.encode()).hexdigest()[:12]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "category": self.category.value,
            "severity": self.severity.value,
            "url": self.url,
            "method": self.method,
            "evidence": self.evidence,
            "evidence_location": self.evidence_location,
            "status_code": self.status_code,
            "host": self.host,
            "path": self.path,
            "matched_pattern": self.matched_pattern,
            "description": self.description,
            "remediation": self.remediation,
            "status": self.status.value,
            "timestamp": self.timestamp.isoformat(),
        }

    def get_evidence_context(self, context_lines: int = 2) -> str:
        if not self.evidence or not self.response_body_snippet:
            return self.evidence
        lines = self.response_body_snippet.split("\n")
        for i, line in enumerate(lines):
            if self.evidence in line:
                start = max(0, i - context_lines)
                end = min(len(lines), i + context_lines + 1)
                return "\n".join(lines[start:end])
        return self.evidence


@dataclass
class PassiveRule:
    id: str
    name: str
    category: PassiveRuleCategory
    severity: PassiveSeverity
    description: str = ""
    remediation: str = ""
    enabled: bool = True
    scope_domains: List[str] = field(default_factory=list)
    scope_paths: List[str] = field(default_factory=list)
    scope_status_codes: List[int] = field(default_factory=list)
    exclude_domains: List[str] = field(default_factory=list)
    exclude_paths: List[str] = field(default_factory=list)
    matchers: List[Dict[str, Any]] = field(default_factory=list)
    matchers_condition: str = "or"
    python_handler: Optional[str] = None
    source_file: str = ""
    source_type: str = "builtin"
    version: str = "1.0"
    author: str = ""


class BasePassiveRule(ABC):
    """被动扫描规则抽象基类

    自定义Python规则需继承此类并实现 check() 方法。
    支持从插件市场安装社区规则包。
    """

    RULE_ID: str = ""
    RULE_NAME: str = ""
    RULE_CATEGORY: str = "自定义"
    RULE_SEVERITY: str = "info"
    RULE_DESCRIPTION: str = ""
    RULE_REMEDIATION: str = ""
    RULE_ENABLED: bool = True
    RULE_VERSION: str = "1.0"
    RULE_AUTHOR: str = ""

    @abstractmethod
    def check(self, task_data: Dict[str, Any]) -> Optional[PassiveScanFinding]:
        ...

    def to_passive_rule(self, source_file: str = "") -> PassiveRule:
        return PassiveRule(
            id=self.RULE_ID,
            name=self.RULE_NAME,
            category=PassiveRuleCategory(self.RULE_CATEGORY),
            severity=PassiveSeverity(self.RULE_SEVERITY),
            description=self.RULE_DESCRIPTION,
            remediation=self.RULE_REMEDIATION,
            enabled=self.RULE_ENABLED,
            python_handler=f"custom_{self.RULE_ID}",
            source_file=source_file,
            source_type="python",
            version=self.RULE_VERSION,
            author=self.RULE_AUTHOR,
        )


class PassiveDedupManager:
    """智能去重管理器 - 内存LRU + SQLite持久化"""

    def __init__(self, db_path: str = DEFAULT_DEDUP_DB_PATH, memory_cache_size: int = 10000):
        self._db_path = db_path
        self._memory_cache_size = memory_cache_size
        self._memory_cache: OrderedDict[str, Set[str]] = OrderedDict()
        self._db_conn: Optional[sqlite3.Connection] = None
        self._lock = threading.Lock()
        self._init_db()

    def _init_db(self):
        os.makedirs(os.path.dirname(self._db_path) or ".", exist_ok=True)
        self._db_conn = sqlite3.connect(self._db_path, check_same_thread=False)
        self._db_conn.execute("""
            CREATE TABLE IF NOT EXISTS dedup_records (
                dedup_key TEXT NOT NULL,
                evidence_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (dedup_key, evidence_hash)
            )
        """)
        self._db_conn.execute("CREATE INDEX IF NOT EXISTS idx_dedup_key ON dedup_records(dedup_key)")
        self._db_conn.commit()

    def is_duplicate(self, rule_id: str, url: str, evidence: str) -> bool:
        dedup_key = f"{rule_id}:{url}"
        evidence_hash = hashlib.md5(evidence[:200].encode()).hexdigest()

        with self._lock:
            if dedup_key in self._memory_cache:
                if evidence_hash in self._memory_cache[dedup_key]:
                    return True
            else:
                exists = self._check_db(dedup_key, evidence_hash)
                if exists:
                    self._add_to_memory(dedup_key, evidence_hash)
                    return True

            self._add_to_memory(dedup_key, evidence_hash)
            self._save_to_db(dedup_key, evidence_hash)
            return False

    def _add_to_memory(self, dedup_key: str, evidence_hash: str):
        if dedup_key not in self._memory_cache:
            self._memory_cache[dedup_key] = set()
            while len(self._memory_cache) > self._memory_cache_size:
                self._memory_cache.popitem(last=False)
        self._memory_cache[dedup_key].add(evidence_hash)

    def _check_db(self, dedup_key: str, evidence_hash: str) -> bool:
        try:
            cursor = self._db_conn.execute(
                "SELECT 1 FROM dedup_records WHERE dedup_key = ? AND evidence_hash = ?",
                (dedup_key, evidence_hash),
            )
            return cursor.fetchone() is not None
        except Exception:
            return False

    def _save_to_db(self, dedup_key: str, evidence_hash: str):
        try:
            self._db_conn.execute(
                "INSERT OR IGNORE INTO dedup_records (dedup_key, evidence_hash) VALUES (?, ?)",
                (dedup_key, evidence_hash),
            )
            self._db_conn.commit()
        except Exception as e:
            logger.debug(f"去重记录写入失败: {e}")

    def clear_all(self):
        with self._lock:
            self._memory_cache.clear()
            try:
                self._db_conn.execute("DELETE FROM dedup_records")
                self._db_conn.commit()
            except Exception as e:
                logger.error(f"清除去重记录失败: {e}")
        logger.info("已清除所有去重记录")

    def clear_by_rule(self, rule_id: str):
        with self._lock:
            keys_to_remove = [k for k in self._memory_cache if k.startswith(f"{rule_id}:")]
            for k in keys_to_remove:
                del self._memory_cache[k]
            try:
                self._db_conn.execute("DELETE FROM dedup_records WHERE dedup_key LIKE ?", (f"{rule_id}:%",))
                self._db_conn.commit()
            except Exception as e:
                logger.error(f"清除规则去重记录失败: {e}")

    def clear_by_url(self, url: str):
        with self._lock:
            keys_to_remove = [k for k in self._memory_cache if k.endswith(f":{url}")]
            for k in keys_to_remove:
                del self._memory_cache[k]
            try:
                self._db_conn.execute("DELETE FROM dedup_records WHERE dedup_key LIKE ?", (f"%:{url}",))
                self._db_conn.commit()
            except Exception as e:
                logger.error(f"清除URL去重记录失败: {e}")

    def get_stats(self) -> Dict[str, int]:
        with self._lock:
            memory_count = sum(len(v) for v in self._memory_cache.values())
            try:
                cursor = self._db_conn.execute("SELECT COUNT(*) FROM dedup_records")
                db_count = cursor.fetchone()[0]
            except Exception:
                db_count = 0
        return {"memory_entries": memory_count, "db_entries": db_count}

    def close(self):
        if self._db_conn:
            self._db_conn.close()


class PassiveRuleLoader:
    """被动检测规则加载器 - YAML/Python规则、热加载、插件市场"""

    def __init__(self, rules_dir: Optional[str] = None):
        self._rules_dir = Path(rules_dir) if rules_dir else None
        self._rules: Dict[str, PassiveRule] = {}
        self._python_handlers: Dict[str, Callable] = {}
        self._python_instances: Dict[str, BasePassiveRule] = {}
        self._file_mtimes: Dict[str, float] = {}
        self._watch_task: Optional[asyncio.Task] = None

    @property
    def rules(self) -> Dict[str, PassiveRule]:
        return self._rules

    @property
    def python_handlers(self) -> Dict[str, Callable]:
        return self._python_handlers

    @property
    def python_instances(self) -> Dict[str, BasePassiveRule]:
        return self._python_instances

    def load_from_directory(self, directory: str) -> int:
        dir_path = Path(directory)
        if not dir_path.exists():
            logger.warning(f"规则目录不存在: {directory}")
            return 0

        loaded = 0
        for file_path in dir_path.glob("*.yaml"):
            if self._load_yaml_rule(file_path):
                loaded += 1
        for file_path in dir_path.glob("*.yml"):
            if self._load_yaml_rule(file_path):
                loaded += 1
        for file_path in dir_path.glob("*.py"):
            if not file_path.name.startswith("_"):
                if self._load_python_rule(file_path):
                    loaded += 1

        logger.info(f"从目录加载了 {loaded} 个被动检测规则")
        return loaded

    def _load_yaml_rule(self, file_path: Path) -> bool:
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)

            if not data or not isinstance(data, dict):
                return False

            info = data.get("info", {})
            scope = data.get("scope", {})

            rule = PassiveRule(
                id=data.get("id", file_path.stem),
                name=info.get("name", file_path.stem),
                category=PassiveRuleCategory(info.get("category", "自定义")),
                severity=PassiveSeverity(info.get("severity", "info")),
                description=info.get("description", ""),
                remediation=info.get("remediation", ""),
                enabled=data.get("enabled", True),
                scope_domains=scope.get("domains", []),
                scope_paths=scope.get("paths", []),
                scope_status_codes=scope.get("status_codes", []),
                exclude_domains=scope.get("exclude_domains", []),
                exclude_paths=scope.get("exclude_paths", []),
                matchers=data.get("matchers", []),
                matchers_condition=data.get("matchers_condition", "or"),
                source_file=str(file_path),
                source_type="yaml",
                version=info.get("version", "1.0"),
                author=info.get("author", ""),
            )

            self._rules[rule.id] = rule
            self._file_mtimes[str(file_path)] = file_path.stat().st_mtime
            logger.debug(f"加载YAML规则: {rule.id} - {rule.name}")
            return True

        except Exception as e:
            logger.warning(f"YAML规则加载失败 {file_path}: {e}")
            return False

    def _load_python_rule(self, file_path: Path) -> bool:
        try:
            import importlib.util
            spec = importlib.util.spec_from_file_location(
                f"passive_rule_{file_path.stem}", file_path
            )
            if spec is None or spec.loader is None:
                return False
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)

            rule_instance = None
            for attr_name in dir(module):
                attr = getattr(module, attr_name)
                if (isinstance(attr, type) and
                        issubclass(attr, BasePassiveRule) and
                        attr is not BasePassiveRule):
                    rule_instance = attr()
                    break

            if rule_instance is not None:
                rule = rule_instance.to_passive_rule(str(file_path))
                self._rules[rule.id] = rule
                self._python_handlers[rule.python_handler] = rule_instance.check
                self._python_instances[rule.python_handler] = rule_instance
                self._file_mtimes[str(file_path)] = file_path.stat().st_mtime
                logger.debug(f"加载Python规则: {rule.id}")
                return True

            if hasattr(module, "RULE_ID") and hasattr(module, "check"):
                rule = PassiveRule(
                    id=getattr(module, "RULE_ID", file_path.stem),
                    name=getattr(module, "RULE_NAME", file_path.stem),
                    category=PassiveRuleCategory(getattr(module, "RULE_CATEGORY", "自定义")),
                    severity=PassiveSeverity(getattr(module, "RULE_SEVERITY", "info")),
                    description=getattr(module, "RULE_DESCRIPTION", ""),
                    remediation=getattr(module, "RULE_REMEDIATION", ""),
                    enabled=getattr(module, "RULE_ENABLED", True),
                    python_handler=f"passive_rule_{file_path.stem}",
                    source_file=str(file_path),
                    source_type="python",
                )
                self._rules[rule.id] = rule
                self._python_handlers[rule.python_handler] = module.check
                self._file_mtimes[str(file_path)] = file_path.stat().st_mtime
                logger.debug(f"加载Python规则: {rule.id}")
                return True

        except Exception as e:
            logger.warning(f"Python规则加载失败 {file_path}: {e}")
            return False

    def hot_reload(self) -> int:
        reloaded = 0
        for file_path_str, old_mtime in list(self._file_mtimes.items()):
            file_path = Path(file_path_str)
            if not file_path.exists():
                continue
            new_mtime = file_path.stat().st_mtime
            if new_mtime > old_mtime:
                for rule in list(self._rules.values()):
                    if rule.source_file == file_path_str:
                        del self._rules[rule.id]
                        if rule.python_handler:
                            self._python_handlers.pop(rule.python_handler, None)
                            self._python_instances.pop(rule.python_handler, None)
                if file_path.suffix in (".yaml", ".yml"):
                    if self._load_yaml_rule(file_path):
                        reloaded += 1
                elif file_path.suffix == ".py":
                    if self._load_python_rule(file_path):
                        reloaded += 1

        if reloaded > 0:
            logger.info(f"热加载了 {reloaded} 个规则")
        return reloaded

    async def start_hot_reload_watcher(self, interval: float = 5.0):
        async def _watcher():
            while True:
                await asyncio.sleep(interval)
                try:
                    self.hot_reload()
                except Exception as e:
                    logger.debug(f"热加载检查异常: {e}")

        self._watch_task = asyncio.create_task(_watcher())
        logger.info(f"规则热加载监控已启动，间隔 {interval}s")

    async def stop_hot_reload_watcher(self):
        if self._watch_task:
            self._watch_task.cancel()
            try:
                await self._watch_task
            except asyncio.CancelledError:
                pass
            self._watch_task = None

    def install_from_plugin_market(self, rule_package: Dict[str, Any]) -> bool:
        try:
            rules_data = rule_package.get("rules", [])
            installed = 0
            for rule_data in rules_data:
                rule = PassiveRule(
                    id=rule_data.get("id", ""),
                    name=rule_data.get("name", ""),
                    category=PassiveRuleCategory(rule_data.get("category", "自定义")),
                    severity=PassiveSeverity(rule_data.get("severity", "info")),
                    description=rule_data.get("description", ""),
                    remediation=rule_data.get("remediation", ""),
                    enabled=True,
                    matchers=rule_data.get("matchers", []),
                    matchers_condition=rule_data.get("matchers_condition", "or"),
                    source_type="marketplace",
                    version=rule_data.get("version", "1.0"),
                    author=rule_data.get("author", ""),
                )
                self._rules[rule.id] = rule
                installed += 1

            logger.info(f"从插件市场安装了 {installed} 个规则")
            return True
        except Exception as e:
            logger.error(f"插件市场规则安装失败: {e}")
            return False

    def get_enabled_rules(self) -> List[PassiveRule]:
        return [r for r in self._rules.values() if r.enabled]

    def get_rules_by_category(self, category: PassiveRuleCategory) -> List[PassiveRule]:
        return [r for r in self._rules.values() if r.category == category and r.enabled]

    def enable_rule(self, rule_id: str):
        if rule_id in self._rules:
            self._rules[rule_id].enabled = True

    def disable_rule(self, rule_id: str):
        if rule_id in self._rules:
            self._rules[rule_id].enabled = False

    def enable_category(self, category: PassiveRuleCategory):
        for rule in self._rules.values():
            if rule.category == category:
                rule.enabled = True

    def disable_category(self, category: PassiveRuleCategory):
        for rule in self._rules.values():
            if rule.category == category:
                rule.enabled = False

    def get_rule(self, rule_id: str) -> Optional[PassiveRule]:
        return self._rules.get(rule_id)

    def search_rules(self, keyword: str) -> List[PassiveRule]:
        kw = keyword.lower()
        return [
            r for r in self._rules.values()
            if kw in r.id.lower() or kw in r.name.lower() or kw in r.description.lower()
        ]


class PassiveRuleEngine:
    """被动规则执行引擎 - 内置36条检测规则"""

    def __init__(self):
        self._builtin_rules = self._create_builtin_rules()

    def _create_builtin_rules(self) -> List[PassiveRule]:
        rules: List[PassiveRule] = []
        rules.extend(self._create_info_leak_rules())
        rules.extend(self._create_security_config_rules())
        rules.extend(self._create_vuln_pattern_rules())
        return rules

    def _create_info_leak_rules(self) -> List[PassiveRule]:
        return [
            PassiveRule(
                id="passive-info-internal-ip",
                name="响应中包含内网IP地址",
                category=PassiveRuleCategory.INFO_LEAK,
                severity=PassiveSeverity.MEDIUM,
                description="响应体中包含内网IP地址（10.x/172.16.x/192.168.x），可能导致内部网络拓扑泄露",
                remediation="移除响应中的内网IP地址，使用域名或公网地址替代",
                matchers=[{"type": "regex", "part": "body", "patterns": [
                    r'\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
                    r'\b172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}\b',
                    r'\b192\.168\.\d{1,3}\.\d{1,3}\b',
                ]}],
            ),
            PassiveRule(
                id="passive-info-email-leak",
                name="响应中包含邮箱地址",
                category=PassiveRuleCategory.INFO_LEAK,
                severity=PassiveSeverity.LOW,
                description="响应体或响应头中包含邮箱地址，可能被爬虫收集用于钓鱼或垃圾邮件",
                remediation="避免在公开页面中直接暴露邮箱地址，使用联系表单替代",
                matchers=[{"type": "regex", "part": "all", "patterns": [
                    r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
                ]}],
            ),
            PassiveRule(
                id="passive-info-cloud-key",
                name="疑似云服务密钥泄露",
                category=PassiveRuleCategory.INFO_LEAK,
                severity=PassiveSeverity.HIGH,
                description="响应体中包含疑似AWS/Azure/GCP/阿里云/腾讯云/GitHub密钥模式",
                remediation="立即轮换泄露的密钥，确保密钥不通过前端代码或API响应暴露",
                matchers=[{"type": "regex", "part": "body", "patterns": [
                    r'AKIA[0-9A-Z]{16}',
                    r'AIza[0-9A-Za-z\-_]{35}',
                    r'eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+',
                    r'LTAI[A-Za-z0-9]{12,20}',
                    r'AKID[A-Za-z0-9]{13,40}',
                    r'sk-[a-zA-Z0-9]{32,}',
                    r'github_pat_[a-zA-Z0-9_]{36,}',
                    r'ghp_[a-zA-Z0-9]{36,}',
                    r'glpat-[a-zA-Z0-9\-_]{20,}',
                ]}],
            ),
            PassiveRule(
                id="passive-info-server-version",
                name="响应头泄露服务器版本信息",
                category=PassiveRuleCategory.INFO_LEAK,
                severity=PassiveSeverity.LOW,
                description="响应头中包含Server/X-Powered-By/X-AspNet-Version等版本信息",
                remediation="配置Web服务器隐藏或修改版本信息，如nginx的server_tokens off",
                matchers=[{"type": "regex", "part": "header", "patterns": [
                    r'Server:.*(Apache|nginx|IIS|Tomcat|Jetty|Caddy|LiteSpeed|OpenResty)[/\s]*[\d.]+',
                    r'X-Powered-By:.*(PHP|ASP\.NET|Express|Next\.js)[/\s]*[\d.]+',
                    r'X-AspNet-Version:[\s]*[\d.]+',
                    r'X-Generator:[\s]*[\w.]+',
                ]}],
            ),
            PassiveRule(
                id="passive-info-html-comment",
                name="HTML注释包含敏感关键词",
                category=PassiveRuleCategory.INFO_LEAK,
                severity=PassiveSeverity.LOW,
                description="HTML注释中包含TODO/FIXME/password/secret等敏感关键词",
                remediation="清理HTML注释中的敏感信息，避免在注释中留下开发调试信息",
                matchers=[{"type": "regex", "part": "body", "patterns": [
                    r'<!--.*?(TODO|FIXME|password|secret|token|key|api_key|credential|passwd).*?-->',
                ]}],
            ),
            PassiveRule(
                id="passive-info-jwt-leak",
                name="JWT Token明文传输风险",
                category=PassiveRuleCategory.INFO_LEAK,
                severity=PassiveSeverity.MEDIUM,
                description="JWT Token在响应体或响应头中明文传输，需检查算法安全性",
                remediation="确保JWT使用强加密算法（RS256/ES256），密钥长度至少256位",
                matchers=[{"type": "regex", "part": "all", "patterns": [
                    r'eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.',
                ]}],
            ),
            PassiveRule(
                id="passive-info-db-connection",
                name="疑似数据库连接串泄露",
                category=PassiveRuleCategory.INFO_LEAK,
                severity=PassiveSeverity.HIGH,
                description="响应体中包含数据库连接字符串（MySQL/PostgreSQL/MongoDB/Redis/SQLite路径）",
                remediation="立即移除硬编码的数据库连接串，使用环境变量或配置中心管理",
                matchers=[{"type": "regex", "part": "body", "patterns": [
                    r'(jdbc:|mongodb://|mysql://|postgresql://|postgres://|redis://|sqlite://)[^\s"\'<>]+',
                    r'DATABASE_URL[=:]\s*["\']?[^\s"\']+',
                    r'DB_CONNECTION[=:]\s*["\']?[^\s"\']+',
                    r'connectionString[=:]\s*["\']?[^\s"\']+',
                ]}],
            ),
            PassiveRule(
                id="passive-info-git-leak",
                name="疑似Git仓库地址泄露",
                category=PassiveRuleCategory.INFO_LEAK,
                severity=PassiveSeverity.MEDIUM,
                description="响应体中包含.git路径或Git仓库地址，可能泄露源码仓库信息",
                remediation="确保.git目录不可通过Web访问，移除响应中的Git仓库地址",
                matchers=[{"type": "regex", "part": "body", "patterns": [
                    r'(git@|https://|git://)[^\s"\'<>]*\.git',
                    r'github\.com/[^\s"\'<>/]+/[^\s"\'<>/]+',
                    r'gitlab\.[^\s"\'<>/]+/[^\s"\'<>/]+/[^\s"\'<>/]+',
                ]}],
            ),
            PassiveRule(
                id="passive-info-phone-number",
                name="响应中包含手机号码",
                category=PassiveRuleCategory.INFO_LEAK,
                severity=PassiveSeverity.LOW,
                description="响应体中包含中国大陆手机号码格式",
                remediation="避免在公开页面中暴露个人手机号码",
                matchers=[{"type": "regex", "part": "body", "patterns": [r'1[3-9]\d{9}']}],
            ),
            PassiveRule(
                id="passive-info-id-card",
                name="响应中包含身份证号码",
                category=PassiveRuleCategory.INFO_LEAK,
                severity=PassiveSeverity.HIGH,
                description="响应体中包含中国大陆身份证号码格式",
                remediation="立即移除响应中的身份证号码，对敏感数据进行脱敏处理",
                matchers=[{"type": "regex", "part": "body", "patterns": [
                    r'[1-9]\d{5}(19|20)\d{2}(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])\d{3}[\dXx]',
                ]}],
            ),
            PassiveRule(
                id="passive-info-sourcemap",
                name="SourceMap文件泄露",
                category=PassiveRuleCategory.INFO_LEAK,
                severity=PassiveSeverity.MEDIUM,
                description="响应中包含sourceMappingURL，前端源码可能通过.map文件泄露",
                remediation="生产环境部署时移除SourceMap文件或限制访问",
                matchers=[{"type": "regex", "part": "body", "patterns": [
                    r'sourceMappingURL=[^\s"\']+\.map',
                    r'//# sourceMappingURL=',
                ]}],
            ),
            PassiveRule(
                id="passive-info-sensitive-file",
                name="敏感文件路径泄露",
                category=PassiveRuleCategory.INFO_LEAK,
                severity=PassiveSeverity.MEDIUM,
                description="响应体中包含敏感配置文件路径（.env/web.config/application.properties等）",
                remediation="确保敏感配置文件不可通过Web访问",
                matchers=[{"type": "regex", "part": "body", "patterns": [
                    r'(\.env|web\.config|application\.properties|settings\.py|config\.yml|\.htaccess)',
                ]}],
            ),
        ]

    def _create_security_config_rules(self) -> List[PassiveRule]:
        return [
            PassiveRule(
                id="passive-config-xfo-missing",
                name="缺少X-Frame-Options头（点击劫持风险）",
                category=PassiveRuleCategory.SECURITY_CONFIG,
                severity=PassiveSeverity.MEDIUM,
                description="响应缺少X-Frame-Options头，存在点击劫持（Clickjacking）风险",
                remediation="添加X-Frame-Options: DENY或SAMEORIGIN响应头",
                matchers=[{"type": "word", "part": "header", "words": ["X-Frame-Options"], "negative": True}],
            ),
            PassiveRule(
                id="passive-config-xcto-missing",
                name="缺少X-Content-Type-Options头",
                category=PassiveRuleCategory.SECURITY_CONFIG,
                severity=PassiveSeverity.LOW,
                description="响应缺少X-Content-Type-Options: nosniff头，存在MIME嗅探风险",
                remediation="添加X-Content-Type-Options: nosniff响应头",
                matchers=[{"type": "word", "part": "header", "words": ["X-Content-Type-Options"], "negative": True}],
            ),
            PassiveRule(
                id="passive-config-csp-missing",
                name="缺少Content-Security-Policy头",
                category=PassiveRuleCategory.SECURITY_CONFIG,
                severity=PassiveSeverity.LOW,
                description="响应缺少Content-Security-Policy头，无法防御XSS和数据注入攻击",
                remediation="配置合理的Content-Security-Policy策略",
                matchers=[{"type": "word", "part": "header", "words": ["Content-Security-Policy"], "negative": True}],
            ),
            PassiveRule(
                id="passive-config-hsts-missing",
                name="缺少Strict-Transport-Security头（HSTS缺失）",
                category=PassiveRuleCategory.SECURITY_CONFIG,
                severity=PassiveSeverity.MEDIUM,
                description="HTTPS响应缺少Strict-Transport-Security头，存在SSL剥离攻击风险",
                remediation="添加Strict-Transport-Security: max-age=31536000; includeSubDomains响应头",
                matchers=[{"type": "word", "part": "header", "words": ["Strict-Transport-Security"], "negative": True}],
            ),
            PassiveRule(
                id="passive-config-referrer-policy",
                name="缺少Referrer-Policy头",
                category=PassiveRuleCategory.SECURITY_CONFIG,
                severity=PassiveSeverity.LOW,
                description="响应缺少Referrer-Policy头，可能通过Referer头泄露敏感URL信息",
                remediation="添加Referrer-Policy: strict-origin-when-cross-origin响应头",
                matchers=[{"type": "word", "part": "header", "words": ["Referrer-Policy"], "negative": True}],
            ),
            PassiveRule(
                id="passive-config-permissions-policy",
                name="缺少Permissions-Policy头",
                category=PassiveRuleCategory.SECURITY_CONFIG,
                severity=PassiveSeverity.LOW,
                description="响应缺少Permissions-Policy头，无法限制浏览器API使用",
                remediation="配置合理的Permissions-Policy策略",
                matchers=[{"type": "word", "part": "header", "words": ["Permissions-Policy"], "negative": True}],
            ),
            PassiveRule(
                id="passive-config-cookie-flags",
                name="Cookie缺少HttpOnly/Secure/SameSite标志",
                category=PassiveRuleCategory.SECURITY_CONFIG,
                severity=PassiveSeverity.MEDIUM,
                description="Set-Cookie未设置HttpOnly/Secure/SameSite标志",
                remediation="为所有Cookie添加HttpOnly; Secure; SameSite=Lax属性",
                matchers=[{"type": "regex", "part": "header", "patterns": [
                    r'Set-Cookie:(?:(?!HttpOnly).)*$',
                    r'Set-Cookie:(?:(?!Secure).)*$',
                    r'Set-Cookie:(?:(?!SameSite).)*$',
                ]}],
            ),
            PassiveRule(
                id="passive-config-cors-wildcard",
                name="CORS配置过于宽松",
                category=PassiveRuleCategory.SECURITY_CONFIG,
                severity=PassiveSeverity.MEDIUM,
                description="Access-Control-Allow-Origin设置为*，允许任意域跨域访问",
                remediation="将Access-Control-Allow-Origin限制为受信任的域名",
                matchers=[{"type": "word", "part": "header", "words": ["Access-Control-Allow-Origin: *"]}],
            ),
            PassiveRule(
                id="passive-config-cors-credentials-wildcard",
                name="CORS配置危险（Origin为*且Credentials为true）",
                category=PassiveRuleCategory.SECURITY_CONFIG,
                severity=PassiveSeverity.HIGH,
                description="Access-Control-Allow-Origin为*且Access-Control-Allow-Credentials为true，这是危险配置",
                remediation="不能同时使用Origin:*和Credentials:true，需指定具体域名",
                matchers=[{
                    "type": "word", "part": "header",
                    "words": ["Access-Control-Allow-Origin: *", "Access-Control-Allow-Credentials: true"],
                    "match_all": True,
                }],
            ),
            PassiveRule(
                id="passive-config-cache-control",
                name="响应缺少Cache-Control头（敏感页面可被缓存）",
                category=PassiveRuleCategory.SECURITY_CONFIG,
                severity=PassiveSeverity.LOW,
                description="包含敏感信息的响应缺少Cache-Control头，可能被中间代理缓存",
                remediation="为敏感页面添加Cache-Control: no-store, no-cache, must-revalidate响应头",
                matchers=[{"type": "word", "part": "header", "words": ["Cache-Control"], "negative": True}],
            ),
        ]

    def _create_vuln_pattern_rules(self) -> List[PassiveRule]:
        return [
            PassiveRule(
                id="passive-vuln-sql-error",
                name="SQL错误消息暴露",
                category=PassiveRuleCategory.VULN_PATTERN,
                severity=PassiveSeverity.HIGH,
                description="响应体中包含SQL错误消息，可能存在SQL注入漏洞或错误配置",
                remediation="配置自定义错误页面，避免将数据库错误信息返回给客户端",
                matchers=[{"type": "regex", "part": "body", "patterns": [
                    r'SQL syntax.*MySQL',
                    r'Warning.*mysql_fetch',
                    r'ORA-\d{5}',
                    r'PostgreSQL.*ERROR',
                    r'SQLite.*error',
                    r'Microsoft OLE DB.*error',
                    r'ODBC Driver.*error',
                    r'Unclosed quotation mark',
                    r'SQL command not properly ended',
                    r'You have an error in your SQL syntax',
                    r'valid MySQL result',
                    r'Microsoft SQL Server.*error',
                ]}],
            ),
            PassiveRule(
                id="passive-vuln-stack-trace",
                name="堆栈跟踪信息泄露",
                category=PassiveRuleCategory.VULN_PATTERN,
                severity=PassiveSeverity.MEDIUM,
                description="响应体中包含堆栈跟踪信息，可能泄露代码路径和逻辑",
                remediation="在生产环境关闭调试模式，配置自定义错误页面",
                matchers=[{"type": "regex", "part": "body", "patterns": [
                    r'Stack trace:',
                    r'Exception in',
                    r'Traceback \(most recent call last\)',
                    r'at \w+\.\w+\([\w.]+:\d+\)',
                    r'File "[\w/\.]+", line \d+',
                    r'\.NET Framework.*error',
                    r'System\.\w+\.\w+Exception',
                    r'java\.\w+\.\w+Exception',
                    r'at org\.\w+\.\w+\.\w+\([\w.]+:\d+\)',
                ]}],
            ),
            PassiveRule(
                id="passive-vuln-path-disclosure",
                name="服务器路径泄露",
                category=PassiveRuleCategory.VULN_PATTERN,
                severity=PassiveSeverity.MEDIUM,
                description="响应体中包含服务器绝对路径，可能泄露服务器目录结构",
                remediation="配置Web服务器隐藏文件路径，使用URL重写",
                matchers=[{"type": "regex", "part": "body", "patterns": [
                    r'/var/www/[\w/]+',
                    r'C:\\inetpub\\[\w\\]+',
                    r'/home/\w+/public_html',
                    r'WEB-INF/web\.xml',
                    r'/usr/local/[\w/]+',
                    r'/opt/[\w/]+',
                    r'/etc/[\w/]+',
                ]}],
            ),
            PassiveRule(
                id="passive-vuln-backup-file",
                name="备份文件泄露",
                category=PassiveRuleCategory.VULN_PATTERN,
                severity=PassiveSeverity.HIGH,
                description="请求路径以备份文件扩展名结尾且返回200，可能存在备份文件泄露",
                remediation="将备份文件移出Web目录，或配置Web服务器禁止访问备份文件",
                matchers=[{"type": "regex", "part": "body", "patterns": [
                    r'\.bak$', r'\.zip$', r'\.tar\.gz$', r'\.sql$',
                    r'\.old$', r'\.backup$', r'\.swp$', r'~$',
                    r'\.7z$', r'\.rar$', r'\.tar$', r'\.gz$',
                ]}],
            ),
            PassiveRule(
                id="passive-vuln-directory-listing",
                name="目录列表暴露",
                category=PassiveRuleCategory.VULN_PATTERN,
                severity=PassiveSeverity.MEDIUM,
                description="响应体包含目录列表，可能暴露敏感文件",
                remediation="在Web服务器配置中禁用目录列表功能",
                matchers=[{"type": "regex", "part": "body", "patterns": [
                    r'<title>Index of /[\w/]*</title>',
                    r'<h1>Index of /[\w/]*</h1>',
                    r'<a href="[^"]+">[^<]+</a>\s*\d{2}-[A-Z][a-z]{2}-\d{4}',
                    r'Directory Listing For',
                    r'\[To Parent Directory\]',
                ]}],
            ),
            PassiveRule(
                id="passive-vuln-php-info",
                name="PHP信息泄露（phpinfo）",
                category=PassiveRuleCategory.VULN_PATTERN,
                severity=PassiveSeverity.HIGH,
                description="响应体包含phpinfo()输出，泄露PHP配置详情",
                remediation="立即删除phpinfo()调用，禁止在生产环境暴露PHP配置",
                matchers=[{"type": "regex", "part": "body", "patterns": [
                    r'<title>phpinfo\(\)</title>',
                    r'PHP Version [\d.]+</td>',
                    r'<h1 class="p">PHP Version [\d.]+</h1>',
                ]}],
            ),
            PassiveRule(
                id="passive-vuln-debug-mode",
                name="调试模式开启",
                category=PassiveRuleCategory.VULN_PATTERN,
                severity=PassiveSeverity.HIGH,
                description="检测到应用调试模式开启，可能泄露敏感调试信息",
                remediation="在生产环境关闭所有调试模式和详细错误输出",
                matchers=[{"type": "regex", "part": "body", "patterns": [
                    r'Django DEBUG = True',
                    r'Whoops! There was an error',
                    r'laravel-debugbar',
                    r'Symfony Web Debug Toolbar',
                    r'<!-- DEBUG MODE -->',
                    r'debug\.log',
                    r'APP_DEBUG=true',
                    r'APP_ENV=local',
                ]}],
            ),
            PassiveRule(
                id="passive-vuln-actuator-exposed",
                name="Spring Boot Actuator调试接口暴露",
                category=PassiveRuleCategory.VULN_PATTERN,
                severity=PassiveSeverity.HIGH,
                description="检测到Spring Boot Actuator端点暴露，可能泄露应用内部信息",
                remediation="配置Spring Security限制Actuator端点访问",
                matchers=[{"type": "regex", "part": "body", "patterns": [
                    r'"_links":\s*\{',
                    r'"self":\s*\{',
                    r'/actuator/health',
                    r'/actuator/env',
                    r'/actuator/mappings',
                    r'/actuator/configprops',
                ]}],
            ),
            PassiveRule(
                id="passive-vuln-env-exposed",
                name=".env环境变量文件泄露",
                category=PassiveRuleCategory.VULN_PATTERN,
                severity=PassiveSeverity.CRITICAL,
                description="检测到.env文件内容泄露，包含数据库密码、API密钥等敏感配置",
                remediation="立即配置Web服务器禁止访问.env文件，轮换所有泄露的密钥和密码",
                matchers=[{"type": "regex", "part": "body", "patterns": [
                    r'^APP_KEY=',
                    r'^DB_PASSWORD=',
                    r'^MAIL_PASSWORD=',
                    r'^AWS_SECRET=',
                    r'^REDIS_PASSWORD=',
                    r'^JWT_SECRET=',
                ]}],
            ),
            PassiveRule(
                id="passive-vuln-php-probe",
                name="PHP探针文件泄露",
                category=PassiveRuleCategory.VULN_PATTERN,
                severity=PassiveSeverity.HIGH,
                description="检测到PHP探针文件（tz.php/i.php/prober.php等），可能泄露服务器信息",
                remediation="立即删除所有PHP探针文件，这些文件不应存在于生产环境",
                matchers=[{"type": "regex", "part": "body", "patterns": [
                    r'<title>.*?(phpinfo|探针|Prober|PHP Probe).*?</title>',
                    r'服务器时间.*?php',
                    r'PHP已编译模块检测',
                    r'探针.*?php',
                ]}],
            ),
            PassiveRule(
                id="passive-vuln-swagger-exposed",
                name="Swagger/OpenAPI文档暴露",
                category=PassiveRuleCategory.VULN_PATTERN,
                severity=PassiveSeverity.MEDIUM,
                description="检测到Swagger UI或OpenAPI文档暴露，可能泄露API接口信息",
                remediation="生产环境禁用Swagger UI，或添加访问认证",
                matchers=[{"type": "regex", "part": "body", "patterns": [
                    r'swagger.*?ui',
                    r'"swagger":\s*"[\d.]+"',
                    r'"openapi":\s*"[\d.]+"',
                    r'<title>Swagger UI</title>',
                ]}],
            ),
            PassiveRule(
                id="passive-vuln-graphql-introspection",
                name="GraphQL内省查询暴露",
                category=PassiveRuleCategory.VULN_PATTERN,
                severity=PassiveSeverity.MEDIUM,
                description="检测到GraphQL Schema信息暴露，可能泄露数据模型",
                remediation="生产环境禁用GraphQL内省查询（introspection: false）",
                matchers=[{"type": "regex", "part": "body", "patterns": [
                    r'"__schema":\s*\{',
                    r'"__type":\s*\{',
                    r'"name":\s*"(Query|Mutation|Subscription)"',
                ]}],
            ),
            PassiveRule(
                id="passive-vuln-error-message",
                name="详细错误消息暴露",
                category=PassiveRuleCategory.VULN_PATTERN,
                severity=PassiveSeverity.MEDIUM,
                description="响应体中包含详细错误消息，可能泄露系统内部信息",
                remediation="配置Web服务器使用通用错误页面，避免暴露详细错误信息",
                matchers=[{"type": "regex", "part": "body", "patterns": [
                    r'(Fatal error|Parse error|Warning|Notice):\s+.*in\s+[\w/\\\.]+',
                    r'ErrorException.*in\s+[\w/\\\.]+',
                    r'PDOException.*in\s+[\w/\\\.]+',
                ]}],
            ),
            PassiveRule(
                id="passive-vuln-crossdomain",
                name="crossdomain.xml过于宽松",
                category=PassiveRuleCategory.VULN_PATTERN,
                severity=PassiveSeverity.LOW,
                description="crossdomain.xml允许所有域访问，存在Flash跨域风险",
                remediation="限制crossdomain.xml中允许的域名，或删除该文件",
                matchers=[{"type": "regex", "part": "body", "patterns": [
                    r'<allow-access-from domain="\*"',
                    r'<site-control permitted-cross-domain-policies="all"',
                ]}],
            ),
        ]

    def get_builtin_rules(self) -> List[PassiveRule]:
        return self._builtin_rules

    def check_rule(self, rule: PassiveRule, url: str, method: str,
                   request_headers: Dict[str, str], request_body: str,
                   response_headers: Dict[str, str], response_body: str,
                   status_code: int) -> Optional[PassiveScanFinding]:
        if not self._check_scope(rule, url, status_code):
            return None

        if not rule.matchers:
            return None

        matcher_results = []
        for matcher in rule.matchers:
            result = self._execute_matcher(matcher, rule, url, method,
                                           request_headers, request_body,
                                           response_headers, response_body,
                                           status_code)
            matcher_results.append(result)

        if rule.matchers_condition == "and":
            matched = all(r is not None for r in matcher_results)
        else:
            matched = any(r is not None for r in matcher_results)

        if matched:
            for r in matcher_results:
                if r is not None:
                    return r

        return None

    def _check_scope(self, rule: PassiveRule, url: str, status_code: int) -> bool:
        parsed = urlparse(url)
        hostname = parsed.hostname or ""

        if rule.exclude_domains:
            if any(d.lower() in hostname.lower() for d in rule.exclude_domains):
                return False

        if rule.exclude_paths:
            if any(parsed.path.startswith(p) for p in rule.exclude_paths):
                return False

        if rule.scope_domains:
            if hostname not in rule.scope_domains:
                return False

        if rule.scope_paths:
            if not any(parsed.path.startswith(p) for p in rule.scope_paths):
                return False

        if rule.scope_status_codes:
            if status_code not in rule.scope_status_codes:
                return False

        return True

    def _execute_matcher(self, matcher: Dict[str, Any], rule: PassiveRule,
                         url: str, method: str,
                         request_headers: Dict[str, str], request_body: str,
                         response_headers: Dict[str, str], response_body: str,
                         status_code: int) -> Optional[PassiveScanFinding]:
        matcher_type = matcher.get("type", "word")
        part = matcher.get("part", "body")
        negative = matcher.get("negative", False)
        match_all = matcher.get("match_all", False)

        target_text = self._get_target_text(part, response_body, response_headers)

        matched = False
        evidence = ""
        matched_pattern = ""

        if matcher_type == "word":
            words = matcher.get("words", [])
            matched_words = []
            for word in words:
                if word in target_text:
                    matched_words.append(word)
            if match_all:
                matched = len(matched_words) == len(words)
            else:
                matched = len(matched_words) > 0
            if matched_words:
                evidence = matched_words[0]
                matched_pattern = ", ".join(matched_words)

        elif matcher_type == "regex":
            patterns = matcher.get("patterns", [])
            matched_patterns = []
            for pattern in patterns:
                try:
                    m = re.search(pattern, target_text, re.IGNORECASE | re.DOTALL)
                    if m:
                        matched_patterns.append(pattern)
                        if not evidence:
                            evidence = m.group(0)
                except re.error:
                    continue
            if match_all:
                matched = len(matched_patterns) == len(patterns)
            else:
                matched = len(matched_patterns) > 0
            if matched_patterns:
                matched_pattern = ", ".join(matched_patterns)

        elif matcher_type == "dsl":
            dsl_exprs = matcher.get("dsl", [])
            for expr in dsl_exprs:
                try:
                    safe_locals = {
                        "body": response_body,
                        "headers": response_headers,
                        "status_code": status_code,
                        "len": len,
                        "contains": lambda s, sub: sub in s,
                    }
                    result = eval(expr, {"__builtins__": {}}, safe_locals)
                    if result:
                        matched = True
                        evidence = expr
                        matched_pattern = expr
                        break
                except Exception:
                    continue

        if negative:
            matched = not matched
            if matched:
                evidence = f"未发现: {matcher.get('words', matcher.get('patterns', []))}"

        if matched:
            parsed = urlparse(url)
            return PassiveScanFinding(
                rule_id=rule.id,
                rule_name=rule.name,
                category=rule.category,
                severity=rule.severity,
                url=url,
                method=method,
                evidence=evidence[:500],
                evidence_location=part,
                request_headers=request_headers,
                response_headers=response_headers,
                request_body=request_body[:1000],
                response_body_snippet=response_body[:2000],
                status_code=status_code,
                host=parsed.hostname or "",
                path=parsed.path or "",
                matched_pattern=matched_pattern,
                description=rule.description,
                remediation=rule.remediation,
            )

        return None

    def _get_target_text(self, part: str, body: str, headers: Dict[str, str]) -> str:
        if part == "body":
            return body
        elif part == "header":
            return "\n".join(f"{k}: {v}" for k, v in headers.items())
        elif part == "firstline":
            return body.split("\n")[0] if body else ""
        elif part == "all":
            header_text = "\n".join(f"{k}: {v}" for k, v in headers.items())
            return f"{header_text}\n\n{body}"
        return body


class PassiveResultExporter:
    """结果导出器 - JSON和HTML格式"""

    @staticmethod
    def export_json(findings: List[PassiveScanFinding], pretty: bool = True) -> str:
        data = [f.to_dict() for f in findings]
        indent = 2 if pretty else None
        return json.dumps(data, ensure_ascii=False, indent=indent, default=str)

    @staticmethod
    def export_html(findings: List[PassiveScanFinding], title: str = "昆仑被动扫描报告") -> str:
        severity_colors = {
            "critical": "#d32f2f", "high": "#f44336",
            "medium": "#ff9800", "low": "#ffc107", "info": "#2196f3",
        }
        category_icons = {
            "信息泄露": "&#128269;", "安全配置缺陷": "&#9881;",
            "漏洞模式": "&#128027;", "自定义": "&#128295;",
        }

        rows_html = ""
        for i, f in enumerate(findings):
            color = severity_colors.get(f.severity.value, "#757575")
            icon = category_icons.get(f.category.value, "&#128203;")
            evidence_escaped = (f.evidence.replace("&", "&amp;").replace("<", "&lt;")
                                .replace(">", "&gt;").replace('"', "&quot;"))
            rows_html += f"""
            <tr>
                <td>{i + 1}</td>
                <td><span style="color:{color};font-weight:bold">{f.severity.value.upper()}</span></td>
                <td>{icon} {f.rule_name}</td>
                <td>{f.category.value}</td>
                <td style="max-width:300px;word-break:break-all">{f.url}</td>
                <td><code style="background:#f5f5f5;padding:2px 6px;border-radius:3px">{evidence_escaped[:200]}</code></td>
                <td>{f.remediation[:100] if f.remediation else '-'}</td>
            </tr>"""

        total = len(findings)
        critical = sum(1 for f in findings if f.severity == PassiveSeverity.CRITICAL)
        high = sum(1 for f in findings if f.severity == PassiveSeverity.HIGH)
        medium = sum(1 for f in findings if f.severity == PassiveSeverity.MEDIUM)
        low = sum(1 for f in findings if f.severity == PassiveSeverity.LOW)
        info = sum(1 for f in findings if f.severity == PassiveSeverity.INFO)

        return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <title>{title}</title>
    <style>
        * {{ margin:0; padding:0; box-sizing:border-box; }}
        body {{ font-family: 'Microsoft YaHei', sans-serif; background:#f0f2f5; color:#333; }}
        .header {{ background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); color:white; padding:30px; text-align:center; }}
        .header h1 {{ font-size:28px; margin-bottom:10px; }}
        .header p {{ opacity:0.8; }}
        .summary {{ display:flex; justify-content:center; gap:20px; padding:20px; flex-wrap:wrap; }}
        .stat-card {{ background:white; border-radius:8px; padding:15px 25px; box-shadow:0 2px 8px rgba(0,0,0,0.1); text-align:center; min-width:100px; }}
        .stat-card .count {{ font-size:32px; font-weight:bold; }}
        .stat-card .label {{ font-size:12px; color:#666; margin-top:5px; }}
        .content {{ max-width:1400px; margin:0 auto; padding:20px; }}
        table {{ width:100%; border-collapse:collapse; background:white; border-radius:8px; overflow:hidden; box-shadow:0 2px 8px rgba(0,0,0,0.1); }}
        th {{ background:#1a1a2e; color:white; padding:12px 15px; text-align:left; font-size:13px; }}
        td {{ padding:10px 15px; border-bottom:1px solid #eee; font-size:13px; }}
        tr:hover {{ background:#f8f9fa; }}
        .footer {{ text-align:center; padding:20px; color:#999; font-size:12px; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>&#128737; {title}</h1>
        <p>生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | 昆仑渗透测试平台</p>
    </div>
    <div class="summary">
        <div class="stat-card"><div class="count" style="color:#d32f2f">{critical}</div><div class="label">严重</div></div>
        <div class="stat-card"><div class="count" style="color:#f44336">{high}</div><div class="label">高危</div></div>
        <div class="stat-card"><div class="count" style="color:#ff9800">{medium}</div><div class="label">中危</div></div>
        <div class="stat-card"><div class="count" style="color:#ffc107">{low}</div><div class="label">低危</div></div>
        <div class="stat-card"><div class="count" style="color:#2196f3">{info}</div><div class="label">信息</div></div>
        <div class="stat-card"><div class="count" style="color:#333">{total}</div><div class="label">总计</div></div>
    </div>
    <div class="content">
        <table>
            <thead>
                <tr><th>#</th><th>严重级别</th><th>规则名称</th><th>类别</th><th>URL</th><th>证据</th><th>修复建议</th></tr>
            </thead>
            <tbody>{rows_html}
            </tbody>
        </table>
    </div>
    <div class="footer"><p>昆仑渗透测试平台 - 被动扫描引擎自动生成</p></div>
</body>
</html>"""


class PassiveNotificationManager:
    """通知管理器 - 高危发现触发桌面通知或Webhook推送"""

    def __init__(self, webhook_url: str = ""):
        self._webhook_url = webhook_url
        self._desktop_enabled = True
        self._webhook_enabled = bool(webhook_url)
        self._notify_severities = {PassiveSeverity.CRITICAL, PassiveSeverity.HIGH}

    def set_webhook_url(self, url: str):
        self._webhook_url = url
        self._webhook_enabled = bool(url)

    def enable_desktop_notifications(self, enabled: bool = True):
        self._desktop_enabled = enabled

    def set_notify_severities(self, severities: Set[PassiveSeverity]):
        self._notify_severities = severities

    def should_notify(self, finding: PassiveScanFinding) -> bool:
        return finding.severity in self._notify_severities

    def send_desktop_notification(self, finding: PassiveScanFinding):
        if not self._desktop_enabled:
            return
        try:
            from plyer import notification
            notification.notify(
                title=f"昆仑 - {finding.severity.value.upper()} 漏洞发现",
                message=f"{finding.rule_name}\n{finding.url[:80]}",
                timeout=5,
            )
        except ImportError:
            logger.debug("plyer未安装，桌面通知不可用")
        except Exception as e:
            logger.debug(f"桌面通知发送失败: {e}")

    async def send_webhook(self, finding: PassiveScanFinding):
        if not self._webhook_enabled or not self._webhook_url:
            return
        try:
            import aiohttp
            payload = {
                "msgtype": "markdown",
                "markdown": {
                    "title": f"昆仑被动扫描 - {finding.severity.value.upper()}",
                    "text": (
                        f"## 被动扫描发现漏洞\n\n"
                        f"**规则**: {finding.rule_name}\n"
                        f"**级别**: <font color=\"warning\">{finding.severity.value.upper()}</font>\n"
                        f"**URL**: {finding.url}\n"
                        f"**证据**: {finding.evidence[:200]}\n"
                        f"**时间**: {finding.timestamp.strftime('%Y-%m-%d %H:%M:%S')}\n"
                    ),
                },
            }
            async with aiohttp.ClientSession() as session:
                async with session.post(self._webhook_url, json=payload, timeout=aiohttp.ClientTimeout(total=5)):
                    pass
        except ImportError:
            logger.debug("aiohttp未安装，Webhook不可用")
        except Exception as e:
            logger.debug(f"Webhook发送失败: {e}")

    async def notify(self, finding: PassiveScanFinding):
        if not self.should_notify(finding):
            return
        self.send_desktop_notification(finding)
        await self.send_webhook(finding)


class PassiveScanner:
    """被动扫描引擎主控

    事件驱动流水线：订阅代理事件 → 有界异步队列 → Worker协程池并发消费 → 事件总线发布结果。
    """

    STATIC_EXTENSIONS = {
        ".css", ".js", ".mjs", ".png", ".jpg", ".jpeg", ".gif", ".ico",
        ".svg", ".woff", ".woff2", ".ttf", ".eot", ".otf", ".map",
        ".mp4", ".mp3", ".webm", ".ogg", ".wav", ".flac",
        ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
        ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2",
        ".webp", ".avif", ".heic",
    }

    def __init__(self, rules_dir: Optional[str] = None,
                 max_queue_size: int = DEFAULT_MAX_QUEUE_SIZE,
                 max_workers: int = DEFAULT_MAX_WORKERS,
                 max_body_size: int = DEFAULT_MAX_BODY_SIZE,
                 dedup_db_path: str = DEFAULT_DEDUP_DB_PATH,
                 webhook_url: str = ""):
        self._rule_loader = PassiveRuleLoader(rules_dir)
        self._rule_engine = PassiveRuleEngine()
        self._dedup_manager = PassiveDedupManager(dedup_db_path)
        self._exporter = PassiveResultExporter()
        self._notifier = PassiveNotificationManager(webhook_url)

        self._max_queue_size = max_queue_size
        self._max_workers = max_workers
        self._max_body_size = max_body_size

        self._queue: asyncio.Queue = asyncio.Queue(maxsize=max_queue_size)
        self._workers: List[asyncio.Task] = []
        self._running = False
        self._event_bus = None

        self._findings: List[PassiveScanFinding] = []
        self._findings_lock = asyncio.Lock()

        self._domain_whitelist: Set[str] = set()
        self._domain_blacklist: Set[str] = set()
        self._url_whitelist: Set[str] = set()

        self._stats = {
            "requests_analyzed": 0,
            "requests_skipped": 0,
            "findings_total": 0,
            "findings_by_severity": defaultdict(int),
            "findings_by_category": defaultdict(int),
            "queue_dropped": 0,
            "start_time": None,
        }

    @property
    def rule_loader(self) -> PassiveRuleLoader:
        return self._rule_loader

    @property
    def rule_engine(self) -> PassiveRuleEngine:
        return self._rule_engine

    @property
    def dedup_manager(self) -> PassiveDedupManager:
        return self._dedup_manager

    @property
    def findings(self) -> List[PassiveScanFinding]:
        return list(self._findings)

    @property
    def stats(self) -> Dict[str, Any]:
        s = dict(self._stats)
        s["findings_by_severity"] = dict(s["findings_by_severity"])
        s["findings_by_category"] = dict(s["findings_by_category"])
        s["dedup_stats"] = self._dedup_manager.get_stats()
        s["queue_size"] = self._queue.qsize()
        s["worker_count"] = len(self._workers)
        s["domain_whitelist"] = list(self._domain_whitelist)
        s["domain_blacklist"] = list(self._domain_blacklist)
        return s

    def set_event_bus(self, event_bus):
        self._event_bus = event_bus

    def set_webhook_url(self, url: str):
        self._notifier.set_webhook_url(url)

    def add_domain_whitelist(self, domain: str):
        self._domain_whitelist.add(domain.lower())

    def add_domain_blacklist(self, domain: str):
        self._domain_blacklist.add(domain.lower())

    def remove_domain_whitelist(self, domain: str):
        self._domain_whitelist.discard(domain.lower())

    def remove_domain_blacklist(self, domain: str):
        self._domain_blacklist.discard(domain.lower())

    def clear_domain_lists(self):
        self._domain_whitelist.clear()
        self._domain_blacklist.clear()

    def add_url_whitelist(self, url: str):
        self._url_whitelist.add(url)

    def remove_url_whitelist(self, url: str):
        self._url_whitelist.discard(url)

    def initialize(self):
        builtin_rules = self._rule_engine.get_builtin_rules()
        for rule in builtin_rules:
            if rule.id not in self._rule_loader.rules:
                self._rule_loader._rules[rule.id] = rule
        logger.info(f"被动扫描器初始化完成，内置 {len(builtin_rules)} 条规则")

    async def start(self):
        if self._running:
            return
        self._running = True
        self._stats["start_time"] = datetime.now()
        for i in range(self._max_workers):
            task = asyncio.create_task(self._worker(i))
            self._workers.append(task)
        logger.info(f"被动扫描引擎启动，{self._max_workers} 个Worker")

    async def stop(self):
        if not self._running:
            return
        self._running = False
        for worker in self._workers:
            worker.cancel()
        self._workers.clear()
        await self._queue.join()
        logger.info("被动扫描引擎已停止")

    async def submit(self, url: str, method: str,
                     request_headers: Dict[str, str], request_body: str,
                     response_headers: Dict[str, str], response_body: str,
                     status_code: int):
        if not self._running:
            return
        if self._should_skip(url, response_body):
            self._stats["requests_skipped"] += 1
            return
        if len(response_body) > self._max_body_size:
            response_body = response_body[:self._max_body_size]
        task_data = {
            "url": url, "method": method,
            "request_headers": request_headers, "request_body": request_body,
            "response_headers": response_headers, "response_body": response_body,
            "status_code": status_code,
        }
        try:
            self._queue.put_nowait(task_data)
        except asyncio.QueueFull:
            try:
                self._queue.get_nowait()
                self._queue.put_nowait(task_data)
                self._stats["queue_dropped"] += 1
            except asyncio.QueueEmpty:
                pass

    def _should_skip(self, url: str, response_body: str) -> bool:
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
        path = parsed.path or ""
        if self._domain_blacklist:
            if any(d.lower() in hostname.lower() for d in self._domain_blacklist):
                return True
        if self._domain_whitelist:
            if not any(d.lower() in hostname.lower() for d in self._domain_whitelist):
                return True
        ext = os.path.splitext(path)[1].lower()
        if ext in self.STATIC_EXTENSIONS:
            return True
        if not response_body or len(response_body.strip()) < 10:
            return True
        return False

    async def _worker(self, worker_id: int):
        logger.debug(f"Worker {worker_id} 启动")
        while self._running:
            try:
                task_data = await asyncio.wait_for(self._queue.get(), timeout=1.0)
            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                break
            try:
                findings = await self._analyze(task_data)
                for finding in findings:
                    await self._handle_finding(finding)
                self._stats["requests_analyzed"] += 1
            except Exception as e:
                logger.error(f"Worker {worker_id} 分析异常: {e}")
            finally:
                self._queue.task_done()
        logger.debug(f"Worker {worker_id} 停止")

    async def _analyze(self, task_data: Dict[str, Any]) -> List[PassiveScanFinding]:
        findings: List[PassiveScanFinding] = []
        url = task_data["url"]
        method = task_data["method"]
        request_headers = task_data["request_headers"]
        request_body = task_data["request_body"]
        response_headers = task_data["response_headers"]
        response_body = task_data["response_body"]
        status_code = task_data["status_code"]

        all_rules = list(self._rule_loader.rules.values())
        for rule in all_rules:
            if not rule.enabled:
                continue
            try:
                if rule.python_handler and rule.python_handler in self._rule_loader.python_handlers:
                    handler = self._rule_loader.python_handlers[rule.python_handler]
                    result = handler(task_data)
                    if result is not None:
                        findings.append(result)
                else:
                    result = self._rule_engine.check_rule(
                        rule, url, method, request_headers, request_body,
                        response_headers, response_body, status_code,
                    )
                    if result is not None:
                        findings.append(result)
            except Exception as e:
                logger.debug(f"规则 {rule.id} 执行异常: {e}")

        return findings

    async def _handle_finding(self, finding: PassiveScanFinding):
        if self._dedup_manager.is_duplicate(finding.rule_id, finding.url, finding.evidence):
            return
        async with self._findings_lock:
            self._findings.append(finding)
            self._stats["findings_total"] += 1
            self._stats["findings_by_severity"][finding.severity.value] += 1
            self._stats["findings_by_category"][finding.category.value] += 1
        if self._event_bus:
            try:
                self._event_bus.publish(
                    event_type="passive_scan_finding",
                    source="passive_scanner",
                    data=finding.to_dict(),
                )
            except Exception as e:
                logger.debug(f"事件发布失败: {e}")
        await self._notifier.notify(finding)

    def export_findings_json(self, pretty: bool = True) -> str:
        return self._exporter.export_json(list(self._findings), pretty)

    def export_findings_html(self, title: str = "昆仑被动扫描报告") -> str:
        return self._exporter.export_html(list(self._findings), title)

    def clear_findings(self):
        self._findings.clear()
        self._stats["findings_total"] = 0
        self._stats["findings_by_severity"].clear()
        self._stats["findings_by_category"].clear()

    def get_findings_by_severity(self, severity: PassiveSeverity) -> List[PassiveScanFinding]:
        return [f for f in self._findings if f.severity == severity]

    def get_findings_by_category(self, category: PassiveRuleCategory) -> List[PassiveScanFinding]:
        return [f for f in self._findings if f.category == category]

    def get_findings_by_url(self, url: str) -> List[PassiveScanFinding]:
        return [f for f in self._findings if url in f.url]

    def update_finding_status(self, finding_id: str, status: FindingStatus):
        for f in self._findings:
            if f.finding_id == finding_id:
                f.status = status
                break

    def get_ui_data(self) -> Dict[str, Any]:
        return {
            "stats": self.stats,
            "recent_findings": [f.to_dict() for f in self._findings[-50:]],
            "rules_count": len(self._rule_loader.rules),
            "enabled_rules_count": len(self._rule_loader.get_enabled_rules()),
            "running": self._running,
        }


class PassiveScannerIntegration:
    """被动扫描器与MITM代理的集成桥接

    订阅代理模块的request_response事件，将流量推入被动扫描流水线。
    提供界面联动接口：高亮标记、悬停摘要、证据详情、右键菜单。
    """

    def __init__(self, scanner: PassiveScanner):
        self._scanner = scanner
        self._event_bus = None
        self._proxy_module = None
        self._highlighted_urls: Dict[str, List[str]] = {}
        self._url_findings_map: Dict[str, List[PassiveScanFinding]] = defaultdict(list)

    def set_event_bus(self, event_bus):
        self._event_bus = event_bus
        self._scanner.set_event_bus(event_bus)

    def set_proxy_module(self, proxy_module):
        self._proxy_module = proxy_module

    def attach_to_proxy(self):
        """挂载到代理模块，订阅请求/响应事件"""
        if self._event_bus:
            self._event_bus.subscribe(
                event_type="proxy_request_response",
                callback=self._on_proxy_event,
            )
            logger.info("被动扫描器已挂载到代理模块事件总线")

        if self._proxy_module and hasattr(self._proxy_module, "add_callback"):
            self._proxy_module.add_callback("on_response", self._on_proxy_response)
            logger.info("被动扫描器已挂载到代理模块回调")

    def detach_from_proxy(self):
        """从代理模块卸载"""
        logger.info("被动扫描器已从代理模块卸载")

    async def _on_proxy_event(self, event):
        """处理代理事件总线消息"""
        data = event.data if hasattr(event, "data") else event
        url = data.get("url", "")
        method = data.get("method", "GET")
        request_headers = data.get("request_headers", {})
        request_body = data.get("request_body", "")
        response_headers = data.get("response_headers", {})
        response_body = data.get("response_body", "")
        status_code = data.get("status_code", 0)

        await self._scanner.submit(
            url=url, method=method,
            request_headers=request_headers, request_body=request_body,
            response_headers=response_headers, response_body=response_body,
            status_code=status_code,
        )

    def _on_proxy_response(self, request, response):
        """处理代理模块直接回调"""
        url = getattr(request, "url", "")
        method = getattr(request, "method", "GET")
        request_headers = dict(getattr(request, "headers", {}))
        request_body = getattr(request, "body", "") or ""
        response_headers = dict(getattr(response, "headers", {}))
        response_body = getattr(response, "body", "") or ""
        status_code = getattr(response, "status_code", 0)

        if isinstance(request_body, bytes):
            request_body = request_body.decode("utf-8", errors="replace")
        if isinstance(response_body, bytes):
            response_body = response_body.decode("utf-8", errors="replace")

        asyncio.create_task(self._scanner.submit(
            url=url, method=method,
            request_headers=request_headers, request_body=request_body,
            response_headers=response_headers, response_body=response_body,
            status_code=status_code,
        ))

    def get_url_highlight_info(self, url: str) -> Optional[Dict[str, Any]]:
        """获取URL的高亮标记信息（界面联动：代理流量列表高亮）"""
        findings = self._scanner.get_findings_by_url(url)
        if not findings:
            return None
        severities = sorted(set(f.severity.value for f in findings),
                           key=lambda s: {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(s, 5))
        return {
            "has_findings": True,
            "finding_count": len(findings),
            "highest_severity": severities[0] if severities else "info",
            "summary": "; ".join(f"{f.rule_name}" for f in findings[:3]),
            "finding_ids": [f.finding_id for f in findings],
        }

    def get_finding_detail(self, finding_id: str) -> Optional[Dict[str, Any]]:
        """获取漏洞详情（界面联动：点击展开证据详情）"""
        for f in self._scanner.findings:
            if f.finding_id == finding_id:
                detail = f.to_dict()
                detail["evidence_context"] = f.get_evidence_context()
                detail["response_body_snippet"] = f.response_body_snippet[:2000]
                return detail
        return None

    def add_to_whitelist(self, url: str):
        """将URL加入白名单（界面联动：右键菜单）"""
        self._scanner.add_url_whitelist(url)
        logger.info(f"URL已加入被动扫描白名单: {url}")

    def ignore_finding(self, finding_id: str):
        """忽略指定发现（界面联动：右键菜单）"""
        self._scanner.update_finding_status(finding_id, FindingStatus.IGNORED)
        logger.info(f"已忽略被动扫描发现: {finding_id}")

    def send_to_repeater(self, finding_id: str) -> Optional[Dict[str, Any]]:
        """发送到Repeater模块（界面联动：右键菜单）"""
        for f in self._scanner.findings:
            if f.finding_id == finding_id:
                return {
                    "url": f.url,
                    "method": f.method,
                    "headers": f.request_headers,
                    "body": f.request_body,
                    "host": f.host,
                }
        return None

    def send_to_fuzzer(self, finding_id: str) -> Optional[Dict[str, Any]]:
        """发送到Fuzzer模块（界面联动：右键菜单）"""
        for f in self._scanner.findings:
            if f.finding_id == finding_id:
                return {
                    "url": f.url,
                    "method": f.method,
                    "headers": f.request_headers,
                    "body": f.request_body,
                    "host": f.host,
                    "injection_point": f.evidence_location,
                }
        return None

    def get_dashboard_data(self) -> Dict[str, Any]:
        """获取仪表盘数据"""
        return self._scanner.get_ui_data()