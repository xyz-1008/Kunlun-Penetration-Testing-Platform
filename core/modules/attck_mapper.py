"""MITRE ATT&CK automatic mapping engine for Kunlun penetration testing platform.

Provides:
- Built-in ATT&CK technique mapping dictionary
- Rule-based automatic mapping engine
- Fuzzy matching for unknown operations
- Manual override support
- Multi-version ATT&CK support (v12/v13/v14)
"""

import asyncio
import logging
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Coroutine, Dict, List, Optional, Set, Tuple

import yaml  # type: ignore[import-untyped]

logger = logging.getLogger(__name__)


class AttckVersion(str, Enum):
    """Supported ATT&CK framework versions."""
    V12 = "v12"
    V13 = "v13"
    V14 = "v14"


class AttckTactic(str, Enum):
    """ATT&CK tactic categories."""
    INITIAL_ACCESS = "initial-access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege-escalation"
    DEFENSE_EVASION = "defense-evasion"
    CREDENTIAL_ACCESS = "credential-access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral-movement"
    COLLECTION = "collection"
    COMMAND_AND_CONTROL = "command-and-control"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"


class Severity(str, Enum):
    """Severity level for ATT&CK technique utilization."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class MappingConfidence(str, Enum):
    """Confidence level for automatic mapping."""
    EXACT = "exact"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    FUZZY = "fuzzy"


@dataclass
class AttckTechnique:
    """Represents a single ATT&CK technique."""
    technique_id: str = ""
    name: str = ""
    tactic: AttckTactic = AttckTactic.INITIAL_ACCESS
    description: str = ""
    severity: Severity = Severity.MEDIUM
    detection_suggestions: List[str] = field(default_factory=list)
    mitigation_suggestions: List[str] = field(default_factory=list)
    sub_techniques: List[str] = field(default_factory=list)
    platforms: List[str] = field(default_factory=list)
    data_sources: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "technique_id": self.technique_id,
            "name": self.name,
            "tactic": self.tactic.value,
            "description": self.description,
            "severity": self.severity.value,
            "detection_suggestions": self.detection_suggestions,
            "mitigation_suggestions": self.mitigation_suggestions,
            "sub_techniques": self.sub_techniques,
            "platforms": self.platforms,
            "data_sources": self.data_sources,
        }


@dataclass
class MappingResult:
    """Result of ATT&CK technique mapping."""
    technique: AttckTechnique
    confidence: MappingConfidence = MappingConfidence.LOW
    matched_rule: str = ""
    operation_type: str = ""
    operation_description: str = ""
    target_host: str = ""
    timestamp: float = 0.0
    is_manual_override: bool = False
    evidence: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "technique": self.technique.to_dict(),
            "confidence": self.confidence.value,
            "matched_rule": self.matched_rule,
            "operation_type": self.operation_type,
            "operation_description": self.operation_description,
            "target_host": self.target_host,
            "timestamp": self.timestamp,
            "is_manual_override": self.is_manual_override,
            "evidence": self.evidence,
        }


@dataclass
class MappingRule:
    """Rule for automatic ATT&CK mapping."""
    rule_id: str = ""
    name: str = ""
    description: str = ""
    operation_types: List[str] = field(default_factory=list)
    keywords: List[str] = field(default_factory=list)
    regex_pattern: str = ""
    attck_technique_id: str = ""
    confidence: MappingConfidence = MappingConfidence.HIGH
    priority: int = 100
    is_custom: bool = False
    enabled: bool = True

    def matches(self, operation_type: str, operation_description: str) -> bool:
        """Check if this rule matches the given operation."""
        if not self.enabled:
            return False
        desc_lower = operation_description.lower()
        if self.operation_types and operation_type in self.operation_types:
            if not self.keywords and not self.regex_pattern:
                return True
        if self.keywords:
            if any(kw.lower() in desc_lower for kw in self.keywords):
                return True
        if self.regex_pattern:
            try:
                if re.search(self.regex_pattern, operation_description, re.IGNORECASE):
                    return True
            except re.error:
                logger.warning("Invalid regex in rule %s: %s", self.rule_id, self.regex_pattern)
        return False


@dataclass
class AttckTimelineEntry:
    """Entry in the ATT&CK attack chain timeline."""
    timestamp: float = 0.0
    tactic: AttckTactic = AttckTactic.INITIAL_ACCESS
    technique: AttckTechnique = field(default_factory=AttckTechnique)
    target_host: str = ""
    description: str = ""
    operation_id: str = ""
    sequence_number: int = 0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "timestamp": self.timestamp,
            "tactic": self.tactic.value,
            "technique": self.technique.to_dict(),
            "target_host": self.target_host,
            "description": self.description,
            "operation_id": self.operation_id,
            "sequence_number": self.sequence_number,
        }


TACTIC_ORDER: List[AttckTactic] = [
    AttckTactic.INITIAL_ACCESS,
    AttckTactic.EXECUTION,
    AttckTactic.PERSISTENCE,
    AttckTactic.PRIVILEGE_ESCALATION,
    AttckTactic.DEFENSE_EVASION,
    AttckTactic.CREDENTIAL_ACCESS,
    AttckTactic.DISCOVERY,
    AttckTactic.LATERAL_MOVEMENT,
    AttckTactic.COLLECTION,
    AttckTactic.COMMAND_AND_CONTROL,
    AttckTactic.EXFILTRATION,
    AttckTactic.IMPACT,
]

FUZZY_KEYWORDS: Dict[str, List[str]] = {
    "T1190": ["exploit", "cve", "vulnerability", "rce", "remote code execution", "漏洞利用", "远程代码执行"],
    "T1078": ["valid account", "credential", "password", "login", "有效账户", "凭据", "密码"],
    "T1133": ["vpn", "rdp", "remote service", "远程服务", "外部"],
    "T1059": ["powershell", "cmd", "shell", "script", "command", "命令", "脚本", "解释器"],
    "T1047": ["wmi", "windows management", "wmic"],
    "T1053": ["scheduled task", "cron", "计划任务", "定时任务"],
    "T1547": ["autostart", "startup", "run key", "启动项", "自启动"],
    "T1543": ["service", "system process", "服务", "系统进程"],
    "T1068": ["privilege escalation", "exploit for priv", "提权", "权限提升"],
    "T1134": ["token", "impersonate", "令牌", "模拟"],
    "T1548": ["uac", "elevation", "bypass", "绕过", "权限控制"],
    "T1027": ["obfuscate", "encode", "混淆", "编码"],
    "T1055": ["inject", "dll", "process", "注入", "进程"],
    "T1562": ["disable", "defense", "antivirus", "firewall", "禁用", "防御"],
    "T1003": ["lsass", "dump", "credential dump", "凭据导出", "内存"],
    "T1552": ["unsecured", "credential file", "private key", "不安全", "私钥"],
    "T1558": ["kerberos", "ticket", "golden ticket", "kerberoasting", "票据"],
    "T1046": ["scan", "port scan", "network discovery", "扫描", "端口"],
    "T1082": ["system info", "discovery", "information", "系统信息", "发现"],
    "T1087": ["account discovery", "enum", "账户发现", "枚举"],
    "T1021": ["remote", "rdp", "smb", "ssh", "winrm", "横向", "远程"],
    "T1550": ["pass the hash", "pass the ticket", "pth", "ptt", "哈希传递", "票据传递"],
    "T1570": ["tool transfer", "lateral tool", "工具传输", "横向移动"],
    "T1005": ["data from local", "collect data", "数据收集", "本地数据"],
    "T1560": ["archive", "compress", "zip", "tar", "压缩", "归档"],
    "T1071": ["http", "dns", "application protocol", "c2", "应用层协议"],
    "T1132": ["encoding", "base64", "编码", "数据编码"],
    "T1573": ["encrypted", "tls", "ssl", "加密", "加密信道"],
    "T1041": ["exfiltration", "c2 channel", "渗出", "c2"],
    "T1048": ["alternative protocol", "替代协议", "渗出"],
    "T1486": ["encrypt", "ransomware", "勒索", "加密"],
    "T1485": ["destroy", "delete", "wipe", "破坏", "删除"],
}


class AttckMapper:
    """Core ATT&CK mapping engine.

    Provides:
    - Built-in technique database
    - Rule-based automatic mapping
    - Fuzzy matching for unknown operations
    - Manual override support
    - Multi-version ATT&CK support
    """

    def __init__(
        self,
        rules_path: Optional[str] = None,
        version: AttckVersion = AttckVersion.V14,
    ) -> None:
        """Initialize the ATT&CK mapper.

        Args:
            rules_path: Optional path to custom rules YAML file.
            version: ATT&CK framework version to use.
        """
        self.version = version
        self.techniques: Dict[str, AttckTechnique] = {}
        self.rules: List[MappingRule] = []
        self.custom_rules: List[MappingRule] = []
        self.mapping_history: List[MappingResult] = []
        self.manual_overrides: Dict[str, MappingResult] = {}
        self._load_builtin_techniques()
        self._load_builtin_rules()
        if rules_path:
            self.load_custom_rules(rules_path)

    def _load_builtin_techniques(self) -> None:
        """Load built-in ATT&CK techniques database."""
        from .attck_techniques_db import BUILTIN_TECHNIQUES
        self.techniques = dict(BUILTIN_TECHNIQUES)

    def _load_builtin_rules(self) -> None:
        """Load built-in mapping rules."""
        builtin_rules = [
            MappingRule(
                rule_id="rule-001",
                name="PoC Exploit Execution",
                description="PoC执行且包含CVE编号映射到T1190",
                operation_types=["poc_execute", "exploit"],
                keywords=["cve", "exploit", "漏洞"],
                regex_pattern=r"CVE-\d{4}-\d{4,}",
                attck_technique_id="T1190",
                confidence=MappingConfidence.EXACT,
                priority=200,
            ),
            MappingRule(
                rule_id="rule-002",
                name="Pass the Hash",
                description="PtH命令执行映射到T1550.002",
                operation_types=["pth", "pass_the_hash", "lateral_movement"],
                keywords=["pass the hash", "pth", "哈希传递", "ntlm"],
                attck_technique_id="T1550.002",
                confidence=MappingConfidence.EXACT,
                priority=200,
            ),
            MappingRule(
                rule_id="rule-003",
                name="LSASS Memory Dump",
                description="LSASS内存访问映射到T1003.001",
                operation_types=["lsass_dump", "credential_dump"],
                keywords=["lsass", "mimikatz", "sekurlsa", "内存转储"],
                attck_technique_id="T1003.001",
                confidence=MappingConfidence.EXACT,
                priority=200,
            ),
            MappingRule(
                rule_id="rule-004",
                name="Scheduled Task Creation",
                description="计划任务创建映射到T1053.005",
                operation_types=["scheduled_task", "cron"],
                keywords=["scheduled task", "schtasks", "计划任务", "cron"],
                attck_technique_id="T1053.005",
                confidence=MappingConfidence.EXACT,
                priority=200,
            ),
            MappingRule(
                rule_id="rule-005",
                name="WMI Execution",
                description="WMI命令执行映射到T1047",
                operation_types=["wmi", "wmic"],
                keywords=["wmi", "wmic", "windows management"],
                attck_technique_id="T1047",
                confidence=MappingConfidence.EXACT,
                priority=200,
            ),
            MappingRule(
                rule_id="rule-006",
                name="PowerShell Execution",
                description="PowerShell执行映射到T1059.001",
                operation_types=["powershell", "ps_exec"],
                keywords=["powershell", "ps1", "invoke-", "encodedcommand"],
                attck_technique_id="T1059.001",
                confidence=MappingConfidence.EXACT,
                priority=200,
            ),
            MappingRule(
                rule_id="rule-007",
                name="Token Manipulation",
                description="令牌操作映射到T1134",
                operation_types=["token_steal", "token_impersonate"],
                keywords=["token", "impersonate", "令牌", "incognito"],
                attck_technique_id="T1134",
                confidence=MappingConfidence.EXACT,
                priority=200,
            ),
            MappingRule(
                rule_id="rule-008",
                name="Service Creation",
                description="服务创建映射到T1543.003",
                operation_types=["service_create", "sc_exec"],
                keywords=["sc create", "new-service", "服务创建"],
                attck_technique_id="T1543.003",
                confidence=MappingConfidence.EXACT,
                priority=200,
            ),
            MappingRule(
                rule_id="rule-009",
                name="UAC Bypass",
                description="UAC绕过映射到T1548.002",
                operation_types=["uac_bypass"],
                keywords=["uac bypass", "fodhelper", "dism", "uac绕过"],
                attck_technique_id="T1548.002",
                confidence=MappingConfidence.EXACT,
                priority=200,
            ),
            MappingRule(
                rule_id="rule-010",
                name="RDP Lateral Movement",
                description="RDP横向移动映射到T1021.001",
                operation_types=["rdp", "rdesktop"],
                keywords=["rdp", "remote desktop", "mstsc", "3389"],
                attck_technique_id="T1021.001",
                confidence=MappingConfidence.EXACT,
                priority=200,
            ),
            MappingRule(
                rule_id="rule-011",
                name="SMB Lateral Movement",
                description="SMB横向移动映射到T1021.002",
                operation_types=["smb", "psexec"],
                keywords=["smb", "psexec", "admin$", "c$"],
                attck_technique_id="T1021.002",
                confidence=MappingConfidence.EXACT,
                priority=200,
            ),
            MappingRule(
                rule_id="rule-012",
                name="WinRM Lateral Movement",
                description="WinRM横向移动映射到T1021.006",
                operation_types=["winrm", "evil-winrm"],
                keywords=["winrm", "wsman", "5985", "5986"],
                attck_technique_id="T1021.006",
                confidence=MappingConfidence.EXACT,
                priority=200,
            ),
            MappingRule(
                rule_id="rule-013",
                name="Golden Ticket",
                description="黄金票据映射到T1558.001",
                operation_types=["golden_ticket"],
                keywords=["golden ticket", "krbtgt", "黄金票据"],
                attck_technique_id="T1558.001",
                confidence=MappingConfidence.EXACT,
                priority=200,
            ),
            MappingRule(
                rule_id="rule-014",
                name="Kerberoasting",
                description="Kerberoasting攻击映射到T1558.003",
                operation_types=["kerberoast"],
                keywords=["kerberoast", "tgs", "spn"],
                attck_technique_id="T1558.003",
                confidence=MappingConfidence.EXACT,
                priority=200,
            ),
            MappingRule(
                rule_id="rule-015",
                name="Process Injection",
                description="进程注入映射到T1055",
                operation_types=["process_inject", "dll_inject"],
                keywords=["inject", "dll", "process hollowing", "进程注入"],
                attck_technique_id="T1055",
                confidence=MappingConfidence.EXACT,
                priority=200,
            ),
            MappingRule(
                rule_id="rule-016",
                name="Privilege Escalation Exploit",
                description="提权漏洞利用映射到T1068",
                operation_types=["privesc_exploit"],
                keywords=["privilege escalation", "提权", "system权限", "nt authority"],
                attck_technique_id="T1068",
                confidence=MappingConfidence.EXACT,
                priority=200,
            ),
            MappingRule(
                rule_id="rule-017",
                name="Registry Persistence",
                description="注册表持久化映射到T1547.001",
                operation_types=["registry_persist"],
                keywords=["run key", "registry", "startup", "注册表", "启动项"],
                attck_technique_id="T1547.001",
                confidence=MappingConfidence.EXACT,
                priority=200,
            ),
            MappingRule(
                rule_id="rule-018",
                name="Data Exfiltration",
                description="数据渗出映射到T1041",
                operation_types=["exfiltrate", "c2_upload"],
                keywords=["exfiltration", "渗出", "upload", "c2"],
                attck_technique_id="T1041",
                confidence=MappingConfidence.HIGH,
                priority=150,
            ),
            MappingRule(
                rule_id="rule-019",
                name="Data Encryption Ransomware",
                description="数据加密勒索映射到T1486",
                operation_types=["encrypt_data", "ransomware"],
                keywords=["encrypt", "ransomware", "勒索", "加密"],
                attck_technique_id="T1486",
                confidence=MappingConfidence.EXACT,
                priority=200,
            ),
            MappingRule(
                rule_id="rule-020",
                name="Data Destruction",
                description="数据破坏映射到T1485",
                operation_types=["destroy_data", "wipe"],
                keywords=["destroy", "delete", "wipe", "破坏", "删除"],
                attck_technique_id="T1485",
                confidence=MappingConfidence.EXACT,
                priority=200,
            ),
        ]
        self.rules = builtin_rules

    def load_custom_rules(self, rules_path: str) -> None:
        """Load custom mapping rules from YAML file.

        Args:
            rules_path: Path to custom rules YAML file.
        """
        try:
            path = Path(rules_path)
            if not path.exists():
                logger.warning("Custom rules file not found: %s", rules_path)
                return
            content = path.read_text(encoding="utf-8")
            data: Dict[str, Any] = yaml.safe_load(content) or {}
            rules_data: List[Dict[str, Any]] = data.get("rules", [])
            for rule_data in rules_data:
                rule = MappingRule(
                    rule_id=rule_data.get("rule_id", f"custom-{len(self.custom_rules)+1:03d}"),
                    name=rule_data.get("name", ""),
                    description=rule_data.get("description", ""),
                    operation_types=rule_data.get("operation_types", []),
                    keywords=rule_data.get("keywords", []),
                    regex_pattern=rule_data.get("regex_pattern", ""),
                    attck_technique_id=rule_data.get("attck_technique_id", ""),
                    confidence=MappingConfidence(rule_data.get("confidence", "high")),
                    priority=rule_data.get("priority", 150),
                    is_custom=True,
                    enabled=rule_data.get("enabled", True),
                )
                self.custom_rules.append(rule)
            logger.info("Loaded %d custom rules from %s", len(rules_data), rules_path)
        except Exception as e:
            logger.error("Failed to load custom rules: %s", e)

    def map_operation(
        self,
        operation_type: str,
        operation_description: str,
        target_host: str = "",
        operation_id: str = "",
        evidence: Optional[Dict[str, Any]] = None,
    ) -> Optional[MappingResult]:
        """Map an operation to ATT&CK technique.

        Evaluates rules in priority order, then falls back to fuzzy matching.

        Args:
            operation_type: Type of the operation.
            operation_description: Description of the operation.
            target_host: Target host information.
            operation_id: Associated operation ID.
            evidence: Supporting evidence for the mapping.

        Returns:
            MappingResult if a match is found, None otherwise.
        """
        override_key = f"{operation_type}:{operation_id}"
        if override_key in self.manual_overrides:
            result = self.manual_overrides[override_key]
            result.is_manual_override = True
            return result

        all_rules = self.custom_rules + self.rules
        sorted_rules = sorted(all_rules, key=lambda r: r.priority, reverse=True)

        for rule in sorted_rules:
            if rule.matches(operation_type, operation_description):
                technique = self.techniques.get(rule.attck_technique_id)
                if technique:
                    result = MappingResult(
                        technique=technique,
                        confidence=rule.confidence,
                        matched_rule=rule.rule_id,
                        operation_type=operation_type,
                        operation_description=operation_description,
                        target_host=target_host,
                        timestamp=time.time(),
                        evidence=evidence or {},
                    )
                    self.mapping_history.append(result)
                    return result

        fuzzy_result = self._fuzzy_match(
            operation_type,
            operation_description,
            target_host,
            operation_id,
            evidence,
        )
        if fuzzy_result:
            self.mapping_history.append(fuzzy_result)
        return fuzzy_result

    def _fuzzy_match(
        self,
        operation_type: str,
        operation_description: str,
        target_host: str,
        operation_id: str,
        evidence: Optional[Dict[str, Any]],
    ) -> Optional[MappingResult]:
        """Perform fuzzy matching based on keywords.

        Args:
            operation_type: Type of the operation.
            operation_description: Description of the operation.
            target_host: Target host information.
            operation_id: Associated operation ID.
            evidence: Supporting evidence.

        Returns:
            MappingResult if fuzzy match found, None otherwise.
        """
        desc_lower = operation_description.lower()
        best_match: Optional[str] = None
        best_score = 0

        for tech_id, keywords in FUZZY_KEYWORDS.items():
            score = 0
            for kw in keywords:
                if kw.lower() in desc_lower:
                    score += len(kw)
            if score > best_score:
                best_score = score
                best_match = tech_id

        if best_match and best_score > 0:
            technique = self.techniques.get(best_match)
            if technique:
                return MappingResult(
                    technique=technique,
                    confidence=MappingConfidence.FUZZY,
                    matched_rule="fuzzy-match",
                    operation_type=operation_type,
                    operation_description=operation_description,
                    target_host=target_host,
                    timestamp=time.time(),
                    evidence=evidence or {},
                )
        return None

    def override_mapping(
        self,
        operation_type: str,
        operation_id: str,
        technique_id: str,
    ) -> Optional[MappingResult]:
        """Manually override a mapping result.

        Args:
            operation_type: Type of the operation.
            operation_id: Associated operation ID.
            technique_id: ATT&CK technique ID to override to.

        Returns:
            New MappingResult with override, or None if technique not found.
        """
        technique = self.techniques.get(technique_id)
        if not technique:
            return None
        override_key = f"{operation_type}:{operation_id}"
        result = MappingResult(
            technique=technique,
            confidence=MappingConfidence.EXACT,
            matched_rule="manual-override",
            operation_type=operation_type,
            is_manual_override=True,
            timestamp=time.time(),
        )
        self.manual_overrides[override_key] = result
        return result

    def get_technique(self, technique_id: str) -> Optional[AttckTechnique]:
        """Get a technique by ID.

        Args:
            technique_id: ATT&CK technique ID.

        Returns:
            AttckTechnique if found, None otherwise.
        """
        return self.techniques.get(technique_id)

    def get_all_techniques(self) -> Dict[str, AttckTechnique]:
        """Get all loaded techniques.

        Returns:
            Dictionary of technique ID to AttckTechnique.
        """
        return dict(self.techniques)

    def get_techniques_by_tactic(self, tactic: AttckTactic) -> List[AttckTechnique]:
        """Get all techniques for a specific tactic.

        Args:
            tactic: ATT&CK tactic to filter by.

        Returns:
            List of techniques matching the tactic.
        """
        return [t for t in self.techniques.values() if t.tactic == tactic]

    def get_used_techniques(self) -> List[MappingResult]:
        """Get all techniques that have been mapped.

        Returns:
            List of all mapping results.
        """
        return list(self.mapping_history)

    def get_technique_usage_count(self) -> Dict[str, int]:
        """Get usage count for each technique.

        Returns:
            Dictionary of technique ID to usage count.
        """
        counts: Dict[str, int] = {}
        for result in self.mapping_history:
            tid = result.technique.technique_id
            counts[tid] = counts.get(tid, 0) + 1
        return counts

    def get_attack_chain_timeline(self) -> List[AttckTimelineEntry]:
        """Generate attack chain timeline sorted by tactic order.

        Returns:
            List of timeline entries ordered by ATT&CK kill chain.
        """
        timeline: List[AttckTimelineEntry] = []
        tactic_groups: Dict[AttckTactic, List[MappingResult]] = {}

        for result in self.mapping_history:
            tactic = result.technique.tactic
            if tactic not in tactic_groups:
                tactic_groups[tactic] = []
            tactic_groups[tactic].append(result)

        seq_num = 0
        for tactic in TACTIC_ORDER:
            if tactic in tactic_groups:
                results = sorted(tactic_groups[tactic], key=lambda r: r.timestamp)
                for result in results:
                    seq_num += 1
                    entry = AttckTimelineEntry(
                        timestamp=result.timestamp,
                        tactic=tactic,
                        technique=result.technique,
                        target_host=result.target_host,
                        description=result.operation_description,
                        operation_id=result.matched_rule,
                        sequence_number=seq_num,
                    )
                    timeline.append(entry)

        return timeline

    def get_statistics(self) -> Dict[str, Any]:
        """Get mapping statistics.

        Returns:
            Dictionary with mapping statistics.
        """
        usage_counts = self.get_technique_usage_count()
        tactic_counts: Dict[str, int] = {}
        severity_counts: Dict[str, int] = {}

        for result in self.mapping_history:
            tactic_val = result.technique.tactic.value
            tactic_counts[tactic_val] = tactic_counts.get(tactic_val, 0) + 1
            sev_val = result.technique.severity.value
            severity_counts[sev_val] = severity_counts.get(sev_val, 0) + 1

        return {
            "total_mappings": len(self.mapping_history),
            "unique_techniques": len(usage_counts),
            "tactic_distribution": tactic_counts,
            "severity_distribution": severity_counts,
            "technique_usage": usage_counts,
            "manual_overrides": len(self.manual_overrides),
            "custom_rules_loaded": len(self.custom_rules),
        }
