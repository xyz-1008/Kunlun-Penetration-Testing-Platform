"""
Windows提权辅助套件 - 报告模块集成
===================================
与报告生成系统深度集成，提供MITRE ATT&CK自动映射、攻击链时间线记录、
提权报告章节自动生成。

核心能力:
    1. MITRE ATT&CK自动映射 - 每个检查项映射到对应ATT&CK技术ID
    2. 攻击链时间线 - 利用成功后自动记录到攻击链时间线
    3. 提权报告章节 - 自动生成包含完整提权过程的报告章节
    4. 与报告生成器集成 - 标准化接口对接现有ReportGenerator

Author: 昆仑安全实验室
License: Internal Use Only
"""

from __future__ import annotations

import json
import logging
import os
from copy import deepcopy
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# =============================================================================
# MITRE ATT&CK 映射表
# =============================================================================

class MITRETechnique:
    """MITRE ATT&CK 技术定义

    Attributes:
        technique_id: 技术ID（如 T1082）
        technique_name: 技术名称
        tactic: 战术阶段
        description: 技术描述
        detection_recommendations: 检测建议
    """
    technique_id: str
    technique_name: str
    tactic: str
    description: str
    detection_recommendations: List[str]

    def __init__(
        self,
        technique_id: str,
        technique_name: str,
        tactic: str,
        description: str = "",
        detection_recommendations: Optional[List[str]] = None,
    ) -> None:
        self.technique_id = technique_id
        self.technique_name = technique_name
        self.tactic = tactic
        self.description = description
        self.detection_recommendations = detection_recommendations or []

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "tactic": self.tactic,
            "description": self.description,
            "detection_recommendations": self.detection_recommendations,
        }


PRIVESC_MITRE_MAPPING: Dict[str, MITRETechnique] = {
    "os_info": MITRETechnique(
        technique_id="T1082",
        technique_name="System Information Discovery",
        tactic="Discovery",
        description="攻击者可能尝试获取操作系统和硬件配置的详细信息，包括版本、补丁级别、架构等。",
        detection_recommendations=[
            "监控系统信息查询命令（systeminfo, ver, wmic os）",
            "关注非正常工作时间的信息收集行为",
        ],
    ),
    "user_info": MITRETechnique(
        technique_id="T1033",
        technique_name="System Owner/User Discovery",
        tactic="Discovery",
        description="攻击者可能尝试识别当前登录用户和用户权限级别。",
        detection_recommendations=[
            "监控whoami、net user、query user等命令",
            "关注特权令牌枚举行为",
        ],
    ),
    "patch_info": MITRETechnique(
        technique_id="T1082",
        technique_name="System Information Discovery",
        tactic="Discovery",
        description="攻击者枚举已安装补丁以识别缺失的安全更新，寻找可利用的已知漏洞。",
        detection_recommendations=[
            "监控wmic qfe、Get-HotFix等补丁查询命令",
            "关注大量补丁枚举请求",
        ],
    ),
    "service_info": MITRETechnique(
        technique_id="T1007",
        technique_name="System Service Discovery",
        tactic="Discovery",
        description="攻击者枚举系统服务以查找配置错误、未引号路径、可写服务等提权机会。",
        detection_recommendations=[
            "监控sc query、wmic service等命令",
            "关注服务配置修改行为",
        ],
    ),
    "autostart_info": MITRETechnique(
        technique_id="T1547.001",
        technique_name="Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder",
        tactic="Persistence",
        description="攻击者枚举自启动项以寻找劫持机会或建立持久化。",
        detection_recommendations=[
            "监控自启动注册表键的枚举和修改",
            "关注启动文件夹的文件变更",
        ],
    ),
    "filesystem_info": MITRETechnique(
        technique_id="T1083",
        technique_name="File and Directory Discovery",
        tactic="Discovery",
        description="攻击者枚举文件系统以查找敏感文件、凭据文件、可写目录等。",
        detection_recommendations=[
            "监控大量文件枚举操作",
            "关注对敏感路径的访问（SAM、SYSTEM注册表文件）",
        ],
    ),
    "network_info": MITRETechnique(
        technique_id="T1049",
        technique_name="System Network Connections Discovery",
        tactic="Discovery",
        description="攻击者枚举网络连接、端口、接口以了解网络拓扑和横向移动机会。",
        detection_recommendations=[
            "监控netstat、ipconfig等网络命令",
            "关注内网扫描行为",
        ],
    ),
    "software_info": MITRETechnique(
        technique_id="T1518.001",
        technique_name="Software Discovery: Security Software Discovery",
        tactic="Discovery",
        description="攻击者枚举已安装软件以识别安全产品和可利用的过时软件。",
        detection_recommendations=[
            "监控wmic product、Get-ItemProperty等软件枚举命令",
            "关注对安全软件进程的探测",
        ],
    ),
    "always_install_elevated": MITRETechnique(
        technique_id="T1068",
        technique_name="Exploitation for Privilege Escalation",
        tactic="Privilege Escalation",
        description="攻击者利用AlwaysInstallElevated注册表配置以SYSTEM权限安装MSI包。",
        detection_recommendations=[
            "监控AlwaysInstallElevated注册表键值",
            "关注msiexec以SYSTEM权限运行",
        ],
    ),
    "unquoted_service_path": MITRETechnique(
        technique_id="T1574.009",
        technique_name="Hijack Execution Flow: Path Interception by Unquoted Path",
        tactic="Privilege Escalation",
        description="攻击者利用未引号服务路径在父目录放置恶意可执行文件。",
        detection_recommendations=[
            "审计服务路径配置",
            "监控非预期路径的可执行文件创建",
        ],
    ),
    "writable_service": MITRETechnique(
        technique_id="T1543.003",
        technique_name="Create or Modify System Process: Windows Service",
        tactic="Privilege Escalation",
        description="攻击者修改可写服务的binPath以执行恶意代码。",
        detection_recommendations=[
            "监控sc config命令",
            "审计服务binPath变更",
        ],
    ),
    "cve_patch_missing": MITRETechnique(
        technique_id="T1068",
        technique_name="Exploitation for Privilege Escalation",
        tactic="Privilege Escalation",
        description="攻击者利用缺失补丁的已知CVE漏洞进行权限提升。",
        detection_recommendations=[
            "保持系统补丁及时更新",
            "监控异常进程创建和权限变更",
        ],
    ),
    "vulnerable_driver": MITRETechnique(
        technique_id="T1068",
        technique_name="Exploitation for Privilege Escalation",
        tactic="Privilege Escalation",
        description="攻击者利用漏洞驱动加载未签名内核模块实现内核级提权。",
        detection_recommendations=[
            "启用Driver Blocklist",
            "监控内核驱动加载事件",
        ],
    ),
    "token_privilege": MITRETechnique(
        technique_id="T1134.001",
        technique_name="Access Token Manipulation: Token Impersonation/Theft",
        tactic="Privilege Escalation",
        description="攻击者利用SeImpersonatePrivilege等特权令牌进行令牌窃取和模拟。",
        detection_recommendations=[
            "审计特权令牌分配",
            "监控命名管道创建和模拟行为",
        ],
    ),
    "uac_config": MITRETechnique(
        technique_id="T1548.002",
        technique_name="Abuse Elevation Control Mechanism: Bypass User Account Control",
        tactic="Privilege Escalation",
        description="攻击者利用UAC配置弱点绕过用户账户控制。",
        detection_recommendations=[
            "确保UAC设置为最高级别",
            "监控UAC绕过行为",
        ],
    ),
    "scheduled_task": MITRETechnique(
        technique_id="T1053.005",
        technique_name="Scheduled Task/Job: Scheduled Task",
        tactic="Privilege Escalation",
        description="攻击者劫持以高权限运行的计划任务以提升权限。",
        detection_recommendations=[
            "审计计划任务配置",
            "监控计划任务文件的非预期修改",
        ],
    ),
    "credential_file": MITRETechnique(
        technique_id="T1552.001",
        technique_name="Unsecured Credentials: Credentials In Files",
        tactic="Credential Access",
        description="攻击者搜索自动安装文件、配置文件中的明文凭据。",
        detection_recommendations=[
            "清理自动部署残留文件",
            "监控对Unattend.xml等文件的访问",
        ],
    ),
    "dll_hijack": MITRETechnique(
        technique_id="T1574.001",
        technique_name="Hijack Execution Flow: DLL Search Order Hijacking",
        tactic="Privilege Escalation",
        description="攻击者在DLL搜索路径中放置恶意DLL，当高权限进程加载时执行。",
        detection_recommendations=[
            "监控非系统目录的DLL加载",
            "启用Safe DLL Search Mode",
        ],
    ),
    "outdated_software": MITRETechnique(
        technique_id="T1068",
        technique_name="Exploitation for Privilege Escalation",
        tactic="Privilege Escalation",
        description="攻击者利用过时软件的已知漏洞进行权限提升。",
        detection_recommendations=[
            "保持软件及时更新",
            "移除不必要的过时软件",
        ],
    ),
    "vm_escape": MITRETechnique(
        technique_id="T1611",
        technique_name="Escape to Host",
        tactic="Privilege Escalation",
        description="攻击者尝试从虚拟机逃逸到宿主机。",
        detection_recommendations=[
            "保持虚拟化平台更新",
            "监控VM逃逸尝试",
        ],
    ),
    "credential_dump": MITRETechnique(
        technique_id="T1003.001",
        technique_name="OS Credential Dumping: LSASS Memory",
        tactic="Credential Access",
        description="攻击者dump LSASS进程内存以提取NTLM哈希和明文凭据。",
        detection_recommendations=[
            "启用LSASS保护（PPL）",
            "监控对LSASS进程的访问",
        ],
    ),
    "sam_export": MITRETechnique(
        technique_id="T1003.002",
        technique_name="OS Credential Dumping: Security Account Manager",
        tactic="Credential Access",
        description="攻击者导出SAM注册表文件以提取本地账户哈希。",
        detection_recommendations=[
            "限制对SAM文件的访问",
            "监控reg save命令",
        ],
    ),
    "lateral_movement": MITRETechnique(
        technique_id="T1021.002",
        technique_name="Remote Services: SMB/Windows Admin Shares",
        tactic="Lateral Movement",
        description="攻击者利用获取的凭据通过SMB/WMI/WinRM进行横向移动。",
        detection_recommendations=[
            "监控SMB/WMI/WinRM连接",
            "审计管理共享访问",
        ],
    ),
}


# =============================================================================
# 攻击链时间线
# =============================================================================

@dataclass
class AttackChainEvent:
    """攻击链事件

    Attributes:
        event_id: 事件ID
        timestamp: 时间戳
        phase: 攻击阶段
        technique_id: MITRE ATT&CK技术ID
        description: 事件描述
        outcome: 结果（success/failure/info）
        details: 详细信息
        evidence: 证据/截图路径
    """
    event_id: str = ""
    timestamp: str = ""
    phase: str = ""
    technique_id: str = ""
    description: str = ""
    outcome: str = "info"
    details: Dict[str, Any] = field(default_factory=dict)
    evidence: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "phase": self.phase,
            "technique_id": self.technique_id,
            "description": self.description,
            "outcome": self.outcome,
            "details": self.details,
            "evidence": self.evidence,
        }


@dataclass
class AttackTimeline:
    """攻击链时间线

    Attributes:
        timeline_id: 时间线ID
        session_id: Beacon会话ID
        hostname: 主机名
        events: 事件列表
        start_time: 开始时间
        end_time: 结束时间
        summary: 摘要
    """
    timeline_id: str = ""
    session_id: str = ""
    hostname: str = ""
    events: List[AttackChainEvent] = field(default_factory=list)
    start_time: str = ""
    end_time: str = ""
    summary: str = ""

    def add_event(self, event: AttackChainEvent) -> None:
        """添加事件

        Args:
            event: 攻击链事件
        """
        self.events.append(event)
        if not self.start_time:
            self.start_time = event.timestamp
        self.end_time = event.timestamp

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "timeline_id": self.timeline_id,
            "session_id": self.session_id,
            "hostname": self.hostname,
            "events": [e.to_dict() for e in self.events],
            "start_time": self.start_time,
            "end_time": self.end_time,
            "summary": self.summary,
            "total_events": len(self.events),
            "techniques_used": list(set(e.technique_id for e in self.events if e.technique_id)),
        }


# =============================================================================
# 提权报告章节
# =============================================================================

@dataclass
class PrivescReportChapter:
    """提权报告章节

    Attributes:
        chapter_id: 章节ID
        title: 章节标题
        initial_privilege: 初始权限级别
        discovered_vectors: 发现的提权向量列表
        selected_exploit: 选择的利用方式
        exploit_result: 利用结果
        final_privilege: 提权后权限级别
        commands_executed: 执行的命令列表
        evidence_paths: 证据文件路径
        mitre_techniques: 涉及的MITRE ATT&CK技术
        timeline: 攻击链时间线
        recommendations: 修复建议
        generated_at: 生成时间
    """
    chapter_id: str = ""
    title: str = "Windows权限提升分析报告"
    initial_privilege: str = ""
    discovered_vectors: List[Dict[str, Any]] = field(default_factory=list)
    selected_exploit: Dict[str, Any] = field(default_factory=dict)
    exploit_result: Dict[str, Any] = field(default_factory=dict)
    final_privilege: str = ""
    commands_executed: List[Dict[str, str]] = field(default_factory=list)
    evidence_paths: List[str] = field(default_factory=list)
    mitre_techniques: List[Dict[str, str]] = field(default_factory=list)
    timeline: Optional[AttackTimeline] = None
    recommendations: List[str] = field(default_factory=list)
    generated_at: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "chapter_id": self.chapter_id,
            "title": self.title,
            "initial_privilege": self.initial_privilege,
            "discovered_vectors": self.discovered_vectors,
            "selected_exploit": self.selected_exploit,
            "exploit_result": self.exploit_result,
            "final_privilege": self.final_privilege,
            "commands_executed": self.commands_executed,
            "evidence_paths": self.evidence_paths,
            "mitre_techniques": self.mitre_techniques,
            "timeline": self.timeline.to_dict() if self.timeline else None,
            "recommendations": self.recommendations,
            "generated_at": self.generated_at,
        }

    def to_html(self) -> str:
        """生成HTML格式的提权报告章节

        Returns:
            HTML字符串
        """
        html = f"""<div class="privesc-chapter">
<h2>{self.title}</h2>

<div class="section">
<h3>1. 初始权限</h3>
<p>初始权限级别: <strong>{self.initial_privilege}</strong></p>
</div>

<div class="section">
<h3>2. 发现的提权向量</h3>
<table>
<tr><th>向量</th><th>风险评分</th><th>风险等级</th><th>利用方法</th></tr>
"""
        for v in self.discovered_vectors:
            html += f"""<tr>
<td>{v.get('title', '')}</td>
<td>{v.get('risk_score', 0)}</td>
<td>{v.get('risk_level', '')}</td>
<td>{v.get('exploit_method', '')[:100]}</td>
</tr>
"""
        html += """</table>
</div>

<div class="section">
<h3>3. 选择的利用方式</h3>
"""
        if self.selected_exploit:
            html += f"""<p><strong>利用方式:</strong> {self.selected_exploit.get('chain_name', '')}</p>
<p><strong>描述:</strong> {self.selected_exploit.get('description', '')}</p>
<p><strong>成功概率:</strong> {self.selected_exploit.get('success_probability', 0)}</p>
"""
        html += """</div>

<div class="section">
<h3>4. 利用结果</h3>
"""
        if self.exploit_result.get("success"):
            html += f"""<p style="color:green"><strong>提权成功!</strong></p>
<p>权限变化: {self.exploit_result.get('privilege_before', '')} → {self.exploit_result.get('privilege_after', '')}</p>
"""
        else:
            html += f"""<p style="color:red"><strong>提权失败</strong></p>
<p>错误: {self.exploit_result.get('error', '')}</p>
"""
        html += """</div>

<div class="section">
<h3>5. 提权后权限级别</h3>
<p>最终权限: <strong>{}</strong></p>
</div>

<div class="section">
<h3>6. MITRE ATT&CK 映射</h3>
<table>
<tr><th>技术ID</th><th>技术名称</th><th>战术阶段</th></tr>
""".format(self.final_privilege)

        for t in self.mitre_techniques:
            html += f"""<tr>
<td>{t.get('technique_id', '')}</td>
<td>{t.get('technique_name', '')}</td>
<td>{t.get('tactic', '')}</td>
</tr>
"""
        html += """</table>
</div>

<div class="section">
<h3>7. 修复建议</h3>
<ul>
"""
        for rec in self.recommendations:
            html += f"<li>{rec}</li>\n"
        html += """</ul>
</div>

<div class="footer">
<p>报告生成时间: {}</p>
</div>
</div>""".format(self.generated_at)

        return html

    def to_markdown(self) -> str:
        """生成Markdown格式的提权报告章节

        Returns:
            Markdown字符串
        """
        md = f"# {self.title}\n\n"
        md += f"## 1. 初始权限\n\n"
        md += f"初始权限级别: **{self.initial_privilege}**\n\n"

        md += f"## 2. 发现的提权向量\n\n"
        md += "| 向量 | 风险评分 | 风险等级 | 利用方法 |\n"
        md += "|------|----------|----------|----------|\n"
        for v in self.discovered_vectors:
            md += f"| {v.get('title', '')} | {v.get('risk_score', 0)} | {v.get('risk_level', '')} | {v.get('exploit_method', '')[:80]} |\n"
        md += "\n"

        md += f"## 3. 选择的利用方式\n\n"
        if self.selected_exploit:
            md += f"- **利用方式**: {self.selected_exploit.get('chain_name', '')}\n"
            md += f"- **描述**: {self.selected_exploit.get('description', '')}\n"
            md += f"- **成功概率**: {self.selected_exploit.get('success_probability', 0)}\n"
        md += "\n"

        md += f"## 4. 利用结果\n\n"
        if self.exploit_result.get("success"):
            md += f"**提权成功!**\n\n"
            md += f"权限变化: {self.exploit_result.get('privilege_before', '')} → {self.exploit_result.get('privilege_after', '')}\n\n"
        else:
            md += f"**提权失败**\n\n"
            md += f"错误: {self.exploit_result.get('error', '')}\n\n"

        md += f"## 5. 提权后权限级别\n\n"
        md += f"最终权限: **{self.final_privilege}**\n\n"

        md += f"## 6. MITRE ATT&CK 映射\n\n"
        md += "| 技术ID | 技术名称 | 战术阶段 |\n"
        md += "|--------|----------|----------|\n"
        for t in self.mitre_techniques:
            md += f"| {t.get('technique_id', '')} | {t.get('technique_name', '')} | {t.get('tactic', '')} |\n"
        md += "\n"

        md += f"## 7. 修复建议\n\n"
        for rec in self.recommendations:
            md += f"- {rec}\n"

        md += f"\n---\n*报告生成时间: {self.generated_at}*\n"
        return md


# =============================================================================
# 提权报告生成器
# =============================================================================

class PrivescReportGenerator:
    """提权报告生成器

    负责:
    1. 从分析结果生成提权报告章节
    2. MITRE ATT&CK自动映射
    3. 攻击链时间线记录
    4. 与现有ReportGenerator集成

    Attributes:
        _timelines: 时间线字典 {session_id: AttackTimeline}
        _report_chapters: 报告章节列表
        _report_generator: 外部报告生成器引用
    """

    def __init__(self) -> None:
        """初始化提权报告生成器"""
        self._timelines: Dict[str, AttackTimeline] = {}
        self._report_chapters: List[PrivescReportChapter] = []
        self._report_generator: Any = None

    def set_report_generator(self, report_generator: Any) -> None:
        """设置外部报告生成器引用

        Args:
            report_generator: ReportGenerator 实例
        """
        self._report_generator = report_generator

    # =========================================================================
    # MITRE ATT&CK 映射
    # =========================================================================

    def map_to_mitre(self, category: str) -> Optional[MITRETechnique]:
        """将检查类别映射到MITRE ATT&CK技术

        Args:
            category: 检查类别

        Returns:
            MITRE技术定义或None
        """
        return PRIVESC_MITRE_MAPPING.get(category)

    def map_findings_to_mitre(
        self, findings: List[Dict[str, Any]],
    ) -> List[Dict[str, str]]:
        """批量映射风险发现到MITRE ATT&CK

        Args:
            findings: 风险发现列表

        Returns:
            MITRE技术列表（去重）
        """
        seen: set = set()
        techniques: List[Dict[str, str]] = []

        for f in findings:
            category = f.get("category", "")
            technique = self.map_to_mitre(category)
            if technique and technique.technique_id not in seen:
                seen.add(technique.technique_id)
                techniques.append({
                    "technique_id": technique.technique_id,
                    "technique_name": technique.technique_name,
                    "tactic": technique.tactic,
                    "description": technique.description,
                })

        return techniques

    def get_mitre_summary(
        self, findings: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """获取MITRE ATT&CK映射摘要

        Args:
            findings: 风险发现列表

        Returns:
            映射摘要
        """
        techniques = self.map_findings_to_mitre(finding)
        tactics = list(set(t["tactic"] for t in techniques))

        return {
            "total_techniques": len(techniques),
            "techniques": techniques,
            "tactics": tactics,
            "tactic_counts": {t: tactics.count(t) for t in tactics},
        }

    # =========================================================================
    # 攻击链时间线
    # =========================================================================

    def create_timeline(self, session_id: str, hostname: str = "") -> AttackTimeline:
        """创建攻击链时间线

        Args:
            session_id: Beacon会话ID
            hostname: 主机名

        Returns:
            攻击链时间线
        """
        import uuid

        timeline = AttackTimeline(
            timeline_id=str(uuid.uuid4())[:12],
            session_id=session_id,
            hostname=hostname,
        )
        self._timelines[session_id] = timeline
        return timeline

    def record_event(
        self,
        session_id: str,
        phase: str,
        description: str,
        outcome: str = "info",
        category: str = "",
        details: Optional[Dict[str, Any]] = None,
    ) -> Optional[AttackChainEvent]:
        """记录攻击链事件

        Args:
            session_id: Beacon会话ID
            phase: 攻击阶段
            description: 事件描述
            outcome: 结果
            category: 关联的检查类别
            details: 详细信息

        Returns:
            攻击链事件
        """
        import uuid

        timeline = self._timelines.get(session_id)
        if not timeline:
            timeline = self.create_timeline(session_id)

        technique = self.map_to_mitre(category)
        technique_id = technique.technique_id if technique else ""

        event = AttackChainEvent(
            event_id=str(uuid.uuid4())[:12],
            timestamp=datetime.now().isoformat(),
            phase=phase,
            technique_id=technique_id,
            description=description,
            outcome=outcome,
            details=details or {},
        )
        timeline.add_event(event)
        return event

    def get_timeline(self, session_id: str) -> Optional[AttackTimeline]:
        """获取攻击链时间线

        Args:
            session_id: Beacon会话ID

        Returns:
            攻击链时间线或None
        """
        return self._timelines.get(session_id)

    # =========================================================================
    # 报告章节生成
    # =========================================================================

    def generate_chapter(
        self,
        session_id: str,
        analysis_result: Optional[Dict[str, Any]] = None,
        exploit_result: Optional[Dict[str, Any]] = None,
        initial_privilege: str = "",
        final_privilege: str = "",
    ) -> PrivescReportChapter:
        """生成提权报告章节

        Args:
            session_id: Beacon会话ID
            analysis_result: 分析结果
            exploit_result: 利用结果
            initial_privilege: 初始权限
            final_privilege: 最终权限

        Returns:
            提权报告章节
        """
        import uuid

        chapter = PrivescReportChapter(
            chapter_id=str(uuid.uuid4())[:12],
            initial_privilege=initial_privilege or "未知",
            final_privilege=final_privilege or "未知",
            generated_at=datetime.now().isoformat(),
        )

        if analysis_result:
            findings = analysis_result.get("findings", [])
            chapter.discovered_vectors = [
                {
                    "title": f.get("title", ""),
                    "risk_score": f.get("risk_score", 0),
                    "risk_level": f.get("risk_level", ""),
                    "exploit_method": f.get("exploit_method", ""),
                    "category": f.get("category", ""),
                }
                for f in findings
                if f.get("risk_score", 0) >= 30
            ]
            chapter.mitre_techniques = self.map_findings_to_mitre(findings)

        if exploit_result:
            chapter.exploit_result = exploit_result
            chapter.selected_exploit = {
                "chain_name": exploit_result.get("chain_id", ""),
                "description": exploit_result.get("status", ""),
                "success_probability": 1.0 if exploit_result.get("success") else 0.0,
            }
            if exploit_result.get("steps_results"):
                for step in exploit_result["steps_results"]:
                    chapter.commands_executed.append({
                        "command": step.get("command", ""),
                        "output": step.get("output", "")[:500],
                    })

        timeline = self._timelines.get(session_id)
        if timeline:
            chapter.timeline = timeline

        chapter.recommendations = self._generate_recommendations(chapter)

        self._report_chapters.append(chapter)
        return chapter

    def _generate_recommendations(
        self, chapter: PrivescReportChapter,
    ) -> List[str]:
        """生成修复建议

        Args:
            chapter: 报告章节

        Returns:
            修复建议列表
        """
        recommendations: List[str] = []

        categories = {v.get("category", "") for v in chapter.discovered_vectors}

        if "always_install_elevated" in categories:
            recommendations.append(
                "禁用AlwaysInstallElevated: 设置注册表键 "
                "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer\\AlwaysInstallElevated = 0"
            )

        if "unquoted_service_path" in categories:
            recommendations.append(
                "修复未引号服务路径: 在所有包含空格的服务路径两侧添加引号"
            )

        if "writable_service" in categories:
            recommendations.append(
                "限制服务权限: 确保仅SYSTEM和管理员可修改服务配置"
            )

        if "cve_patch_missing" in categories:
            recommendations.append(
                "及时安装安全更新: 确保所有关键安全补丁已安装"
            )

        if "vulnerable_driver" in categories:
            recommendations.append(
                "启用驱动黑名单: 通过WDAC或Driver Blocklist阻止已知漏洞驱动加载"
            )

        if "token_privilege" in categories:
            recommendations.append(
                "移除不必要的特权令牌: 对服务账户移除SeImpersonatePrivilege等高风险特权"
            )

        if "uac_config" in categories:
            recommendations.append(
                "启用UAC最高级别: 设置 "
                "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\EnableLUA = 1"
            )

        if "scheduled_task" in categories:
            recommendations.append(
                "审计计划任务权限: 确保计划任务执行路径仅管理员可写"
            )

        if "credential_file" in categories:
            recommendations.append(
                "清理敏感文件: 删除Unattend.xml、sysprep.inf等自动部署残留文件"
            )

        if "dll_hijack" in categories:
            recommendations.append(
                "启用Safe DLL Search Mode: 防止DLL搜索路径劫持"
            )

        if not recommendations:
            recommendations.append("定期进行安全审计和权限检查")
            recommendations.append("遵循最小权限原则配置服务账户")

        return recommendations

    # =========================================================================
    # 与外部报告生成器集成
    # =========================================================================

    def export_to_report(
        self,
        session_id: str,
        format: str = "json",
    ) -> Optional[str]:
        """导出提权报告到外部报告生成器

        Args:
            session_id: Beacon会话ID
            format: 导出格式 (json/html/markdown)

        Returns:
            导出的报告内容或None
        """
        chapter = None
        for c in reversed(self._report_chapters):
            if c.timeline and c.timeline.session_id == session_id:
                chapter = c
                break

        if not chapter:
            logger.warning(f"未找到会话 {session_id} 的报告章节")
            return None

        if format == "html":
            return chapter.to_html()
        elif format == "markdown":
            return chapter.to_markdown()
        else:
            return json.dumps(chapter.to_dict(), ensure_ascii=False, indent=2)

    def get_all_chapters(self) -> List[Dict[str, Any]]:
        """获取所有报告章节

        Returns:
            报告章节列表
        """
        return [c.to_dict() for c in self._report_chapters]

    def get_statistics(self) -> Dict[str, Any]:
        """获取报告统计信息

        Returns:
            统计信息
        """
        total_vectors = sum(
            len(c.discovered_vectors) for c in self._report_chapters
        )
        successful = sum(
            1 for c in self._report_chapters
            if c.exploit_result.get("success")
        )

        return {
            "total_chapters": len(self._report_chapters),
            "total_timelines": len(self._timelines),
            "total_discovered_vectors": total_vectors,
            "successful_exploits": successful,
            "success_rate": f"{successful / max(len(self._report_chapters), 1) * 100:.1f}%",
            "generated_at": datetime.now().isoformat(),
        }


# =============================================================================
# 全局单例
# =============================================================================

_privesc_report_generator: Optional[PrivescReportGenerator] = None


def get_privesc_report_generator() -> PrivescReportGenerator:
    """获取提权报告生成器全局单例

    Returns:
        PrivescReportGenerator 实例
    """
    global _privesc_report_generator
    if _privesc_report_generator is None:
        _privesc_report_generator = PrivescReportGenerator()
    return _privesc_report_generator


__all__ = [
    "PrivescReportGenerator",
    "PrivescReportChapter",
    "AttackTimeline",
    "AttackChainEvent",
    "MITRETechnique",
    "PRIVESC_MITRE_MAPPING",
    "get_privesc_report_generator",
]
