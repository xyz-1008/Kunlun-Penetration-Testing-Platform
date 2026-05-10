"""
Windows/Linux提权辅助套件 - 审计日志与合规记录模块
==================================================
完整记录所有提权操作（收集、利用、持久化、清理），支持导出合规报告。

核心能力:
    1. 全量操作审计 - 记录所有提权相关操作
    2. 操作授权确认 - 利用操作前强制授权确认
    3. 合规报告导出 - 等保2.0要求的操作记录格式
    4. 团队协同共享 - 操作记录一键分享团队作战室

Author: 昆仑安全实验室
License: Internal Use Only
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import sqlite3
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# =============================================================================
# 枚举与数据模型
# =============================================================================

class AuditEventType(str, Enum):
    """审计事件类型"""
    COLLECTION = "collection"
    ANALYSIS = "analysis"
    EXPLOIT = "exploit"
    PERSISTENCE = "persistence"
    CLEANUP = "cleanup"
    AUTHORIZATION = "authorization"
    SHARING = "sharing"
    LATERAL_MOVEMENT = "lateral_movement"


class AuditSeverity(str, Enum):
    """审计事件严重性"""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AuthorizationStatus(str, Enum):
    """授权状态"""
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"


class ComplianceStandard(str, Enum):
    """合规标准"""
    DJCP_2_0 = "djcp_2_0"
    ISO_27001 = "iso_27001"
    NIST_CSF = "nist_csf"
    PCI_DSS = "pci_dss"


@dataclass
class AuditEvent:
    """审计事件

    Attributes:
        event_id: 事件唯一ID
        event_type: 事件类型
        severity: 严重性
        timestamp: 时间戳
        operator: 操作者
        session_id: 会话ID
        target_host: 目标主机
        action: 操作描述
        details: 详细信息
        result: 操作结果
        risk_assessment: 风险评估
        authorization_id: 授权ID
        tags: 标签列表
    """
    event_id: str = ""
    event_type: AuditEventType = AuditEventType.COLLECTION
    severity: AuditSeverity = AuditSeverity.INFO
    timestamp: str = ""
    operator: str = ""
    session_id: str = ""
    target_host: str = ""
    action: str = ""
    details: str = ""
    result: str = ""
    risk_assessment: str = ""
    authorization_id: str = ""
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典

        Returns:
            事件字典
        """
        return {
            "event_id": self.event_id,
            "event_type": self.event_type.value,
            "severity": self.severity.value,
            "timestamp": self.timestamp,
            "operator": self.operator,
            "session_id": self.session_id,
            "target_host": self.target_host,
            "action": self.action,
            "details": self.details,
            "result": self.result,
            "risk_assessment": self.risk_assessment,
            "authorization_id": self.authorization_id,
            "tags": self.tags,
        }


@dataclass
class AuthorizationRequest:
    """授权请求

    Attributes:
        auth_id: 授权唯一ID
        operator: 操作者
        action: 请求的操作
        target: 目标
        reason: 操作理由
        risk_level: 风险等级
        status: 授权状态
        requested_at: 请求时间
        approved_at: 批准时间
        approved_by: 批准者
        expires_at: 过期时间
    """
    auth_id: str = ""
    operator: str = ""
    action: str = ""
    target: str = ""
    reason: str = ""
    risk_level: str = "medium"
    status: AuthorizationStatus = AuthorizationStatus.PENDING
    requested_at: str = ""
    approved_at: str = ""
    approved_by: str = ""
    expires_at: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典

        Returns:
            授权字典
        """
        return {
            "auth_id": self.auth_id,
            "operator": self.operator,
            "action": self.action,
            "target": self.target,
            "reason": self.reason,
            "risk_level": self.risk_level,
            "status": self.status.value,
            "requested_at": self.requested_at,
            "approved_at": self.approved_at,
            "approved_by": self.approved_by,
            "expires_at": self.expires_at,
        }


@dataclass
class ComplianceReport:
    """合规报告

    Attributes:
        report_id: 报告唯一ID
        standard: 合规标准
        generated_at: 生成时间
        generated_by: 生成者
        period_start: 统计起始时间
        period_end: 统计结束时间
        total_events: 总事件数
        events_by_type: 按类型统计
        events_by_severity: 按严重性统计
        authorization_summary: 授权摘要
        risk_summary: 风险摘要
        recommendations: 建议列表
        events: 事件列表
    """
    report_id: str = ""
    standard: ComplianceStandard = ComplianceStandard.DJCP_2_0
    generated_at: str = ""
    generated_by: str = ""
    period_start: str = ""
    period_end: str = ""
    total_events: int = 0
    events_by_type: Dict[str, int] = field(default_factory=dict)
    events_by_severity: Dict[str, int] = field(default_factory=dict)
    authorization_summary: Dict[str, Any] = field(default_factory=dict)
    risk_summary: Dict[str, Any] = field(default_factory=dict)
    recommendations: List[str] = field(default_factory=list)
    events: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典

        Returns:
            报告字典
        """
        return {
            "report_id": self.report_id,
            "standard": self.standard.value,
            "generated_at": self.generated_at,
            "generated_by": self.generated_by,
            "period_start": self.period_start,
            "period_end": self.period_end,
            "total_events": self.total_events,
            "events_by_type": self.events_by_type,
            "events_by_severity": self.events_by_severity,
            "authorization_summary": self.authorization_summary,
            "risk_summary": self.risk_summary,
            "recommendations": self.recommendations,
            "events": self.events,
        }


# =============================================================================
# SQLite审计日志存储
# =============================================================================

class AuditLogStore:
    """SQLite审计日志存储

    Attributes:
        _db_path: 数据库路径
        _conn: 数据库连接
    """

    def __init__(self, db_path: Optional[str] = None) -> None:
        """初始化审计日志存储

        Args:
            db_path: 数据库路径
        """
        self._db_path = db_path or os.path.join(
            os.path.expanduser("~"), ".kunlun", "privesc_audit.db",
        )
        self._conn: Optional[sqlite3.Connection] = None
        self._init_db()

    def _init_db(self) -> None:
        """初始化数据库表"""
        os.makedirs(os.path.dirname(self._db_path) or ".", exist_ok=True)

        self._conn = sqlite3.connect(self._db_path)
        self._conn.row_factory = sqlite3.Row

        cursor = self._conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_events (
                event_id TEXT PRIMARY KEY,
                event_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                operator TEXT NOT NULL,
                session_id TEXT NOT NULL,
                target_host TEXT NOT NULL,
                action TEXT NOT NULL,
                details TEXT,
                result TEXT,
                risk_assessment TEXT,
                authorization_id TEXT,
                tags TEXT
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS authorization_requests (
                auth_id TEXT PRIMARY KEY,
                operator TEXT NOT NULL,
                action TEXT NOT NULL,
                target TEXT NOT NULL,
                reason TEXT,
                risk_level TEXT NOT NULL,
                status TEXT NOT NULL,
                requested_at TEXT NOT NULL,
                approved_at TEXT,
                approved_by TEXT,
                expires_at TEXT
            )
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_events_timestamp
            ON audit_events(timestamp)
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_events_session
            ON audit_events(session_id)
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_events_operator
            ON audit_events(operator)
        """)

        self._conn.commit()

    def insert_event(self, event: AuditEvent) -> bool:
        """插入审计事件

        Args:
            event: 审计事件

        Returns:
            是否成功
        """
        try:
            cursor = self._conn.cursor()
            cursor.execute(
                """
                INSERT OR REPLACE INTO audit_events
                (event_id, event_type, severity, timestamp, operator,
                 session_id, target_host, action, details, result,
                 risk_assessment, authorization_id, tags)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.event_id,
                    event.event_type.value,
                    event.severity.value,
                    event.timestamp,
                    event.operator,
                    event.session_id,
                    event.target_host,
                    event.action,
                    event.details,
                    event.result,
                    event.risk_assessment,
                    event.authorization_id,
                    json.dumps(event.tags, ensure_ascii=False),
                ),
            )
            self._conn.commit()
            return True

        except Exception as e:
            logger.error(f"插入审计事件失败: {e}")
            return False

    def insert_authorization(self, auth: AuthorizationRequest) -> bool:
        """插入授权请求

        Args:
            auth: 授权请求

        Returns:
            是否成功
        """
        try:
            cursor = self._conn.cursor()
            cursor.execute(
                """
                INSERT OR REPLACE INTO authorization_requests
                (auth_id, operator, action, target, reason, risk_level,
                 status, requested_at, approved_at, approved_by, expires_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    auth.auth_id,
                    auth.operator,
                    auth.action,
                    auth.target,
                    auth.reason,
                    auth.risk_level,
                    auth.status.value,
                    auth.requested_at,
                    auth.approved_at,
                    auth.approved_by,
                    auth.expires_at,
                ),
            )
            self._conn.commit()
            return True

        except Exception as e:
            logger.error(f"插入授权请求失败: {e}")
            return False

    def query_events(
        self,
        session_id: Optional[str] = None,
        operator: Optional[str] = None,
        event_type: Optional[AuditEventType] = None,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        limit: int = 100,
    ) -> List[AuditEvent]:
        """查询审计事件

        Args:
            session_id: 会话ID过滤
            operator: 操作者过滤
            event_type: 事件类型过滤
            start_time: 起始时间
            end_time: 结束时间
            limit: 返回数量限制

        Returns:
            审计事件列表
        """
        try:
            query = "SELECT * FROM audit_events WHERE 1=1"
            params: List[Any] = []

            if session_id:
                query += " AND session_id = ?"
                params.append(session_id)

            if operator:
                query += " AND operator = ?"
                params.append(operator)

            if event_type:
                query += " AND event_type = ?"
                params.append(event_type.value)

            if start_time:
                query += " AND timestamp >= ?"
                params.append(start_time)

            if end_time:
                query += " AND timestamp <= ?"
                params.append(end_time)

            query += " ORDER BY timestamp DESC LIMIT ?"
            params.append(limit)

            cursor = self._conn.cursor()
            cursor.execute(query, params)

            rows = cursor.fetchall()
            events = []

            for row in rows:
                tags_str = row["tags"] or "[]"
                try:
                    tags = json.loads(tags_str)
                except json.JSONDecodeError:
                    tags = []

                event = AuditEvent(
                    event_id=row["event_id"],
                    event_type=AuditEventType(row["event_type"]),
                    severity=AuditSeverity(row["severity"]),
                    timestamp=row["timestamp"],
                    operator=row["operator"],
                    session_id=row["session_id"],
                    target_host=row["target_host"],
                    action=row["action"],
                    details=row["details"] or "",
                    result=row["result"] or "",
                    risk_assessment=row["risk_assessment"] or "",
                    authorization_id=row["authorization_id"] or "",
                    tags=tags,
                )
                events.append(event)

            return events

        except Exception as e:
            logger.error(f"查询审计事件失败: {e}")
            return []

    def get_statistics(
        self,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
    ) -> Dict[str, Any]:
        """获取审计统计

        Args:
            start_time: 起始时间
            end_time: 结束时间

        Returns:
            统计信息
        """
        try:
            query = "SELECT * FROM audit_events WHERE 1=1"
            params: List[Any] = []

            if start_time:
                query += " AND timestamp >= ?"
                params.append(start_time)

            if end_time:
                query += " AND timestamp <= ?"
                params.append(end_time)

            cursor = self._conn.cursor()
            cursor.execute(query, params)

            rows = cursor.fetchall()

            events_by_type: Dict[str, int] = {}
            events_by_severity: Dict[str, int] = {}

            for row in rows:
                event_type = row["event_type"]
                severity = row["severity"]

                events_by_type[event_type] = events_by_type.get(event_type, 0) + 1
                events_by_severity[severity] = events_by_severity.get(severity, 0) + 1

            return {
                "total_events": len(rows),
                "events_by_type": events_by_type,
                "events_by_severity": events_by_severity,
            }

        except Exception as e:
            logger.error(f"获取审计统计失败: {e}")
            return {"total_events": 0, "events_by_type": {}, "events_by_severity": {}}

    def close(self) -> None:
        """关闭数据库连接"""
        if self._conn:
            self._conn.close()
            self._conn = None


# =============================================================================
# 授权管理器
# =============================================================================

class AuthorizationManager:
    """操作授权管理器

    利用操作前强制弹出授权确认窗口。

    Attributes:
        _store: 审计日志存储
        _pending_auths: 待处理授权 {auth_id: AuthorizationRequest}
        _auth_callbacks: 授权回调列表
    """

    def __init__(self, store: AuditLogStore) -> None:
        """初始化授权管理器

        Args:
            store: 审计日志存储
        """
        self._store = store
        self._pending_auths: Dict[str, AuthorizationRequest] = {}
        self._auth_callbacks: List[Callable[[AuthorizationRequest], None]] = []

    def on_authorization(
        self, callback: Callable[[AuthorizationRequest], None],
    ) -> None:
        """注册授权回调

        Args:
            callback: 回调函数
        """
        self._auth_callbacks.append(callback)

    def request_authorization(
        self,
        operator: str,
        action: str,
        target: str,
        reason: str = "",
        risk_level: str = "medium",
        ttl_seconds: int = 300,
    ) -> AuthorizationRequest:
        """请求操作授权

        Args:
            operator: 操作者
            action: 操作描述
            target: 目标
            reason: 操作理由
            risk_level: 风险等级
            ttl_seconds: 授权有效期（秒）

        Returns:
            授权请求
        """
        import uuid

        auth_id = str(uuid.uuid4())[:12]
        now = datetime.now().isoformat()

        auth = AuthorizationRequest(
            auth_id=auth_id,
            operator=operator,
            action=action,
            target=target,
            reason=reason,
            risk_level=risk_level,
            status=AuthorizationStatus.PENDING,
            requested_at=now,
            expires_at=datetime.fromtimestamp(
                time.time() + ttl_seconds,
            ).isoformat(),
        )

        self._pending_auths[auth_id] = auth
        self._store.insert_authorization(auth)

        for cb in self._auth_callbacks:
            try:
                cb(auth)
            except Exception:
                pass

        return auth

    def approve_authorization(
        self,
        auth_id: str,
        approved_by: str,
    ) -> Optional[AuthorizationRequest]:
        """批准授权

        Args:
            auth_id: 授权ID
            approved_by: 批准者

        Returns:
            授权请求或None
        """
        auth = self._pending_auths.get(auth_id)
        if not auth:
            return None

        auth.status = AuthorizationStatus.APPROVED
        auth.approved_at = datetime.now().isoformat()
        auth.approved_by = approved_by

        self._store.insert_authorization(auth)

        return auth

    def deny_authorization(
        self,
        auth_id: str,
        denied_by: str,
    ) -> Optional[AuthorizationRequest]:
        """拒绝授权

        Args:
            auth_id: 授权ID
            denied_by: 拒绝者

        Returns:
            授权请求或None
        """
        auth = self._pending_auths.get(auth_id)
        if not auth:
            return None

        auth.status = AuthorizationStatus.DENIED
        auth.approved_by = denied_by

        self._store.insert_authorization(auth)

        return auth

    def is_authorized(self, auth_id: str) -> bool:
        """检查是否已授权

        Args:
            auth_id: 授权ID

        Returns:
            是否已授权
        """
        auth = self._pending_auths.get(auth_id)
        if not auth:
            return False

        if auth.status != AuthorizationStatus.APPROVED:
            return False

        if auth.expires_at:
            try:
                expiry = datetime.fromisoformat(auth.expires_at)
                if datetime.now() > expiry:
                    auth.status = AuthorizationStatus.EXPIRED
                    self._store.insert_authorization(auth)
                    return False
            except ValueError:
                pass

        return True

    def get_pending_auths(self) -> List[AuthorizationRequest]:
        """获取待处理授权列表

        Returns:
            授权请求列表
        """
        return [
            auth for auth in self._pending_auths.values()
            if auth.status == AuthorizationStatus.PENDING
        ]


# =============================================================================
# 团队协同共享
# =============================================================================

class TeamCollaboration:
    """团队协同利用模块

    一人发现提权向量后可一键分享到团队作战室。

    Attributes:
        _shared_findings: 已分享的发现列表
        _share_callbacks: 分享回调列表
    """

    def __init__(self) -> None:
        """初始化团队协同模块"""
        self._shared_findings: List[Dict[str, Any]] = []
        self._share_callbacks: List[Callable[[Dict[str, Any]], None]] = []

    def on_share(
        self, callback: Callable[[Dict[str, Any]], None],
    ) -> None:
        """注册分享回调

        Args:
            callback: 回调函数
        """
        self._share_callbacks.append(callback)

    def share_finding(
        self,
        finding: Dict[str, Any],
        operator: str,
        session_id: str,
        team_channel: str = "default",
    ) -> Dict[str, Any]:
        """分享提权发现到团队

        Args:
            finding: 风险发现
            operator: 操作者
            session_id: 会话ID
            team_channel: 团队频道

        Returns:
            分享结果
        """
        shared_finding = {
            "finding_id": finding.get("finding_id", ""),
            "category": finding.get("category", ""),
            "risk_score": finding.get("risk_score", 0),
            "description": finding.get("description", ""),
            "exploit_method": finding.get("exploit_method", ""),
            "shared_by": operator,
            "shared_at": datetime.now().isoformat(),
            "source_session": session_id,
            "team_channel": team_channel,
        }

        self._shared_findings.append(shared_finding)

        for cb in self._share_callbacks:
            try:
                cb(shared_finding)
            except Exception:
                pass

        return {
            "success": True,
            "shared_finding": shared_finding,
        }

    def get_shared_findings(
        self,
        team_channel: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """获取已分享的发现

        Args:
            team_channel: 团队频道过滤

        Returns:
            分享的发现列表
        """
        findings = self._shared_findings

        if team_channel:
            findings = [
                f for f in findings
                if f.get("team_channel") == team_channel
            ]

        return findings

    def reuse_shared_finding(
        self,
        finding_id: str,
        operator: str,
    ) -> Optional[Dict[str, Any]]:
        """复用已分享的发现

        Args:
            finding_id: 发现ID
            operator: 操作者

        Returns:
            分享的发现或None
        """
        for finding in self._shared_findings:
            if finding.get("finding_id") == finding_id:
                finding["reused_by"] = operator
                finding["reused_at"] = datetime.now().isoformat()
                return finding

        return None


# =============================================================================
# 合规报告生成器
# =============================================================================

class ComplianceReportGenerator:
    """合规报告生成器

    支持等保2.0、ISO 27001、NIST CSF等标准。

    Attributes:
        _store: 审计日志存储
    """

    def __init__(self, store: AuditLogStore) -> None:
        """初始化合规报告生成器

        Args:
            store: 审计日志存储
        """
        self._store = store

    def generate_report(
        self,
        standard: ComplianceStandard = ComplianceStandard.DJCP_2_0,
        generated_by: str = "",
        period_start: Optional[str] = None,
        period_end: Optional[str] = None,
    ) -> ComplianceReport:
        """生成合规报告

        Args:
            standard: 合规标准
            generated_by: 生成者
            period_start: 统计起始时间
            period_end: 统计结束时间

        Returns:
            合规报告
        """
        import uuid

        stats = self._store.get_statistics(period_start, period_end)
        events = self._store.query_events(
            start_time=period_start,
            end_time=period_end,
            limit=1000,
        )

        report = ComplianceReport(
            report_id=str(uuid.uuid4())[:12],
            standard=standard,
            generated_at=datetime.now().isoformat(),
            generated_by=generated_by,
            period_start=period_start or "",
            period_end=period_end or "",
            total_events=stats["total_events"],
            events_by_type=stats["events_by_type"],
            events_by_severity=stats["events_by_severity"],
            recommendations=self._generate_recommendations(stats, standard),
            events=[e.to_dict() for e in events],
        )

        return report

    def export_report(
        self,
        report: ComplianceReport,
        output_path: str,
        format: str = "json",
    ) -> bool:
        """导出合规报告

        Args:
            report: 合规报告
            output_path: 输出路径
            format: 输出格式 (json/csv)

        Returns:
            是否成功
        """
        try:
            os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)

            if format == "json":
                with open(output_path, "w", encoding="utf-8") as f:
                    json.dump(report.to_dict(), f, indent=2, ensure_ascii=False)

            elif format == "csv":
                import csv

                with open(output_path, "w", newline="", encoding="utf-8") as f:
                    writer = csv.DictWriter(
                        f,
                        fieldnames=[
                            "event_id", "event_type", "severity", "timestamp",
                            "operator", "session_id", "target_host", "action",
                            "details", "result", "risk_assessment",
                            "authorization_id",
                        ],
                    )
                    writer.writeheader()

                    for event in report.events:
                        writer.writerow({
                            "event_id": event.get("event_id", ""),
                            "event_type": event.get("event_type", ""),
                            "severity": event.get("severity", ""),
                            "timestamp": event.get("timestamp", ""),
                            "operator": event.get("operator", ""),
                            "session_id": event.get("session_id", ""),
                            "target_host": event.get("target_host", ""),
                            "action": event.get("action", ""),
                            "details": event.get("details", ""),
                            "result": event.get("result", ""),
                            "risk_assessment": event.get("risk_assessment", ""),
                            "authorization_id": event.get("authorization_id", ""),
                        })

            return True

        except Exception as e:
            logger.error(f"导出合规报告失败: {e}")
            return False

    def _generate_recommendations(
        self,
        stats: Dict[str, Any],
        standard: ComplianceStandard,
    ) -> List[str]:
        """生成合规建议

        Args:
            stats: 统计信息
            standard: 合规标准

        Returns:
            建议列表
        """
        recommendations = []

        if standard == ComplianceStandard.DJCP_2_0:
            recommendations.extend(self._djcp_recommendations(stats))
        elif standard == ComplianceStandard.ISO_27001:
            recommendations.extend(self._iso_recommendations(stats))
        elif standard == ComplianceStandard.NIST_CSF:
            recommendations.extend(self._nist_recommendations(stats))

        return recommendations

    def _djcp_recommendations(self, stats: Dict[str, Any]) -> List[str]:
        """等保2.0建议

        Args:
            stats: 统计信息

        Returns:
            建议列表
        """
        recommendations = [
            "确保所有提权操作均有授权记录",
            "定期审计提权操作日志",
            "限制高权限账户的使用范围",
        ]

        critical_count = stats.get("events_by_severity", {}).get("critical", 0)
        if critical_count > 0:
            recommendations.append(
                f"发现 {critical_count} 个严重操作事件，建议立即审查",
            )

        exploit_count = stats.get("events_by_type", {}).get("exploit", 0)
        if exploit_count > 0:
            recommendations.append(
                f"发现 {exploit_count} 次利用操作，建议评估利用必要性",
            )

        return recommendations

    def _iso_recommendations(self, stats: Dict[str, Any]) -> List[str]:
        """ISO 27001建议

        Args:
            stats: 统计信息

        Returns:
            建议列表
        """
        return [
            "确保操作符合ISO 27001 A.12.4日志记录要求",
            "定期审查特权操作记录",
            "建立操作审批流程",
        ]

    def _nist_recommendations(self, stats: Dict[str, Any]) -> List[str]:
        """NIST CSF建议

        Args:
            stats: 统计信息

        Returns:
            建议列表
        """
        return [
            "确保符合NIST CSF DE.CM-8持续监控要求",
            "建立异常操作检测机制",
            "定期评估操作风险",
        ]


# =============================================================================
# 主审计模块
# =============================================================================

class PrivescAuditModule:
    """提权审计模块

    整合审计日志、授权管理、团队协同、合规报告。

    Attributes:
        _store: 审计日志存储
        _auth_manager: 授权管理器
        _collaboration: 团队协同模块
        _report_generator: 合规报告生成器
    """

    def __init__(
        self,
        db_path: Optional[str] = None,
    ) -> None:
        """初始化提权审计模块

        Args:
            db_path: 数据库路径
        """
        self._store = AuditLogStore(db_path)
        self._auth_manager = AuthorizationManager(self._store)
        self._collaboration = TeamCollaboration()
        self._report_generator = ComplianceReportGenerator(self._store)

    @property
    def store(self) -> AuditLogStore:
        """获取审计日志存储

        Returns:
            审计日志存储
        """
        return self._store

    @property
    def auth_manager(self) -> AuthorizationManager:
        """获取授权管理器

        Returns:
            授权管理器
        """
        return self._auth_manager

    @property
    def collaboration(self) -> TeamCollaboration:
        """获取团队协同模块

        Returns:
            团队协同模块
        """
        return self._collaboration

    @property
    def report_generator(self) -> ComplianceReportGenerator:
        """获取合规报告生成器

        Returns:
            合规报告生成器
        """
        return self._report_generator

    async def log_event(
        self,
        event_type: AuditEventType,
        operator: str,
        session_id: str,
        target_host: str,
        action: str,
        severity: AuditSeverity = AuditSeverity.INFO,
        details: str = "",
        result: str = "",
        risk_assessment: str = "",
        authorization_id: str = "",
        tags: Optional[List[str]] = None,
    ) -> Optional[AuditEvent]:
        """记录审计事件

        Args:
            event_type: 事件类型
            operator: 操作者
            session_id: 会话ID
            target_host: 目标主机
            action: 操作描述
            severity: 严重性
            details: 详细信息
            result: 操作结果
            risk_assessment: 风险评估
            authorization_id: 授权ID
            tags: 标签列表

        Returns:
            审计事件或None
        """
        import uuid

        event = AuditEvent(
            event_id=str(uuid.uuid4()),
            event_type=event_type,
            severity=severity,
            timestamp=datetime.now().isoformat(),
            operator=operator,
            session_id=session_id,
            target_host=target_host,
            action=action,
            details=details,
            result=result,
            risk_assessment=risk_assessment,
            authorization_id=authorization_id,
            tags=tags or [],
        )

        if self._store.insert_event(event):
            return event

        return None

    async def request_and_log_exploit(
        self,
        operator: str,
        session_id: str,
        target_host: str,
        exploit_method: str,
        reason: str = "",
        risk_level: str = "high",
    ) -> Dict[str, Any]:
        """请求利用授权并记录

        Args:
            operator: 操作者
            session_id: 会话ID
            target_host: 目标主机
            exploit_method: 利用方法
            reason: 操作理由
            risk_level: 风险等级

        Returns:
            授权和记录结果
        """
        auth = self._auth_manager.request_authorization(
            operator=operator,
            action=f"利用提权: {exploit_method}",
            target=target_host,
            reason=reason,
            risk_level=risk_level,
        )

        await self.log_event(
            event_type=AuditEventType.AUTHORIZATION,
            operator=operator,
            session_id=session_id,
            target_host=target_host,
            action=f"请求利用授权: {exploit_method}",
            severity=AuditSeverity.HIGH,
            details=reason,
            authorization_id=auth.auth_id,
            tags=["authorization", "exploit"],
        )

        return {
            "auth": auth.to_dict(),
            "message": "授权请求已创建，等待批准",
        }

    def generate_compliance_report(
        self,
        standard: ComplianceStandard = ComplianceStandard.DJCP_2_0,
        generated_by: str = "",
        period_start: Optional[str] = None,
        period_end: Optional[str] = None,
    ) -> ComplianceReport:
        """生成合规报告

        Args:
            standard: 合规标准
            generated_by: 生成者
            period_start: 统计起始时间
            period_end: 统计结束时间

        Returns:
            合规报告
        """
        return self._report_generator.generate_report(
            standard=standard,
            generated_by=generated_by,
            period_start=period_start,
            period_end=period_end,
        )

    def close(self) -> None:
        """关闭审计模块"""
        self._store.close()


# =============================================================================
# 全局单例
# =============================================================================

_audit_module: Optional[PrivescAuditModule] = None


def get_audit_module(
    db_path: Optional[str] = None,
) -> PrivescAuditModule:
    """获取提权审计模块全局单例

    Args:
        db_path: 数据库路径

    Returns:
        PrivescAuditModule 实例
    """
    global _audit_module
    if _audit_module is None:
        _audit_module = PrivescAuditModule(db_path)
    return _audit_module


__all__ = [
    "PrivescAuditModule",
    "AuditLogStore",
    "AuthorizationManager",
    "TeamCollaboration",
    "ComplianceReportGenerator",
    "AuditEvent",
    "AuthorizationRequest",
    "ComplianceReport",
    "AuditEventType",
    "AuditSeverity",
    "AuthorizationStatus",
    "ComplianceStandard",
    "get_audit_module",
]
