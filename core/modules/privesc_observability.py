"""
Windows/Linux提权辅助套件 - 可观测性与诊断模块
===================================================
全链路追踪、实时诊断面板、性能基准测试。

核心能力:
    1. 全链路追踪 - Trace ID贯穿全流程、OpenTelemetry格式导出
    2. 实时诊断面板 - 活跃任务监控、错误聚合、Top失败原因
    3. 性能基准测试 - CPU/内存/IO统计、历史版本对比

Author: 昆仑安全实验室
License: Internal Use Only
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Callable, Coroutine, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# =============================================================================
# 枚举与数据模型
# =============================================================================

class SpanStatus(str, Enum):
    """Span状态"""
    OK = "ok"
    ERROR = "error"
    UNSET = "unset"


class DiagnosticLevel(str, Enum):
    """诊断级别"""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


@dataclass
class Span:
    """追踪Span

    Attributes:
        span_id: Span ID
        trace_id: Trace ID
        parent_span_id: 父Span ID
        name: Span名
        operation: 操作名
        start_time: 开始时间
        end_time: 结束时间
        duration_ms: 耗时（毫秒）
        status: 状态
        attributes: 属性
        events: 事件
        error: 错误信息
    """
    span_id: str = ""
    trace_id: str = ""
    parent_span_id: str = ""
    name: str = ""
    operation: str = ""
    start_time: float = 0.0
    end_time: float = 0.0
    duration_ms: float = 0.0
    status: SpanStatus = SpanStatus.UNSET
    attributes: Dict[str, Any] = field(default_factory=dict)
    events: List[Dict[str, Any]] = field(default_factory=list)
    error: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "span_id": self.span_id,
            "trace_id": self.trace_id,
            "parent_span_id": self.parent_span_id,
            "name": self.name,
            "operation": self.operation,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration_ms": self.duration_ms,
            "status": self.status.value,
            "attributes": self.attributes,
            "events": self.events,
            "error": self.error,
        }

    def to_opentelemetry(self) -> Dict[str, Any]:
        """转换为OpenTelemetry格式

        Returns:
            OpenTelemetry格式
        """
        return {
            "traceId": self.trace_id,
            "spanId": self.span_id,
            "parentSpanId": self.parent_span_id or None,
            "name": self.name,
            "kind": "INTERNAL",
            "startTimeUnixNano": int(self.start_time * 1e9),
            "endTimeUnixNano": int(self.end_time * 1e9),
            "durationNanos": int(self.duration_ms * 1e6),
            "status": {
                "code": "STATUS_CODE_OK" if self.status == SpanStatus.OK else "STATUS_CODE_ERROR",
                "message": self.error,
            },
            "attributes": [
                {"key": k, "value": {"stringValue": str(v)}}
                for k, v in self.attributes.items()
            ],
            "events": [
                {
                    "timeUnixNano": int(e.get("timestamp", 0) * 1e9),
                    "name": e.get("name", ""),
                    "attributes": [
                        {"key": k, "value": {"stringValue": str(v)}}
                        for k, v in e.get("attributes", {}).items()
                    ],
                }
                for e in self.events
            ],
        }


@dataclass
class Trace:
    """追踪记录

    Attributes:
        trace_id: Trace ID
        operation: 操作名
        beacon_id: Beacon ID
        start_time: 开始时间
        end_time: 结束时间
        total_duration_ms: 总耗时
        status: 状态
        spans: Span列表
        error: 错误信息
    """
    trace_id: str = ""
    operation: str = ""
    beacon_id: str = ""
    start_time: float = 0.0
    end_time: float = 0.0
    total_duration_ms: float = 0.0
    status: SpanStatus = SpanStatus.UNSET
    spans: List[Span] = field(default_factory=list)
    error: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "trace_id": self.trace_id,
            "operation": self.operation,
            "beacon_id": self.beacon_id,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "total_duration_ms": self.total_duration_ms,
            "status": self.status.value,
            "spans": [s.to_dict() for s in self.spans],
            "error": self.error,
        }

    def to_opentelemetry(self) -> Dict[str, Any]:
        """转换为OpenTelemetry格式

        Returns:
            OpenTelemetry格式
        """
        return {
            "resourceSpans": [
                {
                    "resource": {
                        "attributes": [
                            {"key": "service.name", "value": {"stringValue": "privesc-auxiliary"}},
                            {"key": "beacon.id", "value": {"stringValue": self.beacon_id}},
                            {"key": "operation", "value": {"stringValue": self.operation}},
                        ],
                    },
                    "scopeSpans": [
                        {
                            "scope": {"name": "privesc-observability", "version": "1.0.0"},
                            "spans": [s.to_opentelemetry() for s in self.spans],
                        }
                    ],
                }
            ],
        }


@dataclass
class DiagnosticEvent:
    """诊断事件

    Attributes:
        event_id: 事件ID
        trace_id: Trace ID
        level: 诊断级别
        message: 消息
        component: 组件名
        timestamp: 时间戳
        details: 详细信息
    """
    event_id: str = ""
    trace_id: str = ""
    level: DiagnosticLevel = DiagnosticLevel.INFO
    message: str = ""
    component: str = ""
    timestamp: str = ""
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "event_id": self.event_id,
            "trace_id": self.trace_id,
            "level": self.level.value,
            "message": self.message,
            "component": self.component,
            "timestamp": self.timestamp,
            "details": self.details,
        }


@dataclass
class ErrorAggregation:
    """错误聚合

    Attributes:
        error_type: 错误类型
        count: 出现次数
        last_occurrence: 最后出现时间
        affected_beacons: 受影响的Beacon
        sample_traces: 示例Trace
        suggestion: 建议修复方案
    """
    error_type: str = ""
    count: int = 0
    last_occurrence: str = ""
    affected_beacons: List[str] = field(default_factory=list)
    sample_traces: List[str] = field(default_factory=list)
    suggestion: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "error_type": self.error_type,
            "count": self.count,
            "last_occurrence": self.last_occurrence,
            "affected_beacons": self.affected_beacons,
            "sample_traces": self.sample_traces,
            "suggestion": self.suggestion,
        }


@dataclass
class PerformanceMetrics:
    """性能指标

    Attributes:
        operation: 操作名
        total_runs: 总运行次数
        avg_duration_ms: 平均耗时
        min_duration_ms: 最小耗时
        max_duration_ms: 最大耗时
        p50_duration_ms: P50耗时
        p95_duration_ms: P95耗时
        p99_duration_ms: P99耗时
        cpu_usage_percent: CPU使用率
        memory_usage_mb: 内存使用
        io_operations: IO操作数
        timestamp: 时间戳
    """
    operation: str = ""
    total_runs: int = 0
    avg_duration_ms: float = 0.0
    min_duration_ms: float = 0.0
    max_duration_ms: float = 0.0
    p50_duration_ms: float = 0.0
    p95_duration_ms: float = 0.0
    p99_duration_ms: float = 0.0
    cpu_usage_percent: float = 0.0
    memory_usage_mb: float = 0.0
    io_operations: int = 0
    timestamp: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "operation": self.operation,
            "total_runs": self.total_runs,
            "avg_duration_ms": round(self.avg_duration_ms, 2),
            "min_duration_ms": round(self.min_duration_ms, 2),
            "max_duration_ms": round(self.max_duration_ms, 2),
            "p50_duration_ms": round(self.p50_duration_ms, 2),
            "p95_duration_ms": round(self.p95_duration_ms, 2),
            "p99_duration_ms": round(self.p99_duration_ms, 2),
            "cpu_usage_percent": round(self.cpu_usage_percent, 2),
            "memory_usage_mb": round(self.memory_usage_mb, 2),
            "io_operations": self.io_operations,
            "timestamp": self.timestamp,
        }


@dataclass
class DiagnosticDashboard:
    """诊断面板

    Attributes:
        timestamp: 时间戳
        active_tasks: 活跃任务
        beacon_progress: Beacon进度
        success_rate: 成功率
        error_aggregations: 错误聚合
        performance_metrics: 性能指标
        recent_events: 最近事件
    """
    timestamp: str = ""
    active_tasks: int = 0
    beacon_progress: Dict[str, str] = field(default_factory=dict)
    success_rate: float = 0.0
    error_aggregations: List[ErrorAggregation] = field(default_factory=list)
    performance_metrics: List[PerformanceMetrics] = field(default_factory=list)
    recent_events: List[DiagnosticEvent] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "timestamp": self.timestamp,
            "active_tasks": self.active_tasks,
            "beacon_progress": self.beacon_progress,
            "success_rate": round(self.success_rate, 4),
            "error_aggregations": [e.to_dict() for e in self.error_aggregations],
            "performance_metrics": [m.to_dict() for m in self.performance_metrics],
            "recent_events": [e.to_dict() for e in self.recent_events],
        }


# =============================================================================
# 全链路追踪器
# =============================================================================

class TraceContext:
    """追踪上下文

    Attributes:
        trace_id: Trace ID
        current_span: 当前Span
        spans: Span列表
    """

    def __init__(self, trace_id: str, operation: str, beacon_id: str) -> None:
        """初始化追踪上下文

        Args:
            trace_id: Trace ID
            operation: 操作名
            beacon_id: Beacon ID
        """
        self.trace_id = trace_id
        self.operation = operation
        self.beacon_id = beacon_id
        self.current_span: Optional[Span] = None
        self.spans: List[Span] = []

    def start_span(
        self,
        name: str,
        operation: str,
        parent_span_id: str = "",
        attributes: Optional[Dict[str, Any]] = None,
    ) -> Span:
        """开始Span

        Args:
            name: Span名
            operation: 操作名
            parent_span_id: 父Span ID
            attributes: 属性

        Returns:
            Span
        """
        span = Span(
            span_id=f"span_{uuid.uuid4().hex[:8]}",
            trace_id=self.trace_id,
            parent_span_id=parent_span_id or (self.current_span.span_id if self.current_span else ""),
            name=name,
            operation=operation,
            start_time=time.time(),
            attributes=attributes or {},
        )
        self.current_span = span
        self.spans.append(span)
        return span

    def end_span(self, status: SpanStatus = SpanStatus.OK, error: str = "") -> None:
        """结束Span

        Args:
            status: 状态
            error: 错误信息
        """
        if self.current_span:
            self.current_span.end_time = time.time()
            self.current_span.duration_ms = (
                self.current_span.end_time - self.current_span.start_time
            ) * 1000
            self.current_span.status = status
            self.current_span.error = error


class TraceCollector:
    """追踪收集器

    收集和存储追踪记录。

    Attributes:
        _traces: 追踪记录
        _max_traces: 最大追踪数
    """

    def __init__(self, max_traces: int = 1000) -> None:
        """初始化追踪收集器

        Args:
            max_traces: 最大追踪数
        """
        self._traces: Dict[str, Trace] = {}
        self._max_traces = max_traces

    def add_trace(self, trace: Trace) -> None:
        """添加追踪

        Args:
            trace: 追踪记录
        """
        if len(self._traces) >= self._max_traces:
            oldest_key = min(self._traces.keys(), key=lambda k: self._traces[k].start_time)
            del self._traces[oldest_key]

        self._traces[trace.trace_id] = trace

    def get_trace(self, trace_id: str) -> Optional[Trace]:
        """获取追踪

        Args:
            trace_id: Trace ID

        Returns:
            追踪记录
        """
        return self._traces.get(trace_id)

    def get_traces_by_beacon(self, beacon_id: str) -> List[Trace]:
        """按Beacon获取追踪

        Args:
            beacon_id: Beacon ID

        Returns:
            追踪列表
        """
        return [
            t for t in self._traces.values()
            if t.beacon_id == beacon_id
        ]

    def get_recent_traces(self, limit: int = 50) -> List[Trace]:
        """获取最近追踪

        Args:
            limit: 数量限制

        Returns:
            追踪列表
        """
        sorted_traces = sorted(
            self._traces.values(),
            key=lambda t: t.start_time,
            reverse=True,
        )
        return sorted_traces[:limit]

    def export_opentelemetry(self, trace_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """导出OpenTelemetry格式

        Args:
            trace_id: Trace ID（可选）

        Returns:
            OpenTelemetry格式列表
        """
        if trace_id:
            trace = self._traces.get(trace_id)
            return [trace.to_opentelemetry()] if trace else []

        return [t.to_opentelemetry() for t in self._traces.values()]


# =============================================================================
# 错误聚合器
# =============================================================================

class ErrorAggregator:
    """错误聚合器

    聚合相同类型的失败。

    Attributes:
        _aggregations: 错误聚合
    """

    ERROR_SUGGESTIONS = {
        "timeout": "增加超时时间或检查网络连接",
        "permission_denied": "检查当前用户权限",
        "service_not_found": "检查服务是否存在",
        "connection_refused": "检查目标服务是否运行",
        "kernel_protection": "内核保护阻止了利用，尝试降级策略",
        "patch_installed": "目标已安装补丁，尝试其他CVE",
        "no_suid": "未发现SUID二进制文件",
        "no_sudo": "当前用户无sudo权限",
        "container_escape_failed": "容器逃逸失败，检查内核版本",
        "credential_not_found": "未找到缓存凭据",
    }

    def __init__(self) -> None:
        """初始化错误聚合器"""
        self._aggregations: Dict[str, ErrorAggregation] = {}

    def record_error(
        self,
        error_type: str,
        trace_id: str,
        beacon_id: str,
        timestamp: Optional[str] = None,
    ) -> None:
        """记录错误

        Args:
            error_type: 错误类型
            trace_id: Trace ID
            beacon_id: Beacon ID
            timestamp: 时间戳
        """
        if error_type not in self._aggregations:
            self._aggregations[error_type] = ErrorAggregation(
                error_type=error_type,
                suggestion=self.ERROR_SUGGESTIONS.get(
                    error_type, "检查日志获取详细信息"
                ),
            )

        agg = self._aggregations[error_type]
        agg.count += 1
        agg.last_occurrence = timestamp or datetime.now().isoformat()

        if beacon_id not in agg.affected_beacons:
            agg.affected_beacons.append(beacon_id)

        if len(agg.sample_traces) < 5:
            agg.sample_traces.append(trace_id)

    def get_top_errors(self, limit: int = 10) -> List[ErrorAggregation]:
        """获取Top错误

        Args:
            limit: 数量限制

        Returns:
            错误聚合列表
        """
        sorted_errors = sorted(
            self._aggregations.values(),
            key=lambda e: e.count,
            reverse=True,
        )
        return sorted_errors[:limit]

    def get_all_aggregations(self) -> List[ErrorAggregation]:
        """获取所有聚合

        Returns:
            错误聚合列表
        """
        return list(self._aggregations.values())

    def clear(self) -> None:
        """清空聚合"""
        self._aggregations.clear()


# =============================================================================
# 性能基准测试
# =============================================================================

class PerformanceBenchmark:
    """性能基准测试

    统计CPU/内存/IO消耗。

    Attributes:
        _metrics: 性能指标
        _durations: 耗时记录
    """

    def __init__(self) -> None:
        """初始化性能基准测试"""
        self._metrics: Dict[str, PerformanceMetrics] = {}
        self._durations: Dict[str, List[float]] = defaultdict(list)

    def record_operation(
        self,
        operation: str,
        duration_ms: float,
        cpu_percent: float = 0.0,
        memory_mb: float = 0.0,
        io_ops: int = 0,
    ) -> None:
        """记录操作性能

        Args:
            operation: 操作名
            duration_ms: 耗时
            cpu_percent: CPU使用率
            memory_mb: 内存使用
            io_ops: IO操作数
        """
        self._durations[operation].append(duration_ms)

        durations = self._durations[operation]
        sorted_durations = sorted(durations)
        total = len(sorted_durations)

        metrics = PerformanceMetrics(
            operation=operation,
            total_runs=total,
            avg_duration_ms=sum(durations) / total,
            min_duration_ms=min(durations),
            max_duration_ms=max(durations),
            p50_duration_ms=self._percentile(sorted_durations, 50),
            p95_duration_ms=self._percentile(sorted_durations, 95),
            p99_duration_ms=self._percentile(sorted_durations, 99),
            cpu_usage_percent=cpu_percent,
            memory_usage_mb=memory_mb,
            io_operations=io_ops,
            timestamp=datetime.now().isoformat(),
        )

        self._metrics[operation] = metrics

    def get_metrics(self, operation: str) -> Optional[PerformanceMetrics]:
        """获取性能指标

        Args:
            operation: 操作名

        Returns:
            性能指标
        """
        return self._metrics.get(operation)

    def get_all_metrics(self) -> List[PerformanceMetrics]:
        """获取所有指标

        Returns:
            性能指标列表
        """
        return list(self._metrics.values())

    def compare_with_baseline(
        self,
        operation: str,
        baseline_ms: float,
    ) -> Dict[str, Any]:
        """与基准对比

        Args:
            operation: 操作名
            baseline_ms: 基准耗时

        Returns:
            对比结果
        """
        metrics = self._metrics.get(operation)
        if not metrics:
            return {
                "operation": operation,
                "baseline_ms": baseline_ms,
                "current_ms": 0,
                "regression": False,
                "regression_percent": 0,
            }

        current = metrics.avg_duration_ms
        regression = current > baseline_ms
        regression_percent = (
            ((current - baseline_ms) / baseline_ms) * 100
            if baseline_ms > 0
            else 0
        )

        return {
            "operation": operation,
            "baseline_ms": baseline_ms,
            "current_ms": round(current, 2),
            "regression": regression,
            "regression_percent": round(regression_percent, 2),
        }

    def _percentile(self, sorted_data: List[float], percentile: int) -> float:
        """计算百分位数

        Args:
            sorted_data: 已排序数据
            percentile: 百分位

        Returns:
            百分位值
        """
        if not sorted_data:
            return 0.0

        index = int(len(sorted_data) * percentile / 100)
        index = min(index, len(sorted_data) - 1)
        return sorted_data[index]


# =============================================================================
# 实时诊断面板
# =============================================================================

class DiagnosticDashboardProvider:
    """实时诊断面板提供者

    Attributes:
        _trace_collector: 追踪收集器
        _error_aggregator: 错误聚合器
        _benchmark: 性能基准测试
        _events: 诊断事件
        _beacon_progress: Beacon进度
    """

    def __init__(
        self,
        trace_collector: TraceCollector,
        error_aggregator: ErrorAggregator,
        benchmark: PerformanceBenchmark,
    ) -> None:
        """初始化诊断面板

        Args:
            trace_collector: 追踪收集器
            error_aggregator: 错误聚合器
            benchmark: 性能基准测试
        """
        self._trace_collector = trace_collector
        self._error_aggregator = error_aggregator
        self._benchmark = benchmark
        self._events: List[DiagnosticEvent] = []
        self._beacon_progress: Dict[str, str] = {}
        self._active_tasks: int = 0

    def update_beacon_progress(
        self, beacon_id: str, progress: str,
    ) -> None:
        """更新Beacon进度

        Args:
            beacon_id: Beacon ID
            progress: 进度
        """
        self._beacon_progress[beacon_id] = progress

    def set_active_tasks(self, count: int) -> None:
        """设置活跃任务数

        Args:
            count: 任务数
        """
        self._active_tasks = count

    def add_event(self, event: DiagnosticEvent) -> None:
        """添加诊断事件

        Args:
            event: 诊断事件
        """
        self._events.append(event)
        if len(self._events) > 500:
            self._events = self._events[-500:]

    def get_dashboard(self) -> DiagnosticDashboard:
        """获取诊断面板

        Returns:
            诊断面板
        """
        dashboard = DiagnosticDashboard(
            timestamp=datetime.now().isoformat(),
            active_tasks=self._active_tasks,
            beacon_progress=dict(self._beacon_progress),
            error_aggregations=self._error_aggregator.get_top_errors(10),
            performance_metrics=self._benchmark.get_all_metrics(),
            recent_events=self._events[-20:],
        )

        dashboard.success_rate = self._calculate_success_rate()

        return dashboard

    def _calculate_success_rate(self) -> float:
        """计算成功率

        Returns:
            成功率
        """
        traces = self._trace_collector.get_recent_traces(100)
        if not traces:
            return 0.0

        success = sum(
            1 for t in traces
            if t.status == SpanStatus.OK
        )
        return success / len(traces)


# =============================================================================
# 主可观测性模块
# =============================================================================

class PrivescObservabilityModule:
    """可观测性与诊断模块

    整合全链路追踪、诊断面板、性能基准。

    Attributes:
        _trace_collector: 追踪收集器
        _error_aggregator: 错误聚合器
        _benchmark: 性能基准测试
        _dashboard: 诊断面板
    """

    def __init__(self, max_traces: int = 1000) -> None:
        """初始化可观测性模块

        Args:
            max_traces: 最大追踪数
        """
        self._trace_collector = TraceCollector(max_traces)
        self._error_aggregator = ErrorAggregator()
        self._benchmark = PerformanceBenchmark()
        self._dashboard = DiagnosticDashboardProvider(
            self._trace_collector,
            self._error_aggregator,
            self._benchmark,
        )

    def create_trace(
        self, operation: str, beacon_id: str,
    ) -> TraceContext:
        """创建追踪

        Args:
            operation: 操作名
            beacon_id: Beacon ID

        Returns:
            追踪上下文
        """
        trace_id = f"trace_{uuid.uuid4().hex[:12]}"
        return TraceContext(trace_id, operation, beacon_id)

    def complete_trace(self, context: TraceContext) -> Trace:
        """完成追踪

        Args:
            context: 追踪上下文

        Returns:
            追踪记录
        """
        trace = Trace(
            trace_id=context.trace_id,
            operation=context.operation,
            beacon_id=context.beacon_id,
            start_time=context.spans[0].start_time if context.spans else time.time(),
            end_time=context.spans[-1].end_time if context.spans else time.time(),
            total_duration_ms=sum(s.duration_ms for s in context.spans),
            status=context.spans[-1].status if context.spans else SpanStatus.UNSET,
            spans=context.spans,
        )

        self._trace_collector.add_trace(trace)

        if trace.status == SpanStatus.ERROR:
            self._error_aggregator.record_error(
                error_type=trace.error or "unknown_error",
                trace_id=trace.trace_id,
                beacon_id=trace.beacon_id,
                timestamp=trace.end_time,
            )

        return trace

    def record_performance(
        self,
        operation: str,
        duration_ms: float,
        cpu_percent: float = 0.0,
        memory_mb: float = 0.0,
        io_ops: int = 0,
    ) -> None:
        """记录性能

        Args:
            operation: 操作名
            duration_ms: 耗时
            cpu_percent: CPU使用率
            memory_mb: 内存使用
            io_ops: IO操作数
        """
        self._benchmark.record_operation(
            operation, duration_ms, cpu_percent, memory_mb, io_ops,
        )

    def add_diagnostic_event(self, event: DiagnosticEvent) -> None:
        """添加诊断事件

        Args:
            event: 诊断事件
        """
        self._dashboard.add_event(event)

    def update_beacon_progress(
        self, beacon_id: str, progress: str,
    ) -> None:
        """更新Beacon进度

        Args:
            beacon_id: Beacon ID
            progress: 进度
        """
        self._dashboard.update_beacon_progress(beacon_id, progress)

    def set_active_tasks(self, count: int) -> None:
        """设置活跃任务数

        Args:
            count: 任务数
        """
        self._dashboard.set_active_tasks(count)

    def get_dashboard(self) -> DiagnosticDashboard:
        """获取诊断面板

        Returns:
            诊断面板
        """
        return self._dashboard.get_dashboard()

    def get_trace(self, trace_id: str) -> Optional[Trace]:
        """获取追踪

        Args:
            trace_id: Trace ID

        Returns:
            追踪记录
        """
        return self._trace_collector.get_trace(trace_id)

    def export_opentelemetry(
        self, trace_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """导出OpenTelemetry格式

        Args:
            trace_id: Trace ID（可选）

        Returns:
            OpenTelemetry格式
        """
        return self._trace_collector.export_opentelemetry(trace_id)

    def get_top_errors(self, limit: int = 10) -> List[ErrorAggregation]:
        """获取Top错误

        Args:
            limit: 数量限制

        Returns:
            错误聚合列表
        """
        return self._error_aggregator.get_top_errors(limit)

    def get_performance_metrics(
        self, operation: str,
    ) -> Optional[PerformanceMetrics]:
        """获取性能指标

        Args:
            operation: 操作名

        Returns:
            性能指标
        """
        return self._benchmark.get_metrics(operation)

    def compare_performance(
        self, operation: str, baseline_ms: float,
    ) -> Dict[str, Any]:
        """对比性能

        Args:
            operation: 操作名
            baseline_ms: 基准耗时

        Returns:
            对比结果
        """
        return self._benchmark.compare_with_baseline(operation, baseline_ms)


# =============================================================================
# 全局单例
# =============================================================================

_observability_module: Optional[PrivescObservabilityModule] = None


def get_observability_module() -> PrivescObservabilityModule:
    """获取可观测性模块全局单例

    Returns:
        PrivescObservabilityModule 实例
    """
    global _observability_module
    if _observability_module is None:
        _observability_module = PrivescObservabilityModule()
    return _observability_module


__all__ = [
    "PrivescObservabilityModule",
    "TraceCollector",
    "ErrorAggregator",
    "PerformanceBenchmark",
    "DiagnosticDashboardProvider",
    "TraceContext",
    "Trace",
    "Span",
    "DiagnosticEvent",
    "ErrorAggregation",
    "PerformanceMetrics",
    "DiagnosticDashboard",
    "SpanStatus",
    "DiagnosticLevel",
    "get_observability_module",
]
