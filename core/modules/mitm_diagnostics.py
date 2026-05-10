"""
协议诊断与可观测性模块
包含连接诊断面板、协议合规性检查、Prometheus指标暴露、协议使用统计等功能
"""

import logging
import time
import json
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from collections import defaultdict
from enum import Enum
import threading

logger = logging.getLogger(__name__)


class ProtocolHealth(Enum):
    """协议健康状态"""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


@dataclass
class ConnectionDiagInfo:
    """连接诊断信息"""
    connection_id: str
    protocol: str
    protocol_version: str
    alpn_negotiated: str
    tls_version: str
    cipher_suite: str
    quic_version: str = ""
    quic_connection_id: str = ""
    stream_id_mapping: Dict[int, str] = field(default_factory=dict)
    created_at: float = 0.0
    last_activity: float = 0.0
    request_count: int = 0
    response_count: int = 0
    error_count: int = 0
    health: ProtocolHealth = ProtocolHealth.UNKNOWN


@dataclass
class ProtocolComplianceIssue:
    """协议合规性问题"""
    issue_id: str
    timestamp: float
    severity: str
    category: str
    description: str
    connection_id: str = ""
    stream_id: Optional[int] = None
    recommendation: str = ""


@dataclass
class PrometheusMetric:
    """Prometheus指标"""
    name: str
    metric_type: str
    value: float
    labels: Dict[str, str] = field(default_factory=dict)
    help_text: str = ""


class ConnectionDiagnosisPanel:
    """连接诊断面板"""
    
    def __init__(self):
        self._connections: Dict[str, ConnectionDiagInfo] = {}
        self._lock = threading.RLock()
        
        self._stats = {
            'total_connections': 0,
            'active_connections': 0,
            'closed_connections': 0,
        }
        self._stats_lock = threading.RLock()
    
    def register_connection(self, conn_id: str, protocol: str, 
                           alpn: str = "", tls_version: str = "",
                           cipher_suite: str = "", quic_version: str = "",
                           quic_conn_id: str = ""):
        """注册连接"""
        now = time.time()
        
        info = ConnectionDiagInfo(
            connection_id=conn_id,
            protocol=protocol,
            protocol_version=protocol,
            alpn_negotiated=alpn,
            tls_version=tls_version,
            cipher_suite=cipher_suite,
            quic_version=quic_version,
            quic_connection_id=quic_conn_id,
            created_at=now,
            last_activity=now,
            health=ProtocolHealth.HEALTHY,
        )
        
        with self._lock:
            self._connections[conn_id] = info
        
        with self._stats_lock:
            self._stats['total_connections'] += 1
            self._stats['active_connections'] += 1
        
        logger.debug(f"连接注册: {conn_id[:8]} ({protocol})")
    
    def update_connection_activity(self, conn_id: str, 
                                  request_count: int = 0,
                                  response_count: int = 0,
                                  error_count: int = 0):
        """更新连接活动"""
        with self._lock:
            if conn_id in self._connections:
                info = self._connections[conn_id]
                info.last_activity = time.time()
                info.request_count += request_count
                info.response_count += response_count
                info.error_count += error_count
                
                if info.error_count > 10:
                    info.health = ProtocolHealth.UNHEALTHY
                elif info.error_count > 5:
                    info.health = ProtocolHealth.DEGRADED
    
    def add_stream_mapping(self, conn_id: str, stream_id: int, description: str):
        """添加流映射"""
        with self._lock:
            if conn_id in self._connections:
                self._connections[conn_id].stream_id_mapping[stream_id] = description
    
    def close_connection(self, conn_id: str):
        """关闭连接"""
        with self._lock:
            if conn_id in self._connections:
                del self._connections[conn_id]
        
        with self._stats_lock:
            self._stats['active_connections'] = max(0, self._stats['active_connections'] - 1)
            self._stats['closed_connections'] += 1
    
    def get_connection_info(self, conn_id: str) -> Optional[Dict[str, Any]]:
        """获取连接信息"""
        with self._lock:
            info = self._connections.get(conn_id)
            if not info:
                return None
            
            return {
                'connection_id': info.connection_id,
                'protocol': info.protocol,
                'protocol_version': info.protocol_version,
                'alpn_negotiated': info.alpn_negotiated,
                'tls_version': info.tls_version,
                'cipher_suite': info.cipher_suite,
                'quic_version': info.quic_version,
                'quic_connection_id': info.quic_connection_id,
                'stream_id_mapping': dict(info.stream_id_mapping),
                'created_at': info.created_at,
                'last_activity': info.last_activity,
                'request_count': info.request_count,
                'response_count': info.response_count,
                'error_count': info.error_count,
                'health': info.health.value,
                'duration': time.time() - info.created_at,
            }
    
    def get_all_connections(self) -> List[Dict[str, Any]]:
        """获取所有连接"""
        with self._lock:
            return [
                {
                    'connection_id': info.connection_id,
                    'protocol': info.protocol,
                    'health': info.health.value,
                    'request_count': info.request_count,
                    'response_count': info.response_count,
                    'error_count': info.error_count,
                    'duration': time.time() - info.created_at,
                }
                for info in self._connections.values()
            ]
    
    def get_stats(self) -> Dict[str, Any]:
        """获取统计信息"""
        with self._stats_lock:
            stats = dict(self._stats)
        
        with self._lock:
            stats['connections_by_protocol'] = defaultdict(int)
            for info in self._connections.values():
                stats['connections_by_protocol'][info.protocol] += 1
            stats['connections_by_protocol'] = dict(stats['connections_by_protocol'])
        
        return stats


class ProtocolComplianceChecker:
    """协议合规性检查器"""
    
    def __init__(self):
        self._issues: List[ProtocolComplianceIssue] = []
        self._lock = threading.RLock()
        
        self._stats = {
            'total_checks': 0,
            'issues_found': 0,
            'critical_issues': 0,
            'warnings': 0,
        }
        self._stats_lock = threading.RLock()
    
    def check_http2_compliance(self, headers: List[Tuple[str, str]], 
                              connection_id: str = "") -> List[ProtocolComplianceIssue]:
        """检查HTTP/2合规性"""
        issues = []
        
        with self._stats_lock:
            self._stats['total_checks'] += 1
        
        pseudo_headers_seen = False
        for name, value in headers:
            if name.startswith(':'):
                if not pseudo_headers_seen:
                    pseudo_headers_seen = True
                else:
                    issue = self._create_issue(
                        'warning',
                        'http2_pseudo_header_order',
                        f"伪头部应在普通头部之前: {name}",
                        connection_id,
                        "确保所有伪头部（:method, :path, :authority, :scheme）在普通头部之前"
                    )
                    issues.append(issue)
            
            if name.lower() == 'connection':
                issue = self._create_issue(
                    'critical',
                    'http2_forbidden_header',
                    f"HTTP/2不允许Connection头部: {name}",
                    connection_id,
                    "移除Connection头部，HTTP/2使用帧类型控制连接行为"
                )
                issues.append(issue)
            
            if name.lower() == 'transfer-encoding':
                issue = self._create_issue(
                    'critical',
                    'http2_forbidden_header',
                    f"HTTP/2不允许Transfer-Encoding头部: {name}",
                    connection_id,
                    "移除Transfer-Encoding头部，HTTP/2使用DATA帧传输数据"
                )
                issues.append(issue)
        
        with self._lock:
            self._issues.extend(issues)
        
        with self._stats_lock:
            self._stats['issues_found'] += len(issues)
            self._stats['critical_issues'] += sum(1 for i in issues if i.severity == 'critical')
            self._stats['warnings'] += sum(1 for i in issues if i.severity == 'warning')
        
        return issues
    
    def check_http3_compliance(self, headers: List[Tuple[str, str]],
                              quic_version: str = "",
                              connection_id: str = "") -> List[ProtocolComplianceIssue]:
        """检查HTTP/3合规性"""
        issues = []
        
        with self._stats_lock:
            self._stats['total_checks'] += 1
        
        required_pseudo_headers = {':method', ':path', ':scheme'}
        found_pseudo_headers = {name for name, _ in headers if name.startswith(':')}
        
        missing = required_pseudo_headers - found_pseudo_headers
        if missing:
            issue = self._create_issue(
                'critical',
                'http3_missing_pseudo_header',
                f"缺少必需伪头部: {missing}",
                connection_id,
                f"HTTP/3请求必须包含伪头部: {required_pseudo_headers}"
            )
            issues.append(issue)
        
        if quic_version and quic_version not in ['0x00000001', '0x6b3343cf']:
            issue = self._create_issue(
                'warning',
                'http3_quic_version',
                f"非标准QUIC版本: {quic_version}",
                connection_id,
                "建议使用QUIC v1 (0x00000001) 或 v2 (0x6b3343cf)"
            )
            issues.append(issue)
        
        with self._lock:
            self._issues.extend(issues)
        
        with self._stats_lock:
            self._stats['issues_found'] += len(issues)
            self._stats['critical_issues'] += sum(1 for i in issues if i.severity == 'critical')
            self._stats['warnings'] += sum(1 for i in issues if i.severity == 'warning')
        
        return issues
    
    def _create_issue(self, severity: str, category: str, description: str,
                     connection_id: str = "", recommendation: str = "") -> ProtocolComplianceIssue:
        """创建问题"""
        import hashlib
        return ProtocolComplianceIssue(
            issue_id=hashlib.md5(f"{time.time()}{category}".encode()).hexdigest()[:12],
            timestamp=time.time(),
            severity=severity,
            category=category,
            description=description,
            connection_id=connection_id,
            recommendation=recommendation,
        )
    
    def get_issues(self, limit: int = 100, severity: Optional[str] = None) -> List[Dict[str, Any]]:
        """获取问题"""
        with self._lock:
            issues = self._issues
        
        if severity:
            issues = [i for i in issues if i.severity == severity]
        
        return [
            {
                'issue_id': i.issue_id,
                'timestamp': i.timestamp,
                'severity': i.severity,
                'category': i.category,
                'description': i.description,
                'connection_id': i.connection_id,
                'stream_id': i.stream_id,
                'recommendation': i.recommendation,
            }
            for i in issues[-limit:]
        ]
    
    def get_stats(self) -> Dict[str, Any]:
        """获取统计信息"""
        with self._stats_lock:
            return dict(self._stats)
    
    def clear_issues(self):
        """清除问题"""
        with self._lock:
            self._issues.clear()


class PrometheusMetricsExporter:
    """Prometheus指标导出器"""
    
    def __init__(self):
        self._metrics: Dict[str, PrometheusMetric] = {}
        self._lock = threading.RLock()
    
    def record_metric(self, name: str, metric_type: str, value: float,
                     labels: Dict[str, str] = None, help_text: str = ""):
        """记录指标"""
        metric = PrometheusMetric(
            name=name,
            metric_type=metric_type,
            value=value,
            labels=labels or {},
            help_text=help_text,
        )
        
        with self._lock:
            key = f"{name}:{json.dumps(labels, sort_keys=True) if labels else ''}"
            self._metrics[key] = metric
    
    def increment_counter(self, name: str, labels: Dict[str, str] = None, 
                         help_text: str = ""):
        """增加计数器"""
        with self._lock:
            key = f"{name}:{json.dumps(labels, sort_keys=True) if labels else ''}"
            if key in self._metrics:
                self._metrics[key].value += 1
            else:
                self.record_metric(name, 'counter', 1, labels, help_text)
    
    def set_gauge(self, name: str, value: float, labels: Dict[str, str] = None,
                 help_text: str = ""):
        """设置仪表盘"""
        self.record_metric(name, 'gauge', value, labels, help_text)
    
    def export_metrics(self, format: str = 'prometheus') -> str:
        """导出指标"""
        with self._lock:
            metrics = list(self._metrics.values())
        
        if format == 'prometheus':
            return self._export_prometheus_format(metrics)
        elif format == 'json':
            return self._export_json_format(metrics)
        
        return self._export_prometheus_format(metrics)
    
    def _export_prometheus_format(self, metrics: List[PrometheusMetric]) -> str:
        """导出Prometheus格式"""
        lines = []
        
        for metric in metrics:
            if metric.help_text:
                lines.append(f"# HELP {metric.name} {metric.help_text}")
            lines.append(f"# TYPE {metric.name} {metric.metric_type}")
            
            label_str = ""
            if metric.labels:
                label_parts = [f'{k}="{v}"' for k, v in metric.labels.items()]
                label_str = "{" + ",".join(label_parts) + "}"
            
            lines.append(f"{metric.name}{label_str} {metric.value}")
        
        return "\n".join(lines)
    
    def _export_json_format(self, metrics: List[PrometheusMetric]) -> str:
        """导出JSON格式"""
        data = []
        for metric in metrics:
            data.append({
                'name': metric.name,
                'type': metric.metric_type,
                'value': metric.value,
                'labels': metric.labels,
                'help': metric.help_text,
            })
        return json.dumps(data, indent=2)
    
    def get_all_metrics(self) -> List[Dict[str, Any]]:
        """获取所有指标"""
        with self._lock:
            return [
                {
                    'name': m.name,
                    'type': m.metric_type,
                    'value': m.value,
                    'labels': m.labels,
                    'help': m.help_text,
                }
                for m in self._metrics.values()
            ]
    
    def clear_metrics(self):
        """清除指标"""
        with self._lock:
            self._metrics.clear()


class ProtocolUsageStatistics:
    """协议使用统计"""
    
    def __init__(self):
        self._protocol_counts: Dict[str, int] = defaultdict(int)
        self._protocol_bytes: Dict[str, int] = defaultdict(int)
        self._protocol_requests: Dict[str, int] = defaultdict(int)
        self._protocol_errors: Dict[str, int] = defaultdict(int)
        self._lock = threading.RLock()
        
        self._hourly_stats: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
        
        self._stats = {
            'total_requests': 0,
            'total_responses': 0,
            'total_bytes_in': 0,
            'total_bytes_out': 0,
        }
        self._stats_lock = threading.RLock()
    
    def record_request(self, protocol: str, size: int = 0):
        """记录请求"""
        with self._lock:
            self._protocol_counts[protocol] += 1
            self._protocol_bytes[protocol] += size
            self._protocol_requests[protocol] += 1
        
        with self._stats_lock:
            self._stats['total_requests'] += 1
            self._stats['total_bytes_in'] += size
        
        now = time.time()
        hour_key = time.strftime('%Y-%m-%d %H:00', time.localtime(now))
        with self._lock:
            self._hourly_stats[hour_key][f'{protocol}_requests'] += 1
            self._hourly_stats[hour_key][f'{protocol}_bytes'] += size
    
    def record_response(self, protocol: str, size: int = 0, error: bool = False):
        """记录响应"""
        with self._stats_lock:
            self._stats['total_responses'] += 1
            self._stats['total_bytes_out'] += size
        
        if error:
            with self._lock:
                self._protocol_errors[protocol] += 1
    
    def get_protocol_distribution(self) -> Dict[str, Dict[str, Any]]:
        """获取协议分布"""
        with self._lock:
            total_requests = sum(self._protocol_requests.values())
            
            distribution = {}
            for protocol in self._protocol_requests:
                count = self._protocol_requests[protocol]
                bytes_total = self._protocol_bytes[protocol]
                errors = self._protocol_errors.get(protocol, 0)
                
                distribution[protocol] = {
                    'requests': count,
                    'bytes': bytes_total,
                    'errors': errors,
                    'percentage': (count / total_requests * 100) if total_requests > 0 else 0,
                }
            
            return distribution
    
    def get_hourly_stats(self, hours: int = 24) -> List[Dict[str, Any]]:
        """获取小时统计"""
        with self._lock:
            sorted_hours = sorted(self._hourly_stats.keys())[-hours:]
            return [
                {
                    'hour': hour,
                    'stats': dict(self._hourly_stats[hour]),
                }
                for hour in sorted_hours
            ]
    
    def get_stats(self) -> Dict[str, Any]:
        """获取统计信息"""
        with self._stats_lock:
            stats = dict(self._stats)
        
        stats['protocol_distribution'] = self.get_protocol_distribution()
        
        return stats
    
    def reset_stats(self):
        """重置统计"""
        with self._lock:
            self._protocol_counts.clear()
            self._protocol_bytes.clear()
            self._protocol_requests.clear()
            self._protocol_errors.clear()
            self._hourly_stats.clear()
        
        with self._stats_lock:
            self._stats = {
                'total_requests': 0,
                'total_responses': 0,
                'total_bytes_in': 0,
                'total_bytes_out': 0,
            }


class DiagnosticsAndObservability:
    """诊断与可观测性管理器"""
    
    def __init__(self,
                 enable_diagnosis: bool = True,
                 enable_compliance_check: bool = True,
                 enable_prometheus: bool = True,
                 enable_usage_stats: bool = True):
        self._diagnosis_panel = ConnectionDiagnosisPanel() if enable_diagnosis else None
        self._compliance_checker = ProtocolComplianceChecker() if enable_compliance_check else None
        self._prometheus_exporter = PrometheusMetricsExporter() if enable_prometheus else None
        self._usage_stats = ProtocolUsageStatistics() if enable_usage_stats else None
    
    def register_connection(self, conn_id: str, protocol: str, **kwargs):
        """注册连接"""
        if self._diagnosis_panel:
            self._diagnosis_panel.register_connection(conn_id, protocol, **kwargs)
    
    def update_connection_activity(self, conn_id: str, **kwargs):
        """更新连接活动"""
        if self._diagnosis_panel:
            self._diagnosis_panel.update_connection_activity(conn_id, **kwargs)
    
    def close_connection(self, conn_id: str):
        """关闭连接"""
        if self._diagnosis_panel:
            self._diagnosis_panel.close_connection(conn_id)
    
    def check_compliance(self, protocol: str, headers: List[Tuple[str, str]], 
                        connection_id: str = "", **kwargs) -> List[Dict[str, Any]]:
        """检查合规性"""
        if not self._compliance_checker:
            return []
        
        if protocol in ['HTTP/2', 'h2']:
            issues = self._compliance_checker.check_http2_compliance(headers, connection_id)
        elif protocol in ['HTTP/3', 'h3']:
            issues = self._compliance_checker.check_http3_compliance(headers, connection_id=connection_id, **kwargs)
        else:
            return []
        
        return [
            {
                'issue_id': i.issue_id,
                'severity': i.severity,
                'category': i.category,
                'description': i.description,
                'recommendation': i.recommendation,
            }
            for i in issues
        ]
    
    def record_request(self, protocol: str, size: int = 0):
        """记录请求"""
        if self._usage_stats:
            self._usage_stats.record_request(protocol, size)
        
        if self._prometheus_exporter:
            self._prometheus_exporter.increment_counter(
                'http_requests_total',
                {'protocol': protocol},
                'Total HTTP requests'
            )
    
    def record_response(self, protocol: str, size: int = 0, error: bool = False):
        """记录响应"""
        if self._usage_stats:
            self._usage_stats.record_response(protocol, size, error)
        
        if self._prometheus_exporter:
            self._prometheus_exporter.increment_counter(
                'http_responses_total',
                {'protocol': protocol, 'error': str(error)},
                'Total HTTP responses'
            )
    
    def get_compliance_issues(self, limit: int = 100, 
                             severity: Optional[str] = None) -> List[Dict[str, Any]]:
        """获取合规性问题"""
        if self._compliance_checker:
            return self._compliance_checker.get_issues(limit, severity)
        return []
    
    def get_connection_diagnosis(self, conn_id: str) -> Optional[Dict[str, Any]]:
        """获取连接诊断"""
        if self._diagnosis_panel:
            return self._diagnosis_panel.get_connection_info(conn_id)
        return None
    
    def get_all_connections(self) -> List[Dict[str, Any]]:
        """获取所有连接"""
        if self._diagnosis_panel:
            return self._diagnosis_panel.get_all_connections()
        return []
    
    def get_prometheus_metrics(self, format: str = 'prometheus') -> str:
        """获取Prometheus指标"""
        if self._prometheus_exporter:
            return self._prometheus_exporter.export_metrics(format)
        return ""
    
    def get_usage_statistics(self) -> Dict[str, Any]:
        """获取使用统计"""
        if self._usage_stats:
            return self._usage_stats.get_stats()
        return {}
    
    def get_full_status(self) -> Dict[str, Any]:
        """获取完整状态"""
        status = {}
        
        if self._diagnosis_panel:
            status['diagnosis'] = self._diagnosis_panel.get_stats()
        
        if self._compliance_checker:
            status['compliance'] = self._compliance_checker.get_stats()
        
        if self._usage_stats:
            status['usage'] = self._usage_stats.get_stats()
        
        return status
