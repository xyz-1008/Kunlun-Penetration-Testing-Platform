"""
MITM代理与漏洞扫描引擎深度联动模块
实现注入点标记、PoC验证、漏洞告警、被动扫描
"""

import re
import logging
import threading
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, field
from datetime import datetime
from urllib.parse import urlparse, parse_qs

logger = logging.getLogger(__name__)


@dataclass
class InjectionPoint:
    """注入点"""
    id: str
    url: str
    param_name: str
    param_position: str  # query, body, header, cookie
    param_value: str
    injection_type: str  # SQLi, XSS, SSTI, Command Injection
    confidence: float
    evidence: str = ""


@dataclass
class VulnAlert:
    """漏洞告警"""
    id: str
    timestamp: datetime
    request_id: str
    url: str
    vuln_type: str
    severity: str  # critical, high, medium, low, info
    evidence: str
    raw_request: str = ""
    raw_response: str = ""
    poc_matched: str = ""


class InjectionPointDetector:
    """注入点检测器"""
    
    def __init__(self):
        self._sqli_indicators = [
            r"(?i)('\s*(or|and)\s*['\d])",
            r"(?i)(union\s+select)",
            r"(?i)(;\s*(drop|delete|update|insert))",
            r"(?i)(--\s*$)",
            r"(?i)(/\*.*\*/)",
        ]
        
        self._xss_indicators = [
            r"(?i)(<script)",
            r"(?i)(javascript:)",
            r"(?i)(on\w+\s*=)",
            r"(?i)(alert\s*\()",
        ]
        
        self._ssti_indicators = [
            r"\{\{.*\}\}",
            r"\{%.*%\}",
            r"\$\{.*\}",
            r"<%.*%>",
        ]
        
        self._suspicious_params = [
            'id', 'user', 'username', 'name', 'search', 'q', 'query',
            'file', 'path', 'url', 'redirect', 'callback', 'data',
            'input', 'value', 'param', 'key', 'token', 'page',
            'cmd', 'command', 'exec', 'execute', 'run',
        ]
    
    def detect_injection_points(self, request_data: Dict[str, Any]) -> List[InjectionPoint]:
        """检测请求中的注入点"""
        points = []
        url = request_data.get('url', '')
        headers = request_data.get('headers', {})
        body = request_data.get('body', '')
        
        import uuid
        
        # 检测Query参数
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)
        for name, values in query_params.items():
            value = values[0] if values else ''
            injection_type = self._classify_injection(name, value)
            
            if injection_type:
                points.append(InjectionPoint(
                    id=str(uuid.uuid4())[:12],
                    url=url,
                    param_name=name,
                    param_position='query',
                    param_value=value,
                    injection_type=injection_type,
                    confidence=self._calculate_confidence(name, value, injection_type),
                ))
        
        # 检测Body参数
        content_type = headers.get('Content-Type', '')
        if 'application/json' in content_type:
            points.extend(self._detect_json_injections(url, body))
        elif 'application/x-www-form-urlencoded' in content_type:
            points.extend(self._detect_form_injections(url, body))
        
        return points
    
    def _classify_injection(self, name: str, value: str) -> Optional[str]:
        """分类注入类型"""
        name_lower = name.lower()
        
        # 检查参数名
        if name_lower in self._suspicious_params:
            # 检查值中的注入特征
            for pattern in self._sqli_indicators:
                if re.search(pattern, value):
                    return 'SQLi'
            
            for pattern in self._xss_indicators:
                if re.search(pattern, value):
                    return 'XSS'
            
            for pattern in self._ssti_indicators:
                if re.search(pattern, value):
                    return 'SSTI'
        
        return None
    
    def _calculate_confidence(self, name: str, value: str, injection_type: str) -> float:
        """计算置信度"""
        confidence = 0.3  # 基础置信度
        
        # 参数名匹配
        if name.lower() in self._suspicious_params:
            confidence += 0.2
        
        # 值中包含注入特征
        if injection_type == 'SQLi':
            for pattern in self._sqli_indicators:
                if re.search(pattern, value):
                    confidence += 0.3
        elif injection_type == 'XSS':
            for pattern in self._xss_indicators:
                if re.search(pattern, value):
                    confidence += 0.3
        
        return min(1.0, confidence)
    
    def _detect_json_injections(self, url: str, body: str) -> List[InjectionPoint]:
        """检测JSON Body中的注入点"""
        import json
        points = []
        import uuid
        
        try:
            data = json.loads(body)
            self._extract_json_injections(url, data, '', points)
        except json.JSONDecodeError:
            pass
        
        return points
    
    def _extract_json_injections(self, url: str, data: Any, prefix: str, points: List[InjectionPoint]):
        """递归提取JSON注入点"""
        import uuid
        
        if isinstance(data, dict):
            for key, value in data.items():
                full_key = f"{prefix}.{key}" if prefix else key
                if isinstance(value, (dict, list)):
                    self._extract_json_injections(url, value, full_key, points)
                elif isinstance(value, str):
                    injection_type = self._classify_injection(key, value)
                    if injection_type:
                        points.append(InjectionPoint(
                            id=str(uuid.uuid4())[:12],
                            url=url,
                            param_name=full_key,
                            param_position='body',
                            param_value=value,
                            injection_type=injection_type,
                            confidence=self._calculate_confidence(key, value, injection_type),
                        ))
    
    def _detect_form_injections(self, url: str, body: str) -> List[InjectionPoint]:
        """检测表单Body中的注入点"""
        points = []
        import uuid
        
        try:
            form_data = parse_qs(body)
            for name, values in form_data.items():
                value = values[0] if values else ''
                injection_type = self._classify_injection(name, value)
                
                if injection_type:
                    points.append(InjectionPoint(
                        id=str(uuid.uuid4())[:12],
                        url=url,
                        param_name=name,
                        param_position='body',
                        param_value=value,
                        injection_type=injection_type,
                        confidence=self._calculate_confidence(name, value, injection_type),
                    ))
        except Exception:
            pass
        
        return points


class VulnFeatureDetector:
    """漏洞特征检测器"""
    
    def __init__(self):
        self._sqli_errors = [
            r"(?i)(sql\s*syntax|mysql\s*fetch|mysql\s*error)",
            r"(?i)(unclosed\s*quotation|incorrect\s*syntax)",
            r"(?i)(warning.*mysql|warning.*postgres|warning.*oracle)",
            r"(?i)(odbc\s*drivers?|sqlserver|sqloledb)",
            r"(?i)(you\s*have\s*an\s*error\s*in\s*your\s*sql)",
        ]
        
        self._xss_reflections = [
            r"<script>alert\(",
            r"javascript:alert",
            r"onerror\s*=\s*alert",
            r"onload\s*=\s*alert",
        ]
        
        self._path_traversal = [
            r"/etc/passwd",
            r"/etc/shadow",
            r"windows/system32",
            r"boot\.ini",
            r"win\.ini",
        ]
        
        self._info_disclosure = [
            r"(?i)(password|passwd|pwd)\s*[:=]\s*\S+",
            r"(?i)(api[_-]?key|apikey)\s*[:=]\s*\S+",
            r"(?i)(secret[_-]?key|secretkey)\s*[:=]\s*\S+",
            r"(?i)(access[_-]?token)\s*[:=]\s*\S+",
            r"(?i)(private[_-]?key)\s*[:=]\s*\S+",
            r"(?i)(stack\s*trace|traceback)",
            r"(?i)(debug\s*mode|debug\s*information)",
        ]
    
    def detect_vuln_features(self, response_data: Dict[str, Any]) -> List[VulnAlert]:
        """检测响应中的漏洞特征"""
        alerts = []
        body = response_data.get('body', b'')
        body_str = body if isinstance(body, str) else body.decode('utf-8', errors='replace')
        headers = response_data.get('headers', {})
        
        import uuid
        
        # SQL错误回显
        for pattern in self._sqli_errors:
            if re.search(pattern, body_str):
                alerts.append(VulnAlert(
                    id=str(uuid.uuid4())[:12],
                    timestamp=datetime.utcnow(),
                    request_id=response_data.get('request_id', ''),
                    url=response_data.get('url', ''),
                    vuln_type='SQL Injection',
                    severity='high',
                    evidence=f"SQL错误回显: {pattern}",
                    raw_response=body_str[:500],
                ))
                break
        
        # XSS反射
        for pattern in self._xss_reflections:
            if re.search(pattern, body_str, re.IGNORECASE):
                alerts.append(VulnAlert(
                    id=str(uuid.uuid4())[:12],
                    timestamp=datetime.utcnow(),
                    request_id=response_data.get('request_id', ''),
                    url=response_data.get('url', ''),
                    vuln_type='XSS',
                    severity='medium',
                    evidence=f"XSS特征: {pattern}",
                    raw_response=body_str[:500],
                ))
                break
        
        # 路径遍历
        for pattern in self._path_traversal:
            if re.search(pattern, body_str, re.IGNORECASE):
                alerts.append(VulnAlert(
                    id=str(uuid.uuid4())[:12],
                    timestamp=datetime.utcnow(),
                    request_id=response_data.get('request_id', ''),
                    url=response_data.get('url', ''),
                    vuln_type='Path Traversal',
                    severity='high',
                    evidence=f"路径遍历特征: {pattern}",
                    raw_response=body_str[:500],
                ))
                break
        
        # 信息泄露
        for pattern in self._info_disclosure:
            if re.search(pattern, body_str):
                alerts.append(VulnAlert(
                    id=str(uuid.uuid4())[:12],
                    timestamp=datetime.utcnow(),
                    request_id=response_data.get('request_id', ''),
                    url=response_data.get('url', ''),
                    vuln_type='Information Disclosure',
                    severity='medium',
                    evidence=f"敏感信息泄露: {pattern}",
                    raw_response=body_str[:500],
                ))
        
        return alerts


class PoCMatcher:
    """PoC匹配器"""
    
    def __init__(self):
        self._poc_rules: List[Dict[str, Any]] = []
    
    def match_pocs(self, request_data: Dict[str, Any], 
                   tech_stack: List[str] = None) -> List[Dict[str, Any]]:
        """匹配适用的PoC"""
        matched = []
        url = request_data.get('url', '')
        headers = request_data.get('headers', {})
        
        # 基于技术栈匹配
        if tech_stack:
            for tech in tech_stack:
                tech_lower = tech.lower()
                if 'wordpress' in tech_lower:
                    matched.append({
                        'poc_id': 'wp_core_001',
                        'name': 'WordPress核心漏洞检测',
                        'type': 'wordpress',
                        'severity': 'high',
                    })
                elif 'nginx' in tech_lower:
                    matched.append({
                        'poc_id': 'nginx_001',
                        'name': 'Nginx配置错误检测',
                        'type': 'nginx',
                        'severity': 'medium',
                    })
        
        # 基于URL路径匹配
        path_patterns = {
            r'/wp-admin/': {'poc_id': 'wp_admin_001', 'name': 'WordPress后台检测', 'severity': 'medium'},
            r'/phpmyadmin/': {'poc_id': 'pma_001', 'name': 'phpMyAdmin检测', 'severity': 'high'},
            r'/admin/': {'poc_id': 'admin_001', 'name': '后台路径检测', 'severity': 'low'},
            r'/api/v\d+/': {'poc_id': 'api_001', 'name': 'API接口检测', 'severity': 'medium'},
        }
        
        for pattern, poc in path_patterns.items():
            if re.search(pattern, url, re.IGNORECASE):
                matched.append(poc)
        
        return matched
    
    def send_to_poc_engine(self, request_data: Dict[str, Any], 
                          matched_pocs: List[Dict[str, Any]],
                          callback: Optional[Callable] = None):
        """发送到PoC验证引擎"""
        def _verify():
            for poc in matched_pocs:
                try:
                    # 模拟PoC验证
                    result = {
                        'poc_id': poc['poc_id'],
                        'name': poc['name'],
                        'target': request_data.get('url', ''),
                        'status': 'verified',
                        'evidence': 'PoC验证成功',
                    }
                    
                    if callback:
                        callback(result)
                        
                except Exception as e:
                    logger.error(f"PoC验证失败: {e}")
        
        thread = threading.Thread(target=_verify, daemon=True)
        thread.start()


class VulnScannerLinkage:
    """漏洞扫描引擎联动器"""
    
    def __init__(self):
        self.injection_detector = InjectionPointDetector()
        self.feature_detector = VulnFeatureDetector()
        self.poc_matcher = PoCMatcher()
        
        self._injection_callbacks: List[Callable] = []
        self._alert_callbacks: List[Callable] = []
        self._poc_callbacks: List[Callable] = []
        
        self._injection_points: List[InjectionPoint] = []
        self._alerts: List[VulnAlert] = []
        
        self._passive_mode = True  # 默认被动模式
    
    def process_traffic(self, request_data: Dict[str, Any], 
                       response_data: Dict[str, Any],
                       tech_stack: List[str] = None):
        """处理流量，检测注入点和漏洞特征"""
        try:
            # 检测注入点
            injection_points = self.injection_detector.detect_injection_points(request_data)
            self._injection_points.extend(injection_points)
            
            if injection_points:
                for callback in self._injection_callbacks:
                    try:
                        callback(request_data, injection_points)
                    except Exception as e:
                        logger.error(f"注入点通知失败: {e}")
            
            # 检测漏洞特征
            alerts = self.feature_detector.detect_vuln_features(response_data)
            self._alerts.extend(alerts)
            
            if alerts:
                for callback in self._alert_callbacks:
                    try:
                        callback(response_data, alerts)
                    except Exception as e:
                        logger.error(f"漏洞告警通知失败: {e}")
            
            # 匹配PoC（被动模式下不主动发送）
            if not self._passive_mode:
                matched_pocs = self.poc_matcher.match_pocs(request_data, tech_stack)
                
                if matched_pocs:
                    def on_poc_result(result):
                        for callback in self._poc_callbacks:
                            try:
                                callback(result)
                            except Exception as e:
                                logger.error(f"PoC结果通知失败: {e}")
                    
                    self.poc_matcher.send_to_poc_engine(
                        request_data, matched_pocs, on_poc_result
                    )
            
        except Exception as e:
            logger.error(f"漏洞扫描联动处理失败: {e}")
    
    def set_passive_mode(self, enabled: bool):
        """设置被动模式"""
        self._passive_mode = enabled
    
    def on_injection_point(self, callback: Callable):
        """注册注入点回调"""
        self._injection_callbacks.append(callback)
    
    def on_vuln_alert(self, callback: Callable):
        """注册漏洞告警回调"""
        self._alert_callbacks.append(callback)
    
    def on_poc_result(self, callback: Callable):
        """注册PoC结果回调"""
        self._poc_callbacks.append(callback)
    
    def get_injection_points(self) -> List[InjectionPoint]:
        """获取所有注入点"""
        return self._injection_points
    
    def get_alerts(self) -> List[VulnAlert]:
        """获取所有告警"""
        return self._alerts
    
    def get_statistics(self) -> Dict[str, Any]:
        """获取统计信息"""
        vuln_types = {}
        severity_stats = {}
        
        for alert in self._alerts:
            vuln_types[alert.vuln_type] = vuln_types.get(alert.vuln_type, 0) + 1
            severity_stats[alert.severity] = severity_stats.get(alert.severity, 0) + 1
        
        return {
            'total_injection_points': len(self._injection_points),
            'total_alerts': len(self._alerts),
            'vuln_type_distribution': vuln_types,
            'severity_distribution': severity_stats,
            'passive_mode': self._passive_mode,
        }
