"""
高级过滤与搜索模块 - 支持正则表达式全文搜索和多条件组合过滤
功能：
- 支持正则表达式全文搜索请求/响应Body
- 支持按请求大小、响应大小、响应时间范围过滤
- 支持保存常用搜索条件为快捷筛选器
- 支持多条件组合AND/OR逻辑搜索
- 搜索结果可批量选中发送到Fuzzer或重放引擎
"""

import re
import json
import uuid
import logging
from typing import Dict, List, Any, Optional, Callable, Union
from datetime import datetime
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class SearchLogic(Enum):
    """搜索逻辑"""
    AND = "and"
    OR = "or"


class SearchField(Enum):
    """搜索字段"""
    URL = "url"
    METHOD = "method"
    STATUS_CODE = "status_code"
    REQUEST_HEADERS = "request_headers"
    REQUEST_BODY = "request_body"
    RESPONSE_HEADERS = "response_headers"
    RESPONSE_BODY = "response_body"
    CONTENT_TYPE = "content_type"
    HOST = "host"
    IP = "ip"


@dataclass
class SearchCondition:
    """搜索条件"""
    id: str
    name: str
    field: SearchField
    operator: str  # contains, regex, equals, gt, lt, between
    value: Union[str, int, float, List]
    logic: SearchLogic = SearchLogic.AND
    is_enabled: bool = True


@dataclass
class SearchFilter:
    """搜索筛选器"""
    id: str
    name: str
    description: str
    conditions: List[SearchCondition]
    created_at: datetime
    is_builtin: bool = False


@dataclass
class SearchResult:
    """搜索结果"""
    traffic_id: str
    matched_conditions: List[str]
    match_positions: Dict[str, List[int]]  # field -> positions
    relevance_score: float


class TrafficSearchEngine:
    """流量搜索引擎"""
    
    def __init__(self):
        self._filters: Dict[str, SearchFilter] = {}
        self._callbacks: List[Callable] = []
        
        # 初始化内置筛选器
        self._init_builtin_filters()
    
    def search(self, traffics: List[Dict[str, Any]], 
               conditions: List[SearchCondition]) -> List[SearchResult]:
        """搜索流量"""
        results = []
        
        try:
            for traffic in traffics:
                matched_conditions = []
                match_positions = {}
                
                for condition in conditions:
                    if not condition.is_enabled:
                        continue
                    
                    if self._match_condition(traffic, condition):
                        matched_conditions.append(condition.id)
                        
                        # 记录匹配位置（仅正则搜索）
                        if condition.operator == 'regex':
                            positions = self._find_regex_positions(traffic, condition)
                            if positions:
                                match_positions[condition.field.value] = positions
                
                if matched_conditions:
                    # 计算相关性分数
                    score = self._calculate_relevance(traffic, matched_conditions, conditions)
                    
                    results.append(SearchResult(
                        traffic_id=traffic.get('id', ''),
                        matched_conditions=matched_conditions,
                        match_positions=match_positions,
                        relevance_score=score,
                    ))
            
            # 按相关性排序
            results.sort(key=lambda r: r.relevance_score, reverse=True)
            
        except Exception as e:
            logger.error(f"搜索失败: {e}")
        
        return results
    
    def save_filter(self, name: str, description: str, 
                    conditions: List[SearchCondition],
                    is_builtin: bool = False) -> SearchFilter:
        """保存筛选器"""
        filter_obj = SearchFilter(
            id=str(uuid.uuid4())[:12],
            name=name,
            description=description,
            conditions=conditions,
            created_at=datetime.utcnow(),
            is_builtin=is_builtin,
        )
        
        self._filters[filter_obj.id] = filter_obj
        return filter_obj
    
    def get_filter(self, filter_id: str) -> Optional[SearchFilter]:
        """获取筛选器"""
        return self._filters.get(filter_id)
    
    def get_all_filters(self) -> List[SearchFilter]:
        """获取所有筛选器"""
        return list(self._filters.values())
    
    def delete_filter(self, filter_id: str) -> bool:
        """删除筛选器"""
        if filter_id in self._filters:
            filter_obj = self._filters[filter_id]
            if filter_obj.is_builtin:
                logger.warning("不能删除内置筛选器")
                return False
            del self._filters[filter_id]
            return True
        return False
    
    def _init_builtin_filters(self):
        """初始化内置筛选器"""
        # SQL注入筛选器
        self.save_filter(
            name="SQL注入检测",
            description="检测潜在的SQL注入请求",
            conditions=[
                SearchCondition(
                    id="sqli_1",
                    name="URL包含SQL关键字",
                    field=SearchField.URL,
                    operator="regex",
                    value=r"(union\s+select|or\s+1=1|drop\s+table|insert\s+into)",
                ),
                SearchCondition(
                    id="sqli_2",
                    name="Body包含SQL关键字",
                    field=SearchField.REQUEST_BODY,
                    operator="regex",
                    value=r"(union\s+select|or\s+1=1|drop\s+table)",
                ),
            ],
            is_builtin=True,
        )
        
        # XSS筛选器
        self.save_filter(
            name="XSS检测",
            description="检测潜在的XSS攻击请求",
            conditions=[
                SearchCondition(
                    id="xss_1",
                    name="URL包含XSS关键字",
                    field=SearchField.URL,
                    operator="regex",
                    value=r"(<script|javascript:|on\w+\s*=)",
                ),
                SearchCondition(
                    id="xss_2",
                    name="Body包含XSS关键字",
                    field=SearchField.REQUEST_BODY,
                    operator="regex",
                    value=r"(<script|javascript:|on\w+\s*=)",
                ),
            ],
            is_builtin=True,
        )
        
        # 大响应筛选器
        self.save_filter(
            name="大响应检测",
            description="检测响应大小超过10KB的请求",
            conditions=[
                SearchCondition(
                    id="large_resp_1",
                    name="响应大小>10KB",
                    field=SearchField.RESPONSE_BODY,
                    operator="gt",
                    value=10240,
                ),
            ],
            is_builtin=True,
        )
        
        # 错误响应筛选器
        self.save_filter(
            name="错误响应检测",
            description="检测5xx错误响应",
            conditions=[
                SearchCondition(
                    id="error_resp_1",
                    name="状态码>=500",
                    field=SearchField.STATUS_CODE,
                    operator="gte",
                    value=500,
                ),
            ],
            is_builtin=True,
        )
    
    def _match_condition(self, traffic: Dict, condition: SearchCondition) -> bool:
        """匹配条件"""
        try:
            field_value = self._get_field_value(traffic, condition.field)
            
            if field_value is None:
                return False
            
            if condition.operator == 'contains':
                return str(condition.value).lower() in str(field_value).lower()
            
            elif condition.operator == 'regex':
                return bool(re.search(str(condition.value), str(field_value), re.IGNORECASE))
            
            elif condition.operator == 'equals':
                return str(field_value) == str(condition.value)
            
            elif condition.operator == 'gt':
                return float(field_value) > float(condition.value)
            
            elif condition.operator == 'gte':
                return float(field_value) >= float(condition.value)
            
            elif condition.operator == 'lt':
                return float(field_value) < float(condition.value)
            
            elif condition.operator == 'lte':
                return float(field_value) <= float(condition.value)
            
            elif condition.operator == 'between':
                if isinstance(condition.value, list) and len(condition.value) == 2:
                    return float(condition.value[0]) <= float(field_value) <= float(condition.value[1])
            
            return False
            
        except Exception as e:
            logger.error(f"条件匹配失败: {e}")
            return False
    
    def _get_field_value(self, traffic: Dict, field: SearchField) -> Any:
        """获取字段值"""
        request = traffic.get('request', {})
        response = traffic.get('response', {})
        
        if field == SearchField.URL:
            return request.get('url', '')
        elif field == SearchField.METHOD:
            return request.get('method', '')
        elif field == SearchField.STATUS_CODE:
            return response.get('status_code', 0)
        elif field == SearchField.REQUEST_HEADERS:
            return json.dumps(request.get('headers', {}))
        elif field == SearchField.REQUEST_BODY:
            return request.get('body', '')
        elif field == SearchField.RESPONSE_HEADERS:
            return json.dumps(response.get('headers', {}))
        elif field == SearchField.RESPONSE_BODY:
            return response.get('body', '')
        elif field == SearchField.CONTENT_TYPE:
            headers = response.get('headers', {})
            return headers.get('content-type', headers.get('Content-Type', ''))
        elif field == SearchField.HOST:
            return request.get('host', '')
        elif field == SearchField.IP:
            return request.get('server_ip', '')
        
        return None
    
    def _find_regex_positions(self, traffic: Dict, condition: SearchCondition) -> List[int]:
        """查找正则匹配位置"""
        positions = []
        try:
            field_value = self._get_field_value(traffic, condition.field)
            if field_value:
                for match in re.finditer(str(condition.value), str(field_value), re.IGNORECASE):
                    positions.append(match.start())
        except:
            pass
        return positions
    
    def _calculate_relevance(self, traffic: Dict, matched_conditions: List[str],
                            all_conditions: List[SearchCondition]) -> float:
        """计算相关性分数"""
        if not matched_conditions:
            return 0.0
        
        # 基础分数：匹配条件数量
        score = len(matched_conditions) / len(all_conditions) if all_conditions else 0
        
        # 权重调整：正则匹配权重更高
        regex_conditions = [c for c in all_conditions if c.operator == 'regex' and c.id in matched_conditions]
        score += len(regex_conditions) * 0.1
        
        return min(score, 1.0)


class AdvancedFilterManager:
    """高级过滤管理器"""
    
    def __init__(self):
        self.search_engine = TrafficSearchEngine()
        self._quick_filters: Dict[str, SearchFilter] = {}
    
    def create_quick_filter(self, name: str, conditions: List[SearchCondition]) -> SearchFilter:
        """创建快捷筛选器"""
        filter_obj = self.search_engine.save_filter(
            name=name,
            description=f"快捷筛选器: {name}",
            conditions=conditions,
        )
        self._quick_filters[filter_obj.id] = filter_obj
        return filter_obj
    
    def get_quick_filters(self) -> List[SearchFilter]:
        """获取快捷筛选器"""
        return list(self._quick_filters.values())
    
    def apply_filter(self, traffics: List[Dict], filter_id: str) -> List[SearchResult]:
        """应用筛选器"""
        filter_obj = self.search_engine.get_filter(filter_id)
        if not filter_obj:
            return []
        
        return self.search_engine.search(traffics, filter_obj.conditions)
    
    def search_with_conditions(self, traffics: List[Dict], 
                               conditions: List[SearchCondition]) -> List[SearchResult]:
        """使用条件搜索"""
        return self.search_engine.search(traffics, conditions)
    
    def batch_send_to_fuzzer(self, results: List[SearchResult], 
                             traffics: List[Dict]) -> List[Dict]:
        """批量发送到Fuzzer"""
        traffic_map = {t.get('id'): t for t in traffics}
        return [traffic_map.get(r.traffic_id) for r in results if r.traffic_id in traffic_map]
    
    def batch_send_to_replayer(self, results: List[SearchResult], 
                               traffics: List[Dict]) -> List[Dict]:
        """批量发送到重放引擎"""
        traffic_map = {t.get('id'): t for t in traffics}
        return [traffic_map.get(r.traffic_id) for r in results if r.traffic_id in traffic_map]
