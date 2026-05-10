"""
自动应答与Mock模块 - 支持为特定URL配置自动应答
功能：
- 支持为特定URL配置自动应答，返回预设内容或本地文件
- 自动应答支持正则匹配URL，支持按状态码、Header、Body完全自定义
- 可用于模拟后端接口未完成时的前端调试
- 自动应答规则可导入导出
"""

import re
import json
import uuid
import logging
from typing import Dict, List, Any, Optional, Callable
from datetime import datetime
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class MockRule:
    """Mock规则"""
    id: str
    name: str
    description: str
    url_pattern: str  # 正则表达式
    is_regex: bool = True
    method: str = ".*"  # HTTP方法，支持正则
    status_code: int = 200
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    body_file: Optional[str] = None  # 本地文件路径
    delay_ms: float = 0  # 响应延迟
    is_enabled: bool = True
    match_count: int = 0
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class MockResponse:
    """Mock响应"""
    status_code: int
    headers: Dict[str, str]
    body: str
    delay_ms: float
    rule_id: str
    rule_name: str


class MockRuleEngine:
    """Mock规则引擎"""
    
    def __init__(self):
        self._rules: Dict[str, MockRule] = {}
        self._callbacks: List[Callable] = []
    
    def add_rule(self, name: str, description: str, url_pattern: str,
                 status_code: int = 200, headers: Dict[str, str] = None,
                 body: str = "", body_file: str = None,
                 delay_ms: float = 0, method: str = ".*",
                 is_regex: bool = True) -> MockRule:
        """添加Mock规则"""
        rule = MockRule(
            id=str(uuid.uuid4())[:12],
            name=name,
            description=description,
            url_pattern=url_pattern,
            is_regex=is_regex,
            method=method,
            status_code=status_code,
            headers=headers or {},
            body=body,
            body_file=body_file,
            delay_ms=delay_ms,
        )
        
        self._rules[rule.id] = rule
        return rule
    
    def update_rule(self, rule_id: str, **kwargs) -> Optional[MockRule]:
        """更新Mock规则"""
        if rule_id not in self._rules:
            return None
        
        rule = self._rules[rule_id]
        
        for key, value in kwargs.items():
            if hasattr(rule, key):
                setattr(rule, key, value)
        
        rule.updated_at = datetime.utcnow()
        return rule
    
    def delete_rule(self, rule_id: str) -> bool:
        """删除Mock规则"""
        if rule_id in self._rules:
            del self._rules[rule_id]
            return True
        return False
    
    def match_request(self, url: str, method: str = "GET") -> Optional[MockRule]:
        """匹配请求"""
        for rule in self._rules.values():
            if not rule.is_enabled:
                continue
            
            # 匹配方法
            if method and rule.method != ".*":
                if not re.match(rule.method, method, re.IGNORECASE):
                    continue
            
            # 匹配URL
            if rule.is_regex:
                if re.search(rule.url_pattern, url, re.IGNORECASE):
                    rule.match_count += 1
                    return rule
            else:
                if rule.url_pattern.lower() in url.lower():
                    rule.match_count += 1
                    return rule
        
        return None
    
    def generate_response(self, rule: MockRule) -> MockResponse:
        """生成Mock响应"""
        body = rule.body
        
        # 如果指定了文件，从文件读取
        if rule.body_file:
            try:
                file_path = Path(rule.body_file)
                if file_path.exists():
                    body = file_path.read_text(encoding='utf-8')
                else:
                    logger.error(f"Mock文件不存在: {rule.body_file}")
                    body = f"Error: File not found - {rule.body_file}"
            except Exception as e:
                logger.error(f"读取Mock文件失败: {e}")
                body = f"Error: {str(e)}"
        
        return MockResponse(
            status_code=rule.status_code,
            headers=rule.headers.copy(),
            body=body,
            delay_ms=rule.delay_ms,
            rule_id=rule.id,
            rule_name=rule.name,
        )
    
    def get_rules(self) -> List[MockRule]:
        """获取所有规则"""
        return list(self._rules.values())
    
    def get_rule(self, rule_id: str) -> Optional[MockRule]:
        """获取规则"""
        return self._rules.get(rule_id)
    
    def export_rules(self) -> str:
        """导出规则为JSON"""
        rules_data = []
        for rule in self._rules.values():
            rules_data.append({
                'id': rule.id,
                'name': rule.name,
                'description': rule.description,
                'url_pattern': rule.url_pattern,
                'is_regex': rule.is_regex,
                'method': rule.method,
                'status_code': rule.status_code,
                'headers': rule.headers,
                'body': rule.body,
                'body_file': rule.body_file,
                'delay_ms': rule.delay_ms,
                'is_enabled': rule.is_enabled,
                'created_at': rule.created_at.isoformat(),
                'updated_at': rule.updated_at.isoformat(),
            })
        
        export_data = {
            'version': '1.0',
            'type': 'mock_rules',
            'exported_at': datetime.utcnow().isoformat(),
            'rules': rules_data,
        }
        
        return json.dumps(export_data, indent=2, ensure_ascii=False)
    
    def import_rules(self, json_data: str) -> int:
        """导入规则"""
        try:
            data = json.loads(json_data)
            
            if data.get('type') != 'mock_rules':
                logger.error("无效的Mock规则格式")
                return 0
            
            imported_count = 0
            for rule_data in data.get('rules', []):
                rule = MockRule(
                    id=rule_data.get('id', str(uuid.uuid4())[:12]),
                    name=rule_data['name'],
                    description=rule_data.get('description', ''),
                    url_pattern=rule_data['url_pattern'],
                    is_regex=rule_data.get('is_regex', True),
                    method=rule_data.get('method', '.*'),
                    status_code=rule_data.get('status_code', 200),
                    headers=rule_data.get('headers', {}),
                    body=rule_data.get('body', ''),
                    body_file=rule_data.get('body_file'),
                    delay_ms=rule_data.get('delay_ms', 0),
                    is_enabled=rule_data.get('is_enabled', True),
                    created_at=datetime.fromisoformat(rule_data['created_at']) if rule_data.get('created_at') else datetime.utcnow(),
                    updated_at=datetime.fromisoformat(rule_data['updated_at']) if rule_data.get('updated_at') else datetime.utcnow(),
                )
                
                self._rules[rule.id] = rule
                imported_count += 1
            
            return imported_count
            
        except Exception as e:
            logger.error(f"导入Mock规则失败: {e}")
            return 0
    
    def on_rule_matched(self, callback: Callable):
        """注册规则匹配回调"""
        self._callbacks.append(callback)


class MockManager:
    """Mock管理器"""
    
    def __init__(self):
        self.rule_engine = MockRuleEngine()
        self._stats = {
            'total_requests': 0,
            'matched_requests': 0,
            'unmatched_requests': 0,
        }
    
    def handle_request(self, url: str, method: str = "GET") -> Optional[MockResponse]:
        """处理请求，返回Mock响应（如果匹配）"""
        self._stats['total_requests'] += 1
        
        rule = self.rule_engine.match_request(url, method)
        
        if rule:
            self._stats['matched_requests'] += 1
            
            # 通知规则匹配
            for callback in self.rule_engine._callbacks:
                try:
                    callback(rule, url, method)
                except Exception as e:
                    logger.error(f"规则匹配通知失败: {e}")
            
            return self.rule_engine.generate_response(rule)
        else:
            self._stats['unmatched_requests'] += 1
            return None
    
    def get_stats(self) -> Dict[str, int]:
        """获取统计信息"""
        return self._stats.copy()
    
    def reset_stats(self):
        """重置统计"""
        self._stats = {
            'total_requests': 0,
            'matched_requests': 0,
            'unmatched_requests': 0,
        }
    
    def create_api_mock(self, base_url: str, endpoint: str,
                        response_data: Dict, status_code: int = 200,
                        delay_ms: float = 0) -> MockRule:
        """快速创建API Mock"""
        url_pattern = f"{re.escape(base_url)}{re.escape(endpoint)}"
        
        return self.rule_engine.add_rule(
            name=f"Mock: {endpoint}",
            description=f"模拟API端点: {endpoint}",
            url_pattern=url_pattern,
            status_code=status_code,
            headers={'Content-Type': 'application/json'},
            body=json.dumps(response_data, ensure_ascii=False),
            delay_ms=delay_ms,
        )
    
    def create_file_mock(self, url_pattern: str, file_path: str,
                         content_type: str = "text/html",
                         status_code: int = 200) -> MockRule:
        """快速创建文件Mock"""
        return self.rule_engine.add_rule(
            name=f"Mock: {Path(file_path).name}",
            description=f"模拟文件: {file_path}",
            url_pattern=url_pattern,
            status_code=status_code,
            headers={'Content-Type': content_type},
            body_file=file_path,
        )
