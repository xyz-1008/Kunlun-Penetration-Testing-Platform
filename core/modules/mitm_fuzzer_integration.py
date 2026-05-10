"""
MITM代理与Web Fuzzer联动模块
实现流量到Fuzzer的无缝集成
"""

import re
import json
import logging
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass
from urllib.parse import urlparse, parse_qs, urlencode

logger = logging.getLogger(__name__)


@dataclass
class FuzzableParam:
    """可Fuzz参数"""
    name: str
    position: str  # query, body, header, path, cookie
    value: str
    param_type: str  # string, number, boolean, json
    is_suspicious: bool = False  # 是否可疑
    suspicion_reason: str = ""


@dataclass
class FuzzerRequest:
    """发送到Fuzzer的请求"""
    id: str
    raw_request: str
    method: str
    url: str
    headers: Dict[str, str]
    body: str
    fuzzable_params: List[FuzzableParam]
    template: str  # Fuzzer模板（带fuzztag标记）


class FuzzerIntegration:
    """Web Fuzzer集成器"""
    
    def __init__(self):
        self._fuzzer_callback: Optional[Callable] = None
        self._param_patterns = {
            'query': re.compile(r'[?&]([^=&]+)=([^&]*)'),
            'json_body': re.compile(r'"([^"]+)"\s*:\s*("[^"]*"|\d+|true|false|null)'),
            'form_body': re.compile(r'([^=&]+)=([^&]*)'),
            'header': re.compile(r'^([^:]+):\s*(.+)$', re.MULTILINE),
            'path': re.compile(r'/([^/]+)'),
        }
        
        self._suspicious_params = [
            'id', 'user', 'username', 'name', 'search', 'q', 'query',
            'file', 'path', 'url', 'redirect', 'callback', 'data',
            'input', 'value', 'param', 'key', 'token', 'page',
        ]
    
    def set_fuzzer_callback(self, callback: Callable):
        """设置Fuzzer回调"""
        self._fuzzer_callback = callback
    
    def analyze_request(self, request_data: Dict[str, Any]) -> FuzzerRequest:
        """分析请求，识别可Fuzz参数"""
        method = request_data.get('method', 'GET')
        url = request_data.get('url', '')
        headers = request_data.get('headers', {})
        body = request_data.get('body', '')
        
        fuzzable_params = []
        
        # 分析Query参数
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)
        for name, values in query_params.items():
            value = values[0] if values else ''
            is_suspicious, reason = self._check_suspicious(name, value)
            fuzzable_params.append(FuzzableParam(
                name=name,
                position='query',
                value=value,
                param_type=self._detect_type(value),
                is_suspicious=is_suspicious,
                suspicion_reason=reason
            ))
        
        # 分析Body参数
        content_type = headers.get('Content-Type', '')
        if 'application/json' in content_type:
            fuzzable_params.extend(self._analyze_json_body(body))
        elif 'application/x-www-form-urlencoded' in content_type:
            fuzzable_params.extend(self._analyze_form_body(body))
        
        # 分析可疑Header
        for name, value in headers.items():
            if name.lower() in ['x-forwarded-for', 'x-real-ip', 'x-client-ip', 'host']:
                fuzzable_params.append(FuzzableParam(
                    name=name,
                    position='header',
                    value=value,
                    param_type='string',
                    is_suspicious=True,
                    suspicion_reason='可伪造的Header'
                ))
        
        # 分析Path参数
        path_parts = parsed.path.strip('/').split('/')
        for i, part in enumerate(path_parts):
            if part and not part.isdigit():
                fuzzable_params.append(FuzzableParam(
                    name=f'path_{i}',
                    position='path',
                    value=part,
                    param_type=self._detect_type(part),
                    is_suspicious=False
                ))
        
        # 生成Fuzzer模板
        template = self._generate_fuzzer_template(url, body, fuzzable_params)
        
        return FuzzerRequest(
            id=request_data.get('id', ''),
            raw_request=self._build_raw_request(request_data),
            method=method,
            url=url,
            headers=headers,
            body=body,
            fuzzable_params=fuzzable_params,
            template=template
        )
    
    def send_to_fuzzer(self, request_data: Dict[str, Any], 
                       selected_params: Optional[List[str]] = None) -> bool:
        """发送请求到Web Fuzzer"""
        try:
            fuzzer_request = self.analyze_request(request_data)
            
            # 如果指定了参数，只发送选中的
            if selected_params:
                fuzzer_request.fuzzable_params = [
                    p for p in fuzzer_request.fuzzable_params 
                    if p.name in selected_params
                ]
            
            # 调用回调
            if self._fuzzer_callback:
                self._fuzzer_callback(fuzzer_request)
                logger.info(f"请求已发送到Fuzzer: {fuzzer_request.url}")
                return True
            else:
                logger.warning("Fuzzer回调未设置")
                return False
                
        except Exception as e:
            logger.error(f"发送到Fuzzer失败: {e}")
            return False
    
    def _check_suspicious(self, name: str, value: str) -> tuple:
        """检查参数是否可疑"""
        name_lower = name.lower()
        
        # 检查参数名
        if name_lower in self._suspicious_params:
            return True, f"参数名 '{name}' 常见于注入点"
        
        # 检查值中的注入特征
        injection_patterns = [
            (r'(?i)(union\s+select|or\s+1\s*=\s*1)', 'SQL注入特征'),
            (r'(?i)(<script|javascript:)', 'XSS特征'),
            (r'(?i)(\.\./|\.\.\\)', '路径遍历特征'),
            (r'(?i)(http://|https://|ftp://)', 'SSRF特征'),
        ]
        
        for pattern, reason in injection_patterns:
            if re.search(pattern, value):
                return True, reason
        
        return False, ""
    
    def _detect_type(self, value: str) -> str:
        """检测参数类型"""
        if value.lower() in ['true', 'false']:
            return 'boolean'
        try:
            int(value)
            return 'number'
        except ValueError:
            pass
        try:
            float(value)
            return 'number'
        except ValueError:
            pass
        
        # 尝试解析JSON
        try:
            json.loads(value)
            return 'json'
        except (json.JSONDecodeError, TypeError):
            pass
        
        return 'string'
    
    def _analyze_json_body(self, body: str) -> List[FuzzableParam]:
        """分析JSON Body"""
        params = []
        try:
            data = json.loads(body)
            self._extract_json_params(data, '', params)
        except json.JSONDecodeError:
            pass
        return params
    
    def _extract_json_params(self, data: Any, prefix: str, params: List[FuzzableParam]):
        """递归提取JSON参数"""
        if isinstance(data, dict):
            for key, value in data.items():
                full_key = f"{prefix}.{key}" if prefix else key
                if isinstance(value, (dict, list)):
                    self._extract_json_params(value, full_key, params)
                else:
                    str_value = str(value)
                    is_suspicious, reason = self._check_suspicious(key, str_value)
                    params.append(FuzzableParam(
                        name=full_key,
                        position='body',
                        value=str_value,
                        param_type=self._detect_type(str_value),
                        is_suspicious=is_suspicious,
                        suspicion_reason=reason
                    ))
        elif isinstance(data, list):
            for i, item in enumerate(data):
                full_key = f"{prefix}[{i}]"
                if isinstance(item, (dict, list)):
                    self._extract_json_params(item, full_key, params)
                else:
                    str_value = str(item)
                    params.append(FuzzableParam(
                        name=full_key,
                        position='body',
                        value=str_value,
                        param_type=self._detect_type(str_value)
                    ))
    
    def _analyze_form_body(self, body: str) -> List[FuzzableParam]:
        """分析表单Body"""
        params = []
        try:
            form_data = parse_qs(body)
            for name, values in form_data.items():
                value = values[0] if values else ''
                is_suspicious, reason = self._check_suspicious(name, value)
                params.append(FuzzableParam(
                    name=name,
                    position='body',
                    value=value,
                    param_type=self._detect_type(value),
                    is_suspicious=is_suspicious,
                    suspicion_reason=reason
                ))
        except Exception:
            pass
        return params
    
    def _generate_fuzzer_template(self, url: str, body: str, 
                                  params: List[FuzzableParam]) -> str:
        """生成Fuzzer模板"""
        # 替换URL中的参数为fuzztag
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)
        
        new_query = []
        for name, values in query_params.items():
            value = values[0] if values else ''
            param = next((p for p in params if p.name == name and p.position == 'query'), None)
            if param:
                new_query.append(f"{name}={{{{fuzz:{name}}}}}")
            else:
                new_query.append(f"{name}={value}")
        
        new_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        if new_query:
            new_url += "?" + "&".join(new_query)
        
        # 替换Body中的参数
        new_body = body
        content_type_lower = ''
        for param in params:
            if param.position == 'body':
                if param.param_type == 'json':
                    new_body = new_body.replace(f'"{param.value}"', f'{{{{fuzz:{param.name}}}}}')
                else:
                    new_body = new_body.replace(param.value, f'{{{{fuzz:{param.name}}}}}')
        
        return f"{new_url}\n\n{new_body}" if new_body else new_url
    
    def _build_raw_request(self, request_data: Dict[str, Any]) -> str:
        """构建原始请求字符串"""
        method = request_data.get('method', 'GET')
        url = request_data.get('url', '')
        headers = request_data.get('headers', {})
        body = request_data.get('body', '')
        
        parsed = urlparse(url)
        path = parsed.path
        if parsed.query:
            path += "?" + parsed.query
        
        lines = [f"{method} {path} HTTP/1.1"]
        for name, value in headers.items():
            lines.append(f"{name}: {value}")
        
        if body:
            lines.append("")
            lines.append(body)
        
        return "\r\n".join(lines)
    
    def get_param_statistics(self, fuzzer_request: FuzzerRequest) -> Dict[str, Any]:
        """获取参数统计"""
        stats = {
            'total_params': len(fuzzer_request.fuzzable_params),
            'suspicious_params': sum(1 for p in fuzzer_request.fuzzable_params if p.is_suspicious),
            'by_position': {},
            'by_type': {},
        }
        
        for param in fuzzer_request.fuzzable_params:
            stats['by_position'][param.position] = stats['by_position'].get(param.position, 0) + 1
            stats['by_type'][param.param_type] = stats['by_type'].get(param.param_type, 0) + 1
        
        return stats
