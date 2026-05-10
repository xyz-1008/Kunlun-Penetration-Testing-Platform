"""
请求重放工具模块
基于20年渗透测试经验的专业级HTTP/HTTPS请求重放工具
支持单条重放、批量重放、并发重放、参数fuzzing等功能
"""

import asyncio
import httpx
import logging
import time
import random
import string
from typing import Dict, List, Optional, Callable, Any
from dataclasses import dataclass, field
from datetime import datetime
from urllib.parse import urlparse, parse_qs, urlencode
import json

logger = logging.getLogger(__name__)


@dataclass
class ReplayRequest:
    """重放请求数据类"""
    id: str
    method: str
    url: str
    headers: Dict[str, str] = field(default_factory=dict)
    body: bytes = b''
    timestamp: datetime = field(default_factory=datetime.now)
    tags: List[str] = field(default_factory=list)
    comment: str = ''
    
    def to_dict(self) -> Dict:
        """转换为字典格式"""
        return {
            'id': self.id,
            'method': self.method,
            'url': self.url,
            'headers': self.headers,
            'body': self.body.decode('utf-8', errors='ignore'),
            'timestamp': self.timestamp.isoformat(),
            'tags': self.tags,
            'comment': self.comment
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'ReplayRequest':
        """从字典创建对象"""
        return cls(
            id=data.get('id', ''),
            method=data.get('method', 'GET'),
            url=data.get('url', ''),
            headers=data.get('headers', {}),
            body=data.get('body', '').encode('utf-8'),
            timestamp=datetime.fromisoformat(data.get('timestamp', datetime.now().isoformat())),
            tags=data.get('tags', []),
            comment=data.get('comment', '')
        )


@dataclass
class ReplayResponse:
    """重放响应数据类"""
    request_id: str
    status_code: int
    headers: Dict[str, str]
    body: bytes
    elapsed: float
    timestamp: datetime
    error: Optional[str] = None
    
    def to_dict(self) -> Dict:
        """转换为字典格式"""
        return {
            'request_id': self.request_id,
            'status_code': self.status_code,
            'headers': self.headers,
            'body': self.body.decode('utf-8', errors='ignore'),
            'elapsed': self.elapsed,
            'timestamp': self.timestamp.isoformat(),
            'error': self.error
        }


@dataclass
class FuzzingConfig:
    """Fuzzing配置"""
    param_name: str
    payloads: List[str]
    position: str = 'query'  # query, body, header, path
    replace_mode: str = 'replace'  # replace, append, prepend
    encoding: str = 'none'  # none, url, base64, hex


class RequestRepeater:
    """专业级请求重放工具"""
    
    def __init__(self):
        self.requests: Dict[str, ReplayRequest] = {}
        self.responses: Dict[str, List[ReplayResponse]] = {}
        self.favorites: List[str] = []
        
        # 配置
        self.timeout: int = 30
        self.follow_redirects: bool = False
        self.verify_ssl: bool = False
        self.concurrency: int = 5
        
        # 回调函数
        self.on_request_complete: Optional[Callable] = None
        self.on_batch_complete: Optional[Callable] = None
        
        logger.info("专业级请求重放工具初始化完成")
    
    def add_request(self, method: str, url: str, headers: Dict = None, body: bytes = None) -> str:
        """添加请求"""
        import uuid
        request_id = str(uuid.uuid4())
        
        request = ReplayRequest(
            id=request_id,
            method=method.upper(),
            url=url,
            headers=headers or {},
            body=body or b''
        )
        
        self.requests[request_id] = request
        self.responses[request_id] = []
        
        logger.info(f"添加请求: {method} {url}")
        return request_id
    
    def remove_request(self, request_id: str) -> bool:
        """移除请求"""
        if request_id in self.requests:
            del self.requests[request_id]
            if request_id in self.responses:
                del self.responses[request_id]
            if request_id in self.favorites:
                self.favorites.remove(request_id)
            logger.info(f"移除请求: {request_id}")
            return True
        return False
    
    def tag_request(self, request_id: str, tag: str) -> bool:
        """为请求添加标签"""
        if request_id in self.requests:
            if tag not in self.requests[request_id].tags:
                self.requests[request_id].tags.append(tag)
            return True
        return False
    
    def favorite_request(self, request_id: str) -> bool:
        """收藏请求"""
        if request_id in self.requests and request_id not in self.favorites:
            self.favorites.append(request_id)
            return True
        return False
    
    async def replay_request(self, request_id: str) -> Optional[ReplayResponse]:
        """重放单个请求"""
        if request_id not in self.requests:
            logger.error(f"请求不存在: {request_id}")
            return None
        
        request = self.requests[request_id]
        
        try:
            start_time = time.time()
            
            async with httpx.AsyncClient(
                timeout=self.timeout,
                follow_redirects=self.follow_redirects,
                verify=self.verify_ssl
            ) as client:
                response = await client.request(
                    method=request.method,
                    url=request.url,
                    headers=request.headers,
                    content=request.body
                )
                
                elapsed = time.time() - start_time
                
                replay_response = ReplayResponse(
                    request_id=request_id,
                    status_code=response.status_code,
                    headers=dict(response.headers),
                    body=response.content,
                    elapsed=elapsed,
                    timestamp=datetime.now()
                )
                
                self.responses[request_id].append(replay_response)
                
                if self.on_request_complete:
                    self.on_request_complete(replay_response)
                
                logger.info(f"请求重放成功: {request.method} {request.url} - {response.status_code}")
                return replay_response
                
        except Exception as e:
            error_response = ReplayResponse(
                request_id=request_id,
                status_code=0,
                headers={},
                body=b'',
                elapsed=0,
                timestamp=datetime.now(),
                error=str(e)
            )
            self.responses[request_id].append(error_response)
            logger.error(f"请求重放失败: {e}")
            return error_response
    
    async def replay_multiple(self, request_ids: List[str]) -> List[ReplayResponse]:
        """批量重放请求"""
        semaphore = asyncio.Semaphore(self.concurrency)
        
        async def _replay_with_semaphore(request_id: str):
            async with semaphore:
                return await self.replay_request(request_id)
        
        tasks = [_replay_with_semaphore(request_id) for request_id in request_ids]
        responses = await asyncio.gather(*tasks)
        
        if self.on_batch_complete:
            self.on_batch_complete(responses)
        
        return [r for r in responses if r is not None]
    
    async def replay_all(self) -> List[ReplayResponse]:
        """重放所有请求"""
        return await self.replay_multiple(list(self.requests.keys()))
    
    async def fuzz_request(self, request_id: str, fuzzing_config: FuzzingConfig) -> List[ReplayResponse]:
        """Fuzzing请求"""
        if request_id not in self.requests:
            logger.error(f"请求不存在: {request_id}")
            return []
        
        original_request = self.requests[request_id]
        responses = []
        
        for payload in fuzzing_config.payloads:
            modified_request = self._apply_fuzzing_payload(
                original_request,
                fuzzing_config,
                payload
            )
            
            import uuid
            fuzz_id = str(uuid.uuid4())
            self.requests[fuzz_id] = modified_request
            self.responses[fuzz_id] = []
            
            response = await self.replay_request(fuzz_id)
            if response:
                responses.append(response)
        
        return responses
    
    def _apply_fuzzing_payload(self, request: ReplayRequest, config: FuzzingConfig, payload: str) -> ReplayRequest:
        """应用Fuzzing载荷"""
        import copy
        modified = copy.deepcopy(request)
        
        # 编码处理
        payload = self._encode_payload(payload, config.encoding)
        
        if config.position == 'query':
            modified.url = self._modify_query_param(request.url, config.param_name, payload, config.replace_mode)
        
        elif config.position == 'body':
            modified.body = self._modify_body_param(request.body, config.param_name, payload, config.replace_mode)
        
        elif config.position == 'header':
            if config.replace_mode == 'replace':
                modified.headers[config.param_name] = payload
            elif config.replace_mode == 'append':
                if config.param_name in modified.headers:
                    modified.headers[config.param_name] = modified.headers[config.param_name] + payload
                else:
                    modified.headers[config.param_name] = payload
        
        elif config.position == 'path':
            modified.url = self._modify_path_param(request.url, config.param_name, payload)
        
        return modified
    
    def _encode_payload(self, payload: str, encoding: str) -> str:
        """编码载荷"""
        import base64
        import urllib.parse
        
        if encoding == 'url':
            return urllib.parse.quote(payload)
        elif encoding == 'base64':
            return base64.b64encode(payload.encode()).decode()
        elif encoding == 'hex':
            return payload.encode().hex()
        return payload
    
    def _modify_query_param(self, url: str, param_name: str, payload: str, mode: str) -> str:
        """修改查询参数"""
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)
        
        if param_name in query_params:
            if mode == 'replace':
                query_params[param_name] = [payload]
            elif mode == 'append':
                query_params[param_name] = [query_params[param_name][0] + payload]
            elif mode == 'prepend':
                query_params[param_name] = [payload + query_params[param_name][0]]
        else:
            query_params[param_name] = [payload]
        
        new_query = urlencode(query_params, doseq=True)
        return parsed._replace(query=new_query).geturl()
    
    def _modify_body_param(self, body: bytes, param_name: str, payload: str, mode: str) -> bytes:
        """修改请求体参数"""
        try:
            content_type = ''
            # 尝试解析为表单
            body_str = body.decode('utf-8', errors='ignore')
            params = parse_qs(body_str)
            
            if param_name in params:
                if mode == 'replace':
                    params[param_name] = [payload]
                elif mode == 'append':
                    params[param_name] = [params[param_name][0] + payload]
                elif mode == 'prepend':
                    params[param_name] = [payload + params[param_name][0]]
            else:
                params[param_name] = [payload]
            
            return urlencode(params, doseq=True).encode()
            
        except:
            return body
    
    def _modify_path_param(self, url: str, param_name: str, payload: str) -> str:
        """修改路径参数"""
        # 简单实现：替换路径中的占位符
        placeholder = f'{{{param_name}}}'
        return url.replace(placeholder, payload)
    
    async def compare_responses(self, request_id: str) -> List[Dict]:
        """比较响应"""
        if request_id not in self.responses:
            return []
        
        responses = self.responses[request_id]
        if len(responses) < 2:
            return []
        
        comparisons = []
        for i in range(1, len(responses)):
            comparisons.append(self._compare_two_responses(responses[i-1], responses[i]))
        
        return comparisons
    
    def _compare_two_responses(self, resp1: ReplayResponse, resp2: ReplayResponse) -> Dict:
        """比较两个响应"""
        diff = {
            'status_code_changed': resp1.status_code != resp2.status_code,
            'status_code_diff': {'old': resp1.status_code, 'new': resp2.status_code},
            'body_changed': resp1.body != resp2.body,
            'body_length_diff': {'old': len(resp1.body), 'new': len(resp2.body)},
            'headers_changed': resp1.headers != resp2.headers,
            'elapsed_diff': {'old': resp1.elapsed, 'new': resp2.elapsed, 'diff': resp2.elapsed - resp1.elapsed}
        }
        return diff
    
    def get_request(self, request_id: str) -> Optional[ReplayRequest]:
        """获取请求"""
        return self.requests.get(request_id)
    
    def get_all_requests(self) -> List[ReplayRequest]:
        """获取所有请求"""
        return list(self.requests.values())
    
    def get_responses(self, request_id: str) -> List[ReplayResponse]:
        """获取响应历史"""
        return self.responses.get(request_id, [])
    
    def get_favorites(self) -> List[ReplayRequest]:
        """获取收藏的请求"""
        return [self.requests[rid] for rid in self.favorites if rid in self.requests]
    
    def search_requests(self, keyword: str) -> List[ReplayRequest]:
        """搜索请求"""
        keyword = keyword.lower()
        results = []
        
        for request in self.requests.values():
            if (keyword in request.method.lower() or
                keyword in request.url.lower() or
                keyword in request.comment.lower() or
                keyword in ' '.join(request.tags).lower() or
                keyword in str(request.headers).lower()):
                results.append(request)
        
        return results
    
    def export_requests(self, filepath: str) -> bool:
        """导出请求"""
        try:
            export_data = {
                'requests': [req.to_dict() for req in self.requests.values()],
                'favorites': self.favorites
            }
            
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, ensure_ascii=False, indent=2)
            
            logger.info(f"请求导出成功: {filepath}")
            return True
            
        except Exception as e:
            logger.error(f"请求导出失败: {e}")
            return False
    
    def import_requests(self, filepath: str) -> bool:
        """导入请求"""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                import_data = json.load(f)
            
            for req_data in import_data.get('requests', []):
                req = ReplayRequest.from_dict(req_data)
                self.requests[req.id] = req
                self.responses[req.id] = []
            
            self.favorites = import_data.get('favorites', [])
            
            logger.info(f"请求导入成功: {filepath}")
            return True
            
        except Exception as e:
            logger.error(f"请求导入失败: {e}")
            return False
    
    def generate_payloads(self, payload_type: str) -> List[str]:
        """生成测试载荷"""
        if payload_type == 'sqli':
            return [
                "' OR '1'='1",
                "' OR '1'='1'--",
                "'; DROP TABLE users;--",
                "1' UNION SELECT NULL--",
                "' OR 1=1--"
            ]
        elif payload_type == 'xss':
            return [
                "<script>alert('xss')</script>",
                "<img src=x onerror=alert(1)>",
                "\" onmouseover=\"alert(1)",
                "'><script>alert(1)</script>"
            ]
        elif payload_type == 'lfi':
            return [
                "../../../etc/passwd",
                "../../../../windows/win.ini",
                "../etc/passwd%00",
                "..%2F..%2F..%2Fetc%2Fpasswd"
            ]
        else:
            return []
    
    def set_timeout(self, timeout: int):
        """设置超时时间"""
        self.timeout = timeout
    
    def set_concurrency(self, concurrency: int):
        """设置并发数"""
        self.concurrency = max(1, concurrency)
    
    def set_request_complete_callback(self, callback: Callable):
        """设置请求完成回调"""
        self.on_request_complete = callback
    
    def set_batch_complete_callback(self, callback: Callable):
        """设置批量完成回调"""
        self.on_batch_complete = callback
