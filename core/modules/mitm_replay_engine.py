"""
高级流量重放引擎 - 支持多步骤请求序列录制与回放
功能：
- 支持多步骤请求序列录制与回放，自动处理Cookie和Token传递
- 重放时支持变量提取：从响应中提取Token并替换后续请求中的认证头
- 支持时间间隔模拟：按原始时间间隔或自定义速度回放
- 批量重放时自动对比结果，生成差异报告
- 重放任务可保存为模板，支持定时执行
"""

import re
import json
import uuid
import time
import asyncio
import logging
import requests
from typing import Dict, List, Any, Optional, Callable, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class ReplaySpeed(Enum):
    """重放速度"""
    ORIGINAL = "original"
    FAST = "fast"
    SLOW = "slow"
    CUSTOM = "custom"


class ReplayStatus(Enum):
    """重放状态"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class ReplayStep:
    """重放步骤"""
    id: str
    request_data: Dict[str, Any]
    original_response: Optional[Dict[str, Any]] = None
    replay_response: Optional[Dict[str, Any]] = None
    variables_to_extract: List[str] = field(default_factory=list)
    variables_to_inject: Dict[str, str] = field(default_factory=dict)
    delay_after: float = 0.0  # 秒
    order: int = 0


@dataclass
class ReplayTask:
    """重放任务"""
    id: str
    name: str
    description: str
    steps: List[ReplayStep]
    status: ReplayStatus
    speed: ReplaySpeed
    created_at: datetime
    custom_delay: float = 0.0
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    results: Dict[str, Any] = field(default_factory=dict)
    is_template: bool = False
    schedule: Optional[str] = None  # cron表达式


@dataclass
class ReplayResult:
    """重放结果"""
    task_id: str
    step_id: str
    original_response: Optional[Dict[str, Any]]
    replay_response: Optional[Dict[str, Any]]
    differences: List[Dict[str, Any]]
    status: str
    error: Optional[str] = None
    duration: float = 0.0


class VariableExtractor:
    """变量提取器"""
    
    def __init__(self):
        self._patterns = {
            'json': re.compile(r'"([^"]+)"\s*:\s*"([^"]+)"'),
            'header': re.compile(r'([A-Za-z0-9-]+)\s*:\s*(.+)'),
            'cookie': re.compile(r'(\w+)\s*=\s*([^;]+)'),
            'token': re.compile(r'(?:token|jwt|access_token|bearer)\s*[=:]\s*([A-Za-z0-9_\-\.]+)'),
        }
    
    def extract_from_response(self, response_data: Dict[str, Any], 
                               variable_names: List[str]) -> Dict[str, str]:
        """从响应中提取变量"""
        extracted = {}
        
        try:
            # 从响应体提取
            body = response_data.get('body', '')
            headers = response_data.get('headers', {})
            
            # 尝试JSON解析
            try:
                json_data = json.loads(body) if body else {}
                for var_name in variable_names:
                    value = self._extract_from_json(json_data, var_name)
                    if value is not None:
                        extracted[var_name] = str(value)
            except:
                # 使用正则提取
                for var_name in variable_names:
                    pattern = re.compile(rf'"{var_name}"\s*:\s*"([^"]+)"')
                    match = pattern.search(body)
                    if match:
                        extracted[var_name] = match.group(1)
            
            # 从Header提取
            for var_name in variable_names:
                if var_name in headers:
                    extracted[var_name] = headers[var_name]
            
            # 从Cookie提取
            set_cookie = headers.get('set-cookie', headers.get('Set-Cookie', ''))
            if set_cookie:
                for var_name in variable_names:
                    pattern = re.compile(rf'{var_name}=([^;]+)')
                    match = pattern.search(set_cookie)
                    if match:
                        extracted[var_name] = match.group(1)
            
        except Exception as e:
            logger.error(f"变量提取失败: {e}")
        
        return extracted
    
    def _extract_from_json(self, data: Any, key: str) -> Any:
        """从JSON数据中提取值"""
        if isinstance(data, dict):
            if key in data:
                return data[key]
            for v in data.values():
                result = self._extract_from_json(v, key)
                if result is not None:
                    return result
        elif isinstance(data, list):
            for item in data:
                result = self._extract_from_json(item, key)
                if result is not None:
                    return result
        return None


class ResponseComparator:
    """响应比较器"""
    
    def compare(self, original: Dict[str, Any], 
                replay: Dict[str, Any]) -> List[Dict[str, Any]]:
        """比较原始响应和重放响应"""
        differences = []
        
        try:
            # 比较状态码
            orig_status = original.get('status_code', 0)
            replay_status = replay.get('status_code', 0)
            if orig_status != replay_status:
                differences.append({
                    'field': 'status_code',
                    'original': orig_status,
                    'replay': replay_status,
                    'type': 'value_change',
                })
            
            # 比较Headers
            orig_headers = original.get('headers', {})
            replay_headers = replay.get('headers', {})
            
            all_headers = set(list(orig_headers.keys()) + list(replay_headers.keys()))
            for header in all_headers:
                orig_val = orig_headers.get(header)
                replay_val = replay_headers.get(header)
                if orig_val != replay_val:
                    differences.append({
                        'field': f'header.{header}',
                        'original': orig_val,
                        'replay': replay_val,
                        'type': 'value_change',
                    })
            
            # 比较Body
            orig_body = original.get('body', '')
            replay_body = replay.get('body', '')
            
            if orig_body != replay_body:
                # 尝试JSON比较
                try:
                    orig_json = json.loads(orig_body)
                    replay_json = json.loads(replay_body)
                    json_diffs = self._compare_json(orig_json, replay_json)
                    differences.extend(json_diffs)
                except:
                    # 文本比较
                    differences.append({
                        'field': 'body',
                        'original': orig_body[:200],
                        'replay': replay_body[:200],
                        'type': 'body_change',
                    })
            
        except Exception as e:
            logger.error(f"响应比较失败: {e}")
        
        return differences
    
    def _compare_json(self, orig: Any, replay: Any, path: str = "") -> List[Dict]:
        """比较JSON数据"""
        diffs = []
        
        if type(orig) != type(replay):
            diffs.append({
                'field': path or 'root',
                'original': str(orig),
                'replay': str(replay),
                'type': 'type_change',
            })
            return diffs
        
        if isinstance(orig, dict):
            all_keys = set(list(orig.keys()) + list(replay.keys()))
            for key in all_keys:
                new_path = f"{path}.{key}" if path else key
                if key not in orig:
                    diffs.append({
                        'field': new_path,
                        'original': None,
                        'replay': replay[key],
                        'type': 'added',
                    })
                elif key not in replay:
                    diffs.append({
                        'field': new_path,
                        'original': orig[key],
                        'replay': None,
                        'type': 'removed',
                    })
                else:
                    diffs.extend(self._compare_json(orig[key], replay[key], new_path))
        
        elif isinstance(orig, list):
            if len(orig) != len(replay):
                diffs.append({
                    'field': path or 'root',
                    'original': f"array[{len(orig)}]",
                    'replay': f"array[{len(replay)}]",
                    'type': 'length_change',
                })
            else:
                for i, (o, r) in enumerate(zip(orig, replay)):
                    diffs.extend(self._compare_json(o, r, f"{path}[{i}]"))
        
        elif orig != replay:
            diffs.append({
                'field': path or 'root',
                'original': orig,
                'replay': replay,
                'type': 'value_change',
            })
        
        return diffs


class TrafficReplayerEngine:
    """流量重放引擎"""
    
    def __init__(self):
        self.variable_extractor = VariableExtractor()
        self.comparator = ResponseComparator()
        
        self._tasks: Dict[str, ReplayTask] = {}
        self._results: Dict[str, List[ReplayResult]] = {}
        self._callbacks: Dict[str, List[Callable]] = {
            'on_task_start': [],
            'on_task_complete': [],
            'on_step_complete': [],
        }
    
    def create_task(self, name: str, description: str, 
                    steps: List[Dict[str, Any]], 
                    speed: ReplaySpeed = ReplaySpeed.ORIGINAL,
                    custom_delay: float = 0.0,
                    is_template: bool = False,
                    schedule: str = None) -> ReplayTask:
        """创建重放任务"""
        task = ReplayTask(
            id=str(uuid.uuid4())[:12],
            name=name,
            description=description,
            steps=[self._dict_to_step(s, i) for i, s in enumerate(steps)],
            status=ReplayStatus.PENDING,
            speed=speed,
            custom_delay=custom_delay,
            created_at=datetime.utcnow(),
            is_template=is_template,
            schedule=schedule,
        )
        
        self._tasks[task.id] = task
        return task
    
    async def execute_task(self, task_id: str) -> List[ReplayResult]:
        """执行重放任务"""
        if task_id not in self._tasks:
            logger.error(f"任务不存在: {task_id}")
            return []
        
        task = self._tasks[task_id]
        task.status = ReplayStatus.RUNNING
        task.started_at = datetime.utcnow()
        
        # 通知任务开始
        for callback in self._callbacks['on_task_start']:
            try:
                callback(task)
            except Exception as e:
                logger.error(f"任务开始通知失败: {e}")
        
        results = []
        extracted_vars = {}
        
        try:
            for step in sorted(task.steps, key=lambda s: s.order):
                # 注入变量
                request_data = self._inject_variables(step.request_data, extracted_vars)
                request_data.update(step.variables_to_inject)
                
                # 执行请求
                start_time = time.time()
                try:
                    response = await self._send_request(request_data)
                    duration = time.time() - start_time
                    
                    # 提取变量
                    if step.variables_to_extract:
                        new_vars = self.variable_extractor.extract_from_response(
                            response, step.variables_to_extract
                        )
                        extracted_vars.update(new_vars)
                    
                    # 比较响应
                    differences = []
                    if step.original_response:
                        differences = self.comparator.compare(
                            step.original_response, response
                        )
                    
                    result = ReplayResult(
                        task_id=task_id,
                        step_id=step.id,
                        original_response=step.original_response,
                        replay_response=response,
                        differences=differences,
                        status='success',
                        duration=duration,
                    )
                    
                except Exception as e:
                    result = ReplayResult(
                        task_id=task_id,
                        step_id=step.id,
                        original_response=step.original_response,
                        replay_response=None,
                        differences=[],
                        status='failed',
                        error=str(e),
                        duration=time.time() - start_time,
                    )
                
                results.append(result)
                
                # 通知步骤完成
                for callback in self._callbacks['on_step_complete']:
                    try:
                        callback(task, step, result)
                    except Exception as e:
                        logger.error(f"步骤完成通知失败: {e}")
                
                # 延迟
                delay = self._calculate_delay(task, step)
                if delay > 0:
                    await asyncio.sleep(delay)
            
            task.status = ReplayStatus.COMPLETED
            task.completed_at = datetime.utcnow()
            task.results = {
                'total_steps': len(task.steps),
                'success_count': sum(1 for r in results if r.status == 'success'),
                'failed_count': sum(1 for r in results if r.status == 'failed'),
                'total_duration': sum(r.duration for r in results),
            }
            
            # 通知任务完成
            for callback in self._callbacks['on_task_complete']:
                try:
                    callback(task, results)
                except Exception as e:
                    logger.error(f"任务完成通知失败: {e}")
            
        except Exception as e:
            task.status = ReplayStatus.FAILED
            task.completed_at = datetime.utcnow()
            logger.error(f"任务执行失败: {e}")
        
        self._results[task_id] = results
        return results
    
    def get_task(self, task_id: str) -> Optional[ReplayTask]:
        """获取任务"""
        return self._tasks.get(task_id)
    
    def get_results(self, task_id: str) -> List[ReplayResult]:
        """获取结果"""
        return self._results.get(task_id, [])
    
    def get_templates(self) -> List[ReplayTask]:
        """获取模板"""
        return [t for t in self._tasks.values() if t.is_template]
    
    def on_task_start(self, callback: Callable):
        """注册任务开始回调"""
        self._callbacks['on_task_start'].append(callback)
    
    def on_task_complete(self, callback: Callable):
        """注册任务完成回调"""
        self._callbacks['on_task_complete'].append(callback)
    
    def on_step_complete(self, callback: Callable):
        """注册步骤完成回调"""
        self._callbacks['on_step_complete'].append(callback)
    
    def _dict_to_step(self, data: Dict, order: int) -> ReplayStep:
        """字典转步骤"""
        return ReplayStep(
            id=data.get('id', str(uuid.uuid4())[:12]),
            request_data=data.get('request_data', {}),
            original_response=data.get('original_response'),
            variables_to_extract=data.get('variables_to_extract', []),
            variables_to_inject=data.get('variables_to_inject', {}),
            delay_after=data.get('delay_after', 0.0),
            order=data.get('order', order),
        )
    
    def _inject_variables(self, request_data: Dict, variables: Dict) -> Dict:
        """注入变量到请求"""
        if not variables:
            return request_data
        
        data = request_data.copy()
        
        # 注入到URL
        url = data.get('url', '')
        for key, value in variables.items():
            url = url.replace(f'{{{{{key}}}}}', value)
        data['url'] = url
        
        # 注入到Headers
        headers = data.get('headers', {}).copy()
        for key, value in variables.items():
            for header_key in list(headers.keys()):
                if f'{{{{{key}}}}}' in headers[header_key]:
                    headers[header_key] = headers[header_key].replace(
                        f'{{{{{key}}}}}', value
                    )
        data['headers'] = headers
        
        # 注入到Body
        body = data.get('body', '')
        if body:
            for key, value in variables.items():
                body = body.replace(f'{{{{{key}}}}}', value)
            data['body'] = body
        
        return data
    
    async def _send_request(self, request_data: Dict) -> Dict[str, Any]:
        """发送请求"""
        url = request_data.get('url', '')
        method = request_data.get('method', 'GET').upper()
        headers = request_data.get('headers', {})
        body = request_data.get('body')
        
        loop = asyncio.get_event_loop()
        
        def _send():
            if method == 'GET':
                resp = requests.get(url, headers=headers, timeout=30)
            elif method == 'POST':
                resp = requests.post(url, headers=headers, data=body, timeout=30)
            elif method == 'PUT':
                resp = requests.put(url, headers=headers, data=body, timeout=30)
            elif method == 'DELETE':
                resp = requests.delete(url, headers=headers, timeout=30)
            else:
                resp = requests.request(method, url, headers=headers, data=body, timeout=30)
            
            return {
                'status_code': resp.status_code,
                'headers': dict(resp.headers),
                'body': resp.text,
                'elapsed': resp.elapsed.total_seconds(),
            }
        
        return await loop.run_in_executor(None, _send)
    
    def _calculate_delay(self, task: ReplayTask, step: ReplayStep) -> float:
        """计算延迟"""
        if task.speed == ReplaySpeed.ORIGINAL:
            return step.delay_after
        elif task.speed == ReplaySpeed.FAST:
            return step.delay_after * 0.1
        elif task.speed == ReplaySpeed.SLOW:
            return step.delay_after * 2
        elif task.speed == ReplaySpeed.CUSTOM:
            return task.custom_delay
        return 0
