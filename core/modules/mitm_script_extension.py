"""
MITM代理脚本扩展模块
提供Python Hook接口、热加载、脚本模板等功能
"""

import os
import sys
import time
import logging
import importlib
import hashlib
from typing import Dict, Any, Optional, List, Callable
from pathlib import Path
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class ScriptInfo:
    """脚本信息"""
    name: str
    path: str
    enabled: bool = True
    description: str = ""
    last_modified: float = 0.0
    last_hash: str = ""


class ScriptHook:
    """脚本Hook接口"""
    
    def on_request(self, request: Any) -> Any:
        """请求Hook"""
        return request
    
    def on_response(self, request: Any, response: Any) -> Any:
        """响应Hook"""
        return response
    
    def on_error(self, error: str) -> None:
        """错误Hook"""
        pass


class ScriptManager:
    """脚本管理器"""
    
    def __init__(self, scripts_dir: str = "data/mitm_scripts"):
        self.scripts_dir = Path(scripts_dir)
        self.scripts_dir.mkdir(parents=True, exist_ok=True)
        
        self._scripts: Dict[str, ScriptInfo] = {}
        self._hooks: List[ScriptHook] = []
        self._file_hashes: Dict[str, str] = {}
        self._watch_thread = None
        self._watching = False
        
        self._create_default_templates()
    
    def _create_default_templates(self):
        """创建默认脚本模板"""
        templates = {
            "add_header.py": '''"""
模板：自动添加Header
在每个请求中添加自定义Header
"""

class ScriptHook:
    def on_request(self, request):
        # 添加自定义Header
        request.headers['X-MITM-Proxy'] = 'AutoPenTest'
        request.headers['X-Forwarded-By'] = 'MITM-Module'
        return request
    
    def on_response(self, request, response):
        # 可以在这里修改响应
        return response
''',
            "replace_token.py": '''"""
模板：替换Token
自动替换请求中的认证Token
"""

class ScriptHook:
    def __init__(self):
        self.old_token = "old_token_here"
        self.new_token = "new_token_here"
    
    def on_request(self, request):
        # 替换Authorization Header
        if 'Authorization' in request.headers:
            auth = request.headers['Authorization']
            if self.old_token in auth:
                request.headers['Authorization'] = auth.replace(self.old_token, self.new_token)
        
        # 替换Body中的Token
        if request.body:
            body_str = request.body.decode('utf-8', errors='replace')
            if self.old_token in body_str:
                body_str = body_str.replace(self.old_token, self.new_token)
                request.body = body_str.encode('utf-8')
        
        return request
    
    def on_response(self, request, response):
        return response
''',
            "log_requests.py": '''"""
模板：日志上报
记录所有请求到文件
"""

import logging
from datetime import datetime

logger = logging.getLogger('mitm_script')

class ScriptHook:
    def __init__(self):
        self.log_file = "data/mitm_scripts/requests.log"
    
    def on_request(self, request):
        # 记录请求日志
        timestamp = datetime.utcnow().isoformat()
        log_line = f"[{timestamp}] {request.method} {request.url}\\n"
        
        try:
            with open(self.log_file, 'a', encoding='utf-8') as f:
                f.write(log_line)
        except Exception as e:
            logger.error(f"写入日志失败: {e}")
        
        return request
    
    def on_response(self, request, response):
        # 记录响应日志
        timestamp = datetime.utcnow().isoformat()
        log_line = f"[{timestamp}] Response: {response.status_code} {request.url}\\n"
        
        try:
            with open(self.log_file, 'a', encoding='utf-8') as f:
                f.write(log_line)
        except Exception as e:
            logger.error(f"写入日志失败: {e}")
        
        return response
''',
            "block_ads.py": '''"""
模板：广告拦截
拦截常见广告和跟踪请求
"""

import re

BLOCKED_DOMAINS = [
    'google-analytics.com',
    'doubleclick.net',
    'adservice.google.com',
    'facebook.com/tr',
    'analytics.twitter.com',
]

BLOCKED_PATHS = [
    '/ads/',
    '/analytics/',
    '/tracking/',
    '/pixel.',
]

class ScriptHook:
    def on_request(self, request):
        # 检查域名
        for domain in BLOCKED_DOMAINS:
            if domain in request.host:
                # 返回空响应拦截请求
                return self._create_block_response(request)
        
        # 检查路径
        for path in BLOCKED_PATHS:
            if path in request.path.lower():
                return self._create_block_response(request)
        
        return request
    
    def _create_block_response(self, request):
        """创建拦截响应"""
        class BlockedResponse:
            def __init__(self):
                self.id = request.id + '_blocked'
                self.request_id = request.id
                self.timestamp = request.timestamp
                self.status_code = 204
                self.reason = 'No Content'
                self.headers = {}
                self.body = b''
                self.content_type = ''
                self.content_length = 0
                self.response_time = 0.0
        
        return BlockedResponse()
    
    def on_response(self, request, response):
        return response
''',
        }
        
        for filename, content in templates.items():
            filepath = self.scripts_dir / filename
            if not filepath.exists():
                with open(filepath, 'w', encoding='utf-8') as f:
                    f.write(content)
                logger.info(f"创建脚本模板: {filename}")
    
    def load_script(self, script_path: str) -> Optional[ScriptHook]:
        """加载脚本"""
        try:
            path = Path(script_path)
            if not path.exists():
                logger.error(f"脚本文件不存在: {script_path}")
                return None
            
            # 计算文件hash
            file_hash = self._compute_file_hash(path)
            
            # 如果文件未修改且已加载，跳过
            if script_path in self._file_hashes and self._file_hashes[script_path] == file_hash:
                logger.debug(f"脚本未修改，跳过加载: {script_path}")
                return None
            
            # 动态导入脚本
            module_name = path.stem
            spec = importlib.util.spec_from_file_location(module_name, str(path))
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            
            # 获取ScriptHook类
            if hasattr(module, 'ScriptHook'):
                hook = module.ScriptHook()
                
                # 记录脚本信息
                script_info = ScriptInfo(
                    name=module_name,
                    path=str(path),
                    last_modified=path.stat().st_mtime,
                    last_hash=file_hash,
                )
                self._scripts[script_path] = script_info
                self._file_hashes[script_path] = file_hash
                
                logger.info(f"脚本加载成功: {script_path}")
                return hook
            else:
                logger.error(f"脚本中未找到ScriptHook类: {script_path}")
                return None
                
        except Exception as e:
            logger.error(f"加载脚本失败: {script_path}, 错误: {e}")
            return None
    
    def load_all_scripts(self) -> List[ScriptHook]:
        """加载所有脚本"""
        self._hooks.clear()
        
        for script_file in self.scripts_dir.glob("*.py"):
            if script_file.name.startswith('_'):
                continue
            
            hook = self.load_script(str(script_file))
            if hook:
                self._hooks.append(hook)
        
        logger.info(f"已加载 {len(self._hooks)} 个脚本")
        return self._hooks
    
    def reload_script(self, script_path: str) -> bool:
        """重新加载单个脚本"""
        hook = self.load_script(script_path)
        if hook:
            # 替换旧hook
            self._hooks = [h for h in self._hooks if not hasattr(h, '__module__') or 
                          h.__module__ != Path(script_path).stem]
            self._hooks.append(hook)
            return True
        return False
    
    def check_for_changes(self) -> List[str]:
        """检查脚本文件变更"""
        changed_scripts = []
        
        for script_path, script_info in self._scripts.items():
            path = Path(script_path)
            if not path.exists():
                continue
            
            # 检查修改时间
            current_mtime = path.stat().st_mtime
            if current_mtime > script_info.last_modified:
                # 检查hash是否真的变化
                current_hash = self._compute_file_hash(path)
                if current_hash != script_info.last_hash:
                    changed_scripts.append(script_path)
                    script_info.last_modified = current_mtime
                    script_info.last_hash = current_hash
        
        return changed_scripts
    
    def auto_reload(self):
        """自动重新加载变更的脚本"""
        changed = self.check_for_changes()
        for script_path in changed:
            logger.info(f"检测到脚本变更，重新加载: {script_path}")
            self.reload_script(script_path)
    
    def start_watching(self, interval: float = 2.0):
        """开始监控脚本变更"""
        import threading
        
        self._watching = True
        
        def watch_loop():
            while self._watching:
                self.auto_reload()
                time.sleep(interval)
        
        self._watch_thread = threading.Thread(target=watch_loop, daemon=True)
        self._watch_thread.start()
        logger.info("脚本监控已启动")
    
    def stop_watching(self):
        """停止监控"""
        self._watching = False
        if self._watch_thread:
            self._watch_thread.join(timeout=5)
        logger.info("脚本监控已停止")
    
    def execute_request_hooks(self, request: Any) -> Any:
        """执行请求Hook"""
        for hook in self._hooks:
            try:
                if hasattr(hook, 'on_request'):
                    request = hook.on_request(request)
            except Exception as e:
                logger.error(f"执行请求Hook失败: {e}")
        return request
    
    def execute_response_hooks(self, request: Any, response: Any) -> Any:
        """执行响应Hook"""
        for hook in self._hooks:
            try:
                if hasattr(hook, 'on_response'):
                    response = hook.on_response(request, response)
            except Exception as e:
                logger.error(f"执行响应Hook失败: {e}")
        return response
    
    def get_scripts_list(self) -> List[Dict[str, Any]]:
        """获取脚本列表"""
        result = []
        for path, info in self._scripts.items():
            result.append({
                'name': info.name,
                'path': info.path,
                'enabled': info.enabled,
                'description': info.description,
                'last_modified': info.last_modified,
            })
        return result
    
    def enable_script(self, script_path: str):
        """启用脚本"""
        if script_path in self._scripts:
            self._scripts[script_path].enabled = True
    
    def disable_script(self, script_path: str):
        """禁用脚本"""
        if script_path in self._scripts:
            self._scripts[script_path].enabled = False
    
    def _compute_file_hash(self, path: Path) -> str:
        """计算文件hash"""
        hasher = hashlib.md5()
        with open(path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                hasher.update(chunk)
        return hasher.hexdigest()
