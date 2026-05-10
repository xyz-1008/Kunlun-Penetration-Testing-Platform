"""
插件运行沙箱与资源管控模块
"""

import os
import sys
import json
import signal
import logging
import threading
import multiprocessing
from multiprocessing import Process, Queue
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from datetime import datetime
import time
import psutil

try:
    import resource
    HAS_RESOURCE = True
except ImportError:
    HAS_RESOURCE = False

logger = logging.getLogger(__name__)


@dataclass
class ResourceQuota:
    """资源配额"""
    max_memory_mb: int = 256
    max_cpu_time: int = 30
    max_wall_time: int = 60
    max_file_handles: int = 100
    max_network_connections: int = 10
    allowed_networks: List[str] = field(default_factory=list)
    block_network: bool = False


@dataclass
class SandboxExecutionResult:
    """沙箱执行结果"""
    success: bool
    output: Any = None
    error: str = ""
    timeout: bool = False
    memory_used_mb: float = 0.0
    cpu_time_used: float = 0.0
    wall_time_used: float = 0.0
    exit_code: int = 0
    killed: bool = False


def _run_in_sandbox(func: Callable, args: tuple, kwargs: dict, result_queue: Queue, quota: ResourceQuota):
    """在沙箱中运行函数"""
    try:
        start_time = time.time()
        
        result = func(*args, **kwargs)
        
        end_time = time.time()
        wall_time = end_time - start_time
        
        if HAS_RESOURCE:
            mem_usage = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024
        else:
            try:
                process = psutil.Process(os.getpid())
                mem_usage = process.memory_info().rss / (1024 * 1024)
            except:
                mem_usage = 0.0
        
        result_queue.put(SandboxExecutionResult(
            success=True,
            output=result,
            memory_used_mb=mem_usage,
            cpu_time_used=wall_time,
            wall_time_used=wall_time
        ))
    except Exception as e:
        result_queue.put(SandboxExecutionResult(
            success=False,
            error=str(e),
            exit_code=1
        ))


class PluginSandbox:
    """插件沙箱"""
    
    def __init__(self, quota: ResourceQuota = None):
        self.quota = quota or ResourceQuota()
        self._active_processes: Dict[str, Process] = {}
        self._lock = threading.RLock()
    
    def execute(self, plugin_id: str, func: Callable, args: tuple = (), kwargs: dict = None) -> SandboxExecutionResult:
        """在沙箱中执行"""
        if kwargs is None:
            kwargs = {}
        
        result_queue = Queue()
        
        process = Process(
            target=_run_in_sandbox,
            args=(func, args, kwargs, result_queue, self.quota),
            name=f"sandbox_{plugin_id}"
        )
        
        with self._lock:
            self._active_processes[plugin_id] = process
        
        process.start()
        
        try:
            process.join(timeout=self.quota.max_wall_time)
            
            if process.is_alive():
                process.terminate()
                process.join(timeout=5)
                if process.is_alive():
                    process.kill()
                
                return SandboxExecutionResult(
                    success=False,
                    error=f"执行超时 (>{self.quota.max_wall_time}s)",
                    timeout=True,
                    killed=True
                )
            
            if result_queue.empty():
                return SandboxExecutionResult(
                    success=False,
                    error="未获取到执行结果",
                    exit_code=-1
                )
            
            return result_queue.get_nowait()
            
        except Exception as e:
            if process.is_alive():
                process.terminate()
            
            return SandboxExecutionResult(
                success=False,
                error=f"执行异常: {str(e)}",
                exit_code=-1
            )
        finally:
            with self._lock:
                self._active_processes.pop(plugin_id, None)
    
    def terminate_all(self):
        """终止所有进程"""
        with self._lock:
            for plugin_id, process in self._active_processes.items():
                if process.is_alive():
                    process.terminate()
            
            self._active_processes.clear()
    
    def get_active_count(self) -> int:
        """获取活跃进程数"""
        with self._lock:
            return len([p for p in self._active_processes.values() if p.is_alive()])


class ResourceMonitor:
    """资源监控器"""
    
    def __init__(self):
        self._metrics: Dict[str, List[Dict[str, Any]]] = {}
        self._lock = threading.RLock()
    
    def record_metric(self, plugin_id: str, metric: Dict[str, Any]):
        """记录指标"""
        with self._lock:
            if plugin_id not in self._metrics:
                self._metrics[plugin_id] = []
            
            metric["timestamp"] = datetime.now()
            self._metrics[plugin_id].append(metric)
    
    def get_metrics(self, plugin_id: str, limit: int = 100) -> List[Dict[str, Any]]:
        """获取指标"""
        with self._lock:
            return self._metrics.get(plugin_id, [])[-limit:]
    
    def get_all_metrics(self) -> Dict[str, List[Dict[str, Any]]]:
        """获取所有指标"""
        with self._lock:
            return {k: v.copy() for k, v in self._metrics.items()}
    
    def clear_metrics(self, plugin_id: str = None):
        """清除指标"""
        with self._lock:
            if plugin_id:
                self._metrics.pop(plugin_id, None)
            else:
                self._metrics.clear()
    
    def detect_memory_leak(self, plugin_id: str, threshold_mb: int = 50) -> bool:
        """检测内存泄漏"""
        with self._lock:
            metrics = self._metrics.get(plugin_id, [])
            
            if len(metrics) < 2:
                return False
            
            recent = metrics[-10:]
            memory_values = [m.get("memory_used_mb", 0) for m in recent]
            
            if not memory_values:
                return False
            
            avg_increase = (memory_values[-1] - memory_values[0]) / len(memory_values)
            return avg_increase > threshold_mb / 10
    
    def detect_slow_plugin(self, plugin_id: str, threshold_seconds: float = 10.0) -> bool:
        """检测慢插件"""
        with self._lock:
            metrics = self._metrics.get(plugin_id, [])
            
            if not metrics:
                return False
            
            recent = metrics[-5:]
            exec_times = [m.get("execution_time", 0) for m in recent]
            
            if not exec_times:
                return False
            
            avg_time = sum(exec_times) / len(exec_times)
            return avg_time > threshold_seconds


class ResourceManager:
    """资源管理器"""
    
    def __init__(self):
        self.sandbox = PluginSandbox()
        self.monitor = ResourceMonitor()
        self._quotas: Dict[str, ResourceQuota] = {}
    
    def set_quota(self, plugin_id: str, quota: ResourceQuota):
        """设置配额"""
        self._quotas[plugin_id] = quota
    
    def get_quota(self, plugin_id: str) -> ResourceQuota:
        """获取配额"""
        return self._quotas.get(plugin_id, ResourceQuota())
    
    def execute_with_monitoring(self, plugin_id: str, func: Callable, args: tuple = (), kwargs: dict = None) -> SandboxExecutionResult:
        """执行并监控"""
        quota = self.get_quota(plugin_id)
        sandbox = PluginSandbox(quota)
        
        start_time = time.time()
        result = sandbox.execute(plugin_id, func, args, kwargs or {})
        end_time = time.time()
        
        self.monitor.record_metric(plugin_id, {
            "execution_time": end_time - start_time,
            "memory_used_mb": result.memory_used_mb,
            "cpu_time_used": result.cpu_time_used,
            "success": result.success,
            "error": result.error
        })
        
        if self.monitor.detect_memory_leak(plugin_id):
            logger.warning(f"检测到插件 {plugin_id} 可能存在内存泄漏")
        
        if self.monitor.detect_slow_plugin(plugin_id):
            logger.warning(f"检测到插件 {plugin_id} 执行缓慢")
        
        return result
