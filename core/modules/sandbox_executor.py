"""
沙箱执行引擎与资源管控
"""

import os
import sys
import json
import signal
import logging
import multiprocessing
from multiprocessing import Process, Queue
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
import time
import psutil

try:
    import resource
    HAS_RESOURCE = True
except ImportError:
    HAS_RESOURCE = False

logger = logging.getLogger(__name__)


@dataclass
class SandboxConfig:
    """沙箱配置"""
    timeout: int = 30
    max_memory_mb: int = 256
    max_cpu_time: int = 20
    network_isolation: bool = False
    allowed_networks: List[str] = None
    block_system_calls: List[str] = None
    
    def __post_init__(self):
        if self.allowed_networks is None:
            self.allowed_networks = []
        if self.block_system_calls is None:
            self.block_system_calls = ["exec", "eval", "compile", "__import__"]


@dataclass
class SandboxResult:
    """沙箱执行结果"""
    success: bool
    output: str = ""
    error: str = ""
    timeout: bool = False
    memory_used_mb: float = 0.0
    cpu_time_used: float = 0.0
    exit_code: int = 0


def _run_poc_in_subprocess(poc_module, target: str, result_queue: Queue, config: SandboxConfig):
    """在子进程中执行PoC"""
    try:
        start_time = time.time()
        
        result = poc_module.verify(target)
        
        end_time = time.time()
        cpu_time = end_time - start_time
        
        if HAS_RESOURCE:
            mem_usage = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024
        else:
            try:
                process = psutil.Process(os.getpid())
                mem_usage = process.memory_info().rss / (1024 * 1024)
            except:
                mem_usage = 0.0
        
        if isinstance(result, tuple) and len(result) == 2:
            vulnerable, evidence = result
            result_queue.put(SandboxResult(
                success=True,
                output=str(evidence),
                timeout=False,
                memory_used_mb=mem_usage,
                cpu_time_used=cpu_time,
                exit_code=0
            ))
        else:
            result_queue.put(SandboxResult(
                success=True,
                output=str(result),
                timeout=False,
                memory_used_mb=mem_usage,
                cpu_time_used=cpu_time,
                exit_code=0
            ))
    except Exception as e:
        result_queue.put(SandboxResult(
            success=False,
            error=str(e),
            timeout=False,
            exit_code=1
        ))


class SandboxExecutor:
    """沙箱执行器"""
    
    def __init__(self, config: SandboxConfig = None):
        self.config = config or SandboxConfig()
        self._active_processes: Dict[str, Process] = {}
    
    def execute_poc(self, poc_id: str, poc_module, target: str) -> SandboxResult:
        """在沙箱中执行PoC"""
        result_queue = Queue()
        
        process = Process(
            target=_run_poc_in_subprocess,
            args=(poc_module, target, result_queue, self.config),
            name=f"poc_{poc_id}"
        )
        
        self._active_processes[poc_id] = process
        process.start()
        
        try:
            process.join(timeout=self.config.timeout)
            
            if process.is_alive():
                process.terminate()
                process.join(timeout=5)
                if process.is_alive():
                    process.kill()
                
                return SandboxResult(
                    success=False,
                    error=f"PoC执行超时 (>{self.config.timeout}s)",
                    timeout=True,
                    exit_code=-1
                )
            
            if result_queue.empty():
                return SandboxResult(
                    success=False,
                    error="未获取到执行结果",
                    exit_code=-1
                )
            
            return result_queue.get_nowait()
            
        except Exception as e:
            if process.is_alive():
                process.terminate()
            
            return SandboxResult(
                success=False,
                error=f"执行异常: {str(e)}",
                exit_code=-1
            )
        finally:
            self._active_processes.pop(poc_id, None)
    
    def execute_multiple_pocs(self, pocs: List[Tuple[str, Any, str]], max_concurrent: int = 5) -> Dict[str, SandboxResult]:
        """并发执行多个PoC"""
        results = {}
        semaphore = multiprocessing.Semaphore(max_concurrent)
        
        def _execute_with_semaphore(poc_id, poc_module, target):
            with semaphore:
                results[poc_id] = self.execute_poc(poc_id, poc_module, target)
        
        processes = []
        for poc_id, poc_module, target in pocs:
            p = Process(target=_execute_with_semaphore, args=(poc_id, poc_module, target))
            p.start()
            processes.append(p)
        
        for p in processes:
            p.join(timeout=self.config.timeout + 10)
            if p.is_alive():
                p.terminate()
        
        return results
    
    def terminate_all(self):
        """终止所有活跃进程"""
        for poc_id, process in self._active_processes.items():
            if process.is_alive():
                process.terminate()
        
        self._active_processes.clear()
    
    def get_active_count(self) -> int:
        """获取活跃进程数"""
        return len([p for p in self._active_processes.values() if p.is_alive()])
