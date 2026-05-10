"""
插件开发调试工具链模块
包含本地模拟环境、断点调试、日志注入等功能
"""

import os
import sys
import json
import logging
import inspect
import traceback
from pathlib import Path
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

logger = logging.getLogger(__name__)


class DebugLevel(Enum):
    """调试级别"""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    DEBUG = "debug"


@dataclass
class DebugEvent:
    """调试点事件"""
    timestamp: datetime
    level: DebugLevel
    message: str
    plugin_id: str = ""
    function_name: str = ""
    line_number: int = 0
    variables: Dict[str, Any] = field(default_factory=dict)
    stack_trace: str = ""


@dataclass
class PluginTestResult:
    """插件测试结果"""
    plugin_id: str
    success: bool
    tests_passed: int = 0
    tests_failed: int = 0
    tests_skipped: int = 0
    execution_time: float = 0.0
    errors: List[str] = field(default_factory=list)
    output: str = ""


class DebugLogger:
    """调试日志记录器"""
    
    def __init__(self):
        self._events: List[DebugEvent] = []
        self._callbacks: List[Callable] = []
    
    def log(self, level: DebugLevel, message: str, plugin_id: str = "", 
            function_name: str = "", line_number: int = 0, 
            variables: Dict[str, Any] = None, stack_trace: str = ""):
        """记录调试事件"""
        event = DebugEvent(
            timestamp=datetime.now(),
            level=level,
            message=message,
            plugin_id=plugin_id,
            function_name=function_name,
            line_number=line_number,
            variables=variables or {},
            stack_trace=stack_trace
        )
        
        self._events.append(event)
        
        for callback in self._callbacks:
            try:
                callback(event)
            except Exception as e:
                logger.error(f"调试回调执行失败: {e}")
    
    def get_events(self, limit: int = 100, plugin_id: str = None) -> List[DebugEvent]:
        """获取事件"""
        events = self._events
        
        if plugin_id:
            events = [e for e in events if e.plugin_id == plugin_id]
        
        return events[-limit:]
    
    def clear(self):
        """清除事件"""
        self._events.clear()
    
    def add_callback(self, callback: Callable):
        """添加回调"""
        self._callbacks.append(callback)
    
    def export_logs(self, format: str = "json") -> str:
        """导出日志"""
        if format == "json":
            return json.dumps([
                {
                    "timestamp": e.timestamp.isoformat(),
                    "level": e.level.value,
                    "message": e.message,
                    "plugin_id": e.plugin_id,
                    "function_name": e.function_name,
                    "line_number": e.line_number,
                    "variables": e.variables,
                    "stack_trace": e.stack_trace
                }
                for e in self._events
            ], indent=2, ensure_ascii=False)
        
        elif format == "text":
            lines = []
            for e in self._events:
                lines.append(f"[{e.timestamp}] [{e.level.value.upper()}] {e.plugin_id}: {e.message}")
            return "\n".join(lines)
        
        return ""


class PluginSimulator:
    """插件本地模拟器"""
    
    def __init__(self):
        self.debug_logger = DebugLogger()
        self._mock_data: Dict[str, Any] = {}
    
    def set_mock_data(self, key: str, data: Any):
        """设置模拟数据"""
        self._mock_data[key] = data
    
    def get_mock_data(self, key: str, default: Any = None) -> Any:
        """获取模拟数据"""
        return self._mock_data.get(key, default)
    
    def simulate_plugin(self, plugin_code: str, plugin_id: str = "test_plugin") -> PluginTestResult:
        """模拟执行插件"""
        import time
        start_time = time.time()
        
        result = PluginTestResult(plugin_id=plugin_id, success=False)
        
        try:
            local_vars = {}
            exec(plugin_code, {}, local_vars)
            
            if "verify" in local_vars:
                self.debug_logger.log(
                    DebugLevel.INFO, "开始模拟执行", plugin_id=plugin_id
                )
                
                mock_target = self.get_mock_data("target", "http://test.local")
                verify_result = local_vars["verify"](mock_target)
                
                result.success = True
                result.tests_passed = 1
                result.output = str(verify_result)
                
                self.debug_logger.log(
                    DebugLevel.INFO, f"模拟执行完成: {verify_result}", 
                    plugin_id=plugin_id
                )
            
            elif "execute" in local_vars:
                self.debug_logger.log(
                    DebugLevel.INFO, "开始模拟执行插件", plugin_id=plugin_id
                )
                
                execute_result = local_vars["execute"]()
                
                result.success = True
                result.tests_passed = 1
                result.output = str(execute_result)
            
            else:
                result.errors.append("未找到verify或execute函数")
        
        except Exception as e:
            result.errors.append(str(e))
            result.stack_trace = traceback.format_exc()
            
            self.debug_logger.log(
                DebugLevel.ERROR, f"模拟执行失败: {e}", 
                plugin_id=plugin_id,
                stack_trace=traceback.format_exc()
            )
        
        result.execution_time = time.time() - start_time
        return result
    
    def simulate_context(self, target: str = "http://test.local", 
                        assets: List[Dict] = None) -> Dict[str, Any]:
        """模拟插件上下文"""
        return {
            "target": target,
            "assets": assets or [],
            "config": {},
            "variables": {},
            "mock": True
        }


class PluginDebugger:
    """插件调试器"""
    
    def __init__(self):
        self.simulator = PluginSimulator()
        self._breakpoints: Dict[str, List[int]] = {}
        self._step_mode = False
        self._paused = False
    
    def add_breakpoint(self, plugin_id: str, line_number: int):
        """添加断点"""
        if plugin_id not in self._breakpoints:
            self._breakpoints[plugin_id] = []
        
        if line_number not in self._breakpoints[plugin_id]:
            self._breakpoints[plugin_id].append(line_number)
    
    def remove_breakpoint(self, plugin_id: str, line_number: int):
        """移除断点"""
        if plugin_id in self._breakpoints:
            if line_number in self._breakpoints[plugin_id]:
                self._breakpoints[plugin_id].remove(line_number)
    
    def clear_breakpoints(self, plugin_id: str = None):
        """清除断点"""
        if plugin_id:
            self._breakpoints.pop(plugin_id, None)
        else:
            self._breakpoints.clear()
    
    def get_breakpoints(self, plugin_id: str) -> List[int]:
        """获取断点"""
        return self._breakpoints.get(plugin_id, [])
    
    def set_step_mode(self, enabled: bool):
        """设置单步模式"""
        self._step_mode = enabled
    
    def pause(self):
        """暂停执行"""
        self._paused = True
    
    def resume(self):
        """恢复执行"""
        self._paused = False
    
    def is_paused(self) -> bool:
        """是否暂停"""
        return self._paused
    
    def debug_plugin(self, plugin_code: str, plugin_id: str = "test_plugin") -> PluginTestResult:
        """调试插件"""
        self.simulator.debug_logger.log(
            DebugLevel.INFO, f"开始调试插件: {plugin_id}", plugin_id=plugin_id
        )
        
        result = self.simulator.simulate_plugin(plugin_code, plugin_id)
        
        self.simulator.debug_logger.log(
            DebugLevel.INFO, f"调试完成: {plugin_id}", plugin_id=plugin_id
        )
        
        return result
    
    def get_debug_logs(self, plugin_id: str = None, limit: int = 100) -> List[DebugEvent]:
        """获取调试日志"""
        return self.simulator.debug_logger.get_events(limit, plugin_id)
    
    def export_debug_session(self, plugin_id: str = None) -> str:
        """导出调试会话"""
        return self.simulator.debug_logger.export_logs("json")


class PluginTestRunner:
    """插件测试运行器"""
    
    def __init__(self):
        self.debugger = PluginDebugger()
    
    def run_tests(self, plugin_path: str) -> PluginTestResult:
        """运行插件测试"""
        path = Path(plugin_path)
        
        if not path.exists():
            return PluginTestResult(
                plugin_id=path.stem,
                success=False,
                errors=[f"插件文件不存在: {plugin_path}"]
            )
        
        with open(path, "r", encoding="utf-8") as f:
            plugin_code = f.read()
        
        return self.debugger.debug_plugin(plugin_code, path.stem)
    
    def run_all_tests(self, plugin_dir: str) -> List[PluginTestResult]:
        """运行目录下所有插件测试"""
        results = []
        dir_path = Path(plugin_dir)
        
        if not dir_path.exists():
            return results
        
        for py_file in dir_path.glob("*.py"):
            if py_file.name.startswith("_"):
                continue
            
            result = self.run_tests(str(py_file))
            results.append(result)
        
        return results
    
    def generate_test_report(self, results: List[PluginTestResult]) -> str:
        """生成测试报告"""
        total = len(results)
        passed = sum(1 for r in results if r.success)
        failed = total - passed
        
        report = f"# 插件测试报告\n\n"
        report += f"## 概要\n\n"
        report += f"- 总计: {total}\n"
        report += f"- 通过: {passed}\n"
        report += f"- 失败: {failed}\n\n"
        
        report += "## 详情\n\n"
        
        for result in results:
            status = "通过" if result.success else "失败"
            report += f"### {result.plugin_id} - {status}\n\n"
            report += f"- 执行时间: {result.execution_time:.3f}s\n"
            
            if result.errors:
                report += f"- 错误:\n"
                for error in result.errors:
                    report += f"  - {error}\n"
            
            report += "\n"
        
        return report


class PluginDocGenerator:
    """插件文档生成器"""
    
    def __init__(self):
        pass
    
    def generate_api_doc(self, plugin_path: str) -> str:
        """生成API文档"""
        path = Path(plugin_path)
        
        if not path.exists():
            return "插件文件不存在"
        
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
        
        doc = f"# {path.stem} API文档\n\n"
        doc += f"## 文件信息\n\n"
        doc += f"- 文件: {path.name}\n"
        doc += f"- 路径: {path.absolute()}\n"
        doc += f"- 大小: {path.stat().st_size} bytes\n\n"
        
        doc += "## 代码结构\n\n"
        
        lines = content.split("\n")
        functions = []
        classes = []
        
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("def "):
                func_name = stripped.split("(")[0].replace("def ", "")
                functions.append((func_name, i))
            elif stripped.startswith("class "):
                class_name = stripped.split("(")[0].replace("class ", "")
                classes.append((class_name, i))
        
        if classes:
            doc += "### 类\n\n"
            for name, line in classes:
                doc += f"- `{name}` (行 {line})\n"
            doc += "\n"
        
        if functions:
            doc += "### 函数\n\n"
            for name, line in functions:
                doc += f"- `{name}` (行 {line})\n"
            doc += "\n"
        
        doc += "## 代码预览\n\n"
        doc += "```python\n"
        doc += content[:2000]
        if len(content) > 2000:
            doc += "\n... (截断)"
        doc += "\n```\n"
        
        return doc
