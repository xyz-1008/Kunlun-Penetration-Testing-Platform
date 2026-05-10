"""
插件管理器与调度器
"""

import os
import sys
import json
import logging
import threading
from pathlib import Path
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from datetime import datetime
import concurrent.futures

from .plugin_engine import (
    BasePlugin, PluginLoader, PluginManifest, PluginType, 
    PluginContext, PluginResult, PluginStatus, Permission
)
from .event_bus import EventBus, Event
from .base import ModuleBase

logger = logging.getLogger(__name__)


@dataclass
class PluginRegistryEntry:
    """插件注册条目"""
    plugin_id: str
    plugin: BasePlugin
    manifest: PluginManifest
    status: PluginStatus
    load_time: datetime
    execution_count: int = 0
    last_execution: Optional[datetime] = None
    total_execution_time: float = 0.0
    error_count: int = 0


class PluginRegistry:
    """插件注册中心"""
    
    def __init__(self):
        self._registry: Dict[str, PluginRegistryEntry] = {}
        self._lock = threading.RLock()
    
    def register(self, plugin_id: str, plugin: BasePlugin):
        """注册插件"""
        with self._lock:
            entry = PluginRegistryEntry(
                plugin_id=plugin_id,
                plugin=plugin,
                manifest=plugin.manifest,
                status=plugin.status,
                load_time=datetime.now()
            )
            self._registry[plugin_id] = entry
            logger.info(f"注册插件: {plugin_id}")
    
    def unregister(self, plugin_id: str):
        """注销插件"""
        with self._lock:
            if plugin_id in self._registry:
                del self._registry[plugin_id]
                logger.info(f"注销插件: {plugin_id}")
    
    def get(self, plugin_id: str) -> Optional[PluginRegistryEntry]:
        """获取插件"""
        with self._lock:
            return self._registry.get(plugin_id)
    
    def get_all(self) -> Dict[str, PluginRegistryEntry]:
        """获取所有插件"""
        with self._lock:
            return self._registry.copy()
    
    def get_by_type(self, plugin_type: PluginType) -> List[PluginRegistryEntry]:
        """按类型获取"""
        with self._lock:
            return [
                entry for entry in self._registry.values()
                if entry.manifest and entry.manifest.plugin_type == plugin_type
            ]
    
    def get_by_tag(self, tag: str) -> List[PluginRegistryEntry]:
        """按标签获取"""
        with self._lock:
            return [
                entry for entry in self._registry.values()
                if entry.manifest and tag in entry.manifest.tags
            ]
    
    def update_status(self, plugin_id: str, status: PluginStatus):
        """更新状态"""
        with self._lock:
            if plugin_id in self._registry:
                self._registry[plugin_id].status = status
    
    def record_execution(self, plugin_id: str, execution_time: float, success: bool):
        """记录执行"""
        with self._lock:
            if plugin_id in self._registry:
                entry = self._registry[plugin_id]
                entry.execution_count += 1
                entry.last_execution = datetime.now()
                entry.total_execution_time += execution_time
                if not success:
                    entry.error_count += 1
    
    def get_statistics(self) -> Dict[str, Any]:
        """获取统计"""
        with self._lock:
            total = len(self._registry)
            enabled = sum(1 for e in self._registry.values() if e.status == PluginStatus.ENABLED)
            disabled = sum(1 for e in self._registry.values() if e.status == PluginStatus.DISABLED)
            errors = sum(1 for e in self._registry.values() if e.status == PluginStatus.ERROR)
            
            return {
                "total_plugins": total,
                "enabled": enabled,
                "disabled": disabled,
                "errors": errors,
                "total_executions": sum(e.execution_count for e in self._registry.values()),
                "total_errors": sum(e.error_count for e in self._registry.values())
            }


class PluginScheduler:
    """插件调度器"""
    
    def __init__(self, registry: PluginRegistry, event_bus: EventBus):
        self.registry = registry
        self.event_bus = event_bus
        self._max_concurrent = 5
        self._lock = threading.RLock()
    
    def set_max_concurrent(self, max_concurrent: int):
        """设置最大并发数"""
        self._max_concurrent = max_concurrent
    
    def execute_plugin(self, plugin_id: str, context: PluginContext) -> PluginResult:
        """执行单个插件"""
        entry = self.registry.get(plugin_id)
        if not entry:
            return PluginResult(
                plugin_id=plugin_id,
                success=False,
                error=f"插件不存在: {plugin_id}"
            )
        
        if entry.status == PluginStatus.DISABLED:
            return PluginResult(
                plugin_id=plugin_id,
                success=False,
                error=f"插件已禁用: {plugin_id}"
            )
        
        try:
            self.event_bus.publish("plugin.pre_execute", {"plugin_id": plugin_id}, source="scheduler")
            
            import time
            start_time = time.time()
            
            result = entry.plugin.execute(context)
            
            execution_time = time.time() - start_time
            
            self.registry.record_execution(plugin_id, execution_time, result.success)
            
            self.event_bus.publish(
                "plugin.post_execute",
                {"plugin_id": plugin_id, "result": result},
                source="scheduler"
            )
            
            return result
            
        except Exception as e:
            logger.error(f"插件执行失败 [{plugin_id}]: {e}")
            self.registry.record_execution(plugin_id, 0, False)
            
            return PluginResult(
                plugin_id=plugin_id,
                success=False,
                error=str(e)
            )
    
    def execute_plugins_sequential(self, plugin_ids: List[str], context: PluginContext) -> List[PluginResult]:
        """串行执行插件"""
        results = []
        
        for plugin_id in plugin_ids:
            result = self.execute_plugin(plugin_id, context)
            results.append(result)
            
            if not result.success:
                break
        
        return results
    
    def execute_plugins_parallel(self, plugin_ids: List[str], context: PluginContext) -> List[PluginResult]:
        """并行执行插件"""
        results = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self._max_concurrent) as executor:
            future_to_id = {
                executor.submit(self.execute_plugin, pid, context): pid
                for pid in plugin_ids
            }
            
            for future in concurrent.futures.as_completed(future_to_id):
                plugin_id = future_to_id[future]
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    logger.error(f"插件执行异常 [{plugin_id}]: {e}")
                    results.append(PluginResult(
                        plugin_id=plugin_id,
                        success=False,
                        error=str(e)
                    ))
        
        return results
    
    def execute_pipeline(self, stages: List[List[str]], context: PluginContext) -> List[PluginResult]:
        """执行流水线"""
        all_results = []
        
        for stage in stages:
            stage_results = self.execute_plugins_parallel(stage, context)
            all_results.extend(stage_results)
            
            failed = any(not r.success for r in stage_results)
            if failed:
                break
        
        return all_results


class PluginManager:
    """插件管理器"""
    
    def __init__(self, plugin_dirs: List[str] = None):
        self.loader = PluginLoader(plugin_dirs)
        self.registry = PluginRegistry()
        self.event_bus = EventBus()
        self.scheduler = PluginScheduler(self.registry, self.event_bus)
        self._lock = threading.RLock()
    
    def initialize(self):
        """初始化"""
        self.load_all_plugins()
        logger.info("插件管理器初始化完成")
    
    def load_all_plugins(self) -> int:
        """加载所有插件"""
        plugins = self.loader.load_all_plugins()
        
        for plugin_id, plugin in plugins.items():
            self.registry.register(plugin_id, plugin)
        
        return len(plugins)
    
    def load_plugin(self, plugin_path: str) -> bool:
        """加载单个插件"""
        plugin = self.loader.load_plugin(plugin_path)
        if plugin:
            plugin_id = plugin.manifest.name if plugin.manifest else Path(plugin_path).stem
            self.registry.register(plugin_id, plugin)
            return True
        return False
    
    def unload_plugin(self, plugin_id: str) -> bool:
        """卸载插件"""
        entry = self.registry.get(plugin_id)
        if entry:
            entry.plugin.on_unload()
            self.loader.unload_plugin(plugin_id)
            self.registry.unregister(plugin_id)
            return True
        return False
    
    def reload_plugin(self, plugin_id: str) -> bool:
        """重载插件"""
        if self.unload_plugin(plugin_id):
            entry = self.registry.get(plugin_id)
            if entry:
                return self.load_plugin(entry.manifest.name if entry.manifest else plugin_id)
        return False
    
    def enable_plugin(self, plugin_id: str) -> bool:
        """启用插件"""
        entry = self.registry.get(plugin_id)
        if entry:
            entry.plugin.on_enable()
            self.registry.update_status(plugin_id, PluginStatus.ENABLED)
            return True
        return False
    
    def disable_plugin(self, plugin_id: str) -> bool:
        """禁用插件"""
        entry = self.registry.get(plugin_id)
        if entry:
            entry.plugin.on_disable()
            self.registry.update_status(plugin_id, PluginStatus.DISABLED)
            return True
        return False
    
    def execute_plugin(self, plugin_id: str, context: PluginContext) -> PluginResult:
        """执行插件"""
        return self.scheduler.execute_plugin(plugin_id, context)
    
    def get_plugin(self, plugin_id: str) -> Optional[BasePlugin]:
        """获取插件"""
        entry = self.registry.get(plugin_id)
        return entry.plugin if entry else None
    
    def get_all_plugins(self) -> Dict[str, PluginRegistryEntry]:
        """获取所有插件"""
        return self.registry.get_all()
    
    def get_plugins_by_type(self, plugin_type: PluginType) -> List[PluginRegistryEntry]:
        """按类型获取插件"""
        return self.registry.get_by_type(plugin_type)
    
    def get_statistics(self) -> Dict[str, Any]:
        """获取统计"""
        return self.registry.get_statistics()


class PluginManagerModule(ModuleBase):
    """插件管理器模块（UI集成）"""
    
    def __init__(self, plugin_dirs: List[str] = None):
        super().__init__("插件管理", "企业级插件管理与市场")
        self.plugin_manager = PluginManager(plugin_dirs)
        self.plugin_manager.initialize()
    
    def _create_ui(self) -> 'QWidget':
        """创建UI"""
        from PySide6.QtWidgets import QWidget, QVBoxLayout, QLabel
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.addWidget(QLabel("插件管理模块"))
        return widget
