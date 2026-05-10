"""
插件依赖解析与版本管理模块
"""

import os
import sys
import json
import logging
from pathlib import Path
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from packaging import version as pkg_version
from packaging.specifiers import SpecifierSet, InvalidSpecifier

logger = logging.getLogger(__name__)


@dataclass
class DependencyInfo:
    """依赖信息"""
    name: str
    version_range: str
    required: bool = True
    optional: bool = False


@dataclass
class DependencyResolution:
    """依赖解析结果"""
    success: bool
    resolved: Dict[str, str] = field(default_factory=dict)
    conflicts: List[str] = field(default_factory=list)
    missing: List[str] = field(default_factory=list)
    suggestions: List[str] = field(default_factory=list)


class DependencyResolver:
    """依赖解析器"""
    
    def __init__(self):
        self._dependency_graph: Dict[str, List[DependencyInfo]] = {}
        self._installed: Dict[str, str] = {}
    
    def add_dependency(self, plugin_id: str, dependencies: List[DependencyInfo]):
        """添加依赖"""
        self._dependency_graph[plugin_id] = dependencies
    
    def set_installed(self, package_name: str, version: str):
        """设置已安装的包"""
        self._installed[package_name] = version
    
    def resolve(self, plugin_id: str) -> DependencyResolution:
        """解析依赖"""
        resolution = DependencyResolution(success=True)
        
        if plugin_id not in self._dependency_graph:
            return resolution
        
        dependencies = self._dependency_graph[plugin_id]
        
        for dep in dependencies:
            if dep.name in self._installed:
                installed_version = self._installed[dep.name]
                
                try:
                    spec = SpecifierSet(dep.version_range)
                    if pkg_version.parse(installed_version) in spec:
                        resolution.resolved[dep.name] = installed_version
                    else:
                        resolution.conflicts.append(
                            f"{dep.name} 版本 {installed_version} 不满足 {dep.version_range}"
                        )
                        resolution.success = False
                except InvalidSpecifier:
                    resolution.conflicts.append(f"{dep.name} 版本范围无效: {dep.version_range}")
                    resolution.success = False
            else:
                if dep.required:
                    resolution.missing.append(dep.name)
                    resolution.success = False
                    resolution.suggestions.append(f"安装 {dep.name}{dep.version_range}")
        
        return resolution
    
    def detect_circular_dependencies(self) -> List[List[str]]:
        """检测循环依赖"""
        cycles = []
        visited = set()
        path = []
        
        def dfs(plugin_id: str):
            if plugin_id in path:
                cycle_start = path.index(plugin_id)
                cycles.append(path[cycle_start:] + [plugin_id])
                return
            
            if plugin_id in visited:
                return
            
            visited.add(plugin_id)
            path.append(plugin_id)
            
            for dep in self._dependency_graph.get(plugin_id, []):
                dfs(dep.name)
            
            path.pop()
        
        for plugin_id in self._dependency_graph:
            dfs(plugin_id)
        
        return cycles
    
    def get_installation_order(self, plugin_ids: List[str]) -> List[str]:
        """获取安装顺序"""
        order = []
        visited = set()
        
        def visit(plugin_id: str):
            if plugin_id in visited:
                return
            
            visited.add(plugin_id)
            
            for dep in self._dependency_graph.get(plugin_id, []):
                visit(dep.name)
            
            order.append(plugin_id)
        
        for plugin_id in plugin_ids:
            visit(plugin_id)
        
        return order
    
    def check_compatibility(self, plugin_version: str, app_version_range: str) -> bool:
        """检查兼容性"""
        try:
            spec = SpecifierSet(app_version_range)
            return pkg_version.parse(plugin_version) in spec
        except Exception:
            return True


class VersionManager:
    """版本管理器"""
    
    def __init__(self):
        self._versions: Dict[str, List[str]] = {}
        self._current: Dict[str, str] = {}
        self._rollback_history: Dict[str, List[str]] = {}
    
    def register_version(self, plugin_id: str, version: str):
        """注册版本"""
        if plugin_id not in self._versions:
            self._versions[plugin_id] = []
        
        if version not in self._versions[plugin_id]:
            self._versions[plugin_id].append(version)
            self._versions[plugin_id].sort(key=lambda v: pkg_version.parse(v))
    
    def set_current_version(self, plugin_id: str, version: str):
        """设置当前版本"""
        self._current[plugin_id] = version
    
    def get_available_versions(self, plugin_id: str) -> List[str]:
        """获取可用版本"""
        return self._versions.get(plugin_id, [])
    
    def get_current_version(self, plugin_id: str) -> str:
        """获取当前版本"""
        return self._current.get(plugin_id, "unknown")
    
    def rollback(self, plugin_id: str, target_version: str) -> bool:
        """回滚版本"""
        if plugin_id not in self._versions:
            return False
        
        if target_version not in self._versions[plugin_id]:
            return False
        
        if plugin_id not in self._rollback_history:
            self._rollback_history[plugin_id] = []
        
        self._rollback_history[plugin_id].append(self._current.get(plugin_id, ""))
        self._current[plugin_id] = target_version
        
        logger.info(f"插件 {plugin_id} 回滚到版本 {target_version}")
        return True
    
    def get_rollback_history(self, plugin_id: str) -> List[str]:
        """获取回滚历史"""
        return self._rollback_history.get(plugin_id, [])
    
    def is_newer_version_available(self, plugin_id: str, current: str) -> bool:
        """检查是否有新版本"""
        versions = self._versions.get(plugin_id, [])
        if not versions:
            return False
        
        try:
            current_ver = pkg_version.parse(current)
            return any(pkg_version.parse(v) > current_ver for v in versions)
        except Exception:
            return False
    
    def get_latest_version(self, plugin_id: str) -> Optional[str]:
        """获取最新版本"""
        versions = self._versions.get(plugin_id, [])
        return versions[-1] if versions else None
