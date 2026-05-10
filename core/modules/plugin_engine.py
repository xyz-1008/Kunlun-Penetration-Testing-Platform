"""
企业级插件化架构核心引擎
包含插件基类、类型定义、权限模型
"""

import os
import sys
import logging
import importlib
import importlib.util
from pathlib import Path
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from enum import Enum
from abc import ABC, abstractmethod
from datetime import datetime
import json

logger = logging.getLogger(__name__)


class PluginType(Enum):
    """插件类型"""
    ASSET_SOURCE = "AssetSource"
    SCANNER = "Scanner"
    FINGERPRINT = "Fingerprint"
    EXPLOIT = "Exploit"
    REPORTER = "Reporter"
    C2_EXTENSION = "C2Extension"
    POC = "PoC"
    MITM = "MITM"
    FUZZER = "Fuzzer"
    CUSTOM = "Custom"


class Permission(Enum):
    """权限"""
    NETWORK = "network"
    FILE_READ = "file_read"
    FILE_WRITE = "file_write"
    PROCESS = "process"
    ELEVATED = "elevated"
    DATABASE = "database"
    CONFIG = "config"


class PluginStatus(Enum):
    """插件状态"""
    LOADED = "loaded"
    ENABLED = "enabled"
    DISABLED = "disabled"
    ERROR = "error"
    UNLOADING = "unloading"


class ReleaseChannel(Enum):
    """发布通道"""
    ALPHA = "alpha"
    BETA = "beta"
    STABLE = "stable"


@dataclass
class PluginManifest:
    """插件清单"""
    name: str
    version: str
    author: str
    plugin_type: PluginType
    description: str = ""
    protocol: str = ""
    permissions: List[Permission] = field(default_factory=list)
    dependencies: List[str] = field(default_factory=list)
    optional_dependencies: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    compatible_versions: str = ">=1.0.0"
    release_channel: ReleaseChannel = ReleaseChannel.STABLE
    homepage: str = ""
    license: str = "MIT"
    icon: str = ""
    config_schema: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PluginContext:
    """插件执行上下文"""
    task_id: str = ""
    target: str = ""
    config: Dict[str, Any] = field(default_factory=dict)
    assets: List[Dict[str, Any]] = field(default_factory=list)
    results: List[Dict[str, Any]] = field(default_factory=list)
    variables: Dict[str, Any] = field(default_factory=dict)
    event_bus: Any = None
    logger: Any = None
    start_time: datetime = field(default_factory=datetime.now)
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    fingerprints: List[Dict[str, Any]] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.now)
    
    def get_variable(self, key: str, default: Any = None) -> Any:
        """获取变量"""
        return self.variables.get(key, default)
    
    def set_variable(self, key: str, value: Any):
        """设置变量"""
        self.variables[key] = value
    
    def add_result(self, result: Dict[str, Any]):
        """添加结果"""
        self.results.append(result)
    
    def add_asset(self, asset: Dict[str, Any]):
        """添加资产"""
        self.assets.append(asset)
    
    def add_vulnerability(self, vuln: Dict[str, Any]):
        """添加漏洞"""
        self.vulnerabilities.append(vuln)
    
    def add_fingerprint(self, fingerprint: Dict[str, Any]):
        """添加指纹"""
        self.fingerprints.append(fingerprint)


@dataclass
class PluginResult:
    """插件执行结果"""
    plugin_id: str
    success: bool
    data: Any = None
    error: str = ""
    execution_time: float = 0.0
    timestamp: datetime = field(default_factory=datetime.now)


class BasePlugin(ABC):
    """插件基类"""
    
    def __init__(self):
        self.manifest: Optional[PluginManifest] = None
        self.status: PluginStatus = PluginStatus.LOADED
        self._config: Dict[str, Any] = {}
        self._logger = logging.getLogger(self.__class__.__name__)
    
    @abstractmethod
    def execute(self, context: PluginContext) -> PluginResult:
        """执行插件"""
        pass
    
    def on_load(self):
        """加载时钩子"""
        pass
    
    def on_unload(self):
        """卸载时钩子"""
        pass
    
    def on_enable(self):
        """启用时钩子"""
        self.status = PluginStatus.ENABLED
    
    def on_disable(self):
        """停用时钩子"""
        self.status = PluginStatus.DISABLED
    
    def get_config(self, key: str, default: Any = None) -> Any:
        """获取配置"""
        return self._config.get(key, default)
    
    def set_config(self, key: str, value: Any):
        """设置配置"""
        self._config[key] = value
    
    def log_info(self, message: str):
        """记录信息日志"""
        self._logger.info(f"[{self.manifest.name if self.manifest else 'Unknown'}] {message}")
    
    def log_error(self, message: str):
        """记录错误日志"""
        self._logger.error(f"[{self.manifest.name if self.manifest else 'Unknown'}] {message}")
    
    def log_debug(self, message: str):
        """记录调试日志"""
        self._logger.debug(f"[{self.manifest.name if self.manifest else 'Unknown'}] {message}")


def hook(event_name: str):
    """钩子装饰器"""
    def decorator(func):
        func._hook_event = event_name
        return func
    return decorator


class PluginLoader:
    """插件加载器"""
    
    def __init__(self, plugin_dirs: List[str] = None):
        self.plugin_dirs = plugin_dirs or []
        self._loaded_plugins: Dict[str, BasePlugin] = {}
        self._plugin_modules: Dict[str, Any] = {}
    
    def discover_plugins(self) -> List[str]:
        """发现插件"""
        plugin_files = []
        
        for plugin_dir in self.plugin_dirs:
            dir_path = Path(plugin_dir)
            if not dir_path.exists():
                continue
            
            for file_path in dir_path.rglob("*.py"):
                if file_path.name.startswith("_"):
                    continue
                plugin_files.append(str(file_path))
            
            for package_path in dir_path.rglob("*"):
                if package_path.is_dir() and (package_path / "__init__.py").exists():
                    plugin_files.append(str(package_path))
        
        return plugin_files
    
    def load_plugin(self, plugin_path: str) -> Optional[BasePlugin]:
        """加载单个插件"""
        try:
            path = Path(plugin_path)
            
            if path.is_file() and path.suffix == ".py":
                return self._load_single_file(path)
            elif path.is_dir():
                return self._load_package(path)
            
        except Exception as e:
            logger.error(f"加载插件失败 {plugin_path}: {e}")
            return None
    
    def _load_single_file(self, file_path: Path) -> Optional[BasePlugin]:
        """加载单个Python文件"""
        try:
            module_name = f"plugin_{file_path.stem}"
            spec = importlib.util.spec_from_file_location(module_name, file_path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            
            self._plugin_modules[module_name] = module
            
            plugin_class = self._find_plugin_class(module)
            if plugin_class:
                plugin = plugin_class()
                plugin.on_load()
                
                plugin_id = plugin.manifest.name if plugin.manifest else file_path.stem
                self._loaded_plugins[plugin_id] = plugin
                
                logger.info(f"加载插件: {plugin_id}")
                return plugin
            
        except Exception as e:
            logger.error(f"加载文件插件失败 {file_path}: {e}")
        
        return None
    
    def _load_package(self, package_path: Path) -> Optional[BasePlugin]:
        """加载Python包"""
        try:
            init_file = package_path / "__init__.py"
            if not init_file.exists():
                return None
            
            module_name = f"plugin_{package_path.name}"
            spec = importlib.util.spec_from_file_location(module_name, init_file)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            
            self._plugin_modules[module_name] = module
            
            plugin_class = self._find_plugin_class(module)
            if plugin_class:
                plugin = plugin_class()
                plugin.on_load()
                
                plugin_id = plugin.manifest.name if plugin.manifest else package_path.name
                self._loaded_plugins[plugin_id] = plugin
                
                logger.info(f"加载包插件: {plugin_id}")
                return plugin
            
        except Exception as e:
            logger.error(f"加载包插件失败 {package_path}: {e}")
        
        return None
    
    def _find_plugin_class(self, module) -> Optional[type]:
        """查找插件类"""
        for attr_name in dir(module):
            attr = getattr(module, attr_name)
            if (isinstance(attr, type) and 
                issubclass(attr, BasePlugin) and 
                attr != BasePlugin):
                return attr
        return None
    
    def load_all_plugins(self) -> Dict[str, BasePlugin]:
        """加载所有插件"""
        plugin_files = self.discover_plugins()
        
        for plugin_file in plugin_files:
            self.load_plugin(plugin_file)
        
        logger.info(f"加载了 {len(self._loaded_plugins)} 个插件")
        return self._loaded_plugins
    
    def reload_plugin(self, plugin_id: str) -> bool:
        """重载插件"""
        if plugin_id not in self._loaded_plugins:
            return False
        
        plugin = self._loaded_plugins[plugin_id]
        plugin.on_unload()
        
        del self._loaded_plugins[plugin_id]
        
        for module_name, module in list(self._plugin_modules.items()):
            if plugin_id in module_name:
                importlib.reload(module)
        
        return True
    
    def unload_plugin(self, plugin_id: str) -> bool:
        """卸载插件"""
        if plugin_id not in self._loaded_plugins:
            return False
        
        plugin = self._loaded_plugins[plugin_id]
        plugin.on_unload()
        
        del self._loaded_plugins[plugin_id]
        logger.info(f"卸载插件: {plugin_id}")
        return True
    
    def get_plugin(self, plugin_id: str) -> Optional[BasePlugin]:
        """获取插件"""
        return self._loaded_plugins.get(plugin_id)
    
    def get_all_plugins(self) -> Dict[str, BasePlugin]:
        """获取所有插件"""
        return self._loaded_plugins.copy()
    
    def get_plugins_by_type(self, plugin_type: PluginType) -> List[BasePlugin]:
        """按类型获取插件"""
        return [
            p for p in self._loaded_plugins.values()
            if p.manifest and p.manifest.plugin_type == plugin_type
        ]
    
    def get_plugin_ids(self) -> List[str]:
        """获取所有插件ID"""
        return list(self._loaded_plugins.keys())
