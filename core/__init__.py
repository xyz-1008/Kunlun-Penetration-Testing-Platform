"""
统一后端核心模块
提供统一的后端核心组件导入
"""

from .event_bus import EventBus, PlatformEvent, EventPriority
from .data_bus import DataBus, Base
from .module_registry import ModuleRegistry, ModuleInfo, ModuleState
from .application import Application, get_app, initialize_app

__all__ = [
    'EventBus',
    'PlatformEvent',
    'EventPriority',
    'DataBus',
    'Base',
    'ModuleRegistry',
    'ModuleInfo',
    'ModuleState',
    'Application',
    'get_app',
    'initialize_app',
]
