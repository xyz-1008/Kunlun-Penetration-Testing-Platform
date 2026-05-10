"""统一后端核心 - 应用单例"""

import logging
import threading
from typing import Dict, Any, Optional, Callable, List
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)


class Application:
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._initialized = False
            return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        
        self._logger = logging.getLogger("Application")
        self._running = False
        self._start_time = None
        self.config = None
        self.db = None
        self.event_bus = None
        self._ui_callbacks: Dict[str, List[Callable]] = {}
        self._modules: Dict[str, Any] = {}
        self._initialized = True
    
    def initialize(self, config_manager=None, db_manager=None, event_bus=None):
        self._logger.info("Initializing unified application core...")
        
        if config_manager:
            self.config = config_manager
        if db_manager:
            self.db = db_manager
        if event_bus:
            self.event_bus = event_bus
        
        self._running = True
        self._start_time = datetime.now()
        
        self._logger.info("Application core initialized")
    
    def register_module(self, module_id: str, module_instance):
        self._modules[module_id] = module_instance
        self._logger.info(f"Module registered: {module_id}")
    
    def get_module(self, module_id: str):
        return self._modules.get(module_id)
    
    def call_module_service(self, module_id: str, service_name: str, *args, **kwargs) -> Any:
        module = self._modules.get(module_id)
        if not module:
            raise RuntimeError(f"Module not found: {module_id}")
        
        if hasattr(module, service_name):
            handler = getattr(module, service_name)
            if callable(handler):
                return handler(*args, **kwargs)
        
        raise RuntimeError(f"Service not found: {service_name} in {module_id}")
    
    def register_ui_callback(self, event_name: str, callback: Callable):
        if event_name not in self._ui_callbacks:
            self._ui_callbacks[event_name] = []
        self._ui_callbacks[event_name].append(callback)
    
    def notify_ui(self, event_name: str, data: Dict[str, Any]):
        callbacks = self._ui_callbacks.get(event_name, [])
        for callback in callbacks:
            try:
                callback(data)
            except Exception as e:
                self._logger.error(f"UI callback error: {e}")
    
    def get_comprehensive_stats(self) -> Dict[str, Any]:
        uptime = None
        if self._start_time:
            uptime = (datetime.now() - self._start_time).total_seconds()
        
        return {
            "app": {
                "name": "昆仑安全测试平台 Pro",
                "version": "1.0.0",
                "running": self._running,
                "uptime_seconds": uptime,
                "start_time": self._start_time.isoformat() if self._start_time else None
            },
            "modules": {mid: m.get_status_info() if hasattr(m, 'get_status_info') else {} 
                       for mid, m in self._modules.items()},
        }
    
    def is_running(self) -> bool:
        return self._running
