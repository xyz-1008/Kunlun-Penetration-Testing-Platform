"""
模块注册中心 - 统一管理所有功能模块
功能：
- 模块注册、初始化、销毁
- 模块依赖管理
- 模块生命周期管理
- 模块服务发现
"""

import logging
import threading
from typing import Dict, Any, Optional, List, Type
from datetime import datetime
from enum import Enum

logger = logging.getLogger(__name__)


class ModuleState(Enum):
    """模块状态"""
    REGISTERED = "registered"
    INITIALIZING = "initializing"
    ACTIVE = "active"
    SUSPENDED = "suspended"
    ERROR = "error"
    DESTROYED = "destroyed"


class ModuleInfo:
    """模块信息"""
    
    def __init__(self, module_id: str, module_instance, 
                 dependencies: List[str] = None,
                 lazy_load: bool = True):
        self.module_id = module_id
        self.instance = module_instance
        self.dependencies = dependencies or []
        self.lazy_load = lazy_load
        self.state = ModuleState.REGISTERED
        self.registered_at = datetime.now()
        self.last_error = None
        self.services: Dict[str, Any] = {}
    
    def register_service(self, service_name: str, service_func):
        """注册服务"""
        self.services[service_name] = service_func
    
    def get_service(self, service_name: str):
        """获取服务"""
        return self.services.get(service_name)


class ModuleRegistry:
    """模块注册中心"""
    
    def __init__(self):
        self._modules: Dict[str, ModuleInfo] = {}
        self._lock = threading.RLock()
        self._logger = logging.getLogger("ModuleRegistry")
        self._initialization_order: List[str] = []
    
    def register(self, module_id: str, module_instance, 
                 dependencies: List[str] = None,
                 lazy_load: bool = True):
        """注册模块"""
        with self._lock:
            if module_id in self._modules:
                self._logger.warning(f"模块已存在，将被覆盖: {module_id}")
            
            module_info = ModuleInfo(
                module_id=module_id,
                module_instance=module_instance,
                dependencies=dependencies,
                lazy_load=lazy_load
            )
            
            self._modules[module_id] = module_info
            self._logger.info(f"模块注册成功: {module_id}")
            
            return module_info
    
    def unregister(self, module_id: str):
        """注销模块"""
        with self._lock:
            if module_id not in self._modules:
                self._logger.warning(f"模块不存在: {module_id}")
                return
            
            module_info = self._modules[module_id]
            
            # 销毁模块
            if hasattr(module_info.instance, 'destroy'):
                try:
                    module_info.instance.destroy()
                except Exception as e:
                    self._logger.error(f"模块销毁失败: {module_id}, {e}")
            
            module_info.state = ModuleState.DESTROYED
            del self._modules[module_id]
            self._logger.info(f"模块注销成功: {module_id}")
    
    def get_module(self, module_id: str):
        """获取模块实例"""
        with self._lock:
            module_info = self._modules.get(module_id)
            if not module_info:
                return None
            return module_info.instance
    
    def get_module_info(self, module_id: str) -> Optional[ModuleInfo]:
        """获取模块信息"""
        return self._modules.get(module_id)
    
    def initialize_module(self, module_id: str, **kwargs):
        """初始化模块"""
        with self._lock:
            module_info = self._modules.get(module_id)
            if not module_info:
                raise RuntimeError(f"模块不存在: {module_id}")
            
            # 检查依赖
            for dep in module_info.dependencies:
                if dep not in self._modules:
                    raise RuntimeError(f"模块依赖未满足: {module_id} 需要 {dep}")
                
                dep_info = self._modules[dep]
                if dep_info.state not in [ModuleState.ACTIVE, ModuleState.REGISTERED]:
                    raise RuntimeError(f"模块依赖未就绪: {dep}")
            
            module_info.state = ModuleState.INITIALIZING
            
            try:
                # 调用模块初始化方法
                if hasattr(module_info.instance, 'initialize'):
                    module_info.instance.initialize(**kwargs)
                
                module_info.state = ModuleState.ACTIVE
                self._initialization_order.append(module_id)
                self._logger.info(f"模块初始化成功: {module_id}")
                
            except Exception as e:
                module_info.state = ModuleState.ERROR
                module_info.last_error = str(e)
                self._logger.error(f"模块初始化失败: {module_id}, {e}")
                raise
    
    def initialize_all(self, **kwargs):
        """初始化所有模块"""
        # 拓扑排序初始化
        initialized = set()
        
        def init_module(module_id: str):
            if module_id in initialized:
                return
            
            module_info = self._modules.get(module_id)
            if not module_info:
                return
            
            # 先初始化依赖
            for dep in module_info.dependencies:
                init_module(dep)
            
            # 初始化当前模块
            if module_info.state == ModuleState.REGISTERED:
                self.initialize_module(module_id, **kwargs)
            
            initialized.add(module_id)
        
        for module_id in list(self._modules.keys()):
            init_module(module_id)
    
    def suspend_module(self, module_id: str):
        """暂停模块"""
        with self._lock:
            module_info = self._modules.get(module_id)
            if not module_info:
                return
            
            if hasattr(module_info.instance, 'suspend'):
                module_info.instance.suspend()
            
            module_info.state = ModuleState.SUSPENDED
            self._logger.info(f"模块已暂停: {module_id}")
    
    def resume_module(self, module_id: str):
        """恢复模块"""
        with self._lock:
            module_info = self._modules.get(module_id)
            if not module_info:
                return
            
            if hasattr(module_info.instance, 'resume'):
                module_info.instance.resume()
            
            module_info.state = ModuleState.ACTIVE
            self._logger.info(f"模块已恢复: {module_id}")
    
    def call_service(self, module_id: str, service_name: str, *args, **kwargs):
        """调用模块服务"""
        with self._lock:
            module_info = self._modules.get(module_id)
            if not module_info:
                raise RuntimeError(f"模块不存在: {module_id}")
            
            service = module_info.get_service(service_name)
            if not service:
                # 尝试从模块实例获取
                if hasattr(module_info.instance, service_name):
                    service = getattr(module_info.instance, service_name)
                else:
                    raise RuntimeError(f"服务不存在: {module_id}.{service_name}")
            
            return service(*args, **kwargs)
    
    def get_all_modules(self) -> Dict[str, ModuleInfo]:
        """获取所有模块"""
        return self._modules.copy()
    
    def get_active_modules(self) -> List[str]:
        """获取活跃模块列表"""
        return [
            mid for mid, info in self._modules.items()
            if info.state == ModuleState.ACTIVE
        ]
    
    def get_stats(self) -> Dict[str, Any]:
        """获取统计信息"""
        stats = {
            'total_modules': len(self._modules),
            'active_modules': len(self.get_active_modules()),
            'modules': {}
        }
        
        for module_id, info in self._modules.items():
            stats['modules'][module_id] = {
                'state': info.state.value,
                'dependencies': info.dependencies,
                'services': list(info.services.keys()),
                'registered_at': info.registered_at.isoformat(),
                'last_error': info.last_error
            }
        
        return stats
    
    def shutdown_all(self):
        """关闭所有模块"""
        # 按初始化逆序关闭
        for module_id in reversed(self._initialization_order):
            try:
                self.unregister(module_id)
            except Exception as e:
                self._logger.error(f"模块关闭失败: {module_id}, {e}")
        
        self._initialization_order.clear()
        self._logger.info("所有模块已关闭")
