"""
统一后端核心 - 应用单例
功能：
- Application单例，管理所有模块生命周期
- 初始化流程：加载配置→初始化数据库→注册模块→启动UI→进入事件循环
- 各模块按需延迟加载，未使用模块不占用资源
- 退出时统一清理：关闭连接、保存状态、销毁线程
"""

import logging
import threading
import atexit
from typing import Dict, Any, Optional, Callable, List
from datetime import datetime
from pathlib import Path

from .event_bus import EventBus, EventPriority
from .data_bus import DataBus
from .module_registry import ModuleRegistry, ModuleState

logger = logging.getLogger(__name__)


class Application:
    """统一应用单例"""
    
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
        self._project_root = None
        
        # 核心组件
        self.config = None
        self.data_bus: Optional[DataBus] = None
        self.event_bus: Optional[EventBus] = None
        self.module_registry: Optional[ModuleRegistry] = None
        
        # UI回调
        self._ui_callbacks: Dict[str, List[Callable]] = {}
        
        # 状态
        self._initialized = False
        self._shutdown_hooks: List[Callable] = []
        
        # 注册退出清理
        atexit.register(self._cleanup)
    
    def initialize(self, project_root: str = None, config_manager=None):
        """初始化应用核心"""
        if self._initialized:
            self._logger.warning("应用已初始化")
            return
        
        self._project_root = Path(project_root) if project_root else Path.cwd()
        self._logger.info("=" * 60)
        self._logger.info("初始化统一后端核心")
        self._logger.info("=" * 60)
        
        try:
            # 1. 加载配置
            self._logger.info("步骤1: 加载配置...")
            if config_manager:
                self.config = config_manager
            else:
                from core.config.config_manager import ConfigManager
                self.config = ConfigManager()
            self._logger.info("配置加载完成")
            
            # 2. 初始化数据库
            self._logger.info("步骤2: 初始化数据库...")
            db_path = (self._project_root / "data" / "app.db").resolve()
            db_path.parent.mkdir(parents=True, exist_ok=True)
            self.data_bus = DataBus(str(db_path))
            self.data_bus.create_all_tables()
            self._logger.info("数据库初始化完成")
            
            # 3. 初始化事件总线
            self._logger.info("步骤3: 初始化事件总线...")
            self.event_bus = EventBus()
            self._logger.info("事件总线初始化完成")
            
            # 4. 初始化模块注册中心
            self._logger.info("步骤4: 初始化模块注册中心...")
            self.module_registry = ModuleRegistry()
            self._logger.info("模块注册中心初始化完成")
            
            # 5. 标记为已初始化
            self._running = True
            self._start_time = datetime.now()
            self._initialized = True
            
            self._logger.info("=" * 60)
            self._logger.info("应用核心初始化完成")
            self._logger.info("=" * 60)
            
        except Exception as e:
            self._logger.error(f"应用初始化失败: {e}")
            raise
    
    def register_module(self, module_id: str, module_instance,
                        dependencies: List[str] = None,
                        lazy_load: bool = True):
        """注册功能模块"""
        if not self._initialized:
            raise RuntimeError("应用未初始化")
        
        self.module_registry.register(
            module_id=module_id,
            module_instance=module_instance,
            dependencies=dependencies,
            lazy_load=lazy_load
        )
        
        self._logger.info(f"模块注册: {module_id}")
    
    def initialize_module(self, module_id: str, **kwargs):
        """初始化指定模块"""
        self.module_registry.initialize_module(module_id, **kwargs)
        self._logger.info(f"模块初始化: {module_id}")
    
    def initialize_all_modules(self, **kwargs):
        """初始化所有模块"""
        self.module_registry.initialize_all(**kwargs)
        self._logger.info("所有模块初始化完成")
    
    def get_module(self, module_id: str):
        """获取模块实例"""
        return self.module_registry.get_module(module_id)
    
    def call_module_service(self, module_id: str, service_name: str, *args, **kwargs):
        """调用模块服务"""
        return self.module_registry.call_service(module_id, service_name, *args, **kwargs)
    
    def publish_event(self, event_type: str, source: str, data: Dict[str, Any] = None,
                      priority: EventPriority = EventPriority.NORMAL):
        """发布事件"""
        self.event_bus.publish(event_type, source, data, priority)
    
    def subscribe_event(self, event_type: str, callback: Callable,
                        priority: EventPriority = EventPriority.NORMAL,
                        filter_func: Optional[Callable] = None):
        """订阅事件"""
        self.event_bus.subscribe(event_type, callback, priority, filter_func)
    
    def register_ui_callback(self, event_name: str, callback: Callable):
        """注册UI回调"""
        if event_name not in self._ui_callbacks:
            self._ui_callbacks[event_name] = []
        self._ui_callbacks[event_name].append(callback)
        self._logger.debug(f"UI回调注册: {event_name}")
    
    def notify_ui(self, event_name: str, data: Dict[str, Any]):
        """通知UI"""
        callbacks = self._ui_callbacks.get(event_name, [])
        for callback in callbacks:
            try:
                callback(data)
            except Exception as e:
                self._logger.error(f"UI回调执行失败: {e}")
    
    def add_shutdown_hook(self, hook: Callable):
        """添加关闭钩子"""
        self._shutdown_hooks.append(hook)
    
    def get_comprehensive_stats(self) -> Dict[str, Any]:
        """获取综合统计信息"""
        uptime = None
        if self._start_time:
            uptime = (datetime.now() - self._start_time).total_seconds()
        
        return {
            "application": {
                "name": "昆仑安全测试平台 Pro",
                "version": "1.0.0",
                "running": self._running,
                "uptime_seconds": uptime,
                "start_time": self._start_time.isoformat() if self._start_time else None,
                "project_root": str(self._project_root),
            },
            "modules": self.module_registry.get_stats() if self.module_registry else {},
            "database": self.data_bus.get_stats() if self.data_bus else {},
            "events": self.event_bus.get_stats() if self.event_bus else {},
        }
    
    def shutdown(self):
        """关闭应用"""
        self._logger.info("=" * 60)
        self._logger.info("关闭应用...")
        self._logger.info("=" * 60)
        
        self._running = False
        
        # 1. 关闭所有模块
        if self.module_registry:
            self._logger.info("关闭所有模块...")
            self.module_registry.shutdown_all()
        
        # 2. 执行关闭钩子
        for hook in self._shutdown_hooks:
            try:
                hook()
            except Exception as e:
                self._logger.error(f"关闭钩子执行失败: {e}")
        
        # 3. 关闭数据库
        if self.data_bus:
            self._logger.info("关闭数据库...")
            self.data_bus.close()
        
        # 4. 清空事件历史
        if self.event_bus:
            self._logger.info("清空事件历史...")
            self.event_bus.clear_history()
        
        self._logger.info("=" * 60)
        self._logger.info("应用已关闭")
        self._logger.info("=" * 60)
    
    def _cleanup(self):
        """退出清理"""
        if self._running:
            self.shutdown()
    
    def is_running(self) -> bool:
        """检查应用是否运行中"""
        return self._running
    
    def get_project_root(self) -> Path:
        """获取项目根目录"""
        return self._project_root


# 全局应用实例访问
def get_app() -> Application:
    """获取全局应用实例"""
    return Application()


def initialize_app(project_root: str = None, config_manager=None) -> Application:
    """初始化并返回应用实例"""
    app = Application()
    app.initialize(project_root, config_manager)
    return app
