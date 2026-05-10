"""
模块基类 - 所有专家级模块的基础
"""

from enum import Enum, auto
from typing import Optional, Dict, Any, Callable
import logging
from PySide6.QtCore import QObject, Signal, QThread
from PySide6.QtWidgets import QWidget


logger = logging.getLogger(__name__)


class ModuleStatus(Enum):
    """模块状态"""
    STOPPED = auto()
    RUNNING = auto()
    PAUSED = auto()
    ERROR = auto()


class ModuleBase(QObject):
    """专家级模块基类"""
    
    status_changed = Signal(ModuleStatus)
    log_message = Signal(str, str)  # (level, message)
    data_updated = Signal(Dict[str, Any])
    
    def __init__(self, name: str, description: str = ""):
        super().__init__()
        self.name = name
        self.description = description
        self._status = ModuleStatus.STOPPED
        self._config: Dict[str, Any] = {}
        self._ui: Optional[QWidget] = None
        self._worker_thread: Optional[QThread] = None
        
    @property
    def status(self) -> ModuleStatus:
        return self._status
        
    @status.setter
    def status(self, value: ModuleStatus):
        self._status = value
        self.status_changed.emit(value)
        
    def get_ui(self) -> QWidget:
        """获取模块UI，子类必须重写"""
        if self._ui is None:
            self._ui = self._create_ui()
        return self._ui
        
    def _create_ui(self) -> QWidget:
        """创建UI，子类必须重写"""
        raise NotImplementedError("子类必须实现_create_ui方法")
        
    def start(self):
        """启动模块"""
        self.status = ModuleStatus.RUNNING
        self.log("INFO", f"模块 {self.name} 已启动")
        
    def stop(self):
        """停止模块"""
        self.status = ModuleStatus.STOPPED
        self.log("INFO", f"模块 {self.name} 已停止")
        
    def pause(self):
        """暂停模块"""
        self.status = ModuleStatus.PAUSED
        self.log("INFO", f"模块 {self.name} 已暂停")
        
    def reset(self):
        """重置模块"""
        self.stop()
        self.start()
        
    def log(self, level: str, message: str):
        """记录日志"""
        self.log_message.emit(level, message)
        logger.info(f"[{self.name}] {message}")
        
    def get_config(self) -> Dict[str, Any]:
        """获取配置"""
        return self._config.copy()
        
    def set_config(self, config: Dict[str, Any]):
        """设置配置"""
        self._config.update(config)
        
    def get_status_info(self) -> Dict[str, Any]:
        """获取详细状态信息"""
        return {
            "name": self.name,
            "description": self.description,
            "status": self._status.name,
            "config": self._config
        }
