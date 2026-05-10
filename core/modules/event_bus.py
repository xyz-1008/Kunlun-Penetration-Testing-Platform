"""
事件总线模块
插件间解耦通信
"""

import logging
import threading
from typing import Dict, List, Callable, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime

logger = logging.getLogger(__name__)


@dataclass
class Event:
    """事件"""
    name: str
    data: Any = None
    source: str = ""
    timestamp: datetime = field(default_factory=datetime.now)


class EventBus:
    """事件总线"""
    
    def __init__(self):
        self._subscribers: Dict[str, List[Callable]] = {}
        self._event_history: List[Event] = []
        self._lock = threading.RLock()
    
    def subscribe(self, event_name: str, callback: Callable):
        """订阅事件"""
        with self._lock:
            if event_name not in self._subscribers:
                self._subscribers[event_name] = []
            self._subscribers[event_name].append(callback)
            logger.debug(f"订阅事件: {event_name}")
    
    def unsubscribe(self, event_name: str, callback: Callable):
        """取消订阅"""
        with self._lock:
            if event_name in self._subscribers:
                self._subscribers[event_name].remove(callback)
                logger.debug(f"取消订阅: {event_name}")
    
    def publish(self, event_name: str, data: Any = None, source: str = ""):
        """发布事件"""
        event = Event(name=event_name, data=data, source=source)
        
        with self._lock:
            self._event_history.append(event)
            
            callbacks = self._subscribers.get(event_name, []).copy()
        
        for callback in callbacks:
            try:
                callback(event)
            except Exception as e:
                logger.error(f"事件回调执行失败 [{event_name}]: {e}")
    
    def publish_sync(self, event_name: str, data: Any = None, source: str = ""):
        """同步发布事件"""
        event = Event(name=event_name, data=data, source=source)
        
        with self._lock:
            self._event_history.append(event)
            callbacks = self._subscribers.get(event_name, []).copy()
        
        results = []
        for callback in callbacks:
            try:
                result = callback(event)
                results.append(result)
            except Exception as e:
                logger.error(f"事件回调执行失败 [{event_name}]: {e}")
                results.append(None)
        
        return results
    
    def get_event_history(self, limit: int = 100, event_name: str = None) -> List[Event]:
        """获取事件历史"""
        with self._lock:
            history = self._event_history.copy()
        
        if event_name:
            history = [e for e in history if e.name == event_name]
        
        return history[-limit:]
    
    def clear_history(self):
        """清除历史"""
        with self._lock:
            self._event_history.clear()
    
    def get_subscriber_count(self, event_name: str) -> int:
        """获取订阅者数量"""
        with self._lock:
            return len(self._subscribers.get(event_name, []))
    
    def get_all_events(self) -> List[str]:
        """获取所有事件名"""
        with self._lock:
            return list(self._subscribers.keys())
