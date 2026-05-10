"""
事件总线 - 模块间解耦通信机制
功能：
- 发布/订阅模式，模块间不直接依赖
- 支持同步和异步事件处理
- 事件历史记录和回放
- 支持事件过滤和优先级
"""

import logging
import threading
from typing import Dict, List, Callable, Any, Optional
from datetime import datetime
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class EventPriority(Enum):
    """事件优先级"""
    HIGH = "high"
    NORMAL = "normal"
    LOW = "low"


@dataclass
class PlatformEvent:
    """平台事件"""
    event_type: str
    source: str
    timestamp: datetime = field(default_factory=datetime.now)
    data: Dict[str, Any] = field(default_factory=dict)
    priority: EventPriority = EventPriority.NORMAL


class EventBus:
    """事件总线"""
    
    def __init__(self):
        self._subscribers: Dict[str, List[Dict]] = {}
        self._lock = threading.RLock()
        self._event_history: List[PlatformEvent] = []
        self._max_history = 10000
        self._logger = logging.getLogger("EventBus")
    
    def subscribe(self, event_type: str, callback: Callable, 
                  priority: EventPriority = EventPriority.NORMAL,
                  filter_func: Optional[Callable] = None):
        """订阅事件"""
        with self._lock:
            if event_type not in self._subscribers:
                self._subscribers[event_type] = []
            
            self._subscribers[event_type].append({
                'callback': callback,
                'priority': priority,
                'filter_func': filter_func,
                'active': True
            })
            
            # 按优先级排序
            self._subscribers[event_type].sort(
                key=lambda x: {'high': 0, 'normal': 1, 'low': 2}[x['priority'].value]
            )
            
            self._logger.debug(f"订阅事件: {event_type}")
    
    def unsubscribe(self, event_type: str, callback: Callable):
        """取消订阅"""
        with self._lock:
            if event_type in self._subscribers:
                self._subscribers[event_type] = [
                    sub for sub in self._subscribers[event_type]
                    if sub['callback'] != callback
                ]
    
    def publish(self, event_type: str, source: str, data: Dict[str, Any] = None,
                priority: EventPriority = EventPriority.NORMAL):
        """发布事件"""
        event = PlatformEvent(
            event_type=event_type,
            source=source,
            data=data or {},
            priority=priority
        )
        
        # 记录事件历史
        with self._lock:
            self._event_history.append(event)
            if len(self._event_history) > self._max_history:
                self._event_history = self._event_history[-self._max_history:]
        
        # 通知订阅者
        self._notify_subscribers(event)
    
    def _notify_subscribers(self, event: PlatformEvent):
        """通知订阅者"""
        with self._lock:
            subscribers = self._subscribers.get(event.event_type, [])
        
        for sub in subscribers:
            if not sub['active']:
                continue
            
            # 应用过滤器
            if sub['filter_func'] and not sub['filter_func'](event):
                continue
            
            try:
                sub['callback'](event)
            except Exception as e:
                self._logger.error(f"事件回调执行失败: {e}")
    
    def get_event_history(self, event_type: str = None, 
                          limit: int = 100) -> List[PlatformEvent]:
        """获取事件历史"""
        with self._lock:
            history = self._event_history.copy()
        
        if event_type:
            history = [e for e in history if e.event_type == event_type]
        
        return history[-limit:]
    
    def clear_history(self):
        """清空事件历史"""
        with self._lock:
            self._event_history.clear()
    
    def get_stats(self) -> Dict[str, Any]:
        """获取统计信息"""
        with self._lock:
            event_types = {}
            for event in self._event_history:
                event_types[event.event_type] = event_types.get(event.event_type, 0) + 1
            
            return {
                'total_events': len(self._event_history),
                'event_types': event_types,
                'subscriber_count': sum(len(subs) for subs in self._subscribers.values())
            }
