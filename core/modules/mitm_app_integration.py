"""
Application集成接口 - MITM代理与Application的统一集成
功能：
- 代理模块暴露给UI的接口保持简洁：启动、停止、获取状态、获取流量列表
- 事件总线上发布的事件类型标准化：新请求、新响应、断点触发、漏洞发现
- 其他模块通过订阅事件总线获取代理数据，无需直接依赖代理模块
- 代理配置统一在主配置文件管理，与全局配置合并
"""

import json
import logging
from typing import Dict, List, Any, Optional, Callable
from datetime import datetime
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class MITMEventType(Enum):
    """MITM事件类型"""
    PROXY_STARTED = "proxy_started"
    PROXY_STOPPED = "proxy_stopped"
    NEW_REQUEST = "new_request"
    NEW_RESPONSE = "new_response"
    BREAKPOINT_TRIGGERED = "breakpoint_triggered"
    VULNERABILITY_FOUND = "vulnerability_found"
    ASSET_DISCOVERED = "asset_discovered"
    C2_BEACON_DETECTED = "c2_beacon_detected"
    LATERAL_MOVEMENT_DETECTED = "lateral_movement_detected"
    REVERSE_CONNECTION = "reverse_connection"
    MOCK_RULE_MATCHED = "mock_rule_matched"
    SECURITY_EVENT = "security_event"
    PERFORMANCE_WARNING = "performance_warning"


@dataclass
class MITMEvent:
    """MITM事件"""
    event_type: MITMEventType
    timestamp: datetime
    data: Dict[str, Any]
    source: str = "mitm_proxy"


@dataclass
class MITMConfig:
    """MITM代理配置"""
    # 基础配置
    host: str = "127.0.0.1"
    port: int = 8080
    ssl_port: int = 8443
    
    # 证书配置
    ca_cert_path: str = ""
    ca_key_path: str = ""
    cert_cache_size: int = 1000
    
    # 拦截配置
    intercept_enabled: bool = True
    bypass_domains: List[str] = field(default_factory=list)
    whitelist_domains: List[str] = field(default_factory=list)
    
    # 历史配置
    max_history_count: int = 10000
    archive_enabled: bool = False
    archive_path: str = ""
    keep_hot_days: int = 7
    
    # 性能配置
    max_connections: int = 1000
    max_memory_mb: int = 1024
    enable_throttling: bool = True
    
    # 安全配置
    require_confirmation: bool = True
    encrypted_logging: bool = False
    log_storage_path: str = ""
    
    # 高级功能
    network_simulation_enabled: bool = False
    mock_enabled: bool = False
    passive_scanning_enabled: bool = True
    asset_linkage_enabled: bool = True
    vuln_linkage_enabled: bool = True
    c2_linkage_enabled: bool = False
    lateral_movement_enabled: bool = False
    
    # 上游代理
    upstream_proxy: str = ""
    upstream_auth: str = ""


class EventBus:
    """事件总线 - 标准化事件发布/订阅"""
    
    def __init__(self):
        self._subscribers: Dict[MITMEventType, List[Callable]] = {}
        self._event_history: List[MITMEvent] = []
        self._max_history = 1000
    
    def subscribe(self, event_type: MITMEventType, callback: Callable):
        """订阅事件"""
        if event_type not in self._subscribers:
            self._subscribers[event_type] = []
        self._subscribers[event_type].append(callback)
    
    def unsubscribe(self, event_type: MITMEventType, callback: Callable):
        """取消订阅"""
        if event_type in self._subscribers:
            try:
                self._subscribers[event_type].remove(callback)
            except ValueError:
                pass
    
    def publish(self, event: MITMEvent):
        """发布事件"""
        # 记录事件历史
        self._event_history.append(event)
        if len(self._event_history) > self._max_history:
            self._event_history = self._event_history[-self._max_history:]
        
        # 通知订阅者
        if event.event_type in self._subscribers:
            for callback in self._subscribers[event.event_type]:
                try:
                    callback(event)
                except Exception as e:
                    logger.error(f"事件通知失败: {e}")
    
    def get_event_history(self, event_type: MITMEventType = None,
                          limit: int = 100) -> List[MITMEvent]:
        """获取事件历史"""
        events = self._event_history
        
        if event_type:
            events = [e for e in events if e.event_type == event_type]
        
        return events[-limit:]


class MITMApplicationInterface:
    """MITM代理Application集成接口"""
    
    def __init__(self):
        self.config = MITMConfig()
        self.event_bus = EventBus()
        
        # 内部状态
        self._is_running = False
        self._engine = None
        self._traffic_data: List[Dict[str, Any]] = []
        self._status_callbacks: List[Callable] = []
    
    def start_proxy(self, config: Dict[str, Any] = None) -> bool:
        """启动代理"""
        try:
            if self._is_running:
                logger.warning("代理已在运行")
                return False
            
            # 更新配置
            if config:
                self._update_config(config)
            
            # 这里应该初始化并启动代理引擎
            # self._engine = MITMProxyEngine(self.config.host, self.config.port)
            # self._engine.start()
            
            self._is_running = True
            
            # 发布事件
            self.event_bus.publish(MITMEvent(
                event_type=MITMEventType.PROXY_STARTED,
                timestamp=datetime.utcnow(),
                data={
                    'host': self.config.host,
                    'port': self.config.port,
                }
            ))
            
            logger.info(f"MITM代理启动: {self.config.host}:{self.config.port}")
            return True
            
        except Exception as e:
            logger.error(f"启动代理失败: {e}")
            return False
    
    def stop_proxy(self) -> bool:
        """停止代理"""
        try:
            if not self._is_running:
                logger.warning("代理未运行")
                return False
            
            # 这里应该停止代理引擎
            # if self._engine:
            #     self._engine.stop()
            
            self._is_running = False
            
            # 发布事件
            self.event_bus.publish(MITMEvent(
                event_type=MITMEventType.PROXY_STOPPED,
                timestamp=datetime.utcnow(),
                data={}
            ))
            
            logger.info("MITM代理已停止")
            return True
            
        except Exception as e:
            logger.error(f"停止代理失败: {e}")
            return False
    
    def is_running(self) -> bool:
        """检查代理是否运行"""
        return self._is_running
    
    def get_status(self) -> Dict[str, Any]:
        """获取代理状态"""
        return {
            'is_running': self._is_running,
            'host': self.config.host,
            'port': self.config.port,
            'traffic_count': len(self._traffic_data),
            'config': self._get_config_summary(),
        }
    
    def get_traffic_list(self, page: int = 1, page_size: int = 100,
                         filters: Dict[str, Any] = None) -> Dict[str, Any]:
        """获取流量列表（分页）"""
        # 应用过滤
        filtered_data = self._traffic_data
        if filters:
            filtered_data = self._apply_filters(filtered_data, filters)
        
        # 分页
        start = (page - 1) * page_size
        end = start + page_size
        total_pages = (len(filtered_data) + page_size - 1) // page_size
        
        return {
            'data': filtered_data[start:end],
            'page': page,
            'page_size': page_size,
            'total_count': len(filtered_data),
            'total_pages': total_pages,
            'has_next': page < total_pages,
            'has_prev': page > 1,
        }
    
    def get_traffic_by_id(self, traffic_id: str) -> Optional[Dict[str, Any]]:
        """按ID获取流量"""
        for traffic in self._traffic_data:
            if traffic.get('id') == traffic_id:
                return traffic
        return None
    
    def add_traffic(self, traffic_data: Dict[str, Any]):
        """添加流量记录"""
        self._traffic_data.append(traffic_data)
        
        # 发布事件
        self.event_bus.publish(MITMEvent(
            event_type=MITMEventType.NEW_REQUEST,
            timestamp=datetime.utcnow(),
            data=traffic_data
        ))
    
    def update_traffic_response(self, traffic_id: str, response_data: Dict[str, Any]):
        """更新流量响应"""
        for traffic in self._traffic_data:
            if traffic.get('id') == traffic_id:
                traffic['response'] = response_data
                
                # 发布事件
                self.event_bus.publish(MITMEvent(
                    event_type=MITMEventType.NEW_RESPONSE,
                    timestamp=datetime.utcnow(),
                    data={
                        'traffic_id': traffic_id,
                        'response': response_data,
                    }
                ))
                break
    
    def get_config(self) -> MITMConfig:
        """获取配置"""
        return self.config
    
    def update_config(self, config: Dict[str, Any]) -> bool:
        """更新配置"""
        try:
            self._update_config(config)
            return True
        except Exception as e:
            logger.error(f"更新配置失败: {e}")
            return False
    
    def export_config(self) -> str:
        """导出配置"""
        config_dict = {
            'host': self.config.host,
            'port': self.config.port,
            'ssl_port': self.config.ssl_port,
            'ca_cert_path': self.config.ca_cert_path,
            'ca_key_path': self.config.ca_key_path,
            'intercept_enabled': self.config.intercept_enabled,
            'bypass_domains': self.config.bypass_domains,
            'whitelist_domains': self.config.whitelist_domains,
            'max_history_count': self.config.max_history_count,
            'archive_enabled': self.config.archive_enabled,
            'archive_path': self.config.archive_path,
            'keep_hot_days': self.config.keep_hot_days,
            'max_connections': self.config.max_connections,
            'max_memory_mb': self.config.max_memory_mb,
            'enable_throttling': self.config.enable_throttling,
            'require_confirmation': self.config.require_confirmation,
            'encrypted_logging': self.config.encrypted_logging,
            'log_storage_path': self.config.log_storage_path,
            'network_simulation_enabled': self.config.network_simulation_enabled,
            'mock_enabled': self.config.mock_enabled,
            'passive_scanning_enabled': self.config.passive_scanning_enabled,
            'asset_linkage_enabled': self.config.asset_linkage_enabled,
            'vuln_linkage_enabled': self.config.vuln_linkage_enabled,
            'c2_linkage_enabled': self.config.c2_linkage_enabled,
            'lateral_movement_enabled': self.config.lateral_movement_enabled,
            'upstream_proxy': self.config.upstream_proxy,
            'upstream_auth': self.config.upstream_auth,
        }
        
        return json.dumps(config_dict, indent=2, ensure_ascii=False)
    
    def import_config(self, json_data: str) -> bool:
        """导入配置"""
        try:
            config_dict = json.loads(json_data)
            return self.update_config(config_dict)
        except Exception as e:
            logger.error(f"导入配置失败: {e}")
            return False
    
    def on_status_change(self, callback: Callable):
        """注册状态变更回调"""
        self._status_callbacks.append(callback)
    
    def _update_config(self, config: Dict[str, Any]):
        """更新配置"""
        for key, value in config.items():
            if hasattr(self.config, key):
                setattr(self.config, key, value)
    
    def _get_config_summary(self) -> Dict[str, Any]:
        """获取配置摘要"""
        return {
            'host': self.config.host,
            'port': self.config.port,
            'intercept_enabled': self.config.intercept_enabled,
            'max_history_count': self.config.max_history_count,
            'max_connections': self.config.max_connections,
        }
    
    def _apply_filters(self, data: List[Dict], filters: Dict) -> List[Dict]:
        """应用过滤器"""
        filtered = data
        
        # 按方法过滤
        if 'method' in filters:
            filtered = [d for d in filtered if d.get('request', {}).get('method') == filters['method']]
        
        # 按状态码过滤
        if 'status_code' in filters:
            filtered = [d for d in filtered if d.get('response', {}).get('status_code') == filters['status_code']]
        
        # 按域名过滤
        if 'domain' in filters:
            filtered = [d for d in filtered if filters['domain'] in d.get('request', {}).get('url', '')]
        
        # 按标签过滤
        if 'tags' in filters:
            filtered = [d for d in filtered if any(t in d.get('tags', []) for t in filters['tags'])]
        
        return filtered


class MITMModuleIntegration:
    """MITM模块集成器 - 与其他模块的集成"""
    
    def __init__(self, app_interface: MITMApplicationInterface):
        self.app = app_interface
        
        # 订阅事件
        self._setup_event_subscriptions()
    
    def _setup_event_subscriptions(self):
        """设置事件订阅"""
        # 订阅新请求事件
        self.app.event_bus.subscribe(
            MITMEventType.NEW_REQUEST,
            self._on_new_request
        )
        
        # 订阅新响应事件
        self.app.event_bus.subscribe(
            MITMEventType.NEW_RESPONSE,
            self._on_new_response
        )
        
        # 订阅漏洞发现事件
        self.app.event_bus.subscribe(
            MITMEventType.VULNERABILITY_FOUND,
            self._on_vulnerability_found
        )
        
        # 订阅资产发现事件
        self.app.event_bus.subscribe(
            MITMEventType.ASSET_DISCOVERED,
            self._on_asset_discovered
        )
    
    def _on_new_request(self, event: MITMEvent):
        """处理新请求事件"""
        # 这里可以触发其他模块的逻辑
        pass
    
    def _on_new_response(self, event: MITMEvent):
        """处理新响应事件"""
        # 这里可以触发其他模块的逻辑
        pass
    
    def _on_vulnerability_found(self, event: MITMEvent):
        """处理漏洞发现事件"""
        # 这里可以触发漏洞管理模块的逻辑
        pass
    
    def _on_asset_discovered(self, event: MITMEvent):
        """处理资产发现事件"""
        # 这里可以触发资产管理模块的逻辑
        pass
    
    def get_integration_status(self) -> Dict[str, Any]:
        """获取集成状态"""
        return {
            'app_interface': self.app.get_status(),
            'event_subscriptions': len(self.app.event_bus._subscribers),
            'event_history_count': len(self.app.event_bus._event_history),
        }
