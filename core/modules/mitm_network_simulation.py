"""
网络环境模拟模块 - 支持弱网环境模拟和移动网络特征模拟
功能：
- 支持模拟弱网环境：设置整体延迟、丢包率、带宽限制
- 支持按域名设置不同的网络条件
- 支持模拟移动网络（3G/4G/5G延迟与带宽特征）
- 网络条件配置可保存为预设，一键切换
"""

import time
import random
import asyncio
import logging
from typing import Dict, List, Any, Optional, Callable
from datetime import datetime
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class NetworkPreset(Enum):
    """网络预设"""
    NORMAL = "normal"
    SLOW_3G = "slow_3g"
    FAST_3G = "fast_3g"
    SLOW_4G = "slow_4g"
    FAST_4G = "fast_4g"
    FIVE_G = "five_g"
    CUSTOM = "custom"


# 移动网络特征参数
MOBILE_NETWORK_PROFILES = {
    NetworkPreset.SLOW_3G: {
        'latency_ms': 400,
        'jitter_ms': 100,
        'packet_loss': 0.10,
        'bandwidth_kbps': 500,
        'description': "慢速3G (EDGE)",
    },
    NetworkPreset.FAST_3G: {
        'latency_ms': 150,
        'jitter_ms': 50,
        'packet_loss': 0.05,
        'bandwidth_kbps': 1500,
        'description': "快速3G (HSPA)",
    },
    NetworkPreset.SLOW_4G: {
        'latency_ms': 70,
        'jitter_ms': 20,
        'packet_loss': 0.02,
        'bandwidth_kbps': 4000,
        'description': "慢速4G (LTE)",
    },
    NetworkPreset.FAST_4G: {
        'latency_ms': 30,
        'jitter_ms': 10,
        'packet_loss': 0.01,
        'bandwidth_kbps': 15000,
        'description': "快速4G (LTE-A)",
    },
    NetworkPreset.FIVE_G: {
        'latency_ms': 10,
        'jitter_ms': 5,
        'packet_loss': 0.001,
        'bandwidth_kbps': 100000,
        'description': "5G",
    },
}


@dataclass
class NetworkCondition:
    """网络条件"""
    id: str
    name: str
    description: str
    latency_ms: float
    jitter_ms: float
    packet_loss: float
    bandwidth_kbps: float
    is_enabled: bool = True
    domain_patterns: List[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class NetworkSimulationStats:
    """网络模拟统计"""
    total_requests: int = 0
    delayed_requests: int = 0
    dropped_requests: int = 0
    total_delay_ms: float = 0.0
    avg_delay_ms: float = 0.0
    last_updated: datetime = field(default_factory=datetime.utcnow)


class NetworkSimulator:
    """网络模拟器"""
    
    def __init__(self):
        self._conditions: Dict[str, NetworkCondition] = {}
        self._domain_conditions: Dict[str, str] = {}  # domain -> condition_id
        self._active_condition_id: Optional[str] = None
        self._stats = NetworkSimulationStats()
        self._callbacks: List[Callable] = []
        
        # 初始化预设
        self._init_presets()
    
    def _init_presets(self):
        """初始化预设网络条件"""
        # 正常网络
        self._conditions['normal'] = NetworkCondition(
            id='normal',
            name='正常网络',
            description='无延迟、无丢包、无带宽限制',
            latency_ms=0,
            jitter_ms=0,
            packet_loss=0,
            bandwidth_kbps=0,  # 0表示无限制
        )
        
        # 移动网络预设
        for preset, profile in MOBILE_NETWORK_PROFILES.items():
            self._conditions[preset.value] = NetworkCondition(
                id=preset.value,
                name=profile['description'],
                description=f"模拟{profile['description']}网络环境",
                latency_ms=profile['latency_ms'],
                jitter_ms=profile['jitter_ms'],
                packet_loss=profile['packet_loss'],
                bandwidth_kbps=profile['bandwidth_kbps'],
            )
    
    def create_custom_condition(self, name: str, description: str,
                                 latency_ms: float, jitter_ms: float,
                                 packet_loss: float, bandwidth_kbps: float,
                                 domain_patterns: List[str] = None) -> NetworkCondition:
        """创建自定义网络条件"""
        condition = NetworkCondition(
            id=str(id(name)),
            name=name,
            description=description,
            latency_ms=latency_ms,
            jitter_ms=jitter_ms,
            packet_loss=packet_loss,
            bandwidth_kbps=bandwidth_kbps,
            domain_patterns=domain_patterns or [],
        )
        
        self._conditions[condition.id] = condition
        return condition
    
    def set_active_condition(self, condition_id: str):
        """设置当前激活的网络条件"""
        if condition_id in self._conditions:
            self._active_condition_id = condition_id
            self._notify_condition_changed(condition_id)
        else:
            logger.error(f"网络条件不存在: {condition_id}")
    
    def set_domain_condition(self, domain: str, condition_id: str):
        """为域名设置特定网络条件"""
        if condition_id in self._conditions:
            self._domain_conditions[domain] = condition_id
        else:
            logger.error(f"网络条件不存在: {condition_id}")
    
    def get_condition_for_domain(self, domain: str) -> NetworkCondition:
        """获取域名对应的网络条件"""
        # 检查是否有特定域名条件
        if domain in self._domain_conditions:
            condition_id = self._domain_conditions[domain]
            return self._conditions.get(condition_id, self._get_active_condition())
        
        # 检查域名模式匹配
        for condition in self._conditions.values():
            if condition.domain_patterns:
                for pattern in condition.domain_patterns:
                    if pattern in domain:
                        return condition
        
        return self._get_active_condition()
    
    async def simulate_network(self, domain: str = "", 
                                data_size: int = 0) -> Dict[str, Any]:
        """模拟网络环境"""
        condition = self.get_condition_for_domain(domain)
        
        if not condition.is_enabled:
            return {'delayed': False, 'dropped': False}
        
        result = {
            'delayed': False,
            'dropped': False,
            'delay_ms': 0,
            'condition': condition.name,
        }
        
        # 更新统计
        self._stats.total_requests += 1
        
        # 模拟丢包
        if condition.packet_loss > 0:
            if random.random() < condition.packet_loss:
                result['dropped'] = True
                self._stats.dropped_requests += 1
                return result
        
        # 模拟延迟
        if condition.latency_ms > 0:
            # 计算实际延迟（基础延迟 + 随机抖动）
            jitter = random.uniform(-condition.jitter_ms, condition.jitter_ms)
            actual_delay = max(0, condition.latency_ms + jitter)
            
            result['delayed'] = True
            result['delay_ms'] = actual_delay
            
            # 应用延迟
            await asyncio.sleep(actual_delay / 1000.0)
            
            self._stats.delayed_requests += 1
            self._stats.total_delay_ms += actual_delay
            self._stats.avg_delay_ms = (
                self._stats.total_delay_ms / self._stats.delayed_requests
                if self._stats.delayed_requests > 0 else 0
            )
        
        # 模拟带宽限制
        if condition.bandwidth_kbps > 0 and data_size > 0:
            # 计算传输时间
            bandwidth_bytes_per_ms = (condition.bandwidth_kbps * 1024) / 8 / 1000
            transfer_time_ms = data_size / bandwidth_bytes_per_ms
            
            if transfer_time_ms > 0:
                await asyncio.sleep(transfer_time_ms / 1000.0)
                result['delay_ms'] += transfer_time_ms
        
        self._stats.last_updated = datetime.utcnow()
        return result
    
    def get_presets(self) -> List[NetworkCondition]:
        """获取所有预设"""
        return [
            self._conditions['normal'],
            self._conditions.get('slow_3g'),
            self._conditions.get('fast_3g'),
            self._conditions.get('slow_4g'),
            self._conditions.get('fast_4g'),
            self._conditions.get('five_g'),
        ]
    
    def get_custom_conditions(self) -> List[NetworkCondition]:
        """获取自定义条件"""
        preset_ids = {'normal', 'slow_3g', 'fast_3g', 'slow_4g', 'fast_4g', 'five_g'}
        return [c for c in self._conditions.values() if c.id not in preset_ids]
    
    def get_all_conditions(self) -> List[NetworkCondition]:
        """获取所有条件"""
        return list(self._conditions.values())
    
    def get_active_condition(self) -> Optional[NetworkCondition]:
        """获取当前激活的条件"""
        return self._get_active_condition()
    
    def get_stats(self) -> NetworkSimulationStats:
        """获取统计信息"""
        return self._stats
    
    def reset_stats(self):
        """重置统计"""
        self._stats = NetworkSimulationStats()
    
    def on_condition_changed(self, callback: Callable):
        """注册条件变更回调"""
        self._callbacks.append(callback)
    
    def _get_active_condition(self) -> NetworkCondition:
        """获取当前激活的条件"""
        if self._active_condition_id and self._active_condition_id in self._conditions:
            return self._conditions[self._active_condition_id]
        return self._conditions['normal']
    
    def _notify_condition_changed(self, condition_id: str):
        """通知条件变更"""
        for callback in self._callbacks:
            try:
                callback(condition_id)
            except Exception as e:
                logger.error(f"条件变更通知失败: {e}")


class NetworkEnvironmentManager:
    """网络环境管理器"""
    
    def __init__(self):
        self.simulator = NetworkSimulator()
        self._presets: Dict[str, Dict[str, Any]] = {}
    
    def apply_preset(self, preset: NetworkPreset):
        """应用预设"""
        self.simulator.set_active_condition(preset.value)
    
    def create_preset(self, name: str, condition: NetworkCondition):
        """保存自定义预设为快捷配置"""
        self._presets[name] = {
            'name': condition.name,
            'description': condition.description,
            'latency_ms': condition.latency_ms,
            'jitter_ms': condition.jitter_ms,
            'packet_loss': condition.packet_loss,
            'bandwidth_kbps': condition.bandwidth_kbps,
            'domain_patterns': condition.domain_patterns,
        }
    
    def get_presets(self) -> Dict[str, Dict[str, Any]]:
        """获取所有预设"""
        return self._presets
    
    async def simulate_request(self, url: str, data_size: int = 0) -> Dict[str, Any]:
        """模拟请求网络环境"""
        from urllib.parse import urlparse
        parsed = urlparse(url)
        domain = parsed.hostname or ""
        
        return await self.simulator.simulate_network(domain, data_size)
    
    def get_current_profile(self) -> Dict[str, Any]:
        """获取当前网络配置"""
        condition = self.simulator.get_active_condition()
        return {
            'name': condition.name,
            'description': condition.description,
            'latency_ms': condition.latency_ms,
            'jitter_ms': condition.jitter_ms,
            'packet_loss': condition.packet_loss,
            'bandwidth_kbps': condition.bandwidth_kbps,
        }
