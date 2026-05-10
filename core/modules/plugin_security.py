"""
插件安全机制模块
包含权限检查、代码签名、行为监控
"""

import os
import sys
import json
import logging
import hashlib
import threading
from pathlib import Path
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

logger = logging.getLogger(__name__)


class ThreatLevel(Enum):
    """威胁级别"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class SecurityAlert:
    """安全告警"""
    alert_id: str
    timestamp: datetime
    threat_level: ThreatLevel
    alert_type: str
    description: str
    plugin_id: str = ""
    details: Dict[str, Any] = field(default_factory=dict)


class PermissionChecker:
    """权限检查器"""
    
    def __init__(self):
        self._permissions: Dict[str, Set[str]] = {}
        self._lock = threading.RLock()
    
    def grant_permission(self, plugin_id: str, permission: str):
        """授予权限"""
        with self._lock:
            if plugin_id not in self._permissions:
                self._permissions[plugin_id] = set()
            self._permissions[plugin_id].add(permission)
    
    def revoke_permission(self, plugin_id: str, permission: str):
        """撤销权限"""
        with self._lock:
            if plugin_id in self._permissions:
                self._permissions[plugin_id].discard(permission)
    
    def check_permission(self, plugin_id: str, permission: str) -> bool:
        """检查权限"""
        with self._lock:
            return permission in self._permissions.get(plugin_id, set())
    
    def get_permissions(self, plugin_id: str) -> Set[str]:
        """获取权限列表"""
        with self._lock:
            return self._permissions.get(plugin_id, set()).copy()
    
    def clear_permissions(self, plugin_id: str):
        """清除权限"""
        with self._lock:
            self._permissions.pop(plugin_id, None)


class CodeSigner:
    """代码签名器"""
    
    def __init__(self, key_dir: str = None):
        self.key_dir = Path(key_dir) if key_dir else Path(__file__).parent.parent.parent / "config" / "keys"
        self.key_dir.mkdir(parents=True, exist_ok=True)
    
    def sign_plugin(self, plugin_path: str, private_key_path: str = None) -> str:
        """签名插件"""
        try:
            with open(plugin_path, "rb") as f:
                content = f.read()
            
            checksum = hashlib.sha256(content).hexdigest()
            
            signature_file = Path(plugin_path).with_suffix(".sig")
            with open(signature_file, "w") as f:
                f.write(checksum)
            
            logger.info(f"插件签名成功: {plugin_path}")
            return checksum
        
        except Exception as e:
            logger.error(f"插件签名失败: {e}")
            return ""
    
    def verify_plugin(self, plugin_path: str) -> bool:
        """验证插件签名"""
        try:
            signature_file = Path(plugin_path).with_suffix(".sig")
            if not signature_file.exists():
                logger.warning(f"插件无签名: {plugin_path}")
                return False
            
            with open(signature_file, "r") as f:
                expected_checksum = f.read().strip()
            
            with open(plugin_path, "rb") as f:
                content = f.read()
            
            actual_checksum = hashlib.sha256(content).hexdigest()
            
            return actual_checksum == expected_checksum
        
        except Exception as e:
            logger.error(f"插件验证失败: {e}")
            return False


class BehaviorMonitor:
    """行为监控器"""
    
    def __init__(self):
        self._alerts: List[SecurityAlert] = []
        self._blocked_actions: List[Dict[str, Any]] = []
        self._lock = threading.RLock()
        self._alert_counter = 0
    
    def record_action(self, plugin_id: str, action: str, details: Dict[str, Any] = None) -> bool:
        """记录行为"""
        with self._lock:
            self._alert_counter += 1
            alert = SecurityAlert(
                alert_id=f"alert_{self._alert_counter}",
                timestamp=datetime.now(),
                threat_level=ThreatLevel.LOW,
                alert_type=action,
                description=f"插件 {plugin_id} 执行操作: {action}",
                plugin_id=plugin_id,
                details=details or {}
            )
            self._alerts.append(alert)
            return True
    
    def block_action(self, plugin_id: str, action: str, reason: str, details: Dict[str, Any] = None):
        """阻止行为"""
        with self._lock:
            self._alert_counter += 1
            alert = SecurityAlert(
                alert_id=f"alert_{self._alert_counter}",
                timestamp=datetime.now(),
                threat_level=ThreatLevel.HIGH,
                alert_type=f"blocked_{action}",
                description=f"插件 {plugin_id} 被阻止: {reason}",
                plugin_id=plugin_id,
                details=details or {}
            )
            self._alerts.append(alert)
            
            self._blocked_actions.append({
                "plugin_id": plugin_id,
                "action": action,
                "reason": reason,
                "timestamp": datetime.now()
            })
            
            logger.warning(f"阻止插件行为: {plugin_id} - {action} - {reason}")
    
    def get_alerts(self, limit: int = 100, plugin_id: str = None) -> List[SecurityAlert]:
        """获取告警"""
        with self._lock:
            alerts = self._alerts.copy()
        
        if plugin_id:
            alerts = [a for a in alerts if a.plugin_id == plugin_id]
        
        return alerts[-limit:]
    
    def get_blocked_actions(self, limit: int = 100) -> List[Dict[str, Any]]:
        """获取被阻止的行为"""
        with self._lock:
            return self._blocked_actions[-limit:]
    
    def clear_alerts(self):
        """清除告警"""
        with self._lock:
            self._alerts.clear()
            self._blocked_actions.clear()
    
    def get_statistics(self) -> Dict[str, Any]:
        """获取统计"""
        with self._lock:
            return {
                "total_alerts": len(self._alerts),
                "total_blocked": len(self._blocked_actions),
                "high_threats": sum(1 for a in self._alerts if a.threat_level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL])
            }


class SecurityManager:
    """安全管理器"""
    
    def __init__(self):
        self.permission_checker = PermissionChecker()
        self.code_signer = CodeSigner()
        self.behavior_monitor = BehaviorMonitor()
    
    def initialize_plugin_security(self, plugin_id: str, permissions: List[str]):
        """初始化插件安全"""
        for perm in permissions:
            self.permission_checker.grant_permission(plugin_id, perm)
        
        logger.info(f"插件安全初始化完成: {plugin_id}")
    
    def check_and_record(self, plugin_id: str, action: str, details: Dict[str, Any] = None) -> bool:
        """检查并记录行为"""
        if not self.permission_checker.check_permission(plugin_id, action):
            self.behavior_monitor.block_action(
                plugin_id, action,
                f"权限不足: {action}",
                details
            )
            return False
        
        self.behavior_monitor.record_action(plugin_id, action, details)
        return True
    
    def get_security_report(self, plugin_id: str = None) -> Dict[str, Any]:
        """获取安全报告"""
        return {
            "alerts": self.behavior_monitor.get_alerts(plugin_id=plugin_id),
            "blocked": self.behavior_monitor.get_blocked_actions(),
            "statistics": self.behavior_monitor.get_statistics()
        }
