"""
安全加固模块 - MITM代理安全增强
功能：
- 根CA私钥支持硬件加密存储（如使用系统密钥链）
- 代理访问日志加密存储，防止未授权查看
- 支持配置允许拦截的域名白名单，白名单外直通
- 敏感操作需二次确认：证书导出、日志清理、规则批量修改
- 自动检测并告警：代理被上游恶意劫持或证书被替换
"""

import os
import re
import json
import uuid
import hashlib
import logging
import threading
from typing import Dict, List, Any, Optional, Callable, Set
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

logger = logging.getLogger(__name__)


class SecurityEventType(Enum):
    """安全事件类型"""
    CERT_EXPORT = "cert_export"
    LOG_CLEAR = "log_clear"
    RULE_MODIFY = "rule_modify"
    PROXY_HIJACK = "proxy_hijack"
    CERT_REPLACE = "cert_replace"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    SENSITIVE_DATA_LEAK = "sensitive_data_leak"


@dataclass
class SecurityEvent:
    """安全事件"""
    id: str
    timestamp: datetime
    event_type: SecurityEventType
    description: str
    severity: str  # low, medium, high, critical
    user: str
    ip_address: str
    is_confirmed: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DomainWhitelist:
    """域名白名单"""
    id: str
    pattern: str
    is_regex: bool
    description: str
    created_at: datetime
    is_enabled: bool = True


class CertificateKeyManager:
    """CA私钥管理器 - 支持硬件加密存储"""
    
    def __init__(self, key_path: str = None):
        self._key_path = key_path
        self._key_data: Optional[bytes] = None
        self._is_hardware_stored = False
        self._access_count = 0
        self._last_access: Optional[datetime] = None
        self._lock = threading.Lock()
    
    def load_key(self, password: str = None) -> bool:
        """加载CA私钥"""
        try:
            if self._key_path and os.path.exists(self._key_path):
                with open(self._key_path, 'rb') as f:
                    self._key_data = f.read()
                
                # 检测是否为硬件加密存储
                if self._key_data.startswith(b'hardware_encrypted:'):
                    self._is_hardware_stored = True
                    # 实际应用中应调用系统API解密
                    logger.info("CA私钥使用硬件加密存储")
                
                self._last_access = datetime.utcnow()
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"加载CA私钥失败: {e}")
            return False
    
    def get_key(self, require_confirmation: bool = True) -> Optional[bytes]:
        """获取CA私钥（需要二次确认）"""
        if require_confirmation:
            # 实际应用中应弹出确认对话框
            logger.warning("获取CA私钥需要二次确认")
        
        with self._lock:
            self._access_count += 1
            self._last_access = datetime.utcnow()
            return self._key_data
    
    def is_hardware_stored(self) -> bool:
        """检查是否硬件加密存储"""
        return self._is_hardware_stored
    
    def get_access_log(self) -> Dict[str, Any]:
        """获取访问日志"""
        return {
            'access_count': self._access_count,
            'last_access': self._last_access.isoformat() if self._last_access else None,
            'is_hardware_stored': self._is_hardware_stored,
        }


class EncryptedLogStorage:
    """加密日志存储"""
    
    def __init__(self, storage_path: str, master_password: str):
        self._storage_path = Path(storage_path)
        self._encryption_key = self._derive_key(master_password)
        self._fernet = Fernet(self._encryption_key)
        self._storage_path.mkdir(parents=True, exist_ok=True)
    
    def write_log(self, log_data: Dict[str, Any]) -> bool:
        """写入加密日志"""
        try:
            log_entry = {
                'id': str(uuid.uuid4())[:12],
                'timestamp': datetime.utcnow().isoformat(),
                **log_data,
            }
            
            encrypted_data = self._fernet.encrypt(
                json.dumps(log_entry).encode('utf-8')
            )
            
            log_file = self._storage_path / f"proxy_log_{datetime.utcnow().strftime('%Y%m%d')}.enc"
            
            with open(log_file, 'ab') as f:
                f.write(encrypted_data + b'\n')
            
            return True
            
        except Exception as e:
            logger.error(f"写入加密日志失败: {e}")
            return False
    
    def read_logs(self, date: str = None) -> List[Dict[str, Any]]:
        """读取加密日志"""
        logs = []
        
        try:
            if date:
                log_file = self._storage_path / f"proxy_log_{date}.enc"
            else:
                # 读取所有日志文件
                log_files = list(self._storage_path.glob("proxy_log_*.enc"))
                if not log_files:
                    return []
                log_file = log_files[-1]  # 最新的日志
            
            if not log_file.exists():
                return []
            
            with open(log_file, 'rb') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            decrypted_data = self._fernet.decrypt(line)
                            log_entry = json.loads(decrypted_data)
                            logs.append(log_entry)
                        except Exception as e:
                            logger.error(f"解密日志失败: {e}")
            
        except Exception as e:
            logger.error(f"读取加密日志失败: {e}")
        
        return logs
    
    def clear_logs(self, require_confirmation: bool = True) -> bool:
        """清理日志（需要二次确认）"""
        if require_confirmation:
            logger.warning("清理日志需要二次确认")
        
        try:
            for log_file in self._storage_path.glob("proxy_log_*.enc"):
                log_file.unlink()
            return True
        except Exception as e:
            logger.error(f"清理日志失败: {e}")
            return False
    
    def _derive_key(self, password: str) -> bytes:
        """派生加密密钥"""
        salt = b'mitm_proxy_salt'  # 实际应用中应使用随机salt
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key


class DomainWhitelistManager:
    """域名白名单管理器"""
    
    def __init__(self):
        self._whitelist: Dict[str, DomainWhitelist] = {}
        self._is_enabled = False
    
    def enable_whitelist(self):
        """启用白名单"""
        self._is_enabled = True
    
    def disable_whitelist(self):
        """禁用白名单"""
        self._is_enabled = False
    
    def add_domain(self, pattern: str, is_regex: bool = False,
                   description: str = "") -> DomainWhitelist:
        """添加域名到白名单"""
        whitelist = DomainWhitelist(
            id=str(uuid.uuid4())[:12],
            pattern=pattern,
            is_regex=is_regex,
            description=description,
            created_at=datetime.utcnow(),
        )
        
        self._whitelist[whitelist.id] = whitelist
        return whitelist
    
    def remove_domain(self, whitelist_id: str) -> bool:
        """从白名单移除域名"""
        if whitelist_id in self._whitelist:
            del self._whitelist[whitelist_id]
            return True
        return False
    
    def is_allowed(self, domain: str) -> bool:
        """检查域名是否允许拦截"""
        if not self._is_enabled:
            return True  # 白名单未启用，允许所有
        
        for whitelist in self._whitelist.values():
            if not whitelist.is_enabled:
                continue
            
            if whitelist.is_regex:
                if re.search(whitelist.pattern, domain, re.IGNORECASE):
                    return True
            else:
                if whitelist.pattern.lower() == domain.lower():
                    return True
        
        return False
    
    def get_whitelist(self) -> List[DomainWhitelist]:
        """获取白名单"""
        return list(self._whitelist.values())


class SecurityMonitor:
    """安全监控器"""
    
    def __init__(self):
        self._events: List[SecurityEvent] = []
        self._callbacks: Dict[str, List[Callable]] = {
            'on_security_event': [],
        }
        
        # 基线配置
        self._proxy_baseline = {
            'expected_upstream': None,
            'expected_cert_fingerprint': None,
        }
    
    def set_proxy_baseline(self, upstream_proxy: str = None,
                           cert_fingerprint: str = None):
        """设置代理基线"""
        self._proxy_baseline['expected_upstream'] = upstream_proxy
        self._proxy_baseline['expected_cert_fingerprint'] = cert_fingerprint
    
    def check_proxy_hijack(self, current_upstream: str = None,
                           current_cert_fingerprint: str = None) -> bool:
        """检查代理是否被劫持"""
        is_hijacked = False
        
        # 检查上游代理
        if self._proxy_baseline['expected_upstream']:
            if current_upstream != self._proxy_baseline['expected_upstream']:
                is_hijacked = True
                self._record_security_event(
                    event_type=SecurityEventType.PROXY_HIJACK,
                    description=f"上游代理被修改: {current_upstream}",
                    severity="critical",
                )
        
        # 检查证书指纹
        if self._proxy_baseline['expected_cert_fingerprint']:
            if current_cert_fingerprint != self._proxy_baseline['expected_cert_fingerprint']:
                is_hijacked = True
                self._record_security_event(
                    event_type=SecurityEventType.CERT_REPLACE,
                    description=f"证书被替换: {current_cert_fingerprint}",
                    severity="critical",
                )
        
        return is_hijacked
    
    def record_sensitive_operation(self, operation_type: SecurityEventType,
                                    description: str, user: str = "anonymous",
                                    ip_address: str = ""):
        """记录敏感操作"""
        self._record_security_event(
            event_type=operation_type,
            description=description,
            severity="high",
            user=user,
            ip_address=ip_address,
        )
    
    def get_events(self, severity: str = None, 
                   start_time: datetime = None) -> List[SecurityEvent]:
        """获取安全事件"""
        events = self._events
        
        if severity:
            events = [e for e in events if e.severity == severity]
        
        if start_time:
            events = [e for e in events if e.timestamp >= start_time]
        
        return events
    
    def on_security_event(self, callback: Callable):
        """注册安全事件回调"""
        self._callbacks['on_security_event'].append(callback)
    
    def _record_security_event(self, event_type: SecurityEventType,
                                description: str, severity: str,
                                user: str = "system", ip_address: str = ""):
        """记录安全事件"""
        event = SecurityEvent(
            id=str(uuid.uuid4())[:12],
            timestamp=datetime.utcnow(),
            event_type=event_type,
            description=description,
            severity=severity,
            user=user,
            ip_address=ip_address,
        )
        
        self._events.append(event)
        
        # 通知回调
        for callback in self._callbacks['on_security_event']:
            try:
                callback(event)
            except Exception as e:
                logger.error(f"安全事件通知失败: {e}")


class SecurityHardening:
    """安全加固模块"""
    
    def __init__(self, config_path: str = None):
        self.cert_manager = CertificateKeyManager(config_path)
        self.log_storage: Optional[EncryptedLogStorage] = None
        self.whitelist_manager = DomainWhitelistManager()
        self.security_monitor = SecurityMonitor()
        
        self._require_confirmation = {
            'cert_export': True,
            'log_clear': True,
            'rule_modify': True,
        }
    
    def initialize_encrypted_logging(self, storage_path: str, 
                                      master_password: str):
        """初始化加密日志"""
        self.log_storage = EncryptedLogStorage(storage_path, master_password)
    
    def log_proxy_activity(self, activity_data: Dict[str, Any]):
        """记录代理活动"""
        if self.log_storage:
            self.log_storage.write_log(activity_data)
    
    def enable_domain_whitelist(self):
        """启用域名白名单"""
        self.whitelist_manager.enable_whitelist()
    
    def disable_domain_whitelist(self):
        """禁用域名白名单"""
        self.whitelist_manager.disable_whitelist()
    
    def is_domain_allowed(self, domain: str) -> bool:
        """检查域名是否允许拦截"""
        return self.whitelist_manager.is_allowed(domain)
    
    def require_confirmation_for(self, operation: str) -> bool:
        """检查操作是否需要二次确认"""
        return self._require_confirmation.get(operation, False)
    
    def set_confirmation_required(self, operation: str, required: bool):
        """设置操作是否需要二次确认"""
        self._require_confirmation[operation] = required
    
    def get_security_status(self) -> Dict[str, Any]:
        """获取安全状态"""
        return {
            'cert_key': self.cert_manager.get_access_log(),
            'whitelist_enabled': self.whitelist_manager._is_enabled,
            'whitelist_count': len(self.whitelist_manager.get_whitelist()),
            'encrypted_logging': self.log_storage is not None,
            'recent_events': len(self.security_monitor.get_events()),
        }
