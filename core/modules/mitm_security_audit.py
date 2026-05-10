"""
MITM代理安全与审计模块
访问控制、敏感数据保护、操作审计、一键清理
"""

import os
import json
import hashlib
import logging
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class AuditLog:
    """审计日志"""
    id: str
    timestamp: datetime
    user: str
    action: str
    target: str
    details: Dict[str, Any] = field(default_factory=dict)
    ip_address: str = ""


@dataclass
class AccessRule:
    """访问规则"""
    id: str
    rule_type: str  # ip_whitelist, ip_blacklist, auth
    value: str
    enabled: bool = True
    description: str = ""


class AccessController:
    """访问控制器"""
    
    def __init__(self):
        self._ip_whitelist: Set[str] = set()
        self._ip_blacklist: Set[str] = set()
        self._auth_enabled = False
        self._auth_credentials: Dict[str, str] = {}  # username -> password_hash
        self._rules: List[AccessRule] = []
    
    def add_ip_whitelist(self, ip: str, description: str = ""):
        """添加IP白名单"""
        self._ip_whitelist.add(ip)
        rule = AccessRule(
            id=f"wl_{len(self._ip_whitelist)}",
            rule_type="ip_whitelist",
            value=ip,
            description=description
        )
        self._rules.append(rule)
        logger.info(f"IP白名单已添加: {ip}")
    
    def remove_ip_whitelist(self, ip: str):
        """移除IP白名单"""
        self._ip_whitelist.discard(ip)
        self._rules = [r for r in self._rules if not (r.rule_type == "ip_whitelist" and r.value == ip)]
        logger.info(f"IP白名单已移除: {ip}")
    
    def add_ip_blacklist(self, ip: str, description: str = ""):
        """添加IP黑名单"""
        self._ip_blacklist.add(ip)
        rule = AccessRule(
            id=f"bl_{len(self._ip_blacklist)}",
            rule_type="ip_blacklist",
            value=ip,
            description=description
        )
        self._rules.append(rule)
        logger.info(f"IP黑名单已添加: {ip}")
    
    def remove_ip_blacklist(self, ip: str):
        """移除IP黑名单"""
        self._ip_blacklist.discard(ip)
        self._rules = [r for r in self._rules if not (r.rule_type == "ip_blacklist" and r.value == ip)]
        logger.info(f"IP黑名单已移除: {ip}")
    
    def enable_auth(self, username: str, password: str):
        """启用认证"""
        self._auth_enabled = True
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        self._auth_credentials[username] = password_hash
        logger.info(f"认证已启用: {username}")
    
    def disable_auth(self):
        """禁用认证"""
        self._auth_enabled = False
        self._auth_credentials.clear()
        logger.info("认证已禁用")
    
    def check_access(self, ip: str, username: Optional[str] = None, 
                    password: Optional[str] = None) -> bool:
        """检查访问权限"""
        # 检查黑名单
        if ip in self._ip_blacklist:
            logger.warning(f"访问被拒绝（黑名单）: {ip}")
            return False
        
        # 检查白名单（如果设置了）
        if self._ip_whitelist and ip not in self._ip_whitelist:
            logger.warning(f"访问被拒绝（不在白名单）: {ip}")
            return False
        
        # 检查认证
        if self._auth_enabled:
            if not username or not password:
                logger.warning(f"访问被拒绝（需要认证）: {ip}")
                return False
            
            password_hash = hashlib.sha256(password.encode()).hexdigest()
            stored_hash = self._auth_credentials.get(username)
            
            if not stored_hash or stored_hash != password_hash:
                logger.warning(f"访问被拒绝（认证失败）: {ip}, 用户: {username}")
                return False
        
        return True
    
    def get_rules(self) -> List[AccessRule]:
        """获取所有规则"""
        return self._rules
    
    def get_statistics(self) -> Dict[str, Any]:
        """获取统计信息"""
        return {
            'whitelist_count': len(self._ip_whitelist),
            'blacklist_count': len(self._ip_blacklist),
            'auth_enabled': self._auth_enabled,
            'auth_users': len(self._auth_credentials),
        }


class SensitiveDataProtector:
    """敏感数据保护器"""
    
    def __init__(self):
        self._sensitive_patterns = [
            'password', 'passwd', 'pwd',
            'token', 'access_token', 'refresh_token',
            'api_key', 'apikey', 'api_secret',
            'secret', 'secret_key',
            'authorization', 'auth',
            'cookie', 'session',
            'credit_card', 'card_number',
            'ssn', 'social_security',
            'private_key', 'privatekey',
        ]
        
        self._mask_char = '*'
        self._mask_length = 4  # 保留的字符数
    
    def mask_sensitive_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """模糊化敏感数据"""
        masked = {}
        
        for key, value in data.items():
            key_lower = key.lower()
            
            # 检查是否是敏感字段
            if any(pattern in key_lower for pattern in self._sensitive_patterns):
                if isinstance(value, str):
                    masked[key] = self._mask_string(value)
                else:
                    masked[key] = '[REDACTED]'
            else:
                masked[key] = value
        
        return masked
    
    def mask_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        """模糊化请求头"""
        return self.mask_sensitive_data(headers)
    
    def mask_body(self, body: str, content_type: str = "") -> str:
        """模糊化请求/响应体"""
        if 'application/json' in content_type:
            try:
                data = json.loads(body)
                masked_data = self.mask_sensitive_data(data)
                return json.dumps(masked_data, indent=2)
            except json.JSONDecodeError:
                pass
        
        # 对于非JSON，检查敏感模式
        for pattern in self._sensitive_patterns:
            if pattern in body.lower():
                return '[SENSITIVE DATA REDACTED]'
        
        return body
    
    def _mask_string(self, value: str) -> str:
        """模糊化字符串"""
        if len(value) <= self._mask_length:
            return self._mask_char * len(value)
        
        return value[:self._mask_length] + self._mask_char * (len(value) - self._mask_length)
    
    def add_pattern(self, pattern: str):
        """添加敏感模式"""
        if pattern not in self._sensitive_patterns:
            self._sensitive_patterns.append(pattern)
    
    def get_patterns(self) -> List[str]:
        """获取所有敏感模式"""
        return self._sensitive_patterns


class AuditLogger:
    """审计日志器"""
    
    def __init__(self, log_file: str = "data/mitm_audit.log"):
        self.log_file = Path(log_file)
        self.log_file.parent.mkdir(parents=True, exist_ok=True)
        
        self._logs: List[AuditLog] = []
        self._max_logs = 10000  # 内存中最大日志数
    
    def log(self, user: str, action: str, target: str, 
            details: Dict[str, Any] = None, ip_address: str = ""):
        """记录审计日志"""
        import uuid
        
        log_entry = AuditLog(
            id=str(uuid.uuid4())[:12],
            timestamp=datetime.utcnow(),
            user=user,
            action=action,
            target=target,
            details=details or {},
            ip_address=ip_address
        )
        
        self._logs.append(log_entry)
        
        # 限制内存中的日志数
        if len(self._logs) > self._max_logs:
            self._logs = self._logs[-self._max_logs:]
        
        # 写入文件
        self._write_to_file(log_entry)
        
        logger.info(f"审计日志: [{user}] {action} -> {target}")
    
    def get_logs(self, user: Optional[str] = None, 
                 action: Optional[str] = None,
                 start_time: Optional[datetime] = None,
                 end_time: Optional[datetime] = None,
                 limit: int = 100) -> List[AuditLog]:
        """获取审计日志"""
        filtered = self._logs
        
        if user:
            filtered = [l for l in filtered if l.user == user]
        
        if action:
            filtered = [l for l in filtered if action.lower() in l.action.lower()]
        
        if start_time:
            filtered = [l for l in filtered if l.timestamp >= start_time]
        
        if end_time:
            filtered = [l for l in filtered if l.timestamp <= end_time]
        
        return filtered[-limit:]
    
    def export_logs(self, output_file: str = "audit_export.json"):
        """导出审计日志"""
        logs_data = []
        for log in self._logs:
            logs_data.append({
                'id': log.id,
                'timestamp': log.timestamp.isoformat(),
                'user': log.user,
                'action': log.action,
                'target': log.target,
                'details': log.details,
                'ip_address': log.ip_address,
            })
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(logs_data, f, indent=2, ensure_ascii=False)
        
        logger.info(f"审计日志已导出: {output_file}")
        return output_file
    
    def _write_to_file(self, log_entry: AuditLog):
        """写入日志文件"""
        try:
            with open(self.log_file, 'a', encoding='utf-8') as f:
                log_line = json.dumps({
                    'id': log_entry.id,
                    'timestamp': log_entry.timestamp.isoformat(),
                    'user': log_entry.user,
                    'action': log_entry.action,
                    'target': log_entry.target,
                    'details': log_entry.details,
                    'ip_address': log_entry.ip_address,
                }, ensure_ascii=False)
                f.write(log_line + '\n')
        except Exception as e:
            logger.error(f"写入审计日志失败: {e}")
    
    def get_statistics(self) -> Dict[str, Any]:
        """获取统计信息"""
        actions = {}
        users = set()
        
        for log in self._logs:
            actions[log.action] = actions.get(log.action, 0) + 1
            users.add(log.user)
        
        return {
            'total_logs': len(self._logs),
            'unique_users': len(users),
            'actions': actions,
        }


class DataCleaner:
    """数据清理器"""
    
    def __init__(self):
        self._cleanup_callbacks = []
    
    def register_callback(self, callback, name: str):
        """注册清理回调"""
        self._cleanup_callbacks.append({
            'callback': callback,
            'name': name,
        })
    
    def cleanup_all(self, include_certs: bool = True, 
                   include_history: bool = True,
                   include_logs: bool = True,
                   include_cache: bool = True) -> Dict[str, bool]:
        """一键清理所有数据"""
        results = {}
        
        logger.info("开始清理所有数据...")
        
        for item in self._cleanup_callbacks:
            try:
                if (include_certs and 'cert' in item['name'].lower()) or \
                   (include_history and 'history' in item['name'].lower()) or \
                   (include_logs and 'log' in item['name'].lower()) or \
                   (include_cache and 'cache' in item['name'].lower()):
                    
                    result = item['callback']()
                    results[item['name']] = result
                    logger.info(f"清理完成: {item['name']}")
            except Exception as e:
                results[item['name']] = False
                logger.error(f"清理失败 [{item['name']}]: {e}")
        
        logger.info("数据清理完成")
        return results
    
    def get_callbacks(self) -> List[str]:
        """获取所有清理回调"""
        return [item['name'] for item in self._cleanup_callbacks]


class SecurityAuditor:
    """安全审计管理器"""
    
    def __init__(self, audit_log_file: str = "data/mitm_audit.log"):
        self.access_controller = AccessController()
        self.sensitive_protector = SensitiveDataProtector()
        self.audit_logger = AuditLogger(audit_log_file)
        self.data_cleaner = DataCleaner()
    
    def log_config_change(self, user: str, config_name: str, 
                         old_value: Any, new_value: Any, ip_address: str = ""):
        """记录配置变更"""
        self.audit_logger.log(
            user=user,
            action="CONFIG_CHANGE",
            target=config_name,
            details={
                'old_value': str(old_value),
                'new_value': str(new_value),
            },
            ip_address=ip_address
        )
    
    def log_intercept_modify(self, user: str, request_id: str, 
                            modifications: Dict[str, Any], ip_address: str = ""):
        """记录拦截修改"""
        self.audit_logger.log(
            user=user,
            action="INTERCEPT_MODIFY",
            target=request_id,
            details=modifications,
            ip_address=ip_address
        )
    
    def cleanup_all(self, **kwargs) -> Dict[str, bool]:
        """一键清理"""
        return self.data_cleaner.cleanup_all(**kwargs)
    
    def get_security_status(self) -> Dict[str, Any]:
        """获取安全状态"""
        return {
            'access_control': self.access_controller.get_statistics(),
            'sensitive_patterns': len(self.sensitive_protector.get_patterns()),
            'audit_logs': self.audit_logger.get_statistics(),
            'cleanup_callbacks': self.data_cleaner.get_callbacks(),
        }
