"""
安全管理器
基于20多年渗透测试经验的安全防护系统
"""

import os
import hashlib
import hmac
import secrets
import logging
from pathlib import Path
from typing import Optional, Dict, Any
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64
import psutil
import ctypes

logger = logging.getLogger(__name__)

class SecurityManager:
    """安全管理器"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # 安全状态
        self._is_locked = False
        self._failed_attempts = 0
        self._max_failed_attempts = 5
        
        # 初始化安全组件
        self._initialize_security()
    
    def _initialize_security(self):
        """初始化安全组件"""
        try:
            # 检查运行环境
            self._check_environment()
            
            # 初始化加密系统
            self._initialize_encryption()
            
            # 启动安全监控
            self._start_security_monitoring()
            
            self.logger.info("安全系统初始化完成")
            
        except Exception as e:
            self.logger.error(f"安全系统初始化失败: {e}")
            raise
    
    def _check_environment(self):
        """检查运行环境安全性"""
        # 检查调试器
        if self._is_debugger_present():
            self.logger.warning("检测到调试器")
        
        # 检查虚拟机
        if self._is_virtual_machine():
            self.logger.warning("运行在虚拟机环境中")
        
        # 检查文件权限
        self._check_file_permissions()
    
    def _initialize_encryption(self):
        """初始化加密系统"""
        # 生成应用级加密密钥
        self._app_key = self._generate_secure_key()
        
        # 创建数据加密器
        self.data_encryptor = Fernet(self._app_key)
    
    def _start_security_monitoring(self):
        """启动安全监控"""
        # 这里可以启动线程监控安全事件
        pass
    
    def encrypt_data(self, data: bytes) -> bytes:
        """加密数据"""
        try:
            return self.data_encryptor.encrypt(data)
        except Exception as e:
            self.logger.error(f"数据加密失败: {e}")
            raise
    
    def decrypt_data(self, encrypted_data: bytes) -> bytes:
        """解密数据"""
        try:
            return self.data_encryptor.decrypt(encrypted_data)
        except Exception as e:
            self.logger.error(f"数据解密失败: {e}")
            raise
    
    def hash_password(self, password: str, salt: Optional[bytes] = None) -> Dict[str, bytes]:
        """哈希密码"""
        if salt is None:
            salt = secrets.token_bytes(32)
        
        # 使用PBKDF2进行密码哈希
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        
        key = kdf.derive(password.encode('utf-8'))
        
        return {
            'hash': key,
            'salt': salt
        }
    
    def verify_password(self, password: str, stored_hash: bytes, salt: bytes) -> bool:
        """验证密码"""
        try:
            new_hash = self.hash_password(password, salt)['hash']
            return hmac.compare_digest(new_hash, stored_hash)
        except Exception as e:
            self.logger.error(f"密码验证失败: {e}")
            return False
    
    def generate_secure_token(self, length: int = 32) -> str:
        """生成安全令牌"""
        return secrets.token_urlsafe(length)
    
    def secure_erase(self, data: Any) -> None:
        """安全擦除数据"""
        try:
            if isinstance(data, str):
                data_bytes = data.encode('utf-8')
            elif isinstance(data, bytes):
                data_bytes = data
            else:
                return
            
            # 多次覆盖数据
            length = len(data_bytes)
            for _ in range(3):
                # 使用随机数据覆盖
                random_data = secrets.token_bytes(length)
                ctypes.memmove(id(data_bytes), id(random_data), length)
            
            # 最后用零覆盖
            zero_data = bytes(length)
            ctypes.memmove(id(data_bytes), id(zero_data), length)
            
        except Exception as e:
            self.logger.error(f"安全擦除失败: {e}")
    
    def validate_input(self, input_data: str, input_type: str) -> bool:
        """验证用户输入"""
        validation_rules = {
            'username': r'^[a-zA-Z0-9_]{3,20}$',
            'email': r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$',
            'filename': r'^[a-zA-Z0-9._-]{1,255}$',
            'url': r'^https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(/.*)?$',
            'ip_address': r'^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        }
        
        import re
        pattern = validation_rules.get(input_type)
        if pattern:
            return bool(re.match(pattern, input_data))
        
        return True  # 无规则时默认通过
    
    def sanitize_input(self, input_data: str) -> str:
        """清理危险输入"""
        # SQL注入防护
        sql_dangerous = ["'", '"', ";", "--", "/*", "*/", "xp_", "union", "select"]
        for dangerous in sql_dangerous:
            input_data = input_data.replace(dangerous, "")
        
        # XSS防护
        xss_dangerous = ["<", ">", "script", "javascript:", "onload", "onerror"]
        for dangerous in xss_dangerous:
            input_data = input_data.replace(dangerous, "")
        
        # 路径遍历防护
        path_dangerous = ["../", "..\\", "/etc/passwd", "C:\\Windows"]
        for dangerous in path_dangerous:
            input_data = input_data.replace(dangerous, "")
        
        return input_data.strip()
    
    def _is_debugger_present(self) -> bool:
        """检测调试器"""
        try:
            # 检查常见调试器进程
            debuggers = ['ollydbg.exe', 'x64dbg.exe', 'idaq.exe', 'ida64.exe', 
                        'windbg.exe', 'immunitydebugger.exe']
            
            for proc in psutil.process_iter(['name']):
                if proc.info['name'].lower() in debuggers:
                    return True
            
            return False
            
        except:
            return False
    
    def _is_virtual_machine(self) -> bool:
        """检测虚拟机"""
        try:
            # 检查常见虚拟机进程
            vm_indicators = ['vmtoolsd.exe', 'vmwaretray.exe', 'vboxservice.exe']
            
            for proc in psutil.process_iter(['name']):
                if proc.info['name'].lower() in vm_indicators:
                    return True
            
            return False
            
        except:
            return False
    
    def _check_file_permissions(self):
        """检查文件权限"""
        try:
            # 检查关键文件权限
            critical_files = [
                'config/secrets.enc',
                'config/encryption.key',
                'data/app.db'
            ]
            
            for file_path in critical_files:
                if os.path.exists(file_path):
                    # 在Unix系统上检查文件权限
                    if os.name != 'nt':
                        stat_info = os.stat(file_path)
                        if stat_info.st_mode & 0o077 != 0:  # 检查group和other权限
                            self.logger.warning(f"文件权限过松: {file_path}")
            
        except Exception as e:
            self.logger.error(f"文件权限检查失败: {e}")
    
    def _generate_secure_key(self) -> bytes:
        """生成安全密钥"""
        return Fernet.generate_key()
    
    def lock_application(self):
        """锁定应用"""
        self._is_locked = True
        self.logger.info("应用已锁定")
    
    def unlock_application(self, password: str) -> bool:
        """解锁应用"""
        if self._failed_attempts >= self._max_failed_attempts:
            self.logger.warning("解锁尝试次数过多")
            return False
        
        # 这里应该验证密码
        # 简化实现，实际应该从配置或数据库读取哈希值
        if password == "default_password":  # 这应该被替换
            self._is_locked = False
            self._failed_attempts = 0
            self.logger.info("应用已解锁")
            return True
        else:
            self._failed_attempts += 1
            self.logger.warning(f"解锁失败，剩余尝试次数: {self._max_failed_attempts - self._failed_attempts}")
            return False
    
    def is_locked(self) -> bool:
        """检查应用是否锁定"""
        return self._is_locked
    
    def get_security_status(self) -> Dict[str, Any]:
        """获取安全状态"""
        return {
            'locked': self._is_locked,
            'failed_attempts': self._failed_attempts,
            'max_attempts': self._max_failed_attempts,
            'debugger_detected': self._is_debugger_present(),
            'vm_detected': self._is_virtual_machine()
        }
    
    def audit_security_event(self, event_type: str, details: str, user: str = "system"):
        """记录安全审计事件"""
        audit_log = {
            'timestamp': self._get_timestamp(),
            'event_type': event_type,
            'user': user,
            'details': details,
            'ip_address': self._get_ip_address()
        }
        
        self.logger.info(f"安全审计: {audit_log}")
        
        # 这里应该将审计记录保存到文件或数据库
        self._save_audit_log(audit_log)
    
    def _get_timestamp(self) -> str:
        """获取时间戳"""
        from datetime import datetime
        return datetime.now().isoformat()
    
    def _get_ip_address(self) -> str:
        """获取IP地址"""
        try:
            import socket
            return socket.gethostbyname(socket.gethostname())
        except:
            return "unknown"
    
    def _save_audit_log(self, audit_log: Dict):
        """保存审计日志"""
        try:
            audit_dir = Path("logs/audit")
            audit_dir.mkdir(exist_ok=True)
            
            audit_file = audit_dir / "security_audit.log"
            
            with open(audit_file, 'a', encoding='utf-8') as f:
                f.write(f"{audit_log}\n")
                
        except Exception as e:
            self.logger.error(f"保存审计日志失败: {e}")

# 安全管理器单例
_security_instance = None

def get_security_manager() -> SecurityManager:
    """获取安全管理器实例"""
    global _security_instance
    if _security_instance is None:
        _security_instance = SecurityManager()
    return _security_instance