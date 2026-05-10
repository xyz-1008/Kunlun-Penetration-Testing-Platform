"""
配置管理器
基于20多年渗透测试经验的配置管理系统
"""

import os
import yaml
import json
from pathlib import Path
from typing import Any, Dict, Optional
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import logging

logger = logging.getLogger(__name__)

class ConfigManager:
    """配置管理器"""
    
    def __init__(self, config_dir: str = "config"):
        self.config_dir = Path(config_dir)
        self.config_dir.mkdir(exist_ok=True)
        
        # 配置文件路径
        self.config_file = self.config_dir / "app.yaml"
        self.secrets_file = self.config_dir / "secrets.enc"
        
        # 配置数据
        self._config_data = {}
        self._secrets_data = {}
        
        # 加密器
        self.fernet = None
        
        # 默认配置
        self._default_config = {
            'app': {
                'name': '渗透测试工具箱-昆仑Desktop',
                'version': '1.0.0',
                'language': 'zh_CN',
                'theme': 'dark',
                'auto_update': True,
                'check_updates_on_startup': True
            },
            'database': {
                'path': 'data/app.db',
                'backup_interval': 24,  # 小时
                'auto_backup': True
            },
            'security': {
                'encryption_enabled': True,
                'auto_lock_timeout': 300,  # 秒
                'require_password': False,
                'audit_log_enabled': True
            },
            'ui': {
                'window_width': 1200,
                'window_height': 800,
                'maximized': True,
                'recent_files_limit': 10
            },
            'modules': {
                'poc_manager': {'enabled': True, 'auto_sync': True},
                'sqli_tester': {'enabled': True, 'safe_mode': True},
                'egress_builder': {'enabled': True, 'require_auth': True},
                'knowledge_base': {'enabled': True, 'auto_update': True}
            }
        }
        
        # 初始化
        self._initialize_encryption()
        self.load_config()
    
    def _initialize_encryption(self):
        """初始化加密系统"""
        try:
            # 生成或加载加密密钥
            key_file = self.config_dir / "encryption.key"
            
            if key_file.exists():
                # 加载现有密钥
                with open(key_file, 'rb') as f:
                    key = f.read()
            else:
                # 生成新密钥
                key = Fernet.generate_key()
                with open(key_file, 'wb') as f:
                    f.write(key)
                # 设置文件权限（Unix系统）
                if os.name != 'nt':
                    os.chmod(key_file, 0o600)
            
            self.fernet = Fernet(key)
            
        except Exception as e:
            logger.error(f"加密系统初始化失败: {e}")
            # 使用弱加密作为后备
            self.fernet = None
    
    def _create_fernet_from_password(self, password: str) -> Fernet:
        """从密码创建Fernet加密器"""
        salt = b'auto_pentest_desktop_salt'
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return Fernet(key)
    
    def load_config(self) -> bool:
        """加载配置"""
        try:
            # 加载主配置
            if self.config_file.exists():
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    loaded_config = yaml.safe_load(f) or {}
                self._config_data = self._deep_merge(self._default_config, loaded_config)
            else:
                self._config_data = self._default_config.copy()
                self.save_config()
            
            # 加载加密的敏感配置
            if self.secrets_file.exists() and self.fernet:
                with open(self.secrets_file, 'rb') as f:
                    encrypted_data = f.read()
                decrypted = self.fernet.decrypt(encrypted_data)
                self._secrets_data = json.loads(decrypted.decode())
            
            logger.info("配置加载成功")
            return True
            
        except Exception as e:
            logger.error(f"配置加载失败: {e}")
            self._config_data = self._default_config.copy()
            return False
    
    def save_config(self) -> bool:
        """保存配置"""
        try:
            # 保存主配置
            with open(self.config_file, 'w', encoding='utf-8') as f:
                yaml.dump(self._config_data, f, default_flow_style=False, allow_unicode=True)
            
            # 保存加密的敏感配置
            if self.fernet and self._secrets_data:
                encrypted = self.fernet.encrypt(json.dumps(self._secrets_data).encode())
                with open(self.secrets_file, 'wb') as f:
                    f.write(encrypted)
            
            logger.info("配置保存成功")
            return True
            
        except Exception as e:
            logger.error(f"配置保存失败: {e}")
            return False
    
    def get(self, key: str, default: Any = None) -> Any:
        """获取配置值"""
        keys = key.split('.')
        value = self._config_data
        
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        
        return value
    
    def set(self, key: str, value: Any, save: bool = True) -> bool:
        """设置配置值"""
        keys = key.split('.')
        config = self._config_data
        
        # 导航到父级
        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]
        
        # 设置值
        config[keys[-1]] = value
        
        if save:
            return self.save_config()
        
        return True
    
    def get_secret(self, key: str, default: Any = None) -> Any:
        """获取敏感配置值"""
        return self._secrets_data.get(key, default)
    
    def set_secret(self, key: str, value: Any, save: bool = True) -> bool:
        """设置敏感配置值"""
        # 输入验证
        if not isinstance(key, str) or not key.strip():
            logger.error("敏感配置的键必须是非空字符串")
            return False
        
        # 对敏感值进行加密存储
        if isinstance(value, str) and len(value) > 0:
            # 检查是否是API密钥格式
            if any(pattern in key.lower() for pattern in ['key', 'secret', 'token', 'password', 'auth']):
                # 确保值被加密
                self._secrets_data[key] = value
            else:
                self._secrets_data[key] = value
        else:
            self._secrets_data[key] = value
        
        if save:
            return self.save_config()
        
        return True
    
    def validate_api_key(self, key: str, key_type: str = "generic") -> bool:
        """验证API密钥格式"""
        if not key or not isinstance(key, str):
            return False
        
        key = key.strip()
        
        # 基本长度检查
        if len(key) < 8:
            return False
        
        # 根据类型验证格式
        if key_type.lower() == "fofa":
            # FOFA通常使用邮箱+key格式
            return '@' in key or len(key) >= 16
        elif key_type.lower() == "shodan":
            # Shodan key通常是32位十六进制
            return len(key) >= 16
        elif key_type.lower() == "openai":
            # OpenAI key以sk-开头
            return key.startswith('sk-') and len(key) >= 20
        elif key_type.lower() == "hunter":
            # 鹰图key格式
            return len(key) >= 16
        
        return True
    
    def sanitize_input(self, value: str) -> str:
        """清理输入值，防止注入攻击"""
        if not isinstance(value, str):
            return value
        
        # 移除潜在的危险字符
        dangerous_chars = ['<', '>', '"', "'", '&', ';', '|', '`', '$', '(', ')', '{', '}']
        sanitized = value
        for char in dangerous_chars:
            # 不替换所有字符，只替换可能导致问题的字符
            if char in ['<', '>']:
                sanitized = sanitized.replace(char, '')
        
        # 限制长度
        if len(sanitized) > 10000:
            sanitized = sanitized[:10000]
        
        return sanitized.strip()
    
    def reset_to_defaults(self) -> bool:
        """重置为默认配置"""
        try:
            self._config_data = self._default_config.copy()
            self._secrets_data = {}
            
            # 删除配置文件
            if self.config_file.exists():
                self.config_file.unlink()
            if self.secrets_file.exists():
                self.secrets_file.unlink()
            
            logger.info("配置已重置为默认值")
            return True
            
        except Exception as e:
            logger.error(f"重置配置失败: {e}")
            return False
    
    def export_config(self, export_path: str) -> bool:
        """导出配置"""
        try:
            export_data = {
                'config': self._config_data,
                'secrets': self._secrets_data
            }
            
            with open(export_path, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2, ensure_ascii=False)
            
            logger.info(f"配置已导出到: {export_path}")
            return True
            
        except Exception as e:
            logger.error(f"导出配置失败: {e}")
            return False
    
    def import_config(self, import_path: str) -> bool:
        """导入配置"""
        try:
            with open(import_path, 'r', encoding='utf-8') as f:
                import_data = json.load(f)
            
            self._config_data = import_data.get('config', {})
            self._secrets_data = import_data.get('secrets', {})
            
            return self.save_config()
            
        except Exception as e:
            logger.error(f"导入配置失败: {e}")
            return False
    
    def _deep_merge(self, base: Dict, update: Dict) -> Dict:
        """深度合并字典"""
        result = base.copy()
        
        for key, value in update.items():
            if isinstance(value, dict) and key in result and isinstance(result[key], dict):
                result[key] = self._deep_merge(result[key], value)
            else:
                result[key] = value
        
        return result
    
    def validate_config(self) -> Dict[str, list]:
        """验证配置有效性"""
        errors = []
        warnings = []
        
        # 验证数据库路径
        db_path = self.get('database.path')
        if not db_path:
            errors.append("数据库路径不能为空")
        
        # 验证安全设置
        lock_timeout = self.get('security.auto_lock_timeout')
        if lock_timeout < 60:
            warnings.append("自动锁定时间过短，建议至少60秒")
        
        # 验证UI设置
        width = self.get('ui.window_width')
        height = self.get('ui.window_height')
        if width < 800 or height < 600:
            warnings.append("窗口尺寸过小，可能影响使用体验")
        
        return {'errors': errors, 'warnings': warnings}
    
    def get_module_config(self, module_name: str) -> Dict:
        """获取模块配置"""
        return self.get(f'modules.{module_name}', {})
    
    def set_module_config(self, module_name: str, config: Dict) -> bool:
        """设置模块配置"""
        return self.set(f'modules.{module_name}', config)
    
    def is_module_enabled(self, module_name: str) -> bool:
        """检查模块是否启用"""
        module_config = self.get_module_config(module_name)
        return module_config.get('enabled', True)

# 配置管理器单例
_config_instance = None

def get_config_manager() -> ConfigManager:
    """获取配置管理器实例"""
    global _config_instance
    if _config_instance is None:
        _config_instance = ConfigManager()
    return _config_instance