"""
通用工具类 - 优化重复代码模式
基于20年渗透测试经验的代码优化工具
"""

import logging
import hashlib
import secrets
import time
from typing import Any, Callable, Dict, List, Optional, Tuple, Union
from functools import wraps
from datetime import datetime

logger = logging.getLogger(__name__)

class CommonUtils:
    """通用工具类"""
    
    @staticmethod
    def generate_id(prefix: str = "") -> str:
        """生成唯一ID"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S_%f')
        random_part = secrets.token_hex(4)
        return f"{prefix}{timestamp}_{random_part}"
    
    @staticmethod
    def safe_execute(func: Callable, default_return: Any = None, 
                    log_error: bool = True, *args, **kwargs) -> Any:
        """安全执行函数，避免异常传播"""
        try:
            return func(*args, **kwargs)
        except Exception as e:
            if log_error:
                logger.error(f"函数执行失败 {func.__name__}: {e}")
            return default_return
    
    @staticmethod
    def retry_on_failure(max_retries: int = 3, delay: float = 1.0, 
                        exceptions: Tuple = (Exception,)):
        """重试装饰器"""
        def decorator(func):
            @wraps(func)
            def wrapper(*args, **kwargs):
                for attempt in range(max_retries):
                    try:
                        return func(*args, **kwargs)
                    except exceptions as e:
                        if attempt == max_retries - 1:
                            raise
                        logger.warning(f"第{attempt + 1}次重试 {func.__name__}: {e}")
                        time.sleep(delay * (attempt + 1))
                return None
            return wrapper
        return decorator
    
    @staticmethod
    def validate_input(data: Any, validation_rules: Dict) -> bool:
        """通用输入验证"""
        if not isinstance(data, (str, int, float, list, dict)):
            return False
        
        for rule_name, rule_func in validation_rules.items():
            if not rule_func(data):
                return False
        
        return True
    
    @staticmethod
    def hash_data(data: str, algorithm: str = "sha256") -> str:
        """数据哈希"""
        if algorithm == "sha256":
            return hashlib.sha256(data.encode()).hexdigest()
        elif algorithm == "md5":
            return hashlib.md5(data.encode()).hexdigest()
        else:
            raise ValueError(f"不支持的哈希算法: {algorithm}")
    
    @staticmethod
    def format_timestamp(timestamp: Optional[datetime] = None, 
                        format_str: str = "%Y-%m-%d %H:%M:%S") -> str:
        """格式化时间戳"""
        if timestamp is None:
            timestamp = datetime.now()
        return timestamp.strftime(format_str)
    
    @staticmethod
    def deep_merge_dicts(dict1: Dict, dict2: Dict) -> Dict:
        """深度合并字典"""
        result = dict1.copy()
        
        for key, value in dict2.items():
            if (key in result and isinstance(result[key], dict) 
                and isinstance(value, dict)):
                result[key] = CommonUtils.deep_merge_dicts(result[key], value)
            else:
                result[key] = value
        
        return result

class LoggingUtils:
    """日志工具类"""
    
    @staticmethod
    def log_init_complete(component_name: str):
        """记录组件初始化完成"""
        logger.info(f"{component_name}初始化完成")
    
    @staticmethod
    def log_operation_start(operation_name: str, details: str = ""):
        """记录操作开始"""
        if details:
            logger.info(f"开始{operation_name}: {details}")
        else:
            logger.info(f"开始{operation_name}")
    
    @staticmethod
    def log_operation_complete(operation_name: str, details: str = ""):
        """记录操作完成"""
        if details:
            logger.info(f"{operation_name}完成: {details}")
        else:
            logger.info(f"{operation_name}完成")
    
    @staticmethod
    def log_error_with_context(error: Exception, context: str = ""):
        """记录带上下文的错误"""
        if context:
            logger.error(f"{context}: {error}")
        else:
            logger.error(f"错误: {error}")

class SecurityUtils:
    """安全工具类"""
    
    @staticmethod
    def sanitize_input(input_data: str) -> str:
        """输入清理"""
        # 移除潜在的恶意字符
        dangerous_chars = ['<', '>', '"', "'", '&', ';', '|', '`', '$', '(', ')']
        for char in dangerous_chars:
            input_data = input_data.replace(char, '')
        
        return input_data.strip()
    
    @staticmethod
    def validate_url(url: str) -> bool:
        """URL验证"""
        import re
        url_pattern = r'^https?://[^\s/$.?#].[^\s]*$'
        return bool(re.match(url_pattern, url))
    
    @staticmethod
    def validate_email(email: str) -> bool:
        """邮箱验证"""
        import re
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(email_pattern, email))
    
    @staticmethod
    def generate_secure_password(length: int = 16) -> str:
        """生成安全密码"""
        import string
        characters = string.ascii_letters + string.digits + "!@#$%^&*"
        return ''.join(secrets.choice(characters) for _ in range(length))

class PerformanceUtils:
    """性能工具类"""
    
    @staticmethod
    def timer(func: Callable):
        """性能计时装饰器"""
        @wraps(func)
        def wrapper(*args, **kwargs):
            start_time = time.time()
            result = func(*args, **kwargs)
            end_time = time.time()
            
            logger.debug(f"{func.__name__} 执行时间: {end_time - start_time:.4f}秒")
            return result
        return wrapper
    
    @staticmethod
    def memory_usage() -> float:
        """获取内存使用情况"""
        import psutil
        process = psutil.Process()
        return process.memory_info().rss / 1024 / 1024  # MB
    
    @staticmethod
    def optimize_memory():
        """内存优化"""
        import gc
        gc.collect()
        logger.debug("内存优化完成")

# 创建全局实例
common_utils = CommonUtils()
logging_utils = LoggingUtils()
security_utils = SecurityUtils()
performance_utils = PerformanceUtils()