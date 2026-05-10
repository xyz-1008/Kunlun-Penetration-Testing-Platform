#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
昆仑渗透测试平台 - 运行时路径处理工具模块
===========================================
功能：
  1. 自动适配开发环境和打包后环境的路径
  2. 使用sys._MEIPASS(打包后)或os.path.dirname(__file__)(开发时)
  3. 提供统一的路径访问接口
  4. 支持用户数据目录(appdirs)作为配置和证书存储
  5. 支持程序运行目录下的自定义覆盖

使用示例：
    from utils.path_utils import PathUtils
    
    # 获取资源文件路径
    rules_dir = PathUtils.get_resource_path("rules")
    template_path = PathUtils.get_resource_path("templates", "report.html")
    
    # 获取用户数据目录
    cert_dir = PathUtils.get_user_data_path("certs")
    config_path = PathUtils.get_user_data_path("config", "settings.json")
    
    # 获取插件目录
    plugin_dir = PathUtils.get_plugin_path()
"""

import os
import sys
import platform
import tempfile
from pathlib import Path
from typing import Optional, Union, List


class PathUtils:
    """运行时路径处理工具类"""
    
    # ==================== 内部状态 ====================
    _is_frozen: bool = False
    _resource_base: Path = None
    _user_data_base: Path = None
    _temp_base: Path = None
    
    @classmethod
    def _init(cls):
        """初始化路径配置"""
        if cls._resource_base is not None:
            return
        
        # 检测是否为打包后环境
        cls._is_frozen = getattr(sys, 'frozen', False)
        
        if cls._is_frozen:
            # 打包后环境：使用sys._MEIPASS
            cls._resource_base = Path(sys._MEIPASS)
        else:
            # 开发环境：使用脚本所在目录
            cls._resource_base = Path(__file__).parent.parent.absolute()
        
        # 用户数据目录
        cls._user_data_base = cls._get_appdirs_user_data_path()
        
        # 临时目录
        cls._temp_base = Path(tempfile.gettempdir()) / "KunLun_PenTest"
        cls._temp_base.mkdir(parents=True, exist_ok=True)
    
    # ==================== 资源路径 (只读) ====================
    @classmethod
    def get_resource_path(cls, *relative_parts: str) -> Path:
        """
        获取资源文件路径（打包后从_MEIPASS读取）
        
        参数：
            *relative_parts: 相对路径部分
        
        返回：
            绝对路径
        
        示例：
            PathUtils.get_resource_path("rules", "nuclei")
            PathUtils.get_resource_path("templates", "report.html")
        """
        cls._init()
        return cls._resource_base.joinpath(*relative_parts)
    
    @classmethod
    def get_rules_path(cls, *relative_parts: str) -> Path:
        """获取Nuclei规则目录路径"""
        return cls.get_resource_path("rules", *relative_parts)
    
    @classmethod
    def get_templates_path(cls, *relative_parts: str) -> Path:
        """获取模板目录路径"""
        return cls.get_resource_path("templates", *relative_parts)
    
    @classmethod
    def get_profiles_path(cls, *relative_parts: str) -> Path:
        """获取Profile模板路径"""
        return cls.get_resource_path("profiles", *relative_parts)
    
    @classmethod
    def get_gadget_chains_path(cls, *relative_parts: str) -> Path:
        """获取Gadget链配置路径"""
        return cls.get_resource_path("gadget_chains", *relative_parts)
    
    @classmethod
    def get_ranges_path(cls, *relative_parts: str) -> Path:
        """获取靶场配置路径"""
        return cls.get_resource_path("ranges", *relative_parts)
    
    @classmethod
    def get_assets_path(cls, *relative_parts: str) -> Path:
        """获取静态资源路径"""
        return cls.get_resource_path("assets", *relative_parts)
    
    @classmethod
    def get_locales_path(cls, *relative_parts: str) -> Path:
        """获取语言文件路径"""
        return cls.get_resource_path("locales", *relative_parts)
    
    @classmethod
    def get_docs_path(cls, *relative_parts: str) -> Path:
        """获取文档路径"""
        return cls.get_resource_path("docs", *relative_parts)
    
    @classmethod
    def get_examples_path(cls, *relative_parts: str) -> Path:
        """获取示例文件路径"""
        return cls.get_resource_path("examples", *relative_parts)
    
    # ==================== 用户数据路径 (可读写) ====================
    @classmethod
    def _get_appdirs_user_data_path(cls) -> Path:
        """
        获取用户数据目录（跨平台）
        
        Windows: %APPDATA%/KunLun_PenTest
        macOS: ~/Library/Application Support/KunLun_PenTest
        Linux: ~/.local/share/KunLun_PenTest
        """
        system = platform.system()
        
        if system == "Windows":
            appdata = os.environ.get("APPDATA")
            if appdata:
                return Path(appdata) / "KunLun_PenTest"
            return Path.home() / "AppData" / "Roaming" / "KunLun_PenTest"
        
        elif system == "Darwin":  # macOS
            return Path.home() / "Library" / "Application Support" / "KunLun_PenTest"
        
        else:  # Linux
            data_home = os.environ.get("XDG_DATA_HOME")
            if data_home:
                return Path(data_home) / "KunLun_PenTest"
            return Path.home() / ".local" / "share" / "KunLun_PenTest"
    
    @classmethod
    def get_user_data_path(cls, *relative_parts: str) -> Path:
        """
        获取用户数据目录路径（可读写）
        
        参数：
            *relative_parts: 相对路径部分
        
        返回：
            绝对路径
        
        示例：
            PathUtils.get_user_data_path("certs")
            PathUtils.get_user_data_path("config", "settings.json")
        """
        cls._init()
        path = cls._user_data_base.joinpath(*relative_parts)
        path.mkdir(parents=True, exist_ok=True)
        return path
    
    @classmethod
    def get_certs_path(cls, *relative_parts: str) -> Path:
        """获取证书存储目录"""
        return cls.get_user_data_path("certs", *relative_parts)
    
    @classmethod
    def get_config_path(cls, *relative_parts: str) -> Path:
        """获取配置文件目录"""
        return cls.get_user_data_path("config", *relative_parts)
    
    @classmethod
    def get_plugins_path(cls, *relative_parts: str) -> Path:
        """获取用户插件目录"""
        return cls.get_user_data_path("plugins", *relative_parts)
    
    @classmethod
    def get_cache_path(cls, *relative_parts: str) -> Path:
        """获取缓存目录"""
        return cls.get_user_data_path("cache", *relative_parts)
    
    @classmethod
    def get_logs_path(cls, *relative_parts: str) -> Path:
        """获取日志目录"""
        return cls.get_user_data_path("logs", *relative_parts)
    
    @classmethod
    def get_database_path(cls, *relative_parts: str) -> Path:
        """获取数据库文件目录"""
        return cls.get_user_data_path("database", *relative_parts)
    
    @classmethod
    def get_sessions_path(cls, *relative_parts: str) -> Path:
        """获取会话文件目录"""
        return cls.get_user_data_path("sessions", *relative_parts)
    
    @classmethod
    def get_reports_path(cls, *relative_parts: str) -> Path:
        """获取报告输出目录"""
        return cls.get_user_data_path("reports", *relative_parts)
    
    # ==================== 临时路径 ====================
    @classmethod
    def get_temp_path(cls, *relative_parts: str) -> Path:
        """
        获取临时文件目录
        
        参数：
            *relative_parts: 相对路径部分
        
        返回：
            绝对路径
        """
        cls._init()
        path = cls._temp_base.joinpath(*relative_parts)
        path.parent.mkdir(parents=True, exist_ok=True)
        return path
    
    @classmethod
    def get_payload_temp_path(cls, *relative_parts: str) -> Path:
        """获取Payload临时文件目录（C2框架使用）"""
        return cls.get_temp_path("payloads", *relative_parts)
    
    @classmethod
    def get_mitm_temp_path(cls, *relative_parts: str) -> Path:
        """获取MITM代理临时文件目录"""
        return cls.get_temp_path("mitm", *relative_parts)
    
    # ==================== 程序运行目录 ====================
    @classmethod
    def get_executable_path(cls) -> Path:
        """获取可执行文件路径"""
        if cls._is_frozen:
            return Path(sys.executable)
        return Path(sys.argv[0]).absolute()
    
    @classmethod
    def get_executable_dir(cls) -> Path:
        """获取可执行文件所在目录"""
        return cls.get_executable_path().parent
    
    @classmethod
    def get_runtime_path(cls, *relative_parts: str) -> Path:
        """
        获取程序运行目录下的路径（用户可自定义覆盖）
        
        参数：
            *relative_parts: 相对路径部分
        
        返回：
            绝对路径
        """
        return cls.get_executable_dir().joinpath(*relative_parts)
    
    # ==================== 路径查找 (支持覆盖) ====================
    @classmethod
    def find_resource(cls, resource_name: str, search_dirs: Optional[List[Path]] = None) -> Optional[Path]:
        """
        查找资源文件（支持用户覆盖）
        
        查找顺序：
        1. 程序运行目录
        2. 用户数据目录
        3. 资源目录（打包内嵌）
        
        参数：
            resource_name: 资源文件名
            search_dirs: 额外搜索目录
        
        返回：
            文件路径，如果未找到返回None
        """
        cls._init()
        
        # 1. 程序运行目录
        runtime_path = cls.get_runtime_path(resource_name)
        if runtime_path.exists():
            return runtime_path
        
        # 2. 用户数据目录
        user_data_path = cls.get_user_data_path(resource_name)
        if user_data_path.exists():
            return user_data_path
        
        # 3. 资源目录
        resource_path = cls.get_resource_path(resource_name)
        if resource_path.exists():
            return resource_path
        
        # 4. 额外搜索目录
        if search_dirs:
            for search_dir in search_dirs:
                path = search_dir / resource_name
                if path.exists():
                    return path
        
        return None
    
    @classmethod
    def find_resource_in_dirs(cls, resource_name: str, base_dirs: List[Path]) -> Optional[Path]:
        """
        在指定目录列表中查找资源文件
        
        参数：
            resource_name: 资源文件名
            base_dirs: 基础目录列表
        
        返回：
            文件路径，如果未找到返回None
        """
        for base_dir in base_dirs:
            path = base_dir / resource_name
            if path.exists():
                return path
        return None
    
    # ==================== 环境检测 ====================
    @classmethod
    def is_frozen(cls) -> bool:
        """检测是否为打包后环境"""
        cls._init()
        return cls._is_frozen
    
    @classmethod
    def get_platform(cls) -> str:
        """获取当前平台"""
        return platform.system()
    
    @classmethod
    def is_admin(cls) -> bool:
        """检测是否具有管理员权限"""
        if platform.system() == "Windows":
            import ctypes
            try:
                return bool(ctypes.windll.shell32.IsUserAnAdmin())
            except:
                return False
        else:
            return os.geteuid() == 0
    
    @classmethod
    def require_admin(cls, feature_name: str = "此功能") -> bool:
        """
        检测并要求管理员权限
        
        参数：
            feature_name: 功能名称
        
        返回：
            是否具有管理员权限
        """
        if not cls.is_admin():
            print(f"⚠ {feature_name}需要管理员权限，请以管理员身份运行程序")
            return False
        return True
    
    # ==================== 路径清理 ====================
    @classmethod
    def cleanup_temp(cls, max_age_hours: int = 24) -> int:
        """
        清理临时文件
        
        参数：
            max_age_hours: 最大保留时间（小时）
        
        返回：
            清理的文件数量
        """
        import time
        
        cls._init()
        cleaned = 0
        
        if not cls._temp_base.exists():
            return 0
        
        current_time = time.time()
        max_age_seconds = max_age_hours * 3600
        
        for root, dirs, files in os.walk(cls._temp_base):
            for file in files:
                file_path = Path(root) / file
                try:
                    file_age = current_time - file_path.stat().st_mtime
                    if file_age > max_age_seconds:
                        file_path.unlink()
                        cleaned += 1
                except:
                    pass
        
        return cleaned
    
    # ==================== 调试信息 ====================
    @classmethod
    def get_debug_info(cls) -> dict:
        """获取路径调试信息"""
        cls._init()
        
        return {
            "is_frozen": cls._is_frozen,
            "platform": platform.system(),
            "platform_release": platform.release(),
            "python_version": platform.python_version(),
            "resource_base": str(cls._resource_base),
            "user_data_base": str(cls._user_data_base),
            "temp_base": str(cls._temp_base),
            "executable": str(cls.get_executable_path()),
            "executable_dir": str(cls.get_executable_dir()),
            "cwd": str(Path.cwd()),
            "meipass": getattr(sys, '_MEIPASS', None),
        }
    
    @classmethod
    def print_debug_info(cls):
        """打印路径调试信息"""
        info = cls.get_debug_info()
        print("=" * 60)
        print("昆仑渗透测试平台 - 路径调试信息")
        print("=" * 60)
        for key, value in info.items():
            print(f"  {key}: {value}")
        print("=" * 60)


# ==================== 便捷函数 ====================
def get_resource_path(*relative_parts: str) -> Path:
    """获取资源文件路径（便捷函数）"""
    return PathUtils.get_resource_path(*relative_parts)


def get_user_data_path(*relative_parts: str) -> Path:
    """获取用户数据路径（便捷函数）"""
    return PathUtils.get_user_data_path(*relative_parts)


def get_temp_path(*relative_parts: str) -> Path:
    """获取临时文件路径（便捷函数）"""
    return PathUtils.get_temp_path(*relative_parts)


def is_frozen() -> bool:
    """检测是否为打包后环境（便捷函数）"""
    return PathUtils.is_frozen()


def is_admin() -> bool:
    """检测是否具有管理员权限（便捷函数）"""
    return PathUtils.is_admin()


# 模块加载时自动初始化
PathUtils._init()
