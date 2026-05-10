#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
KunLun Penetration Testing Platform - Path Utilities Module

提供运行时路径处理功能，支持开发环境和打包后环境的路径差异。
"""

import sys
import os
from pathlib import Path
from typing import Union

# 全局变量缓存
_frozen = None
_base_path = None
_user_dir = None


def is_frozen() -> bool:
    """
    判断是否为打包后的运行环境
    
    Returns:
        bool: 如果是打包环境返回 True，否则返回 False
    """
    global _frozen
    if _frozen is None:
        _frozen = getattr(sys, 'frozen', False)
    return _frozen


def base_path() -> Path:
    """
    获取应用程序的基础路径
    
    在开发环境中返回当前脚本所在目录的父目录
    在打包环境中返回 sys._MEIPASS（解压目录）
    
    Returns:
        Path: 应用程序基础路径
    """
    global _base_path
    if _base_path is None:
        if is_frozen():
            _base_path = Path(sys._MEIPASS)
        else:
            _base_path = Path(__file__).resolve().parent.parent
    return _base_path


def data_path(rel_path: Union[str, Path]) -> Path:
    """
    获取数据文件的绝对路径
    
    Args:
        rel_path: 相对路径
        
    Returns:
        Path: 数据文件的绝对路径
    """
    return base_path() / rel_path


def user_dir() -> Path:
    """
    获取用户数据目录（用于存储证书、配置等）
    
    在用户主目录下创建 .kunlun 目录
    
    Returns:
        Path: 用户数据目录路径
    """
    global _user_dir
    if _user_dir is None:
        _user_dir = Path(os.path.expanduser("~")) / ".kunlun"
        _user_dir.mkdir(parents=True, exist_ok=True)
    return _user_dir


def cert_path(filename: str = "rootCA.pem") -> Path:
    """
    获取证书文件路径
    
    如果证书不存在于用户目录，则从数据目录复制
    
    Args:
        filename: 证书文件名
        
    Returns:
        Path: 证书文件路径
    """
    cert_file = user_dir() / filename
    
    # 如果用户目录不存在，从数据目录复制
    if not cert_file.exists():
        src_cert = data_path("certs") / filename
        if src_cert.exists():
            import shutil
            shutil.copy2(src_cert, cert_file)
    
    return cert_file


def rules_path(sub_path: str = "") -> Path:
    """
    获取规则目录路径
    
    Args:
        sub_path: 子路径
        
    Returns:
        Path: 规则目录路径
    """
    return data_path("rules") / sub_path


def profiles_path(sub_path: str = "") -> Path:
    """
    获取配置文件目录路径
    
    Args:
        sub_path: 子路径
        
    Returns:
        Path: 配置文件目录路径
    """
    return data_path("profiles") / sub_path


def templates_path(sub_path: str = "") -> Path:
    """
    获取模板目录路径
    
    Args:
        sub_path: 子路径
        
    Returns:
        Path: 模板目录路径
    """
    return data_path("templates") / sub_path


def plugins_path(sub_path: str = "") -> Path:
    """
    获取插件目录路径
    
    Args:
        sub_path: 子路径
        
    Returns:
        Path: 插件目录路径
    """
    return data_path("plugins") / sub_path


def config_path(filename: str = "app.yaml") -> Path:
    """
    获取配置文件路径
    
    Args:
        filename: 配置文件名
        
    Returns:
        Path: 配置文件路径
    """
    return data_path("config") / filename


def assets_path(sub_path: str = "") -> Path:
    """
    获取资源文件目录路径
    
    Args:
        sub_path: 子路径
        
    Returns:
        Path: 资源文件目录路径
    """
    return data_path("assets") / sub_path


def ensure_dir(path: Union[str, Path]) -> Path:
    """
    确保目录存在，如果不存在则创建
    
    Args:
        path: 目录路径
        
    Returns:
        Path: 目录路径
    """
    p = Path(path)
    p.mkdir(parents=True, exist_ok=True)
    return p


def resolve_path(path: Union[str, Path]) -> Path:
    """
    解析路径，支持相对路径和绝对路径
    
    Args:
        path: 路径字符串或 Path 对象
        
    Returns:
        Path: 解析后的绝对路径
    """
    p = Path(path)
    if p.is_absolute():
        return p.resolve()
    else:
        return (base_path() / p).resolve()


# 初始化时确保必要目录存在
def init_paths():
    """初始化所有必要的目录"""
    user_dir()
    ensure_dir(user_dir() / "logs")
    ensure_dir(user_dir() / "results")
    ensure_dir(user_dir() / "payloads")
    ensure_dir(user_dir() / "certs")


# 模块加载时自动初始化
init_paths()


if __name__ == "__main__":
    # 测试路径功能
    print(f"是否打包环境: {is_frozen()}")
    print(f"基础路径: {base_path()}")
    print(f"用户目录: {user_dir()}")
    print(f"证书路径: {cert_path()}")
    print(f"规则目录: {rules_path()}")
    print(f"配置文件: {config_path()}")
