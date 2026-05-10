# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller打包配置文件
昆仑安全测试平台 Pro - 统一后端核心

打包命令：
pyinstaller platform.spec

或：
pyinstaller --onefile --windowed --name=KunlunPenTestPlatform platform_main.py
"""

import sys
from pathlib import Path

block_cipher = None

# 获取项目根目录
project_root = Path(__file__).parent

# 收集所有Python模块
modules = []
for py_file in project_root.rglob('*.py'):
    if '__pycache__' not in str(py_file):
        modules.append(str(py_file))

# 收集所有数据文件
datas = []
data_dirs = ['config', 'data', 'poc_library']
for d in data_dirs:
    dir_path = project_root / d
    if dir_path.exists():
        datas.append((str(dir_path), d))

a = Analysis(
    ['platform_main.py'],
    pathex=[],
    binaries=[],
    datas=datas,
    hiddenimports=[
        'PySide6',
        'PySide6.QtCore',
        'PySide6.QtGui',
        'PySide6.QtWidgets',
        'sqlalchemy',
        'sqlalchemy.ext.declarative',
        'sqlalchemy.orm',
        'cryptography',
        'cryptography.fernet',
        'yaml',
        'core',
        'core.application',
        'core.event_bus',
        'core.data_bus',
        'core.module_registry',
        'core.config.config_manager',
        'core.modules',
        'ui',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        'tkinter',
        'unittest',
        'email',
        'http',
        'xml',
        'pydoc',
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='KunlunPenTestPlatform',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,  # 无控制台窗口
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign=None,
    icon=None,  # 可添加图标: icon='icon.ico'
)
