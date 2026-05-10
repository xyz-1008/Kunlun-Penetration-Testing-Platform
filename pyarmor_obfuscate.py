#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
KunLun Penetration Testing Platform - PyArmor Encryption Script
PyArmor 8.x compatible - uses 'gen' command
"""

import os
import sys
import shutil
import argparse
import subprocess
from pathlib import Path

# Fix encoding for Windows
if sys.platform == 'win32':
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')

PROJECT_ROOT = Path(__file__).parent.absolute()
DEFAULT_OUTPUT = PROJECT_ROOT / "dist_encrypted"

# 数据文件模式（不加密）
DATA_PATTERNS = [
    "*.yaml", "*.yml", "*.json", "*.toml", "*.ini", "*.cfg", "*.conf",
    "*.html", "*.j2", "*.jinja2", "*.md", "*.rst", "*.txt",
    "*.pem", "*.crt", "*.key", "*.p12", "*.pfx",
    "*.png", "*.jpg", "*.jpeg", "*.gif", "*.svg", "*.ico",
    "*.woff", "*.woff2", "*.ttf", "*.eot",
    "*.csv", "*.xml", "*.sql", "*.db", "*.sqlite",
    "README.md", "CHANGELOG.md", "LICENSE",
    "test_*.py", "*_test.py",
]

# 数据目录（不加密，直接复制）
DATA_DIRS = [
    "rules", "profiles", "templates", "certs", "plugins", "assets",
    "config", "locales", "docs", "examples", "gadget_chains", "ranges"
]


def run_pyarmor_gen():
    """使用 PyArmor 8.x gen 命令加密项目"""
    output_dir = DEFAULT_OUTPUT
    
    # 清理输出目录
    if output_dir.exists():
        shutil.rmtree(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # PyArmor 8.x 正确命令格式
    cmd = [
        sys.executable, "-m", "pyarmor",
        "gen",
        "--output", str(output_dir),
        "--recursive",
        "--enable-jit",
        "--mix-str",
        "--advanced", "4",  # 必须提供值 0-5
    ]
    
    # 添加排除模式
    for pattern in DATA_PATTERNS:
        cmd.extend(["--exclude", pattern])
    
    # 添加入口文件
    cmd.append(str(PROJECT_ROOT / "main.py"))
    
    print(f"执行命令: {' '.join(cmd)}")
    
    try:
        result = subprocess.run(
            cmd,
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            timeout=7200,
            env={**os.environ, "PYTHONIOENCODING": "utf-8"}
        )
        
        if result.returncode == 0:
            print("✓ PyArmor加密成功")
            return True
        else:
            print("✗ PyArmor加密失败")
            print(f"stdout: {result.stdout}")
            print(f"stderr: {result.stderr}")
            return False
            
    except Exception as e:
        print(f"✗ 加密异常: {e}")
        return False


def copy_data_files():
    """复制数据文件到输出目录"""
    output_dir = DEFAULT_OUTPUT
    
    for dir_name in DATA_DIRS:
        src = PROJECT_ROOT / dir_name
        dst = output_dir / dir_name
        if src.exists():
            if dst.exists():
                shutil.rmtree(dst)
            shutil.copytree(src, dst)
            print(f"✓ 复制目录: {dir_name}/")
    
    # 复制根目录数据文件
    for pattern in ["*.yaml", "*.yml", "*.json", "*.toml", "*.md"]:
        for file in PROJECT_ROOT.glob(pattern):
            if file.name not in ["README.md", "CHANGELOG.md"]:
                shutil.copy2(file, output_dir / file.name)


def main():
    print("=" * 60)
    print("昆仑渗透测试平台 - PyArmor加密")
    print("=" * 60)
    
    # 检查 PyArmor 版本
    result = subprocess.run(
        [sys.executable, "-m", "pyarmor", "--version"],
        capture_output=True, text=True
    )
    if result.returncode == 0:
        print(f"PyArmor版本: {result.stdout.strip()}")
    else:
        print("安装 PyArmor...")
        subprocess.run([sys.executable, "-m", "pip", "install", "pyarmor"], check=True)
    
    # 执行加密
    if run_pyarmor_gen():
        copy_data_files()
        print("\n✓ 加密完成！输出目录: dist_encrypted")
    else:
        sys.exit(1)


if __name__ == "__main__":
    main()
