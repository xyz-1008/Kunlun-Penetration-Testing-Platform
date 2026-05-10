#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
KunLun Penetration Testing Platform - PyArmor Encryption Script
"""

import os
import sys
import shutil
import argparse
import subprocess
from pathlib import Path
from typing import List, Set

# Fix encoding for Windows
if sys.platform == 'win32':
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')

# ==================== 配置 ====================
# 项目根目录
PROJECT_ROOT = Path(__file__).parent.absolute()

# 默认输出目录
DEFAULT_OUTPUT = PROJECT_ROOT / "dist_encrypted"

# 需要加密的目录
ENCRYPT_DIRS = [
    "core",
    "gui",
    "utils",
    "cli",
    "main.py",
]

# 不需要加密的文件/目录（纯数据文件）
EXCLUDE_PATTERNS = [
    # 配置文件模板
    "*.yaml",
    "*.yml",
    "*.json",
    "*.toml",
    "*.ini",
    "*.cfg",
    "*.conf",
    
    # 模板文件
    "*.html",
    "*.j2",
    "*.jinja2",
    "*.md",
    "*.rst",
    "*.txt",
    
    # 证书和密钥
    "*.pem",
    "*.crt",
    "*.key",
    "*.p12",
    "*.pfx",
    
    # 图片和资源
    "*.png",
    "*.jpg",
    "*.jpeg",
    "*.gif",
    "*.svg",
    "*.ico",
    "*.woff",
    "*.woff2",
    "*.ttf",
    "*.eot",
    
    # 数据文件
    "*.csv",
    "*.xml",
    "*.sql",
    "*.db",
    "*.sqlite",
    
    # 文档
    "README.md",
    "CHANGELOG.md",
    "LICENSE",
    "docs/",
    "examples/",
    
    # 测试文件
    "tests/",
    "test_*.py",
    "*_test.py",
    
    # 构建产物
    "build/",
    "dist/",
    "*.egg-info/",
    "__pycache__/",
    "*.pyc",
    "*.pyo",
    "*.pyd",
    "*.so",
    "*.dylib",
    
    # IDE配置
    ".vscode/",
    ".idea/",
    "*.swp",
    "*.swo",
    "*~",
    
    # Git
    ".git/",
    ".gitignore",
    ".gitattributes",
    
    # 环境
    ".env",
    ".env.*",
    "venv/",
    ".venv/",
    "env/",
]


def run_pyarmor_obfuscate(
    project_root: Path,
    output_dir: Path,
    advanced: bool = True,
    string_encrypt: bool = True,
) -> bool:
    """
    使用PyArmor 7.x进行批量加密（使用obfuscate命令）
    
    参数：
        project_root: 项目根目录
        output_dir: 输出目录
        advanced: 使用高级模式
        string_encrypt: 加密字符串常量
    
    返回：
        是否成功
    """
    # 清理输出目录
    if output_dir.exists():
        shutil.rmtree(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # PyArmor 7.x 使用 obfuscate 命令（简写为 o）
    # 命令格式: pyarmor obfuscate [选项] 入口文件
    cmd = [
        "pyarmor",
        "obfuscate",  # PyArmor 7.x 使用 obfuscate 而非 gen
        "--output", str(output_dir),
        "--restrict", "4",
        "--recursive",
        "--obf-code", "2",
        "--obf-mod", "2",
    ]
    
    if advanced:
        cmd.append("--advanced")
    
    if string_encrypt:
        cmd.append("--enable-str-crypto")
    
    # 添加排除模式
    for pattern in EXCLUDE_PATTERNS:
        if pattern.startswith("*"):
            cmd.extend(["--exclude", pattern])
    
    # 添加入口文件
    cmd.append(str(project_root / "main.py"))
    
    print(f"执行PyArmor命令: {' '.join(cmd)}")
    
    try:
        result = subprocess.run(
            cmd,
            cwd=project_root,
            capture_output=True,
            text=True,
            timeout=7200,  # 2小时超时
            env={**os.environ, "PYTHONIOENCODING": "utf-8"}
        )
        
        if result.returncode == 0:
            print("✓ PyArmor加密成功")
            print(f"输出目录: {output_dir}")
            return True
        else:
            print("✗ PyArmor加密失败")
            print(f"返回码: {result.returncode}")
            print(f"标准输出: {result.stdout}")
            print(f"错误输出: {result.stderr}")
            return False
            
    except subprocess.TimeoutExpired:
        print("✗ PyArmor加密超时")
        return False
    except Exception as e:
        print(f"✗ PyArmor加密异常: {e}")
        import traceback
        print(traceback.format_exc())
        return False


def copy_data_files(project_root: Path, output_dir: Path) -> None:
    """复制不需要加密的数据文件到输出目录"""
    print("复制数据文件...")
    
    # 需要复制的目录
    data_dirs = [
        "rules",
        "profiles",
        "gadget_chains",
        "ranges",
        "templates",
        "certs",
        "plugins",
        "assets",
        "config",
        "locales",
        "docs",
        "examples",
    ]
    
    for dir_name in data_dirs:
        src = project_root / dir_name
        dst = output_dir / dir_name
        
        if src.exists():
            if dst.exists():
                shutil.rmtree(dst)
            shutil.copytree(src, dst)
            print(f"  ✓ 复制 {dir_name}/")
    
    # 复制根目录下的数据文件
    for pattern in ["*.yaml", "*.yml", "*.json", "*.toml", "*.md", "*.txt"]:
        for file_path in project_root.glob(pattern):
            if file_path.name not in ["README.md", "CHANGELOG.md", "LICENSE"]:
                shutil.copy2(file_path, output_dir / file_path.name)
    
    print("✓ 数据文件复制完成")


def main():
    """主函数"""
    parser = argparse.ArgumentParser(description="昆仑渗透测试平台 - PyArmor加密脚本")
    parser.add_argument(
        "--advanced",
        action="store_true",
        default=True,
        help="使用高级模式（默认启用）",
    )
    parser.add_argument(
        "--no-advanced",
        action="store_true",
        help="禁用高级模式",
    )
    parser.add_argument(
        "--no-string-encrypt",
        action="store_true",
        help="禁用字符串加密",
    )
    parser.add_argument(
        "--output",
        type=str,
        default=str(DEFAULT_OUTPUT),
        help="输出目录路径",
    )
    
    args = parser.parse_args()
    
    # 确定配置
    advanced = not args.no_advanced
    string_encrypt = not args.no_string_encrypt
    output_dir = Path(args.output)
    
    print("=" * 60)
    print("昆仑渗透测试平台 - PyArmor加密")
    print("=" * 60)
    print(f"项目根目录: {PROJECT_ROOT}")
    print(f"输出目录: {output_dir}")
    print(f"高级模式: {advanced}")
    print(f"字符串加密: {string_encrypt}")
    print("=" * 60)
    
    # 检查PyArmor安装 (PyArmor 7.x)
    try:
        result = subprocess.run(
            ["pyarmor", "--version"],
            capture_output=True,
            text=True,
            env={**os.environ, "PYTHONIOENCODING": "utf-8"}
        )
        if result.returncode == 0:
            version_output = result.stdout.strip()
            print(f"PyArmor已安装: {version_output}")
        else:
            print("PyArmor未找到，正在安装...")
            subprocess.run(
                [sys.executable, "-m", "pip", "install", "pyarmor<8.0"],
                check=True,
                capture_output=True
            )
            result = subprocess.run(
                ["pyarmor", "--version"],
                capture_output=True,
                text=True,
                env={**os.environ, "PYTHONIOENCODING": "utf-8"}
            )
            print(f"PyArmor安装成功: {result.stdout.strip()}")
    except Exception as e:
        print(f"PyArmor检查失败: {e}")
        import traceback
        print(traceback.format_exc())
        sys.exit(1)
    
    # 执行加密
    success = run_pyarmor_obfuscate(
        project_root=PROJECT_ROOT,
        output_dir=output_dir,
        advanced=advanced,
        string_encrypt=string_encrypt,
    )
    
    if success:
        # 复制数据文件
        copy_data_files(PROJECT_ROOT, output_dir)
        
        print("\n" + "=" * 60)
        print("✓ 加密完成！")
        print(f"加密文件位于: {output_dir}")
        print("下一步：使用PyInstaller打包加密后的文件")
        print("=" * 60)
    else:
        print("\n" + "=" * 60)
        print("✗ 加密失败，请检查错误信息")
        print("=" * 60)
        sys.exit(1)


if __name__ == "__main__":
    main()
