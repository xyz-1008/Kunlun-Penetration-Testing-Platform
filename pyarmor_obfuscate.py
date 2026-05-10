#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
昆仑渗透测试平台 - PyArmor 加密脚本
====================================
功能：
  1. 对整个项目进行AES-256加密与代码混淆
  2. 排除不需要加密的文件（配置文件、YAML规则、JSON模板等纯数据文件）
  3. 使用--advanced模式启用高级反编译保护
  4. 对敏感字符串常量进行加密保护
  5. 输出到dist_encrypted目录

使用方法：
  python pyarmor_obfuscate.py [--advanced] [--no-string-encrypt] [--output DIR]

依赖：
  pip install pyarmor
"""

import os
import sys
import shutil
import argparse
import subprocess
from pathlib import Path
from typing import List, Set

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

# 敏感字符串模式（需要额外加密）
SENSITIVE_PATTERNS = [
    "jwt_secret",
    "api_key",
    "password",
    "token",
    "secret",
    "credential",
    "private_key",
    "access_key",
    "auth_token",
]


def get_python_files(root: Path, exclude_patterns: List[str]) -> List[Path]:
    """获取需要加密的Python文件列表"""
    python_files = []
    
    for py_file in root.rglob("*.py"):
        # 检查是否在排除列表中
        should_exclude = False
        rel_path = py_file.relative_to(root)
        
        for pattern in exclude_patterns:
            if pattern.endswith("/"):
                # 目录排除
                if rel_path.parts[0] == pattern.rstrip("/"):
                    should_exclude = True
                    break
            elif py_file.match(pattern):
                should_exclude = True
                break
        
        if not should_exclude:
            python_files.append(py_file)
    
    return python_files


def run_pyarmor(
    input_dir: Path,
    output_dir: Path,
    advanced: bool = True,
    string_encrypt: bool = True,
    obf_code: int = 2,
    obf_mod: int = 2,
    wrap_mode: bool = True,
    restrict_mode: int = 4,
    expire: str = None,
    license_file: str = None,
) -> bool:
    """
    运行PyArmor加密
    
    参数：
        input_dir: 输入目录
        output_dir: 输出目录
        advanced: 使用高级模式
        string_encrypt: 加密字符串常量
        obf_code: 代码混淆级别 (0-2)
        obf_mod: 模块混淆级别 (0-2)
        wrap_mode: 包装模式
        restrict_mode: 限制模式 (0-4)
        expire: 过期时间 (YYYY-MM-DD)
        license_file: 许可证文件路径
    
    返回：
        是否成功
    """
    # 构建PyArmor命令
    cmd = [
        sys.executable, "-m", "pyarmor",
        "gen",
        "--output", str(output_dir),
        "--obf-code", str(obf_code),
        "--obf-mod", str(obf_mod),
        "--restrict", str(restrict_mode),
    ]
    
    if advanced:
        cmd.append("--advanced")
    
    if string_encrypt:
        cmd.append("--enable-str-crypto")
    
    if wrap_mode:
        cmd.append("--wrap-mode")
    
    if expire:
        cmd.extend(["--expire", expire])
    
    if license_file:
        cmd.extend(["--with-license", license_file])
    
    # 添加输入文件
    cmd.append(str(input_dir / "main.py"))
    
    print(f"执行PyArmor命令: {' '.join(cmd)}")
    
    try:
        result = subprocess.run(
            cmd,
            cwd=input_dir,
            capture_output=True,
            text=True,
            timeout=3600,  # 1小时超时
        )
        
        if result.returncode == 0:
            print("✓ PyArmor加密成功")
            print(f"输出目录: {output_dir}")
            return True
        else:
            print("✗ PyArmor加密失败")
            print(f"stdout: {result.stdout}")
            print(f"stderr: {result.stderr}")
            return False
            
    except subprocess.TimeoutExpired:
        print("✗ PyArmor加密超时")
        return False
    except Exception as e:
        print(f"✗ PyArmor加密异常: {e}")
        return False


def run_pyarmor_batch(
    project_root: Path,
    output_dir: Path,
    advanced: bool = True,
    string_encrypt: bool = True,
) -> bool:
    """
    批量加密整个项目
    
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
    
    # 构建PyArmor命令
    cmd = [
        sys.executable, "-m", "pyarmor",
        "gen",
        "--output", str(output_dir),
        "--obf-code", "2",
        "--obf-mod", "2",
        "--restrict", "4",
        "--recursive",
    ]
    
    if advanced:
        cmd.append("--advanced")
    
    if string_encrypt:
        cmd.append("--enable-str-crypto")
    
    cmd.append("--wrap-mode")
    
    # 添加排除模式
    for pattern in EXCLUDE_PATTERNS:
        if pattern.endswith(".py") or pattern.startswith("*"):
            cmd.extend(["--exclude", pattern])
    
    # 添加入口文件
    cmd.append(str(project_root / "main.py"))
    
    print(f"执行PyArmor批量加密命令: {' '.join(cmd)}")
    
    try:
        result = subprocess.run(
            cmd,
            cwd=project_root,
            capture_output=True,
            text=True,
            timeout=7200,  # 2小时超时
        )
        
        if result.returncode == 0:
            print("✓ PyArmor批量加密成功")
            print(f"输出目录: {output_dir}")
            return True
        else:
            print("✗ PyArmor批量加密失败")
            print(f"stdout: {result.stdout}")
            print(f"stderr: {result.stderr}")
            return False
            
    except subprocess.TimeoutExpired:
        print("✗ PyArmor批量加密超时")
        return False
    except Exception as e:
        print(f"✗ PyArmor批量加密异常: {e}")
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
    parser.add_argument(
        "--expire",
        type=str,
        help="许可证过期时间 (YYYY-MM-DD)",
    )
    parser.add_argument(
        "--license",
        type=str,
        help="许可证文件路径",
    )
    parser.add_argument(
        "--batch",
        action="store_true",
        default=True,
        help="使用批量加密模式（默认启用）",
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
    print(f"批量加密: {args.batch}")
    print("=" * 60)
    
    # 检查PyArmor是否安装
    try:
        import pyarmor
        print(f"✓ PyArmor版本: {pyarmor.__version__}")
    except ImportError:
        print("✗ PyArmor未安装，正在安装...")
        subprocess.run([sys.executable, "-m", "pip", "install", "pyarmor"])
        try:
            import pyarmor
            print(f"✓ PyArmor版本: {pyarmor.__version__}")
        except ImportError:
            print("✗ PyArmor安装失败，请手动安装: pip install pyarmor")
            sys.exit(1)
    
    # 执行加密
    if args.batch:
        success = run_pyarmor_batch(
            project_root=PROJECT_ROOT,
            output_dir=output_dir,
            advanced=advanced,
            string_encrypt=string_encrypt,
        )
    else:
        success = run_pyarmor(
            input_dir=PROJECT_ROOT,
            output_dir=output_dir,
            advanced=advanced,
            string_encrypt=string_encrypt,
            expire=args.expire,
            license_file=args.license,
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
