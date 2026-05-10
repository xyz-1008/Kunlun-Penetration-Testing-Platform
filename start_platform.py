#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
昆仑安全测试平台 Pro - 启动脚本
基于20年渗透测试经验和360网络安全标准开发
"""

import os
import sys
import logging
import asyncio
from pathlib import Path

# 添加当前目录到Python路径
current_dir = Path(__file__).parent
sys.path.insert(0, str(current_dir))

def setup_logging():
    """设置日志系统"""
    log_dir = current_dir / "logs"
    log_dir.mkdir(exist_ok=True)
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_dir / "platform.log", encoding='utf-8'),
            logging.StreamHandler(sys.stdout)
        ]
    )

def check_dependencies():
    """检查依赖库"""
    required_packages = [
        'PySide6', 'aiohttp', 'cryptography', 'bcrypt', 'jwt',
        'psutil', 'sqlalchemy', 'flask', 'requests', 'bs4'
    ]
    
    missing_packages = []
    for package in required_packages:
        try:
            __import__(package.replace('-', '_'))
        except ImportError:
            missing_packages.append(package)
    
    if missing_packages:
        print("缺少必要的依赖库:")
        for package in missing_packages:
            print(f"  - {package}")
        print("\n请运行以下命令安装依赖:")
        print(f"pip install {' '.join(missing_packages)}")
        return False
    
    return True

def create_directories():
    """创建必要的目录结构"""
    directories = [
        "logs", "config", "data", "poc_library", 
        "plugins", "reports", "temp"
    ]
    
    for directory in directories:
        dir_path = current_dir / directory
        dir_path.mkdir(exist_ok=True)
        print(f"创建目录: {directory}")

def create_default_config():
    """创建默认配置文件"""
    config_file = current_dir / "config" / "app.yaml"
    
    if not config_file.exists():
        config_content = """# 昆仑安全测试平台 Pro 配置文件
# 基于20年渗透测试经验和360网络安全标准

app:
  name: "昆仑安全测试平台 Pro"
  version: "1.0.0"
  author: "昆仑安全实验室"
  description: "专业级综合安全测试平台"
  debug: false

proxy:
  port: 8080
  host: "0.0.0.0"
  intercept_enabled: true
  ssl_strip_enabled: false
  max_connections: 1000

scanner:
  timeout: 10
  max_threads: 20
  user_agent: "Mozilla/5.0 (昆仑安全测试平台)"
  scan_depth: 3
  follow_redirects: true

intruder:
  max_threads: 10
  delay: 0.1
  retry_count: 3
  timeout: 30

security:
  session_timeout: 3600
  max_login_attempts: 5
  enable_audit_log: true
  enable_rate_limiting: true

performance:
  enable_caching: true
  cache_ttl: 300
  enable_compression: true
  max_memory_usage: 2048

ui:
  theme: "dark"
  language: "zh_CN"
  font_size: 12
  auto_save: true
"""
        config_file.write_text(config_content, encoding='utf-8')
        print("创建默认配置文件: config/app.yaml")

def display_welcome():
    """显示欢迎信息"""
    welcome_text = """
╔════════════════════════════════════════════════════════════════╗
║                    昆仑安全测试平台 Pro                        ║
║             基于20年渗透测试经验的专业级平台                   ║
║                   昆仑安全实验室 荣誉出品                     ║
╚════════════════════════════════════════════════════════════════╝

平台特性:
✓ 专业级代理拦截和流量分析
✓ 智能漏洞扫描和风险评估  
✓ 多协议攻击工具和爆破功能
✓ 高级编码解码和Payload生成
✓ 自动化漏洞验证和攻击链构建
✓ 实时团队协作和项目管理
✓ 跨平台兼容和专业UI设计

技术架构:
• 模块化架构设计，易于扩展
• 高性能异步处理引擎
• 完善的安全加固机制
• 专业级深色主题界面

版本: v1.0.0 | 发布日期: 2026-04-17
"""
    print(welcome_text)

async def start_platform():
    """启动安全测试平台"""
    try:
        from ui.professional_platform import ProfessionalSecurityPlatform
        from core.app import AutoPenTestApp
        
        # 创建应用实例
        app = AutoPenTestApp(sys.argv)
        
        # 创建主窗口
        platform_window = ProfessionalSecurityPlatform(app_instance=app)
        platform_window.show()
        
        # 启动应用
        return app.exec()
        
    except Exception as e:
        logging.error(f"启动平台失败: {e}")
        print(f"错误: {e}")
        return 1

def main():
    """主函数"""
    print("正在启动昆仑安全测试平台 Pro...")
    
    # 设置日志
    setup_logging()
    
    # 检查依赖
    if not check_dependencies():
        return 1
    
    # 创建目录结构
    create_directories()
    
    # 创建默认配置
    create_default_config()
    
    # 显示欢迎信息
    display_welcome()
    
    # 启动平台
    try:
        if sys.platform == "win32":
            # Windows平台使用asyncio事件循环
            asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
        
        return asyncio.run(start_platform())
        
    except KeyboardInterrupt:
        print("\n用户中断，正在退出...")
        return 0
    except Exception as e:
        logging.error(f"平台运行异常: {e}")
        print(f"平台运行异常: {e}")
        return 1

if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)