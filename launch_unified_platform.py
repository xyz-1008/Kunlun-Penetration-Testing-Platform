#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
昆仑安全测试平台 - 统一启动脚本
基于20年渗透测试经验和360网络安全标准
昆仑安全实验室自主研发的专业级综合安全测试平台
"""

import os
import sys
import logging
from pathlib import Path

# 添加当前目录到Python路径
current_dir = Path(__file__).parent
sys.path.insert(0, str(current_dir))

class UnifiedPlatformLauncher:
    """统一平台启动器"""
    
    def __init__(self):
        self.logger = None
        self.project_root = current_dir
        
    def setup_logging(self):
        """设置统一的日志系统"""
        log_dir = self.project_root / "logs"
        log_dir.mkdir(exist_ok=True)
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_dir / "unified_platform.log", encoding='utf-8'),
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging.getLogger(__name__)
        
    def create_directories(self):
        """创建必要的目录结构"""
        directories = [
            "logs", "config", "data", "poc_library", 
            "plugins", "reports", "temp", "backup"
        ]
        
        for directory in directories:
            dir_path = self.project_root / directory
            dir_path.mkdir(exist_ok=True)
            self.logger.info(f"创建目录: {directory}")
            
    def check_dependencies(self):
        """检查依赖库"""
        required_packages = [
            'PySide6', 'aiohttp', 'cryptography', 'bcrypt', 
            'sqlalchemy', 'requests', 'bs4', 'psutil'
        ]
        
        missing_packages = []
        for package in required_packages:
            try:
                __import__(package.replace('-', '_'))
            except ImportError:
                missing_packages.append(package)
        
        if missing_packages:
            self.logger.error("缺少必要的依赖库:")
            for package in missing_packages:
                self.logger.error(f"  - {package}")
            self.logger.error("\n请运行以下命令安装依赖:")
            self.logger.error(f"pip install {' '.join(missing_packages)}")
            return False
        
        self.logger.info("所有依赖检查通过")
        return True
        
    def display_welcome(self):
        """显示欢迎信息"""
        welcome_text = """
╔════════════════════════════════════════════════════════════════╗
║                    昆仑安全测试平台 Pro                          ║
║           基于20年渗透测试经验的专业级综合安全测试平台          ║
║                   昆仑安全实验室 荣誉出品                         ║
╚════════════════════════════════════════════════════════════════╝

平台特性:
✓ 专业级代理拦截和流量分析
✓ 智能漏洞扫描和风险评估  
✓ 多协议攻击工具和爆破功能
✓ 高级编码解码和Payload生成
✓ 自动化漏洞验证和攻击链构建
✓ 网络空间搜索引擎集成（FOFA、360 Quake、Hunter）
✓ 实时团队协作和项目管理
✓ 跨平台兼容和专业UI设计

技术架构:
• 模块化架构设计，易于扩展
• 高性能异步处理引擎
• 完善的安全加固机制
• 专业级深色主题界面
• 统一启动机制，单进程运行

版本: v1.0.0 | 发布日期: 2026-04-18
© 2026 昆仑安全实验室 版权所有
"""
        print(welcome_text)
        self.logger.info("昆仑安全测试平台 Pro 启动")
        
    def launch_unified_platform(self):
        """启动统一平台"""
        try:
            from core.app import KunlunSecurityPlatformApp
            
            self.logger.info("正在初始化应用...")
            
            # 创建应用实例
            app = KunlunSecurityPlatformApp(sys.argv)
            
            self.logger.info("昆仑安全测试平台 Pro 启动完成")
            
            # 启动应用
            return app.exec()
            
        except Exception as e:
            self.logger.error(f"启动平台失败: {e}", exc_info=True)
            print(f"错误: {e}")
            return 1
            
    def run(self):
        """运行统一启动器"""
        print("正在启动昆仑安全测试平台 Pro...")
        
        # 设置日志
        self.setup_logging()
        
        # 检查依赖
        if not self.check_dependencies():
            return 1
        
        # 创建目录结构
        self.create_directories()
        
        # 显示欢迎信息
        self.display_welcome()
        
        # 启动统一平台
        try:
            # 设置高DPI支持
            if hasattr(sys, '_MEIPASS'):
                os.environ["QT_SCALE_FACTOR"] = "1"
            else:
                os.environ["QT_AUTO_SCREEN_SCALE_FACTOR"] = "1"
            
            return self.launch_unified_platform()
            
        except KeyboardInterrupt:
            self.logger.info("用户中断，正在退出...")
            print("\n用户中断，正在退出...")
            return 0
        except Exception as e:
            self.logger.error(f"平台运行异常: {e}", exc_info=True)
            print(f"平台运行异常: {e}")
            return 1

def main():
    """主函数"""
    launcher = UnifiedPlatformLauncher()
    exit_code = launcher.run()
    sys.exit(exit_code)

if __name__ == "__main__":
    main()