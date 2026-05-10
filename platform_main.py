#!/usr/bin/env python3
"""
昆仑安全测试平台 Pro - 统一后端核心入口
基于20年渗透测试经验的专业级综合安全测试平台
昆仑安全实验室 荣誉出品

统一后端架构：
- Application单例，管理所有模块生命周期
- 模块注册中心：所有功能模块统一注册、初始化、销毁
- 事件总线：模块间通过事件总线解耦通信
- 数据总线：统一SQLite数据库，所有模块共享数据访问层
- 配置管理：单一config.yaml，控制所有模块行为
"""

import sys
import os
import logging
from pathlib import Path


def setup_project_env():
    """设置项目环境"""
    # 检测是否为PyInstaller打包环境
    if getattr(sys, 'frozen', False):
        # PyInstaller打包环境
        project_root = Path(sys.executable).parent
    else:
        # 开发环境
        project_root = Path(__file__).parent
    
    # 添加项目根目录到Python路径
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))
    
    # 创建必要目录
    directories = [
        'logs', 'config', 'data', 'temp', 
        'poc_library', 'plugins', 'reports', 'backup'
    ]
    
    for d in directories:
        (project_root / d).mkdir(exist_ok=True)
    
    # 配置日志
    log_file = project_root / 'logs' / 'platform.log'
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(str(log_file), encoding='utf-8'),
            logging.StreamHandler()
        ]
    )
    
    return project_root


def check_deps():
    """检查核心依赖"""
    required = ['PySide6', 'sqlalchemy', 'cryptography']
    missing = []
    
    for pkg in required:
        try:
            __import__(pkg.replace('-', '_'))
        except ImportError:
            missing.append(pkg)
    
    if missing:
        print(f"缺少依赖: {', '.join(missing)}")
        print(f"请运行: pip install {' '.join(missing)}")
        return False
    
    return True


def main():
    """应用主函数"""
    project_root = setup_project_env()
    logger = logging.getLogger(__name__)
    
    logger.info("=" * 60)
    logger.info("昆仑安全测试平台 Pro - 统一后端核心")
    logger.info("=" * 60)
    
    # 检查依赖
    if not check_deps():
        logger.error("依赖检查失败")
        return 1
    
    # 设置Qt高DPI
    if hasattr(sys, '_MEIPASS'):
        os.environ["QT_SCALE_FACTOR"] = "1"
    else:
        os.environ["QT_AUTO_SCREEN_SCALE_FACTOR"] = "1"
    
    try:
        from PySide6.QtWidgets import QApplication
        from PySide6.QtCore import Qt
        
        # 创建Qt应用
        app = QApplication(sys.argv)
        app.setApplicationName("昆仑安全测试平台 Pro")
        app.setApplicationVersion("1.0.0")
        app.setOrganizationName("昆仑安全实验室")
        
        # 初始化统一后端核心
        from core.application import initialize_app
        from core.config.config_manager import ConfigManager
        
        logger.info("初始化统一后端核心...")
        config = ConfigManager()
        platform_app = initialize_app(
            project_root=str(project_root),
            config_manager=config
        )
        
        logger.info("统一后端核心初始化完成")
        
        # 加载主界面
        logger.info("加载主界面...")
        from ui.kunlun_expert_platform import KunlunExpertPlatform
        
        main_window = KunlunExpertPlatform(app_instance=platform_app)
        main_window.showMaximized()
        
        logger.info("应用启动完成")
        
        # 进入事件循环
        return app.exec()
        
    except Exception as e:
        logger.exception("启动失败")
        try:
            from PySide6.QtWidgets import QMessageBox
            QMessageBox.critical(
                None,
                "启动错误",
                f"应用启动失败:\n{str(e)}\n\n查看日志: logs/platform.log"
            )
        except:
            print(f"启动失败: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
