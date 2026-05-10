"""
昆仑安全测试平台 Pro - 核心应用
"""

import sys
import logging
from pathlib import Path
from PySide6.QtWidgets import QApplication, QMessageBox
from PySide6.QtCore import QTimer

logger = logging.getLogger(__name__)


class KunlunSecurityPlatformApp(QApplication):
    """主应用类"""

    def __init__(self, argv):
        super().__init__(argv)

        self.setApplicationName("昆仑安全测试平台 Pro")
        self.setApplicationVersion("1.0.0")
        self.setOrganizationName("昆仑安全实验室")

        self.config = None
        self.security = None
        self.database = None
        self.main_window = None

        QTimer.singleShot(0, self._initialize)

    def _initialize(self):
        """初始化组件"""
        try:
            logger.info("初始化应用...")

            # 加载配置
            try:
                from core.config.config_manager import ConfigManager
                self.config = ConfigManager()
            except Exception as e:
                logger.warning(f"配置加载失败: {e}")

            # 创建主窗口
            logger.info("加载主界面...")
            from ui.kunlun_expert_platform import KunlunExpertPlatform
            self.main_window = KunlunExpertPlatform(app_instance=self)
            self.main_window.showMaximized()

            logger.info("初始化完成")

        except Exception as e:
            logger.exception("初始化失败")
            QMessageBox.critical(
                None,
                "初始化错误",
                f"初始化失败:\n{str(e)}"
            )
            sys.exit(1)


# 全局应用访问
_app_instance = None


def get_app():
    """获取全局应用实例"""
    global _app_instance
    return _app_instance


def set_app(app):
    """设置全局应用实例"""
    global _app_instance
    _app_instance = app
