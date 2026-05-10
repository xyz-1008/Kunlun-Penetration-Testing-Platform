"""
设置对话框 - 专家级配置管理界面
集成所有功能配置项，实现零外部依赖体验
"""

import os
import json
import logging
from pathlib import Path
from typing import Dict, Any

from PySide6.QtWidgets import (
    QDialog, QWidget, QVBoxLayout, QHBoxLayout, QTabWidget,
    QPushButton, QLabel, QLineEdit, QTextEdit, QComboBox,
    QGroupBox, QFormLayout, QCheckBox, QFileDialog,
    QTableWidget, QTableWidgetItem, QHeaderView, QMessageBox,
    QSpinBox, QDoubleSpinBox, QRadioButton, QButtonGroup,
    QScrollArea, QFrame, QListWidget, QListWidgetItem, QSplitter
)
from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QFont

logger = logging.getLogger(__name__)


class SettingsDialog(QDialog):
    """设置对话框"""
    
    settings_changed = Signal()
    
    def __init__(self, parent=None, config_manager=None):
        super().__init__(parent)
        self.config_manager = config_manager
        self.setWindowTitle("⚙️ 系统设置")
        self.setMinimumSize(900, 700)
        self.resize(1000, 750)
        
        self._create_ui()
        self._load_settings()
    
    def _create_ui(self):
        """创建UI"""
        layout = QVBoxLayout(self)
        
        # 主标签页
        self.tabs = QTabWidget()
        
        # 通用设置
        general_tab = self._create_general_tab()
        self.tabs.addTab(general_tab, "🔧 通用设置")
        
        # 网络设置
        network_tab = self._create_network_tab()
        self.tabs.addTab(network_tab, "🌐 网络设置")
        
        # API配置
        api_tab = self._create_api_tab()
        self.tabs.addTab(api_tab, "🔑 API配置")
        
        # 扫描策略
        scanner_tab = self._create_scanner_tab()
        self.tabs.addTab(scanner_tab, "🔍 扫描策略")
        
        # 代理设置
        proxy_tab = self._create_proxy_tab()
        self.tabs.addTab(proxy_tab, "🔌 代理设置")
        
        # 安全设置
        security_tab = self._create_security_tab()
        self.tabs.addTab(security_tab, "🔒 安全设置")
        
        # 外观设置
        appearance_tab = self._create_appearance_tab()
        self.tabs.addTab(appearance_tab, "🎨 外观设置")
        
        layout.addWidget(self.tabs)
        
        # 按钮区
        button_layout = QHBoxLayout()
        
        self.import_btn = QPushButton("📥 导入配置")
        self.import_btn.clicked.connect(self._import_config)
        button_layout.addWidget(self.import_btn)
        
        self.export_btn = QPushButton("📤 导出配置")
        self.export_btn.clicked.connect(self._export_config)
        button_layout.addWidget(self.export_btn)
        
        self.reset_btn = QPushButton("🔄 恢复默认")
        self.reset_btn.clicked.connect(self._reset_to_defaults)
        button_layout.addWidget(self.reset_btn)
        
        button_layout.addStretch()
        
        self.cancel_btn = QPushButton("❌ 取消")
        self.cancel_btn.clicked.connect(self.reject)
        button_layout.addWidget(self.cancel_btn)
        
        self.save_btn = QPushButton("💾 保存设置")
        self.save_btn.clicked.connect(self._save_settings)
        self.save_btn.setStyleSheet("background-color: #4a90d9; color: white; padding: 8px 20px; font-weight: bold;")
        button_layout.addWidget(self.save_btn)
        
        layout.addLayout(button_layout)
    
    def _create_general_tab(self) -> QWidget:
        """创建通用设置标签页"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # 应用设置
        app_group = QGroupBox("应用设置")
        app_layout = QFormLayout(app_group)
        
        self.app_name_input = QLineEdit()
        self.app_name_input.setPlaceholderText("昆仑安全测试平台 Pro")
        app_layout.addRow("应用名称:", self.app_name_input)
        
        self.language_combo = QComboBox()
        self.language_combo.addItems(["简体中文", "English", "日本語"])
        app_layout.addRow("语言:", self.language_combo)
        
        self.theme_combo = QComboBox()
        self.theme_combo.addItems(["深色主题", "浅色主题", "跟随系统"])
        app_layout.addRow("主题:", self.theme_combo)
        
        self.auto_update_check = QCheckBox("自动检查更新")
        app_layout.addRow("", self.auto_update_check)
        
        layout.addWidget(app_group)
        
        # 启动设置
        startup_group = QGroupBox("启动设置")
        startup_layout = QFormLayout(startup_group)
        
        self.auto_load_last_check = QCheckBox("启动时加载上次项目")
        startup_layout.addRow("", self.auto_load_last_check)
        
        self.show_welcome_check = QCheckBox("显示欢迎页面")
        startup_layout.addRow("", self.show_welcome_check)
        
        layout.addWidget(startup_group)
        
        # 数据存储
        storage_group = QGroupBox("数据存储")
        storage_layout = QFormLayout(storage_group)
        
        self.data_path_input = QLineEdit()
        self.data_path_input.setPlaceholderText("data/")
        storage_layout.addRow("数据目录:", self.data_path_input)
        
        browse_btn = QPushButton("📁 浏览")
        browse_btn.clicked.connect(self._browse_data_path)
        storage_layout.addRow("", browse_btn)
        
        self.auto_backup_check = QCheckBox("自动备份数据")
        storage_layout.addRow("", self.auto_backup_check)
        
        self.backup_interval_spin = QSpinBox()
        self.backup_interval_spin.setRange(1, 168)
        self.backup_interval_spin.setValue(24)
        self.backup_interval_spin.setSuffix(" 小时")
        storage_layout.addRow("备份间隔:", self.backup_interval_spin)
        
        layout.addWidget(storage_group)
        
        layout.addStretch()
        return widget
    
    def _create_network_tab(self) -> QWidget:
        """创建网络设置标签页"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # 超时设置
        timeout_group = QGroupBox("超时设置")
        timeout_layout = QFormLayout(timeout_group)
        
        self.connect_timeout_spin = QSpinBox()
        self.connect_timeout_spin.setRange(1, 120)
        self.connect_timeout_spin.setValue(10)
        self.connect_timeout_spin.setSuffix(" 秒")
        timeout_layout.addRow("连接超时:", self.connect_timeout_spin)
        
        self.read_timeout_spin = QSpinBox()
        self.read_timeout_spin.setRange(1, 300)
        self.read_timeout_spin.setValue(30)
        self.read_timeout_spin.setSuffix(" 秒")
        timeout_layout.addRow("读取超时:", self.read_timeout_spin)
        
        self.max_retries_spin = QSpinBox()
        self.max_retries_spin.setRange(0, 10)
        self.max_retries_spin.setValue(3)
        timeout_layout.addRow("最大重试次数:", self.max_retries_spin)
        
        layout.addWidget(timeout_group)
        
        # 并发设置
        concurrency_group = QGroupBox("并发设置")
        concurrency_layout = QFormLayout(concurrency_group)
        
        self.max_connections_spin = QSpinBox()
        self.max_connections_spin.setRange(1, 1000)
        self.max_connections_spin.setValue(100)
        concurrency_layout.addRow("最大连接数:", self.max_connections_spin)
        
        self.max_threads_spin = QSpinBox()
        self.max_threads_spin.setRange(1, 100)
        self.max_threads_spin.setValue(10)
        concurrency_layout.addRow("最大线程数:", self.max_threads_spin)
        
        self.rate_limit_spin = QSpinBox()
        self.rate_limit_spin.setRange(0, 10000)
        self.rate_limit_spin.setValue(0)
        self.rate_limit_spin.setSuffix(" 请求/秒 (0=无限制)")
        concurrency_layout.addRow("速率限制:", self.rate_limit_spin)
        
        layout.addWidget(concurrency_group)
        
        # User-Agent设置
        ua_group = QGroupBox("User-Agent设置")
        ua_layout = QFormLayout(ua_group)
        
        self.ua_combo = QComboBox()
        self.ua_combo.addItems([
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
            "自定义"
        ])
        ua_layout.addRow("预设UA:", self.ua_combo)
        
        self.custom_ua_input = QLineEdit()
        self.custom_ua_input.setPlaceholderText("自定义User-Agent")
        ua_layout.addRow("自定义UA:", self.custom_ua_input)
        
        layout.addWidget(ua_group)
        
        layout.addStretch()
        return widget
    
    def _create_api_tab(self) -> QWidget:
        """创建API配置标签页"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # 网络空间搜索引擎API
        search_engines_group = QGroupBox("网络空间搜索引擎")
        search_engines_layout = QVBoxLayout(search_engines_group)
        
        self.search_engines_table = QTableWidget()
        self.search_engines_table.setColumnCount(4)
        self.search_engines_table.setHorizontalHeaderLabels(["平台", "API Key", "API Secret", "启用"])
        self.search_engines_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        
        # 填充搜索引擎配置
        search_engines = [
            ("FOFA", "fofa_email", "fofa_key"),
            ("360 Quake", "quake_key", ""),
            ("鹰图 Hunter", "hunter_key", ""),
            ("Shodan", "shodan_key", ""),
            ("Censys", "censys_id", "censys_secret"),
            ("ZoomEye", "zoomeye_key", "")
        ]
        
        for name, key_field, secret_field in search_engines:
            row = self.search_engines_table.rowCount()
            self.search_engines_table.insertRow(row)
            self.search_engines_table.setItem(row, 0, QTableWidgetItem(name))
            
            key_item = QTableWidgetItem(self.config_manager.get_secret(key_field, "") if key_field else "")
            self.search_engines_table.setItem(row, 1, key_item)
            
            secret_item = QTableWidgetItem(self.config_manager.get_secret(secret_field, "") if secret_field else "")
            self.search_engines_table.setItem(row, 2, secret_item)
            
            enable_check = QCheckBox()
            enable_check.setChecked(self.config_manager.get(f"api.{name.lower().replace(' ', '_')}.enabled", False))
            self.search_engines_table.setCellWidget(row, 3, enable_check)
        
        search_engines_layout.addWidget(self.search_engines_table)
        layout.addWidget(search_engines_group)
        
        # AI辅助API
        ai_group = QGroupBox("AI辅助API")
        ai_layout = QFormLayout(ai_group)
        
        self.openai_key_input = QLineEdit()
        self.openai_key_input.setEchoMode(QLineEdit.Password)
        self.openai_key_input.setPlaceholderText("sk-...")
        ai_layout.addRow("OpenAI API Key:", self.openai_key_input)
        
        self.openai_model_combo = QComboBox()
        self.openai_model_combo.addItems(["gpt-4", "gpt-3.5-turbo", "gpt-4-turbo"])
        ai_layout.addRow("模型:", self.openai_model_combo)
        
        layout.addWidget(ai_group)
        
        # 漏洞情报API
        vuln_group = QGroupBox("漏洞情报API")
        vuln_layout = QFormLayout(vuln_group)
        
        self.nvd_key_input = QLineEdit()
        self.nvd_key_input.setEchoMode(QLineEdit.Password)
        vuln_layout.addRow("NVD API Key:", self.nvd_key_input)
        
        self.cnvd_key_input = QLineEdit()
        self.cnvd_key_input.setEchoMode(QLineEdit.Password)
        vuln_layout.addRow("CNVD API Key:", self.cnvd_key_input)
        
        layout.addWidget(vuln_group)
        
        layout.addStretch()
        return widget
    
    def _create_scanner_tab(self) -> QWidget:
        """创建扫描策略标签页"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # 扫描模式
        mode_group = QGroupBox("扫描模式")
        mode_layout = QFormLayout(mode_group)
        
        self.scan_mode_combo = QComboBox()
        self.scan_mode_combo.addItems(["快速扫描", "标准扫描", "深度扫描", "全面扫描"])
        mode_layout.addRow("扫描模式:", self.scan_mode_combo)
        
        self.passive_scan_check = QCheckBox("启用被动扫描")
        mode_layout.addRow("", self.passive_scan_check)
        
        self.active_scan_check = QCheckBox("启用主动扫描")
        mode_layout.addRow("", self.active_scan_check)
        
        layout.addWidget(mode_group)
        
        # 漏洞检测
        vuln_group = QGroupBox("漏洞检测")
        vuln_layout = QVBoxLayout(vuln_group)
        
        self.vuln_checks = {}
        vuln_types = [
            ("SQL注入", "sqli"),
            ("XSS跨站脚本", "xss"),
            ("CSRF跨站请求伪造", "csrf"),
            ("路径遍历", "path_traversal"),
            ("命令注入", "command_injection"),
            ("SSRF服务端请求伪造", "ssrf"),
            ("文件包含", "file_inclusion"),
            ("XML注入", "xml_injection"),
            ("LDAP注入", "ldap_injection"),
            ("弱口令", "weak_password"),
            ("敏感信息泄露", "info_disclosure"),
            ("安全配置错误", "misconfiguration")
        ]
        
        for name, key in vuln_types:
            check = QCheckBox(name)
            check.setChecked(self.config_manager.get(f"scanner.vuln_checks.{key}", True))
            self.vuln_checks[key] = check
            vuln_layout.addWidget(check)
        
        layout.addWidget(vuln_group)
        
        # 扫描范围
        scope_group = QGroupBox("扫描范围")
        scope_layout = QFormLayout(scope_group)
        
        self.max_pages_spin = QSpinBox()
        self.max_pages_spin.setRange(1, 10000)
        self.max_pages_spin.setValue(1000)
        scope_layout.addRow("最大页面数:", self.max_pages_spin)
        
        self.max_depth_spin = QSpinBox()
        self.max_depth_spin.setRange(1, 20)
        self.max_depth_spin.setValue(5)
        scope_layout.addRow("最大深度:", self.max_depth_spin)
        
        self.follow_redirects_check = QCheckBox("跟随重定向")
        scope_layout.addRow("", self.follow_redirects_check)
        
        self.respect_robots_check = QCheckBox("遵守robots.txt")
        scope_layout.addRow("", self.respect_robots_check)
        
        layout.addWidget(scope_group)
        
        layout.addStretch()
        return widget
    
    def _create_proxy_tab(self) -> QWidget:
        """创建代理设置标签页"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # 代理模式
        proxy_mode_group = QGroupBox("代理模式")
        proxy_mode_layout = QVBoxLayout(proxy_mode_group)
        
        self.proxy_mode_group = QButtonGroup()
        
        self.no_proxy_radio = QRadioButton("不使用代理")
        self.proxy_mode_group.addButton(self.no_proxy_radio, 0)
        proxy_mode_layout.addWidget(self.no_proxy_radio)
        
        self.system_proxy_radio = QRadioButton("使用系统代理")
        self.proxy_mode_group.addButton(self.system_proxy_radio, 1)
        proxy_mode_layout.addWidget(self.system_proxy_radio)
        
        self.custom_proxy_radio = QRadioButton("自定义代理")
        self.proxy_mode_group.addButton(self.custom_proxy_radio, 2)
        proxy_mode_layout.addWidget(self.custom_proxy_radio)
        
        layout.addWidget(proxy_mode_group)
        
        # 自定义代理设置
        custom_proxy_group = QGroupBox("自定义代理")
        custom_proxy_layout = QFormLayout(custom_proxy_group)
        
        self.proxy_type_combo = QComboBox()
        self.proxy_type_combo.addItems(["HTTP", "HTTPS", "SOCKS5", "SOCKS4"])
        custom_proxy_layout.addRow("代理类型:", self.proxy_type_combo)
        
        self.proxy_host_input = QLineEdit()
        self.proxy_host_input.setPlaceholderText("127.0.0.1")
        custom_proxy_layout.addRow("代理主机:", self.proxy_host_input)
        
        self.proxy_port_spin = QSpinBox()
        self.proxy_port_spin.setRange(1, 65535)
        self.proxy_port_spin.setValue(8080)
        custom_proxy_layout.addRow("代理端口:", self.proxy_port_spin)
        
        self.proxy_auth_check = QCheckBox("需要认证")
        custom_proxy_layout.addRow("", self.proxy_auth_check)
        
        self.proxy_user_input = QLineEdit()
        self.proxy_user_input.setPlaceholderText("用户名")
        custom_proxy_layout.addRow("用户名:", self.proxy_user_input)
        
        self.proxy_pass_input = QLineEdit()
        self.proxy_pass_input.setEchoMode(QLineEdit.Password)
        self.proxy_pass_input.setPlaceholderText("密码")
        custom_proxy_layout.addRow("密码:", self.proxy_pass_input)
        
        layout.addWidget(custom_proxy_group)
        
        # 拦截规则
        intercept_group = QGroupBox("拦截规则")
        intercept_layout = QVBoxLayout(intercept_group)
        
        self.intercept_patterns = QTextEdit()
        self.intercept_patterns.setPlaceholderText(
            "每行一个正则表达式，例如:\n"
            ".*\\.js$\n"
            ".*\\.css$\n"
            ".*\\.png$\n"
            ".*\\.jpg$"
        )
        self.intercept_patterns.setMaximumHeight(150)
        intercept_layout.addWidget(self.intercept_patterns)
        
        self.intercept_enabled_check = QCheckBox("启用拦截")
        intercept_layout.addWidget(self.intercept_enabled_check)
        
        layout.addWidget(intercept_group)
        
        layout.addStretch()
        return widget
    
    def _create_security_tab(self) -> QWidget:
        """创建安全设置标签页"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # 加密设置
        encryption_group = QGroupBox("加密设置")
        encryption_layout = QFormLayout(encryption_group)
        
        self.encryption_enabled_check = QCheckBox("启用数据加密")
        encryption_layout.addRow("", self.encryption_enabled_check)
        
        self.encryption_algo_combo = QComboBox()
        self.encryption_algo_combo.addItems(["AES-256-GCM", "AES-128-GCM", "ChaCha20-Poly1305"])
        encryption_layout.addRow("加密算法:", self.encryption_algo_combo)
        
        layout.addWidget(encryption_group)
        
        # 自动锁定
        lock_group = QGroupBox("自动锁定")
        lock_layout = QFormLayout(lock_group)
        
        self.auto_lock_check = QCheckBox("启用自动锁定")
        lock_layout.addRow("", self.auto_lock_check)
        
        self.auto_lock_timeout_spin = QSpinBox()
        self.auto_lock_timeout_spin.setRange(60, 3600)
        self.auto_lock_timeout_spin.setValue(300)
        self.auto_lock_timeout_spin.setSuffix(" 秒")
        lock_layout.addRow("锁定超时:", self.auto_lock_timeout_spin)
        
        self.require_password_check = QCheckBox("启动时需要密码")
        lock_layout.addRow("", self.require_password_check)
        
        layout.addWidget(lock_group)
        
        # 审计日志
        audit_group = QGroupBox("审计日志")
        audit_layout = QFormLayout(audit_group)
        
        self.audit_log_enabled_check = QCheckBox("启用审计日志")
        audit_layout.addRow("", self.audit_log_enabled_check)
        
        self.audit_log_path_input = QLineEdit()
        self.audit_log_path_input.setPlaceholderText("logs/audit.log")
        audit_layout.addRow("日志路径:", self.audit_log_path_input)
        
        self.audit_log_level_combo = QComboBox()
        self.audit_log_level_combo.addItems(["DEBUG", "INFO", "WARNING", "ERROR"])
        audit_layout.addRow("日志级别:", self.audit_log_level_combo)
        
        layout.addWidget(audit_group)
        
        # 安全扫描
        security_scan_group = QGroupBox("安全扫描")
        security_scan_layout = QFormLayout(security_scan_group)
        
        self.safe_mode_check = QCheckBox("安全模式（不发送攻击载荷）")
        security_scan_layout.addRow("", self.safe_mode_check)
        
        self.max_payload_size_spin = QSpinBox()
        self.max_payload_size_spin.setRange(100, 100000)
        self.max_payload_size_spin.setValue(10000)
        self.max_payload_size_spin.setSuffix(" 字节")
        security_scan_layout.addRow("最大载荷大小:", self.max_payload_size_spin)
        
        layout.addWidget(security_scan_group)
        
        layout.addStretch()
        return widget
    
    def _create_appearance_tab(self) -> QWidget:
        """创建外观设置标签页"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # 窗口设置
        window_group = QGroupBox("窗口设置")
        window_layout = QFormLayout(window_group)
        
        self.window_width_spin = QSpinBox()
        self.window_width_spin.setRange(800, 3840)
        self.window_width_spin.setValue(1600)
        window_layout.addRow("窗口宽度:", self.window_width_spin)
        
        self.window_height_spin = QSpinBox()
        self.window_height_spin.setRange(600, 2160)
        self.window_height_spin.setValue(950)
        window_layout.addRow("窗口高度:", self.window_height_spin)
        
        self.maximized_check = QCheckBox("启动时最大化")
        window_layout.addRow("", self.maximized_check)
        
        layout.addWidget(window_group)
        
        # 字体设置
        font_group = QGroupBox("字体设置")
        font_layout = QFormLayout(font_group)
        
        self.font_family_combo = QComboBox()
        self.font_family_combo.addItems(["Consolas", "Courier New", "Monaco", "Source Code Pro", "Fira Code"])
        font_layout.addRow("代码字体:", self.font_family_combo)
        
        self.font_size_spin = QSpinBox()
        self.font_size_spin.setRange(8, 24)
        self.font_size_spin.setValue(10)
        font_layout.addRow("字体大小:", self.font_size_spin)
        
        layout.addWidget(font_group)
        
        # 颜色主题
        color_group = QGroupBox("颜色主题")
        color_layout = QFormLayout(color_group)
        
        self.highlight_color_input = QLineEdit()
        self.highlight_color_input.setPlaceholderText("#4a90d9")
        color_layout.addRow("高亮颜色:", self.highlight_color_input)
        
        self.success_color_input = QLineEdit()
        self.success_color_input.setPlaceholderText("#4caf50")
        color_layout.addRow("成功颜色:", self.success_color_input)
        
        self.error_color_input = QLineEdit()
        self.error_color_input.setPlaceholderText("#f44336")
        color_layout.addRow("错误颜色:", self.error_color_input)
        
        self.warning_color_input = QLineEdit()
        self.warning_color_input.setPlaceholderText("#ff9800")
        color_layout.addRow("警告颜色:", self.warning_color_input)
        
        layout.addWidget(color_group)
        
        layout.addStretch()
        return widget
    
    def _load_settings(self):
        """加载设置"""
        if not self.config_manager:
            return
        
        # 通用设置
        self.app_name_input.setText(self.config_manager.get("app.name", "昆仑安全测试平台 Pro"))
        
        language = self.config_manager.get("app.language", "zh_CN")
        lang_map = {"zh_CN": 0, "en_US": 1, "ja_JP": 2}
        self.language_combo.setCurrentIndex(lang_map.get(language, 0))
        
        theme = self.config_manager.get("app.theme", "dark")
        theme_map = {"dark": 0, "light": 1, "system": 2}
        self.theme_combo.setCurrentIndex(theme_map.get(theme, 0))
        
        self.auto_update_check.setChecked(self.config_manager.get("app.auto_update", True))
        self.auto_load_last_check.setChecked(self.config_manager.get("app.auto_load_last", False))
        self.show_welcome_check.setChecked(self.config_manager.get("app.show_welcome", True))
        
        self.data_path_input.setText(self.config_manager.get("database.path", "data/"))
        self.auto_backup_check.setChecked(self.config_manager.get("database.auto_backup", True))
        self.backup_interval_spin.setValue(self.config_manager.get("database.backup_interval", 24))
        
        # 网络设置
        self.connect_timeout_spin.setValue(self.config_manager.get("network.connect_timeout", 10))
        self.read_timeout_spin.setValue(self.config_manager.get("network.read_timeout", 30))
        self.max_retries_spin.setValue(self.config_manager.get("network.max_retries", 3))
        self.max_connections_spin.setValue(self.config_manager.get("network.max_connections", 100))
        self.max_threads_spin.setValue(self.config_manager.get("network.max_threads", 10))
        self.rate_limit_spin.setValue(self.config_manager.get("network.rate_limit", 0))
        
        # 扫描策略
        scan_mode = self.config_manager.get("scanner.mode", "standard")
        mode_map = {"quick": 0, "standard": 1, "deep": 2, "full": 3}
        self.scan_mode_combo.setCurrentIndex(mode_map.get(scan_mode, 1))
        
        self.passive_scan_check.setChecked(self.config_manager.get("scanner.passive_scan", True))
        self.active_scan_check.setChecked(self.config_manager.get("scanner.active_scan", True))
        self.max_pages_spin.setValue(self.config_manager.get("scanner.max_pages", 1000))
        self.max_depth_spin.setValue(self.config_manager.get("scanner.max_depth", 5))
        self.follow_redirects_check.setChecked(self.config_manager.get("scanner.follow_redirects", True))
        self.respect_robots_check.setChecked(self.config_manager.get("scanner.respect_robots", False))
        
        # 代理设置
        proxy_mode = self.config_manager.get("proxy.mode", "no_proxy")
        proxy_mode_map = {"no_proxy": 0, "system": 1, "custom": 2}
        self.proxy_mode_group.button(proxy_mode_map.get(proxy_mode, 0)).setChecked(True)
        
        self.proxy_type_combo.setCurrentText(self.config_manager.get("proxy.type", "HTTP"))
        self.proxy_host_input.setText(self.config_manager.get("proxy.host", "127.0.0.1"))
        self.proxy_port_spin.setValue(self.config_manager.get("proxy.port", 8080))
        self.proxy_auth_check.setChecked(self.config_manager.get("proxy.auth_enabled", False))
        self.proxy_user_input.setText(self.config_manager.get("proxy.username", ""))
        
        self.intercept_patterns.setPlainText(self.config_manager.get("proxy.intercept_patterns", ""))
        self.intercept_enabled_check.setChecked(self.config_manager.get("proxy.intercept_enabled", False))
        
        # 安全设置
        self.encryption_enabled_check.setChecked(self.config_manager.get("security.encryption_enabled", True))
        self.auto_lock_check.setChecked(self.config_manager.get("security.auto_lock_enabled", False))
        self.auto_lock_timeout_spin.setValue(self.config_manager.get("security.auto_lock_timeout", 300))
        self.require_password_check.setChecked(self.config_manager.get("security.require_password", False))
        self.audit_log_enabled_check.setChecked(self.config_manager.get("security.audit_log_enabled", True))
        self.audit_log_path_input.setText(self.config_manager.get("security.audit_log_path", "logs/audit.log"))
        self.safe_mode_check.setChecked(self.config_manager.get("security.safe_mode", False))
        self.max_payload_size_spin.setValue(self.config_manager.get("security.max_payload_size", 10000))
        
        # 外观设置
        self.window_width_spin.setValue(self.config_manager.get("ui.window_width", 1600))
        self.window_height_spin.setValue(self.config_manager.get("ui.window_height", 950))
        self.maximized_check.setChecked(self.config_manager.get("ui.maximized", True))
        self.font_size_spin.setValue(self.config_manager.get("ui.font_size", 10))
    
    def _save_settings(self):
        """保存设置"""
        if not self.config_manager:
            return
        
        try:
            # 通用设置
            self.config_manager.set("app.name", self.app_name_input.text())
            lang_map = {0: "zh_CN", 1: "en_US", 2: "ja_JP"}
            self.config_manager.set("app.language", lang_map.get(self.language_combo.currentIndex(), "zh_CN"))
            theme_map = {0: "dark", 1: "light", 2: "system"}
            self.config_manager.set("app.theme", theme_map.get(self.theme_combo.currentIndex(), "dark"))
            self.config_manager.set("app.auto_update", self.auto_update_check.isChecked())
            self.config_manager.set("app.auto_load_last", self.auto_load_last_check.isChecked())
            self.config_manager.set("app.show_welcome", self.show_welcome_check.isChecked())
            self.config_manager.set("database.path", self.data_path_input.text())
            self.config_manager.set("database.auto_backup", self.auto_backup_check.isChecked())
            self.config_manager.set("database.backup_interval", self.backup_interval_spin.value())
            
            # 网络设置
            self.config_manager.set("network.connect_timeout", self.connect_timeout_spin.value())
            self.config_manager.set("network.read_timeout", self.read_timeout_spin.value())
            self.config_manager.set("network.max_retries", self.max_retries_spin.value())
            self.config_manager.set("network.max_connections", self.max_connections_spin.value())
            self.config_manager.set("network.max_threads", self.max_threads_spin.value())
            self.config_manager.set("network.rate_limit", self.rate_limit_spin.value())
            
            # 扫描策略
            mode_map = {0: "quick", 1: "standard", 2: "deep", 3: "full"}
            self.config_manager.set("scanner.mode", mode_map.get(self.scan_mode_combo.currentIndex(), "standard"))
            self.config_manager.set("scanner.passive_scan", self.passive_scan_check.isChecked())
            self.config_manager.set("scanner.active_scan", self.active_scan_check.isChecked())
            self.config_manager.set("scanner.max_pages", self.max_pages_spin.value())
            self.config_manager.set("scanner.max_depth", self.max_depth_spin.value())
            self.config_manager.set("scanner.follow_redirects", self.follow_redirects_check.isChecked())
            self.config_manager.set("scanner.respect_robots", self.respect_robots_check.isChecked())
            
            # 漏洞检测
            for key, check in self.vuln_checks.items():
                self.config_manager.set(f"scanner.vuln_checks.{key}", check.isChecked())
            
            # 代理设置
            proxy_mode_map = {0: "no_proxy", 1: "system", 2: "custom"}
            self.config_manager.set("proxy.mode", proxy_mode_map.get(self.proxy_mode_group.checkedId(), "no_proxy"))
            self.config_manager.set("proxy.type", self.proxy_type_combo.currentText())
            self.config_manager.set("proxy.host", self.proxy_host_input.text())
            self.config_manager.set("proxy.port", self.proxy_port_spin.value())
            self.config_manager.set("proxy.auth_enabled", self.proxy_auth_check.isChecked())
            self.config_manager.set("proxy.username", self.proxy_user_input.text())
            self.config_manager.set("proxy.intercept_patterns", self.intercept_patterns.toPlainText())
            self.config_manager.set("proxy.intercept_enabled", self.intercept_enabled_check.isChecked())
            
            # 安全设置
            self.config_manager.set("security.encryption_enabled", self.encryption_enabled_check.isChecked())
            self.config_manager.set("security.auto_lock_enabled", self.auto_lock_check.isChecked())
            self.config_manager.set("security.auto_lock_timeout", self.auto_lock_timeout_spin.value())
            self.config_manager.set("security.require_password", self.require_password_check.isChecked())
            self.config_manager.set("security.audit_log_enabled", self.audit_log_enabled_check.isChecked())
            self.config_manager.set("security.audit_log_path", self.audit_log_path_input.text())
            self.config_manager.set("security.safe_mode", self.safe_mode_check.isChecked())
            self.config_manager.set("security.max_payload_size", self.max_payload_size_spin.value())
            
            # 外观设置
            self.config_manager.set("ui.window_width", self.window_width_spin.value())
            self.config_manager.set("ui.window_height", self.window_height_spin.value())
            self.config_manager.set("ui.maximized", self.maximized_check.isChecked())
            self.config_manager.set("ui.font_size", self.font_size_spin.value())
            
            # 保存API密钥
            for row in range(self.search_engines_table.rowCount()):
                platform = self.search_engines_table.item(row, 0).text()
                api_key = self.search_engines_table.item(row, 1).text()
                api_secret = self.search_engines_table.item(row, 2).text()
                
                platform_key = platform.lower().replace(" ", "_")
                self.config_manager.set_secret(f"{platform_key}_key", api_key)
                if api_secret:
                    self.config_manager.set_secret(f"{platform_key}_secret", api_secret)
            
            QMessageBox.information(self, "成功", "设置已保存")
            self.settings_changed.emit()
            self.accept()
            
        except Exception as e:
            QMessageBox.critical(self, "错误", f"保存设置失败: {str(e)}")
    
    def _reset_to_defaults(self):
        """恢复默认设置"""
        reply = QMessageBox.question(
            self,
            "确认",
            "确定要恢复所有设置为默认值吗？",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            if self.config_manager:
                self.config_manager.reset_to_defaults()
                self._load_settings()
                QMessageBox.information(self, "成功", "已恢复默认设置")
    
    def _import_config(self):
        """导入配置"""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "导入配置",
            "",
            "JSON文件 (*.json);;所有文件 (*)"
        )
        
        if file_path:
            if self.config_manager:
                if self.config_manager.import_config(file_path):
                    self._load_settings()
                    QMessageBox.information(self, "成功", "配置导入成功")
                else:
                    QMessageBox.critical(self, "错误", "配置导入失败")
    
    def _export_config(self):
        """导出配置"""
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "导出配置",
            "config_export.json",
            "JSON文件 (*.json);;所有文件 (*)"
        )
        
        if file_path:
            if self.config_manager:
                if self.config_manager.export_config(file_path):
                    QMessageBox.information(self, "成功", f"配置已导出到: {file_path}")
                else:
                    QMessageBox.critical(self, "错误", "配置导出失败")
    
    def _browse_data_path(self):
        """浏览数据路径"""
        dir_path = QFileDialog.getExistingDirectory(self, "选择数据目录")
        if dir_path:
            self.data_path_input.setText(dir_path)
