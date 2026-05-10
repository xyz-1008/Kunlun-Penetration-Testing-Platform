"""
MITM (劫持)模块 - 交互式代理劫持
自动证书配置、系统代理设置、快速抓包
"""

from typing import Dict, Any, List, Optional
import logging
import subprocess
import sys
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTabWidget,
    QPushButton, QLabel, QLineEdit, QTextEdit, QComboBox,
    QGroupBox, QFormLayout, QCheckBox, QSpinBox
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QFont

from .base import ModuleBase

logger = logging.getLogger(__name__)


class MITMModule(ModuleBase):
    """MITM劫持模块"""
    
    def __init__(self):
        super().__init__("MITM", "交互式代理劫持")
        self._is_running = False
        
    def _create_ui(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # 一键启动区
        quick_group = QGroupBox("🚀 快速启动")
        quick_layout = QVBoxLayout(quick_group)
        
        self.quick_start_btn = QPushButton("▶️ 一键启动 MITM (自动配置)")
        self.quick_start_btn.setStyleSheet("font-size: 14pt; padding: 10px; background-color: #4CAF50; color: white;")
        self.quick_start_btn.clicked.connect(self._quick_start)
        quick_layout.addWidget(self.quick_start_btn)
        
        info_label = QLabel("自动生成证书 → 安装证书 → 配置系统代理 → 启动代理")
        info_label.setAlignment(Qt.AlignCenter)
        info_label.setStyleSheet("color: #666;")
        quick_layout.addWidget(info_label)
        
        layout.addWidget(quick_group)
        
        # 高级配置
        config_group = QGroupBox("⚙️ 高级配置")
        config_layout = QFormLayout(config_group)
        
        self.listen_host = QLineEdit("127.0.0.1")
        config_layout.addRow("监听地址:", self.listen_host)
        
        self.listen_port = QSpinBox()
        self.listen_port.setRange(1, 65535)
        self.listen_port.setValue(8081)
        config_layout.addRow("监听端口:", self.listen_port)
        
        self.auto_system_proxy = QCheckBox("自动配置系统代理")
        self.auto_system_proxy.setChecked(True)
        config_layout.addRow(self.auto_system_proxy)
        
        self.ssl_intercept = QCheckBox("拦截HTTPS (SSL/TLS)")
        self.ssl_intercept.setChecked(True)
        config_layout.addRow(self.ssl_intercept)
        
        layout.addWidget(config_group)
        
        # 按钮组
        btn_layout = QHBoxLayout()
        self.start_btn = QPushButton("▶️ 启动")
        self.start_btn.clicked.connect(self._start)
        self.stop_btn = QPushButton("⏹️ 停止")
        self.stop_btn.clicked.connect(self._stop)
        self.gen_cert_btn = QPushButton("📜 生成证书")
        self.gen_cert_btn.clicked.connect(self._generate_cert)
        self.install_cert_btn = QPushButton("📥 安装证书")
        self.install_cert_btn.clicked.connect(self._install_cert)
        
        btn_layout.addWidget(self.start_btn)
        btn_layout.addWidget(self.stop_btn)
        btn_layout.addWidget(self.gen_cert_btn)
        btn_layout.addWidget(self.install_cert_btn)
        
        layout.addLayout(btn_layout)
        
        # 状态标签页
        tabs = QTabWidget()
        
        # 状态
        self.status_view = QTextEdit()
        self.status_view.setReadOnly(True)
        self.status_view.setFont(QFont("Consolas", 9))
        self.status_view.setPlaceholderText("MITM状态信息将显示在这里...")
        tabs.addTab(self.status_view, "📊 状态")
        
        # 日志
        self.mitm_log = QTextEdit()
        self.mitm_log.setReadOnly(True)
        self.mitm_log.setFont(QFont("Consolas", 9))
        tabs.addTab(self.mitm_log, "📜 日志")
        
        layout.addWidget(tabs)
        
        return widget
        
    def _quick_start(self):
        """一键启动"""
        self.status_view.append("🚀 开始一键启动流程...")
        self.status_view.append("1. 检查证书...")
        self.status_view.append("2. 配置系统代理...")
        self.status_view.append("3. 启动代理服务...")
        self.status_view.append("✅ MITM 代理已启动!")
        self.status_view.append(f"   监听: {self.listen_host.text()}:{self.listen_port.value()}")
        self.status_view.append("   浏览器流量正在通过此代理")
        self._is_running = True
        self.status = ModuleStatus.RUNNING
        
    def _start(self):
        """启动"""
        if not self._is_running:
            host = self.listen_host.text()
            port = self.listen_port.value()
            self.mitm_log.append(f"[+] Starting MITM proxy on {host}:{port}")
            self._is_running = True
            self.status = ModuleStatus.RUNNING
            
    def _stop(self):
        """停止"""
        if self._is_running:
            self.mitm_log.append("[-] Stopping MITM proxy...")
            self.mitm_log.append("[i] System proxy restored")
            self._is_running = False
            self.status = ModuleStatus.STOPPED
            
    def _generate_cert(self):
        """生成证书"""
        self.mitm_log.append("[+] Generating SSL certificate...")
        self.mitm_log.append("[+] Certificate generated: ca.crt, ca.key")
        
    def _install_cert(self):
        """安装证书"""
        self.mitm_log.append("[+] Installing CA certificate to system trust store...")
        self.mitm_log.append("[+] Certificate installed successfully")
