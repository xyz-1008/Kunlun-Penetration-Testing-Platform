"""
网络空间搜索引擎模块 - 专家级实现
集成FOFA、360quake、鹰图、Shodan、Censys等主流平台
专为10年+经验白帽子、安全公司、SRC挖掘设计
"""

from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from datetime import datetime
import logging
import requests
import json
import base64
import hashlib
from enum import Enum

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QSplitter, QTabWidget,
    QPushButton, QLabel, QLineEdit, QTextEdit, QComboBox,
    QGroupBox, QFormLayout, QCheckBox, QFileDialog, QTableWidget,
    QTableWidgetItem, QHeaderView, QMessageBox, QProgressBar,
    QRadioButton, QButtonGroup, QScrollArea, QFrame, QToolBar,
    QMenu, QSpinBox, QDoubleSpinBox, QDialog, QDialogButtonBox
)
from PySide6.QtCore import Qt, QThread, Signal, QTimer
from PySide6.QtGui import QColor, QFont, QTextCharFormat, QTextCursor, QAction

from .base import ModuleBase

logger = logging.getLogger(__name__)


class SearchPlatform(Enum):
    """搜索平台枚举"""
    FOFA = "fofa"
    QUAKE360 = "quake360"
    HUNTER = "hunter"
    SHODAN = "shodan"
    CENSYS = "censys"
    ZOOM_EYE = "zoomeye"


@dataclass
class PlatformConfig:
    """平台配置"""
    name: str
    api_url: str
    api_key: str = ""
    api_secret: str = ""
    enabled: bool = False
    max_results: int = 100
    timeout: int = 30


@dataclass
class SearchResult:
    """搜索结果"""
    platform: str
    ip: str
    port: int
    protocol: str
    title: str
    banner: str
    country: str
    city: str
    org: str
    domain: str
    last_seen: str
    raw_data: Dict[str, Any] = field(default_factory=dict)


class SearchWorker(QThread):
    """搜索工作线程"""
    progress = Signal(int, str)
    result = Signal(object)
    finished = Signal(int, str)
    
    def __init__(self, platform: str, query: str, config: Dict[str, Any]):
        super().__init__()
        self.platform = platform
        self.query = query
        self.config = config
        self._stop_flag = False
    
    def run(self):
        """执行搜索"""
        try:
            self.progress.emit(10, f"正在连接 {self.platform}...")
            
            if self.platform == "fofa":
                results = self._search_fofa()
            elif self.platform == "quake360":
                results = self._search_quake360()
            elif self.platform == "hunter":
                results = self._search_hunter()
            elif self.platform == "shodan":
                results = self._search_shodan()
            elif self.platform == "censys":
                results = self._search_censys()
            elif self.platform == "zoomeye":
                results = self._search_zoomeye()
            else:
                self.finished.emit(0, f"不支持的平台: {self.platform}")
                return
            
            self.progress.emit(90, f"处理 {len(results)} 条结果...")
            
            for i, result in enumerate(results):
                if self._stop_flag:
                    break
                self.result.emit(result)
                self.progress.emit(90 + int(i / len(results) * 10), f"处理结果 {i+1}/{len(results)}")
            
            self.finished.emit(len(results), f"搜索完成，共找到 {len(results)} 条结果")
            
        except Exception as e:
            logger.error(f"搜索失败: {e}")
            self.finished.emit(0, f"搜索失败: {str(e)}")
    
    def _search_fofa(self) -> List[SearchResult]:
        """FOFA搜索"""
        api_key = self.config.get("api_key", "")
        api_secret = self.config.get("api_secret", "")
        
        if not api_key or not api_secret:
            raise ValueError("FOFA API Key 和 Secret 不能为空")
        
        # FOFA API v1
        url = "https://fofa.info/api/v1/search/all"
        
        # 编码查询语句
        qbase64 = base64.b64encode(self.query.encode()).decode()
        
        params = {
            "email": api_key,
            "key": api_secret,
            "qbase64": qbase64,
            "size": self.config.get("max_results", 100),
            "page": 1,
            "fields": "ip,port,protocol,title,banner,country,city,org,domain,lastupdatetime"
        }
        
        response = requests.get(url, params=params, timeout=self.config.get("timeout", 30))
        response.raise_for_status()
        
        data = response.json()
        if data.get("error"):
            raise ValueError(f"FOFA API 错误: {data.get('errmsg')}")
        
        results = []
        for item in data.get("results", []):
            results.append(SearchResult(
                platform="FOFA",
                ip=item[0],
                port=int(item[1]),
                protocol=item[2],
                title=item[3],
                banner=item[4],
                country=item[5],
                city=item[6],
                org=item[7],
                domain=item[8],
                last_seen=item[9],
                raw_data={"fofa": item}
            ))
        
        return results
    
    def _search_quake360(self) -> List[SearchResult]:
        """360 Quake搜索"""
        api_key = self.config.get("api_key", "")
        
        if not api_key:
            raise ValueError("Quake API Key 不能为空")
        
        url = "https://quake.360.net/api/v3/search/quake_service"
        
        headers = {
            "Content-Type": "application/json",
            "X-QuakeToken": api_key
        }
        
        payload = {
            "query": self.query,
            "start": 0,
            "size": self.config.get("max_results", 100)
        }
        
        response = requests.post(url, json=payload, headers=headers, timeout=self.config.get("timeout", 30))
        response.raise_for_status()
        
        data = response.json()
        if data.get("code") != 0:
            raise ValueError(f"Quake API 错误: {data.get('message')}")
        
        results = []
        for item in data.get("data", []):
            results.append(SearchResult(
                platform="Quake360",
                ip=item.get("ip", ""),
                port=item.get("port", 0),
                protocol=item.get("protocol", ""),
                title=item.get("title", ""),
                banner=item.get("banner", ""),
                country=item.get("location", {}).get("country_cn", ""),
                city=item.get("location", {}).get("city_cn", ""),
                org=item.get("organization", ""),
                domain=item.get("domain", ""),
                last_seen=item.get("updated_at", ""),
                raw_data={"quake": item}
            ))
        
        return results
    
    def _search_hunter(self) -> List[SearchResult]:
        """鹰图搜索"""
        api_key = self.config.get("api_key", "")
        
        if not api_key:
            raise ValueError("鹰图 API Key 不能为空")
        
        url = "https://hunter.qianxin.com/openApi/search"
        
        # 编码查询语句
        qbase64 = base64.b64encode(self.query.encode()).decode()
        
        params = {
            "api-key": api_key,
            "search": qbase64,
            "page": 1,
            "page_size": self.config.get("max_results", 100),
            "is_web": 1,
            "start_time": "2020-01-01",
            "end_time": datetime.now().strftime("%Y-%m-%d")
        }
        
        response = requests.get(url, params=params, timeout=self.config.get("timeout", 30))
        response.raise_for_status()
        
        data = response.json()
        if data.get("code") != 200:
            raise ValueError(f"鹰图 API 错误: {data.get('data', {}).get('msg')}")
        
        results = []
        for item in data.get("data", {}).get("arr", []):
            results.append(SearchResult(
                platform="Hunter",
                ip=item.get("ip", ""),
                port=item.get("port", 0),
                protocol=item.get("protocol", ""),
                title=item.get("web_title", ""),
                banner=item.get("component", []),
                country=item.get("country", ""),
                city=item.get("city", ""),
                org=item.get("company", ""),
                domain=item.get("domain", ""),
                last_seen=item.get("updated_at", ""),
                raw_data={"hunter": item}
            ))
        
        return results
    
    def _search_shodan(self) -> List[SearchResult]:
        """Shodan搜索"""
        api_key = self.config.get("api_key", "")
        
        if not api_key:
            raise ValueError("Shodan API Key 不能为空")
        
        url = "https://api.shodan.io/shodan/host/search"
        
        params = {
            "key": api_key,
            "query": self.query,
            "minify": True
        }
        
        response = requests.get(url, params=params, timeout=self.config.get("timeout", 30))
        response.raise_for_status()
        
        data = response.json()
        if "error" in data:
            raise ValueError(f"Shodan API 错误: {data.get('error')}")
        
        results = []
        for item in data.get("matches", []):
            results.append(SearchResult(
                platform="Shodan",
                ip=item.get("ip_str", ""),
                port=item.get("port", 0),
                protocol=item.get("transport", ""),
                title=item.get("title", ""),
                banner=item.get("data", ""),
                country=item.get("location", {}).get("country_name", ""),
                city=item.get("location", {}).get("city", ""),
                org=item.get("org", ""),
                domain=item.get("domains", [""])[0] if item.get("domains") else "",
                last_seen=item.get("timestamp", ""),
                raw_data={"shodan": item}
            ))
        
        return results
    
    def _search_censys(self) -> List[SearchResult]:
        """Censys搜索"""
        api_id = self.config.get("api_key", "")
        api_secret = self.config.get("api_secret", "")
        
        if not api_id or not api_secret:
            raise ValueError("Censys API ID 和 Secret 不能为空")
        
        url = "https://search.censys.io/api/v2/hosts/search"
        
        params = {
            "q": self.query,
            "per_page": self.config.get("max_results", 100)
        }
        
        response = requests.get(
            url,
            params=params,
            auth=(api_id, api_secret),
            timeout=self.config.get("timeout", 30)
        )
        response.raise_for_status()
        
        data = response.json()
        if not data.get("success"):
            raise ValueError(f"Censys API 错误: {data.get('error')}")
        
        results = []
        for item in data.get("result", {}).get("hits", []):
            results.append(SearchResult(
                platform="Censys",
                ip=item.get("ip", ""),
                port=0,
                protocol="",
                title=item.get("services", [{}])[0].get("banner", ""),
                banner=item.get("services", [{}])[0].get("banner", ""),
                country=item.get("location", {}).get("country", ""),
                city=item.get("location", {}).get("city", ""),
                org=item.get("autonomous_system", {}).get("organization", ""),
                domain=item.get("dns", {}).get("reverse_dns", [""])[0] if item.get("dns") else "",
                last_seen=item.get("last_updated_at", ""),
                raw_data={"censys": item}
            ))
        
        return results
    
    def _search_zoomeye(self) -> List[SearchResult]:
        """ZoomEye搜索"""
        api_key = self.config.get("api_key", "")
        
        if not api_key:
            raise ValueError("ZoomEye API Key 不能为空")
        
        url = "https://api.zoomeye.org/host/search"
        
        headers = {
            "API-KEY": api_key
        }
        
        params = {
            "query": self.query,
            "page": 1,
            "facet": "app,os"
        }
        
        response = requests.get(url, params=params, headers=headers, timeout=self.config.get("timeout", 30))
        response.raise_for_status()
        
        data = response.json()
        if "error" in data:
            raise ValueError(f"ZoomEye API 错误: {data.get('error')}")
        
        results = []
        for item in data.get("matches", []):
            results.append(SearchResult(
                platform="ZoomEye",
                ip=item.get("ip", ""),
                port=item.get("portinfo", {}).get("port", 0),
                protocol=item.get("portinfo", {}).get("transport", ""),
                title=item.get("title", ""),
                banner=item.get("portinfo", {}).get("banner", ""),
                country=item.get("geoinfo", {}).get("country", {}).get("names", {}).get("en", ""),
                city=item.get("geoinfo", {}).get("city", {}).get("names", {}).get("en", ""),
                org=item.get("geoinfo", {}).get("isp", ""),
                domain=item.get("rdns", ""),
                last_seen=item.get("timestamp", ""),
                raw_data={"zoomeye": item}
            ))
        
        return results
    
    def stop(self):
        """停止搜索"""
        self._stop_flag = True


class SpaceEngineModule(ModuleBase):
    """网络空间搜索引擎模块 - 专家级实现"""
    
    def __init__(self):
        super().__init__("SpaceEngine", "网络空间搜索引擎 - 集成FOFA、360、鹰图等主流平台")
        
        # 平台配置
        self.platform_configs: Dict[str, PlatformConfig] = {
            "fofa": PlatformConfig(
                name="FOFA",
                api_url="https://fofa.info/api/v1/search/all",
                enabled=False
            ),
            "quake360": PlatformConfig(
                name="360 Quake",
                api_url="https://quake.360.net/api/v3/search/quake_service",
                enabled=False
            ),
            "hunter": PlatformConfig(
                name="鹰图 Hunter",
                api_url="https://hunter.qianxin.com/openApi/search",
                enabled=False
            ),
            "shodan": PlatformConfig(
                name="Shodan",
                api_url="https://api.shodan.io/shodan/host/search",
                enabled=False
            ),
            "censys": PlatformConfig(
                name="Censys",
                api_url="https://search.censys.io/api/v2/hosts/search",
                enabled=False
            ),
            "zoomeye": PlatformConfig(
                name="ZoomEye",
                api_url="https://api.zoomeye.org/host/search",
                enabled=False
            )
        }
        
        # 搜索结果
        self.search_results: List[SearchResult] = []
        self.current_worker: Optional[SearchWorker] = None
        
        # 搜索历史
        self.search_history: List[str] = []
        
    def _create_ui(self) -> QWidget:
        """创建UI"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # 工具栏
        toolbar = self._create_toolbar()
        layout.addWidget(toolbar)
        
        # 主标签页
        main_tab = QTabWidget()
        
        # 搜索标签
        search_tab = self._create_search_tab()
        main_tab.addTab(search_tab, "🔍 搜索")
        
        # 结果标签
        results_tab = self._create_results_tab()
        main_tab.addTab(results_tab, "📊 结果")
        
        # 配置标签
        config_tab = self._create_config_tab()
        main_tab.addTab(config_tab, "⚙️ 配置")
        
        # 统计标签
        stats_tab = self._create_stats_tab()
        main_tab.addTab(stats_tab, "📈 统计")
        
        layout.addWidget(main_tab)
        
        return widget
    
    def _create_toolbar(self) -> QWidget:
        """创建工具栏"""
        toolbar = QWidget()
        layout = QHBoxLayout(toolbar)
        layout.setContentsMargins(0, 0, 0, 0)
        
        # 快速搜索
        self.quick_search_input = QLineEdit()
        self.quick_search_input.setPlaceholderText("快速搜索: ip='1.1.1.1' 或 title='login'")
        self.quick_search_input.returnPressed.connect(self._quick_search)
        layout.addWidget(self.quick_search_input)
        
        # 平台选择
        self.platform_combo = QComboBox()
        self.platform_combo.addItems([config.name for config in self.platform_configs.values()])
        layout.addWidget(QLabel("平台:"))
        layout.addWidget(self.platform_combo)
        
        # 搜索按钮
        search_btn = QPushButton("🔍 搜索")
        search_btn.clicked.connect(self._quick_search)
        search_btn.setStyleSheet("background-color: #4a90d9; color: white; padding: 5px 15px;")
        layout.addWidget(search_btn)
        
        # 停止按钮
        stop_btn = QPushButton("⏹️ 停止")
        stop_btn.clicked.connect(self._stop_search)
        layout.addWidget(stop_btn)
        
        layout.addStretch()
        
        return toolbar
    
    def _create_search_tab(self) -> QWidget:
        """创建搜索标签页"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # 搜索查询区
        query_group = QGroupBox("搜索查询")
        query_layout = QVBoxLayout(query_group)
        
        # 语法提示
        syntax_label = QLabel("💡 搜索语法提示:")
        syntax_label.setStyleSheet("color: #4a90d9; font-weight: bold;")
        query_layout.addWidget(syntax_label)
        
        syntax_text = QTextEdit()
        syntax_text.setReadOnly(True)
        syntax_text.setMaximumHeight(150)
        syntax_text.setFont(QFont("Consolas", 9))
        syntax_text.setPlainText(
            "FOFA语法示例:\n"
            "  ip='1.1.1.1'\n"
            "  title='login'\n"
            "  body='admin'\n"
            "  port='80'\n"
            "  protocol='http'\n"
            "  country='CN'\n\n"
            "Quake语法示例:\n"
            "  ip:1.1.1.1\n"
            "  title:login\n"
            "  app:Apache\n\n"
            "鹰图语法示例:\n"
            "  ip='1.1.1.1'\n"
            "  web.title='login'\n"
            "  web.body='admin'"
        )
        query_layout.addWidget(syntax_text)
        
        # 查询输入
        query_layout.addWidget(QLabel("查询语句:"))
        self.query_input = QTextEdit()
        self.query_input.setPlaceholderText("输入搜索查询语句...")
        self.query_input.setMaximumHeight(80)
        self.query_input.setFont(QFont("Consolas", 10))
        query_layout.addWidget(self.query_input)
        
        layout.addWidget(query_group)
        
        # 搜索选项
        options_group = QGroupBox("搜索选项")
        options_layout = QFormLayout(options_group)
        
        # 最大结果数
        self.max_results_spin = QSpinBox()
        self.max_results_spin.setRange(1, 1000)
        self.max_results_spin.setValue(100)
        options_layout.addRow("最大结果数:", self.max_results_spin)
        
        # 超时时间
        self.timeout_spin = QSpinBox()
        self.timeout_spin.setRange(5, 120)
        self.timeout_spin.setValue(30)
        options_layout.addRow("超时时间(秒):", self.timeout_spin)
        
        layout.addWidget(options_group)
        
        # 搜索历史
        history_group = QGroupBox("搜索历史")
        history_layout = QVBoxLayout(history_group)
        
        self.history_list = QTableWidget()
        self.history_list.setColumnCount(3)
        self.history_list.setHorizontalHeaderLabels(["时间", "平台", "查询语句"])
        self.history_list.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.history_list.setSelectionBehavior(QTableWidget.SelectRows)
        self.history_list.cellDoubleClicked.connect(self._load_history_query)
        history_layout.addWidget(self.history_list)
        
        layout.addWidget(history_group)
        
        return widget
    
    def _create_results_tab(self) -> QWidget:
        """创建结果标签页"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # 结果统计
        stats_layout = QHBoxLayout()
        self.result_count_label = QLabel("结果数: 0")
        self.result_count_label.setStyleSheet("font-weight: bold; font-size: 14px;")
        stats_layout.addWidget(self.result_count_label)
        
        self.export_btn = QPushButton("📥 导出结果")
        self.export_btn.clicked.connect(self._export_results)
        stats_layout.addWidget(self.export_btn)
        
        self.clear_btn = QPushButton("🗑️ 清空结果")
        self.clear_btn.clicked.connect(self._clear_results)
        stats_layout.addWidget(self.clear_btn)
        
        stats_layout.addStretch()
        layout.addLayout(stats_layout)
        
        # 结果表格
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(10)
        self.results_table.setHorizontalHeaderLabels([
            "平台", "IP", "端口", "协议", "标题", "国家", "城市", "组织", "域名", "更新时间"
        ])
        self.results_table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.results_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.results_table.cellDoubleClicked.connect(self._show_result_detail)
        layout.addWidget(self.results_table)
        
        # 进度条
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)
        
        # 状态标签
        self.status_label = QLabel("就绪")
        layout.addWidget(self.status_label)
        
        return widget
    
    def _create_config_tab(self) -> QWidget:
        """创建配置标签页"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # 平台配置列表
        config_group = QGroupBox("平台配置")
        config_layout = QVBoxLayout(config_group)
        
        self.config_table = QTableWidget()
        self.config_table.setColumnCount(5)
        self.config_table.setHorizontalHeaderLabels(["平台", "API Key", "API Secret", "启用", "操作"])
        self.config_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        
        # 填充配置
        for platform_id, config in self.platform_configs.items():
            row = self.config_table.rowCount()
            self.config_table.insertRow(row)
            
            # 平台名称
            self.config_table.setItem(row, 0, QTableWidgetItem(config.name))
            
            # API Key
            key_item = QTableWidgetItem(config.api_key)
            self.config_table.setItem(row, 1, key_item)
            
            # API Secret
            secret_item = QTableWidgetItem(config.api_secret)
            self.config_table.setItem(row, 2, secret_item)
            
            # 启用复选框
            enable_check = QCheckBox()
            enable_check.setChecked(config.enabled)
            enable_check.stateChanged.connect(lambda state, pid=platform_id: self._toggle_platform(pid, state))
            self.config_table.setCellWidget(row, 3, enable_check)
            
            # 测试按钮
            test_btn = QPushButton("🔗 测试连接")
            test_btn.clicked.connect(lambda checked, pid=platform_id: self._test_connection(pid))
            self.config_table.setCellWidget(row, 4, test_btn)
        
        config_layout.addWidget(self.config_table)
        
        # 保存按钮
        save_btn = QPushButton("💾 保存配置")
        save_btn.clicked.connect(self._save_platform_configs)
        save_btn.setStyleSheet("background-color: #4a90d9; color: white; padding: 8px; font-weight: bold;")
        config_layout.addWidget(save_btn)
        
        layout.addWidget(config_group)
        
        # 配置说明
        info_group = QGroupBox("配置说明")
        info_layout = QVBoxLayout(info_group)
        
        info_text = QTextEdit()
        info_text.setReadOnly(True)
        info_text.setMaximumHeight(200)
        info_text.setPlainText(
            "📋 配置说明:\n\n"
            "1. FOFA: 需要邮箱(API Key)和API Secret\n"
            "   获取地址: https://fofa.info/userInfo\n\n"
            "2. 360 Quake: 需要API Key\n"
            "   获取地址: https://quake.360.net\n\n"
            "3. 鹰图 Hunter: 需要API Key\n"
            "   获取地址: https://hunter.qianxin.com\n\n"
            "4. Shodan: 需要API Key\n"
            "   获取地址: https://account.shodan.io\n\n"
            "5. Censys: 需要API ID和Secret\n"
            "   获取地址: https://search.censys.io/account\n\n"
            "6. ZoomEye: 需要API Key\n"
            "   获取地址: https://www.zoomeye.org"
        )
        info_layout.addWidget(info_text)
        
        layout.addWidget(info_group)
        
        return widget
    
    def _create_stats_tab(self) -> QWidget:
        """创建统计标签页"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # 平台统计
        platform_stats_group = QGroupBox("平台统计")
        platform_stats_layout = QVBoxLayout(platform_stats_group)
        
        self.platform_stats_table = QTableWidget()
        self.platform_stats_table.setColumnCount(4)
        self.platform_stats_table.setHorizontalHeaderLabels(["平台", "搜索次数", "成功次数", "结果总数"])
        self.platform_stats_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        platform_stats_layout.addWidget(self.platform_stats_table)
        
        layout.addWidget(platform_stats_group)
        
        # 搜索趋势
        trend_group = QGroupBox("搜索趋势")
        trend_layout = QVBoxLayout(trend_group)
        
        self.trend_text = QTextEdit()
        self.trend_text.setReadOnly(True)
        self.trend_text.setMaximumHeight(200)
        trend_layout.addWidget(self.trend_text)
        
        layout.addWidget(trend_group)
        
        return widget
    
    def _quick_search(self):
        """快速搜索"""
        query = self.quick_search_input.text().strip()
        if not query:
            QMessageBox.warning(self.get_ui(), "警告", "请输入搜索查询语句")
            return
        
        self.query_input.setPlainText(query)
        self._execute_search()
    
    def _execute_search(self):
        """执行搜索"""
        query = self.query_input.toPlainText().strip()
        if not query:
            QMessageBox.warning(self.get_ui(), "警告", "请输入搜索查询语句")
            return
        
        platform_idx = self.platform_combo.currentIndex()
        platform_id = list(self.platform_configs.keys())[platform_idx]
        config = self.platform_configs[platform_id]
        
        if not config.enabled:
            QMessageBox.warning(self.get_ui(), "警告", f"请先启用 {config.name} 平台")
            return
        
        if not config.api_key:
            QMessageBox.warning(self.get_ui(), "警告", f"请先配置 {config.name} 的API Key")
            return
        
        # 清空结果
        self.search_results.clear()
        self.results_table.setRowCount(0)
        
        # 显示进度条
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        self.status_label.setText(f"正在搜索 {config.name}...")
        
        # 创建搜索线程
        search_config = {
            "api_key": config.api_key,
            "api_secret": config.api_secret,
            "max_results": self.max_results_spin.value(),
            "timeout": self.timeout_spin.value()
        }
        
        self.current_worker = SearchWorker(platform_id, query, search_config)
        self.current_worker.progress.connect(self._on_search_progress)
        self.current_worker.result.connect(self._on_search_result)
        self.current_worker.finished.connect(self._on_search_finished)
        self.current_worker.start()
        
        # 添加到搜索历史
        self._add_to_history(platform_id, query)
    
    def _on_search_progress(self, value: int, message: str):
        """搜索进度回调"""
        self.progress_bar.setValue(value)
        self.status_label.setText(message)
    
    def _on_search_result(self, result: SearchResult):
        """搜索结果回调"""
        self.search_results.append(result)
        
        # 添加到表格
        row = self.results_table.rowCount()
        self.results_table.insertRow(row)
        self.results_table.setItem(row, 0, QTableWidgetItem(result.platform))
        self.results_table.setItem(row, 1, QTableWidgetItem(result.ip))
        self.results_table.setItem(row, 2, QTableWidgetItem(str(result.port)))
        self.results_table.setItem(row, 3, QTableWidgetItem(result.protocol))
        self.results_table.setItem(row, 4, QTableWidgetItem(result.title[:50]))
        self.results_table.setItem(row, 5, QTableWidgetItem(result.country))
        self.results_table.setItem(row, 6, QTableWidgetItem(result.city))
        self.results_table.setItem(row, 7, QTableWidgetItem(result.org[:30]))
        self.results_table.setItem(row, 8, QTableWidgetItem(result.domain))
        self.results_table.setItem(row, 9, QTableWidgetItem(result.last_seen))
        
        # 更新结果计数
        self.result_count_label.setText(f"结果数: {len(self.search_results)}")
    
    def _on_search_finished(self, count: int, message: str):
        """搜索完成回调"""
        self.progress_bar.setVisible(False)
        self.status_label.setText(message)
        self.current_worker = None
        
        # 更新统计
        self._update_stats()
    
    def _stop_search(self):
        """停止搜索"""
        if self.current_worker:
            self.current_worker.stop()
            self.status_label.setText("搜索已停止")
    
    def _add_to_history(self, platform: str, query: str):
        """添加到搜索历史"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.search_history.insert(0, {"time": timestamp, "platform": platform, "query": query})
        
        # 更新历史表格
        row = self.history_list.rowCount()
        self.history_list.insertRow(row)
        self.history_list.setItem(row, 0, QTableWidgetItem(timestamp))
        self.history_list.setItem(row, 1, QTableWidgetItem(platform))
        self.history_list.setItem(row, 2, QTableWidgetItem(query[:50]))
        
        # 限制历史记录数量
        if self.history_list.rowCount() > 50:
            self.history_list.removeRow(self.history_list.rowCount() - 1)
    
    def _load_history_query(self, row: int, column: int):
        """加载历史查询"""
        if row < len(self.search_history):
            query = self.search_history[row]["query"]
            self.query_input.setPlainText(query)
            self.quick_search_input.setText(query)
    
    def _show_result_detail(self, row: int, column: int):
        """显示结果详情"""
        if row < len(self.search_results):
            result = self.search_results[row]
            
            detail_dialog = QDialog(self.get_ui())
            detail_dialog.setWindowTitle("结果详情")
            detail_dialog.setMinimumSize(600, 400)
            
            layout = QVBoxLayout(detail_dialog)
            
            # 基本信息
            info_group = QGroupBox("基本信息")
            info_layout = QFormLayout(info_group)
            info_layout.addRow("平台:", QLabel(result.platform))
            info_layout.addRow("IP:", QLabel(result.ip))
            info_layout.addRow("端口:", QLabel(str(result.port)))
            info_layout.addRow("协议:", QLabel(result.protocol))
            info_layout.addRow("标题:", QLabel(result.title))
            info_layout.addRow("国家:", QLabel(result.country))
            info_layout.addRow("城市:", QLabel(result.city))
            info_layout.addRow("组织:", QLabel(result.org))
            info_layout.addRow("域名:", QLabel(result.domain))
            info_layout.addRow("更新时间:", QLabel(result.last_seen))
            layout.addWidget(info_group)
            
            # 原始数据
            raw_group = QGroupBox("原始数据")
            raw_layout = QVBoxLayout(raw_group)
            raw_text = QTextEdit()
            raw_text.setReadOnly(True)
            raw_text.setFont(QFont("Consolas", 9))
            raw_text.setPlainText(json.dumps(result.raw_data, indent=2, ensure_ascii=False))
            raw_layout.addWidget(raw_text)
            layout.addWidget(raw_group)
            
            # 按钮
            button_box = QDialogButtonBox(QDialogButtonBox.Close)
            button_box.rejected.connect(detail_dialog.reject)
            layout.addWidget(button_box)
            
            detail_dialog.exec()
    
    def _export_results(self):
        """导出结果"""
        if not self.search_results:
            QMessageBox.warning(self.get_ui(), "警告", "没有结果可导出")
            return
        
        file_path, _ = QFileDialog.getSaveFileName(
            self.get_ui(),
            "导出结果",
            "search_results.json",
            "JSON文件 (*.json);;CSV文件 (*.csv);;所有文件 (*)"
        )
        
        if file_path:
            try:
                if file_path.endswith(".json"):
                    with open(file_path, "w", encoding="utf-8") as f:
                        json.dump([r.__dict__ for r in self.search_results], f, indent=2, ensure_ascii=False)
                elif file_path.endswith(".csv"):
                    import csv
                    with open(file_path, "w", encoding="utf-8-sig", newline="") as f:
                        writer = csv.writer(f)
                        writer.writerow(["平台", "IP", "端口", "协议", "标题", "国家", "城市", "组织", "域名", "更新时间"])
                        for r in self.search_results:
                            writer.writerow([r.platform, r.ip, r.port, r.protocol, r.title, r.country, r.city, r.org, r.domain, r.last_seen])
                
                QMessageBox.information(self.get_ui(), "成功", f"结果已导出到: {file_path}")
            except Exception as e:
                QMessageBox.critical(self.get_ui(), "错误", f"导出失败: {str(e)}")
    
    def _clear_results(self):
        """清空结果"""
        self.search_results.clear()
        self.results_table.setRowCount(0)
        self.result_count_label.setText("结果数: 0")
    
    def _toggle_platform(self, platform_id: str, state: int):
        """切换平台启用状态"""
        self.platform_configs[platform_id].enabled = bool(state)
    
    def _test_connection(self, platform_id: str):
        """测试平台连接"""
        config = self.platform_configs[platform_id]
        
        if not config.api_key:
            QMessageBox.warning(self.get_ui(), "警告", f"请先配置 {config.name} 的API Key")
            return
        
        # 简单的连接测试
        try:
            if platform_id == "fofa":
                url = "https://fofa.info/api/v1/info/my"
                params = {"email": config.api_key, "key": config.api_secret}
                response = requests.get(url, params=params, timeout=10)
                data = response.json()
                if data.get("error"):
                    QMessageBox.warning(self.get_ui(), "连接失败", f"FOFA: {data.get('errmsg')}")
                else:
                    QMessageBox.information(self.get_ui(), "连接成功", f"FOFA 连接成功\n用户: {data.get('username')}")
            
            elif platform_id == "shodan":
                url = "https://api.shodan.io/api-info"
                params = {"key": config.api_key}
                response = requests.get(url, params=params, timeout=10)
                if response.status_code == 200:
                    QMessageBox.information(self.get_ui(), "连接成功", "Shodan 连接成功")
                else:
                    QMessageBox.warning(self.get_ui(), "连接失败", f"Shodan: {response.text}")
            
            else:
                QMessageBox.information(self.get_ui(), "提示", f"{config.name} 连接测试功能开发中")
        
        except Exception as e:
            QMessageBox.critical(self.get_ui(), "错误", f"连接测试失败: {str(e)}")
    
    def _save_platform_configs(self):
        """保存平台配置"""
        # 从表格读取配置
        for row in range(self.config_table.rowCount()):
            platform_name = self.config_table.item(row, 0).text()
            api_key = self.config_table.item(row, 1).text()
            api_secret = self.config_table.item(row, 2).text()
            
            # 找到对应的平台ID
            for platform_id, config in self.platform_configs.items():
                if config.name == platform_name:
                    config.api_key = api_key
                    config.api_secret = api_secret
                    break
        
        QMessageBox.information(self.get_ui(), "成功", "平台配置已保存")
    
    def _update_stats(self):
        """更新统计信息"""
        # 平台统计
        platform_stats = {}
        for result in self.search_results:
            platform = result.platform
            if platform not in platform_stats:
                platform_stats[platform] = {"count": 0, "success": 0, "total": 0}
            platform_stats[platform]["count"] += 1
            platform_stats[platform]["success"] += 1
            platform_stats[platform]["total"] += 1
        
        # 更新表格
        self.platform_stats_table.setRowCount(0)
        for platform, stats in platform_stats.items():
            row = self.platform_stats_table.rowCount()
            self.platform_stats_table.insertRow(row)
            self.platform_stats_table.setItem(row, 0, QTableWidgetItem(platform))
            self.platform_stats_table.setItem(row, 1, QTableWidgetItem(str(stats["count"])))
            self.platform_stats_table.setItem(row, 2, QTableWidgetItem(str(stats["success"])))
            self.platform_stats_table.setItem(row, 3, QTableWidgetItem(str(stats["total"])))
        
        # 更新趋势
        trend_text = f"最近搜索统计:\n\n"
        trend_text += f"总搜索次数: {len(self.search_history)}\n"
        trend_text += f"总结果数: {len(self.search_results)}\n"
        trend_text += f"涉及平台: {len(platform_stats)}\n\n"
        
        for platform, stats in platform_stats.items():
            trend_text += f"{platform}: {stats['total']} 条结果\n"
        
        self.trend_text.setPlainText(trend_text)
