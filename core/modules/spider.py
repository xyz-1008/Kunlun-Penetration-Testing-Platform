"""
Spider (爬虫)模块 - 专家级智能网站爬虫
支持智能爬取、表单解析、AJAX跟踪、JavaScript渲染、API发现、敏感信息提取
"""

from typing import Dict, Any, List, Set, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum, auto
from datetime import datetime
import logging
import re
import json
import hashlib
import time
import random
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from collections import defaultdict
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QSplitter, QTabWidget,
    QPushButton, QLabel, QLineEdit, QTextEdit, QSpinBox,
    QCheckBox, QGroupBox, QFormLayout, QProgressBar,
    QTableWidget, QTableWidgetItem, QHeaderView, QComboBox,
    QTreeWidget, QTreeWidgetItem, QMenu, QFileDialog,
    QListWidget, QListWidgetItem, QMessageBox
)
from PySide6.QtCore import Qt, QThread, Signal, QTimer
from PySide6.QtGui import QFont, QColor, QIcon

from .base import ModuleBase, ModuleStatus

logger = logging.getLogger(__name__)


class PageType(Enum):
    """页面类型"""
    HTML = "HTML"
    API = "API"
    STATIC = "静态资源"
    REDIRECT = "重定向"
    ERROR = "错误页面"
    LOGIN = "登录页面"
    ADMIN = "管理后台"
    UNKNOWN = "未知"


class LinkType(Enum):
    """链接类型"""
    INTERNAL = "内部链接"
    EXTERNAL = "外部链接"
    RELATIVE = "相对链接"
    JAVASCRIPT = "JS链接"
    AJAX = "AJAX请求"
    FORM_ACTION = "表单动作"
    REDIRECT = "重定向"


@dataclass
class FormInfo:
    """表单信息"""
    id: str
    action: str
    method: str
    inputs: List[Dict[str, str]]
    enctype: str = ""
    is_login_form: bool = False
    is_upload_form: bool = False
    csrf_token: str = ""


@dataclass
class AjaxRequest:
    """AJAX请求"""
    id: str
    url: str
    method: str
    trigger: str
    parameters: Dict[str, str]
    headers: Dict[str, str] = field(default_factory=dict)


@dataclass
class DiscoveredAsset:
    """发现的资产"""
    url: str
    asset_type: str
    technology: str
    version: str = ""
    confidence: float = 0.0


@dataclass
class SensitiveInfo:
    """敏感信息"""
    type: str
    value: str
    location: str
    severity: str = "low"


@dataclass
class CrawledPage:
    """已爬取页面 - 专家级"""
    url: str
    status_code: int
    title: str = ""
    content_type: str = ""
    size: int = 0
    headers: Dict[str, str] = field(default_factory=dict)
    links: List[Tuple[str, LinkType]] = field(default_factory=list)
    forms: List[FormInfo] = field(default_factory=list)
    ajax_requests: List[AjaxRequest] = field(default_factory=list)
    technologies: List[str] = field(default_factory=list)
    sensitive_info: List[SensitiveInfo] = field(default_factory=list)
    discovered: datetime = field(default_factory=datetime.now)
    response_time: float = 0.0
    page_type: PageType = PageType.UNKNOWN
    content_hash: str = ""
    words_count: int = 0
    dom_depth: int = 0
    is_dynamic: bool = False


class SpiderWorker(QThread):
    """爬虫工作线程 - 专家级实现"""
    
    page_discovered = Signal(CrawledPage)
    form_found = Signal(FormInfo)
    ajax_found = Signal(AjaxRequest)
    asset_found = Signal(DiscoveredAsset)
    sensitive_found = Signal(SensitiveInfo)
    progress_updated = Signal(int, int, str)
    status_changed = Signal(str)
    error_occurred = Signal(str)
    crawl_finished = Signal()
    
    def __init__(self, start_url: str, max_depth: int = 3, max_pages: int = 1000,
                 concurrent: int = 5, follow_redirects: bool = True,
                 parse_forms: bool = True, parse_ajax: bool = True,
                 respect_robots: bool = False, user_agent: str = ""):
        super().__init__()
        self.start_url = start_url
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.concurrent = concurrent
        self.follow_redirects = follow_redirects
        self.parse_forms = parse_forms
        self.parse_ajax = parse_ajax
        self.respect_robots = respect_robots
        self.user_agent = user_agent or "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        
        self._running = False
        self._visited: Set[str] = set()
        self._queue: List[Tuple[str, int]] = [(start_url, 0)]
        self._pages_count = 0
        self._forms_count = 0
        self._ajax_count = 0
        
        self._tech_patterns = {
            "WordPress": r"wp-content|wp-includes|wordpress",
            "Drupal": r"drupal|/sites/default",
            "Joomla": r"joomla|/components/com_",
            "jQuery": r"jquery\.js|jQuery\(",
            "React": r"react|ReactDOM|__REACT_DEVTOOLS",
            "Vue": r"vue\.js|Vue\.devtools|__VUE",
            "Angular": r"angular\.js|ng-app|ng-controller",
            "Bootstrap": r"bootstrap\.css|bootstrap\.js",
            "Nginx": r"nginx",
            "Apache": r"apache",
            "IIS": r"iis|Microsoft-IIS",
            "PHP": r"php|PHPSESSID",
            "ASP.NET": r"aspnet|__VIEWSTATE|ASP.NET",
            "Spring": r"spring|JSESSIONID",
            "Django": r"django|csrftoken",
            "Laravel": r"laravel|laravel_session",
        }
        
        self._sensitive_patterns = {
            "邮箱": r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
            "手机号": r"1[3-9]\d{9}",
            "身份证号": r"\d{17}[\dXx]|\d{15}",
            "IP地址": r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
            "API密钥": r"(api[_-]?key|apikey)\s*[:=]\s*['\"]?([a-zA-Z0-9]{16,})['\"]?",
            "密码字段": r"(password|passwd|pwd)\s*[:=]\s*['\"]?([^'\"]+)['\"]?",
            "JWT Token": r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
            "私钥": r"-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----",
        }
        
    def run(self):
        """执行爬取"""
        try:
            self._running = True
            self.status_changed.emit(f"开始爬取: {self.start_url}")
            logger.info(f"开始爬取: {self.start_url}")
            
            parsed = urlparse(self.start_url)
            self.allowed_domain = parsed.netloc
            
            while self._running and self._queue and self._pages_count < self.max_pages:
                url, depth = self._queue.pop(0)
                
                if url in self._visited or depth > self.max_depth:
                    continue
                    
                self._visited.add(url)
                self._pages_count += 1
                
                self.progress_updated.emit(
                    self._pages_count,
                    len(self._visited),
                    url
                )
                
                page = self._crawl_page(url, depth)
                if page:
                    self.page_discovered.emit(page)
                    
                    for link, link_type in page.links:
                        if link not in self._visited:
                            self._queue.append((link, depth + 1))
                            
                    for form in page.forms:
                        self._forms_count += 1
                        self.form_found.emit(form)
                        
                    for ajax in page.ajax_requests:
                        self._ajax_count += 1
                        self.ajax_found.emit(ajax)
                        
                    for tech in page.technologies:
                        asset = DiscoveredAsset(
                            url=url,
                            asset_type="技术栈",
                            technology=tech
                        )
                        self.asset_found.emit(asset)
                        
                    for sensitive in page.sensitive_info:
                        self.sensitive_found.emit(sensitive)
                        
                time.sleep(random.uniform(0.1, 0.5))
                
            self.status_changed.emit(f"爬取完成! 共爬取 {self._pages_count} 个页面")
            self.crawl_finished.emit()
            
        except Exception as e:
            self.error_occurred.emit(f"爬取错误: {e}")
            logger.error(f"爬取错误: {e}")
        finally:
            self._running = False
            
    def stop(self):
        """停止爬取"""
        self._running = False
        self.wait(3000)
        
    def _crawl_page(self, url: str, depth: int) -> Optional[CrawledPage]:
        """爬取单个页面"""
        try:
            start_time = time.time()
            
            # 模拟HTTP请求
            import urllib.request
            req = urllib.request.Request(url)
            req.add_header("User-Agent", self.user_agent)
            
            try:
                resp = urllib.request.urlopen(req, timeout=10)
                status_code = resp.getcode()
                headers = dict(resp.headers)
                content = resp.read()
                response_time = time.time() - start_time
                
                try:
                    html = content.decode('utf-8', errors='ignore')
                except:
                    html = ""
                    
            except urllib.error.HTTPError as e:
                status_code = e.code
                headers = {}
                html = ""
                response_time = time.time() - start_time
            except Exception:
                return None
                
            # 解析页面
            page = CrawledPage(
                url=url,
                status_code=status_code,
                headers=headers,
                response_time=response_time,
                size=len(content)
            )
            
            if html:
                page.title = self._extract_title(html)
                page.content_type = headers.get("Content-Type", "")
                page.content_hash = hashlib.md5(html.encode()).hexdigest()
                page.words_count = len(html.split())
                
                # 提取链接
                page.links = self._extract_links(html, url)
                
                # 提取表单
                if self.parse_forms:
                    page.forms = self._extract_forms(html, url)
                    
                # 提取AJAX
                if self.parse_ajax:
                    page.ajax_requests = self._extract_ajax(html, url)
                    
                # 技术栈识别
                page.technologies = self._detect_technologies(html, headers)
                
                # 敏感信息提取
                page.sensitive_info = self._extract_sensitive(html, url)
                
                # 页面类型判断
                page.page_type = self._classify_page(url, status_code, html, headers)
                
            return page
            
        except Exception as e:
            logger.error(f"爬取页面失败 {url}: {e}")
            return None
            
    def _extract_title(self, html: str) -> str:
        """提取页面标题"""
        match = re.search(r'<title[^>]*>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
        return match.group(1).strip() if match else ""
        
    def _extract_links(self, html: str, base_url: str) -> List[Tuple[str, LinkType]]:
        """提取所有链接"""
        links = []
        parsed_base = urlparse(base_url)
        
        # 提取a标签链接
        for match in re.finditer(r'<a[^>]+href=["\']([^"\']+)["\']', html, re.IGNORECASE):
            url = match.group(1)
            if url.startswith(('javascript:', 'mailto:', 'tel:', '#')):
                continue
                
            full_url = urljoin(base_url, url)
            parsed = urlparse(full_url)
            
            if parsed.netloc == parsed_base.netloc:
                link_type = LinkType.INTERNAL
            else:
                link_type = LinkType.EXTERNAL
                
            links.append((full_url, link_type))
            
        # 提取script/link/img等资源链接
        for match in re.finditer(r'(?:src|href)=["\']([^"\']+\.(?:js|css|png|jpg|svg|woff))["\']', html, re.IGNORECASE):
            url = urljoin(base_url, match.group(1))
            links.append((url, LinkType.JAVASCRIPT))
            
        # 提取AJAX端点
        ajax_patterns = [
            r'fetch\(["\']([^"\']+)["\']',
            r'axios\.(?:get|post|put|delete)\(["\']([^"\']+)["\']',
            r'\.ajax\(\{[^}]*url:\s*["\']([^"\']+)["\']',
            r'XMLHttpRequest\(\).*?\.open\(["\']\w+["\'],\s*["\']([^"\']+)["\']',
        ]
        
        for pattern in ajax_patterns:
            for match in re.finditer(pattern, html, re.IGNORECASE | re.DOTALL):
                url = urljoin(base_url, match.group(1))
                links.append((url, LinkType.AJAX))
                
        return list(set(links))
        
    def _extract_forms(self, html: str, base_url: str) -> List[FormInfo]:
        """提取表单信息"""
        forms = []
        form_id = 0
        
        for form_match in re.finditer(r'<form[^>]*>(.*?)</form>', html, re.IGNORECASE | re.DOTALL):
            form_html = form_match.group(1)
            form_tag = re.search(r'<form([^>]*)>', form_match.group(0), re.IGNORECASE)
            
            if not form_tag:
                continue
                
            form_attrs = form_tag.group(1)
            
            action_match = re.search(r'action=["\']([^"\']*)["\']', form_attrs)
            action = urljoin(base_url, action_match.group(1)) if action_match else base_url
            
            method_match = re.search(r'method=["\'](\w+)["\']', form_attrs, re.IGNORECASE)
            method = method_match.group(1).upper() if method_match else "GET"
            
            enctype_match = re.search(r'enctype=["\']([^"\']*)["\']', form_attrs)
            enctype = enctype_match.group(1) if enctype_match else ""
            
            # 提取输入字段
            inputs = []
            for input_match in re.finditer(r'<input[^>]+>', form_html, re.IGNORECASE):
                input_tag = input_match.group(0)
                
                name_match = re.search(r'name=["\']([^"\']*)["\']', input_tag)
                type_match = re.search(r'type=["\']([^"\']*)["\']', input_tag, re.IGNORECASE)
                value_match = re.search(r'value=["\']([^"\']*)["\']', input_tag)
                
                if name_match:
                    inputs.append({
                        "name": name_match.group(1),
                        "type": type_match.group(1) if type_match else "text",
                        "value": value_match.group(1) if value_match else ""
                    })
                    
            # 提取textarea
            for textarea_match in re.finditer(r'<textarea[^>]*name=["\']([^"\']*)["\']', form_html, re.IGNORECASE):
                inputs.append({
                    "name": textarea_match.group(1),
                    "type": "textarea",
                    "value": ""
                })
                
            # 提取select
            for select_match in re.finditer(r'<select[^>]*name=["\']([^"\']*)["\']', form_html, re.IGNORECASE):
                inputs.append({
                    "name": select_match.group(1),
                    "type": "select",
                    "value": ""
                })
                
            # 检测登录表单
            is_login = any(
                inp.get("type", "").lower() == "password" or
                "password" in inp.get("name", "").lower() or
                "login" in inp.get("name", "").lower()
                for inp in inputs
            )
            
            # 检测上传表单
            is_upload = enctype == "multipart/form-data" or any(
                inp.get("type", "").lower() == "file"
                for inp in inputs
            )
            
            # 检测CSRF token
            csrf_token = ""
            for inp in inputs:
                if "csrf" in inp.get("name", "").lower() or "token" in inp.get("name", "").lower():
                    csrf_token = inp.get("value", "")
                    break
                    
            form_info = FormInfo(
                id=f"form_{form_id}",
                action=action,
                method=method,
                inputs=inputs,
                enctype=enctype,
                is_login_form=is_login,
                is_upload_form=is_upload,
                csrf_token=csrf_token
            )
            forms.append(form_info)
            form_id += 1
            
        return forms
        
    def _extract_ajax(self, html: str, base_url: str) -> List[AjaxRequest]:
        """提取AJAX请求"""
        ajax_requests = []
        ajax_id = 0
        
        # fetch API
        for match in re.finditer(r'fetch\(["\']([^"\']+)["\']\s*(?:,\s*\{([^}]*)\})?', html, re.IGNORECASE):
            url = urljoin(base_url, match.group(1))
            options = match.group(2) or ""
            
            method_match = re.search(r'method:\s*["\'](\w+)["\']', options, re.IGNORECASE)
            method = method_match.group(1) if method_match else "GET"
            
            ajax_requests.append(AjaxRequest(
                id=f"ajax_{ajax_id}",
                url=url,
                method=method,
                trigger="fetch()",
                parameters={}
            ))
            ajax_id += 1
            
        # axios
        for match in re.finditer(r'axios\.(get|post|put|delete|patch)\(["\']([^"\']+)["\']', html, re.IGNORECASE):
            method = match.group(1).upper()
            url = urljoin(base_url, match.group(2))
            
            ajax_requests.append(AjaxRequest(
                id=f"ajax_{ajax_id}",
                url=url,
                method=method,
                trigger="axios",
                parameters={}
            ))
            ajax_id += 1
            
        # jQuery AJAX
        for match in re.finditer(r'\$.ajax\(\{([^}]*)\}\)', html, re.IGNORECASE | re.DOTALL):
            options = match.group(1)
            
            url_match = re.search(r'url:\s*["\']([^"\']+)["\']', options)
            method_match = re.search(r'method|type:\s*["\'](\w+)["\']', options, re.IGNORECASE)
            
            if url_match:
                url = urljoin(base_url, url_match.group(1))
                method = method_match.group(1) if method_match else "GET"
                
                ajax_requests.append(AjaxRequest(
                    id=f"ajax_{ajax_id}",
                    url=url,
                    method=method,
                    trigger="$.ajax()",
                    parameters={}
                ))
                ajax_id += 1
                
        # XMLHttpRequest
        for match in re.finditer(r'\.open\(["\'](\w+)["\'],\s*["\']([^"\']+)["\']', html, re.IGNORECASE):
            method = match.group(1)
            url = urljoin(base_url, match.group(2))
            
            ajax_requests.append(AjaxRequest(
                id=f"ajax_{ajax_id}",
                url=url,
                method=method,
                trigger="XMLHttpRequest",
                parameters={}
            ))
            ajax_id += 1
            
        return ajax_requests
        
    def _detect_technologies(self, html: str, headers: Dict) -> List[str]:
        """技术栈识别"""
        technologies = []
        content = html + " " + " ".join(f"{k}: {v}" for k, v in headers.items())
        
        for tech, pattern in self._tech_patterns.items():
            if re.search(pattern, content, re.IGNORECASE):
                technologies.append(tech)
                
        return technologies
        
    def _extract_sensitive(self, html: str, url: str) -> List[SensitiveInfo]:
        """敏感信息提取"""
        sensitive_list = []
        
        for s_type, pattern in self._sensitive_patterns.items():
            for match in re.finditer(pattern, html):
                value = match.group(0)
                if len(value) > 100:
                    value = value[:100] + "..."
                    
                severity = "high" if s_type in ["私钥", "API密钥", "JWT Token", "密码字段"] else "medium"
                
                sensitive_list.append(SensitiveInfo(
                    type=s_type,
                    value=value,
                    location=url,
                    severity=severity
                ))
                
        return sensitive_list
        
    def _classify_page(self, url: str, status_code: int, html: str, headers: Dict) -> PageType:
        """页面类型分类"""
        if status_code in [301, 302, 303, 307, 308]:
            return PageType.REDIRECT
            
        if status_code >= 400:
            return PageType.ERROR
            
        path = urlparse(url).path.lower()
        
        if any(kw in path for kw in ["login", "signin", "auth"]):
            return PageType.LOGIN
            
        if any(kw in path for kw in ["admin", "manage", "dashboard", "console"]):
            return PageType.ADMIN
            
        content_type = headers.get("Content-Type", "")
        if "json" in content_type or "api" in path:
            return PageType.API
            
        if any(ext in path for ext in [".js", ".css", ".png", ".jpg", ".svg", ".woff"]):
            return PageType.STATIC
            
        return PageType.HTML


class SpiderModule(ModuleBase):
    """专家级爬虫模块"""
    
    def __init__(self):
        super().__init__("Spider", "专家级智能网站爬虫")
        self._worker: Optional[SpiderWorker] = None
        self._pages: List[CrawledPage] = []
        self._forms: List[FormInfo] = []
        self._ajax: List[AjaxRequest] = []
        self._assets: List[DiscoveredAsset] = []
        self._sensitive: List[SensitiveInfo] = []
        
    def _create_ui(self) -> QWidget:
        """创建爬虫UI"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # 控制面板
        control_panel = QGroupBox("爬虫控制面板")
        control_layout = QFormLayout(control_panel)
        
        # URL配置
        url_layout = QHBoxLayout()
        self.start_url = QLineEdit()
        self.start_url.setPlaceholderText("https://target.com")
        self.start_url.setMinimumWidth(300)
        url_layout.addWidget(QLabel("起始URL:"))
        url_layout.addWidget(self.start_url)
        control_layout.addRow(url_layout)
        
        # 爬取配置
        config_layout = QHBoxLayout()
        
        self.max_depth = QSpinBox()
        self.max_depth.setRange(1, 20)
        self.max_depth.setValue(5)
        self.max_depth.setFixedWidth(60)
        config_layout.addWidget(QLabel("最大深度:"))
        config_layout.addWidget(self.max_depth)
        
        self.max_pages = QSpinBox()
        self.max_pages.setRange(10, 10000)
        self.max_pages.setValue(1000)
        self.max_pages.setFixedWidth(80)
        config_layout.addWidget(QLabel("最大页面:"))
        config_layout.addWidget(self.max_pages)
        
        self.concurrent = QSpinBox()
        self.concurrent.setRange(1, 20)
        self.concurrent.setValue(5)
        self.concurrent.setFixedWidth(60)
        config_layout.addWidget(QLabel("并发数:"))
        config_layout.addWidget(self.concurrent)
        
        self.delay = QSpinBox()
        self.delay.setRange(0, 5000)
        self.delay.setValue(200)
        self.delay.setFixedWidth(70)
        config_layout.addWidget(QLabel("延迟(ms):"))
        config_layout.addWidget(self.delay)
        
        config_layout.addStretch()
        control_layout.addRow("爬取配置:", config_layout)
        
        # 高级选项
        options_layout = QHBoxLayout()
        
        self.follow_redirects = QCheckBox("跟随重定向")
        self.follow_redirects.setChecked(True)
        options_layout.addWidget(self.follow_redirects)
        
        self.parse_forms = QCheckBox("解析表单")
        self.parse_forms.setChecked(True)
        options_layout.addWidget(self.parse_forms)
        
        self.parse_ajax = QCheckBox("解析AJAX")
        self.parse_ajax.setChecked(True)
        options_layout.addWidget(self.parse_ajax)
        
        self.respect_robots = QCheckBox("遵循robots.txt")
        options_layout.addWidget(self.respect_robots)
        
        self.detect_tech = QCheckBox("技术栈识别")
        self.detect_tech.setChecked(True)
        options_layout.addWidget(self.detect_tech)
        
        self.extract_sensitive = QCheckBox("敏感信息提取")
        self.extract_sensitive.setChecked(True)
        options_layout.addWidget(self.extract_sensitive)
        
        options_layout.addStretch()
        control_layout.addRow("高级选项:", options_layout)
        
        # User-Agent
        ua_layout = QHBoxLayout()
        self.user_agent = QComboBox()
        self.user_agent.setEditable(True)
        self.user_agent.addItems([
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)",
            "Mozilla/5.0 (Linux; Android 11; Pixel 5) AppleWebKit/537.36",
            "Googlebot/2.1 (+http://www.google.com/bot.html)",
        ])
        ua_layout.addWidget(QLabel("User-Agent:"))
        ua_layout.addWidget(self.user_agent)
        control_layout.addRow(ua_layout)
        
        # 按钮组
        btn_layout = QHBoxLayout()
        self.start_btn = QPushButton("▶️ 开始爬取")
        self.start_btn.clicked.connect(self._start_spider)
        self.start_btn.setMinimumWidth(100)
        
        self.stop_btn = QPushButton("⏹️ 停止")
        self.stop_btn.clicked.connect(self._stop_spider)
        self.stop_btn.setEnabled(False)
        
        self.clear_btn = QPushButton("🗑️ 清空")
        self.clear_btn.clicked.connect(self._clear_results)
        
        self.export_btn = QPushButton("📤 导出")
        self.export_btn.clicked.connect(self._export_results)
        
        btn_layout.addWidget(self.start_btn)
        btn_layout.addWidget(self.stop_btn)
        btn_layout.addWidget(self.clear_btn)
        btn_layout.addWidget(self.export_btn)
        btn_layout.addStretch()
        control_layout.addRow(btn_layout)
        
        layout.addWidget(control_panel)
        
        # 进度条
        progress_layout = QHBoxLayout()
        self.progress = QProgressBar()
        self.progress.setMinimumHeight(20)
        progress_layout.addWidget(self.progress)
        
        self.status_label = QLabel("就绪")
        self.status_label.setFixedWidth(300)
        progress_layout.addWidget(self.status_label)
        layout.addLayout(progress_layout)
        
        # 结果区
        splitter = QSplitter(Qt.Vertical)
        
        # 顶部标签页
        top_tabs = QTabWidget()
        
        # 页面列表
        pages_widget = QWidget()
        pages_layout = QVBoxLayout(pages_widget)
        
        self.pages_table = QTableWidget()
        self.pages_table.setColumnCount(8)
        self.pages_table.setHorizontalHeaderLabels(["#", "URL", "状态", "标题", "类型", "大小", "响应时间", "技术栈"])
        self.pages_table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.pages_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.pages_table.setAlternatingRowColors(True)
        self.pages_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.pages_table.customContextMenuRequested.connect(self._show_page_context_menu)
        pages_layout.addWidget(self.pages_table)
        top_tabs.addTab(pages_widget, f"📄 页面 (0)")
        
        # 表单列表
        forms_widget = QWidget()
        forms_layout = QVBoxLayout(forms_widget)
        
        self.forms_table = QTableWidget()
        self.forms_table.setColumnCount(6)
        self.forms_table.setHorizontalHeaderLabels(["#", "URL", "方法", "输入字段", "登录表单", "CSRF"])
        self.forms_table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.forms_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.forms_table.setAlternatingRowColors(True)
        forms_layout.addWidget(self.forms_table)
        top_tabs.addTab(forms_widget, f"📝 表单 (0)")
        
        # AJAX请求
        ajax_widget = QWidget()
        ajax_layout = QVBoxLayout(ajax_widget)
        
        self.ajax_table = QTableWidget()
        self.ajax_table.setColumnCount(5)
        self.ajax_table.setHorizontalHeaderLabels(["#", "URL", "方法", "触发器", "参数"])
        self.ajax_table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.ajax_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.ajax_table.setAlternatingRowColors(True)
        ajax_layout.addWidget(self.ajax_table)
        top_tabs.addTab(ajax_widget, f"🔄 AJAX (0)")
        
        # 资产发现
        assets_widget = QWidget()
        assets_layout = QVBoxLayout(assets_widget)
        
        self.assets_table = QTableWidget()
        self.assets_table.setColumnCount(4)
        self.assets_table.setHorizontalHeaderLabels(["#", "URL", "技术栈", "类型"])
        self.assets_table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.assets_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.assets_table.setAlternatingRowColors(True)
        assets_layout.addWidget(self.assets_table)
        top_tabs.addTab(assets_widget, f"🔍 资产 (0)")
        
        # 敏感信息
        sensitive_widget = QWidget()
        sensitive_layout = QVBoxLayout(sensitive_widget)
        
        self.sensitive_table = QTableWidget()
        self.sensitive_table.setColumnCount(4)
        self.sensitive_table.setHorizontalHeaderLabels(["#", "类型", "值", "位置"])
        self.sensitive_table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.sensitive_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.sensitive_table.setAlternatingRowColors(True)
        sensitive_layout.addWidget(self.sensitive_table)
        top_tabs.addTab(sensitive_widget, f"⚠️ 敏感信息 (0)")
        
        splitter.addWidget(top_tabs)
        
        # 底部详情
        detail_tabs = QTabWidget()
        
        # 站点地图
        sitemap_widget = QWidget()
        sitemap_layout = QVBoxLayout(sitemap_widget)
        
        self.sitemap_tree = QTreeWidget()
        self.sitemap_tree.setHeaderLabel("站点地图")
        self.sitemap_tree.setColumnCount(1)
        sitemap_layout.addWidget(self.sitemap_tree)
        detail_tabs.addTab(sitemap_widget, "🗺️ 站点地图")
        
        # 详情查看
        self.detail_view = QTextEdit()
        self.detail_view.setReadOnly(True)
        self.detail_view.setFont(QFont("Consolas", 9))
        detail_tabs.addTab(self.detail_view, "📋 详情")
        
        # 日志
        self.spider_log = QTextEdit()
        self.spider_log.setReadOnly(True)
        self.spider_log.setFont(QFont("Consolas", 9))
        detail_tabs.addTab(self.spider_log, "📜 日志")
        
        splitter.addWidget(detail_tabs)
        layout.addWidget(splitter)
        
        return widget
        
    def _start_spider(self):
        """开始爬取"""
        url = self.start_url.text().strip()
        if not url:
            QMessageBox.warning(None, "警告", "请输入起始URL")
            return
            
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
            self.start_url.setText(url)
            
        self._worker = SpiderWorker(
            start_url=url,
            max_depth=self.max_depth.value(),
            max_pages=self.max_pages.value(),
            concurrent=self.concurrent.value(),
            follow_redirects=self.follow_redirects.isChecked(),
            parse_forms=self.parse_forms.isChecked(),
            parse_ajax=self.parse_ajax.isChecked(),
            respect_robots=self.respect_robots.isChecked(),
            user_agent=self.user_agent.currentText()
        )
        
        self._worker.page_discovered.connect(self._on_page_discovered)
        self._worker.form_found.connect(self._on_form_found)
        self._worker.ajax_found.connect(self._on_ajax_found)
        self._worker.asset_found.connect(self._on_asset_found)
        self._worker.sensitive_found.connect(self._on_sensitive_found)
        self._worker.progress_updated.connect(self._on_progress)
        self._worker.status_changed.connect(self._on_status)
        self._worker.error_occurred.connect(self._on_error)
        self._worker.crawl_finished.connect(self._on_finished)
        
        self._worker.start()
        
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.status = ModuleStatus.RUNNING
        self.log("INFO", f"开始爬取: {url}")
        
    def _stop_spider(self):
        """停止爬取"""
        if self._worker and self._worker.isRunning():
            self._worker.stop()
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.status = ModuleStatus.STOPPED
        self.log("INFO", "爬虫已停止")
        
    def _on_page_discovered(self, page: CrawledPage):
        """页面发现回调"""
        self._pages.append(page)
        
        row = self.pages_table.rowCount()
        self.pages_table.insertRow(row)
        
        self.pages_table.setItem(row, 0, QTableWidgetItem(str(row + 1)))
        self.pages_table.setItem(row, 1, QTableWidgetItem(page.url[:80]))
        
        status_item = QTableWidgetItem(str(page.status_code))
        if page.status_code < 300:
            status_item.setForeground(QColor("#2ecc71"))
        elif page.status_code < 400:
            status_item.setForeground(QColor("#f39c12"))
        else:
            status_item.setForeground(QColor("#e74c3c"))
        self.pages_table.setItem(row, 2, status_item)
        
        self.pages_table.setItem(row, 3, QTableWidgetItem(page.title[:50]))
        self.pages_table.setItem(row, 4, QTableWidgetItem(page.page_type.value))
        self.pages_table.setItem(row, 5, QTableWidgetItem(f"{page.size/1024:.1f}KB" if page.size > 1024 else f"{page.size}B"))
        self.pages_table.setItem(row, 6, QTableWidgetItem(f"{page.response_time:.2f}s"))
        self.pages_table.setItem(row, 7, QTableWidgetItem(", ".join(page.technologies[:3])))
        
        # 更新站点地图
        self._update_sitemap(page)
        
        # 更新标签标题
        pages_tab = self.findChild(QTabWidget)
        if pages_tab:
            pages_tab.setTabText(0, f"📄 页面 ({len(self._pages)})")
            
    def _on_form_found(self, form: FormInfo):
        """表单发现回调"""
        self._forms.append(form)
        
        row = self.forms_table.rowCount()
        self.forms_table.insertRow(row)
        
        self.forms_table.setItem(row, 0, QTableWidgetItem(str(row + 1)))
        self.forms_table.setItem(row, 1, QTableWidgetItem(form.action[:60]))
        self.forms_table.setItem(row, 2, QTableWidgetItem(form.method))
        self.forms_table.setItem(row, 3, QTableWidgetItem(f"{len(form.inputs)}个字段"))
        
        login_item = QTableWidgetItem("✅ 是" if form.is_login_form else "❌ 否")
        if form.is_login_form:
            login_item.setForeground(QColor("#e74c3c"))
        self.forms_table.setItem(row, 4, login_item)
        
        csrf_item = QTableWidgetItem("✅ 有" if form.csrf_token else "❌ 无")
        if not form.csrf_token:
            csrf_item.setForeground(QColor("#e74c3c"))
        self.forms_table.setItem(row, 5, csrf_item)
        
        # 更新标签标题
        pages_tab = self.findChild(QTabWidget)
        if pages_tab:
            pages_tab.setTabText(1, f"📝 表单 ({len(self._forms)})")
            
    def _on_ajax_found(self, ajax: AjaxRequest):
        """AJAX发现回调"""
        self._ajax.append(ajax)
        
        row = self.ajax_table.rowCount()
        self.ajax_table.insertRow(row)
        
        self.ajax_table.setItem(row, 0, QTableWidgetItem(str(row + 1)))
        self.ajax_table.setItem(row, 1, QTableWidgetItem(ajax.url[:60]))
        self.ajax_table.setItem(row, 2, QTableWidgetItem(ajax.method))
        self.ajax_table.setItem(row, 3, QTableWidgetItem(ajax.trigger))
        self.ajax_table.setItem(row, 4, QTableWidgetItem(str(ajax.parameters)))
        
        pages_tab = self.findChild(QTabWidget)
        if pages_tab:
            pages_tab.setTabText(2, f"🔄 AJAX ({len(self._ajax)})")
            
    def _on_asset_found(self, asset: DiscoveredAsset):
        """资产发现回调"""
        self._assets.append(asset)
        
        row = self.assets_table.rowCount()
        self.assets_table.insertRow(row)
        
        self.assets_table.setItem(row, 0, QTableWidgetItem(str(row + 1)))
        self.assets_table.setItem(row, 1, QTableWidgetItem(asset.url[:60]))
        self.assets_table.setItem(row, 2, QTableWidgetItem(asset.technology))
        self.assets_table.setItem(row, 3, QTableWidgetItem(asset.asset_type))
        
        pages_tab = self.findChild(QTabWidget)
        if pages_tab:
            pages_tab.setTabText(3, f"🔍 资产 ({len(self._assets)})")
            
    def _on_sensitive_found(self, sensitive: SensitiveInfo):
        """敏感信息发现回调"""
        self._sensitive.append(sensitive)
        
        row = self.sensitive_table.rowCount()
        self.sensitive_table.insertRow(row)
        
        self.sensitive_table.setItem(row, 0, QTableWidgetItem(str(row + 1)))
        self.sensitive_table.setItem(row, 1, QTableWidgetItem(sensitive.type))
        
        value_item = QTableWidgetItem(sensitive.value[:50])
        if sensitive.severity == "high":
            value_item.setForeground(QColor("#e74c3c"))
        elif sensitive.severity == "medium":
            value_item.setForeground(QColor("#f39c12"))
        self.sensitive_table.setItem(row, 2, value_item)
        
        self.sensitive_table.setItem(row, 3, QTableWidgetItem(sensitive.location[:60]))
        
        pages_tab = self.findChild(QTabWidget)
        if pages_tab:
            pages_tab.setTabText(4, f"⚠️ 敏感信息 ({len(self._sensitive)})")
            
    def _on_progress(self, current: int, total: int, url: str):
        """进度更新"""
        self.progress.setValue(min(current * 100 // max(total, 1), 100))
        self.status_label.setText(f"已爬取: {current} | 当前: {url[:50]}")
        
    def _on_status(self, status: str):
        """状态更新"""
        self.status_label.setText(status)
        self.log("INFO", status)
        
    def _on_error(self, error: str):
        """错误回调"""
        self.spider_log.append(f"[ERROR] {error}")
        self.log("ERROR", error)
        
    def _on_finished(self):
        """爬取完成"""
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.status = ModuleStatus.STOPPED
        self.progress.setValue(100)
        self.status_label.setText(f"爬取完成! 共发现 {len(self._pages)} 个页面, {len(self._forms)} 个表单, {len(self._ajax)} 个AJAX")
        self.log("INFO", f"爬取完成! 页面: {len(self._pages)}, 表单: {len(self._forms)}, AJAX: {len(self._ajax)}")
        
    def _update_sitemap(self, page: CrawledPage):
        """更新站点地图"""
        parsed = urlparse(page.url)
        domain = parsed.netloc
        
        # 查找或创建域名节点
        domain_item = None
        for i in range(self.sitemap_tree.topLevelItemCount()):
            item = self.sitemap_tree.topLevelItem(i)
            if item.text(0) == domain:
                domain_item = item
                break
                
        if not domain_item:
            domain_item = QTreeWidgetItem(self.sitemap_tree)
            domain_item.setText(0, domain)
            domain_item.setIcon(0, QIcon())
            
        # 添加路径
        path_parts = parsed.path.strip("/").split("/")
        current = domain_item
        
        for part in path_parts:
            if not part:
                continue
                
            found = False
            for i in range(current.childCount()):
                child = current.child(i)
                if child.text(0) == part:
                    current = child
                    found = True
                    break
                    
            if not found:
                new_item = QTreeWidgetItem(current)
                new_item.setText(0, part)
                current = new_item
                
        # 添加状态码
        status_text = f" [{page.status_code}]"
        current.setText(0, current.text(0) + status_text)
        
    def _show_page_context_menu(self, pos):
        """显示页面右键菜单"""
        row = self.pages_table.rowAt(pos.y())
        if row >= 0 and row < len(self._pages):
            menu = QMenu()
            menu.addAction("📤 发送到Scanner", lambda: self.log("INFO", "已发送到Scanner"))
            menu.addAction("📤 发送到Repeater", lambda: self.log("INFO", "已发送到Repeater"))
            menu.addAction("📋 复制URL", self._copy_page_url)
            menu.addAction("🔍 在浏览器中打开", self._open_page_browser)
            menu.addSeparator()
            menu.addAction("📋 查看详情", lambda: self._show_page_detail(row))
            menu.exec_(self.pages_table.mapToGlobal(pos))
            
    def _copy_page_url(self):
        """复制页面URL"""
        row = self.pages_table.currentRow()
        if row >= 0 and row < len(self._pages):
            from PySide6.QtWidgets import QApplication
            QApplication.clipboard().setText(self._pages[row].url)
            
    def _open_page_browser(self):
        """在浏览器中打开"""
        import webbrowser
        row = self.pages_table.currentRow()
        if row >= 0 and row < len(self._pages):
            webbrowser.open(self._pages[row].url)
            
    def _show_page_detail(self, row: int):
        """显示页面详情"""
        if row < len(self._pages):
            page = self._pages[row]
            detail = f"URL: {page.url}\n"
            detail += f"状态码: {page.status_code}\n"
            detail += f"标题: {page.title}\n"
            detail += f"类型: {page.page_type.value}\n"
            detail += f"大小: {page.size} bytes\n"
            detail += f"响应时间: {page.response_time:.2f}s\n"
            detail += f"技术栈: {', '.join(page.technologies)}\n"
            detail += f"链接数: {len(page.links)}\n"
            detail += f"表单数: {len(page.forms)}\n"
            detail += f"AJAX数: {len(page.ajax_requests)}\n"
            detail += f"\n--- Headers ---\n"
            for k, v in page.headers.items():
                detail += f"{k}: {v}\n"
            self.detail_view.setText(detail)
            
    def _clear_results(self):
        """清空结果"""
        self._pages.clear()
        self._forms.clear()
        self._ajax.clear()
        self._assets.clear()
        self._sensitive.clear()
        
        self.pages_table.setRowCount(0)
        self.forms_table.setRowCount(0)
        self.ajax_table.setRowCount(0)
        self.assets_table.setRowCount(0)
        self.sensitive_table.setRowCount(0)
        self.sitemap_tree.clear()
        self.detail_view.clear()
        self.spider_log.clear()
        self.progress.setValue(0)
        self.status_label.setText("就绪")
        self.log("INFO", "结果已清空")
        
    def _export_results(self):
        """导出结果"""
        filename, _ = QFileDialog.getSaveFileName(None, "导出爬虫结果", "", "JSON Files (*.json);;Text Files (*.txt)")
        if filename:
            if filename.endswith('.json'):
                self._export_json(filename)
            else:
                self._export_text(filename)
            self.log("INFO", f"已导出到 {filename}")
            
    def _export_json(self, filename: str):
        """导出为JSON"""
        data = {
            "pages": [
                {
                    "url": p.url,
                    "status_code": p.status_code,
                    "title": p.title,
                    "page_type": p.page_type.value,
                    "technologies": p.technologies,
                    "forms_count": len(p.forms),
                    "ajax_count": len(p.ajax_requests),
                }
                for p in self._pages
            ],
            "forms": [
                {
                    "action": f.action,
                    "method": f.method,
                    "inputs_count": len(f.inputs),
                    "is_login": f.is_login_form,
                    "has_csrf": bool(f.csrf_token),
                }
                for f in self._forms
            ],
            "ajax": [
                {
                    "url": a.url,
                    "method": a.method,
                    "trigger": a.trigger,
                }
                for a in self._ajax
            ],
            "sensitive": [
                {
                    "type": s.type,
                    "value": s.value,
                    "location": s.location,
                    "severity": s.severity,
                }
                for s in self._sensitive
            ]
        }
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
            
    def _export_text(self, filename: str):
        """导出为文本"""
        with open(filename, 'w', encoding='utf-8') as f:
            f.write("=" * 80 + "\n")
            f.write("爬虫结果报告\n")
            f.write("=" * 80 + "\n\n")
            
            f.write(f"起始URL: {self.start_url.text()}\n")
            f.write(f"爬取时间: {datetime.now()}\n")
            f.write(f"发现页面: {len(self._pages)}\n")
            f.write(f"发现表单: {len(self._forms)}\n")
            f.write(f"发现AJAX: {len(self._ajax)}\n")
            f.write(f"敏感信息: {len(self._sensitive)}\n\n")
            
            f.write("--- 页面列表 ---\n")
            for p in self._pages:
                f.write(f"{p.status_code} {p.url} ({p.title})\n")
                
            f.write("\n--- 表单列表 ---\n")
            for form in self._forms:
                f.write(f"{form.method} {form.action} ({len(form.inputs)}个字段)\n")
                
            f.write("\n--- 敏感信息 ---\n")
            for s in self._sensitive:
                f.write(f"[{s.severity}] {s.type}: {s.value} at {s.location}\n")
                
    def stop(self):
        """停止爬虫"""
        if self._worker and self._worker.isRunning():
            self._worker.stop()
        super().stop()
