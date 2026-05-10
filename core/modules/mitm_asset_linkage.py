"""
MITM代理与资产识别引擎深度联动模块
实现流量自动提取资产、指纹识别、资产入库、技术栈标签显示
"""

import re
import logging
import threading
from typing import Dict, List, Any, Optional, Callable, Set
from dataclasses import dataclass, field
from datetime import datetime
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


@dataclass
class DiscoveredAsset:
    """发现的资产"""
    id: str
    timestamp: datetime
    domain: str = ""
    ip: str = ""
    port: int = 0
    protocol: str = ""
    url: str = ""
    api_endpoints: List[str] = field(default_factory=list)
    tech_stack: List[str] = field(default_factory=list)
    server_type: str = ""
    framework: str = ""
    cms: str = ""
    is_new: bool = True
    is_notified: bool = False


class AssetExtractor:
    """资产提取器"""
    
    def __init__(self):
        self._ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        self._domain_pattern = re.compile(
            r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}'
        )
        self._api_pattern = re.compile(r'(?:/api/|/v\d+/|/graphql)[^\s"\'<>]+')
        self._internal_ip_pattern = re.compile(
            r'\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|'
            r'172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|'
            r'192\.168\.\d{1,3}\.\d{1,3})\b'
        )
    
    def extract_from_request(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """从请求中提取资产信息"""
        url = request_data.get('url', '')
        headers = request_data.get('headers', {})
        body = request_data.get('body', '')
        
        extracted = {
            'domains': set(),
            'ips': set(),
            'ports': set(),
            'api_endpoints': set(),
        }
        
        # 解析URL
        try:
            parsed = urlparse(url)
            if parsed.hostname:
                if self._ip_pattern.match(parsed.hostname):
                    extracted['ips'].add(parsed.hostname)
                else:
                    extracted['domains'].add(parsed.hostname)
                
                if parsed.port:
                    extracted['ports'].add(parsed.port)
                elif parsed.scheme == 'https':
                    extracted['ports'].add(443)
                elif parsed.scheme == 'http':
                    extracted['ports'].add(80)
        except Exception:
            pass
        
        # 从Host头提取
        host = headers.get('Host', '')
        if host:
            host_parts = host.split(':')
            hostname = host_parts[0]
            if self._ip_pattern.match(hostname):
                extracted['ips'].add(hostname)
            else:
                extracted['domains'].add(hostname)
            
            if len(host_parts) > 1:
                try:
                    extracted['ports'].add(int(host_parts[1]))
                except ValueError:
                    pass
        
        # 从Body中提取IP和API端点
        body_str = body if isinstance(body, str) else body.decode('utf-8', errors='replace')
        
        for match in self._ip_pattern.finditer(body_str):
            ip = match.group()
            if not self._internal_ip_pattern.match(ip):
                extracted['ips'].add(ip)
        
        for match in self._api_pattern.finditer(body_str):
            extracted['api_endpoints'].add(match.group())
        
        # 从URL中提取API端点
        for match in self._api_pattern.finditer(url):
            extracted['api_endpoints'].add(match.group())
        
        return extracted
    
    def extract_from_response(self, response_data: Dict[str, Any]) -> Dict[str, Any]:
        """从响应中提取资产信息"""
        headers = response_data.get('headers', {})
        body = response_data.get('body', b'')
        
        extracted = {
            'server_type': '',
            'framework': '',
            'cms': '',
            'tech_stack': [],
            'ips': set(),
            'domains': set(),
        }
        
        # 分析响应头
        server = headers.get('Server', '')
        if server:
            extracted['server_type'] = server
            extracted['tech_stack'].append(f'Server:{server}')
            
            if 'nginx' in server.lower():
                extracted['tech_stack'].append('Nginx')
            elif 'apache' in server.lower():
                extracted['tech_stack'].append('Apache')
            elif 'iis' in server.lower():
                extracted['tech_stack'].append('IIS')
        
        x_powered = headers.get('X-Powered-By', '')
        if x_powered:
            extracted['tech_stack'].append(f'X-Powered-By:{x_powered}')
            
            if 'php' in x_powered.lower():
                extracted['framework'] = 'PHP'
                extracted['tech_stack'].append('PHP')
            elif 'asp.net' in x_powered.lower():
                extracted['framework'] = 'ASP.NET'
                extracted['tech_stack'].append('ASP.NET')
            elif 'express' in x_powered.lower():
                extracted['framework'] = 'Express'
                extracted['tech_stack'].append('Express')
        
        # 检测CMS特征
        body_str = body if isinstance(body, str) else body.decode('utf-8', errors='replace')
        
        cms_patterns = {
            'WordPress': [r'wp-content', r'wp-includes', r'wp-admin'],
            'Joomla': [r'/components/', r'/modules/', r'/templates/'],
            'Drupal': [r'/sites/', r'/core/', r'drupalSettings'],
            'Django': [r'csrfmiddlewaretoken', r'/static/admin/'],
            'Laravel': [r'laravel_session', r'/css/app.css'],
            'ThinkPHP': [r'thinkphp', r'TP_VERSION'],
        }
        
        for cms, patterns in cms_patterns.items():
            for pattern in patterns:
                if re.search(pattern, body_str, re.IGNORECASE):
                    extracted['cms'] = cms
                    extracted['tech_stack'].append(cms)
                    break
        
        # 从Body中提取IP和域名
        for match in self._ip_pattern.finditer(body_str):
            extracted['ips'].add(match.group())
        
        for match in self._domain_pattern.finditer(body_str):
            domain = match.group()
            if not domain.startswith('www.'):
                extracted['domains'].add(domain)
        
        return extracted


class FingerprintAnalyzer:
    """指纹分析器 - 异步调用资产指纹识别引擎"""
    
    def __init__(self):
        self._analysis_cache: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()
    
    def analyze_async(self, url: str, response_data: Dict[str, Any], 
                     callback: Optional[Callable] = None):
        """异步分析指纹"""
        def _analyze():
            try:
                result = self._analyze_fingerprint(url, response_data)
                
                with self._lock:
                    self._analysis_cache[url] = result
                
                if callback:
                    callback(result)
                    
            except Exception as e:
                logger.error(f"指纹分析失败: {e}")
        
        thread = threading.Thread(target=_analyze, daemon=True)
        thread.start()
    
    def _analyze_fingerprint(self, url: str, response_data: Dict[str, Any]) -> Dict[str, Any]:
        """执行指纹分析"""
        headers = response_data.get('headers', {})
        body = response_data.get('body', b'')
        body_str = body if isinstance(body, str) else body.decode('utf-8', errors='replace')
        
        result = {
            'url': url,
            'server': headers.get('Server', ''),
            'technologies': [],
            'cms': '',
            'framework': '',
            'language': '',
            'os': '',
            'confidence': 0.0,
        }
        
        # 技术栈识别
        tech_indicators = {
            'jQuery': [r'jquery', r'\$\(document\)'],
            'React': [r'react', r'ReactDOM', r'__reactInternalInstance'],
            'Vue': [r'vue', r'Vue\.devtools', r'__vue__'],
            'Angular': [r'angular', r'ng-app', r'ng-version'],
            'Bootstrap': [r'bootstrap', r'\.btn-', r'\.container'],
            'Tailwind': [r'tailwind', r'\.tw-'],
            'WordPress': [r'wp-content', r'wp-includes'],
            'Nginx': [r'nginx'],
            'Apache': [r'apache'],
            'IIS': [r'iis', r'microsoft-iis'],
            'PHP': [r'x-powered-by.*php', r'PHPSESSID'],
            'Java': [r'set-cookie.*jsessionid', r'x-powered-by.*servlet'],
            'Python': [r'set-cookie.*sessionid', r'server.*python'],
        }
        
        for tech, patterns in tech_indicators.items():
            for pattern in patterns:
                if re.search(pattern, body_str, re.IGNORECASE) or \
                   re.search(pattern, str(headers), re.IGNORECASE):
                    result['technologies'].append(tech)
                    break
        
        # 计算置信度
        if result['technologies']:
            result['confidence'] = min(0.9, 0.5 + len(result['technologies']) * 0.1)
        
        if result['server']:
            result['confidence'] = min(1.0, result['confidence'] + 0.2)
        
        return result
    
    def get_cached_result(self, url: str) -> Optional[Dict[str, Any]]:
        """获取缓存的分析结果"""
        with self._lock:
            return self._analysis_cache.get(url)


class AssetManager:
    """资产管理器"""
    
    def __init__(self):
        self._assets: Dict[str, DiscoveredAsset] = {}
        self._known_domains: Set[str] = set()
        self._known_ips: Set[str] = set()
        self._callbacks: List[Callable] = []
    
    def add_asset(self, asset: DiscoveredAsset) -> bool:
        """添加资产"""
        asset_id = f"{asset.domain or asset.ip}:{asset.port}"
        
        if asset_id in self._assets:
            existing = self._assets[asset_id]
            existing.api_endpoints.extend(
                ep for ep in asset.api_endpoints 
                if ep not in existing.api_endpoints
            )
            existing.tech_stack.extend(
                tech for tech in asset.tech_stack 
                if tech not in existing.tech_stack
            )
            existing.timestamp = asset.timestamp
            asset.is_new = False
            return False
        
        self._assets[asset_id] = asset
        
        if asset.domain:
            self._known_domains.add(asset.domain)
        if asset.ip:
            self._known_ips.add(asset.ip)
        
        # 通知回调
        for callback in self._callbacks:
            try:
                callback(asset)
            except Exception as e:
                logger.error(f"资产通知回调失败: {e}")
        
        return True
    
    def is_known(self, domain: str = "", ip: str = "") -> bool:
        """检查是否已知资产"""
        if domain and domain in self._known_domains:
            return True
        if ip and ip in self._known_ips:
            return True
        return False
    
    def add_callback(self, callback: Callable):
        """添加新资产发现回调"""
        self._callbacks.append(callback)
    
    def get_assets(self) -> List[DiscoveredAsset]:
        """获取所有资产"""
        return list(self._assets.values())
    
    def get_asset_count(self) -> int:
        """获取资产数量"""
        return len(self._assets)
    
    def get_statistics(self) -> Dict[str, Any]:
        """获取统计信息"""
        cms_stats = {}
        server_stats = {}
        
        for asset in self._assets.values():
            if asset.cms:
                cms_stats[asset.cms] = cms_stats.get(asset.cms, 0) + 1
            if asset.server_type:
                server_stats[asset.server_type] = server_stats.get(asset.server_type, 0) + 1
        
        return {
            'total_assets': len(self._assets),
            'unique_domains': len(self._known_domains),
            'unique_ips': len(self._known_ips),
            'cms_distribution': cms_stats,
            'server_distribution': server_stats,
        }


class AssetLinkageEngine:
    """资产识别引擎联动器"""
    
    def __init__(self):
        self.extractor = AssetExtractor()
        self.analyzer = FingerprintAnalyzer()
        self.manager = AssetManager()
        
        self._new_asset_callbacks: List[Callable] = []
        self._fingerprint_callbacks: List[Callable] = []
    
    def process_traffic(self, request_data: Dict[str, Any], 
                       response_data: Dict[str, Any]):
        """处理流量，提取和分析资产"""
        try:
            # 提取资产信息
            req_assets = self.extractor.extract_from_request(request_data)
            resp_assets = self.extractor.extract_from_response(response_data)
            
            # 合并资产信息
            url = request_data.get('url', '')
            parsed = urlparse(url)
            
            domain = parsed.hostname or ''
            ip = ''
            port = parsed.port or (443 if parsed.scheme == 'https' else 80)
            
            if self.extractor._ip_pattern.match(domain):
                ip = domain
                domain = ''
            
            # 创建资产对象
            import uuid
            asset = DiscoveredAsset(
                id=str(uuid.uuid4())[:12],
                timestamp=datetime.utcnow(),
                domain=domain,
                ip=ip,
                port=port,
                protocol=parsed.scheme,
                url=url,
                api_endpoints=list(req_assets['api_endpoints']),
                tech_stack=resp_assets['tech_stack'],
                server_type=resp_assets['server_type'],
                framework=resp_assets['framework'],
                cms=resp_assets['cms'],
            )
            
            # 检查是否新资产
            asset.is_new = not self.manager.is_known(domain=domain, ip=ip)
            
            # 添加到资产管理器
            is_newly_added = self.manager.add_asset(asset)
            
            # 如果是新资产，通知回调
            if is_newly_added and asset.is_new:
                for callback in self._new_asset_callbacks:
                    try:
                        callback(asset)
                    except Exception as e:
                        logger.error(f"新资产通知失败: {e}")
            
            # 异步指纹分析
            def on_fingerprint_complete(result):
                for callback in self._fingerprint_callbacks:
                    try:
                        callback(asset, result)
                    except Exception as e:
                        logger.error(f"指纹回调失败: {e}")
            
            self.analyzer.analyze_async(url, response_data, on_fingerprint_complete)
            
        except Exception as e:
            logger.error(f"资产联动处理失败: {e}")
    
    def on_new_asset(self, callback: Callable):
        """注册新资产发现回调"""
        self._new_asset_callbacks.append(callback)
    
    def on_fingerprint(self, callback: Callable):
        """注册指纹分析回调"""
        self._fingerprint_callbacks.append(callback)
    
    def get_tech_stack_for_url(self, url: str) -> List[str]:
        """获取URL的技术栈标签"""
        cached = self.analyzer.get_cached_result(url)
        if cached:
            return cached.get('technologies', [])
        return []
    
    def get_status(self) -> Dict[str, Any]:
        """获取联动状态"""
        return {
            'assets': self.manager.get_statistics(),
        }
