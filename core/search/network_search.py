"""
网络空间搜索引擎模块
基于20年渗透测试经验的专业级网络空间搜索工具
支持FOFA、ZoomEye、Shodan、Censys、Hunter等多个搜索引擎
"""

import httpx
import base64
import logging
import json
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime
import os

logger = logging.getLogger(__name__)


@dataclass
class SearchResult:
    """搜索结果"""
    id: str
    ip: str
    port: int
    host: Optional[str] = None
    title: Optional[str] = None
    domain: Optional[str] = None
    url: Optional[str] = None
    protocol: Optional[str] = None
    banner: Optional[str] = None
    server: Optional[str] = None
    location: Optional[str] = None
    country: Optional[str] = None
    city: Optional[str] = None
    os: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    raw_data: Dict = field(default_factory=dict)
    source: str = ''


@dataclass
class SearchEngineConfig:
    """搜索引擎配置"""
    name: str
    enabled: bool = True
    api_key: str = ''
    api_email: str = ''
    api_url: str = ''
    rate_limit: int = 1


class NetworkSearch:
    """专业级网络空间搜索引擎"""
    
    def __init__(self, config_path: str = None):
        self.engines: Dict[str, SearchEngineConfig] = {}
        self.results: List[SearchResult] = []
        self.config_path = config_path or os.path.join(os.path.dirname(__file__), '../../config/search_engines.json')
        
        self._init_default_engines()
        self._load_config()
        
        logger.info("专业级网络空间搜索引擎初始化完成")
    
    def _init_default_engines(self):
        """初始化默认搜索引擎"""
        self.engines['fofa'] = SearchEngineConfig(
            name='FOFA',
            api_url='https://fofa.info/api/v1/search/all',
            rate_limit=1
        )
        
        self.engines['zoomeye'] = SearchEngineConfig(
            name='ZoomEye',
            api_url='https://api.zoomeye.org/host/search',
            rate_limit=1
        )
        
        self.engines['shodan'] = SearchEngineConfig(
            name='Shodan',
            api_url='https://api.shodan.io/shodan/host/search',
            rate_limit=1
        )
        
        self.engines['censys'] = SearchEngineConfig(
            name='Censys',
            api_url='https://search.censys.io/api/v2/hosts/search',
            rate_limit=1
        )
        
        self.engines['hunter'] = SearchEngineConfig(
            name='Hunter',
            api_url='https://hunter.qianxin.com/openApi/search',
            rate_limit=1
        )
    
    def _load_config(self):
        """加载配置"""
        try:
            if os.path.exists(self.config_path):
                with open(self.config_path, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                    for name, engine_config in config.items():
                        if name in self.engines:
                            self.engines[name].api_key = engine_config.get('api_key', '')
                            self.engines[name].api_email = engine_config.get('api_email', '')
                            self.engines[name].enabled = engine_config.get('enabled', True)
        except Exception as e:
            logger.error(f"加载配置失败: {e}")
    
    def _save_config(self):
        """保存配置"""
        try:
            os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
            config = {}
            for name, engine in self.engines.items():
                config[name] = {
                    'api_key': engine.api_key,
                    'api_email': engine.api_email,
                    'enabled': engine.enabled
                }
            with open(self.config_path, 'w', encoding='utf-8') as f:
                json.dump(config, f, ensure_ascii=False, indent=2)
        except Exception as e:
            logger.error(f"保存配置失败: {e}")
    
    def set_api_key(self, engine: str, api_key: str, api_email: str = ''):
        """设置API密钥"""
        if engine in self.engines:
            self.engines[engine].api_key = api_key
            self.engines[engine].api_email = api_email
            self._save_config()
            logger.info(f"设置{engine} API密钥")
    
    def enable_engine(self, engine: str, enable: bool = True):
        """启用/禁用搜索引擎"""
        if engine in self.engines:
            self.engines[engine].enabled = enable
            self._save_config()
    
    async def search(self, query: str, engines: List[str] = None, page: int = 1, page_size: int = 100) -> List[SearchResult]:
        """搜索"""
        self.results = []
        
        if engines is None:
            engines = [name for name, engine in self.engines.items() if engine.enabled and engine.api_key]
        
        tasks = []
        for engine_name in engines:
            if engine_name in self.engines and self.engines[engine_name].enabled:
                tasks.append(self._search_engine(engine_name, query, page, page_size))
        
        import asyncio
        for task in asyncio.as_completed(tasks):
            results = await task
            self.results.extend(results)
        
        return self.results
    
    async def _search_engine(self, engine_name: str, query: str, page: int, page_size: int) -> List[SearchResult]:
        """搜索单个引擎"""
        engine = self.engines[engine_name]
        
        try:
            if engine_name == 'fofa':
                return await self._search_fofa(engine, query, page, page_size)
            elif engine_name == 'zoomeye':
                return await self._search_zoomeye(engine, query, page, page_size)
            elif engine_name == 'shodan':
                return await self._search_shodan(engine, query, page, page_size)
            elif engine_name == 'censys':
                return await self._search_censys(engine, query, page, page_size)
            elif engine_name == 'hunter':
                return await self._search_hunter(engine, query, page, page_size)
            else:
                logger.warning(f"不支持的搜索引擎: {engine_name}")
                return []
        except Exception as e:
            logger.error(f"{engine_name}搜索失败: {e}")
            return []
    
    async def _search_fofa(self, engine: SearchEngineConfig, query: str, page: int, page_size: int) -> List[SearchResult]:
        """FOFA搜索"""
        results = []
        
        qbase64 = base64.b64encode(query.encode()).decode()
        
        params = {
            'qbase64': qbase64,
            'page': page,
            'size': page_size,
            'email': engine.api_email,
            'key': engine.api_key,
            'full': 'true'
        }
        
        async with httpx.AsyncClient(timeout=30) as client:
            response = await client.get(engine.api_url, params=params)
            data = response.json()
            
            if data.get('error', False):
                logger.error(f"FOFA搜索错误: {data.get('errmsg', '未知错误')}")
                return []
            
            for i, item in enumerate(data.get('results', [])):
                result = SearchResult(
                    id=f'fofa_{page}_{i}',
                    ip=item[1] if len(item) > 1 else '',
                    port=int(item[2]) if len(item) > 2 else 0,
                    host=item[0] if len(item) > 0 else None,
                    domain=item[5] if len(item) > 5 else None,
                    title=item[6] if len(item) > 6 else None,
                    server=item[7] if len(item) > 7 else None,
                    country=item[9] if len(item) > 9 else None,
                    city=item[10] if len(item) > 10 else None,
                    raw_data={'fofa': item},
                    source='fofa'
                )
                results.append(result)
        
        logger.info(f"FOFA找到 {len(results)} 个结果")
        return results
    
    async def _search_zoomeye(self, engine: SearchEngineConfig, query: str, page: int, page_size: int) -> List[SearchResult]:
        """ZoomEye搜索"""
        results = []
        
        params = {
            'query': query,
            'page': page,
            'sub_type': 'web',
            'page_size': page_size
        }
        
        headers = {
            'API-KEY': engine.api_key
        }
        
        async with httpx.AsyncClient(timeout=30) as client:
            response = await client.get(engine.api_url, params=params, headers=headers)
            data = response.json()
            
            for i, item in enumerate(data.get('matches', [])):
                result = SearchResult(
                    id=f'zoomeye_{page}_{i}',
                    ip=item.get('ip', ''),
                    port=item.get('portinfo', {}).get('port', 0),
                    host=item.get('site', ''),
                    title=item.get('title', ''),
                    country=item.get('geoinfo', {}).get('country', {}).get('names', {}).get('en', ''),
                    city=item.get('geoinfo', {}).get('city', {}).get('names', {}).get('en', ''),
                    raw_data={'zoomeye': item},
                    source='zoomeye'
                )
                results.append(result)
        
        logger.info(f"ZoomEye找到 {len(results)} 个结果")
        return results
    
    async def _search_shodan(self, engine: SearchEngineConfig, query: str, page: int, page_size: int) -> List[SearchResult]:
        """Shodan搜索"""
        results = []
        
        params = {
            'query': query,
            'page': page,
            'minify': 'true',
            'key': engine.api_key
        }
        
        async with httpx.AsyncClient(timeout=30) as client:
            response = await client.get(engine.api_url, params=params)
            data = response.json()
            
            for i, item in enumerate(data.get('matches', [])):
                result = SearchResult(
                    id=f'shodan_{page}_{i}',
                    ip=item.get('ip_str', ''),
                    port=item.get('port', 0),
                    host=item.get('hostnames', [''])[0] if item.get('hostnames') else None,
                    domain=item.get('domains', [''])[0] if item.get('domains') else None,
                    location=f"{item.get('city', '')}, {item.get('country_code', '')}",
                    country=item.get('country_name', ''),
                    city=item.get('city', ''),
                    os=item.get('os', ''),
                    banner=item.get('data', ''),
                    raw_data={'shodan': item},
                    source='shodan'
                )
                results.append(result)
        
        logger.info(f"Shodan找到 {len(results)} 个结果")
        return results
    
    async def _search_censys(self, engine: SearchEngineConfig, query: str, page: int, page_size: int) -> List[SearchResult]:
        """Censys搜索"""
        results = []
        
        params = {
            'q': query,
            'page': page,
            'per_page': page_size
        }
        
        auth = base64.b64encode(f'{engine.api_email}:{engine.api_key}'.encode()).decode()
        headers = {
            'Authorization': f'Basic {auth}'
        }
        
        async with httpx.AsyncClient(timeout=30) as client:
            response = await client.get(engine.api_url, params=params, headers=headers)
            data = response.json()
            
            for i, item in enumerate(data.get('result', {}).get('hits', [])):
                result = SearchResult(
                    id=f'censys_{page}_{i}',
                    ip=item.get('ip', ''),
                    port=item.get('services', [{}])[0].get('port', 0) if item.get('services') else 0,
                    location=item.get('location', {}).get('country', ''),
                    country=item.get('location', {}).get('country', ''),
                    raw_data={'censys': item},
                    source='censys'
                )
                results.append(result)
        
        logger.info(f"Censys找到 {len(results)} 个结果")
        return results
    
    async def _search_hunter(self, engine: SearchEngineConfig, query: str, page: int, page_size: int) -> List[SearchResult]:
        """Hunter搜索"""
        results = []
        
        params = {
            'api-key': engine.api_key,
            'search': query,
            'page': page,
            'page_size': page_size
        }
        
        async with httpx.AsyncClient(timeout=30) as client:
            response = await client.get(engine.api_url, params=params)
            data = response.json()
            
            if data.get('code', 0) != 200:
                logger.error(f"Hunter搜索错误: {data.get('message', '未知错误')}")
                return []
            
            for i, item in enumerate(data.get('data', {}).get('arr', [])):
                result = SearchResult(
                    id=f'hunter_{page}_{i}',
                    ip=item.get('ip', ''),
                    port=item.get('port', 0),
                    host=item.get('url', ''),
                    title=item.get('web_title', ''),
                    domain=item.get('domain', ''),
                    country=item.get('country', ''),
                    raw_data={'hunter': item},
                    source='hunter'
                )
                results.append(result)
        
        logger.info(f"Hunter找到 {len(results)} 个结果")
        return results
    
    def get_results(self) -> List[SearchResult]:
        """获取结果"""
        return self.results
    
    def get_results_by_source(self, source: str) -> List[SearchResult]:
        """按来源获取结果"""
        return [r for r in self.results if r.source == source]
    
    def filter_results(self, keyword: str = '', country: str = '', port: int = 0) -> List[SearchResult]:
        """过滤结果"""
        filtered = self.results
        
        if keyword:
            keyword = keyword.lower()
            filtered = [
                r for r in filtered if
                keyword in str(r.ip).lower() or
                keyword in str(r.host).lower() or
                keyword in str(r.title).lower() or
                keyword in str(r.domain).lower()
            ]
        
        if country:
            filtered = [r for r in filtered if country.lower() in str(r.country).lower()]
        
        if port > 0:
            filtered = [r for r in filtered if r.port == port]
        
        return filtered
    
    def export_results(self, filepath: str, format: str = 'json') -> bool:
        """导出结果"""
        try:
            data = [
                {
                    'id': r.id,
                    'ip': r.ip,
                    'port': r.port,
                    'host': r.host,
                    'title': r.title,
                    'domain': r.domain,
                    'url': r.url,
                    'protocol': r.protocol,
                    'banner': r.banner,
                    'server': r.server,
                    'country': r.country,
                    'city': r.city,
                    'os': r.os,
                    'source': r.source
                }
                for r in self.results
            ]
            
            if format == 'json':
                with open(filepath, 'w', encoding='utf-8') as f:
                    json.dump(data, f, ensure_ascii=False, indent=2)
            elif format == 'csv':
                import csv
                with open(filepath, 'w', encoding='utf-8-sig', newline='') as f:
                    writer = csv.DictWriter(f, fieldnames=data[0].keys() if data else [])
                    writer.writeheader()
                    writer.writerows(data)
            elif format == 'txt':
                with open(filepath, 'w', encoding='utf-8') as f:
                    for r in self.results:
                        f.write(f"{r.ip}:{r.port}\\n")
            
            logger.info(f"导出 {len(self.results)} 个结果到 {filepath}")
            return True
            
        except Exception as e:
            logger.error(f"导出结果失败: {e}")
            return False
    
    def get_stats(self) -> Dict:
        """获取统计信息"""
        stats = {
            'total': len(self.results),
            'by_source': {},
            'by_country': {},
            'by_port': {}
        }
        
        for r in self.results:
            stats['by_source'][r.source] = stats['by_source'].get(r.source, 0) + 1
            
            if r.country:
                stats['by_country'][r.country] = stats['by_country'].get(r.country, 0) + 1
            
            if r.port > 0:
                stats['by_port'][r.port] = stats['by_port'].get(r.port, 0) + 1
        
        return stats
    
    def clear_results(self):
        """清空结果"""
        self.results = []
    
    def get_enabled_engines(self) -> List[str]:
        """获取已启用的搜索引擎"""
        return [name for name, engine in self.engines.items() if engine.enabled and engine.api_key]
