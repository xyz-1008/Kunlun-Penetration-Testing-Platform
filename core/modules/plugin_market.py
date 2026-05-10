"""
插件市场集成模块
"""

import os
import sys
import json
import logging
import hashlib
import requests
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime

logger = logging.getLogger(__name__)


@dataclass
class PluginMarketEntry:
    """插件市场条目"""
    plugin_id: str
    name: str
    version: str
    author: str
    description: str
    plugin_type: str
    rating: float = 0.0
    downloads: int = 0
    tags: List[str] = field(default_factory=list)
    price: float = 0.0
    is_paid: bool = False
    homepage: str = ""
    download_url: str = ""
    checksum: str = ""
    release_date: str = ""
    last_updated: str = ""
    screenshots: List[str] = field(default_factory=list)
    reviews_count: int = 0


class PluginMarket:
    """插件市场"""
    
    def __init__(self, market_url: str = "https://market.example.com/api"):
        self.market_url = market_url
        self._cache: Dict[str, PluginMarketEntry] = {}
        self._cache_file = Path(__file__).parent.parent.parent / "data" / "market_cache.json"
        self._cache_file.parent.mkdir(parents=True, exist_ok=True)
        self._load_cache()
    
    def _load_cache(self):
        """加载缓存"""
        if self._cache_file.exists():
            try:
                with open(self._cache_file, "r", encoding="utf-8") as f:
                    cache_data = json.load(f)
                
                for plugin_id, data in cache_data.items():
                    self._cache[plugin_id] = PluginMarketEntry(**data)
                
                logger.info(f"加载了 {len(self._cache)} 个市场缓存")
            except Exception as e:
                logger.error(f"加载市场缓存失败: {e}")
    
    def _save_cache(self):
        """保存缓存"""
        try:
            cache_data = {
                plugin_id: entry.__dict__
                for plugin_id, entry in self._cache.items()
            }
            
            with open(self._cache_file, "w", encoding="utf-8") as f:
                json.dump(cache_data, f, indent=2, ensure_ascii=False)
        except Exception as e:
            logger.error(f"保存市场缓存失败: {e}")
    
    def fetch_plugins(self, category: str = None, search: str = None) -> List[PluginMarketEntry]:
        """获取插件列表"""
        try:
            params = {}
            if category:
                params["category"] = category
            if search:
                params["search"] = search
            
            response = requests.get(
                f"{self.market_url}/plugins",
                params=params,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                plugins = []
                
                for item in data.get("plugins", []):
                    entry = PluginMarketEntry(**item)
                    self._cache[entry.plugin_id] = entry
                    plugins.append(entry)
                
                self._save_cache()
                return plugins
            
        except Exception as e:
            logger.warning(f"获取市场插件失败: {e}")
        
        return list(self._cache.values())
    
    def get_plugin_detail(self, plugin_id: str) -> Optional[PluginMarketEntry]:
        """获取插件详情"""
        if plugin_id in self._cache:
            return self._cache[plugin_id]
        
        try:
            response = requests.get(
                f"{self.market_url}/plugins/{plugin_id}",
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                entry = PluginMarketEntry(**data)
                self._cache[plugin_id] = entry
                self._save_cache()
                return entry
        
        except Exception as e:
            logger.warning(f"获取插件详情失败: {e}")
        
        return None
    
    def download_plugin(self, plugin_id: str, save_dir: str) -> bool:
        """下载插件"""
        entry = self.get_plugin_detail(plugin_id)
        if not entry:
            return False
        
        try:
            response = requests.get(entry.download_url, timeout=30)
            
            if response.status_code == 200:
                save_path = Path(save_dir) / f"{plugin_id}.py"
                save_path.parent.mkdir(parents=True, exist_ok=True)
                
                with open(save_path, "wb") as f:
                    f.write(response.content)
                
                if entry.checksum:
                    file_checksum = hashlib.sha256(response.content).hexdigest()
                    if file_checksum != entry.checksum:
                        logger.error(f"插件校验失败: {plugin_id}")
                        save_path.unlink()
                        return False
                
                logger.info(f"下载插件成功: {plugin_id}")
                return True
        
        except Exception as e:
            logger.error(f"下载插件失败: {e}")
        
        return False
    
    def search_plugins(self, query: str) -> List[PluginMarketEntry]:
        """搜索插件"""
        return self.fetch_plugins(search=query)
    
    def get_categories(self) -> List[str]:
        """获取分类"""
        try:
            response = requests.get(
                f"{self.market_url}/categories",
                timeout=10
            )
            
            if response.status_code == 200:
                return response.json().get("categories", [])
        
        except Exception as e:
            logger.warning(f"获取分类失败: {e}")
        
        return []
    
    def rate_plugin(self, plugin_id: str, rating: int) -> bool:
        """评分插件"""
        try:
            response = requests.post(
                f"{self.market_url}/plugins/{plugin_id}/rate",
                json={"rating": rating},
                timeout=10
            )
            
            return response.status_code == 200
        
        except Exception as e:
            logger.error(f"评分失败: {e}")
            return False
    
    def get_top_plugins(self, limit: int = 10) -> List[PluginMarketEntry]:
        """获取热门插件"""
        try:
            response = requests.get(
                f"{self.market_url}/plugins/top",
                params={"limit": limit},
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                plugins = []
                
                for item in data.get("plugins", []):
                    entry = PluginMarketEntry(**item)
                    self._cache[entry.plugin_id] = entry
                    plugins.append(entry)
                
                return plugins
        
        except Exception as e:
            logger.warning(f"获取热门插件失败: {e}")
        
        return []
    
    def get_new_plugins(self, limit: int = 10) -> List[PluginMarketEntry]:
        """获取新插件"""
        try:
            response = requests.get(
                f"{self.market_url}/plugins/new",
                params={"limit": limit},
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                plugins = []
                
                for item in data.get("plugins", []):
                    entry = PluginMarketEntry(**item)
                    self._cache[entry.plugin_id] = entry
                    plugins.append(entry)
                
                return plugins
        
        except Exception as e:
            logger.warning(f"获取新插件失败: {e}")
        
        return []
    
    def refresh_cache(self):
        """刷新缓存"""
        self._cache.clear()
        self.fetch_plugins()
