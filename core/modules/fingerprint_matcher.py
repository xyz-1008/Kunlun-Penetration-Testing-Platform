"""
指纹匹配与语义版本比较模块
"""

import re
import logging
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from packaging import version as pkg_version
from packaging.specifiers import SpecifierSet, InvalidSpecifier

logger = logging.getLogger(__name__)


@dataclass
class AssetFingerprint:
    """资产指纹"""
    product: str
    version: str = ""
    ports: List[int] = None
    protocol: str = ""
    tags: List[str] = None
    cpe: str = ""
    
    def __post_init__(self):
        if self.ports is None:
            self.ports = []
        if self.tags is None:
            self.tags = []


@dataclass
class MatchResult:
    """匹配结果"""
    matched: bool
    poc_id: str
    reason: str = ""
    confidence: float = 1.0


class FingerprintMatcher:
    """指纹匹配器"""
    
    def __init__(self):
        self._cache: Dict[str, MatchResult] = {}
    
    def match_poc(self, asset: AssetFingerprint, poc_metadata: Dict[str, Any]) -> MatchResult:
        """匹配资产与PoC"""
        cache_key = f"{asset.product}_{asset.version}_{poc_metadata.get('name', '')}"
        if cache_key in self._cache:
            return self._cache[cache_key]
        
        result = self._do_match(asset, poc_metadata)
        self._cache[cache_key] = result
        return result
    
    def _do_match(self, asset: AssetFingerprint, poc_metadata: Dict[str, Any]) -> MatchResult:
        """执行匹配"""
        poc_product = poc_metadata.get("product", "")
        poc_version_range = poc_metadata.get("version_range", "")
        poc_tags = poc_metadata.get("tags", [])
        poc_cpe = poc_metadata.get("cpe", "")
        
        if not poc_product and not poc_cpe:
            return MatchResult(False, poc_metadata.get("name", ""), "PoC未指定产品")
        
        product_match = self._match_product(asset.product, poc_product, poc_cpe)
        if not product_match:
            return MatchResult(False, poc_metadata.get("name", ""), "产品不匹配")
        
        if poc_version_range:
            version_match = self._match_version(asset.version, poc_version_range)
            if not version_match:
                return MatchResult(False, poc_metadata.get("name", ""), "版本不匹配")
        
        tag_match = self._match_tags(asset.tags, poc_tags)
        
        return MatchResult(True, poc_metadata.get("name", ""), "匹配成功", 1.0)
    
    def _match_product(self, asset_product: str, poc_product: str, poc_cpe: str = "") -> bool:
        """匹配产品"""
        if not asset_product:
            return False
        
        asset_lower = asset_product.lower()
        poc_lower = poc_product.lower()
        
        if poc_lower in asset_lower or asset_lower in poc_lower:
            return True
        
        if poc_cpe:
            cpe_parts = poc_cpe.split(":")
            if len(cpe_parts) >= 5:
                cpe_product = cpe_parts[4].lower()
                if cpe_product in asset_lower or asset_lower in cpe_product:
                    return True
        
        return False
    
    def _match_version(self, asset_version: str, version_range: str) -> bool:
        """匹配版本范围"""
        if not asset_version:
            return True
        
        try:
            asset_ver = pkg_version.parse(asset_version)
        except Exception:
            logger.warning(f"无法解析资产版本: {asset_version}")
            return True
        
        try:
            normalized_range = self._normalize_version_range(version_range)
            spec = SpecifierSet(normalized_range)
            return asset_ver in spec
        except InvalidSpecifier as e:
            logger.warning(f"无效的版本范围: {version_range}, 错误: {e}")
            return True
        except Exception as e:
            logger.warning(f"版本匹配失败: {e}")
            return True
    
    def _normalize_version_range(self, version_range: str) -> str:
        """规范化版本范围"""
        range_str = version_range.strip()
        
        if range_str.startswith("^"):
            base_version = range_str[1:].strip()
            parts = base_version.split(".")
            if len(parts) >= 2:
                major = parts[0]
                next_major = str(int(major) + 1)
                return f">={base_version},<{next_major}.0.0"
            return f">={base_version}"
        
        if range_str.startswith("~"):
            base_version = range_str[1:].strip()
            parts = base_version.split(".")
            if len(parts) >= 2:
                major, minor = parts[0], parts[1]
                next_minor = str(int(minor) + 1)
                return f">={base_version},<{major}.{next_minor}.0"
            return f">={base_version}"
        
        return range_str
    
    def _match_tags(self, asset_tags: List[str], poc_tags: List[str]) -> bool:
        """匹配标签"""
        if not poc_tags:
            return True
        
        asset_tags_lower = [t.lower() for t in asset_tags]
        poc_tags_lower = [t.lower() for t in poc_tags]
        
        for tag in poc_tags_lower:
            if tag in asset_tags_lower:
                return True
        
        return False
    
    def filter_pocs_for_asset(self, asset: AssetFingerprint, pocs: Dict[str, Dict[str, Any]]) -> List[str]:
        """为资产筛选可用的PoC"""
        matched_pocs = []
        
        for poc_id, poc_data in pocs.items():
            metadata = poc_data.get("metadata", {})
            result = self.match_poc(asset, metadata)
            if result.matched:
                matched_pocs.append(poc_id)
        
        return matched_pocs
    
    def clear_cache(self):
        """清除缓存"""
        self._cache.clear()
