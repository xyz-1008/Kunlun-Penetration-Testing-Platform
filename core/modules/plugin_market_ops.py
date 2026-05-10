"""
插件市场运营功能模块
包含分类与标签、质量评分、开发者认证等功能
"""

import os
import sys
import json
import logging
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

logger = logging.getLogger(__name__)


class DeveloperLevel(Enum):
    """开发者等级"""
    NEWBIE = "新手"
    REGULAR = "普通"
    VERIFIED = "认证"
    EXPERT = "专家"
    MASTER = "大师"


class PluginQuality(Enum):
    """插件质量等级"""
    POOR = "差"
    FAIR = "一般"
    GOOD = "良好"
    EXCELLENT = "优秀"
    OUTSTANDING = "卓越"


@dataclass
class DeveloperProfile:
    """开发者档案"""
    developer_id: str
    name: str
    email: str = ""
    level: DeveloperLevel = DeveloperLevel.NEWBIE
    plugins_count: int = 0
    total_downloads: int = 0
    total_rating: float = 0.0
    verified: bool = False
    join_date: datetime = field(default_factory=datetime.now)
    bio: str = ""
    homepage: str = ""
    github: str = ""


@dataclass
class PluginReview:
    """插件评论"""
    review_id: str
    plugin_id: str
    user_id: str
    rating: int
    comment: str = ""
    created_at: datetime = field(default_factory=datetime.now)
    helpful_count: int = 0


@dataclass
class PluginCategory:
    """插件分类"""
    category_id: str
    name: str
    description: str = ""
    icon: str = ""
    plugin_count: int = 0
    parent_id: str = ""


class PluginMarketOperations:
    """插件市场运营"""
    
    def __init__(self):
        self._developers: Dict[str, DeveloperProfile] = {}
        self._reviews: Dict[str, List[PluginReview]] = {}
        self._categories: Dict[str, PluginCategory] = {}
        self._tags: Dict[str, int] = {}
        self._featured_plugins: List[str] = []
        
        self._init_default_categories()
    
    def _init_default_categories(self):
        """初始化默认分类"""
        categories = [
            ("recon", "信息收集", "资产发现和信息收集类插件"),
            ("scanner", "扫描器", "端口扫描和漏洞扫描类插件"),
            ("exploit", "漏洞利用", "漏洞验证和利用类插件"),
            ("fingerprint", "指纹识别", "技术和产品指纹识别类插件"),
            ("report", "报告输出", "报告生成和导出类插件"),
            ("mitm", "中间人", "流量拦截和修改类插件"),
            ("fuzzer", "模糊测试", "输入模糊测试类插件"),
            ("utility", "工具", "辅助工具类插件"),
        ]
        
        for cat_id, name, desc in categories:
            self._categories[cat_id] = PluginCategory(
                category_id=cat_id,
                name=name,
                description=desc
            )
    
    def add_developer(self, profile: DeveloperProfile):
        """添加开发者"""
        self._developers[profile.developer_id] = profile
    
    def get_developer(self, developer_id: str) -> Optional[DeveloperProfile]:
        """获取开发者"""
        return self._developers.get(developer_id)
    
    def verify_developer(self, developer_id: str) -> bool:
        """认证开发者"""
        if developer_id in self._developers:
            self._developers[developer_id].verified = True
            self._developers[developer_id].level = DeveloperLevel.VERIFIED
            return True
        return False
    
    def update_developer_level(self, developer_id: str):
        """更新开发者等级"""
        if developer_id not in self._developers:
            return
        
        dev = self._developers[developer_id]
        
        if dev.plugins_count >= 50 and dev.total_rating >= 4.5:
            dev.level = DeveloperLevel.MASTER
        elif dev.plugins_count >= 20 and dev.total_rating >= 4.0:
            dev.level = DeveloperLevel.EXPERT
        elif dev.plugins_count >= 5 and dev.total_rating >= 3.5:
            dev.level = DeveloperLevel.REGULAR
        else:
            dev.level = DeveloperLevel.NEWBIE
    
    def add_review(self, review: PluginReview):
        """添加评论"""
        if review.plugin_id not in self._reviews:
            self._reviews[review.plugin_id] = []
        
        self._reviews[review.plugin_id].append(review)
    
    def get_reviews(self, plugin_id: str, limit: int = 20) -> List[PluginReview]:
        """获取评论"""
        return self._reviews.get(plugin_id, [])[-limit:]
    
    def get_plugin_rating(self, plugin_id: str) -> float:
        """获取插件评分"""
        reviews = self._reviews.get(plugin_id, [])
        
        if not reviews:
            return 0.0
        
        return sum(r.rating for r in reviews) / len(reviews)
    
    def calculate_quality(self, plugin_id: str) -> PluginQuality:
        """计算插件质量"""
        rating = self.get_plugin_rating(plugin_id)
        reviews = self._reviews.get(plugin_id, [])
        
        if rating >= 4.5 and len(reviews) >= 10:
            return PluginQuality.OUTSTANDING
        elif rating >= 4.0 and len(reviews) >= 5:
            return PluginQuality.EXCELLENT
        elif rating >= 3.0:
            return PluginQuality.GOOD
        elif rating >= 2.0:
            return PluginQuality.FAIR
        else:
            return PluginQuality.POOR
    
    def add_tag(self, tag: str):
        """添加标签"""
        tag = tag.lower()
        self._tags[tag] = self._tags.get(tag, 0) + 1
    
    def get_tags(self, limit: int = 50) -> List[tuple]:
        """获取标签"""
        sorted_tags = sorted(self._tags.items(), key=lambda x: x[1], reverse=True)
        return sorted_tags[:limit]
    
    def get_categories(self) -> Dict[str, PluginCategory]:
        """获取分类"""
        return self._categories.copy()
    
    def add_category(self, category: PluginCategory):
        """添加分类"""
        self._categories[category.category_id] = category
    
    def set_featured(self, plugin_ids: List[str]):
        """设置推荐插件"""
        self._featured_plugins = plugin_ids
    
    def get_featured(self) -> List[str]:
        """获取推荐插件"""
        return self._featured_plugins.copy()
    
    def get_market_statistics(self) -> Dict[str, Any]:
        """获取市场统计"""
        total_plugins = sum(cat.plugin_count for cat in self._categories.values())
        total_developers = len(self._developers)
        total_reviews = sum(len(reviews) for reviews in self._reviews.values())
        
        return {
            "total_plugins": total_plugins,
            "total_developers": total_developers,
            "total_reviews": total_reviews,
            "categories": len(self._categories),
            "tags": len(self._tags),
            "featured_count": len(self._featured_plugins)
        }
    
    def export_market_data(self) -> Dict[str, Any]:
        """导出市场数据"""
        return {
            "developers": {
                dev_id: {
                    "name": dev.name,
                    "level": dev.level.value,
                    "plugins_count": dev.plugins_count,
                    "verified": dev.verified
                }
                for dev_id, dev in self._developers.items()
            },
            "categories": {
                cat_id: {
                    "name": cat.name,
                    "description": cat.description,
                    "plugin_count": cat.plugin_count
                }
                for cat_id, cat in self._categories.items()
            },
            "tags": self._tags,
            "featured": self._featured_plugins,
            "statistics": self.get_market_statistics()
        }


class PluginQualityChecker:
    """插件质量检查器"""
    
    def __init__(self):
        self._checks: List[Callable] = [
            self._check_code_quality,
            self._check_documentation,
            self._check_security,
            self._check_performance,
        ]
    
    def check_plugin(self, plugin_path: str) -> Dict[str, Any]:
        """检查插件质量"""
        path = Path(plugin_path)
        
        if not path.exists():
            return {"success": False, "error": "插件文件不存在"}
        
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
        
        results = {}
        
        for check in self._checks:
            try:
                result = check(content)
                results[check.__name__] = result
            except Exception as e:
                results[check.__name__] = {"success": False, "error": str(e)}
        
        overall_score = sum(
            r.get("score", 0) for r in results.values() if r.get("success")
        ) / len(results)
        
        return {
            "success": True,
            "overall_score": overall_score,
            "checks": results
        }
    
    def _check_code_quality(self, content: str) -> Dict[str, Any]:
        """检查代码质量"""
        score = 0
        issues = []
        
        lines = content.split("\n")
        
        if len(lines) > 500:
            issues.append("代码过长，建议拆分")
        else:
            score += 20
        
        if any(line.startswith("def ") for line in lines):
            score += 20
        else:
            issues.append("缺少函数定义")
        
        if any("docstring" in line.lower() or '"""' in line for line in lines):
            score += 20
        else:
            issues.append("缺少文档字符串")
        
        if "try:" in content and "except:" in content:
            score += 20
        else:
            issues.append("缺少异常处理")
        
        if "import" in content:
            score += 20
        else:
            issues.append("缺少导入语句")
        
        return {
            "success": True,
            "score": score,
            "issues": issues
        }
    
    def _check_documentation(self, content: str) -> Dict[str, Any]:
        """检查文档"""
        score = 0
        issues = []
        
        if '"""' in content:
            score += 30
        else:
            issues.append("缺少模块文档")
        
        if "description" in content.lower():
            score += 20
        else:
            issues.append("缺少描述信息")
        
        if "author" in content.lower():
            score += 20
        else:
            issues.append("缺少作者信息")
        
        if "version" in content.lower():
            score += 15
        else:
            issues.append("缺少版本信息")
        
        if "example" in content.lower() or "usage" in content.lower():
            score += 15
        else:
            issues.append("缺少使用示例")
        
        return {
            "success": True,
            "score": score,
            "issues": issues
        }
    
    def _check_security(self, content: str) -> Dict[str, Any]:
        """检查安全性"""
        score = 0
        issues = []
        
        dangerous_patterns = [
            "eval(",
            "exec(",
            "__import__(",
            "os.system(",
            "subprocess.call(",
        ]
        
        found_dangerous = []
        for pattern in dangerous_patterns:
            if pattern in content:
                found_dangerous.append(pattern)
        
        if not found_dangerous:
            score += 50
        else:
            issues.append(f"发现危险函数: {', '.join(found_dangerous)}")
            score += 20
        
        if "verify" in content or "validate" in content:
            score += 30
        else:
            issues.append("缺少输入验证")
        
        if "timeout" in content.lower():
            score += 20
        else:
            issues.append("缺少超时设置")
        
        return {
            "success": True,
            "score": score,
            "issues": issues
        }
    
    def _check_performance(self, content: str) -> Dict[str, Any]:
        """检查性能"""
        score = 0
        issues = []
        
        if "async" in content or "await" in content:
            score += 30
        else:
            issues.append("建议使用异步编程")
        
        if "cache" in content.lower():
            score += 20
        else:
            issues.append("建议添加缓存")
        
        if "timeout" in content.lower():
            score += 20
        else:
            issues.append("建议设置超时")
        
        if "limit" in content.lower() or "max_" in content.lower():
            score += 15
        else:
            issues.append("建议限制资源使用")
        
        if "batch" in content.lower() or "chunk" in content.lower():
            score += 15
        else:
            issues.append("建议批量处理")
        
        return {
            "success": True,
            "score": score,
            "issues": issues
        }
