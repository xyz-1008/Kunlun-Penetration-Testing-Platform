"""
流量标记与协作模块 - 支持流量打标签、备注和分享
功能：
- 支持对流量打标签和备注，方便团队协作时标记关键流量
- 支持将流量记录导出为分享包，包含请求/响应和备注
- 团队成员可导入分享包，直接查看完整上下文
- 流量标记支持颜色分类：高危、可疑、已利用、待分析
"""

import json
import uuid
import logging
from typing import Dict, List, Any, Optional, Callable
from datetime import datetime
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class TrafficTag(Enum):
    """流量标签"""
    HIGH_RISK = "high_risk"  # 高危
    SUSPICIOUS = "suspicious"  # 可疑
    EXPLOITED = "exploited"  # 已利用
    PENDING_ANALYSIS = "pending_analysis"  # 待分析
    FALSE_POSITIVE = "false_positive"  # 误报
    CONFIRMED = "confirmed"  # 已确认
    IGNORED = "ignored"  # 已忽略


TAG_COLORS = {
    TrafficTag.HIGH_RISK: "#FF0000",  # 红色
    TrafficTag.SUSPICIOUS: "#FFA500",  # 橙色
    TrafficTag.EXPLOITED: "#800080",  # 紫色
    TrafficTag.PENDING_ANALYSIS: "#FFFF00",  # 黄色
    TrafficTag.FALSE_POSITIVE: "#808080",  # 灰色
    TrafficTag.CONFIRMED: "#008000",  # 绿色
    TrafficTag.IGNORED: "#C0C0C0",  # 银色
}


@dataclass
class TrafficAnnotation:
    """流量标注"""
    id: str
    traffic_id: str
    tags: List[TrafficTag]
    note: str
    created_by: str
    created_at: datetime
    updated_at: datetime
    is_shared: bool = False


@dataclass
class SharePackage:
    """分享包"""
    id: str
    name: str
    description: str
    created_by: str
    created_at: datetime
    traffics: List[Dict[str, Any]]
    annotations: List[TrafficAnnotation]
    metadata: Dict[str, Any] = field(default_factory=dict)


class TrafficMarker:
    """流量标记器"""
    
    def __init__(self):
        self._annotations: Dict[str, TrafficAnnotation] = {}
        self._callbacks: Dict[str, List[Callable]] = {
            'on_tag_added': [],
            'on_note_updated': [],
        }
    
    def add_tags(self, traffic_id: str, tags: List[TrafficTag], 
                 user: str = "anonymous") -> Optional[TrafficAnnotation]:
        """添加标签"""
        try:
            if traffic_id in self._annotations:
                annotation = self._annotations[traffic_id]
                annotation.tags = list(set(annotation.tags + tags))
                annotation.updated_at = datetime.utcnow()
            else:
                annotation = TrafficAnnotation(
                    id=str(uuid.uuid4())[:12],
                    traffic_id=traffic_id,
                    tags=tags,
                    note="",
                    created_by=user,
                    created_at=datetime.utcnow(),
                    updated_at=datetime.utcnow(),
                )
                self._annotations[traffic_id] = annotation
            
            # 通知标签添加
            for callback in self._callbacks['on_tag_added']:
                try:
                    callback(traffic_id, tags)
                except Exception as e:
                    logger.error(f"标签添加通知失败: {e}")
            
            return annotation
            
        except Exception as e:
            logger.error(f"添加标签失败: {e}")
            return None
    
    def update_note(self, traffic_id: str, note: str, 
                    user: str = "anonymous") -> Optional[TrafficAnnotation]:
        """更新备注"""
        try:
            if traffic_id in self._annotations:
                annotation = self._annotations[traffic_id]
                annotation.note = note
                annotation.updated_at = datetime.utcnow()
                
                # 通知备注更新
                for callback in self._callbacks['on_note_updated']:
                    try:
                        callback(traffic_id, note)
                    except Exception as e:
                        logger.error(f"备注更新通知失败: {e}")
                
                return annotation
            else:
                # 创建新标注
                return self.add_tags(traffic_id, [], user)
            
        except Exception as e:
            logger.error(f"更新备注失败: {e}")
            return None
    
    def get_annotation(self, traffic_id: str) -> Optional[TrafficAnnotation]:
        """获取标注"""
        return self._annotations.get(traffic_id)
    
    def get_by_tag(self, tag: TrafficTag) -> List[TrafficAnnotation]:
        """按标签获取标注"""
        return [a for a in self._annotations.values() if tag in a.tags]
    
    def on_tag_added(self, callback: Callable):
        """注册标签添加回调"""
        self._callbacks['on_tag_added'].append(callback)
    
    def on_note_updated(self, callback: Callable):
        """注册备注更新回调"""
        self._callbacks['on_note_updated'].append(callback)


class ShareManager:
    """分享管理器"""
    
    def __init__(self):
        self._packages: Dict[str, SharePackage] = {}
    
    def create_package(self, name: str, description: str, 
                       traffic_data: List[Dict[str, Any]],
                       annotations: List[TrafficAnnotation],
                       user: str = "anonymous") -> SharePackage:
        """创建分享包"""
        package = SharePackage(
            id=str(uuid.uuid4())[:12],
            name=name,
            description=description,
            created_by=user,
            created_at=datetime.utcnow(),
            traffics=traffic_data,
            annotations=annotations,
            metadata={
                'traffic_count': len(traffic_data),
                'annotation_count': len(annotations),
            }
        )
        
        self._packages[package.id] = package
        return package
    
    def export_package(self, package_id: str) -> Optional[str]:
        """导出分享包为JSON"""
        if package_id not in self._packages:
            return None
        
        package = self._packages[package_id]
        
        export_data = {
            'version': '1.0',
            'type': 'traffic_share_package',
            'package': {
                'id': package.id,
                'name': package.name,
                'description': package.description,
                'created_by': package.created_by,
                'created_at': package.created_at.isoformat(),
                'traffics': package.traffics,
                'annotations': [
                    {
                        'id': a.id,
                        'traffic_id': a.traffic_id,
                        'tags': [t.value for t in a.tags],
                        'note': a.note,
                        'created_by': a.created_by,
                        'created_at': a.created_at.isoformat(),
                    }
                    for a in package.annotations
                ],
                'metadata': package.metadata,
            }
        }
        
        return json.dumps(export_data, indent=2, ensure_ascii=False)
    
    def import_package(self, json_data: str) -> Optional[SharePackage]:
        """导入分享包"""
        try:
            data = json.loads(json_data)
            
            if data.get('type') != 'traffic_share_package':
                logger.error("无效的分享包格式")
                return None
            
            pkg_data = data['package']
            
            # 还原标注
            annotations = []
            for ann_data in pkg_data.get('annotations', []):
                tags = [TrafficTag(t) for t in ann_data.get('tags', [])]
                annotation = TrafficAnnotation(
                    id=ann_data['id'],
                    traffic_id=ann_data['traffic_id'],
                    tags=tags,
                    note=ann_data.get('note', ''),
                    created_by=ann_data.get('created_by', ''),
                    created_at=datetime.fromisoformat(ann_data['created_at']),
                    updated_at=datetime.utcnow(),
                    is_shared=True,
                )
                annotations.append(annotation)
            
            # 创建分享包
            package = SharePackage(
                id=pkg_data['id'],
                name=pkg_data['name'],
                description=pkg_data.get('description', ''),
                created_by=pkg_data.get('created_by', ''),
                created_at=datetime.fromisoformat(pkg_data['created_at']),
                traffics=pkg_data.get('traffics', []),
                annotations=annotations,
                metadata=pkg_data.get('metadata', {}),
            )
            
            self._packages[package.id] = package
            return package
            
        except Exception as e:
            logger.error(f"导入分享包失败: {e}")
            return None
    
    def get_packages(self) -> List[SharePackage]:
        """获取所有分享包"""
        return list(self._packages.values())


class TrafficCollaboration:
    """流量协作模块"""
    
    def __init__(self):
        self.marker = TrafficMarker()
        self.share_manager = ShareManager()
        
        self._collaboration_callbacks: List[Callable] = []
    
    def mark_traffic(self, traffic_id: str, tags: List[TrafficTag], 
                     note: str = "", user: str = "anonymous") -> Optional[TrafficAnnotation]:
        """标记流量"""
        annotation = self.marker.add_tags(traffic_id, tags, user)
        if annotation and note:
            self.marker.update_note(traffic_id, note, user)
        return annotation
    
    def get_traffic_tags(self, traffic_id: str) -> List[TrafficTag]:
        """获取流量标签"""
        annotation = self.marker.get_annotation(traffic_id)
        return annotation.tags if annotation else []
    
    def get_traffic_color(self, traffic_id: str) -> str:
        """获取流量显示颜色"""
        tags = self.get_traffic_tags(traffic_id)
        if not tags:
            return "#FFFFFF"  # 白色（默认）
        
        # 返回最高优先级标签的颜色
        priority_order = [
            TrafficTag.HIGH_RISK,
            TrafficTag.EXPLOITED,
            TrafficTag.SUSPICIOUS,
            TrafficTag.PENDING_ANALYSIS,
            TrafficTag.CONFIRMED,
            TrafficTag.FALSE_POSITIVE,
            TrafficTag.IGNORED,
        ]
        
        for tag in priority_order:
            if tag in tags:
                return TAG_COLORS.get(tag, "#FFFFFF")
        
        return "#FFFFFF"
    
    def create_share_package(self, name: str, description: str,
                             traffic_data: List[Dict[str, Any]],
                             traffic_ids: List[str],
                             user: str = "anonymous") -> Optional[SharePackage]:
        """创建分享包"""
        # 收集标注
        annotations = []
        for traffic_id in traffic_ids:
            annotation = self.marker.get_annotation(traffic_id)
            if annotation:
                annotations.append(annotation)
        
        return self.share_manager.create_package(
            name, description, traffic_data, annotations, user
        )
    
    def export_share_package(self, package_id: str) -> Optional[str]:
        """导出分享包"""
        return self.share_manager.export_package(package_id)
    
    def import_share_package(self, json_data: str) -> Optional[SharePackage]:
        """导入分享包"""
        return self.share_manager.import_package(json_data)
    
    def on_traffic_marked(self, callback: Callable):
        """注册流量标记回调"""
        self.marker.on_tag_added(callback)
        self.marker.on_note_updated(callback)
