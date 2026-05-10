"""
Webshell管理器模块
基于20年渗透测试经验的专业级Webshell管理器
支持PHP/JSP/ASP Webshell管理、分类、搜索等功能
"""

import json
import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime
import os

logger = logging.getLogger(__name__)


@dataclass
class WebshellRecord:
    """Webshell记录"""
    id: str
    url: str
    type: str  # php, jsp, asp
    password: str
    method: str = 'POST'
    encoding: str = 'base64'
    status: str = 'unknown'
    last_connect: Optional[datetime] = None
    os_type: Optional[str] = None
    current_user: Optional[str] = None
    current_dir: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    notes: str = ''
    created_at: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> Dict:
        """转换为字典"""
        return {
            'id': self.id,
            'url': self.url,
            'type': self.type,
            'password': self.password,
            'method': self.method,
            'encoding': self.encoding,
            'status': self.status,
            'last_connect': self.last_connect.isoformat() if self.last_connect else None,
            'os_type': self.os_type,
            'current_user': self.current_user,
            'current_dir': self.current_dir,
            'tags': self.tags,
            'notes': self.notes,
            'created_at': self.created_at.isoformat()
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'WebshellRecord':
        """从字典创建"""
        return cls(
            id=data.get('id', ''),
            url=data.get('url', ''),
            type=data.get('type', 'php'),
            password=data.get('password', ''),
            method=data.get('method', 'POST'),
            encoding=data.get('encoding', 'base64'),
            status=data.get('status', 'unknown'),
            last_connect=datetime.fromisoformat(data['last_connect']) if data.get('last_connect') else None,
            os_type=data.get('os_type'),
            current_user=data.get('current_user'),
            current_dir=data.get('current_dir'),
            tags=data.get('tags', []),
            notes=data.get('notes', ''),
            created_at=datetime.fromisoformat(data.get('created_at', datetime.now().isoformat()))
        )


class WebshellManager:
    """专业级Webshell管理器"""
    
    def __init__(self, data_path: str = None):
        self.webshells: Dict[str, WebshellRecord] = {}
        self.data_path = data_path or os.path.join(os.path.dirname(__file__), '../../data/webshells.json')
        
        # 初始化连接器
        from .php_connector import PHPConnector
        from .jsp_connector import JSPConnector
        from .asp_connector import ASPConnector
        
        self.php_connector = PHPConnector()
        self.jsp_connector = JSPConnector()
        self.asp_connector = ASPConnector()
        
        # 加载数据
        self._load_data()
        
        logger.info("专业级Webshell管理器初始化完成")
    
    def _load_data(self):
        """加载数据"""
        try:
            os.makedirs(os.path.dirname(self.data_path), exist_ok=True)
            if os.path.exists(self.data_path):
                with open(self.data_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    for ws_data in data.get('webshells', []):
                        ws = WebshellRecord.from_dict(ws_data)
                        self.webshells[ws.id] = ws
                logger.info(f"加载了 {len(self.webshells)} 个Webshell记录")
        except Exception as e:
            logger.error(f"加载数据失败: {e}")
    
    def _save_data(self):
        """保存数据"""
        try:
            os.makedirs(os.path.dirname(self.data_path), exist_ok=True)
            data = {
                'webshells': [ws.to_dict() for ws in self.webshells.values()],
                'updated_at': datetime.now().isoformat()
            }
            with open(self.data_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
        except Exception as e:
            logger.error(f"保存数据失败: {e}")
    
    def add_webshell(self, url: str, ws_type: str, password: str, method: str = 'POST', encoding: str = 'base64', notes: str = '') -> str:
        """添加Webshell"""
        import uuid
        ws_id = str(uuid.uuid4())
        
        webshell = WebshellRecord(
            id=ws_id,
            url=url,
            type=ws_type.lower(),
            password=password,
            method=method,
            encoding=encoding,
            notes=notes
        )
        
        self.webshells[ws_id] = webshell
        self._save_data()
        
        logger.info(f"添加Webshell: {url} ({ws_type})")
        return ws_id
    
    def update_webshell(self, ws_id: str, **kwargs) -> bool:
        """更新Webshell信息"""
        if ws_id not in self.webshells:
            return False
        
        ws = self.webshells[ws_id]
        
        for key, value in kwargs.items():
            if hasattr(ws, key):
                setattr(ws, key, value)
        
        self._save_data()
        return True
    
    def remove_webshell(self, ws_id: str) -> bool:
        """移除Webshell"""
        if ws_id in self.webshells:
            del self.webshells[ws_id]
            self._save_data()
            logger.info(f"移除Webshell: {ws_id}")
            return True
        return False
    
    async def test_webshell(self, ws_id: str) -> tuple[bool, str]:
        """测试Webshell"""
        if ws_id not in self.webshells:
            return False, "Webshell不存在"
        
        ws = self.webshells[ws_id]
        
        try:
            if ws.type == 'php':
                conn_id = self.php_connector.add_connection(ws.url, ws.password, ws.method, ws.encoding)
                success, message = await self.php_connector.test_connection(conn_id)
                if success:
                    conn = self.php_connector.get_connection(conn_id)
                    ws.os_type = conn.os_type
                    ws.current_user = conn.current_user
                    ws.current_dir = conn.current_dir
                    ws.status = 'online'
                    ws.last_connect = datetime.now()
                self.php_connector.remove_connection(conn_id)
            
            elif ws.type == 'jsp':
                conn_id = self.jsp_connector.add_connection(ws.url, ws.password, ws.method)
                success, message = await self.jsp_connector.test_connection(conn_id)
                if success:
                    conn = self.jsp_connector.get_connection(conn_id)
                    ws.os_type = conn.os_type
                    ws.current_user = conn.current_user
                    ws.current_dir = conn.current_dir
                    ws.status = 'online'
                    ws.last_connect = datetime.now()
                self.jsp_connector.remove_connection(conn_id)
            
            elif ws.type == 'asp':
                conn_id = self.asp_connector.add_connection(ws.url, ws.password, ws.method)
                success, message = await self.asp_connector.test_connection(conn_id)
                if success:
                    conn = self.asp_connector.get_connection(conn_id)
                    ws.os_type = conn.os_type
                    ws.current_user = conn.current_user
                    ws.current_dir = conn.current_dir
                    ws.status = 'online'
                    ws.last_connect = datetime.now()
                self.asp_connector.remove_connection(conn_id)
            
            else:
                return False, f"不支持的Webshell类型: {ws.type}"
            
            self._save_data()
            return success, message
            
        except Exception as e:
            logger.error(f"测试Webshell失败: {e}")
            return False, str(e)
    
    async def test_all_webshells(self) -> Dict[str, tuple[bool, str]]:
        """测试所有Webshell"""
        results = {}
        for ws_id in self.webshells.keys():
            results[ws_id] = await self.test_webshell(ws_id)
        return results
    
    def get_webshell(self, ws_id: str) -> Optional[WebshellRecord]:
        """获取Webshell"""
        return self.webshells.get(ws_id)
    
    def get_all_webshells(self) -> List[WebshellRecord]:
        """获取所有Webshell"""
        return list(self.webshells.values())
    
    def get_webshells_by_type(self, ws_type: str) -> List[WebshellRecord]:
        """按类型获取Webshell"""
        return [ws for ws in self.webshells.values() if ws.type == ws_type.lower()]
    
    def get_webshells_by_status(self, status: str) -> List[WebshellRecord]:
        """按状态获取Webshell"""
        return [ws for ws in self.webshells.values() if ws.status == status]
    
    def get_webshells_by_tag(self, tag: str) -> List[WebshellRecord]:
        """按标签获取Webshell"""
        return [ws for ws in self.webshells.values() if tag in ws.tags]
    
    def add_tag(self, ws_id: str, tag: str) -> bool:
        """添加标签"""
        if ws_id in self.webshells:
            if tag not in self.webshells[ws_id].tags:
                self.webshells[ws_id].tags.append(tag)
                self._save_data()
            return True
        return False
    
    def remove_tag(self, ws_id: str, tag: str) -> bool:
        """移除标签"""
        if ws_id in self.webshells:
            if tag in self.webshells[ws_id].tags:
                self.webshells[ws_id].tags.remove(tag)
                self._save_data()
            return True
        return False
    
    def search_webshells(self, keyword: str) -> List[WebshellRecord]:
        """搜索Webshell"""
        keyword = keyword.lower()
        results = []
        
        for ws in self.webshells.values():
            if (keyword in ws.url.lower() or
                keyword in ws.notes.lower() or
                keyword in ws.type.lower() or
                keyword in ' '.join(ws.tags).lower()):
                results.append(ws)
        
        return results
    
    def get_stats(self) -> Dict:
        """获取统计信息"""
        total = len(self.webshells)
        php_count = len([w for w in self.webshells.values() if w.type == 'php'])
        jsp_count = len([w for w in self.webshells.values() if w.type == 'jsp'])
        asp_count = len([w for w in self.webshells.values() if w.type == 'asp'])
        online_count = len([w for w in self.webshells.values() if w.status == 'online'])
        offline_count = len([w for w in self.webshells.values() if w.status == 'offline'])
        
        all_tags = set()
        for ws in self.webshells.values():
            all_tags.update(ws.tags)
        
        return {
            'total': total,
            'by_type': {
                'php': php_count,
                'jsp': jsp_count,
                'asp': asp_count
            },
            'by_status': {
                'online': online_count,
                'offline': offline_count,
                'unknown': total - online_count - offline_count
            },
            'tags_count': len(all_tags),
            'unique_tags': list(all_tags)
        }
    
    def export_webshells(self, filepath: str) -> bool:
        """导出Webshell"""
        try:
            export_data = {
                'webshells': [ws.to_dict() for ws in self.webshells.values()],
                'exported_at': datetime.now().isoformat()
            }
            
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, ensure_ascii=False, indent=2)
            
            logger.info(f"Webshell导出成功: {filepath}")
            return True
            
        except Exception as e:
            logger.error(f"Webshell导出失败: {e}")
            return False
    
    def import_webshells(self, filepath: str) -> int:
        """导入Webshell"""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                import_data = json.load(f)
            
            imported = 0
            for ws_data in import_data.get('webshells', []):
                ws = WebshellRecord.from_dict(ws_data)
                if ws.id not in self.webshells:
                    self.webshells[ws.id] = ws
                    imported += 1
            
            self._save_data()
            logger.info(f"导入了 {imported} 个Webshell")
            return imported
            
        except Exception as e:
            logger.error(f"Webshell导入失败: {e}")
            return 0
